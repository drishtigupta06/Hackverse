#!/usr/bin/env python3
"""
Celery tasks — async scan pipeline orchestration with Redis broker.
"""
import logging
import os
import sys
from datetime import datetime

from celery import Celery

sys.path.insert(0, os.path.dirname(__file__))
import config

app = Celery("cyberguard", broker=config.REDIS_URL, backend=config.REDIS_URL)
app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=3600 * 24,
    worker_send_task_events=True,
    task_send_sent_event=True,
)

logger = logging.getLogger(__name__)


def _get_db():
    """Synchronous MongoDB client for use in Celery workers."""
    from pymongo import MongoClient
    client = MongoClient(config.MONGO_URL)
    return client[config.MONGO_DB]


def _update_scan(scan_id: str, update: dict):
    try:
        db = _get_db()
        db.scans.update_one({"scan_id": scan_id}, {"$set": update})
    except Exception as e:
        logger.error(f"[celery] DB update failed for scan {scan_id}: {e}")


@app.task(bind=True, max_retries=2, soft_time_limit=7200, time_limit=7500)
def run_scan_task(self, scan_id: str, target: str, scan_types: list):
    """
    Main scan pipeline task.
    
    Steps:
    1. Mark scan as running
    2. Run Nmap (if requested)
    3. Run Acunetix (if requested)
    4. Normalize vulnerabilities
    5. Enrich with NVD data
    6. Ingest CVEs into RAG engine
    7. Build attack graph
    8. Mark scan as completed
    """
    logger.info(f"[celery] Starting scan {scan_id} for {target}, types: {scan_types}")

    _update_scan(scan_id, {
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
    })

    all_vulns = []
    raw_ports = []

    try:
        # ── Step 1: Nmap ──────────────────────────────────────────────────
        if "nmap" in scan_types:
            _update_scan(scan_id, {"status_detail": "Running Nmap scan..."})
            import nmap_scanner
            raw_ports = nmap_scanner.run_nmap_scan(target)
            logger.info(f"[celery] Nmap returned {len(raw_ports)} port entries")

            import vulnerability_normalizer
            nmap_vulns = vulnerability_normalizer.normalize_nmap_results(raw_ports, scan_id)
            all_vulns.extend(nmap_vulns)

        # ── Step 2: Acunetix ──────────────────────────────────────────────
        if "acunetix" in scan_types and config.ACUNETIX_KEY:
            _update_scan(scan_id, {"status_detail": "Running Acunetix scan..."})
            import acunetix_scanner
            import vulnerability_normalizer
            raw_acunetix = acunetix_scanner.scan_target(target)
            acunetix_vulns = vulnerability_normalizer.normalize_acunetix_results(raw_acunetix, target, scan_id)
            all_vulns.extend(acunetix_vulns)

        # ── Step 3: Enrich with NVD ────────────────────────────────────────
        cves_to_enrich = [v for v in all_vulns if v.get("cve_id")]
        if cves_to_enrich:
            _update_scan(scan_id, {"status_detail": f"Enriching {len(cves_to_enrich)} CVEs from NVD..."})
            import threat_intel
            all_vulns = threat_intel.enrich_vulnerabilities(all_vulns)

        # ── Step 3.5: Map to MITRE ATT&CK ──────────────────────────────────
        _update_scan(scan_id, {"status_detail": "Mapping to MITRE ATT&CK framework..."})
        for v in all_vulns:
            tactic, technique = map_to_mitre(v)
            v["mitre_tactic"] = tactic
            v["mitre_technique"] = technique

        # ── Step 4: Ingest into RAG ────────────────────────────────────────
        _update_scan(scan_id, {"status_detail": "Updating intelligence base..."})
        import rag_engine
        # Ingest full report (all findings) so AI can answer questions about it
        rag_engine.ingest_scan_report(all_vulns, target=target, scan_label=scan_id[:8])
        # Also keep ingest_cve_records for specific CVE knowledge (optional, redundant but safe)
        rag_engine.ingest_cve_records([v for v in all_vulns if v.get("cve_id")])

        # ── Step 5: Save vulnerabilities to DB ────────────────────────────
        db = _get_db()
        if all_vulns:
            db.vulnerabilities.insert_many(all_vulns)
        
        # ── Step 6: Build attack graph ────────────────────────────────────
        _update_scan(scan_id, {"status_detail": "Building attack graph..."})
        import attack_graph
        graph_data = attack_graph.build_attack_graph(scan_id, all_vulns)
        db.graphs.replace_one({"scan_id": scan_id}, graph_data, upsert=True)
        
        # Optionally write to Neo4j
        attack_graph.try_write_neo4j(graph_data)

        # ── Step 7: Save port results ──────────────────────────────────────
        if raw_ports:
            hosts_map = {}
            for entry in raw_ports:
                h = entry.get("host", "")
                hosts_map.setdefault(h, []).append({
                    "port": entry.get("port"),
                    "protocol": entry.get("protocol"),
                    "state": entry.get("state"),
                    "service": entry.get("service"),
                    "version": entry.get("version"),
                })
            for host_ip, ports in hosts_map.items():
                db.hosts.replace_one(
                    {"scan_id": scan_id, "host": host_ip},
                    {"scan_id": scan_id, "host": host_ip, "ports": ports, "discovered_at": datetime.utcnow().isoformat()},
                    upsert=True,
                )

        # ── Step 8: Mark completed ────────────────────────────────────────
        _update_scan(scan_id, {
            "status": "completed",
            "status_detail": "Scan complete",
            "completed_at": datetime.utcnow().isoformat(),
            "vuln_count": len(all_vulns),
            "host_count": len(set(v.get("host") for v in all_vulns)),
        })
        logger.info(f"[celery] Scan {scan_id} completed: {len(all_vulns)} findings")

    except Exception as exc:
        logger.error(f"[celery] Scan {scan_id} failed: {exc}", exc_info=True)
        _update_scan(scan_id, {
            "status": "failed",
            "status_detail": "Scan failed",
            "error": str(exc),
            "completed_at": datetime.utcnow().isoformat(),
        })
        raise self.retry(exc=exc, countdown=10)


@app.task(bind=True, max_retries=1)
def run_recon_task(self, recon_id: str, target_domain: str):
    """
    Subdomain discovery task using Amass and Subfinder.
    """
    import asyncio
    import recon_scanner
    
    logger.info(f"[celery] Starting recon {recon_id} for {target_domain}")
    
    # Simple sync DB update
    db = _get_db()
    db.recon_jobs.update_one(
        {"recon_id": recon_id},
        {"$set": {"status": "running", "started_at": datetime.utcnow().isoformat()}}
    )

    try:
        # Run the async scanner in a loop
        scanner = recon_scanner.ReconScanner(target_domain)
        loop = asyncio.get_event_loop()
        assets = loop.run_until_complete(scanner.execute_discovery())
        
        # Save assets
        if assets:
            asset_dicts = []
            for asset in assets:
                d = asset.dict()
                d["scan_id"] = recon_id
                d["discovered_at"] = datetime.utcnow().isoformat()
                asset_dicts.append(d)
            db.recon_assets.insert_many(asset_dicts)
            
        db.recon_jobs.update_one(
            {"recon_id": recon_id},
            {"$set": {
                "status": "completed",
                "completed_at": datetime.utcnow().isoformat(),
                "asset_count": len(assets)
            }}
        )
        logger.info(f"[celery] Recon {recon_id} complete. Found {len(assets)} assets.")

    except Exception as exc:
        logger.error(f"[celery] Recon {recon_id} failed: {exc}")
        db.recon_jobs.update_one(
            {"recon_id": recon_id},
            {"$set": {
                "status": "failed",
                "completed_at": datetime.utcnow().isoformat(),
                "error": str(exc)
            }}
        )

@app.task(bind=True, max_retries=1)
def run_mobile_scan_task(self, scan_id: str, file_path: str, filename: str):
    """
    Mobile Application Security Scan task via MobSF.
    """
    import asyncio
    import mobsf_scanner
    
    logger.info(f"[celery] Starting mobile scan {scan_id} for {filename}")
    db = _get_db()
    
    # Update status to scanning
    db.mobile_scans.update_one(
        {"scan_id": scan_id},
        {"$set": {"status": "scanning"}}
    )
    
    try:
        scanner = mobsf_scanner.MobSFScanner()
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(scanner.scan_file(file_path, filename))
        
        db.mobile_scans.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "status": "completed",
                "completed_at": datetime.utcnow().isoformat(),
                "results": results,
            }}
        )
        logger.info(f"[celery] Mobile scan {scan_id} complete. Found {len(results.get('vulnerabilities', []))} vulns.")
        
    except Exception as exc:
        logger.error(f"[celery] Mobile scan {scan_id} failed: {exc}")
        db.mobile_scans.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "status": "failed",
                "completed_at": datetime.utcnow().isoformat(),
                "error": str(exc)
            }}
        )

