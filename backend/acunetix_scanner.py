#!/usr/bin/env python3
"""
DAST Scanner integration.
Runs automated web application vulnerability scans using the configured
DAST engine and returns normalized findings.
"""
import requests
import time
import logging
from typing import Optional, List, Dict, Any

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import config

logger = logging.getLogger(__name__)

FULL_SCAN_PROFILE = "11111111-1111-1111-1111-111111111111"
HIGH_RISK_PROFILE  = "11111111-1111-1111-1111-111111111112"


class DASTScanner:
    """Web application DAST scanner client."""

    def __init__(self, api_url: str = None, api_key: str = None):
        self.api_url = (api_url or config.ACUNETIX_URL).rstrip("/")
        self.headers = {
            "X-Auth": api_key or config.ACUNETIX_KEY,
            "Content-Type": "application/json",
        }

    def _get(self, path: str, **kwargs) -> Optional[dict]:
        try:
            r = requests.get(
                f"{self.api_url}{path}", headers=self.headers,
                verify=False, timeout=30, **kwargs
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"[dast] GET {path} failed: {e}")
            return None

    def _post(self, path: str, data: dict) -> Optional[dict]:
        try:
            r = requests.post(
                f"{self.api_url}{path}", headers=self.headers,
                json=data, verify=False, timeout=30
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"[dast] POST {path} failed: {e}")
            return None

    def _delete(self, path: str) -> bool:
        try:
            r = requests.delete(
                f"{self.api_url}{path}", headers=self.headers,
                verify=False, timeout=15
            )
            return r.status_code in (200, 204)
        except Exception as e:
            logger.error(f"[dast] DELETE {path} failed: {e}")
            return False

    def test_connection(self) -> bool:
        """Verify API is reachable."""
        resp = self._get("/api/v1/targets")
        return resp is not None

    def add_target(self, target_url: str, description: str = "Security Scan") -> Optional[str]:
        logger.info(f"[dast] Adding target: {target_url}")
        resp = self._post("/api/v1/targets", {
            "address": target_url,
            "description": description,
            "type": "default",
            "criticality": 10,
        })
        if resp and resp.get("target_id"):
            return resp["target_id"]
        # Find existing target
        return self.find_target_id(target_url)

    def find_target_id(self, target_url: str) -> Optional[str]:
        resp = self._get("/api/v1/targets", params={"q": target_url})
        if resp:
            for t in resp.get("targets", []):
                if t.get("address") == target_url:
                    return t.get("target_id")
        return None

    def start_scan(self, target_id: str, profile_id: str = FULL_SCAN_PROFILE) -> Optional[str]:
        logger.info(f"[dast] Starting scan for target: {target_id}")
        resp = self._post("/api/v1/scans", {
            "target_id": target_id,
            "profile_id": profile_id,
            "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
        })
        return resp.get("scan_id") if resp else None

    def get_scan_status(self, scan_id: str) -> str:
        resp = self._get(f"/api/v1/scans/{scan_id}")
        if resp:
            return resp.get("current_session", {}).get("status", "unknown")
        return "unknown"

    def get_scan_session_id(self, scan_id: str) -> Optional[str]:
        resp = self._get(f"/api/v1/scans/{scan_id}")
        if resp:
            return resp.get("current_session", {}).get("scan_session_id")
        return None

    def poll_scan(self, scan_id: str, max_wait: int = 7200, interval: int = 30) -> bool:
        """Poll until completed. Returns True on success."""
        logger.info(f"[dast] Polling scan {scan_id}")
        elapsed = 0
        while elapsed < max_wait:
            status = self.get_scan_status(scan_id)
            logger.info(f"[dast] Scan status: {status} ({elapsed}s)")
            if status in ("completed", "done"):
                return True
            if status in ("failed", "aborted"):
                logger.warning(f"[dast] Scan {scan_id} {status}")
                return False
            time.sleep(interval)
            elapsed += interval
        logger.warning(f"[dast] Scan {scan_id} timed out after {max_wait}s")
        return False

    def get_vulnerabilities(self, scan_id: str) -> List[Dict[str, Any]]:
        """Fetch all vulnerability findings for a completed scan."""
        # Get session id
        resp = self._get(f"/api/v1/scans/{scan_id}")
        if not resp:
            return []
        result_id = resp.get("current_session", {}).get("scan_session_id")
        if not result_id:
            logger.warning(f"[dast] No session ID for scan {scan_id}")
            return []

        # Paginate all results
        all_vulns = []
        offset = 0
        limit = 100
        while True:
            data = self._get(
                f"/api/v1/scans/{scan_id}/results/{result_id}/vulnerabilities",
                params={"c": limit, "s": offset}
            )
            if not data:
                break
            items = data.get("vulnerabilities", [])
            all_vulns.extend(items)
            if len(items) < limit:
                break
            offset += limit

        logger.info(f"[dast] Retrieved {len(all_vulns)} findings for scan {scan_id}")
        return all_vulns

    def list_existing_scans(self, limit: int = 50) -> List[Dict]:
        """List all scans in the DAST engine — used to sync historical reports."""
        resp = self._get("/api/v1/scans", params={"c": limit})
        return resp.get("scans", []) if resp else []

    def get_scan_report_html(self, scan_id: str, result_id: str) -> Optional[str]:
        """Download HTML report for later text extraction."""
        try:
            r = requests.get(
                f"{self.api_url}/api/v1/scans/{scan_id}/results/{result_id}/download/html",
                headers=self.headers, verify=False, timeout=60
            )
            if r.ok:
                return r.text
        except Exception as e:
            logger.error(f"[dast] Report download failed: {e}")
        return None


def run_acunetix_scan(target_url: str, poll_timeout: int = 7200) -> List[Dict[str, Any]]:
    """
    Run a full DAST scan: add target → start → poll → fetch vulnerabilities.
    Returns raw vulnerability dicts.
    """
    if not config.ACUNETIX_KEY:
        logger.warning("[dast] No API key configured, skipping scan")
        return []

    scanner = DASTScanner()

    # Test connectivity
    if not scanner.test_connection():
        logger.error("[dast] Cannot reach DAST API — check URL and credentials")
        return []

    target_id = scanner.add_target(target_url)
    if not target_id:
        logger.error(f"[dast] Could not add/find target: {target_url}")
        return []

    scan_id = scanner.start_scan(target_id)
    if not scan_id:
        logger.error(f"[dast] Could not start scan for target: {target_id}")
        return []

    logger.info(f"[dast] Scan {scan_id} started for {target_url}")
    completed = scanner.poll_scan(scan_id, max_wait=poll_timeout)

    if not completed:
        logger.warning(f"[dast] Scan did not complete in time, fetching partial results")

    vulns = scanner.get_vulnerabilities(scan_id)
    logger.info(f"[dast] {len(vulns)} vulnerabilities for {target_url}")
    return vulns


def sync_all_scans_to_rag() -> int:
    """
    Sync ALL completed scans from the DAST engine into the RAG vector store.
    Called on startup and periodically. Returns number of reports ingested.
    """
    if not config.ACUNETIX_KEY:
        return 0

    try:
        import rag_engine
        import vulnerability_normalizer

        scanner = DASTScanner()
        scans = scanner.list_existing_scans(limit=100)
        ingested = 0

        for scan in scans:
            scan_id = scan.get("scan_id") or scan.get("scan_session_id", "")
            status = scan.get("current_session", {}).get("status", "")
            target = scan.get("target", {}).get("address", "")

            if status not in ("completed", "done"):
                continue

            vulns = scanner.get_vulnerabilities(scan_id)
            if not vulns:
                continue

            # Normalize and ingest into RAG
            normalized = vulnerability_normalizer.normalize_acunetix_results(vulns, target, f"dast_{scan_id}")
            rag_engine.ingest_scan_report(normalized, target=target, scan_label=f"dast_{scan_id[:8]}")
            ingested += 1
            logger.info(f"[dast] Ingested {len(normalized)} findings from scan {scan_id[:8]} into RAG")

        logger.info(f"[dast] Synced {ingested} historical reports into RAG")
        return ingested

    except Exception as e:
        logger.error(f"[dast] sync_all_scans_to_rag failed: {e}")
        return 0


# Backwards compat alias
def scan_target(target_url: str, poll_timeout: int = 3600) -> List[Dict[str, Any]]:
    return run_acunetix_scan(target_url, poll_timeout)
