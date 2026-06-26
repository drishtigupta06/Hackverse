#!/usr/bin/env python3
"""
Threat intelligence module — fetches CVE metadata from NVD API v2
and enriches vulnerability records.
"""
import requests
import logging
import time
from typing import Optional, Dict, Any, List

import config

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_BASE = "https://exploit-db.com/search"


def fetch_cve_nvd(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch CVE data from NVD API v2.
    Returns dict with: description, cvss_score, cvss_vector, references, published.
    """
    params = {"cveId": cve_id}
    headers = {}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY

    try:
        resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        
        cve_data = vulns[0].get("cve", {})
        
        # Description (prefer English)
        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        
        # CVSS score (prefer v3.1, fallback v3.0, v2)
        cvss_score = None
        cvss_vector = None
        metrics = cve_data.get("metrics", {})
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                break
        
        # References
        references = [r.get("url") for r in cve_data.get("references", [])[:5] if r.get("url")]
        
        return {
            "cve_id": cve_id,
            "description": desc,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "references": references,
            "published": cve_data.get("published"),
            "modified": cve_data.get("lastModified"),
        }
    except Exception as e:
        logger.error(f"[threat_intel] NVD fetch failed for {cve_id}: {e}")
        return None


def enrich_vulnerabilities(records: List[Dict], rate_limit_delay: float = 0.6) -> List[Dict]:
    """
    Enrich a list of normalized vulnerability records with NVD CVE data.
    Respects NVD rate limit (5 req/30s without key, 50 req/30s with key).
    """
    enriched = []
    
    for rec in records:
        cve_id = rec.get("cve_id")
        if cve_id:
            nvd_data = fetch_cve_nvd(cve_id)
            if nvd_data:
                # Merge NVD data into record (NVD takes priority for description/score)
                if nvd_data.get("description") and not rec.get("description"):
                    rec["description"] = nvd_data["description"]
                if nvd_data.get("cvss_score"):
                    rec["cvss_score"] = nvd_data["cvss_score"]
                if nvd_data.get("references"):
                    existing = set(rec.get("references", []))
                    rec["references"] = list(existing | set(nvd_data["references"]))
                rec["nvd_published"] = nvd_data.get("published")
                rec["cvss_vector"] = nvd_data.get("cvss_vector")
                
                # Update severity based on CVSS score
                score = rec.get("cvss_score")
                if score:
                    rec["severity"] = _cvss_to_severity(score)
            
            time.sleep(rate_limit_delay)  # Rate limiting
        
        enriched.append(rec)
    
    logger.info(f"[threat_intel] Enriched {len(enriched)} records")
    return enriched


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0:
        return "low"
    return "info"


def fetch_recent_cves(keyword: str = "apache", limit: int = 10) -> List[Dict]:
    """Search NVD for recent CVEs by keyword."""
    try:
        resp = requests.get(
            NVD_BASE,
            params={"keywordSearch": keyword, "resultsPerPage": limit},
            timeout=15,
        )
        resp.raise_for_status()
        cves = []
        for item in resp.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                ""
            )
            cves.append({"cve_id": cve_id, "description": desc})
        return cves
    except Exception as e:
        logger.error(f"[threat_intel] NVD keyword search failed: {e}")
        return []


def fetch_cve_details(cve_id: str) -> Dict[str, Any]:
    """Alias used by the /cve/{cve_id} API endpoint. Returns full details or raises."""
    data = fetch_cve_nvd(cve_id)
    if not data:
        raise ValueError(f"CVE {cve_id} not found in NVD")
    # Add NVD link
    data["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    data["exploitdb_url"] = f"https://www.exploit-db.com/search?cve={cve_id}"
    return data
