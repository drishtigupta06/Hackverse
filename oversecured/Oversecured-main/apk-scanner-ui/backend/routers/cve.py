import os
import json
import asyncio
import logging
from fastapi import APIRouter, Query

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/cves", tags=["cves"])

SCANNER_PATH = os.getenv("SCANNER_PATH", "/scanner/scanner.py")
CVE_CACHE = os.path.join(os.path.dirname(SCANNER_PATH), "rules", "cve_cache.json")


@router.get("/search")
async def search_cves(
    q: str = Query(..., description="Search keyword", max_length=200),
    days: int = Query(90, description="Days back", ge=1, le=3650),
    limit: int = Query(50, description="Max results", ge=1, le=500),
):
    try:
        if os.path.exists(CVE_CACHE):
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _search_cache, q, days, limit)
        else:
            proc = await asyncio.create_subprocess_exec(
                "python", SCANNER_PATH, "--cve-search", q, "--cve-days", str(days),
                "--sarif", "/dev/null", "-o", "/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await asyncio.wait_for(proc.communicate(), timeout=5)
                except Exception:
                    pass
                if os.path.exists(CVE_CACHE):
                    loop = asyncio.get_event_loop()
                    results = await loop.run_in_executor(None, _search_cache, q, days, limit)
                else:
                    results = _fallback_search(q)
                return {"query": q, "results": results[:limit]}

            if os.path.exists(CVE_CACHE):
                loop = asyncio.get_event_loop()
                results = await loop.run_in_executor(None, _search_cache, q, days, limit)
            else:
                results = _fallback_search(q)
    except Exception as e:
        logger.warning("CVE search failed: %s", e)
        results = _fallback_search(q)

    return {"query": q, "results": results[:limit]}


def _search_cache(q: str, days: int, limit: int) -> list:
    import datetime
    q_lower = q.lower()
    try:
        with open(CVE_CACHE) as f:
            cves = json.load(f)
    except Exception:
        return []

    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    results = []
    cve_list = cves if isinstance(cves, list) else cves.get("cves", cves.get("vulnerabilities", []))
    for cve in cve_list:
        cve_id = cve.get("id", cve.get("cve_id", ""))
        summary = cve.get("summary", cve.get("description", cve.get("descriptions", [{}])[0].get("value", "")))
        published = cve.get("published", cve.get("date_published", ""))
        severity = cve.get("severity", cve.get("baseSeverity", ""))
        cvss = cve.get("cvss", cve.get("baseScore", cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", ""))) or None

        if q_lower not in cve_id.lower() and q_lower not in summary.lower():
            continue

        if published:
            try:
                pub_date = datetime.datetime.fromisoformat(published.replace("Z", "+00:00"))
                if pub_date < cutoff:
                    continue
            except Exception:
                pass

        results.append({
            "id": cve_id,
            "summary": summary,
            "severity": severity.upper() if severity else None,
            "cvss": float(cvss) if cvss else None,
            "published": published,
        })

    results.sort(key=lambda x: x.get("cvss") or 0, reverse=True)
    return results


def _fallback_search(q: str) -> list:
    return [
        {
            "id": "CVE-UPDATE-NEEDED",
            "summary": f"Run the scanner with --cve-update to download and cache Android CVEs, then search for '{q}'",
            "severity": "INFO",
            "cvss": None,
            "published": None,
        }
    ]
