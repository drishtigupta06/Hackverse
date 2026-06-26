import os
import json
import asyncio
import logging
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path

from services.db import get_db
from models.scan import Scan

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


@router.get("/{scan_id}/html")
def _is_safe_path(basedir: Path, path_str: str) -> bool:
    try:
        p = Path(path_str).resolve()
        return str(p).startswith(str(basedir.resolve()))
    except (ValueError, OSError):
        return False


@router.get("/{scan_id}/html")
async def download_html(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, detail="Scan not found")
    if not scan.html_report_path:
        raise HTTPException(404, detail="HTML report not found")
    from services.apk_store import REPORTS_DIR
    if not _is_safe_path(REPORTS_DIR, scan.html_report_path):
        raise HTTPException(400, detail="Invalid report path")
    if not Path(scan.html_report_path).exists():
        raise HTTPException(404, detail="HTML report not found")
    return FileResponse(
        scan.html_report_path,
        media_type="text/html",
        filename=f"scan_{scan_id}.html",
    )


@router.get("/{scan_id}/sarif")
async def download_sarif(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, detail="Scan not found")
    if not scan.sarif_path:
        raise HTTPException(404, detail="SARIF report not found")
    from services.apk_store import REPORTS_DIR
    if not _is_safe_path(REPORTS_DIR, scan.sarif_path):
        raise HTTPException(400, detail="Invalid report path")
    if not Path(scan.sarif_path).exists():
        raise HTTPException(404, detail="SARIF report not found")
    return FileResponse(
        scan.sarif_path,
        media_type="application/json",
        filename=f"scan_{scan_id}.sarif",
    )


@router.get("/{scan_id}/json")
async def download_json(scan_id: str, db: AsyncSession = Depends(get_db)):
    from models.finding import Finding
    from models.exploit_chain import ExploitChain

    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, detail="Scan not found")

    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = findings_result.scalars().all()

    chains_result = await db.execute(
        select(ExploitChain).where(ExploitChain.scan_id == scan_id)
    )
    chains = chains_result.scalars().all()

    data = {
        "scan_id": scan_id,
        "app_id": str(scan.app_id),
        "status": scan.status,
        "scan_mode": scan.scan_mode,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "duration_secs": scan.duration_secs,
        "findings": [
            {
                "id": str(f.id),
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "source": f.source,
                "confidence": f.confidence,
                "validated": f.validated,
            }
            for f in findings
        ],
        "exploit_chains": [
            {
                "id": str(c.id),
                "title": c.title,
                "severity": c.severity,
                "validated": c.validated,
                "steps": c.steps,
            }
            for c in chains
        ],
    }

    raw = await asyncio.to_thread(lambda: json.dumps(data, indent=2, default=str))
    return StreamingResponse(
        iter([raw]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.json"},
    )
