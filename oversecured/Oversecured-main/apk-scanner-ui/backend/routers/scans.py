import uuid
import asyncio
import signal
import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from services.db import get_db
from services.queue import push_scan
from services.scanner_runner import _running_processes
from schemas.scan import ScanResponse, ScanListResponse
from schemas.config import ScanConfigSchema
from models.scan import Scan
from services.apk_store import delete_report_dir

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


async def _validate_uuid(id_str: str, label: str = "ID"):
    try:
        return uuid.UUID(id_str)
    except ValueError:
        raise HTTPException(400, detail=f"Invalid {label} format")


@router.post("", response_model=ScanResponse)
async def create_scan(config: ScanConfigSchema, db: AsyncSession = Depends(get_db)):
    from models.app_model import App

    try:
        app_uuid = uuid.UUID(config.app_id)
    except ValueError:
        raise HTTPException(400, detail="Invalid app_id format")

    app_result = await db.execute(select(App).where(App.id == app_uuid))
    app = app_result.scalar_one_or_none()
    if not app:
        raise HTTPException(404, detail="App not found")

    scan_id = uuid.uuid4()
    scan = Scan(
        id=scan_id,
        app_id=app_uuid,
        status="queued",
        scan_mode=config.scan_mode,
        config=config.model_dump(),
    )
    db.add(scan)
    await db.commit()

    await push_scan(str(scan_id), config.app_id, config.model_dump())

    return ScanResponse(
        id=str(scan.id),
        app_id=str(scan.app_id),
        status=scan.status,
        scan_mode=scan.scan_mode,
        config=scan.config,
        created_at=scan.created_at,
    )


@router.get("", response_model=ScanListResponse)
async def list_scans(
    app_id: str = Query(None),
    status: str = Query(None),
    scan_mode: str = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    query = select(Scan).order_by(Scan.created_at.desc())
    count_query = select(func.count(Scan.id))

    if app_id:
        query = query.where(Scan.app_id == app_id)
        count_query = count_query.where(Scan.app_id == app_id)
    if status:
        query = query.where(Scan.status == status)
        count_query = count_query.where(Scan.status == status)
    if scan_mode:
        query = query.where(Scan.scan_mode == scan_mode)
        count_query = count_query.where(Scan.scan_mode == scan_mode)

    result = await db.execute(count_query)
    total = result.scalar()

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    scans = result.scalars().all()

    return ScanListResponse(
        scans=[
            ScanResponse(
                id=str(s.id),
                app_id=str(s.app_id),
                status=s.status,
                scan_mode=s.scan_mode,
                config=s.config,
                sector_detected=s.sector_detected,
                started_at=s.started_at,
                completed_at=s.completed_at,
                duration_secs=s.duration_secs,
                html_report_path=s.html_report_path,
                sarif_path=s.sarif_path,
                error_message=s.error_message,
                created_at=s.created_at,
            )
            for s in scans
        ],
        total=total or 0,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    await _validate_uuid(scan_id, "scan ID")
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, detail="Scan not found")
    return ScanResponse(
        id=str(scan.id),
        app_id=str(scan.app_id),
        status=scan.status,
        scan_mode=scan.scan_mode,
        config=scan.config,
        sector_detected=scan.sector_detected,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_secs=scan.duration_secs,
        html_report_path=scan.html_report_path,
        sarif_path=scan.sarif_path,
        error_message=scan.error_message,
        created_at=scan.created_at,
    )


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    await _validate_uuid(scan_id, "scan ID")
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, detail="Scan not found")

    proc_info = _running_processes.get(scan_id)
    if proc_info and scan.status == "running":
        proc = proc_info.get("process")
        if proc and proc.returncode is None:
            proc.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
        _running_processes.pop(scan_id, None)

    delete_report_dir(scan_id)
    await db.delete(scan)
    await db.commit()
    return {"detail": "Scan deleted"}


@router.patch("/{scan_id}/cancel")
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    await _validate_uuid(scan_id, "scan ID")
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, detail="Scan not found")
    if scan.status != "running":
        raise HTTPException(400, detail="Scan is not running")

    proc_info = _running_processes.get(scan_id)
    if proc_info:
        proc = proc_info.get("process")
        if proc and proc.returncode is None:
            proc.send_signal(signal.SIGTERM)
            _running_processes.pop(scan_id, None)

    scan.status = "cancelled"
    scan.completed_at = func.now()
    await db.commit()
    return {"detail": "Scan cancelled"}
