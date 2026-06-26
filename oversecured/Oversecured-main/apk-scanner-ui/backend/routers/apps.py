import uuid
import hashlib
import asyncio
import logging
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from services.db import get_db
from models.app_model import App
from schemas.app import AppResponse, AppListResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/apps", tags=["apps"])

MAX_APK_SIZE = 500 * 1024 * 1024
APK_MAGIC = b"\x50\x4b\x03\x04"


@router.post("/upload", response_model=AppResponse)
async def upload_apk(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    if not file.filename:
        raise HTTPException(400, detail="Filename is required")

    name = file.filename
    if not name.lower().endswith(".apk"):
        raise HTTPException(400, detail="Only .apk files are allowed")

    content = await file.read()
    if len(content) > MAX_APK_SIZE:
        raise HTTPException(400, detail="File too large (max 500MB)")

    if len(content) < 4 or content[:4] != APK_MAGIC:
        raise HTTPException(400, detail="File is not a valid APK (ZIP format)")

    sha256 = hashlib.sha256(content).hexdigest()
    from services.apk_store import save_apk
    info = await save_apk(content, file.filename)

    pkg_name = None
    app_name = None
    version_code = None
    version_name = None
    try:
        from androguard.misc import AnalyzeAPK
        loop = asyncio.get_event_loop()
        a, _, _ = await loop.run_in_executor(None, AnalyzeAPK, info["upload_path"])
        pkg_name = a.get_package()
        app_name = a.get_app_name()
        version_code = a.get_androidversion_code()
        version_name = a.get_androidversion_name()
    except Exception as e:
        logger.warning(f"Could not parse APK metadata: {e}")

    app = App(
        id=uuid.uuid4(),
        filename=info["filename"],
        package_name=pkg_name,
        app_name=app_name,
        version_code=str(version_code) if version_code else None,
        version_name=str(version_name) if version_name else None,
        sha256=info["sha256"],
        size_bytes=info["size_bytes"],
        upload_path=info["upload_path"],
    )
    db.add(app)
    await db.commit()
    await db.refresh(app)

    return AppResponse(
        id=str(app.id),
        filename=app.filename,
        package_name=app.package_name,
        app_name=app.app_name,
        version_code=app.version_code,
        version_name=app.version_name,
        sha256=app.sha256,
        size_bytes=app.size_bytes,
        uploaded_at=app.uploaded_at,
    )


@router.get("", response_model=AppListResponse)
async def list_apps(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(App).order_by(App.uploaded_at.desc()))
    apps = result.scalars().all()
    return AppListResponse(
        apps=[
            AppResponse(
                id=str(a.id), filename=a.filename, package_name=a.package_name,
                app_name=a.app_name, version_code=a.version_code,
                version_name=a.version_name, sha256=a.sha256,
                size_bytes=a.size_bytes, uploaded_at=a.uploaded_at,
            )
            for a in apps
        ],
        total=len(apps),
    )


@router.get("/{app_id}", response_model=AppResponse)
async def get_app(app_id: str, db: AsyncSession = Depends(get_db)):
    try:
        uuid.UUID(app_id)
    except ValueError:
        raise HTTPException(400, detail="Invalid app ID format")

    result = await db.execute(select(App).where(App.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(404, detail="App not found")
    return AppResponse(
        id=str(app.id), filename=app.filename, package_name=app.package_name,
        app_name=app.app_name, version_code=app.version_code,
        version_name=app.version_name, sha256=app.sha256,
        size_bytes=app.size_bytes, uploaded_at=app.uploaded_at,
    )


@router.delete("/{app_id}")
async def delete_app(app_id: str, db: AsyncSession = Depends(get_db)):
    try:
        uuid.UUID(app_id)
    except ValueError:
        raise HTTPException(400, detail="Invalid app ID format")

    result = await db.execute(select(App).where(App.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(404, detail="App not found")

    from services.apk_store import delete_apk, delete_report_dir
    from models.scan import Scan
    from models.finding import Finding

    scan_result = await db.execute(select(Scan).where(Scan.app_id == app_id))
    for scan in scan_result.scalars().all():
        delete_report_dir(str(scan.id))

    upload_path = app.upload_path
    await db.delete(app)
    await db.commit()

    delete_apk(upload_path)

    return {"detail": "App deleted"}
