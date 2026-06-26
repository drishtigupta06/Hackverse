import os
import hashlib
import aiofiles
from pathlib import Path

DATA_DIR = os.getenv("DATA_DIR", "/data")
APKS_DIR = Path(DATA_DIR) / "apks"
REPORTS_DIR = Path(DATA_DIR) / "reports"


def _ensure_dirs():
    try:
        APKS_DIR.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        raise RuntimeError(f"Cannot create data directories: {e}")


_ensure_dirs()


async def save_apk(file_content: bytes, filename: str) -> dict:
    sha256 = hashlib.sha256(file_content).hexdigest()
    ext = Path(filename).suffix
    save_path = APKS_DIR / f"{sha256}{ext}"

    if save_path.exists():
        async with aiofiles.open(str(save_path), "rb") as f:
            existing_content = await f.read()
            if existing_content != file_content:
                raise RuntimeError(f"SHA256 collision for {save_path}")
    else:
        async with aiofiles.open(str(save_path), "wb") as f:
            await f.write(file_content)

    return {
        "sha256": sha256,
        "upload_path": str(save_path),
        "size_bytes": len(file_content),
        "filename": filename,
    }


async def get_apk_path(app_id, db_session) -> str:
    from models.app_model import App
    from sqlalchemy import select
    import uuid

    if isinstance(app_id, str):
        try:
            app_id = uuid.UUID(app_id)
        except ValueError:
            raise ValueError(f"Invalid app_id format: {app_id}")

    result = await db_session.execute(select(App).where(App.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise FileNotFoundError(f"App {app_id} not found")
    return app.upload_path


def get_report_path(scan_id: str) -> Path:
    if not scan_id or ".." in scan_id or "/" in scan_id:
        raise ValueError("Invalid scan_id")
    return REPORTS_DIR / str(scan_id)


def ensure_report_dir(scan_id: str) -> Path:
    path = get_report_path(scan_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def delete_apk(upload_path: str):
    try:
        p = Path(upload_path)
        if p.exists():
            p.unlink()
    except Exception as e:
        raise RuntimeError(f"Failed to delete APK file: {e}")


def delete_report_dir(scan_id: str):
    if not scan_id or ".." in scan_id or "/" in scan_id:
        raise ValueError("Invalid scan_id")
    path = get_report_path(scan_id)
    if path.exists():
        import shutil
        shutil.rmtree(str(path))
