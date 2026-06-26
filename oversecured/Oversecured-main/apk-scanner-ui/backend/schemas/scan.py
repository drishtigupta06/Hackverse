from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid

class ScanCreate(BaseModel):
    app_id: str
    config: Dict[str, Any]

class ScanResponse(BaseModel):
    id: str
    app_id: str
    status: str
    scan_mode: str
    config: Dict[str, Any]
    sector_detected: Optional[List[str]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_secs: Optional[int] = None
    html_report_path: Optional[str] = None
    sarif_path: Optional[str] = None
    error_message: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class ScanListResponse(BaseModel):
    scans: List[ScanResponse]
    total: int
