from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class AppResponse(BaseModel):
    id: str
    filename: str
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    version_code: Optional[str] = None
    version_name: Optional[str] = None
    sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    uploaded_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class AppListResponse(BaseModel):
    apps: List[AppResponse]
    total: int
