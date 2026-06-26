from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class FindingResponse(BaseModel):
    id: str
    scan_id: str
    app_id: str
    rule_id: str
    rule_group: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str
    original_sev: Optional[str] = None
    category: Optional[str] = None
    source: Optional[str] = None
    confidence: Optional[int] = None
    validated: bool = False
    poc_command: Optional[str] = None
    poc_vector: Optional[str] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    location: Optional[str] = None
    escalation_rule: Optional[str] = None
    sectors: Optional[List[str]] = None
    raw_data: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class FindingSummary(BaseModel):
    total: int
    by_severity: Dict[str, int]
    by_source: Dict[str, int]
    by_rule_group: Dict[str, int]

class FindingListResponse(BaseModel):
    findings: List[FindingResponse]
    total: int
