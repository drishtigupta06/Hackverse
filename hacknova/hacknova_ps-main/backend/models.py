from datetime import datetime
from typing import Optional, List
import uuid
from pydantic import BaseModel, Field
from enum import Enum

# ─── Enums ───────────────────────────────────────────────────────────────────

class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

# ─── Autonomous Agent ────────────────────────────────────────────────────────

class AgentEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    phase: str  # Observe, Orient, Decide, Act
    message: str
    metadata: Optional[dict] = None

class AgentJob(BaseModel):
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str
    status: str = "running" # running, completed, manually_stopped, failed
    events: List[AgentEvent] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

# ─── Auth ────────────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    username: str
    password: str
    email: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# ─── Scan ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    scan_types: List[str] = ["nmap"]  # ["nmap", "acunetix"]
    description: Optional[str] = None

class PortResult(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    scripts: Optional[str] = None

class HostResult(BaseModel):
    host: str
    status: str = "up"
    ports: List[PortResult] = []

class VulnerabilityRecord(BaseModel):
    cve_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    severity: Severity = Severity.info
    cvss_score: Optional[float] = None
    host: str
    port: Optional[int] = None
    service: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    source: str = "nmap"  # nmap | acunetix | nvd
    exploit_available: bool = False
    remediation: Optional[str] = None
    references: List[str] = []
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

class ScanJob(BaseModel):
    scan_id: str
    user: str
    target: str
    description: Optional[str] = None
    scan_types: List[str] = ["nmap"]
    status: ScanStatus = ScanStatus.pending
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    host_count: int = 0
    vuln_count: int = 0
    error: Optional[str] = None
    celery_task_id: Optional[str] = None

# ─── Chat ────────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    question: str
    scan_id: Optional[str] = None

class ChatResponse(BaseModel):
    answer: str
    context_used: List[str] = []

# ─── Graph ───────────────────────────────────────────────────────────────────

class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # attacker | host | port | service | vulnerability | exploit
    severity: Optional[str] = None
    data: dict = {}

class GraphEdge(BaseModel):
    source: str
    target: str
    label: str

class AttackGraph(BaseModel):
    scan_id: str
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []

# ─── Recon ───────────────────────────────────────────────────────────────────

class AssetType(str, Enum):
    subdomain = "subdomain"
    ip = "ip"
    tld = "tld"

class ReconAsset(BaseModel):
    domain: str
    ip_addresses: List[str] = []
    asset_type: AssetType = AssetType.subdomain
    source: List[str] = [] # ["amass", "subfinder"]
    description: Optional[str] = None
    status_code: Optional[int] = None
    screenshot_path: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    scan_id: Optional[str] = None # Link to a specific recon job

class ReconJob(BaseModel):
    recon_id: str
    user: str
    target_domain: str
    status: ScanStatus = ScanStatus.pending
    asset_count: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

class ReconRequest(BaseModel):
    target_domain: str
    description: Optional[str] = None

# ─── LLM Scan Models ─────────────────────────────────────────────────────────

class LLMScanRequest(BaseModel):
    model_name: str
    target_type: str = "huggingface.InferenceAPI"  # openai, huggingface, nim, replicate
    probes: List[str] = ["dan", "promptinject", "xss"]
    description: Optional[str] = None

class LLMScanResult(BaseModel):
    probe: str
    detector: str
    status: str
    failed_attempts: int
    total_attempts: int
    severity: str = "info"

class LLMScanJob(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_name: str
    target_type: str = "huggingface.InferenceAPI"
    probes: List[str] = []
    status: str = "pending"
    results: List[LLMScanResult] = []
    logs: List[str] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

# ─── Credential Leak Models ───────────────────────────────────────────────────

class LeakFinding(BaseModel):
    source: str
    title: str
    description: str
    date_found: Optional[str] = None
    severity: str = "high"

class LeakReport(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_domain: str
    status: str = "pending"
    findings: List[LeakFinding] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

# ─── Mobile Scan Models ───────────────────────────────────────────────────────

class MobileVulnerability(BaseModel):
    title: str
    severity: str
    description: str
    component: Optional[str] = None

class MobileScanResult(BaseModel):
    vulnerabilities: List[MobileVulnerability] = []
    permissions_analyzed: int = 0
    raw_report_id: Optional[str] = None

class MobileScan(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    file_hash: Optional[str] = None
    status: str = "pending"  # pending, uploading, scanning, completed, failed
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    results: Optional[MobileScanResult] = None
    error: Optional[str] = None

