import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB
from sqlalchemy.orm import relationship
from .base import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    app_id = Column(UUID(as_uuid=True), ForeignKey("apps.id", ondelete="CASCADE"), nullable=False)
    status = Column(Text, nullable=False, default="queued")
    scan_mode = Column(Text, nullable=False, default="standard")
    config = Column(JSONB, nullable=False, default=dict)
    sector_detected = Column(ARRAY(Text))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    duration_secs = Column(Integer)
    log_path = Column(Text)
    html_report_path = Column(Text)
    sarif_path = Column(Text)
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    app = relationship("App", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    exploit_chains = relationship("ExploitChain", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
