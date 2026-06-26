import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB
from sqlalchemy.orm import relationship
from .base import Base

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    app_id = Column(UUID(as_uuid=True), ForeignKey("apps.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(Text, nullable=False)
    rule_group = Column(Text)
    title = Column(Text, nullable=False)
    description = Column(Text)
    severity = Column(Text, nullable=False)
    original_sev = Column(Text)
    category = Column(Text)
    source = Column(Text)
    confidence = Column(Integer)
    validated = Column(Boolean, default=False)
    poc_command = Column(Text)
    poc_vector = Column(Text)
    impact = Column(Text)
    recommendation = Column(Text)
    location = Column(Text)
    escalation_rule = Column(Text)
    sectors = Column(ARRAY(Text))
    raw_data = Column(JSONB)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="findings")
    app = relationship("App", back_populates="findings")
