from datetime import datetime, timezone
from sqlalchemy import Column, String, BigInteger, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from .base import Base

class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    ts = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    level = Column(Text, default="info")
    message = Column(Text, nullable=False)

    scan = relationship("Scan", back_populates="logs")
