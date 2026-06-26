import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, BigInteger, DateTime, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from .base import Base

class App(Base):
    __tablename__ = "apps"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    filename = Column(Text, nullable=False)
    package_name = Column(Text)
    app_name = Column(Text)
    version_code = Column(Text)
    version_name = Column(Text)
    sha256 = Column(Text)
    size_bytes = Column(BigInteger)
    upload_path = Column(Text, nullable=False)
    uploaded_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scans = relationship("Scan", back_populates="app", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="app", cascade="all, delete-orphan")
