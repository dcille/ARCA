"""DSPM Finding model for persisting DSPM scan results."""
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Float, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class DSPMFinding(Base):
    __tablename__ = "dspm_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    provider_id: Mapped[str] = mapped_column(String(36), ForeignKey("providers.id"), nullable=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("dspm_scans.id"), nullable=False, index=True)
    module: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    description: Mapped[str] = mapped_column(Text, nullable=True)
    resource_id: Mapped[str] = mapped_column(String(500), nullable=True)
    resource_name: Mapped[str] = mapped_column(String(500), nullable=True)
    category: Mapped[str] = mapped_column(String(100), nullable=True, index=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[str] = mapped_column(Text, nullable=True)  # JSON
    status: Mapped[str] = mapped_column(String(20), default="open")  # open, resolved, ignored
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
