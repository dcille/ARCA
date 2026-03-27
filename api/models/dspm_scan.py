"""DSPM Scan model for tracking DSPM scan executions."""
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Integer, Float, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class DSPMScan(Base):
    __tablename__ = "dspm_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    provider_id: Mapped[str] = mapped_column(String(36), ForeignKey("providers.id"), nullable=True)
    task_id: Mapped[str] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, running, completed, failed
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    overall_risk_label: Mapped[str] = mapped_column(String(20), default="low")
    modules_run: Mapped[int] = mapped_column(Integer, default=0)
    modules_failed: Mapped[int] = mapped_column(Integer, default=0)
    findings_by_severity: Mapped[str] = mapped_column(Text, nullable=True)  # JSON
    findings_by_module: Mapped[str] = mapped_column(Text, nullable=True)  # JSON
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=True)
    enable_content_scanning: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
