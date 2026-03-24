"""Ransomware Readiness Finding model — individual rule evaluation results."""
import uuid
from datetime import datetime

from sqlalchemy import String, Integer, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class RRFinding(Base):
    __tablename__ = "rr_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # RR-IAM-001
    domain: Mapped[str] = mapped_column(String(5), nullable=False, index=True)  # D1..D7
    severity: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # pass/fail/warning
    provider: Mapped[str] = mapped_column(String(10), nullable=False)  # aws/azure/gcp
    account_id: Mapped[str] = mapped_column(String(256), nullable=True, index=True)
    resource_count: Mapped[int] = mapped_column(Integer, default=0)
    passed_resources: Mapped[int] = mapped_column(Integer, default=0)
    failed_resources: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[str] = mapped_column(Text, nullable=True)  # JSON
    finding_status: Mapped[str] = mapped_column(String(20), default="open")  # open/accepted/exception/resolved
    assigned_to: Mapped[str] = mapped_column(String(256), nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=True)
    ticket_url: Mapped[str] = mapped_column(String(512), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    resolved_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
