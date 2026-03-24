"""Ransomware Readiness Governance model — manual operator inputs for D7 rules."""
import uuid
from datetime import datetime

from sqlalchemy import String, Boolean, Float, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class RRGovernance(Base):
    __tablename__ = "rr_governance"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # RR-GOV-001: Ransomware response plan
    ransomware_response_plan: Mapped[bool] = mapped_column(Boolean, default=False)

    # RR-GOV-002: Last tabletop exercise date
    last_tabletop_exercise_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # RR-GOV-003: Security training completion percentage
    security_training_completion: Mapped[float] = mapped_column(Float, nullable=True)

    # RR-GOV-004: IR roles and responsibilities defined
    ir_roles_defined: Mapped[bool] = mapped_column(Boolean, default=False)

    # RR-GOV-005: Communication plan exists
    communication_plan_exists: Mapped[bool] = mapped_column(Boolean, default=False)

    # D3 manual fields
    rto_rpo_documented: Mapped[bool] = mapped_column(Boolean, default=False)
    backup_restore_tested: Mapped[bool] = mapped_column(Boolean, default=False)
    dr_plan_documented: Mapped[bool] = mapped_column(Boolean, default=False)

    # D5 manual fields
    iac_scanning_integrated: Mapped[bool] = mapped_column(Boolean, default=False)

    # D6 manual fields
    siem_integration_configured: Mapped[bool] = mapped_column(Boolean, default=False)

    # Notes
    notes: Mapped[str] = mapped_column(Text, nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
