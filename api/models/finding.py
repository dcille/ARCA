"""Finding model for cloud security findings."""
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    provider_id: Mapped[str] = mapped_column(String(36), ForeignKey("providers.id"), nullable=False)
    check_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    check_title: Mapped[str] = mapped_column(String(500), nullable=False)
    service: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # critical, high, medium, low, informational
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # PASS, FAIL
    region: Mapped[str] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[str] = mapped_column(String(500), nullable=True)
    resource_name: Mapped[str] = mapped_column(String(500), nullable=True)
    status_extended: Mapped[str] = mapped_column(Text, nullable=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=True)
    remediation_url: Mapped[str] = mapped_column(String(500), nullable=True)
    compliance_frameworks: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string
    check_description: Mapped[str] = mapped_column(Text, nullable=True)
    evidence_log: Mapped[str] = mapped_column(Text, nullable=True)  # JSON: {api_call, response}
    mitre_techniques: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of MITRE ATT&CK technique IDs
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
