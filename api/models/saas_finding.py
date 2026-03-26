"""SaaS security finding model."""
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class SaaSFinding(Base):
    __tablename__ = "saas_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    connection_id: Mapped[str] = mapped_column(String(36), ForeignKey("saas_connections.id"), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    check_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    check_title: Mapped[str] = mapped_column(String(500), nullable=False)
    service_area: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., users, access_control, session_management
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # PASS, FAIL
    resource_id: Mapped[str] = mapped_column(String(500), nullable=True)
    resource_name: Mapped[str] = mapped_column(String(500), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=True)
    remediation_url: Mapped[str] = mapped_column(String(500), nullable=True)
    compliance_frameworks: Mapped[str] = mapped_column(Text, nullable=True)
    mitre_techniques: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of MITRE ATT&CK technique IDs
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
