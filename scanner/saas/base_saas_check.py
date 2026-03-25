"""Base class for SaaS security checks."""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SaaSCheckResult:
    """Result of a SaaS security check."""
    check_id: str
    check_title: str
    service_area: str
    severity: str  # critical, high, medium, low, informational
    status: str  # PASS, FAIL, MANUAL (requires manual review)
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    remediation_url: Optional[str] = None
    compliance_frameworks: list[str] = field(default_factory=list)
    assessment_type: str = "automated"  # automated, manual
    cis_control_id: Optional[str] = None  # CIS benchmark control ID (e.g., "1.1.1")
    cis_level: Optional[str] = None  # L1 (essential), L2 (enhanced)
    cis_profile: Optional[str] = None  # E3, E5, Enterprise, etc.

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "check_title": self.check_title,
            "service_area": self.service_area,
            "severity": self.severity,
            "status": self.status,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "description": self.description,
            "remediation": self.remediation,
            "remediation_url": self.remediation_url,
            "compliance_frameworks": self.compliance_frameworks,
            "assessment_type": self.assessment_type,
            "cis_control_id": self.cis_control_id,
            "cis_level": self.cis_level,
            "cis_profile": self.cis_profile,
        }


class BaseSaaSScanner:
    """Base class for all SaaS scanners."""

    provider_type: str = ""

    def __init__(self, credentials: dict):
        self.credentials = credentials

    def run_all_checks(self) -> list[dict]:
        raise NotImplementedError

    def test_connection(self) -> tuple[bool, str]:
        raise NotImplementedError
