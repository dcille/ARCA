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
    status: str  # PASS, FAIL
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    remediation_url: Optional[str] = None
    compliance_frameworks: list[str] = field(default_factory=list)

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
