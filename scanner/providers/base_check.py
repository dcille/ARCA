"""Base check classes for all security checks."""
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class CheckResult:
    """Represents the result of a single security check against a resource."""
    check_id: str
    check_title: str
    service: str
    severity: str  # critical, high, medium, low, informational
    status: str  # PASS, FAIL
    region: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    status_extended: Optional[str] = None
    remediation: Optional[str] = None
    remediation_url: Optional[str] = None
    compliance_frameworks: list[str] = field(default_factory=list)
    check_description: Optional[str] = None
    evidence_log: Optional[str] = None  # JSON string: {"api_call": "...", "response": "..."}
    mitre_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "check_title": self.check_title,
            "service": self.service,
            "severity": self.severity,
            "status": self.status,
            "region": self.region,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "status_extended": self.status_extended,
            "remediation": self.remediation,
            "remediation_url": self.remediation_url,
            "compliance_frameworks": self.compliance_frameworks,
            "check_description": self.check_description,
            "evidence_log": self.evidence_log,
            "mitre_techniques": self.mitre_techniques,
        }


class BaseCheck:
    """Base class for all security checks."""

    check_id: str = ""
    check_title: str = ""
    service: str = ""
    severity: str = "medium"
    compliance_frameworks: list[str] = []

    def execute(self, **kwargs) -> list[CheckResult]:
        raise NotImplementedError
