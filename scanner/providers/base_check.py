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
    status: str  # PASS, FAIL, MANUAL (requires manual review)
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
    assessment_type: str = "automated"  # automated, manual
    cis_control_id: Optional[str] = None  # CIS benchmark control ID (e.g., "1.1")
    cis_level: Optional[str] = None  # L1 (essential), L2 (enhanced)

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
            "assessment_type": self.assessment_type,
            "cis_control_id": self.cis_control_id,
            "cis_level": self.cis_level,
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
