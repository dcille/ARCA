"""Base class for SaaS security checks."""
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger(__name__)


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
        self._scan_logger = None

    def _run_check_groups(
        self,
        check_groups: list[Callable[[], list[dict]]],
        scanner_module: str = "",
    ) -> list[dict]:
        """Run check groups with scan-logger instrumentation.

        Each ``_check_*`` method is wrapped with module_start / module_end
        entries so the resulting scan log mirrors the detail level of the
        cloud-provider CIS evaluator engines.
        """
        slog = getattr(self, "_scan_logger", None)
        module = scanner_module or f"{self.provider_type}_scanner.py"
        results: list[dict] = []

        for check_fn in check_groups:
            group_name = check_fn.__name__  # e.g. "_check_dns_security"
            module_key = f"{self.provider_type}::{group_name}"

            if slog:
                slog.log_module_start(module_key, f"Running {group_name}")

            group_results: list[dict] = []
            status = "success"
            try:
                group_results = check_fn()
                results.extend(group_results)
            except Exception as e:
                status = "error"
                logger.error(f"{self.provider_type} check group {group_name} failed: {e}")
                if slog:
                    slog.log_error(module_key, f"{group_name} raised {type(e).__name__}: {e}")

            if slog:
                slog.log_module_end(
                    module_key,
                    result_count=len(group_results),
                    status=status,
                )

        return results

    def run_all_checks(self) -> list[dict]:
        raise NotImplementedError

    def test_connection(self) -> tuple[bool, str]:
        raise NotImplementedError
