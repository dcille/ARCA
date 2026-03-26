"""Base evaluator infrastructure for AWS CIS control evaluation.

Mirrors the Azure evaluator pattern but uses boto3 for AWS SDK access.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


@dataclass
class EvalConfig:
    """Runtime configuration passed to every evaluator."""
    account_id: str = ""
    regions: list[str] = field(default_factory=lambda: ["us-east-1"])
    max_resources_per_check: int = 500
    timeout_seconds: int = 60


def make_result(
    *, cis_id: str, check_id: str, title: str, service: str, severity: str,
    status: str, resource_id: str, resource_name: str = "",
    status_extended: str = "", remediation: str = "", region: str = "",
    compliance_frameworks: Optional[list[str]] = None,
) -> dict:
    return {
        "check_id": check_id, "check_title": title, "service": service,
        "severity": severity, "status": status, "resource_id": resource_id,
        "resource_name": resource_name or (resource_id.split("/")[-1] if resource_id else ""),
        "region": region, "status_extended": status_extended,
        "remediation": remediation,
        "compliance_frameworks": compliance_frameworks or ["CIS-AWS-6.0"],
        "cis_control_id": cis_id,
    }


def make_manual_result(cis_id, check_id, title, service, severity, account_id, reason):
    return make_result(
        cis_id=cis_id, check_id=check_id, title=title, service=service,
        severity=severity, status="MANUAL", resource_id=account_id,
        status_extended=f"Manual verification required: {reason}",
        remediation=f"Refer to CIS AWS Foundations Benchmark v6.0.0, control {cis_id}.",
    )


def make_error_result(cis_id, check_id, title, service, severity, account_id, error):
    return make_result(
        cis_id=cis_id, check_id=check_id, title=title, service=service,
        severity=severity, status="ERROR", resource_id=account_id,
        status_extended=f"Evaluation failed: {error}",
        remediation="Check that the IAM credentials have the required permissions.",
    )


class AWSClientCache:
    """Lazy-loading cache for boto3 clients. One instance per scan."""

    def __init__(self, session: boto3.Session, regions: list[str] = None):
        self._session = session
        self._regions = regions or ["us-east-1"]
        self._cache: dict[str, Any] = {}

    def client(self, service: str, region: str = None) -> Any:
        region = region or self._regions[0]
        key = f"{service}:{region}"
        if key not in self._cache:
            self._cache[key] = self._session.client(service, region_name=region)
        return self._cache[key]

    @property
    def iam(self):
        return self.client("iam")

    @property
    def s3(self):
        return self.client("s3")

    @property
    def regions(self):
        return self._regions

    @property
    def session(self):
        return self._session


EvaluatorFn = Callable[[AWSClientCache, EvalConfig], list[dict]]


def safe_evaluate(evaluator, clients, config, cis_id, check_id, title, service, severity):
    try:
        return evaluator(clients, config)
    except Exception as e:
        logger.warning("Evaluator %s failed: %s", cis_id, e)
        return [make_error_result(cis_id, check_id, title, service, severity, config.account_id, str(e))]
