"""IBM Cloud CIS Evaluator Base — HTTP client helpers, result builders.

IBM Cloud SDK uses REST API with IAM bearer tokens.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class EvalConfig:
    api_key: str = ""
    account_id: str = ""
    regions: list[str] = field(default_factory=lambda: ["us-south"])


class IBMCloudClientCache:
    """Cache IAM token and provide authenticated HTTP helpers."""

    def __init__(self, cfg: EvalConfig):
        self._cfg = cfg
        self._token: Optional[str] = None

    @property
    def token(self) -> str:
        if not self._token:
            import requests
            resp = requests.post(
                "https://iam.cloud.ibm.com/identity/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                      "apikey": self._cfg.api_key},
                timeout=30)
            resp.raise_for_status()
            self._token = resp.json()["access_token"]
        return self._token

    @property
    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def get(self, url: str, params: dict = None, timeout: int = 30):
        import requests
        return requests.get(url, headers=self.headers, params=params, timeout=timeout)


# ── Date helpers ──

def days_since(dt_str: Optional[str]) -> int:
    if not dt_str: return 9999
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception: return 9999


# ── Result builders ──

def make_result(cis_id, title, resource_id, resource_name, passed,
                detail="", severity="medium", service="IBMCloud", remediation=""):
    return {
        "check_id": f"ibm_cis_{cis_id.replace('.', '_')}",
        "check_title": title,
        "service": service,
        "severity": severity,
        "status": "PASS" if passed else "FAIL",
        "resource_id": resource_id,
        "resource_name": resource_name,
        "status_extended": detail,
        "remediation": remediation,
        "compliance_frameworks": ["CIS-IBM-Cloud-2.0"],
        "cis_control_id": cis_id,
    }


def make_manual_result(cis_id, title, service="IBMCloud", severity="medium"):
    return {
        "check_id": f"ibm_cis_{cis_id.replace('.', '_')}",
        "check_title": title,
        "service": service,
        "severity": severity,
        "status": "MANUAL",
        "resource_id": "ibm-cloud-account",
        "resource_name": "Manual verification required",
        "status_extended": f"CIS {cis_id}: Requires manual verification via IBM Cloud Console",
        "remediation": f"Refer to CIS IBM Cloud Foundations Benchmark v2.0.0, control {cis_id}",
        "compliance_frameworks": ["CIS-IBM-Cloud-2.0"],
        "cis_control_id": cis_id,
    }


def safe_evaluate(fn, clients, cfg):
    try:
        return fn(clients, cfg)
    except Exception as e:
        logger.error(f"Evaluator {fn.__name__} failed: {e}")
        return []
