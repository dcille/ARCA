"""Base evaluator infrastructure for IBM Cloud CIS v2.0.0 control evaluation.

Uses the IBM Cloud REST API with IAM bearer tokens rather than a dedicated SDK.
The ``requests`` library is the only dependency.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, Any

import requests

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------

@dataclass
class EvalConfig:
    """Runtime configuration passed to every evaluator."""
    account_id: str = ""
    regions: list[str] = field(default_factory=lambda: ["us-south"])
    max_resources_per_check: int = 500
    timeout_seconds: int = 60


# -----------------------------------------------------------------
# Result builder helpers
# -----------------------------------------------------------------

def make_result(
    *,
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
    status: str,             # PASS | FAIL | MANUAL | ERROR | N/A
    resource_id: str,
    resource_name: str = "",
    status_extended: str = "",
    remediation: str = "",
    region: str = "",
    compliance_frameworks: Optional[list[str]] = None,
) -> dict:
    """Build a CheckResult dict compatible with the existing scanner output."""
    return {
        "check_id": check_id,
        "check_title": title,
        "service": service,
        "severity": severity,
        "status": status,
        "resource_id": resource_id,
        "resource_name": resource_name or (resource_id.split("/")[-1] if resource_id else ""),
        "region": region,
        "status_extended": status_extended,
        "remediation": remediation,
        "compliance_frameworks": compliance_frameworks or ["CIS-IBM-Cloud-2.0"],
        "cis_control_id": cis_id,
    }


def make_manual_result(cis_id, check_id, title, service, severity, account_id, reason):
    return make_result(
        cis_id=cis_id, check_id=check_id, title=title, service=service,
        severity=severity, status="MANUAL", resource_id=account_id,
        status_extended=f"Manual verification required: {reason}",
        remediation=f"Refer to CIS IBM Cloud Foundations Benchmark v2.0.0, control {cis_id}.",
    )


def make_error_result(cis_id, check_id, title, service, severity, account_id, error):
    return make_result(
        cis_id=cis_id, check_id=check_id, title=title, service=service,
        severity=severity, status="ERROR", resource_id=account_id,
        status_extended=f"Evaluation failed: {error}",
        remediation="Check that the IAM API key has the required permissions.",
    )


# -----------------------------------------------------------------
# IBM Cloud REST client cache with IAM token management
# -----------------------------------------------------------------

class IBMCloudClientCache:
    """Lazy-loading cache for IBM Cloud REST API calls with IAM token management."""

    IAM_TOKEN_URL = "https://iam.cloud.ibm.com/identity/token"

    def __init__(self, api_key: str, account_id: str, regions: list[str] | None = None):
        self._api_key = api_key
        self._account_id = account_id
        self._regions = regions or ["us-south"]
        self._token: str | None = None
        self._token_expiry: float = 0.0

    @property
    def account_id(self) -> str:
        return self._account_id

    @property
    def regions(self) -> list[str]:
        return self._regions

    def _refresh_token(self) -> None:
        """Obtain or refresh the IAM bearer token."""
        resp = requests.post(
            self.IAM_TOKEN_URL,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey": self._api_key,
            },
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._token_expiry = time.time() + body.get("expires_in", 3600) - 120

    @property
    def token(self) -> str:
        """Return a valid IAM bearer token, refreshing if needed."""
        if not self._token or time.time() >= self._token_expiry:
            self._refresh_token()
        return self._token  # type: ignore[return-value]

    def headers(self) -> dict[str, str]:
        """Authorization + JSON content-type headers."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def get(self, url: str, **kwargs) -> requests.Response:
        """Perform an authenticated GET request."""
        kwargs.setdefault("headers", self.headers())
        kwargs.setdefault("timeout", 30)
        return requests.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """Perform an authenticated POST request."""
        kwargs.setdefault("headers", self.headers())
        kwargs.setdefault("timeout", 30)
        return requests.post(url, **kwargs)

    # ------- Convenience API methods -------

    def iam_get(self, path: str, **params) -> dict:
        """GET from the IAM API."""
        url = f"https://iam.cloud.ibm.com{path}"
        resp = self.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def containers_get(self, path: str, region: str | None = None, **params) -> dict:
        """GET from the IBM Cloud Kubernetes Service API."""
        region = region or self._regions[0]
        url = f"https://containers.cloud.ibm.com/global{path}"
        resp = self.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def kms_get(self, instance_id: str, path: str, region: str | None = None, **params) -> dict:
        """GET from a Key Protect instance."""
        region = region or self._regions[0]
        url = f"https://{region}.kms.cloud.ibm.com/api/v2{path}"
        hdrs = self.headers()
        hdrs["bluemix-instance"] = instance_id
        resp = requests.get(url, headers=hdrs, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def secrets_manager_get(self, instance_url: str, path: str) -> dict:
        """GET from a Secrets Manager instance."""
        url = f"{instance_url}/api/v2{path}"
        resp = self.get(url)
        resp.raise_for_status()
        return resp.json()

    def resource_controller_get(self, path: str, **params) -> dict:
        """GET from the Resource Controller API."""
        url = f"https://resource-controller.cloud.ibm.com{path}"
        resp = self.get(url, params=params)
        resp.raise_for_status()
        return resp.json()


# -----------------------------------------------------------------
# Evaluator type alias + safe runner
# -----------------------------------------------------------------

EvaluatorFn = Callable[[IBMCloudClientCache, EvalConfig], list[dict]]


def safe_evaluate(evaluator, clients, config, cis_id, check_id, title, service, severity):
    """Run an evaluator function, catching exceptions."""
    try:
        return evaluator(clients, config)
    except Exception as e:
        logger.warning("Evaluator %s failed: %s", cis_id, e)
        return [make_error_result(cis_id, check_id, title, service, severity, config.account_id, str(e))]
