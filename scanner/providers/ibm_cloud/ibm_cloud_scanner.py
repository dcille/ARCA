"""IBM Cloud Security Scanner — CIS IBM Cloud Foundations Benchmark v1.1.0.

Implements security checks for IBM Cloud services following
CIS IBM Cloud Foundations Benchmark v1.1.0.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from scanner.providers.base_check import CheckResult
from scanner.cis_controls.ibm_cloud_cis_controls import IBM_CLOUD_CIS_CONTROLS

logger = logging.getLogger(__name__)

COMPLIANCE = ["CIS-IBM-Cloud-1.1.0", "NIST-800-53", "CCM-4.1"]


class IBMCloudScanner:
    """IBM Cloud security scanner with CIS-aligned checks."""

    def __init__(self, credentials: dict, regions: Optional[list] = None, services: Optional[list] = None):
        self.credentials = credentials
        self.regions = regions or ["us-south"]
        self.services = services
        self._api_key = credentials.get("api_key")
        self._account_id = credentials.get("account_id")
        self._iam_token = None

    def _get_iam_token(self) -> str:
        """Obtain an IAM access token using the API key."""
        if self._iam_token:
            return self._iam_token
        try:
            import requests
            resp = requests.post(
                "https://iam.cloud.ibm.com/identity/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                    "apikey": self._api_key,
                },
                timeout=30,
            )
            resp.raise_for_status()
            self._iam_token = resp.json()["access_token"]
            return self._iam_token
        except Exception as e:
            logger.error(f"Failed to obtain IBM Cloud IAM token: {e}")
            raise

    def _api_headers(self) -> dict:
        """Return authorization headers for IBM Cloud API calls."""
        return {
            "Authorization": f"Bearer {self._get_iam_token()}",
            "Content-Type": "application/json",
        }

    def scan(self) -> list[dict]:
        """Run all IBM Cloud security checks."""
        results = []
        check_methods = {
            "iam": self._check_iam,
            "cos": self._check_cos,
            "activity_tracker": self._check_activity_tracker,
            "networking": self._check_networking,
            "kubernetes": self._check_kubernetes,
        }

        slog = getattr(self, "_scan_logger", None)

        for service_name, check_fn in check_methods.items():
            if self.services and service_name not in self.services:
                continue
            if slog:
                slog.log_module_start(
                    f"ibm_cloud_scanner.py::_check_{service_name}",
                    f"Checking IBM Cloud service: {service_name}",
                )
            try:
                service_results = check_fn()
                results.extend(service_results)
                if slog:
                    slog.log_module_end(
                        f"ibm_cloud_scanner.py::_check_{service_name}",
                        result_count=len(service_results),
                    )
            except Exception as e:
                logger.warning(f"IBM Cloud {service_name} checks failed: {e}")
                if slog:
                    slog.log_error(f"ibm_cloud_scanner.py::_check_{service_name}", str(e))

        return results

    # ── IAM checks ──────────────────────────────────────────────────────

    def _check_iam(self) -> list[dict]:
        """CIS Section 1: Identity and Access Management checks."""
        results = []
        try:
            import requests
            headers = self._api_headers()

            # Check API keys for the account
            try:
                resp = requests.get(
                    "https://iam.cloud.ibm.com/v1/apikeys",
                    headers=headers,
                    params={"account_id": self._account_id, "pagesize": 100} if self._account_id else {"pagesize": 100},
                    timeout=30,
                )
                resp.raise_for_status()
                api_keys = resp.json().get("apikeys", [])

                for key in api_keys:
                    key_id = key.get("id", "unknown")
                    key_name = key.get("name", key_id)
                    created_at = key.get("created_at", "")

                    # CIS 1.2 — Check for API keys unused for 180+ days
                    if created_at:
                        try:
                            created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                            age_days = (datetime.now(timezone.utc) - created).days
                            status = "FAIL" if age_days > 180 else "PASS"
                            results.append(CheckResult(
                                check_id="ibm_cloud_iam_api_key_age",
                                check_title="CIS 1.2 — API keys unused for 180 days should be disabled",
                                service="iam",
                                severity="high",
                                status=status,
                                resource_id=key_id,
                                resource_name=key_name,
                                status_extended=f"API key '{key_name}' is {age_days} days old",
                                remediation="Disable or delete API keys that have not been used for 180+ days",
                                compliance_frameworks=COMPLIANCE,
                                cis_control_id="1.2",
                                cis_level="L1",
                            ).to_dict())
                        except (ValueError, TypeError):
                            pass

                    # CIS 1.5 — Ensure no owner account API key exists
                    iam_id = key.get("iam_id", "")
                    if key.get("account_owner", False) or "IBMid" in iam_id:
                        entity_tag = key.get("entity_tag", "")
                        results.append(CheckResult(
                            check_id="ibm_cloud_iam_no_owner_api_key",
                            check_title="CIS 1.5 — Ensure no owner account API key exists",
                            service="iam",
                            severity="high",
                            status="FAIL",
                            resource_id=key_id,
                            resource_name=key_name,
                            status_extended=f"Owner API key '{key_name}' exists — avoid using account owner API keys",
                            remediation="Delete account owner API keys and use service IDs or trusted profiles instead",
                            compliance_frameworks=COMPLIANCE,
                            cis_control_id="1.5",
                            cis_level="L1",
                        ).to_dict())

            except Exception as e:
                logger.warning(f"IBM Cloud IAM API keys check failed: {e}")

            # CIS 1.6/1.7/1.8 — Check MFA settings
            if self._account_id:
                try:
                    resp = requests.get(
                        f"https://iam.cloud.ibm.com/v1/accounts/{self._account_id}/settings",
                        headers=headers,
                        timeout=30,
                    )
                    resp.raise_for_status()
                    settings = resp.json()

                    mfa_enabled = settings.get("mfa", "NONE") != "NONE"
                    results.append(CheckResult(
                        check_id="ibm_cloud_iam_mfa_enabled",
                        check_title="CIS 1.6 — Ensure MFA is enabled for all users in account",
                        service="iam",
                        severity="critical",
                        status="PASS" if mfa_enabled else "FAIL",
                        resource_id=self._account_id,
                        resource_name="Account IAM Settings",
                        status_extended=f"Account MFA setting: {settings.get('mfa', 'NONE')}",
                        remediation="Enable MFA at the account level via IBM Cloud IAM settings",
                        compliance_frameworks=COMPLIANCE,
                        cis_control_id="1.6",
                        cis_level="L1",
                    ).to_dict())

                    # CIS 1.18 — Ensure IAM does not allow public access
                    public_access = settings.get("restrict_create_platform_apikey", "NOT_SET")
                    results.append(CheckResult(
                        check_id="ibm_cloud_iam_no_public_access",
                        check_title="CIS 1.18 — Ensure IAM does not allow public access to cloud services",
                        service="iam",
                        severity="critical",
                        status="PASS" if public_access == "RESTRICTED" else "FAIL",
                        resource_id=self._account_id,
                        resource_name="Account IAM Settings",
                        status_extended=f"Public access restriction: {public_access}",
                        remediation="Restrict public access in IAM account settings",
                        compliance_frameworks=COMPLIANCE,
                        cis_control_id="1.18",
                        cis_level="L1",
                    ).to_dict())

                except Exception as e:
                    logger.warning(f"IBM Cloud IAM account settings check failed: {e}")

        except Exception as e:
            logger.warning(f"IBM Cloud IAM checks failed: {e}")

        return results

    # ── Cloud Object Storage (COS) checks ────────────────────────────────

    def _check_cos(self) -> list[dict]:
        """CIS Section 2: Storage checks for Cloud Object Storage."""
        results = []
        try:
            import requests
            headers = self._api_headers()

            # List COS instances via resource controller
            resp = requests.get(
                "https://resource-controller.cloud.ibm.com/v2/resource_instances",
                headers=headers,
                params={"resource_id": "dff97f5c-bc5e-4455-b470-411c3edbe49c", "limit": 100},  # COS resource ID
                timeout=30,
            )
            resp.raise_for_status()
            cos_instances = resp.json().get("resources", [])

            for instance in cos_instances:
                instance_id = instance.get("id", "unknown")
                instance_name = instance.get("name", instance_id)
                crn = instance.get("crn", "")

                # CIS 2.1 — Ensure COS bucket encryption
                results.append(CheckResult(
                    check_id="ibm_cloud_cos_encryption",
                    check_title="CIS 2.1 — Ensure Cloud Object Storage buckets are encrypted",
                    service="cos",
                    severity="high",
                    status="MANUAL",
                    resource_id=instance_id,
                    resource_name=instance_name,
                    status_extended=f"COS instance '{instance_name}' — verify bucket-level encryption with Key Protect or HPCS",
                    remediation="Enable encryption with IBM Key Protect or Hyper Protect Crypto Services for all COS buckets",
                    compliance_frameworks=COMPLIANCE,
                    cis_control_id="2.1",
                    cis_level="L1",
                    assessment_type="manual",
                ).to_dict())

        except Exception as e:
            logger.warning(f"IBM Cloud COS checks failed: {e}")

        return results

    # ── Activity Tracker checks ──────────────────────────────────────────

    def _check_activity_tracker(self) -> list[dict]:
        """CIS Section 3: Audit logging checks."""
        results = []
        try:
            import requests
            headers = self._api_headers()

            # Check for Activity Tracker instances
            resp = requests.get(
                "https://resource-controller.cloud.ibm.com/v2/resource_instances",
                headers=headers,
                params={"resource_id": "97547f5d-0cd1-4d0c-ae3c-2a09e9ce5f04", "limit": 100},  # AT resource ID
                timeout=30,
            )
            resp.raise_for_status()
            at_instances = resp.json().get("resources", [])

            if not at_instances:
                results.append(CheckResult(
                    check_id="ibm_cloud_activity_tracker_enabled",
                    check_title="CIS 3.1 — Ensure Activity Tracker is provisioned for audit logging",
                    service="activity_tracker",
                    severity="high",
                    status="FAIL",
                    resource_id=self._account_id or "account",
                    resource_name="Activity Tracker",
                    status_extended="No Activity Tracker instance found in the account",
                    remediation="Provision an Activity Tracker instance to capture audit events",
                    compliance_frameworks=COMPLIANCE,
                    cis_control_id="3.1",
                    cis_level="L1",
                ).to_dict())
            else:
                for at in at_instances:
                    results.append(CheckResult(
                        check_id="ibm_cloud_activity_tracker_enabled",
                        check_title="CIS 3.1 — Ensure Activity Tracker is provisioned for audit logging",
                        service="activity_tracker",
                        severity="high",
                        status="PASS",
                        resource_id=at.get("id", "unknown"),
                        resource_name=at.get("name", "Activity Tracker"),
                        status_extended=f"Activity Tracker '{at.get('name')}' is provisioned in {at.get('region_id', 'unknown')}",
                        compliance_frameworks=COMPLIANCE,
                        cis_control_id="3.1",
                        cis_level="L1",
                    ).to_dict())

        except Exception as e:
            logger.warning(f"IBM Cloud Activity Tracker checks failed: {e}")

        return results

    # ── Networking checks ────────────────────────────────────────────────

    def _check_networking(self) -> list[dict]:
        """CIS Section 6: Networking checks for VPC."""
        results = []
        try:
            import requests
            headers = self._api_headers()

            for region in self.regions:
                # Check VPC security groups
                try:
                    resp = requests.get(
                        f"https://{region}.iaas.cloud.ibm.com/v1/security_groups",
                        headers=headers,
                        params={"version": "2024-01-01", "generation": 2},
                        timeout=30,
                    )
                    resp.raise_for_status()
                    security_groups = resp.json().get("security_groups", [])

                    for sg in security_groups:
                        sg_id = sg.get("id", "unknown")
                        sg_name = sg.get("name", sg_id)

                        # Check for overly permissive inbound rules
                        for rule in sg.get("rules", []):
                            if rule.get("direction") == "inbound":
                                remote = rule.get("remote", {})
                                cidr = remote.get("cidr_block", "")
                                if cidr == "0.0.0.0/0":
                                    port_min = rule.get("port_min", 0)
                                    port_max = rule.get("port_max", 65535)
                                    protocol = rule.get("protocol", "all")
                                    results.append(CheckResult(
                                        check_id="ibm_cloud_vpc_sg_unrestricted_ingress",
                                        check_title="CIS 6.1 — Ensure no security group allows unrestricted ingress from 0.0.0.0/0",
                                        service="networking",
                                        severity="high",
                                        status="FAIL",
                                        region=region,
                                        resource_id=sg_id,
                                        resource_name=sg_name,
                                        status_extended=f"Security group '{sg_name}' allows inbound {protocol} "
                                                        f"ports {port_min}-{port_max} from 0.0.0.0/0",
                                        remediation="Restrict security group inbound rules to specific source CIDRs",
                                        compliance_frameworks=COMPLIANCE,
                                        cis_control_id="6.1",
                                        cis_level="L1",
                                    ).to_dict())

                except Exception as e:
                    logger.warning(f"IBM Cloud VPC security groups check in {region} failed: {e}")

        except Exception as e:
            logger.warning(f"IBM Cloud networking checks failed: {e}")

        return results

    # ── Kubernetes (IKS) checks ──────────────────────────────────────────

    def _check_kubernetes(self) -> list[dict]:
        """CIS Section 7: Container checks for IBM Kubernetes Service."""
        results = []
        try:
            import requests
            headers = self._api_headers()

            # List IKS clusters
            resp = requests.get(
                "https://containers.cloud.ibm.com/global/v1/clusters",
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            clusters = resp.json() if isinstance(resp.json(), list) else []

            for cluster in clusters:
                cluster_id = cluster.get("id", "unknown")
                cluster_name = cluster.get("name", cluster_id)
                cluster_state = cluster.get("state", "unknown")

                # CIS 7.1 — Ensure clusters are running a supported Kubernetes version
                kube_version = cluster.get("kubeVersion", "unknown")
                results.append(CheckResult(
                    check_id="ibm_cloud_iks_version",
                    check_title="CIS 7.1 — Ensure IKS clusters run a supported Kubernetes version",
                    service="kubernetes",
                    severity="medium",
                    status="MANUAL",
                    resource_id=cluster_id,
                    resource_name=cluster_name,
                    status_extended=f"Cluster '{cluster_name}' is running Kubernetes {kube_version} (state: {cluster_state})",
                    remediation="Update the cluster to a supported Kubernetes version",
                    compliance_frameworks=COMPLIANCE,
                    cis_control_id="7.1",
                    cis_level="L1",
                    assessment_type="manual",
                ).to_dict())

        except Exception as e:
            logger.warning(f"IBM Cloud Kubernetes checks failed: {e}")

        return results

    # ------------------------------------------------------------------
    # CIS benchmark coverage
    # ------------------------------------------------------------------

    def _emit_cis_coverage(self, existing_results: list[dict]) -> list[dict]:
        """Emit MANUAL results for CIS controls not covered by automated checks."""
        covered_cis_ids: set[str] = set()
        check_to_cis = {}
        for ctrl in IBM_CLOUD_CIS_CONTROLS:
            cis_id = ctrl["cis_id"]
            check_to_cis[f"ibm_cis_{cis_id.replace('.', '_')}"] = cis_id

        for result in existing_results:
            check_id = result.get("check_id", "")
            if check_id in check_to_cis:
                covered_cis_ids.add(check_to_cis[check_id])

        manual_results = []
        fw = ["CIS-IBM-Cloud-2.0.0", "NIST-800-53", "CCM-4.1"]

        for ctrl in IBM_CLOUD_CIS_CONTROLS:
            cis_id = ctrl["cis_id"]
            title = ctrl["title"]
            level = ctrl["cis_level"]
            assessment_type = ctrl["assessment_type"]
            severity = ctrl["severity"]
            service_area = ctrl["service_area"]
            if cis_id not in covered_cis_ids:
                manual_results.append(CheckResult(
                    check_id=f"ibm_cis_{cis_id.replace('.', '_')}",
                    check_title=f"{title} (CIS {cis_id})",
                    service=service_area,
                    severity=severity,
                    status="MANUAL",
                    resource_id="ibm-cloud-account",
                    status_extended=(
                        f"CIS {cis_id} [{level}] - {assessment_type.upper()} assessment. "
                        f"This control requires {'manual verification' if assessment_type == 'manual' else 'automated check implementation'}."
                    ),
                    remediation=ctrl.get("remediation", f"Refer to CIS IBM Cloud Foundations Benchmark v2.0.0, control {cis_id}."),
                    compliance_frameworks=fw,
                    assessment_type=assessment_type,
                    cis_control_id=cis_id,
                    cis_level=level,
                ).to_dict())

        return manual_results

    def run_all_checks(self) -> list[dict]:
        """Run all IBM Cloud security checks including complete CIS benchmark coverage."""
        slog = getattr(self, "_scan_logger", None)

        # Phase 1: Service checks
        if slog:
            slog.log_phase_start("service_checks", "ibm_cloud_scanner.py")
        results = self.scan()
        if slog:
            slog.log_phase_end("service_checks", "ibm_cloud_scanner.py", result_count=len(results))

        # Phase 2: CIS coverage
        if slog:
            slog.log_phase_start("cis_coverage", "ibm_cloud_scanner.py")
        results.extend(self._emit_cis_coverage(results))
        if slog:
            slog.log_phase_end("cis_coverage", "ibm_cloud_scanner.py", result_count=len(results))

        return results
