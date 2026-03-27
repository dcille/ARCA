"""GCP Security Scanner — comprehensive CIS/NIST/CCM-aligned checks.

Implements 80+ security checks across GCP services following CIS GCP Foundations
Benchmark v3.0, NIST 800-53, SOC 2, and CSA CCM v4.1 frameworks.

Provides complete CIS GCP Foundation Benchmark v3.0.0 coverage: automated checks
emit PASS/FAIL results while controls not yet automated are emitted as MANUAL
results so that every benchmark control appears in scan output.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from scanner.providers.base_check import CheckResult
from scanner.cis_controls.gcp_cis_controls import GCP_CIS_CONTROLS

logger = logging.getLogger(__name__)

# Default compliance frameworks applied to all checks unless overridden
_DEFAULT_FRAMEWORKS = ["CIS-GCP-3.0", "NIST-800-53", "SOC2", "CCM-4.1"]


class GCPScanner:
    """GCP cloud security scanner with complete CIS GCP Foundation Benchmark v3.0.0 coverage."""

    compliance_frameworks = ["CIS-GCP-3.0", "NIST-800-53", "SOC2", "CCM-4.1"]

    def __init__(self, credentials: dict, services: Optional[list] = None):
        self.credentials = credentials
        self.services = services
        self.project_id = credentials.get("project_id")

    def _get_credentials(self):
        from google.oauth2 import service_account
        import json
        cred_info = self.credentials.get("service_account_key")
        if isinstance(cred_info, str):
            cred_info = json.loads(cred_info)
        return service_account.Credentials.from_service_account_info(cred_info)

    def scan(self) -> list[dict]:
        results = []
        check_methods = {
            "iam": self._check_iam,
            "compute": self._check_compute,
            "storage": self._check_storage,
            "sql": self._check_sql,
            "logging": self._check_logging,
            "kms": self._check_kms,
            "gke": self._check_gke,
            "networking": self._check_networking,
            "bigquery": self._check_bigquery,
            "pubsub": self._check_pubsub,
            "dns": self._check_dns,
            "dataproc": self._check_dataproc,
            "cloudfunctions": self._check_cloud_functions,
            "cloudrun": self._check_cloud_run,
            "secretmanager": self._check_secret_manager,
        }

        slog = getattr(self, "_scan_logger", None)

        for service_name, check_fn in check_methods.items():
            if self.services and service_name not in self.services:
                continue
            if slog:
                slog.log_module_start(
                    f"gcp_scanner.py::_check_{service_name}",
                    f"Checking GCP service: {service_name}",
                )
            try:
                service_results = check_fn()
                results.extend(service_results)
                if slog:
                    slog.log_module_end(
                        f"gcp_scanner.py::_check_{service_name}",
                        result_count=len(service_results),
                    )
            except Exception as e:
                logger.warning(f"GCP {service_name} checks failed: {e}")
                if slog:
                    slog.log_error(f"gcp_scanner.py::_check_{service_name}", str(e))

        return results

    # ------------------------------------------------------------------
    # IAM checks (15)
    # ------------------------------------------------------------------

    def _check_iam(self) -> list[dict]:
        results = []
        try:
            from google.cloud import resourcemanager_v3
            credentials = self._get_credentials()
            client = resourcemanager_v3.ProjectsClient(credentials=credentials)

            from google.iam.v1 import iam_policy_pb2
            policy = client.get_iam_policy(
                request=iam_policy_pb2.GetIamPolicyRequest(resource=f"projects/{self.project_id}")
            )

            primitive_roles = {"roles/owner", "roles/editor", "roles/viewer"}
            sa_admin_role = "roles/iam.serviceAccountAdmin"
            sa_key_admin_role = "roles/iam.serviceAccountKeyAdmin"
            sa_token_creator = "roles/iam.serviceAccountTokenCreator"

            has_public = False
            has_primitive_roles = False
            has_sa_admin_key = False
            has_separation_violation = False

            for binding in policy.bindings:
                for member in binding.members:
                    # 1. gcp_iam_no_public_access
                    if member in ("allUsers", "allAuthenticatedUsers"):
                        has_public = True
                        results.append(CheckResult(
                            check_id="gcp_iam_no_public_access",
                            check_title="IAM policy does not grant public access",
                            service="iam", severity="critical", status="FAIL",
                            resource_id=f"projects/{self.project_id}",
                            status_extended=f"Role {binding.role} is granted to {member}",
                            remediation="Remove allUsers and allAuthenticatedUsers from IAM bindings",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())

                    # 2. gcp_iam_no_primitive_roles
                    if binding.role in primitive_roles and member.startswith("user:"):
                        has_primitive_roles = True
                        results.append(CheckResult(
                            check_id="gcp_iam_no_primitive_roles",
                            check_title="IAM policy does not use primitive roles for users",
                            service="iam", severity="high", status="FAIL",
                            resource_id=f"projects/{self.project_id}",
                            status_extended=f"User {member} has primitive role {binding.role}",
                            remediation="Replace primitive roles (Owner/Editor/Viewer) with predefined or custom roles",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())

                    # 3. gcp_iam_no_sa_admin_key — SA should not have both admin and key admin
                    if binding.role in (sa_admin_role, sa_key_admin_role):
                        has_sa_admin_key = True

                    # 5. gcp_iam_separation_of_duties — SA admin + token creator on same member
                    if binding.role == sa_token_creator and member.startswith("serviceAccount:"):
                        # Check if same SA also has admin
                        for other_binding in policy.bindings:
                            if other_binding.role == sa_admin_role and member in other_binding.members:
                                has_separation_violation = True
                                results.append(CheckResult(
                                    check_id="gcp_iam_separation_of_duties",
                                    check_title="Separation of duties enforced for service account admin",
                                    service="iam", severity="high", status="FAIL",
                                    resource_id=f"projects/{self.project_id}",
                                    status_extended=f"{member} has both SA Admin and Token Creator roles",
                                    remediation="Ensure no identity has both Service Account Admin and Service Account Token Creator roles",
                                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                                ).to_dict())

                    # 8. gcp_iam_corp_login_required — non-corp accounts (gmail.com)
                    if member.startswith("user:") and member.endswith("@gmail.com"):
                        results.append(CheckResult(
                            check_id="gcp_iam_corp_login_required",
                            check_title="Corporate login identities are used",
                            service="iam", severity="high", status="FAIL",
                            resource_id=f"projects/{self.project_id}",
                            status_extended=f"Non-corporate account {member} has access",
                            remediation="Use corporate Google Workspace or Cloud Identity accounts instead of personal gmail.com accounts",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())

            if not has_public:
                results.append(CheckResult(
                    check_id="gcp_iam_no_public_access",
                    check_title="IAM policy does not grant public access",
                    service="iam", severity="critical", status="PASS",
                    resource_id=f"projects/{self.project_id}",
                    status_extended="No public IAM bindings found",
                    remediation="Remove allUsers and allAuthenticatedUsers from IAM bindings",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

            if not has_primitive_roles:
                results.append(CheckResult(
                    check_id="gcp_iam_no_primitive_roles",
                    check_title="IAM policy does not use primitive roles for users",
                    service="iam", severity="high", status="PASS",
                    resource_id=f"projects/{self.project_id}",
                    status_extended="No primitive roles assigned to users",
                    remediation="Replace primitive roles (Owner/Editor/Viewer) with predefined or custom roles",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

            if not has_separation_violation:
                results.append(CheckResult(
                    check_id="gcp_iam_separation_of_duties",
                    check_title="Separation of duties enforced for service account admin",
                    service="iam", severity="high", status="PASS",
                    resource_id=f"projects/{self.project_id}",
                    status_extended="No separation-of-duties violations found",
                    remediation="Ensure no identity has both Service Account Admin and Service Account Token Creator roles",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

            # 3. gcp_iam_no_sa_admin_key — check SA keys
            from google.cloud import iam_admin_v1
            iam_client = iam_admin_v1.IAMClient(credentials=credentials)
            sa_list = iam_client.list_service_accounts(
                request={"name": f"projects/{self.project_id}"}
            )

            user_managed_key_found = False
            key_rotation_fail = False
            ninety_days_ago = datetime.now(tz=timezone.utc) - timedelta(days=90)

            for sa in sa_list:
                keys = iam_client.list_service_account_keys(
                    request={
                        "name": sa.name,
                        "key_types": [iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED],
                    }
                )
                for key in keys.keys:
                    user_managed_key_found = True
                    # 4. gcp_iam_sa_key_rotation
                    created = key.valid_after_time
                    if created and created < ninety_days_ago:
                        key_rotation_fail = True
                        results.append(CheckResult(
                            check_id="gcp_iam_sa_key_rotation",
                            check_title="Service account keys are rotated within 90 days",
                            service="iam", severity="high", status="FAIL",
                            resource_id=sa.name,
                            resource_name=sa.email,
                            status_extended=f"SA key {key.name.split('/')[-1]} created {created}, older than 90 days",
                            remediation="Rotate service account keys every 90 days or less",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())

                    # Per-key result for gcp_iam_no_sa_admin_key
                    if has_sa_admin_key:
                        results.append(CheckResult(
                            check_id="gcp_iam_no_sa_admin_key",
                            check_title="Service accounts with admin privileges do not have user-managed keys",
                            service="iam", severity="high", status="FAIL",
                            resource_id=sa.name,
                            resource_name=sa.email,
                            status_extended=f"SA {sa.email} has admin role and user-managed key",
                            remediation="Remove user-managed keys from service accounts with admin privileges",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())

            # 5. gcp_iam_no_user_managed_sa_keys (project-level summary)
            results.append(CheckResult(
                check_id="gcp_iam_no_user_managed_sa_keys",
                check_title="Service accounts do not have user-managed keys",
                service="iam", severity="medium",
                status="FAIL" if user_managed_key_found else "PASS",
                resource_id=f"projects/{self.project_id}",
                status_extended=f"User-managed SA keys found: {user_managed_key_found}",
                remediation="Use GCP-managed keys or Workload Identity Federation instead of user-managed keys",
                compliance_frameworks=_DEFAULT_FRAMEWORKS,
            ).to_dict())

            if not key_rotation_fail:
                results.append(CheckResult(
                    check_id="gcp_iam_sa_key_rotation",
                    check_title="Service account keys are rotated within 90 days",
                    service="iam", severity="high", status="PASS",
                    resource_id=f"projects/{self.project_id}",
                    status_extended="All service account keys are within 90-day rotation window",
                    remediation="Rotate service account keys every 90 days or less",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

            if not has_sa_admin_key:
                results.append(CheckResult(
                    check_id="gcp_iam_no_sa_admin_key",
                    check_title="Service accounts with admin privileges do not have user-managed keys",
                    service="iam", severity="high", status="PASS",
                    resource_id=f"projects/{self.project_id}",
                    status_extended="No admin service accounts with user-managed keys",
                    remediation="Remove user-managed keys from service accounts with admin privileges",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

            # 7. gcp_iam_api_keys_restricted
            try:
                from googleapiclient.discovery import build
                api_keys_svc = build("apikeys", "v2", credentials=credentials)
                api_keys = api_keys_svc.projects().locations().keys().list(
                    parent=f"projects/{self.project_id}/locations/global"
                ).execute()
                unrestricted_keys = []
                for api_key in api_keys.get("keys", []):
                    restrictions = api_key.get("restrictions", {})
                    if not restrictions.get("apiTargets") and not restrictions.get("browserKeyRestrictions") \
                            and not restrictions.get("serverKeyRestrictions") and not restrictions.get("androidKeyRestrictions") \
                            and not restrictions.get("iosKeyRestrictions"):
                        unrestricted_keys.append(api_key.get("displayName", api_key.get("uid", "unknown")))
                        results.append(CheckResult(
                            check_id="gcp_iam_api_keys_restricted",
                            check_title="API keys have application restrictions",
                            service="iam", severity="medium", status="FAIL",
                            resource_id=api_key.get("name", ""),
                            resource_name=api_key.get("displayName", ""),
                            status_extended=f"API key {api_key.get('displayName', 'unknown')} has no restrictions",
                            remediation="Add application and API restrictions to all API keys",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())
                if not unrestricted_keys:
                    results.append(CheckResult(
                        check_id="gcp_iam_api_keys_restricted",
                        check_title="API keys have application restrictions",
                        service="iam", severity="medium", status="PASS",
                        resource_id=f"projects/{self.project_id}",
                        status_extended="All API keys have restrictions configured",
                        remediation="Add application and API restrictions to all API keys",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
            except Exception as e:
                logger.warning(f"GCP API keys check failed: {e}")

            # 9. gcp_iam_sa_user_role — SA has iam.serviceAccountUser role (CIS 1.6)
            has_sa_user_role = False
            for binding in policy.bindings:
                if binding.role == "roles/iam.serviceAccountUser":
                    has_sa_user_role = True
                    for member in binding.members:
                        results.append(CheckResult(
                            check_id="gcp_iam_sa_user_role",
                            check_title="Service Account User role is not assigned at project level",
                            service="iam", severity="high", status="FAIL",
                            resource_id=f"projects/{self.project_id}",
                            status_extended=f"Member {member} has roles/iam.serviceAccountUser at project level",
                            remediation="Remove roles/iam.serviceAccountUser at project level; grant it on specific service accounts instead",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())
            if not has_sa_user_role:
                results.append(CheckResult(
                    check_id="gcp_iam_sa_user_role",
                    check_title="Service Account User role is not assigned at project level",
                    service="iam", severity="high", status="PASS",
                    resource_id=f"projects/{self.project_id}",
                    status_extended="No member has roles/iam.serviceAccountUser at project level",
                    remediation="Remove roles/iam.serviceAccountUser at project level; grant it on specific service accounts instead",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

            # 10. gcp_iam_sa_token_creator_role — SA Token Creator role at project level (CIS 1.7)
            has_sa_token_creator_role = False
            for binding in policy.bindings:
                if binding.role == "roles/iam.serviceAccountTokenCreator":
                    has_sa_token_creator_role = True
                    for member in binding.members:
                        results.append(CheckResult(
                            check_id="gcp_iam_sa_token_creator_role",
                            check_title="Service Account Token Creator role is not assigned at project level",
                            service="iam", severity="high", status="FAIL",
                            resource_id=f"projects/{self.project_id}",
                            status_extended=f"Member {member} has roles/iam.serviceAccountTokenCreator at project level",
                            remediation="Remove roles/iam.serviceAccountTokenCreator at project level; grant it on specific service accounts instead",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())
            if not has_sa_token_creator_role:
                results.append(CheckResult(
                    check_id="gcp_iam_sa_token_creator_role",
                    check_title="Service Account Token Creator role is not assigned at project level",
                    service="iam", severity="high", status="PASS",
                    resource_id=f"projects/{self.project_id}",
                    status_extended="No member has roles/iam.serviceAccountTokenCreator at project level",
                    remediation="Remove roles/iam.serviceAccountTokenCreator at project level; grant it on specific service accounts instead",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

            # 11. gcp_iam_kms_separation_of_duties — KMS admin and CryptoKey Encrypter/Decrypter (CIS 1.12)
            kms_admin_members = set()
            kms_encrypter_members = set()
            for binding in policy.bindings:
                if binding.role == "roles/cloudkms.admin":
                    kms_admin_members.update(binding.members)
                if binding.role == "roles/cloudkms.cryptoKeyEncrypterDecrypter":
                    kms_encrypter_members.update(binding.members)
            kms_overlap = kms_admin_members & kms_encrypter_members
            if kms_overlap:
                for member in kms_overlap:
                    results.append(CheckResult(
                        check_id="gcp_iam_kms_separation_of_duties",
                        check_title="KMS admin and CryptoKey Encrypter/Decrypter roles are separated",
                        service="iam", severity="high", status="FAIL",
                        resource_id=f"projects/{self.project_id}",
                        status_extended=f"Member {member} has both cloudkms.admin and cloudkms.cryptoKeyEncrypterDecrypter roles",
                        remediation="Ensure no member has both roles/cloudkms.admin and roles/cloudkms.cryptoKeyEncrypterDecrypter",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
            else:
                results.append(CheckResult(
                    check_id="gcp_iam_kms_separation_of_duties",
                    check_title="KMS admin and CryptoKey Encrypter/Decrypter roles are separated",
                    service="iam", severity="high", status="PASS",
                    resource_id=f"projects/{self.project_id}",
                    status_extended="No member has both cloudkms.admin and cloudkms.cryptoKeyEncrypterDecrypter roles",
                    remediation="Ensure no member has both roles/cloudkms.admin and roles/cloudkms.cryptoKeyEncrypterDecrypter",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

            # 12. gcp_iam_api_keys_exist — Check if API keys are being used (CIS 1.13)
            try:
                from googleapiclient.discovery import build as _build_api
                api_keys_svc2 = _build_api("apikeys", "v2", credentials=credentials)
                api_keys2 = api_keys_svc2.projects().locations().keys().list(
                    parent=f"projects/{self.project_id}/locations/global"
                ).execute()
                api_key_list = api_keys2.get("keys", [])
                has_api_keys = len(api_key_list) > 0
                results.append(CheckResult(
                    check_id="gcp_iam_api_keys_exist",
                    check_title="API keys are not used (prefer OAuth or service accounts)",
                    service="iam", severity="low", status="FAIL" if has_api_keys else "PASS",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Project has {len(api_key_list)} API key(s) — consider using OAuth or service accounts instead",
                    remediation="Eliminate API key usage and use OAuth 2.0 or service account credentials instead",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 13. gcp_iam_api_keys_rotated — API keys rotated within 90 days (CIS 1.16)
                api_key_rotation_fail = False
                for api_key in api_key_list:
                    create_time_str = api_key.get("createTime", "")
                    if create_time_str:
                        try:
                            create_time = datetime.fromisoformat(create_time_str.replace("Z", "+00:00"))
                            if create_time < ninety_days_ago:
                                api_key_rotation_fail = True
                                results.append(CheckResult(
                                    check_id="gcp_iam_api_keys_rotated",
                                    check_title="API keys are rotated within 90 days",
                                    service="iam", severity="medium", status="FAIL",
                                    resource_id=api_key.get("name", ""),
                                    resource_name=api_key.get("displayName", ""),
                                    status_extended=f"API key {api_key.get('displayName', 'unknown')} created {create_time_str}, older than 90 days",
                                    remediation="Rotate API keys every 90 days or less",
                                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                                ).to_dict())
                        except (ValueError, TypeError):
                            pass
                if not api_key_rotation_fail:
                    results.append(CheckResult(
                        check_id="gcp_iam_api_keys_rotated",
                        check_title="API keys are rotated within 90 days",
                        service="iam", severity="medium", status="PASS",
                        resource_id=f"projects/{self.project_id}",
                        status_extended="All API keys are within the 90-day rotation window",
                        remediation="Rotate API keys every 90 days or less",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
            except Exception as e:
                logger.warning(f"GCP API keys existence/rotation check failed: {e}")

            # 14. gcp_iam_essential_contacts — Essential Contacts configured (CIS 1.17)
            try:
                from googleapiclient.discovery import build as _build_ec
                ec_svc = _build_ec("essentialcontacts", "v1", credentials=credentials)
                contacts = ec_svc.projects().contacts().list(
                    parent=f"projects/{self.project_id}"
                ).execute()
                contact_list = contacts.get("contacts", [])
                has_contacts = len(contact_list) > 0
                results.append(CheckResult(
                    check_id="gcp_iam_essential_contacts",
                    check_title="Essential Contacts are configured for the project",
                    service="iam", severity="medium",
                    status="PASS" if has_contacts else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Essential Contacts configured: {len(contact_list)} contact(s)",
                    remediation="Configure Essential Contacts to receive important Google Cloud notifications",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())
            except Exception as e:
                logger.warning(f"GCP Essential Contacts check failed: {e}")

            # 15. gcp_iam_secrets_in_functions — No secrets in Cloud Functions env vars (CIS 1.18)
            try:
                from googleapiclient.discovery import build as _build_cf
                cf_svc = _build_cf("cloudfunctions", "v1", credentials=credentials)
                functions = cf_svc.projects().locations().functions().list(
                    parent=f"projects/{self.project_id}/locations/-"
                ).execute()
                suspicious_keys = {"SECRET", "PASSWORD", "API_KEY", "TOKEN", "PRIVATE_KEY", "CREDENTIALS"}
                secrets_found = False
                for func in functions.get("functions", []):
                    env_vars = func.get("environmentVariables", {})
                    func_name = func.get("name", "").split("/")[-1]
                    for var_name in env_vars:
                        if any(s in var_name.upper() for s in suspicious_keys):
                            secrets_found = True
                            results.append(CheckResult(
                                check_id="gcp_iam_secrets_in_functions",
                                check_title="Cloud Functions do not contain secrets in environment variables",
                                service="iam", severity="high", status="FAIL",
                                resource_id=func.get("name", ""),
                                resource_name=func_name,
                                status_extended=f"Function {func_name} has suspicious env var: {var_name}",
                                remediation="Use Secret Manager to store secrets instead of Cloud Function environment variables",
                                compliance_frameworks=_DEFAULT_FRAMEWORKS,
                            ).to_dict())
                if not secrets_found:
                    results.append(CheckResult(
                        check_id="gcp_iam_secrets_in_functions",
                        check_title="Cloud Functions do not contain secrets in environment variables",
                        service="iam", severity="high", status="PASS",
                        resource_id=f"projects/{self.project_id}",
                        status_extended="No suspicious secret-like environment variables found in Cloud Functions",
                        remediation="Use Secret Manager to store secrets instead of Cloud Function environment variables",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
            except Exception as e:
                logger.warning(f"GCP Cloud Functions secrets check failed: {e}")

        except Exception as e:
            logger.warning(f"GCP IAM checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # Compute checks (10)
    # ------------------------------------------------------------------

    def _check_compute(self) -> list[dict]:
        results = []
        try:
            from google.cloud import compute_v1
            credentials = self._get_credentials()
            instances_client = compute_v1.InstancesClient(credentials=credentials)

            agg = instances_client.aggregated_list(project=self.project_id)
            for zone, response in agg:
                for instance in response.instances or []:
                    name = instance.name
                    zone_name = zone.split("/")[-1]
                    res_id = f"projects/{self.project_id}/zones/{zone_name}/instances/{name}"

                    # 1. gcp_compute_no_external_ip
                    has_ext_ip = any(
                        ac.nat_i_p for ni in instance.network_interfaces or []
                        for ac in ni.access_configs or []
                    )
                    results.append(CheckResult(
                        check_id="gcp_compute_no_external_ip",
                        check_title="VM instance has no external IP",
                        service="compute", severity="medium",
                        status="FAIL" if has_ext_ip else "PASS",
                        resource_id=res_id, resource_name=name,
                        status_extended=f"Instance {name} external IP: {has_ext_ip}",
                        remediation="Remove external IP addresses from instances that don't need them",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

                    # 2. gcp_compute_os_login
                    os_login = any(
                        item.key == "enable-oslogin" and item.value.lower() == "true"
                        for item in (instance.metadata.items or []) if instance.metadata
                    )
                    results.append(CheckResult(
                        check_id="gcp_compute_os_login",
                        check_title="VM instance has OS Login enabled",
                        service="compute", severity="medium",
                        status="PASS" if os_login else "FAIL",
                        resource_id=res_id, resource_name=name,
                        status_extended=f"Instance {name} OS Login: {os_login}",
                        remediation="Enable OS Login for centralized SSH key management",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

                    # 3. gcp_compute_shielded_vm
                    shielded_cfg = instance.shielded_instance_config
                    shielded = (
                        shielded_cfg
                        and shielded_cfg.enable_secure_boot
                        and shielded_cfg.enable_vtpm
                        and shielded_cfg.enable_integrity_monitoring
                    ) if shielded_cfg else False
                    results.append(CheckResult(
                        check_id="gcp_compute_shielded_vm",
                        check_title="VM instance uses Shielded VM features",
                        service="compute", severity="medium",
                        status="PASS" if shielded else "FAIL",
                        resource_id=res_id, resource_name=name,
                        status_extended=f"Instance {name} Shielded VM (secure boot, vTPM, integrity): {shielded}",
                        remediation="Enable Secure Boot, vTPM, and Integrity Monitoring on the instance",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

                    # 4. gcp_compute_disk_encryption_cmek
                    all_cmek = True
                    for disk in instance.disks or []:
                        enc = disk.disk_encryption_key
                        if not enc or not enc.kms_key_name:
                            all_cmek = False
                            break
                    results.append(CheckResult(
                        check_id="gcp_compute_disk_encryption_cmek",
                        check_title="VM disks are encrypted with customer-managed keys (CMEK)",
                        service="compute", severity="medium",
                        status="PASS" if all_cmek else "FAIL",
                        resource_id=res_id, resource_name=name,
                        status_extended=f"Instance {name} CMEK disk encryption: {all_cmek}",
                        remediation="Use Customer-Managed Encryption Keys (CMEK) for all attached disks",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

                    # 5. gcp_compute_no_default_sa
                    sa_list = instance.service_accounts or []
                    uses_default_sa = any(
                        sa.email.endswith("-compute@developer.gserviceaccount.com")
                        for sa in sa_list
                    )
                    results.append(CheckResult(
                        check_id="gcp_compute_no_default_sa",
                        check_title="VM instance does not use default Compute Engine service account",
                        service="compute", severity="high",
                        status="FAIL" if uses_default_sa else "PASS",
                        resource_id=res_id, resource_name=name,
                        status_extended=f"Instance {name} uses default SA: {uses_default_sa}",
                        remediation="Use a custom service account with minimum necessary permissions",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

                    # 6. gcp_compute_serial_port_disabled
                    serial_enabled = any(
                        item.key == "serial-port-enable" and item.value.lower() == "true"
                        for item in (instance.metadata.items or []) if instance.metadata
                    )
                    results.append(CheckResult(
                        check_id="gcp_compute_serial_port_disabled",
                        check_title="VM instance has serial port access disabled",
                        service="compute", severity="medium",
                        status="FAIL" if serial_enabled else "PASS",
                        resource_id=res_id, resource_name=name,
                        status_extended=f"Instance {name} serial port enabled: {serial_enabled}",
                        remediation="Disable interactive serial port access on the instance",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

                    # 7. gcp_compute_ip_forwarding_disabled
                    ip_forwarding = instance.can_ip_forward
                    results.append(CheckResult(
                        check_id="gcp_compute_ip_forwarding_disabled",
                        check_title="VM instance has IP forwarding disabled",
                        service="compute", severity="medium",
                        status="FAIL" if ip_forwarding else "PASS",
                        resource_id=res_id, resource_name=name,
                        status_extended=f"Instance {name} IP forwarding: {ip_forwarding}",
                        remediation="Disable IP forwarding unless the instance is used as a gateway or router",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

                    # 8. gcp_compute_confidential_computing
                    confidential = (
                        instance.confidential_instance_config
                        and instance.confidential_instance_config.enable_confidential_compute
                    ) if instance.confidential_instance_config else False
                    results.append(CheckResult(
                        check_id="gcp_compute_confidential_computing",
                        check_title="VM instance has Confidential Computing enabled",
                        service="compute", severity="low",
                        status="PASS" if confidential else "FAIL",
                        resource_id=res_id, resource_name=name,
                        status_extended=f"Instance {name} Confidential Computing: {confidential}",
                        remediation="Enable Confidential Computing to encrypt data in use with AMD SEV",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

                    # 9. gcp_compute_no_full_api_access — VM does not use full API access scope (CIS 4.2)
                    has_full_access = any(
                        "https://www.googleapis.com/auth/cloud-platform" in (sa.scopes or [])
                        for sa in (instance.service_accounts or [])
                    )
                    results.append(CheckResult(
                        check_id="gcp_compute_no_full_api_access",
                        check_title="VM instance does not use full API access scope",
                        service="compute", severity="high",
                        status="FAIL" if has_full_access else "PASS",
                        resource_id=res_id, resource_name=name,
                        status_extended=f"Instance {name} full API access scope: {has_full_access}",
                        remediation="Use minimum necessary API scopes instead of full cloud-platform access",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

                    # 10. gcp_compute_block_project_ssh — VM blocks project-wide SSH keys (CIS 4.3)
                    block_ssh = any(
                        item.key == "block-project-ssh-keys" and item.value.lower() == "true"
                        for item in (instance.metadata.items or []) if instance.metadata
                    )
                    results.append(CheckResult(
                        check_id="gcp_compute_block_project_ssh",
                        check_title="VM instance blocks project-wide SSH keys",
                        service="compute", severity="medium",
                        status="PASS" if block_ssh else "FAIL",
                        resource_id=res_id, resource_name=name,
                        status_extended=f"Instance {name} blocks project-wide SSH keys: {block_ssh}",
                        remediation="Set block-project-ssh-keys metadata to true to prevent project-wide SSH key access",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

        except Exception as e:
            logger.warning(f"GCP compute checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # Storage checks (6)
    # ------------------------------------------------------------------

    def _check_storage(self) -> list[dict]:
        results = []
        try:
            from google.cloud import storage
            credentials = self._get_credentials()
            client = storage.Client(credentials=credentials, project=self.project_id)

            buckets = list(client.list_buckets())
            for bucket in buckets:
                name = bucket.name
                res_id = f"gs://{name}"

                # 1. gcp_storage_uniform_access
                uniform_access = bucket.iam_configuration.uniform_bucket_level_access_enabled
                results.append(CheckResult(
                    check_id="gcp_storage_uniform_access",
                    check_title="Bucket has uniform bucket-level access",
                    service="storage", severity="medium",
                    status="PASS" if uniform_access else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"Bucket {name} uniform access: {uniform_access}",
                    remediation="Enable uniform bucket-level access",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 2. gcp_storage_versioning
                versioning = bucket.versioning_enabled
                results.append(CheckResult(
                    check_id="gcp_storage_versioning",
                    check_title="Bucket has versioning enabled",
                    service="storage", severity="low",
                    status="PASS" if versioning else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"Bucket {name} versioning: {versioning}",
                    remediation="Enable versioning for data protection",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3. gcp_storage_no_public_access
                try:
                    policy = bucket.get_iam_policy(requested_policy_version=3)
                    is_public = False
                    for binding in policy.bindings:
                        members = set(binding.get("members", []))
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            is_public = True
                            break
                    results.append(CheckResult(
                        check_id="gcp_storage_no_public_access",
                        check_title="Bucket is not publicly accessible",
                        service="storage", severity="critical",
                        status="FAIL" if is_public else "PASS",
                        resource_id=res_id, resource_name=name,
                        status_extended=f"Bucket {name} public access: {is_public}",
                        remediation="Remove allUsers and allAuthenticatedUsers from bucket IAM policy",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Could not check public access for bucket {name}: {e}")

                # 4. gcp_storage_logging_enabled
                logging_config = bucket.get_logging()
                logging_enabled = logging_config is not None and logging_config.get("logBucket") is not None
                results.append(CheckResult(
                    check_id="gcp_storage_logging_enabled",
                    check_title="Bucket has access logging enabled",
                    service="storage", severity="medium",
                    status="PASS" if logging_enabled else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"Bucket {name} logging enabled: {logging_enabled}",
                    remediation="Enable access logging by setting a log bucket",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 5. gcp_storage_retention_policy
                retention = bucket.retention_policy_effective_time is not None or (
                    bucket.retention_period is not None and bucket.retention_period > 0
                )
                results.append(CheckResult(
                    check_id="gcp_storage_retention_policy",
                    check_title="Bucket has a retention policy configured",
                    service="storage", severity="medium",
                    status="PASS" if retention else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"Bucket {name} retention policy: {retention}",
                    remediation="Configure a retention policy to prevent accidental data deletion",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 6. gcp_storage_cmek_encryption
                default_kms = bucket.default_kms_key_name
                cmek = default_kms is not None and len(default_kms) > 0
                results.append(CheckResult(
                    check_id="gcp_storage_cmek_encryption",
                    check_title="Bucket is encrypted with customer-managed keys (CMEK)",
                    service="storage", severity="medium",
                    status="PASS" if cmek else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"Bucket {name} CMEK encryption: {cmek}",
                    remediation="Set a default Cloud KMS key for bucket encryption",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

        except Exception as e:
            logger.warning(f"GCP storage checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # SQL checks (8)
    # ------------------------------------------------------------------

    def _check_sql(self) -> list[dict]:
        results = []
        try:
            from googleapiclient.discovery import build
            credentials = self._get_credentials()
            service = build("sqladmin", "v1beta4", credentials=credentials)

            instances = service.instances().list(project=self.project_id).execute()
            for instance in instances.get("items", []):
                name = instance["name"]
                settings = instance.get("settings", {})
                ip_config = settings.get("ipConfiguration", {})

                # 1. gcp_sql_no_public_ip
                public_ip = ip_config.get("ipv4Enabled", True)
                results.append(CheckResult(
                    check_id="gcp_sql_no_public_ip",
                    check_title="Cloud SQL instance has no public IP",
                    service="sql", severity="high",
                    status="FAIL" if public_ip else "PASS",
                    resource_id=name, resource_name=name,
                    status_extended=f"SQL instance {name} public IP: {public_ip}",
                    remediation="Disable public IP for the Cloud SQL instance",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 2. gcp_sql_ssl_required
                ssl_required = ip_config.get("requireSsl", False)
                results.append(CheckResult(
                    check_id="gcp_sql_ssl_required",
                    check_title="Cloud SQL instance requires SSL",
                    service="sql", severity="high",
                    status="PASS" if ssl_required else "FAIL",
                    resource_id=name, resource_name=name,
                    status_extended=f"SQL instance {name} SSL required: {ssl_required}",
                    remediation="Enable SSL/TLS requirement for connections",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3. gcp_sql_backup_enabled
                backup = settings.get("backupConfiguration", {})
                backup_enabled = backup.get("enabled", False)
                results.append(CheckResult(
                    check_id="gcp_sql_backup_enabled",
                    check_title="Cloud SQL instance has backups enabled",
                    service="sql", severity="medium",
                    status="PASS" if backup_enabled else "FAIL",
                    resource_id=name, resource_name=name,
                    status_extended=f"SQL instance {name} backups: {backup_enabled}",
                    remediation="Enable automated backups for the SQL instance",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 4. gcp_sql_pitr_enabled
                pitr_enabled = backup.get("pointInTimeRecoveryEnabled", False)
                results.append(CheckResult(
                    check_id="gcp_sql_pitr_enabled",
                    check_title="Cloud SQL instance has point-in-time recovery enabled",
                    service="sql", severity="medium",
                    status="PASS" if pitr_enabled else "FAIL",
                    resource_id=name, resource_name=name,
                    status_extended=f"SQL instance {name} PITR: {pitr_enabled}",
                    remediation="Enable point-in-time recovery (binary logging for MySQL, WAL for PostgreSQL)",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 5. gcp_sql_no_public_networks — authorized networks with 0.0.0.0/0
                auth_networks = ip_config.get("authorizedNetworks", [])
                has_public_net = any(
                    net.get("value") == "0.0.0.0/0" for net in auth_networks
                )
                results.append(CheckResult(
                    check_id="gcp_sql_no_public_networks",
                    check_title="Cloud SQL instance has no public authorized networks",
                    service="sql", severity="critical",
                    status="FAIL" if has_public_net else "PASS",
                    resource_id=name, resource_name=name,
                    status_extended=f"SQL instance {name} has 0.0.0.0/0 authorized: {has_public_net}",
                    remediation="Remove 0.0.0.0/0 from authorized networks and restrict to specific IP ranges",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 6. gcp_sql_cmek_encryption
                disk_enc_cfg = instance.get("diskEncryptionConfiguration", {})
                cmek = bool(disk_enc_cfg.get("kmsKeyName"))
                results.append(CheckResult(
                    check_id="gcp_sql_cmek_encryption",
                    check_title="Cloud SQL instance is encrypted with CMEK",
                    service="sql", severity="medium",
                    status="PASS" if cmek else "FAIL",
                    resource_id=name, resource_name=name,
                    status_extended=f"SQL instance {name} CMEK encryption: {cmek}",
                    remediation="Configure Customer-Managed Encryption Keys (CMEK) for the SQL instance",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 7. gcp_sql_audit_logging — check database flags for audit logging
                db_flags = settings.get("databaseFlags", [])
                db_type = instance.get("databaseVersion", "")
                audit_flag = False
                if db_type.startswith("POSTGRES"):
                    audit_flag = any(
                        f.get("name") == "cloudsql.enable_pgaudit" and f.get("value") == "on"
                        for f in db_flags
                    )
                elif db_type.startswith("MYSQL"):
                    audit_flag = any(
                        f.get("name") == "audit_log" and f.get("value") == "ON"
                        for f in db_flags
                    )
                elif db_type.startswith("SQLSERVER"):
                    # SQL Server has built-in audit; check user audit flag
                    audit_flag = any(
                        f.get("name") == "user options" for f in db_flags
                    )
                results.append(CheckResult(
                    check_id="gcp_sql_audit_logging",
                    check_title="Cloud SQL instance has database audit logging enabled",
                    service="sql", severity="medium",
                    status="PASS" if audit_flag else "FAIL",
                    resource_id=name, resource_name=name,
                    status_extended=f"SQL instance {name} ({db_type}) audit logging: {audit_flag}",
                    remediation="Enable database audit logging via database flags (e.g., cloudsql.enable_pgaudit for PostgreSQL)",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 8. gcp_sql_auto_storage_increase
                auto_resize = settings.get("storageAutoResize", False)
                results.append(CheckResult(
                    check_id="gcp_sql_auto_storage_increase",
                    check_title="Cloud SQL instance has automatic storage increase enabled",
                    service="sql", severity="low",
                    status="PASS" if auto_resize else "FAIL",
                    resource_id=name, resource_name=name,
                    status_extended=f"SQL instance {name} auto storage increase: {auto_resize}",
                    remediation="Enable automatic storage increase to prevent out-of-disk issues",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

        except Exception as e:
            logger.warning(f"GCP SQL checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # Logging checks (16)
    # ------------------------------------------------------------------

    def _check_logging(self) -> list[dict]:
        results = []
        try:
            from google.cloud import logging as gcp_logging
            credentials = self._get_credentials()
            client = gcp_logging.Client(credentials=credentials, project=self.project_id)

            # 1. gcp_logging_sinks_configured
            sinks = list(client.list_sinks())
            results.append(CheckResult(
                check_id="gcp_logging_sinks_configured",
                check_title="Log sinks are configured",
                service="logging", severity="medium",
                status="PASS" if sinks else "FAIL",
                resource_id=f"projects/{self.project_id}",
                status_extended=f"Project has {len(sinks)} log sink(s)",
                remediation="Configure log sinks for log export and retention",
                compliance_frameworks=_DEFAULT_FRAMEWORKS,
            ).to_dict())

            # 2. gcp_logging_audit_logs_enabled — check data access audit logs
            try:
                from google.cloud import resourcemanager_v3
                from google.iam.v1 import iam_policy_pb2
                rm_client = resourcemanager_v3.ProjectsClient(credentials=credentials)
                policy = rm_client.get_iam_policy(
                    request=iam_policy_pb2.GetIamPolicyRequest(resource=f"projects/{self.project_id}")
                )
                # Audit configs are typically accessed via the CRM API
                from googleapiclient.discovery import build
                crm_service = build("cloudresourcemanager", "v1", credentials=credentials)
                iam_policy = crm_service.projects().getIamPolicy(
                    resource=self.project_id, body={"options": {"requestedPolicyVersion": 3}}
                ).execute()
                audit_configs = iam_policy.get("auditConfigs", [])
                has_data_access = any(
                    cfg.get("service") == "allServices" for cfg in audit_configs
                )
                results.append(CheckResult(
                    check_id="gcp_logging_audit_logs_enabled",
                    check_title="Data Access audit logs are enabled for all services",
                    service="logging", severity="high",
                    status="PASS" if has_data_access else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Data Access audit logs for allServices: {has_data_access}",
                    remediation="Enable Data Access audit logs for allServices in the project IAM policy",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())
            except Exception as e:
                logger.warning(f"GCP audit log check failed: {e}")

            # 3. gcp_logging_metric_filters — check for required metric filters
            required_filters = [
                "resource.type=audited_resource AND protoPayload.methodName=",
                "protoPayload.methodName=SetIamPolicy",
            ]
            try:
                metrics = list(client.list_metrics())
                metric_filters = [m.filter_ for m in metrics]
                has_iam_metric = any(
                    "SetIamPolicy" in f or "setIamPolicy" in f for f in metric_filters
                )
                results.append(CheckResult(
                    check_id="gcp_logging_metric_filters",
                    check_title="Log metric filters exist for critical operations",
                    service="logging", severity="medium",
                    status="PASS" if has_iam_metric else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Log metric filters count: {len(metrics)}, IAM change filter: {has_iam_metric}",
                    remediation="Create log-based metrics for IAM changes, network changes, and other critical operations",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())
                # 3a. gcp_logging_ownership_changes — Log metric filter for ownership changes (CIS 2.4)
                has_ownership_filter = any("roles/owner" in f for f in metric_filters)
                results.append(CheckResult(
                    check_id="gcp_logging_ownership_changes",
                    check_title="Log metric filter exists for project ownership changes",
                    service="logging", severity="medium",
                    status="PASS" if has_ownership_filter else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Metric filter for ownership changes: {has_ownership_filter}",
                    remediation="Create a log metric filter for project ownership assignments/changes",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3b. gcp_logging_audit_config_changes — Log metric filter for audit config changes (CIS 2.5)
                has_audit_config_filter = any("auditConfigDeltas" in f for f in metric_filters)
                results.append(CheckResult(
                    check_id="gcp_logging_audit_config_changes",
                    check_title="Log metric filter exists for audit configuration changes",
                    service="logging", severity="medium",
                    status="PASS" if has_audit_config_filter else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Metric filter for audit config changes: {has_audit_config_filter}",
                    remediation="Create a log metric filter for audit configuration changes",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3c. gcp_logging_custom_role_changes — Log metric filter for custom role changes (CIS 2.6)
                has_custom_role_filter = any("iam_role" in f for f in metric_filters)
                results.append(CheckResult(
                    check_id="gcp_logging_custom_role_changes",
                    check_title="Log metric filter exists for custom role changes",
                    service="logging", severity="medium",
                    status="PASS" if has_custom_role_filter else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Metric filter for custom role changes: {has_custom_role_filter}",
                    remediation="Create a log metric filter for custom role creation, deletion, and updates",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3d. gcp_logging_firewall_changes — Log metric filter for firewall rule changes (CIS 2.7)
                has_firewall_filter = any("gce_firewall_rule" in f for f in metric_filters)
                results.append(CheckResult(
                    check_id="gcp_logging_firewall_changes",
                    check_title="Log metric filter exists for VPC firewall rule changes",
                    service="logging", severity="medium",
                    status="PASS" if has_firewall_filter else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Metric filter for firewall rule changes: {has_firewall_filter}",
                    remediation="Create a log metric filter for VPC firewall rule changes",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3e. gcp_logging_route_changes — Log metric filter for route changes (CIS 2.8)
                has_route_filter = any("gce_route" in f for f in metric_filters)
                results.append(CheckResult(
                    check_id="gcp_logging_route_changes",
                    check_title="Log metric filter exists for VPC network route changes",
                    service="logging", severity="medium",
                    status="PASS" if has_route_filter else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Metric filter for route changes: {has_route_filter}",
                    remediation="Create a log metric filter for VPC network route changes",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3f. gcp_logging_vpc_changes — Log metric filter for VPC network changes (CIS 2.9)
                has_vpc_filter = any("gce_network" in f for f in metric_filters)
                results.append(CheckResult(
                    check_id="gcp_logging_vpc_changes",
                    check_title="Log metric filter exists for VPC network changes",
                    service="logging", severity="medium",
                    status="PASS" if has_vpc_filter else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Metric filter for VPC network changes: {has_vpc_filter}",
                    remediation="Create a log metric filter for VPC network creation, deletion, and patching",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3g. gcp_logging_storage_iam_changes — Log metric filter for Cloud Storage IAM changes (CIS 2.10)
                has_storage_iam_filter = any("storage.setIamPermissions" in f for f in metric_filters)
                results.append(CheckResult(
                    check_id="gcp_logging_storage_iam_changes",
                    check_title="Log metric filter exists for Cloud Storage IAM permission changes",
                    service="logging", severity="medium",
                    status="PASS" if has_storage_iam_filter else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Metric filter for Storage IAM changes: {has_storage_iam_filter}",
                    remediation="Create a log metric filter for Cloud Storage IAM permission changes",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3h. gcp_logging_sql_config_changes — Log metric filter for SQL instance config changes (CIS 2.11)
                has_sql_config_filter = any("cloudsql.instances" in f for f in metric_filters)
                results.append(CheckResult(
                    check_id="gcp_logging_sql_config_changes",
                    check_title="Log metric filter exists for SQL instance configuration changes",
                    service="logging", severity="medium",
                    status="PASS" if has_sql_config_filter else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Metric filter for SQL config changes: {has_sql_config_filter}",
                    remediation="Create a log metric filter for Cloud SQL instance configuration changes",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

            except Exception as e:
                logger.warning(f"GCP metric filters check failed: {e}")

            # 3i. gcp_logging_cloud_asset_inventory — Cloud Asset Inventory enabled (CIS 2.14)
            try:
                from googleapiclient.discovery import build as _build_cai
                cai_svc = _build_cai("cloudasset", "v1", credentials=credentials)
                feeds = cai_svc.feeds().list(
                    parent=f"projects/{self.project_id}"
                ).execute()
                feed_list = feeds.get("feeds", [])
                has_cai = len(feed_list) > 0
                results.append(CheckResult(
                    check_id="gcp_logging_cloud_asset_inventory",
                    check_title="Cloud Asset Inventory is enabled",
                    service="logging", severity="medium",
                    status="PASS" if has_cai else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"Cloud Asset Inventory feeds configured: {len(feed_list)}",
                    remediation="Enable Cloud Asset Inventory to track and monitor resource changes",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())
            except Exception as e:
                logger.warning(f"GCP Cloud Asset Inventory check failed: {e}")

            # 3j. gcp_logging_lb_logging — Load balancer logging enabled (CIS 2.17)
            try:
                from googleapiclient.discovery import build as _build_lb
                compute_svc = _build_lb("compute", "v1", credentials=credentials)
                backend_services = compute_svc.backendServices().aggregatedList(
                    project=self.project_id
                ).execute()
                lb_logging_fail = False
                for scope, scoped_list in backend_services.get("items", {}).items():
                    for bs in scoped_list.get("backendServices", []):
                        bs_name = bs.get("name", "")
                        log_config = bs.get("logConfig", {})
                        logging_enabled = log_config.get("enable", False)
                        if not logging_enabled:
                            lb_logging_fail = True
                            results.append(CheckResult(
                                check_id="gcp_logging_lb_logging",
                                check_title="Load balancer logging is enabled",
                                service="logging", severity="medium",
                                status="FAIL",
                                resource_id=bs.get("selfLink", bs_name),
                                resource_name=bs_name,
                                status_extended=f"Backend service {bs_name} logging: disabled",
                                remediation="Enable logging on all load balancer backend services",
                                compliance_frameworks=_DEFAULT_FRAMEWORKS,
                            ).to_dict())
                        else:
                            results.append(CheckResult(
                                check_id="gcp_logging_lb_logging",
                                check_title="Load balancer logging is enabled",
                                service="logging", severity="medium",
                                status="PASS",
                                resource_id=bs.get("selfLink", bs_name),
                                resource_name=bs_name,
                                status_extended=f"Backend service {bs_name} logging: enabled",
                                remediation="Enable logging on all load balancer backend services",
                                compliance_frameworks=_DEFAULT_FRAMEWORKS,
                            ).to_dict())
            except Exception as e:
                logger.warning(f"GCP load balancer logging check failed: {e}")

            # 4. gcp_logging_bucket_retention
            try:
                from googleapiclient.discovery import build
                logging_svc = build("logging", "v2", credentials=credentials)
                buckets_response = logging_svc.projects().locations().buckets().list(
                    parent=f"projects/{self.project_id}/locations/-"
                ).execute()
                all_retention_ok = True
                for log_bucket in buckets_response.get("buckets", []):
                    retention_days = log_bucket.get("retentionDays", 0)
                    bucket_name = log_bucket.get("name", "").split("/")[-1]
                    if retention_days < 365:
                        all_retention_ok = False
                        results.append(CheckResult(
                            check_id="gcp_logging_bucket_retention",
                            check_title="Log buckets have retention of 365 days or more",
                            service="logging", severity="medium",
                            status="FAIL",
                            resource_id=log_bucket.get("name", ""),
                            resource_name=bucket_name,
                            status_extended=f"Log bucket {bucket_name} retention: {retention_days} days (requires 365+)",
                            remediation="Set log bucket retention to at least 365 days for compliance",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())
                if all_retention_ok:
                    results.append(CheckResult(
                        check_id="gcp_logging_bucket_retention",
                        check_title="Log buckets have retention of 365 days or more",
                        service="logging", severity="medium", status="PASS",
                        resource_id=f"projects/{self.project_id}",
                        status_extended="All log buckets have retention >= 365 days",
                        remediation="Set log bucket retention to at least 365 days for compliance",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
            except Exception as e:
                logger.warning(f"GCP log bucket retention check failed: {e}")

            # 5. gcp_logging_vpc_flow_logs
            try:
                from google.cloud import compute_v1
                subnets_client = compute_v1.SubnetworksClient(credentials=credentials)
                agg = subnets_client.aggregated_list(project=self.project_id)
                flow_logs_disabled = []
                for region, response in agg:
                    for subnet in response.subnetworks or []:
                        if not subnet.log_config or not subnet.log_config.enable:
                            flow_logs_disabled.append(subnet.name)
                            results.append(CheckResult(
                                check_id="gcp_logging_vpc_flow_logs",
                                check_title="VPC subnet has flow logs enabled",
                                service="logging", severity="medium",
                                status="FAIL",
                                resource_id=subnet.self_link or subnet.name,
                                resource_name=subnet.name,
                                status_extended=f"Subnet {subnet.name} flow logs: disabled",
                                remediation="Enable VPC Flow Logs for all subnets for network monitoring",
                                compliance_frameworks=_DEFAULT_FRAMEWORKS,
                            ).to_dict())
                        else:
                            results.append(CheckResult(
                                check_id="gcp_logging_vpc_flow_logs",
                                check_title="VPC subnet has flow logs enabled",
                                service="logging", severity="medium",
                                status="PASS",
                                resource_id=subnet.self_link or subnet.name,
                                resource_name=subnet.name,
                                status_extended=f"Subnet {subnet.name} flow logs: enabled",
                                remediation="Enable VPC Flow Logs for all subnets for network monitoring",
                                compliance_frameworks=_DEFAULT_FRAMEWORKS,
                            ).to_dict())
            except Exception as e:
                logger.warning(f"GCP VPC flow logs check failed: {e}")

            # 6. gcp_logging_dns_logging
            try:
                from googleapiclient.discovery import build
                dns_svc = build("dns", "v1", credentials=credentials)
                policies = dns_svc.policies().list(project=self.project_id).execute()
                dns_logging_enabled = False
                for pol in policies.get("policies", []):
                    if pol.get("enableLogging", False):
                        dns_logging_enabled = True
                        break
                results.append(CheckResult(
                    check_id="gcp_logging_dns_logging",
                    check_title="Cloud DNS logging is enabled",
                    service="logging", severity="medium",
                    status="PASS" if dns_logging_enabled else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"DNS logging enabled via policy: {dns_logging_enabled}",
                    remediation="Enable Cloud DNS logging via DNS policies for DNS query auditing",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())
            except Exception as e:
                logger.warning(f"GCP DNS logging check failed: {e}")

        except Exception as e:
            logger.warning(f"GCP logging checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # KMS checks (3)
    # ------------------------------------------------------------------

    def _check_kms(self) -> list[dict]:
        results = []
        try:
            from google.cloud import kms
            credentials = self._get_credentials()
            client = kms.KeyManagementServiceClient(credentials=credentials)

            parent = f"projects/{self.project_id}/locations/-"
            key_rings = list(client.list_key_rings(request={"parent": parent}))

            for ring in key_rings:
                keys = list(client.list_crypto_keys(request={"parent": ring.name}))
                for key in keys:
                    key_short = key.name.split("/")[-1]

                    # 1. gcp_kms_key_rotation
                    rotation = key.rotation_period
                    has_rotation = rotation is not None and rotation.total_seconds() <= 7776000  # 90 days
                    results.append(CheckResult(
                        check_id="gcp_kms_key_rotation",
                        check_title="KMS key has rotation period of 90 days or less",
                        service="kms", severity="medium",
                        status="PASS" if has_rotation else "FAIL",
                        resource_id=key.name, resource_name=key_short,
                        status_extended=f"KMS key rotation configured: {has_rotation}",
                        remediation="Set key rotation period to 90 days or less",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

                    # 2. gcp_kms_no_public_access
                    try:
                        iam_policy = client.get_iam_policy(request={"resource": key.name})
                        is_public = False
                        for binding in iam_policy.bindings:
                            for member in binding.members:
                                if member in ("allUsers", "allAuthenticatedUsers"):
                                    is_public = True
                                    break
                        results.append(CheckResult(
                            check_id="gcp_kms_no_public_access",
                            check_title="KMS key is not publicly accessible",
                            service="kms", severity="critical",
                            status="FAIL" if is_public else "PASS",
                            resource_id=key.name, resource_name=key_short,
                            status_extended=f"KMS key {key_short} public access: {is_public}",
                            remediation="Remove allUsers and allAuthenticatedUsers from the KMS key IAM policy",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())
                    except Exception as e:
                        logger.warning(f"KMS IAM policy check failed for {key_short}: {e}")

                    # 3. gcp_kms_hsm_protection
                    protection_level = key.version_template.protection_level if key.version_template else None
                    is_hsm = protection_level == kms.ProtectionLevel.HSM if protection_level else False
                    results.append(CheckResult(
                        check_id="gcp_kms_hsm_protection",
                        check_title="KMS key uses HSM protection level",
                        service="kms", severity="low",
                        status="PASS" if is_hsm else "FAIL",
                        resource_id=key.name, resource_name=key_short,
                        status_extended=f"KMS key {key_short} HSM protection: {is_hsm}",
                        remediation="Use HSM protection level for keys that require hardware-backed security",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

        except Exception as e:
            logger.warning(f"GCP KMS checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # GKE checks (8)
    # ------------------------------------------------------------------

    def _check_gke(self) -> list[dict]:
        results = []
        try:
            from google.cloud import container_v1
            credentials = self._get_credentials()
            client = container_v1.ClusterManagerClient(credentials=credentials)

            parent = f"projects/{self.project_id}/locations/-"
            response = client.list_clusters(request={"parent": parent})

            for cluster in response.clusters:
                name = cluster.name
                location = cluster.location
                res_id = f"projects/{self.project_id}/locations/{location}/clusters/{name}"

                # 1. gcp_gke_private_cluster
                private_cluster = (
                    cluster.private_cluster_config
                    and cluster.private_cluster_config.enable_private_nodes
                )
                results.append(CheckResult(
                    check_id="gcp_gke_private_cluster",
                    check_title="GKE cluster uses private nodes",
                    service="gke", severity="high",
                    status="PASS" if private_cluster else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"GKE cluster {name} private nodes: {private_cluster}",
                    remediation="Enable private nodes for the GKE cluster",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 2. gcp_gke_network_policy
                network_policy = cluster.network_policy and cluster.network_policy.enabled
                results.append(CheckResult(
                    check_id="gcp_gke_network_policy",
                    check_title="GKE cluster has network policy enabled",
                    service="gke", severity="medium",
                    status="PASS" if network_policy else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"GKE cluster {name} network policy: {network_policy}",
                    remediation="Enable network policy for pod-level network security",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3. gcp_gke_master_auth_networks
                master_auth_nets = (
                    cluster.master_authorized_networks_config
                    and cluster.master_authorized_networks_config.enabled
                )
                results.append(CheckResult(
                    check_id="gcp_gke_master_auth_networks",
                    check_title="GKE cluster has master authorized networks enabled",
                    service="gke", severity="high",
                    status="PASS" if master_auth_nets else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"GKE cluster {name} master authorized networks: {master_auth_nets}",
                    remediation="Enable master authorized networks to restrict API server access",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 4. gcp_gke_pod_security_policy
                psp_enabled = cluster.pod_security_policy_config and cluster.pod_security_policy_config.enabled
                results.append(CheckResult(
                    check_id="gcp_gke_pod_security_policy",
                    check_title="GKE cluster has Pod Security Policy / Standards enabled",
                    service="gke", severity="medium",
                    status="PASS" if psp_enabled else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"GKE cluster {name} pod security policy: {psp_enabled}",
                    remediation="Enable Pod Security Standards (PSS) or Gatekeeper policies for workload security",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 5. gcp_gke_shielded_nodes
                shielded_nodes = (
                    cluster.shielded_nodes
                    and cluster.shielded_nodes.enabled
                )
                results.append(CheckResult(
                    check_id="gcp_gke_shielded_nodes",
                    check_title="GKE cluster has Shielded GKE Nodes enabled",
                    service="gke", severity="medium",
                    status="PASS" if shielded_nodes else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"GKE cluster {name} shielded nodes: {shielded_nodes}",
                    remediation="Enable Shielded GKE Nodes for node identity verification and integrity",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 6. gcp_gke_workload_identity
                wi_config = cluster.workload_identity_config
                workload_identity = wi_config and bool(wi_config.workload_pool)
                results.append(CheckResult(
                    check_id="gcp_gke_workload_identity",
                    check_title="GKE cluster has Workload Identity enabled",
                    service="gke", severity="high",
                    status="PASS" if workload_identity else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"GKE cluster {name} Workload Identity: {workload_identity}",
                    remediation="Enable Workload Identity to provide fine-grained GCP IAM for pods",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 7. gcp_gke_binary_auth
                binary_auth = (
                    cluster.binary_authorization
                    and cluster.binary_authorization.enabled
                )
                results.append(CheckResult(
                    check_id="gcp_gke_binary_auth",
                    check_title="GKE cluster has Binary Authorization enabled",
                    service="gke", severity="medium",
                    status="PASS" if binary_auth else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"GKE cluster {name} Binary Authorization: {binary_auth}",
                    remediation="Enable Binary Authorization to ensure only trusted container images are deployed",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 8. gcp_gke_cluster_logging
                logging_service = cluster.logging_service
                logging_enabled = logging_service and logging_service != "none"
                results.append(CheckResult(
                    check_id="gcp_gke_cluster_logging",
                    check_title="GKE cluster has logging enabled",
                    service="gke", severity="high",
                    status="PASS" if logging_enabled else "FAIL",
                    resource_id=res_id, resource_name=name,
                    status_extended=f"GKE cluster {name} logging service: {logging_service}",
                    remediation="Enable Cloud Logging for the GKE cluster (logging.googleapis.com/kubernetes)",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

        except Exception as e:
            logger.warning(f"GCP GKE checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # Networking checks (9)
    # ------------------------------------------------------------------

    def _check_networking(self) -> list[dict]:
        results = []
        try:
            from google.cloud import compute_v1
            credentials = self._get_credentials()
            firewalls_client = compute_v1.FirewallsClient(credentials=credentials)

            firewalls = firewalls_client.list(project=self.project_id)
            default_allow_found = False

            for fw in firewalls:
                # 1 & 2. gcp_firewall_open_22 / gcp_firewall_open_3389
                if fw.direction != "INGRESS":
                    continue
                for src_range in fw.source_ranges or []:
                    if src_range == "0.0.0.0/0":
                        for allowed in fw.allowed or []:
                            for port in allowed.ports or []:
                                if port in ("22", "3389"):
                                    results.append(CheckResult(
                                        check_id=f"gcp_firewall_open_{port}",
                                        check_title=f"Firewall rule allows unrestricted access to port {port}",
                                        service="networking", severity="high",
                                        status="FAIL",
                                        resource_id=fw.self_link, resource_name=fw.name,
                                        status_extended=f"Firewall {fw.name} allows 0.0.0.0/0 on port {port}",
                                        remediation=f"Restrict port {port} to specific source IP ranges",
                                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                                    ).to_dict())

                # 3. gcp_firewall_no_default_allow — detect default-allow-* rules
                if fw.name.startswith("default-allow"):
                    default_allow_found = True
                    results.append(CheckResult(
                        check_id="gcp_firewall_no_default_allow",
                        check_title="Default allow firewall rules are removed",
                        service="networking", severity="medium",
                        status="FAIL",
                        resource_id=fw.self_link, resource_name=fw.name,
                        status_extended=f"Default allow firewall rule {fw.name} exists",
                        remediation="Remove default-allow-* firewall rules and replace with specific rules",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

            if not default_allow_found:
                results.append(CheckResult(
                    check_id="gcp_firewall_no_default_allow",
                    check_title="Default allow firewall rules are removed",
                    service="networking", severity="medium", status="PASS",
                    resource_id=f"projects/{self.project_id}",
                    status_extended="No default-allow firewall rules found",
                    remediation="Remove default-allow-* firewall rules and replace with specific rules",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

            # 4. gcp_network_dns_sec — check managed zones for DNSSEC
            try:
                from googleapiclient.discovery import build
                dns_svc = build("dns", "v1", credentials=credentials)
                zones = dns_svc.managedZones().list(project=self.project_id).execute()
                for zone in zones.get("managedZones", []):
                    zone_name = zone.get("name", "")
                    dnssec_config = zone.get("dnssecConfig", {})
                    dnssec_state = dnssec_config.get("state", "off")
                    is_on = dnssec_state == "on"
                    # Only check public zones
                    if zone.get("visibility", "public") == "public":
                        results.append(CheckResult(
                            check_id="gcp_network_dns_sec",
                            check_title="Cloud DNS zone has DNSSEC enabled",
                            service="networking", severity="medium",
                            status="PASS" if is_on else "FAIL",
                            resource_id=zone.get("id", zone_name),
                            resource_name=zone_name,
                            status_extended=f"DNS zone {zone_name} DNSSEC: {dnssec_state}",
                            remediation="Enable DNSSEC for public managed zones",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())
            except Exception as e:
                logger.warning(f"GCP DNSSEC check failed: {e}")

            # 5. gcp_network_private_google_access — check subnets
            try:
                subnets_client = compute_v1.SubnetworksClient(credentials=credentials)
                agg = subnets_client.aggregated_list(project=self.project_id)
                for region, response in agg:
                    for subnet in response.subnetworks or []:
                        pga = subnet.private_ip_google_access
                        results.append(CheckResult(
                            check_id="gcp_network_private_google_access",
                            check_title="Subnet has Private Google Access enabled",
                            service="networking", severity="medium",
                            status="PASS" if pga else "FAIL",
                            resource_id=subnet.self_link or subnet.name,
                            resource_name=subnet.name,
                            status_extended=f"Subnet {subnet.name} Private Google Access: {pga}",
                            remediation="Enable Private Google Access on subnets to access Google APIs without external IPs",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())
            except Exception as e:
                logger.warning(f"GCP Private Google Access check failed: {e}")

            # 6. gcp_network_flow_logs_enabled — same as logging flow logs but from networking perspective
            try:
                subnets_client = compute_v1.SubnetworksClient(credentials=credentials)
                agg = subnets_client.aggregated_list(project=self.project_id)
                for region, response in agg:
                    for subnet in response.subnetworks or []:
                        flow_enabled = subnet.log_config and subnet.log_config.enable
                        results.append(CheckResult(
                            check_id="gcp_network_flow_logs_enabled",
                            check_title="Subnet has VPC Flow Logs enabled",
                            service="networking", severity="medium",
                            status="PASS" if flow_enabled else "FAIL",
                            resource_id=subnet.self_link or subnet.name,
                            resource_name=subnet.name,
                            status_extended=f"Subnet {subnet.name} flow logs: {flow_enabled}",
                            remediation="Enable VPC Flow Logs for network traffic analysis and monitoring",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())
            except Exception as e:
                logger.warning(f"GCP network flow logs check failed: {e}")

            # 7. gcp_network_no_default_network — Ensure default network is not present (CIS 3.1)
            try:
                networks_client = compute_v1.NetworksClient(credentials=credentials)
                networks = networks_client.list(project=self.project_id)
                has_default_network = False
                for network in networks:
                    if network.name == "default":
                        has_default_network = True
                        results.append(CheckResult(
                            check_id="gcp_network_no_default_network",
                            check_title="Default network does not exist in the project",
                            service="networking", severity="medium",
                            status="FAIL",
                            resource_id=network.self_link or f"projects/{self.project_id}/global/networks/default",
                            resource_name="default",
                            status_extended="Default network exists in the project",
                            remediation="Delete the default network and create custom VPC networks with specific subnets",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())
                        break
                if not has_default_network:
                    results.append(CheckResult(
                        check_id="gcp_network_no_default_network",
                        check_title="Default network does not exist in the project",
                        service="networking", severity="medium",
                        status="PASS",
                        resource_id=f"projects/{self.project_id}",
                        status_extended="No default network found in the project",
                        remediation="Delete the default network and create custom VPC networks with specific subnets",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
            except Exception as e:
                logger.warning(f"GCP default network check failed: {e}")

            # 8. gcp_network_no_legacy_network — No legacy networks (CIS 3.2)
            try:
                networks_client = compute_v1.NetworksClient(credentials=credentials)
                networks = networks_client.list(project=self.project_id)
                legacy_found = False
                for network in networks:
                    # Legacy networks have autoCreateSubnetworks=False and no subnet_mode (IPv4Range set instead)
                    is_legacy = hasattr(network, "i_pv4_range") and network.i_pv4_range
                    if is_legacy:
                        legacy_found = True
                        results.append(CheckResult(
                            check_id="gcp_network_no_legacy_network",
                            check_title="No legacy networks exist in the project",
                            service="networking", severity="medium",
                            status="FAIL",
                            resource_id=network.self_link or network.name,
                            resource_name=network.name,
                            status_extended=f"Legacy network {network.name} exists in the project",
                            remediation="Delete legacy networks and use VPC networks with custom or auto subnets",
                            compliance_frameworks=_DEFAULT_FRAMEWORKS,
                        ).to_dict())
                if not legacy_found:
                    results.append(CheckResult(
                        check_id="gcp_network_no_legacy_network",
                        check_title="No legacy networks exist in the project",
                        service="networking", severity="medium",
                        status="PASS",
                        resource_id=f"projects/{self.project_id}",
                        status_extended="No legacy networks found in the project",
                        remediation="Delete legacy networks and use VPC networks with custom or auto subnets",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
            except Exception as e:
                logger.warning(f"GCP legacy network check failed: {e}")

            # 9. gcp_network_ssl_policy — SSL policies use restricted/modern profiles (CIS 3.9)
            try:
                ssl_policies_client = compute_v1.SslPoliciesClient(credentials=credentials)
                ssl_policies = ssl_policies_client.list(project=self.project_id)
                ssl_policy_found = False
                for ssl_policy in ssl_policies:
                    ssl_policy_found = True
                    min_tls = ssl_policy.min_tls_version if hasattr(ssl_policy, "min_tls_version") else ""
                    is_secure = min_tls in ("TLS_1_2", "TLS_1_3")
                    results.append(CheckResult(
                        check_id="gcp_network_ssl_policy",
                        check_title="SSL policy uses TLS 1.2 or higher",
                        service="networking", severity="high",
                        status="PASS" if is_secure else "FAIL",
                        resource_id=ssl_policy.self_link or ssl_policy.name,
                        resource_name=ssl_policy.name,
                        status_extended=f"SSL policy {ssl_policy.name} minTlsVersion: {min_tls}",
                        remediation="Configure SSL policies to use TLS 1.2 or higher with RESTRICTED or MODERN profile",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
                if not ssl_policy_found:
                    results.append(CheckResult(
                        check_id="gcp_network_ssl_policy",
                        check_title="SSL policy uses TLS 1.2 or higher",
                        service="networking", severity="high",
                        status="FAIL",
                        resource_id=f"projects/{self.project_id}",
                        status_extended="No SSL policies configured — default GCP SSL policy may allow older TLS versions",
                        remediation="Create an SSL policy with TLS 1.2 or higher and RESTRICTED or MODERN profile",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
            except Exception as e:
                logger.warning(f"GCP SSL policy check failed: {e}")

        except Exception as e:
            logger.warning(f"GCP networking checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # BigQuery checks (5)
    # ------------------------------------------------------------------

    def _check_bigquery(self) -> list[dict]:
        results = []
        try:
            from google.cloud import bigquery
            credentials = self._get_credentials()
            client = bigquery.Client(credentials=credentials, project=self.project_id)

            datasets = list(client.list_datasets())
            for dataset_ref in datasets:
                dataset = client.get_dataset(dataset_ref.reference)
                ds_id = dataset.dataset_id
                full_id = f"{self.project_id}.{ds_id}"

                # 1. gcp_bigquery_dataset_no_public
                access_entries = dataset.access_entries
                is_public = any(
                    entry.entity_id in ("allUsers", "allAuthenticatedUsers")
                    for entry in access_entries
                    if hasattr(entry, "entity_id") and entry.entity_id
                )
                results.append(CheckResult(
                    check_id="gcp_bigquery_dataset_no_public",
                    check_title="BigQuery dataset is not publicly accessible",
                    service="bigquery", severity="critical",
                    status="FAIL" if is_public else "PASS",
                    resource_id=full_id, resource_name=ds_id,
                    status_extended=f"BigQuery dataset {ds_id} public access: {is_public}",
                    remediation="Remove allUsers and allAuthenticatedUsers from BigQuery dataset access entries",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 2. gcp_bigquery_cmek_encryption
                cmek = dataset.default_encryption_configuration and bool(
                    dataset.default_encryption_configuration.kms_key_name
                )
                results.append(CheckResult(
                    check_id="gcp_bigquery_cmek_encryption",
                    check_title="BigQuery dataset uses CMEK encryption",
                    service="bigquery", severity="medium",
                    status="PASS" if cmek else "FAIL",
                    resource_id=full_id, resource_name=ds_id,
                    status_extended=f"BigQuery dataset {ds_id} CMEK encryption: {cmek}",
                    remediation="Set a default Cloud KMS encryption key on the BigQuery dataset",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3. gcp_bigquery_table_encrypted — check tables for CMEK
                tables = list(client.list_tables(dataset_ref.reference))
                for table_ref in tables:
                    table = client.get_table(table_ref)
                    tbl_name = table.table_id
                    tbl_cmek = table.encryption_configuration and bool(
                        table.encryption_configuration.kms_key_name
                    )
                    results.append(CheckResult(
                        check_id="gcp_bigquery_table_encrypted",
                        check_title="BigQuery table is encrypted with CMEK",
                        service="bigquery", severity="medium",
                        status="PASS" if tbl_cmek else "FAIL",
                        resource_id=f"{full_id}.{tbl_name}", resource_name=tbl_name,
                        status_extended=f"BigQuery table {tbl_name} CMEK: {tbl_cmek}",
                        remediation="Configure CMEK encryption on the BigQuery table",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

                # 4. gcp_bigquery_classification — Dataset has data classification labels (CIS 7.4)
                labels = dataset.labels or {}
                classification_keywords = {"classification", "data_classification", "data-classification",
                                           "sensitivity", "data_sensitivity", "data-sensitivity"}
                has_classification = any(k.lower() in classification_keywords for k in labels)
                results.append(CheckResult(
                    check_id="gcp_bigquery_classification",
                    check_title="BigQuery dataset has data classification labels",
                    service="bigquery", severity="low",
                    status="PASS" if has_classification else "FAIL",
                    resource_id=full_id, resource_name=ds_id,
                    status_extended=f"BigQuery dataset {ds_id} has classification label: {has_classification}",
                    remediation="Add a data classification label (e.g., 'classification') to the BigQuery dataset",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

            # 5. gcp_bigquery_audit_logging — check if BigQuery data access audit logs are enabled
            try:
                from googleapiclient.discovery import build
                crm_service = build("cloudresourcemanager", "v1", credentials=credentials)
                iam_policy = crm_service.projects().getIamPolicy(
                    resource=self.project_id, body={"options": {"requestedPolicyVersion": 3}}
                ).execute()
                audit_configs = iam_policy.get("auditConfigs", [])
                bq_audit = any(
                    cfg.get("service") in ("bigquery.googleapis.com", "allServices")
                    for cfg in audit_configs
                )
                results.append(CheckResult(
                    check_id="gcp_bigquery_audit_logging",
                    check_title="BigQuery audit logging is enabled",
                    service="bigquery", severity="medium",
                    status="PASS" if bq_audit else "FAIL",
                    resource_id=f"projects/{self.project_id}",
                    status_extended=f"BigQuery audit logging enabled: {bq_audit}",
                    remediation="Enable Data Access audit logs for bigquery.googleapis.com",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())
            except Exception as e:
                logger.warning(f"BigQuery audit logging check failed: {e}")

        except Exception as e:
            logger.warning(f"GCP BigQuery checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # Pub/Sub checks (2)
    # ------------------------------------------------------------------

    def _check_pubsub(self) -> list[dict]:
        results = []
        try:
            from google.cloud import pubsub_v1
            credentials = self._get_credentials()
            publisher = pubsub_v1.PublisherClient(credentials=credentials)
            project_path = f"projects/{self.project_id}"

            topics = publisher.list_topics(request={"project": project_path})
            for topic in topics:
                topic_short = topic.name.split("/")[-1]

                # 1. gcp_pubsub_no_public_access
                try:
                    policy = publisher.get_iam_policy(request={"resource": topic.name})
                    is_public = False
                    for binding in policy.bindings:
                        for member in binding.members:
                            if member in ("allUsers", "allAuthenticatedUsers"):
                                is_public = True
                                break
                    results.append(CheckResult(
                        check_id="gcp_pubsub_no_public_access",
                        check_title="Pub/Sub topic is not publicly accessible",
                        service="pubsub", severity="high",
                        status="FAIL" if is_public else "PASS",
                        resource_id=topic.name, resource_name=topic_short,
                        status_extended=f"Pub/Sub topic {topic_short} public access: {is_public}",
                        remediation="Remove allUsers and allAuthenticatedUsers from the topic IAM policy",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
                except Exception as e:
                    logger.warning(f"Pub/Sub IAM check failed for {topic_short}: {e}")

                # 2. gcp_pubsub_encrypted
                cmek = topic.kms_key_name and len(topic.kms_key_name) > 0
                results.append(CheckResult(
                    check_id="gcp_pubsub_encrypted",
                    check_title="Pub/Sub topic is encrypted with CMEK",
                    service="pubsub", severity="medium",
                    status="PASS" if cmek else "FAIL",
                    resource_id=topic.name, resource_name=topic_short,
                    status_extended=f"Pub/Sub topic {topic_short} CMEK encryption: {cmek}",
                    remediation="Configure a Cloud KMS key for Pub/Sub topic encryption",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

        except Exception as e:
            logger.warning(f"GCP Pub/Sub checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # DNS checks (2)
    # ------------------------------------------------------------------

    def _check_dns(self) -> list[dict]:
        results = []
        try:
            from googleapiclient.discovery import build
            credentials = self._get_credentials()
            dns_svc = build("dns", "v1", credentials=credentials)

            zones = dns_svc.managedZones().list(project=self.project_id).execute()
            for zone in zones.get("managedZones", []):
                zone_name = zone.get("name", "")
                dnssec_config = zone.get("dnssecConfig", {})
                dnssec_state = dnssec_config.get("state", "off")

                # Only check public zones
                if zone.get("visibility", "public") != "public":
                    continue

                # 1. gcp_dns_dnssec_enabled
                is_on = dnssec_state == "on"
                results.append(CheckResult(
                    check_id="gcp_dns_dnssec_enabled",
                    check_title="Cloud DNS managed zone has DNSSEC enabled",
                    service="dns", severity="medium",
                    status="PASS" if is_on else "FAIL",
                    resource_id=zone.get("id", zone_name),
                    resource_name=zone_name,
                    status_extended=f"DNS zone {zone_name} DNSSEC: {dnssec_state}",
                    remediation="Enable DNSSEC on the managed zone",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 2. gcp_dns_rsasha1_disabled — check that RSASHA1 is not used for key signing
                if is_on:
                    default_key_specs = dnssec_config.get("defaultKeySpecs", [])
                    uses_rsasha1 = any(
                        spec.get("algorithm") == "RSASHA1" for spec in default_key_specs
                    )
                    results.append(CheckResult(
                        check_id="gcp_dns_rsasha1_disabled",
                        check_title="Cloud DNS DNSSEC does not use RSASHA1",
                        service="dns", severity="high",
                        status="FAIL" if uses_rsasha1 else "PASS",
                        resource_id=zone.get("id", zone_name),
                        resource_name=zone_name,
                        status_extended=f"DNS zone {zone_name} uses RSASHA1: {uses_rsasha1}",
                        remediation="Use RSASHA256, RSASHA512, or ECDSAP256SHA256 for DNSSEC key signing",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
                else:
                    results.append(CheckResult(
                        check_id="gcp_dns_rsasha1_disabled",
                        check_title="Cloud DNS DNSSEC does not use RSASHA1",
                        service="dns", severity="high",
                        status="FAIL",
                        resource_id=zone.get("id", zone_name),
                        resource_name=zone_name,
                        status_extended=f"DNS zone {zone_name} DNSSEC not enabled — cannot verify algorithm",
                        remediation="Enable DNSSEC and use RSASHA256, RSASHA512, or ECDSAP256SHA256",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

        except Exception as e:
            logger.warning(f"GCP DNS checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # Dataproc checks (2)
    # ------------------------------------------------------------------

    def _check_dataproc(self) -> list[dict]:
        results = []
        try:
            from googleapiclient.discovery import build
            credentials = self._get_credentials()
            dataproc_svc = build("dataproc", "v1", credentials=credentials)

            # List clusters across all regions
            regions_to_check = ["global"]
            try:
                compute_svc = build("compute", "v1", credentials=credentials)
                regions_resp = compute_svc.regions().list(project=self.project_id).execute()
                regions_to_check = [r["name"] for r in regions_resp.get("items", [])]
            except Exception:
                regions_to_check = ["us-central1", "us-east1", "us-west1", "europe-west1", "asia-east1"]

            for region in regions_to_check:
                try:
                    clusters_resp = dataproc_svc.projects().regions().clusters().list(
                        projectId=self.project_id, region=region
                    ).execute()
                except Exception:
                    continue

                for cluster in clusters_resp.get("clusters", []):
                    cluster_name = cluster.get("clusterName", "")
                    config = cluster.get("config", {})
                    res_id = f"projects/{self.project_id}/regions/{region}/clusters/{cluster_name}"

                    # 1. gcp_dataproc_encrypted
                    enc_config = config.get("encryptionConfig", {})
                    cmek = bool(enc_config.get("gcePdKmsKeyName"))
                    results.append(CheckResult(
                        check_id="gcp_dataproc_encrypted",
                        check_title="Dataproc cluster is encrypted with CMEK",
                        service="dataproc", severity="medium",
                        status="PASS" if cmek else "FAIL",
                        resource_id=res_id, resource_name=cluster_name,
                        status_extended=f"Dataproc cluster {cluster_name} CMEK: {cmek}",
                        remediation="Configure a KMS key for Dataproc cluster disk encryption",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

                    # 2. gcp_dataproc_private
                    gce_config = config.get("gceClusterConfig", {})
                    internal_only = gce_config.get("internalIpOnly", False)
                    results.append(CheckResult(
                        check_id="gcp_dataproc_private",
                        check_title="Dataproc cluster uses internal IP only",
                        service="dataproc", severity="high",
                        status="PASS" if internal_only else "FAIL",
                        resource_id=res_id, resource_name=cluster_name,
                        status_extended=f"Dataproc cluster {cluster_name} internal IP only: {internal_only}",
                        remediation="Configure the Dataproc cluster to use internal IP addresses only",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

        except Exception as e:
            logger.warning(f"GCP Dataproc checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # Cloud Functions checks (8)
    # ------------------------------------------------------------------

    def _check_cloud_functions(self) -> list[dict]:
        results = []
        try:
            from googleapiclient.discovery import build
            credentials = self._get_credentials()
            cf_svc = build("cloudfunctions", "v2", credentials=credentials)

            functions_resp = cf_svc.projects().locations().functions().list(
                parent=f"projects/{self.project_id}/locations/-"
            ).execute()

            for func in functions_resp.get("functions", []):
                func_name = func.get("name", "").split("/")[-1]
                res_id = func.get("name", "")
                svc_config = func.get("serviceConfig", {})
                build_config = func.get("buildConfig", {})

                # 1. Ingress restricted
                ingress = svc_config.get("ingressSettings", "ALLOW_ALL")
                results.append(CheckResult(
                    check_id="gcp_function_ingress_restricted",
                    check_title="Cloud Function restricts ingress traffic",
                    service="cloudfunctions", severity="high",
                    status="PASS" if ingress != "ALLOW_ALL" else "FAIL",
                    resource_id=res_id, resource_name=func_name,
                    status_extended=f"Function {func_name} ingress: {ingress}",
                    remediation="Set ingress settings to ALLOW_INTERNAL_ONLY or ALLOW_INTERNAL_AND_GCLB",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 2. VPC connector
                vpc_connector = svc_config.get("vpcConnector", "")
                results.append(CheckResult(
                    check_id="gcp_function_vpc_connector",
                    check_title="Cloud Function uses a VPC connector",
                    service="cloudfunctions", severity="medium",
                    status="PASS" if vpc_connector else "FAIL",
                    resource_id=res_id, resource_name=func_name,
                    status_extended=f"Function {func_name} VPC connector: {vpc_connector or 'none'}",
                    remediation="Attach a Serverless VPC Access connector to route traffic through your VPC",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3. Runtime version not deprecated
                runtime = build_config.get("runtime", "")
                deprecated_runtimes = ["python37", "python38", "nodejs10", "nodejs12", "go111", "go113"]
                is_deprecated = runtime in deprecated_runtimes
                results.append(CheckResult(
                    check_id="gcp_function_runtime_supported",
                    check_title="Cloud Function uses a supported runtime version",
                    service="cloudfunctions", severity="medium",
                    status="FAIL" if is_deprecated else "PASS",
                    resource_id=res_id, resource_name=func_name,
                    status_extended=f"Function {func_name} runtime: {runtime}",
                    remediation="Upgrade to a supported runtime version",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 4. No default service account
                sa = svc_config.get("serviceAccountEmail", "")
                uses_default = sa.endswith("@appspot.gserviceaccount.com") or \
                    "compute@developer.gserviceaccount.com" in sa
                results.append(CheckResult(
                    check_id="gcp_function_custom_sa",
                    check_title="Cloud Function uses a custom service account",
                    service="cloudfunctions", severity="high",
                    status="FAIL" if uses_default else "PASS",
                    resource_id=res_id, resource_name=func_name,
                    status_extended=f"Function {func_name} SA: {sa}",
                    remediation="Assign a dedicated service account with least-privilege permissions",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 5. Secret environment variables (not in plaintext)
                env_vars = svc_config.get("environmentVariables", {})
                suspect_keys = [k for k in env_vars if any(
                    s in k.upper() for s in ["SECRET", "PASSWORD", "KEY", "TOKEN", "API_KEY"]
                )]
                results.append(CheckResult(
                    check_id="gcp_function_no_secret_envvars",
                    check_title="Cloud Function does not store secrets in plaintext env vars",
                    service="cloudfunctions", severity="critical",
                    status="FAIL" if suspect_keys else "PASS",
                    resource_id=res_id, resource_name=func_name,
                    status_extended=f"Function {func_name} suspect env vars: {suspect_keys or 'none'}",
                    remediation="Use Secret Manager references instead of plaintext environment variables",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 6. Max instances limit set
                max_instances = svc_config.get("maxInstanceCount", 0)
                results.append(CheckResult(
                    check_id="gcp_function_max_instances",
                    check_title="Cloud Function has max instances limit configured",
                    service="cloudfunctions", severity="low",
                    status="PASS" if max_instances > 0 else "FAIL",
                    resource_id=res_id, resource_name=func_name,
                    status_extended=f"Function {func_name} max instances: {max_instances or 'unlimited'}",
                    remediation="Set a max instances limit to prevent runaway scaling and cost overruns",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

        except Exception as e:
            logger.warning(f"GCP Cloud Functions checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # Cloud Run checks (8)
    # ------------------------------------------------------------------

    def _check_cloud_run(self) -> list[dict]:
        results = []
        try:
            from googleapiclient.discovery import build
            credentials = self._get_credentials()
            run_svc = build("run", "v2", credentials=credentials)

            services_resp = run_svc.projects().locations().services().list(
                parent=f"projects/{self.project_id}/locations/-"
            ).execute()

            for service in services_resp.get("services", []):
                svc_name = service.get("name", "").split("/")[-1]
                res_id = service.get("name", "")
                template = service.get("template", {})

                # 1. No public unauthenticated access
                iam_resp = run_svc.projects().locations().services().getIamPolicy(
                    resource=res_id
                ).execute()
                bindings = iam_resp.get("bindings", [])
                is_public = any(
                    "allUsers" in b.get("members", []) or
                    "allAuthenticatedUsers" in b.get("members", [])
                    for b in bindings if b.get("role") == "roles/run.invoker"
                )
                results.append(CheckResult(
                    check_id="gcp_cloudrun_no_public_access",
                    check_title="Cloud Run service does not allow unauthenticated access",
                    service="cloudrun", severity="high",
                    status="FAIL" if is_public else "PASS",
                    resource_id=res_id, resource_name=svc_name,
                    status_extended=f"Service {svc_name} public access: {is_public}",
                    remediation="Remove allUsers/allAuthenticatedUsers from Cloud Run invoker role",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 2. Custom service account
                sa = template.get("serviceAccount", "")
                uses_default = not sa or sa.endswith("compute@developer.gserviceaccount.com")
                results.append(CheckResult(
                    check_id="gcp_cloudrun_custom_sa",
                    check_title="Cloud Run service uses a custom service account",
                    service="cloudrun", severity="high",
                    status="FAIL" if uses_default else "PASS",
                    resource_id=res_id, resource_name=svc_name,
                    status_extended=f"Service {svc_name} SA: {sa or 'default compute SA'}",
                    remediation="Assign a dedicated service account with minimal permissions",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3. VPC egress configured
                annotations = template.get("annotations", {})
                vpc_access = annotations.get("run.googleapis.com/vpc-access-connector", "")
                egress = annotations.get("run.googleapis.com/vpc-access-egress", "")
                results.append(CheckResult(
                    check_id="gcp_cloudrun_vpc_egress",
                    check_title="Cloud Run service routes egress through VPC",
                    service="cloudrun", severity="medium",
                    status="PASS" if vpc_access and egress == "all-traffic" else "FAIL",
                    resource_id=res_id, resource_name=svc_name,
                    status_extended=f"Service {svc_name} VPC connector: {vpc_access or 'none'}, egress: {egress or 'default'}",
                    remediation="Configure a VPC connector with all-traffic egress for network security",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 4. Ingress restricted
                ingress = service.get("ingress", "INGRESS_TRAFFIC_ALL")
                results.append(CheckResult(
                    check_id="gcp_cloudrun_ingress_restricted",
                    check_title="Cloud Run service restricts ingress traffic",
                    service="cloudrun", severity="high",
                    status="PASS" if ingress != "INGRESS_TRAFFIC_ALL" else "FAIL",
                    resource_id=res_id, resource_name=svc_name,
                    status_extended=f"Service {svc_name} ingress: {ingress}",
                    remediation="Set ingress to INGRESS_TRAFFIC_INTERNAL_ONLY or INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 5. Binary authorization
                binary_auth = service.get("binaryAuthorization", {})
                ba_enabled = binary_auth.get("useDefault", False) or binary_auth.get("policy")
                results.append(CheckResult(
                    check_id="gcp_cloudrun_binary_auth",
                    check_title="Cloud Run service has Binary Authorization enabled",
                    service="cloudrun", severity="medium",
                    status="PASS" if ba_enabled else "FAIL",
                    resource_id=res_id, resource_name=svc_name,
                    status_extended=f"Service {svc_name} Binary Authorization: {bool(ba_enabled)}",
                    remediation="Enable Binary Authorization to ensure only trusted container images are deployed",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 6. CMEK encryption
                encryption = template.get("encryptionKey", "")
                results.append(CheckResult(
                    check_id="gcp_cloudrun_cmek",
                    check_title="Cloud Run service uses customer-managed encryption key",
                    service="cloudrun", severity="medium",
                    status="PASS" if encryption else "FAIL",
                    resource_id=res_id, resource_name=svc_name,
                    status_extended=f"Service {svc_name} CMEK: {encryption or 'Google-managed'}",
                    remediation="Configure a CMEK from Cloud KMS for Cloud Run service encryption",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 7. Container secrets not in env vars
                containers = template.get("containers", [{}])
                for container in containers:
                    env_list = container.get("env", [])
                    suspect = [e["name"] for e in env_list if
                               e.get("value") and any(
                                   s in e["name"].upper()
                                   for s in ["SECRET", "PASSWORD", "KEY", "TOKEN", "APIKEY"]
                               )]
                    results.append(CheckResult(
                        check_id="gcp_cloudrun_no_secret_envvars",
                        check_title="Cloud Run container does not store secrets in plaintext env vars",
                        service="cloudrun", severity="critical",
                        status="FAIL" if suspect else "PASS",
                        resource_id=res_id, resource_name=svc_name,
                        status_extended=f"Service {svc_name} suspect env vars: {suspect or 'none'}",
                        remediation="Use Secret Manager volumes or references instead of plaintext env vars",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())

        except Exception as e:
            logger.warning(f"GCP Cloud Run checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # Secret Manager checks (6)
    # ------------------------------------------------------------------

    def _check_secret_manager(self) -> list[dict]:
        results = []
        try:
            from googleapiclient.discovery import build
            credentials = self._get_credentials()
            sm_svc = build("secretmanager", "v1", credentials=credentials)

            secrets_resp = sm_svc.projects().secrets().list(
                parent=f"projects/{self.project_id}"
            ).execute()

            for secret in secrets_resp.get("secrets", []):
                secret_name = secret.get("name", "").split("/")[-1]
                res_id = secret.get("name", "")
                labels = secret.get("labels", {})
                replication = secret.get("replication", {})

                # 1. CMEK encryption
                has_cmek = False
                if replication.get("userManaged"):
                    replicas = replication["userManaged"].get("replicas", [])
                    has_cmek = all(
                        r.get("customerManagedEncryption", {}).get("kmsKeyName")
                        for r in replicas
                    )
                elif replication.get("automatic"):
                    has_cmek = bool(
                        replication["automatic"].get("customerManagedEncryption", {}).get("kmsKeyName")
                    )
                results.append(CheckResult(
                    check_id="gcp_secret_cmek",
                    check_title="Secret is encrypted with customer-managed key",
                    service="secretmanager", severity="medium",
                    status="PASS" if has_cmek else "FAIL",
                    resource_id=res_id, resource_name=secret_name,
                    status_extended=f"Secret {secret_name} CMEK: {has_cmek}",
                    remediation="Configure CMEK encryption for the secret using Cloud KMS",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 2. Rotation configured
                rotation = secret.get("rotation", {})
                has_rotation = bool(rotation.get("rotationPeriod") or rotation.get("nextRotationTime"))
                results.append(CheckResult(
                    check_id="gcp_secret_rotation",
                    check_title="Secret has automatic rotation configured",
                    service="secretmanager", severity="high",
                    status="PASS" if has_rotation else "FAIL",
                    resource_id=res_id, resource_name=secret_name,
                    status_extended=f"Secret {secret_name} rotation: {'configured' if has_rotation else 'not configured'}",
                    remediation="Configure automatic rotation with a rotation period and Cloud Function topic",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 3. Labels/ownership
                has_owner = bool(labels.get("owner") or labels.get("team") or labels.get("managed-by"))
                results.append(CheckResult(
                    check_id="gcp_secret_labeled",
                    check_title="Secret has ownership labels",
                    service="secretmanager", severity="low",
                    status="PASS" if has_owner else "FAIL",
                    resource_id=res_id, resource_name=secret_name,
                    status_extended=f"Secret {secret_name} ownership labels: {has_owner}",
                    remediation="Add owner/team labels to track secret ownership and responsibility",
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                ).to_dict())

                # 4. IAM not overly permissive
                try:
                    iam_resp = sm_svc.projects().secrets().getIamPolicy(
                        resource=res_id
                    ).execute()
                    bindings = iam_resp.get("bindings", [])
                    overly_permissive = any(
                        "allUsers" in b.get("members", []) or
                        "allAuthenticatedUsers" in b.get("members", [])
                        for b in bindings
                    )
                    results.append(CheckResult(
                        check_id="gcp_secret_no_public_access",
                        check_title="Secret is not accessible to allUsers or allAuthenticatedUsers",
                        service="secretmanager", severity="critical",
                        status="FAIL" if overly_permissive else "PASS",
                        resource_id=res_id, resource_name=secret_name,
                        status_extended=f"Secret {secret_name} public access: {overly_permissive}",
                        remediation="Remove allUsers/allAuthenticatedUsers from secret IAM bindings",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
                except Exception:
                    pass

                # 5. Version count (detect stale secrets with many unused versions)
                try:
                    versions_resp = sm_svc.projects().secrets().versions().list(
                        parent=res_id
                    ).execute()
                    versions = versions_resp.get("versions", [])
                    enabled_count = sum(1 for v in versions if v.get("state") == "ENABLED")
                    results.append(CheckResult(
                        check_id="gcp_secret_version_cleanup",
                        check_title="Secret does not have excessive enabled versions",
                        service="secretmanager", severity="low",
                        status="FAIL" if enabled_count > 5 else "PASS",
                        resource_id=res_id, resource_name=secret_name,
                        status_extended=f"Secret {secret_name} enabled versions: {enabled_count}",
                        remediation="Disable or destroy old secret versions to reduce exposure surface",
                        compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    ).to_dict())
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"GCP Secret Manager checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # CIS coverage gap-fill
    # ------------------------------------------------------------------

    def _emit_cis_coverage(self, automated_results: list[dict]) -> list[dict]:
        """Emit MANUAL results for CIS controls not covered by automated checks.

        Ensures every control from the CIS GCP Foundation Benchmark v3.0.0
        appears in the scan output.  Automated checks that already produced
        PASS/FAIL results are skipped; uncovered controls are emitted with
        status ``MANUAL`` so that reviewers know a human assessment is needed.
        """
        # Build set of CIS IDs already covered by automated results
        covered_cis_ids: set[str] = set()
        for result in automated_results:
            cis_id = result.get("cis_control_id")
            if cis_id:
                covered_cis_ids.add(cis_id)

        # Map check_ids to CIS control IDs based on naming patterns
        check_to_cis: dict[str, str] = {
            # Section 1 — IAM
            "gcp_iam_corp_login_required": "1.1",
            "gcp_iam_no_user_managed_sa_keys": "1.4",
            "gcp_iam_no_sa_admin_key": "1.5",
            "gcp_iam_sa_user_role": "1.6",
            "gcp_iam_sa_token_creator_role": "1.6",
            "gcp_iam_sa_key_rotation": "1.7",
            "gcp_iam_kms_separation_of_duties": "1.8",
            "gcp_kms_no_public_access": "1.9",
            "gcp_kms_key_rotation": "1.10",
            "gcp_iam_api_keys_restricted": "1.11",
            "gcp_iam_api_keys_rotated": "1.13",
            "gcp_iam_api_keys_exist": "1.14",
            "gcp_iam_essential_contacts": "1.15",
            # Section 2 — Logging & Monitoring
            "gcp_logging_audit_logs_enabled": "2.1",
            "gcp_logging_ownership_changes": "2.2",
            "gcp_logging_audit_config_changes": "2.3",
            "gcp_logging_custom_role_changes": "2.4",
            "gcp_logging_firewall_changes": "2.5",
            "gcp_logging_route_changes": "2.6",
            "gcp_logging_vpc_changes": "2.7",
            "gcp_logging_storage_iam_changes": "2.8",
            "gcp_logging_sql_config_changes": "2.9",
            "gcp_logging_dns_logging": "2.10",
            "gcp_logging_cloud_asset_inventory": "2.11",
            "gcp_logging_bucket_retention": "2.16",
            "gcp_logging_vpc_flow_logs": "3.5",
            # Section 3 — Networking
            "gcp_network_no_default_network": "3.1",
            "gcp_network_no_legacy_network": "3.2",
            "gcp_network_dns_sec": "3.3",
            "gcp_dns_dnssec_enabled": "3.3",
            "gcp_dns_rsasha1_disabled": "3.4",
            "gcp_network_flow_logs_enabled": "3.5",
            "gcp_firewall_open_22": "3.6",
            "gcp_firewall_open_3389": "3.7",
            "gcp_network_ssl_policy": "3.8",
            "gcp_firewall_no_default_allow": "3.10",
            # Section 4 — Virtual Machines
            "gcp_compute_no_default_sa": "4.1",
            "gcp_compute_no_full_api_access": "4.2",
            "gcp_compute_block_project_ssh": "4.3",
            "gcp_compute_os_login": "4.4",
            "gcp_compute_serial_port_disabled": "4.5",
            "gcp_compute_ip_forwarding_disabled": "4.6",
            "gcp_compute_disk_encryption_cmek": "4.7",
            "gcp_compute_shielded_vm": "4.8",
            "gcp_compute_no_external_ip": "4.9",
            "gcp_compute_confidential_computing": "4.12",
            # Section 5 — Storage
            "gcp_storage_no_public_access": "5.1",
            "gcp_storage_uniform_access": "5.2",
            "gcp_storage_versioning": "5.3",
            "gcp_storage_cmek_encryption": "5.4",
            "gcp_storage_logging_enabled": "5.5",
            "gcp_storage_retention_policy": "5.6",
            # Section 6 — Cloud SQL
            "gcp_sql_no_public_networks": "6.1",
            "gcp_sql_no_public_ip": "6.2",
            "gcp_sql_ssl_required": "6.3",
            "gcp_sql_backup_enabled": "6.5",
            "gcp_sql_pitr_enabled": "6.6",
            "gcp_sql_cmek_encryption": "6.4",
            # Section 7 — BigQuery
            "gcp_bigquery_dataset_no_public": "7.1",
            "gcp_bigquery_cmek_encryption": "7.2",
            "gcp_bigquery_classification": "7.3",
            "gcp_bigquery_table_encrypted": "7.4",
        }

        for result in automated_results:
            check_id = result.get("check_id", "")
            if check_id in check_to_cis:
                covered_cis_ids.add(check_to_cis[check_id])

        # Emit MANUAL results for uncovered CIS controls
        manual_results: list[dict] = []
        for ctrl in GCP_CIS_CONTROLS:
            cis_id = ctrl["cis_id"]
            title = ctrl["title"]
            level = ctrl["cis_level"]
            assess_type = ctrl["assessment_type"]
            severity = ctrl["severity"]
            service_area = ctrl["service_area"]
            if cis_id not in covered_cis_ids:
                manual_results.append(CheckResult(
                    check_id=f"gcp_cis_{cis_id.replace('.', '_')}",
                    check_title=f"{title} (CIS {cis_id})",
                    service=service_area,
                    severity=severity,
                    status="MANUAL",
                    resource_id=self.project_id,
                    status_extended=(
                        f"CIS {cis_id} [{level}] - {assess_type.upper()} assessment. "
                        f"This control requires "
                        f"{'manual verification' if assess_type == 'manual' else 'automated check implementation'}."
                    ),
                    remediation=ctrl.get("remediation", f"Refer to CIS Google Cloud Platform Foundation Benchmark v4.0.0, control {cis_id}."),
                    compliance_frameworks=_DEFAULT_FRAMEWORKS,
                    assessment_type=assess_type,
                    cis_control_id=cis_id,
                    cis_level=level,
                ).to_dict())

        return manual_results

    # ------------------------------------------------------------------
    # Public entry point with full CIS coverage
    # ------------------------------------------------------------------

    def run_all_checks(self) -> list[dict]:
        """Run all GCP security checks including complete CIS benchmark coverage.

        Three-phase approach:
          1. Service checks (existing scan() method)
          2. CIS Evaluator Engine (84 controls — CIS GCP v4.0.0)
          3. Fallback: _emit_cis_coverage() if engine fails
        """
        slog = getattr(self, "_scan_logger", None)

        # Phase 1: Service checks
        if slog:
            slog.log_phase_start("service_checks", "gcp_scanner.py")
        results = self.scan()
        if slog:
            slog.log_phase_end("service_checks", "gcp_scanner.py", result_count=len(results))

        # Phase 2: CIS Evaluator Engine (84 controls)
        if slog:
            slog.log_phase_start("cis_evaluator_engine", "gcp_cis_evaluator_engine.py")
        try:
            from .gcp_cis_evaluator_engine import GCPCISEvaluatorEngine
            engine = GCPCISEvaluatorEngine(
                credentials=self.credentials,
                services=self.services,
            )
            cis_results = engine.evaluate_all()

            # Deduplicate: CIS evaluator results take precedence
            existing_check_ids = {r.get("check_id") for r in results if r.get("check_id")}
            added = 0
            for r in cis_results:
                cid = r.get("check_id", "")
                if cid not in existing_check_ids:
                    results.append(r)
                    existing_check_ids.add(cid)
                    added += 1

            logger.info("GCP CIS engine added %d results", len(cis_results))
            if slog:
                slog.log_phase_end("cis_evaluator_engine", "gcp_cis_evaluator_engine.py", result_count=added)
        except Exception as e:
            logger.warning("GCP CIS engine failed, falling back to CIS coverage gap-fill: %s", e)
            if slog:
                slog.log_error("gcp_cis_evaluator_engine.py", f"CIS engine failed: {e}")
                slog.log_phase_end("cis_evaluator_engine", "gcp_cis_evaluator_engine.py", status="error")
            results.extend(self._emit_cis_coverage(results))

        return results
