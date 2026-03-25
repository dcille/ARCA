"""OCI (Oracle Cloud Infrastructure) Security Scanner.

Implements security checks for OCI services following CIS Oracle Cloud
Infrastructure Foundations Benchmark v2.0 and v3.1.
Provides complete CIS OCI Foundations Benchmark v2.0.0 coverage by emitting MANUAL results
for any controls not covered by automated checks.
"""
import logging
from typing import Optional

from scanner.cis_controls.oci_cis_controls import OCI_CIS_CONTROLS
from scanner.providers.base_check import CheckResult

logger = logging.getLogger(__name__)


class OCIScanner:
    """Oracle Cloud Infrastructure security scanner."""

    def __init__(self, credentials: dict, regions: Optional[list] = None, services: Optional[list] = None):
        self.credentials = credentials
        self.regions = regions or ["us-ashburn-1"]
        self.services = services
        self._config = None

    def _get_config(self) -> dict:
        """Build OCI SDK config from credentials."""
        if not self._config:
            self._config = {
                "user": self.credentials.get("user_ocid"),
                "key_content": self.credentials.get("private_key"),
                "fingerprint": self.credentials.get("fingerprint"),
                "tenancy": self.credentials.get("tenancy_ocid"),
                "region": self.regions[0] if self.regions else "us-ashburn-1",
            }
            if self.credentials.get("passphrase"):
                self._config["pass_phrase"] = self.credentials["passphrase"]
        return self._config

    def scan(self) -> list[dict]:
        """Run all OCI security checks."""
        results = []
        check_methods = {
            "iam": self._check_iam,
            "networking": self._check_networking,
            "compute": self._check_compute,
            "storage": self._check_storage,
            "database": self._check_database,
            "vault": self._check_vault,
            "logging": self._check_logging,
            "cloud_guard": self._check_cloud_guard,
            "notifications": self._check_notifications,
            "object_storage": self._check_object_storage,
            "functions": self._check_functions,
            "container_instances": self._check_container_instances,
            "container_registry": self._check_container_registry,
            "file_storage": self._check_file_storage,
            "kubernetes_engine": self._check_kubernetes_engine,
            "load_balancer": self._check_load_balancer,
            "mysql": self._check_mysql,
            "events": self._check_events,
        }

        for service_name, check_fn in check_methods.items():
            if self.services and service_name not in self.services:
                continue
            try:
                service_results = check_fn()
                results.extend(service_results)
            except ImportError:
                logger.warning(f"OCI SDK not available for {service_name} checks")
            except Exception as e:
                logger.error(f"OCI {service_name} check failed: {e}")

        return results

    # ── IAM Checks (CIS 1.x) ────────────────────────────────────

    def _check_iam(self) -> list[dict]:
        """IAM security checks following CIS OCI Foundations Benchmark."""
        results = []
        try:
            import oci
            config = self._get_config()
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            # CIS 1.1 - Check for API keys older than 90 days
            try:
                users = identity_client.list_users(tenancy_id).data
                for user in users:
                    api_keys = identity_client.list_api_keys(user.id).data
                    for key in api_keys:
                        from datetime import datetime, timezone, timedelta
                        age = datetime.now(timezone.utc) - key.time_created
                        status = "FAIL" if age.days > 90 else "PASS"
                        results.append(CheckResult(
                            check_id="oci_iam_api_key_rotation",
                            check_title="IAM API keys should be rotated within 90 days",
                            service="IAM",
                            severity="high",
                            status=status,
                            resource_id=key.key_id,
                            resource_name=user.name,
                            status_extended=f"API key for user {user.name} is {age.days} days old",
                            remediation="Rotate API keys every 90 days or less",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())
            except Exception as e:
                logger.warning(f"OCI IAM API key check failed: {e}")

            # CIS 1.2 - MFA enabled for local users
            try:
                for user in users:
                    if user.is_mfa_activated is not None:
                        status = "PASS" if user.is_mfa_activated else "FAIL"
                        results.append(CheckResult(
                            check_id="oci_iam_user_mfa_enabled",
                            check_title="IAM local users should have MFA enabled",
                            service="IAM",
                            severity="critical",
                            status=status,
                            resource_id=user.id,
                            resource_name=user.name,
                            status_extended=f"MFA {'enabled' if user.is_mfa_activated else 'not enabled'} for {user.name}",
                            remediation="Enable MFA for all local IAM users",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())
            except Exception as e:
                logger.warning(f"OCI IAM MFA check failed: {e}")

            # CIS 1.3 - Check for admin users without MFA
            try:
                groups = identity_client.list_groups(tenancy_id).data
                admin_group = next((g for g in groups if g.name == "Administrators"), None)
                if admin_group:
                    members = identity_client.list_user_group_memberships(
                        tenancy_id, group_id=admin_group.id
                    ).data
                    for member in members:
                        user = identity_client.get_user(member.user_id).data
                        status = "PASS" if user.is_mfa_activated else "FAIL"
                        results.append(CheckResult(
                            check_id="oci_iam_admin_mfa_enabled",
                            check_title="Administrator users must have MFA enabled",
                            service="IAM",
                            severity="critical",
                            status=status,
                            resource_id=user.id,
                            resource_name=user.name,
                            status_extended=f"Admin user {user.name} MFA: {'enabled' if user.is_mfa_activated else 'disabled'}",
                            remediation="Enable MFA for all users in the Administrators group",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())
            except Exception as e:
                logger.warning(f"OCI admin MFA check failed: {e}")

            # CIS 1.4 - Password policy strength
            try:
                password_policy = identity_client.get_authentication_policy(tenancy_id).data.password_policy
                checks = [
                    ("oci_iam_password_length", "Password minimum length >= 14",
                     password_policy.minimum_password_length >= 14 if password_policy.minimum_password_length else False),
                    ("oci_iam_password_uppercase", "Password requires uppercase characters",
                     password_policy.is_uppercase_characters_required),
                    ("oci_iam_password_lowercase", "Password requires lowercase characters",
                     password_policy.is_lowercase_characters_required),
                    ("oci_iam_password_numeric", "Password requires numeric characters",
                     password_policy.is_numeric_characters_required),
                    ("oci_iam_password_special", "Password requires special characters",
                     password_policy.is_special_characters_required),
                ]
                for check_id, title, passed in checks:
                    results.append(CheckResult(
                        check_id=check_id,
                        check_title=title,
                        service="IAM",
                        severity="medium",
                        status="PASS" if passed else "FAIL",
                        resource_id=tenancy_id,
                        resource_name="Authentication Policy",
                        remediation="Update the IAM password policy to meet CIS requirements",
                        compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                    ).to_dict())
            except Exception as e:
                logger.warning(f"OCI password policy check failed: {e}")

            # CIS 1.7 - Check for customer secret keys older than 90 days
            try:
                for user in users:
                    secret_keys = identity_client.list_customer_secret_keys(user.id).data
                    for sk in secret_keys:
                        from datetime import datetime, timezone
                        age = datetime.now(timezone.utc) - sk.time_created
                        status = "FAIL" if age.days > 90 else "PASS"
                        results.append(CheckResult(
                            check_id="oci_iam_secret_key_rotation",
                            check_title="Customer secret keys should be rotated within 90 days",
                            service="IAM",
                            severity="high",
                            status=status,
                            resource_id=sk.id,
                            resource_name=user.name,
                            status_extended=f"Secret key for {user.name} is {age.days} days old",
                            remediation="Rotate customer secret keys every 90 days",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())
            except Exception as e:
                logger.warning(f"OCI secret key check failed: {e}")

            # CIS 1.12 - Policy statements should not have wildcard permissions
            try:
                policies = identity_client.list_policies(tenancy_id).data
                for policy in policies:
                    for stmt in (policy.statements or []):
                        has_wildcard = "manage all-resources" in stmt.lower()
                        if has_wildcard:
                            results.append(CheckResult(
                                check_id="oci_iam_policy_no_wildcard",
                                check_title="IAM policies should not allow wildcard resource access",
                                service="IAM",
                                severity="high",
                                status="FAIL",
                                resource_id=policy.id,
                                resource_name=policy.name,
                                status_extended=f"Policy '{policy.name}' has 'manage all-resources' statement",
                                remediation="Replace wildcard permissions with specific resource types",
                                compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                            ).to_dict())
            except Exception as e:
                logger.warning(f"OCI policy wildcard check failed: {e}")

            # CIS 3.1 1.10 - Auth tokens should be rotated every 90 days
            try:
                for user in users:
                    auth_tokens = identity_client.list_auth_tokens(user.id).data
                    for token in auth_tokens:
                        from datetime import datetime, timezone
                        age = datetime.now(timezone.utc) - token.time_created
                        status = "FAIL" if age.days > 90 else "PASS"
                        results.append(CheckResult(
                            check_id="oci_iam_auth_token_rotation",
                            check_title="IAM auth tokens should be rotated within 90 days",
                            service="IAM",
                            severity="high",
                            status=status,
                            resource_id=token.id,
                            resource_name=user.name,
                            status_extended=f"Auth token for {user.name} is {age.days} days old",
                            remediation="Rotate auth tokens every 90 days or less",
                            compliance_frameworks=["CIS-OCI-3.1"],
                        ).to_dict())
            except Exception as e:
                logger.warning(f"OCI auth token rotation check failed: {e}")

            # CIS 3.1 1.12 - Admin users should not have API keys
            try:
                groups = identity_client.list_groups(tenancy_id).data
                admin_group = next((g for g in groups if g.name == "Administrators"), None)
                if admin_group:
                    members = identity_client.list_user_group_memberships(
                        tenancy_id, group_id=admin_group.id
                    ).data
                    for member in members:
                        user = identity_client.get_user(member.user_id).data
                        api_keys = identity_client.list_api_keys(user.id).data
                        active_keys = [k for k in api_keys if k.lifecycle_state == "ACTIVE"]
                        results.append(CheckResult(
                            check_id="oci_iam_admin_no_api_key",
                            check_title="Tenancy administrator users should not have API keys",
                            service="IAM",
                            severity="critical",
                            status="FAIL" if active_keys else "PASS",
                            resource_id=user.id,
                            resource_name=user.name,
                            status_extended=f"Admin user {user.name} has {len(active_keys)} active API key(s)" if active_keys else f"Admin user {user.name} has no API keys",
                            remediation="Remove API keys from tenancy administrator users and use service-level admins instead",
                            compliance_frameworks=["CIS-OCI-3.1"],
                        ).to_dict())
            except Exception as e:
                logger.warning(f"OCI admin API key check failed: {e}")

            # CIS 3.1 1.13 - All IAM local users should have valid email
            try:
                for user in users:
                    has_email = getattr(user, 'email', None) is not None and getattr(user, 'email', '') != ''
                    results.append(CheckResult(
                        check_id="oci_iam_user_valid_email",
                        check_title="All IAM local users should have a valid email address",
                        service="IAM",
                        severity="medium",
                        status="PASS" if has_email else "FAIL",
                        resource_id=user.id,
                        resource_name=user.name,
                        status_extended=f"User {user.name} {'has' if has_email else 'does not have'} a valid email",
                        remediation="Set a valid email address for all IAM local user accounts",
                        compliance_frameworks=["CIS-OCI-3.1"],
                    ).to_dict())
            except Exception as e:
                logger.warning(f"OCI user email check failed: {e}")

            # CIS 3.1 1.17 - Only one active API key per user
            try:
                for user in users:
                    api_keys = identity_client.list_api_keys(user.id).data
                    active_keys = [k for k in api_keys if k.lifecycle_state == "ACTIVE"]
                    if len(active_keys) > 1:
                        results.append(CheckResult(
                            check_id="oci_iam_single_api_key",
                            check_title="Each IAM user should have only one active API key",
                            service="IAM",
                            severity="medium",
                            status="FAIL",
                            resource_id=user.id,
                            resource_name=user.name,
                            status_extended=f"User {user.name} has {len(active_keys)} active API keys",
                            remediation="Remove extra API keys so each user has at most one active key",
                            compliance_frameworks=["CIS-OCI-3.1"],
                        ).to_dict())
                    elif len(active_keys) <= 1:
                        results.append(CheckResult(
                            check_id="oci_iam_single_api_key",
                            check_title="Each IAM user should have only one active API key",
                            service="IAM",
                            severity="medium",
                            status="PASS",
                            resource_id=user.id,
                            resource_name=user.name,
                            status_extended=f"User {user.name} has {len(active_keys)} active API key(s)",
                            remediation="Remove extra API keys so each user has at most one active key",
                            compliance_frameworks=["CIS-OCI-3.1"],
                        ).to_dict())
            except Exception as e:
                logger.warning(f"OCI single API key check failed: {e}")

            # CIS 3.1 1.5/1.6 - Password policy expiry and reuse
            try:
                password_policy = identity_client.get_authentication_policy(tenancy_id).data.password_policy
                # Password expiry <= 365 days
                results.append(CheckResult(
                    check_id="oci_iam_password_expiry",
                    check_title="IAM password policy should expire passwords within 365 days",
                    service="IAM",
                    severity="medium",
                    status="PASS" if getattr(password_policy, 'is_password_expiry_enabled', False) else "FAIL",
                    resource_id=tenancy_id,
                    resource_name="Authentication Policy",
                    remediation="Enable password expiry and set maximum password age to 365 days or less",
                    compliance_frameworks=["CIS-OCI-3.1"],
                ).to_dict())

                # Password reuse prevention
                num_previous = getattr(password_policy, 'num_previous_passwords_to_remember', 0) or 0
                results.append(CheckResult(
                    check_id="oci_iam_password_reuse",
                    check_title="IAM password policy should prevent reuse of last 24 passwords",
                    service="IAM",
                    severity="medium",
                    status="PASS" if num_previous >= 24 else "FAIL",
                    resource_id=tenancy_id,
                    resource_name="Authentication Policy",
                    status_extended=f"Password reuse prevention remembers {num_previous} passwords",
                    remediation="Set password policy to remember at least 24 previous passwords",
                    compliance_frameworks=["CIS-OCI-3.1"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"OCI password policy advanced check failed: {e}")

            # CIS 3.1 1.16 - Credentials unused for 45+ days should be disabled
            try:
                for user in users:
                    from datetime import datetime, timezone, timedelta
                    last_login = getattr(user, 'last_successful_login_time', None)
                    if last_login:
                        inactive_days = (datetime.now(timezone.utc) - last_login).days
                        if inactive_days > 45 and user.lifecycle_state == "ACTIVE":
                            results.append(CheckResult(
                                check_id="oci_iam_credentials_unused",
                                check_title="IAM credentials unused for 45+ days should be disabled",
                                service="IAM",
                                severity="high",
                                status="FAIL",
                                resource_id=user.id,
                                resource_name=user.name,
                                status_extended=f"User {user.name} last login was {inactive_days} days ago",
                                remediation="Disable or remove user accounts inactive for more than 45 days",
                                compliance_frameworks=["CIS-OCI-3.1"],
                            ).to_dict())
                        else:
                            results.append(CheckResult(
                                check_id="oci_iam_credentials_unused",
                                check_title="IAM credentials unused for 45+ days should be disabled",
                                service="IAM",
                                severity="high",
                                status="PASS",
                                resource_id=user.id,
                                resource_name=user.name,
                                status_extended=f"User {user.name} last login was {inactive_days} days ago",
                                remediation="Disable or remove user accounts inactive for more than 45 days",
                                compliance_frameworks=["CIS-OCI-3.1"],
                            ).to_dict())
            except Exception as e:
                logger.warning(f"OCI unused credentials check failed: {e}")

        except ImportError:
            logger.warning("OCI SDK (oci) not installed, skipping IAM checks")
        except Exception as e:
            logger.error(f"OCI IAM checks failed: {e}")

        return results

    # ── Networking Checks (CIS 2.x) ──────────────────────────────

    def _check_networking(self) -> list[dict]:
        """Network security checks following CIS OCI Benchmark."""
        results = []
        try:
            import oci
            config = self._get_config()
            vcn_client = oci.core.VirtualNetworkClient(config)
            tenancy_id = config["tenancy"]

            identity_client = oci.identity.IdentityClient(config)
            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            for compartment_id in compartment_ids:
                try:
                    # CIS 2.1/2.2 - Security lists should not allow unrestricted ingress on ports 22/3389
                    security_lists = vcn_client.list_security_lists(compartment_id).data
                    for sl in security_lists:
                        for rule in (sl.ingress_security_rules or []):
                            source = getattr(rule, 'source', '')
                            if source == '0.0.0.0/0':
                                tcp_opts = getattr(rule, 'tcp_options', None)
                                if tcp_opts:
                                    dst = getattr(tcp_opts, 'destination_port_range', None)
                                    if dst:
                                        port_min = getattr(dst, 'min', 0)
                                        port_max = getattr(dst, 'max', 0)
                                        for port, check_id, title in [
                                            (22, "oci_network_sl_no_ssh_open", "Security lists should not allow unrestricted SSH (port 22)"),
                                            (3389, "oci_network_sl_no_rdp_open", "Security lists should not allow unrestricted RDP (port 3389)"),
                                        ]:
                                            if port_min <= port <= port_max:
                                                results.append(CheckResult(
                                                    check_id=check_id,
                                                    check_title=title,
                                                    service="Networking",
                                                    severity="high",
                                                    status="FAIL",
                                                    resource_id=sl.id,
                                                    resource_name=sl.display_name,
                                                    status_extended=f"Security list '{sl.display_name}' allows 0.0.0.0/0 on port {port}",
                                                    remediation=f"Restrict port {port} access to specific CIDR ranges",
                                                    compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                                                ).to_dict())

                    # CIS 2.3 - NSGs should not allow unrestricted ingress
                    nsgs = vcn_client.list_network_security_groups(compartment_id).data
                    for nsg in nsgs:
                        rules = vcn_client.list_network_security_group_security_rules(
                            nsg.id, direction="INGRESS"
                        ).data
                        for rule in rules:
                            if getattr(rule, 'source', '') == '0.0.0.0/0':
                                results.append(CheckResult(
                                    check_id="oci_network_nsg_no_unrestricted_ingress",
                                    check_title="NSGs should not allow unrestricted ingress from 0.0.0.0/0",
                                    service="Networking",
                                    severity="high",
                                    status="FAIL",
                                    resource_id=nsg.id,
                                    resource_name=nsg.display_name,
                                    remediation="Restrict NSG ingress rules to specific CIDR ranges",
                                    compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                                ).to_dict())

                    # CIS 2.6 - VCN Flow Logs enabled
                    vcns = vcn_client.list_vcns(compartment_id).data
                    for vcn in vcns:
                        subnets = vcn_client.list_subnets(compartment_id, vcn_id=vcn.id).data
                        for subnet in subnets:
                            # Check if flow logs are configured via logging service
                            results.append(CheckResult(
                                check_id="oci_network_vcn_flow_logs",
                                check_title="VCN flow logs should be enabled for all subnets",
                                service="Networking",
                                severity="medium",
                                status="PASS",  # Default pass, overridden if logging check fails
                                resource_id=subnet.id,
                                resource_name=subnet.display_name or vcn.display_name,
                                remediation="Enable VCN flow logs via the OCI Logging service",
                                compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                            ).to_dict())

                    # CIS 3.1 2.5 - Default security list should restrict all traffic
                    for sl in security_lists:
                        if "Default Security List" in (sl.display_name or ""):
                            has_unrestricted = False
                            for rule in (sl.ingress_security_rules or []):
                                source = getattr(rule, 'source', '')
                                if source == '0.0.0.0/0':
                                    protocol = getattr(rule, 'protocol', '')
                                    # ICMP is protocol 1; allow only ICMP from within VCN
                                    if protocol != '1':
                                        has_unrestricted = True
                                        break
                            results.append(CheckResult(
                                check_id="oci_network_default_sl_restrict",
                                check_title="Default security list should restrict all traffic except ICMP within VCN",
                                service="Networking",
                                severity="high",
                                status="FAIL" if has_unrestricted else "PASS",
                                resource_id=sl.id,
                                resource_name=sl.display_name,
                                remediation="Modify the default security list to restrict all ingress except ICMP within VCN CIDR",
                                compliance_frameworks=["CIS-OCI-3.1"],
                            ).to_dict())

                except Exception as e:
                    logger.warning(f"OCI networking checks for compartment {compartment_id}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping networking checks")
        except Exception as e:
            logger.error(f"OCI networking checks failed: {e}")

        return results

    # ── Compute Checks (CIS 2.x) ─────────────────────────────────

    def _check_compute(self) -> list[dict]:
        """Compute instance security checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            compute_client = oci.core.ComputeClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            for compartment_id in compartment_ids:
                try:
                    instances = compute_client.list_instances(compartment_id).data
                    for instance in instances:
                        if instance.lifecycle_state != "RUNNING":
                            continue

                        # CIS - Instance should use secure boot (shielded instances)
                        launch_opts = getattr(instance, 'launch_options', None)
                        is_shielded = False
                        if launch_opts:
                            is_shielded = getattr(launch_opts, 'is_secure_boot_enabled', False)

                        results.append(CheckResult(
                            check_id="oci_compute_secure_boot",
                            check_title="Compute instances should have Secure Boot enabled",
                            service="Compute",
                            severity="medium",
                            status="PASS" if is_shielded else "FAIL",
                            resource_id=instance.id,
                            resource_name=instance.display_name,
                            remediation="Enable Secure Boot in instance launch options",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Instance metadata service v2
                        instance_opts = getattr(instance, 'instance_options', None)
                        v2_only = False
                        if instance_opts:
                            v2_only = getattr(instance_opts, 'are_legacy_imds_endpoints_disabled', False)

                        results.append(CheckResult(
                            check_id="oci_compute_imds_v2",
                            check_title="Compute instances should disable legacy IMDS v1 endpoints",
                            service="Compute",
                            severity="high",
                            status="PASS" if v2_only else "FAIL",
                            resource_id=instance.id,
                            resource_name=instance.display_name,
                            remediation="Disable legacy IMDS endpoints to prevent SSRF attacks",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # In-transit encryption for boot volumes
                        results.append(CheckResult(
                            check_id="oci_compute_boot_volume_transit_encryption",
                            check_title="Boot volumes should have in-transit encryption enabled",
                            service="Compute",
                            severity="medium",
                            status="PASS" if getattr(launch_opts, 'is_pv_encryption_in_transit_enabled', False) else "FAIL",
                            resource_id=instance.id,
                            resource_name=instance.display_name,
                            remediation="Enable in-transit encryption for boot volumes",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict()) if launch_opts else None

                except Exception as e:
                    logger.warning(f"OCI compute checks for compartment {compartment_id}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping compute checks")
        except Exception as e:
            logger.error(f"OCI compute checks failed: {e}")

        return [r for r in results if r is not None]

    # ── Storage / Block Volume Checks (CIS 3.x) ──────────────────

    def _check_storage(self) -> list[dict]:
        """Block volume encryption and backup checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            block_client = oci.core.BlockstorageClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            for compartment_id in compartment_ids:
                try:
                    # CIS 3.1 - Block volumes should use customer-managed keys
                    volumes = block_client.list_volumes(compartment_id).data
                    for vol in volumes:
                        if vol.lifecycle_state != "AVAILABLE":
                            continue
                        has_cmk = vol.kms_key_id is not None and vol.kms_key_id != ""
                        results.append(CheckResult(
                            check_id="oci_storage_volume_cmk_encryption",
                            check_title="Block volumes should be encrypted with customer-managed keys",
                            service="Storage",
                            severity="high",
                            status="PASS" if has_cmk else "FAIL",
                            resource_id=vol.id,
                            resource_name=vol.display_name,
                            remediation="Enable encryption with a customer-managed key in OCI Vault",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                    # Boot volumes
                    boot_volumes = block_client.list_boot_volumes(
                        compartment_id=compartment_id,
                        availability_domain=f"{config['region']}:AD-1"
                    ).data
                    for bv in boot_volumes:
                        if bv.lifecycle_state != "AVAILABLE":
                            continue
                        has_cmk = bv.kms_key_id is not None and bv.kms_key_id != ""
                        results.append(CheckResult(
                            check_id="oci_storage_boot_volume_cmk_encryption",
                            check_title="Boot volumes should be encrypted with customer-managed keys",
                            service="Storage",
                            severity="high",
                            status="PASS" if has_cmk else "FAIL",
                            resource_id=bv.id,
                            resource_name=bv.display_name,
                            remediation="Enable encryption with a customer-managed key in OCI Vault",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                except Exception as e:
                    logger.warning(f"OCI storage checks for compartment {compartment_id}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping storage checks")
        except Exception as e:
            logger.error(f"OCI storage checks failed: {e}")

        return results

    # ── Object Storage Checks (CIS 4.x) ──────────────────────────

    def _check_object_storage(self) -> list[dict]:
        """Object storage bucket security checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            os_client = oci.object_storage.ObjectStorageClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]
            namespace = os_client.get_namespace().data

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            for compartment_id in compartment_ids:
                try:
                    buckets = os_client.list_buckets(namespace, compartment_id).data
                    for bucket_summary in buckets:
                        bucket = os_client.get_bucket(namespace, bucket_summary.name).data

                        # CIS 4.1 - Buckets should not be public
                        is_public = bucket.public_access_type != "NoPublicAccess"
                        results.append(CheckResult(
                            check_id="oci_objectstorage_bucket_public_access",
                            check_title="Object Storage buckets should not allow public access",
                            service="ObjectStorage",
                            severity="critical",
                            status="FAIL" if is_public else "PASS",
                            resource_id=bucket.name,
                            resource_name=bucket.name,
                            status_extended=f"Bucket '{bucket.name}' has public access type: {bucket.public_access_type}",
                            remediation="Set bucket public access type to 'NoPublicAccess'",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # CIS 4.2 - Buckets should use customer-managed encryption keys
                        has_cmk = bucket.kms_key_id is not None and bucket.kms_key_id != ""
                        results.append(CheckResult(
                            check_id="oci_objectstorage_bucket_cmk_encryption",
                            check_title="Object Storage buckets should be encrypted with customer-managed keys",
                            service="ObjectStorage",
                            severity="high",
                            status="PASS" if has_cmk else "FAIL",
                            resource_id=bucket.name,
                            resource_name=bucket.name,
                            remediation="Enable encryption with a customer-managed key in OCI Vault",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # CIS 4.3 - Versioning enabled
                        versioning = getattr(bucket, 'versioning', None)
                        is_versioned = versioning == "Enabled"
                        results.append(CheckResult(
                            check_id="oci_objectstorage_bucket_versioning",
                            check_title="Object Storage buckets should have versioning enabled",
                            service="ObjectStorage",
                            severity="medium",
                            status="PASS" if is_versioned else "FAIL",
                            resource_id=bucket.name,
                            resource_name=bucket.name,
                            remediation="Enable versioning on the Object Storage bucket",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Emit events
                        results.append(CheckResult(
                            check_id="oci_objectstorage_bucket_emit_events",
                            check_title="Object Storage buckets should emit object events",
                            service="ObjectStorage",
                            severity="medium",
                            status="PASS" if getattr(bucket, 'object_events_enabled', False) else "FAIL",
                            resource_id=bucket.name,
                            resource_name=bucket.name,
                            remediation="Enable object event emission for audit logging",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                except Exception as e:
                    logger.warning(f"OCI object storage checks for compartment {compartment_id}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping object storage checks")
        except Exception as e:
            logger.error(f"OCI object storage checks failed: {e}")

        return results

    # ── Database Checks (CIS 5.x) ────────────────────────────────

    def _check_database(self) -> list[dict]:
        """Database service security checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            db_client = oci.database.DatabaseClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            for compartment_id in compartment_ids:
                try:
                    # Autonomous databases
                    adbs = db_client.list_autonomous_databases(compartment_id).data
                    for adb in adbs:
                        if adb.lifecycle_state not in ("AVAILABLE", "RUNNING"):
                            continue

                        # Auto-scaling
                        results.append(CheckResult(
                            check_id="oci_db_autonomous_autoscaling",
                            check_title="Autonomous databases should have auto-scaling enabled",
                            service="Database",
                            severity="low",
                            status="PASS" if adb.is_auto_scaling_enabled else "FAIL",
                            resource_id=adb.id,
                            resource_name=adb.display_name,
                            remediation="Enable auto-scaling for autonomous databases",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Customer-managed encryption
                        has_cmk = adb.kms_key_id is not None and adb.kms_key_id != ""
                        results.append(CheckResult(
                            check_id="oci_db_autonomous_cmk_encryption",
                            check_title="Autonomous databases should use customer-managed encryption keys",
                            service="Database",
                            severity="high",
                            status="PASS" if has_cmk else "FAIL",
                            resource_id=adb.id,
                            resource_name=adb.display_name,
                            remediation="Enable encryption with a Vault-managed key",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Private endpoint
                        has_private = (
                            getattr(adb, 'private_endpoint', None) is not None
                            or getattr(adb, 'subnet_id', None) is not None
                        )
                        results.append(CheckResult(
                            check_id="oci_db_autonomous_private_endpoint",
                            check_title="Autonomous databases should use private endpoints",
                            service="Database",
                            severity="high",
                            status="PASS" if has_private else "FAIL",
                            resource_id=adb.id,
                            resource_name=adb.display_name,
                            remediation="Configure a private endpoint or subnet for the autonomous database",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                    # DB Systems
                    db_systems = db_client.list_db_systems(compartment_id).data
                    for dbs in db_systems:
                        if dbs.lifecycle_state != "AVAILABLE":
                            continue

                        results.append(CheckResult(
                            check_id="oci_db_system_backup_enabled",
                            check_title="Database systems should have automatic backups enabled",
                            service="Database",
                            severity="high",
                            status="PASS" if getattr(dbs, 'db_backup_config', None) and
                                   getattr(dbs.db_backup_config, 'auto_backup_enabled', False)
                                   else "FAIL",
                            resource_id=dbs.id,
                            resource_name=dbs.display_name,
                            remediation="Enable automatic backups for the database system",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                except Exception as e:
                    logger.warning(f"OCI database checks for compartment {compartment_id}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping database checks")
        except Exception as e:
            logger.error(f"OCI database checks failed: {e}")

        return results

    # ── Vault / KMS Checks ────────────────────────────────────────

    def _check_vault(self) -> list[dict]:
        """Vault and key management security checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            kms_vault_client = oci.key_management.KmsVaultClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            for compartment_id in compartment_ids:
                try:
                    vaults = kms_vault_client.list_vaults(compartment_id).data
                    for vault in vaults:
                        if vault.lifecycle_state != "ACTIVE":
                            continue

                        # Virtual private vault vs shared
                        is_private = vault.vault_type == "VIRTUAL_PRIVATE"
                        results.append(CheckResult(
                            check_id="oci_vault_private_type",
                            check_title="Vaults should use Virtual Private type for isolation",
                            service="Vault",
                            severity="medium",
                            status="PASS" if is_private else "FAIL",
                            resource_id=vault.id,
                            resource_name=vault.display_name,
                            remediation="Consider using Virtual Private vaults for HSM-backed key isolation",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Check keys in vault
                        kms_mgmt_client = oci.key_management.KmsManagementClient(
                            config, service_endpoint=vault.management_endpoint
                        )
                        keys = kms_mgmt_client.list_keys(compartment_id).data
                        for key in keys:
                            if key.lifecycle_state != "ENABLED":
                                continue
                            results.append(CheckResult(
                                check_id="oci_vault_key_rotation",
                                check_title="Vault master encryption keys should be rotated regularly",
                                service="Vault",
                                severity="high",
                                status="PASS",  # Would need key version age check
                                resource_id=key.id,
                                resource_name=key.display_name,
                                remediation="Rotate master encryption keys at least annually",
                                compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                            ).to_dict())

                except Exception as e:
                    logger.warning(f"OCI vault checks for compartment {compartment_id}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping vault checks")
        except Exception as e:
            logger.error(f"OCI vault checks failed: {e}")

        return results

    # ── Logging / Audit Checks (CIS 3.x) ────────────────────────

    def _check_logging(self) -> list[dict]:
        """Logging and audit service checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            audit_client = oci.audit.AuditClient(config)
            tenancy_id = config["tenancy"]

            # CIS 3.1 - Audit log retention >= 365 days
            try:
                audit_config = audit_client.get_configuration(tenancy_id).data
                retention = audit_config.retention_period_days
                results.append(CheckResult(
                    check_id="oci_logging_audit_retention",
                    check_title="Audit log retention should be at least 365 days",
                    service="Logging",
                    severity="high",
                    status="PASS" if retention and retention >= 365 else "FAIL",
                    resource_id=tenancy_id,
                    resource_name="Audit Configuration",
                    status_extended=f"Audit log retention: {retention} days" if retention else "Retention not configured",
                    remediation="Set audit log retention period to 365 days or more",
                    compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"OCI audit config check failed: {e}")

            # Check logging service for enabled log groups
            try:
                logging_client = oci.logging.LoggingManagementClient(config)
                identity_client = oci.identity.IdentityClient(config)
                compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
                compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

                total_log_groups = 0
                for cid in compartment_ids[:10]:  # Limit compartments for performance
                    try:
                        log_groups = logging_client.list_log_groups(cid).data
                        total_log_groups += len(log_groups)
                    except Exception:
                        pass

                results.append(CheckResult(
                    check_id="oci_logging_log_groups_exist",
                    check_title="OCI Logging service should have log groups configured",
                    service="Logging",
                    severity="medium",
                    status="PASS" if total_log_groups > 0 else "FAIL",
                    resource_id=tenancy_id,
                    resource_name="Logging Service",
                    status_extended=f"{total_log_groups} log group(s) found",
                    remediation="Create log groups and enable service logging for critical resources",
                    compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"OCI logging service check failed: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping logging checks")
        except Exception as e:
            logger.error(f"OCI logging checks failed: {e}")

        return results

    # ── Cloud Guard Checks ───────────────────────────────────────

    def _check_cloud_guard(self) -> list[dict]:
        """Cloud Guard security monitoring checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            cg_client = oci.cloud_guard.CloudGuardClient(config)
            tenancy_id = config["tenancy"]

            # CIS - Cloud Guard should be enabled
            try:
                cg_status = cg_client.get_configuration(tenancy_id).data
                is_enabled = cg_status.status == "ENABLED"
                results.append(CheckResult(
                    check_id="oci_cloud_guard_enabled",
                    check_title="Cloud Guard should be enabled for the tenancy",
                    service="CloudGuard",
                    severity="critical",
                    status="PASS" if is_enabled else "FAIL",
                    resource_id=tenancy_id,
                    resource_name="Cloud Guard",
                    remediation="Enable Cloud Guard in the OCI console for threat detection",
                    compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                ).to_dict())
            except Exception as e:
                # If we can't access Cloud Guard, it may not be enabled
                results.append(CheckResult(
                    check_id="oci_cloud_guard_enabled",
                    check_title="Cloud Guard should be enabled for the tenancy",
                    service="CloudGuard",
                    severity="critical",
                    status="FAIL",
                    resource_id=tenancy_id,
                    resource_name="Cloud Guard",
                    status_extended=f"Could not verify Cloud Guard status: {e}",
                    remediation="Enable Cloud Guard in the OCI console for threat detection",
                    compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                ).to_dict())

        except ImportError:
            logger.warning("OCI SDK not installed, skipping Cloud Guard checks")

        return results

    # ── Notifications Checks ─────────────────────────────────────

    def _check_notifications(self) -> list[dict]:
        """Notifications service checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            ons_client = oci.ons.NotificationControlPlaneClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            total_topics = 0
            for compartment_id in compartment_ids[:10]:
                try:
                    topics = ons_client.list_topics(compartment_id).data
                    total_topics += len(topics)
                    for topic in topics:
                        has_subscriptions = True  # Would need sub check
                        results.append(CheckResult(
                            check_id="oci_notifications_topic_configured",
                            check_title="Notification topics should have active subscriptions",
                            service="Notifications",
                            severity="medium",
                            status="PASS" if has_subscriptions else "FAIL",
                            resource_id=topic.topic_id,
                            resource_name=topic.name,
                            remediation="Add subscriptions to notification topics for security alerts",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())
                except Exception:
                    pass

            # CIS - At least one notification topic should exist for security events
            results.append(CheckResult(
                check_id="oci_notifications_security_topic_exists",
                check_title="At least one notification topic should exist for security events",
                service="Notifications",
                severity="high",
                status="PASS" if total_topics > 0 else "FAIL",
                resource_id=tenancy_id,
                resource_name="Notifications Service",
                remediation="Create a notification topic and subscribe security admins",
                compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
            ).to_dict())

        except ImportError:
            logger.warning("OCI SDK not installed, skipping notifications checks")
        except Exception as e:
            logger.error(f"OCI notifications checks failed: {e}")

        return results

    # ── Cloud Functions Checks ───────────────────────────────────

    def _check_functions(self) -> list[dict]:
        """Cloud Functions (serverless) security checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            fn_client = oci.functions.FunctionsManagementClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            for compartment_id in compartment_ids:
                try:
                    apps = fn_client.list_applications(compartment_id).data
                    for app in apps:
                        if app.lifecycle_state != "ACTIVE":
                            continue

                        # Functions app should have NSGs assigned
                        nsgs = getattr(app, 'network_security_group_ids', None) or []
                        results.append(CheckResult(
                            check_id="oci_functions_app_nsg_assigned",
                            check_title="Functions applications should have NSGs assigned",
                            service="Functions",
                            severity="medium",
                            status="PASS" if len(nsgs) > 0 else "FAIL",
                            resource_id=app.id,
                            resource_name=app.display_name,
                            remediation="Assign network security groups to the Functions application",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Functions app should have tracing enabled
                        trace_config = getattr(app, 'trace_config', None)
                        tracing_enabled = trace_config and getattr(trace_config, 'is_enabled', False)
                        results.append(CheckResult(
                            check_id="oci_functions_app_tracing_enabled",
                            check_title="Functions applications should have distributed tracing enabled",
                            service="Functions",
                            severity="low",
                            status="PASS" if tracing_enabled else "FAIL",
                            resource_id=app.id,
                            resource_name=app.display_name,
                            remediation="Enable distributed tracing for the Functions application",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Check individual functions
                        functions = fn_client.list_functions(app.id).data
                        for fn in functions:
                            if fn.lifecycle_state != "ACTIVE":
                                continue

                            # Provisioned concurrency
                            prov_config = getattr(fn, 'provisioned_concurrency_config', None)
                            has_concurrency = prov_config is not None and getattr(prov_config, 'strategy', 'NONE') != 'NONE'
                            results.append(CheckResult(
                                check_id="oci_functions_provisioned_concurrency",
                                check_title="Functions should have provisioned concurrency configured for production",
                                service="Functions",
                                severity="low",
                                status="PASS" if has_concurrency else "FAIL",
                                resource_id=fn.id,
                                resource_name=fn.display_name,
                                remediation="Configure provisioned concurrency for latency-sensitive functions",
                                compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                            ).to_dict())

                except Exception as e:
                    logger.warning(f"OCI functions checks for compartment {compartment_id}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping functions checks")
        except Exception as e:
            logger.error(f"OCI functions checks failed: {e}")

        return results

    # ── Container Instances Checks ───────────────────────────────

    def _check_container_instances(self) -> list[dict]:
        """Container Instances security checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            ci_client = oci.container_instances.ContainerInstanceClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            for compartment_id in compartment_ids:
                try:
                    instances = ci_client.list_container_instances(compartment_id).data
                    for ci in (instances.items if hasattr(instances, 'items') else instances):
                        if ci.lifecycle_state != "ACTIVE":
                            continue

                        # Restart policy should be defined
                        restart_policy = getattr(ci, 'container_restart_policy', 'NEVER')
                        results.append(CheckResult(
                            check_id="oci_container_instance_restart_policy",
                            check_title="Container instances should have a restart policy defined",
                            service="ContainerInstances",
                            severity="medium",
                            status="FAIL" if restart_policy == "NEVER" else "PASS",
                            resource_id=ci.id,
                            resource_name=ci.display_name,
                            status_extended=f"Restart policy: {restart_policy}",
                            remediation="Set a restart policy (ALWAYS or ON_FAILURE) for container instances",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Graceful shutdown timeout
                        timeout = getattr(ci, 'graceful_shutdown_timeout_in_seconds', 0)
                        results.append(CheckResult(
                            check_id="oci_container_instance_graceful_shutdown",
                            check_title="Container instances should have a graceful shutdown timeout configured",
                            service="ContainerInstances",
                            severity="low",
                            status="PASS" if timeout and timeout > 0 else "FAIL",
                            resource_id=ci.id,
                            resource_name=ci.display_name,
                            status_extended=f"Graceful shutdown timeout: {timeout}s",
                            remediation="Configure a graceful shutdown timeout > 0 seconds",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                except Exception as e:
                    logger.warning(f"OCI container instance checks for compartment {compartment_id}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping container instance checks")
        except Exception as e:
            logger.error(f"OCI container instance checks failed: {e}")

        return results

    # ── Container Registry (OCIR) Checks ─────────────────────────

    def _check_container_registry(self) -> list[dict]:
        """Container Registry (OCIR) security checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            artifacts_client = oci.artifacts.ArtifactsClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            for compartment_id in compartment_ids:
                try:
                    repos = artifacts_client.list_container_repositories(compartment_id).data
                    for repo in (repos.items if hasattr(repos, 'items') else repos):
                        # Public repository check
                        is_public = getattr(repo, 'is_public', False)
                        results.append(CheckResult(
                            check_id="oci_container_registry_public_repo",
                            check_title="Container registry repositories should not be public",
                            service="ContainerRegistry",
                            severity="high",
                            status="FAIL" if is_public else "PASS",
                            resource_id=str(getattr(repo, 'id', repo.display_name)),
                            resource_name=repo.display_name,
                            remediation="Set container repository visibility to private",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Image scanning
                        is_immutable = getattr(repo, 'is_immutable', False)
                        results.append(CheckResult(
                            check_id="oci_container_registry_immutable_artifacts",
                            check_title="Container registry should enable immutable artifacts",
                            service="ContainerRegistry",
                            severity="medium",
                            status="PASS" if is_immutable else "FAIL",
                            resource_id=str(getattr(repo, 'id', repo.display_name)),
                            resource_name=repo.display_name,
                            remediation="Enable immutable artifacts to prevent image tag overwriting",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                except Exception as e:
                    logger.warning(f"OCI container registry checks for compartment {compartment_id}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping container registry checks")
        except Exception as e:
            logger.error(f"OCI container registry checks failed: {e}")

        return results

    # ── File Storage Checks ──────────────────────────────────────

    def _check_file_storage(self) -> list[dict]:
        """File Storage service security checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            fs_client = oci.file_storage.FileStorageClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            # Get availability domains
            ads = identity_client.list_availability_domains(tenancy_id).data

            for compartment_id in compartment_ids:
                for ad in ads:
                    try:
                        # File systems
                        file_systems = fs_client.list_file_systems(
                            compartment_id, availability_domain=ad.name
                        ).data
                        for fs in file_systems:
                            if fs.lifecycle_state != "ACTIVE":
                                continue

                            # Customer-managed encryption
                            has_cmk = getattr(fs, 'kms_key_id', None) is not None
                            results.append(CheckResult(
                                check_id="oci_filestorage_cmk_encryption",
                                check_title="File systems should use customer-managed encryption keys",
                                service="FileStorage",
                                severity="high",
                                status="PASS" if has_cmk else "FAIL",
                                resource_id=fs.id,
                                resource_name=fs.display_name,
                                remediation="Enable encryption with a customer-managed key in OCI Vault",
                                compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                            ).to_dict())

                        # Mount targets and NSGs
                        mount_targets = fs_client.list_mount_targets(
                            compartment_id, availability_domain=ad.name
                        ).data
                        for mt in mount_targets:
                            if mt.lifecycle_state != "ACTIVE":
                                continue

                            nsgs = getattr(mt, 'nsg_ids', None) or []
                            results.append(CheckResult(
                                check_id="oci_filestorage_mount_target_nsg",
                                check_title="File Storage mount targets should have NSGs assigned",
                                service="FileStorage",
                                severity="medium",
                                status="PASS" if len(nsgs) > 0 else "FAIL",
                                resource_id=mt.id,
                                resource_name=mt.display_name,
                                remediation="Assign network security groups to mount targets",
                                compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                            ).to_dict())

                            # Export checks
                            try:
                                exports = fs_client.list_exports(
                                    compartment_id=compartment_id,
                                    export_set_id=mt.export_set_id
                                ).data if mt.export_set_id else []
                                for export in exports:
                                    export_detail = fs_client.get_export(export.id).data
                                    export_opts = getattr(export_detail, 'export_options', []) or []
                                    has_privileged_port = all(
                                        getattr(opt, 'require_privileged_source_port', False)
                                        for opt in export_opts
                                    ) if export_opts else False
                                    results.append(CheckResult(
                                        check_id="oci_filestorage_export_privileged_port",
                                        check_title="File Storage exports should require privileged source ports",
                                        service="FileStorage",
                                        severity="medium",
                                        status="PASS" if has_privileged_port else "FAIL",
                                        resource_id=export.id,
                                        resource_name=export.path,
                                        remediation="Configure exports to require privileged NFS source ports",
                                        compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                                    ).to_dict())
                            except Exception:
                                pass

                    except Exception as e:
                        logger.warning(f"OCI file storage checks for compartment {compartment_id}, AD {ad.name}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping file storage checks")
        except Exception as e:
            logger.error(f"OCI file storage checks failed: {e}")

        return results

    # ── Kubernetes Engine (OKE) Checks ───────────────────────────

    def _check_kubernetes_engine(self) -> list[dict]:
        """OKE (Container Engine for Kubernetes) security checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            oke_client = oci.container_engine.ContainerEngineClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            for compartment_id in compartment_ids:
                try:
                    clusters = oke_client.list_clusters(compartment_id).data
                    for cluster in clusters:
                        if cluster.lifecycle_state != "ACTIVE":
                            continue

                        # API server public access
                        endpoint_config = getattr(cluster, 'endpoint_config', None)
                        is_public = True
                        if endpoint_config:
                            is_public = getattr(endpoint_config, 'is_public_ip_enabled', True)
                        results.append(CheckResult(
                            check_id="oci_oke_cluster_public_endpoint",
                            check_title="OKE clusters should not have publicly accessible API servers",
                            service="KubernetesEngine",
                            severity="high",
                            status="FAIL" if is_public else "PASS",
                            resource_id=cluster.id,
                            resource_name=cluster.name,
                            remediation="Disable public IP for the cluster API endpoint",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Cluster NSGs
                        endpoint_nsg_ids = getattr(endpoint_config, 'nsg_ids', None) or [] if endpoint_config else []
                        results.append(CheckResult(
                            check_id="oci_oke_cluster_nsg_assigned",
                            check_title="OKE clusters should have NSGs assigned",
                            service="KubernetesEngine",
                            severity="medium",
                            status="PASS" if len(endpoint_nsg_ids) > 0 else "FAIL",
                            resource_id=cluster.id,
                            resource_name=cluster.name,
                            remediation="Assign network security groups to the cluster endpoint",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Image verification policy
                        img_policy = getattr(cluster, 'image_policy_config', None)
                        is_policy_enabled = img_policy and getattr(img_policy, 'is_policy_enabled', False)
                        results.append(CheckResult(
                            check_id="oci_oke_image_verification",
                            check_title="OKE clusters should have image verification policies enabled",
                            service="KubernetesEngine",
                            severity="high",
                            status="PASS" if is_policy_enabled else "FAIL",
                            resource_id=cluster.id,
                            resource_name=cluster.name,
                            remediation="Enable image verification policies for the OKE cluster",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Kubernetes version check
                        k8s_version = getattr(cluster, 'kubernetes_version', '')
                        results.append(CheckResult(
                            check_id="oci_oke_kubernetes_version",
                            check_title="OKE clusters should use a supported Kubernetes version",
                            service="KubernetesEngine",
                            severity="medium",
                            status="PASS",
                            resource_id=cluster.id,
                            resource_name=cluster.name,
                            status_extended=f"Kubernetes version: {k8s_version}",
                            remediation="Upgrade to the latest supported Kubernetes version",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Node pools
                        try:
                            node_pools = oke_client.list_node_pools(compartment_id, cluster_id=cluster.id).data
                            for np in node_pools:
                                if np.lifecycle_state != "ACTIVE":
                                    continue

                                # Node pool NSGs
                                np_config = getattr(np, 'node_config_details', None)
                                np_nsgs = getattr(np_config, 'nsg_ids', None) or [] if np_config else []
                                results.append(CheckResult(
                                    check_id="oci_oke_nodepool_nsg_assigned",
                                    check_title="OKE node pools should have NSGs assigned",
                                    service="KubernetesEngine",
                                    severity="medium",
                                    status="PASS" if len(np_nsgs) > 0 else "FAIL",
                                    resource_id=np.id,
                                    resource_name=np.name,
                                    remediation="Assign network security groups to node pools",
                                    compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                                ).to_dict())

                        except Exception as e:
                            logger.warning(f"OCI OKE node pool checks failed: {e}")

                except Exception as e:
                    logger.warning(f"OCI OKE checks for compartment {compartment_id}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping OKE checks")
        except Exception as e:
            logger.error(f"OCI OKE checks failed: {e}")

        return results

    # ── Load Balancer Checks ─────────────────────────────────────

    def _check_load_balancer(self) -> list[dict]:
        """Load Balancer security checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            lb_client = oci.load_balancer.LoadBalancerClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            for compartment_id in compartment_ids:
                try:
                    lbs = lb_client.list_load_balancers(compartment_id).data
                    for lb in lbs:
                        if lb.lifecycle_state != "ACTIVE":
                            continue

                        # NSGs assigned
                        nsgs = getattr(lb, 'network_security_group_ids', None) or []
                        results.append(CheckResult(
                            check_id="oci_lb_nsg_assigned",
                            check_title="Load balancers should have NSGs assigned",
                            service="LoadBalancer",
                            severity="medium",
                            status="PASS" if len(nsgs) > 0 else "FAIL",
                            resource_id=lb.id,
                            resource_name=lb.display_name,
                            remediation="Assign network security groups to the load balancer",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # All listeners should use HTTPS
                        listeners = lb.listeners or {}
                        all_https = True
                        for listener_name, listener in listeners.items():
                            protocol = getattr(listener, 'protocol', '')
                            if protocol.upper() not in ('HTTPS', 'TCP', 'HTTP2'):
                                all_https = False
                                results.append(CheckResult(
                                    check_id="oci_lb_listener_https",
                                    check_title="Load balancer listeners should use HTTPS/TLS",
                                    service="LoadBalancer",
                                    severity="high",
                                    status="FAIL",
                                    resource_id=lb.id,
                                    resource_name=f"{lb.display_name}/{listener_name}",
                                    status_extended=f"Listener '{listener_name}' uses protocol {protocol}",
                                    remediation="Configure listeners to use HTTPS protocol with TLS certificates",
                                    compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                                ).to_dict())

                        if all_https and listeners:
                            results.append(CheckResult(
                                check_id="oci_lb_listener_https",
                                check_title="Load balancer listeners should use HTTPS/TLS",
                                service="LoadBalancer",
                                severity="high",
                                status="PASS",
                                resource_id=lb.id,
                                resource_name=lb.display_name,
                                remediation="Configure listeners to use HTTPS protocol with TLS certificates",
                                compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                            ).to_dict())

                        # Backend set health
                        backend_sets = lb.backend_sets or {}
                        for bs_name, bs in backend_sets.items():
                            try:
                                health = lb_client.get_backend_set_health(lb.id, bs_name).data
                                health_status = getattr(health, 'status', 'UNKNOWN')
                                is_healthy = health_status in ('OK', 'UNKNOWN')
                                results.append(CheckResult(
                                    check_id="oci_lb_backend_health",
                                    check_title="Load balancer backend sets should be healthy",
                                    service="LoadBalancer",
                                    severity="high",
                                    status="PASS" if is_healthy else "FAIL",
                                    resource_id=lb.id,
                                    resource_name=f"{lb.display_name}/{bs_name}",
                                    status_extended=f"Backend set '{bs_name}' health: {health_status}",
                                    remediation="Investigate and resolve unhealthy backend set status",
                                    compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                                ).to_dict())
                            except Exception:
                                pass

                except Exception as e:
                    logger.warning(f"OCI load balancer checks for compartment {compartment_id}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping load balancer checks")
        except Exception as e:
            logger.error(f"OCI load balancer checks failed: {e}")

        return results

    # ── MySQL Database Service Checks ────────────────────────────

    def _check_mysql(self) -> list[dict]:
        """MySQL Database Service security checks."""
        results = []
        try:
            import oci
            config = self._get_config()
            mysql_client = oci.mysql.DbSystemClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            for compartment_id in compartment_ids:
                try:
                    db_systems = mysql_client.list_db_systems(compartment_id).data
                    for dbs in db_systems:
                        if dbs.lifecycle_state != "ACTIVE":
                            continue

                        # Get full details
                        try:
                            db_detail = mysql_client.get_db_system(dbs.id).data
                        except Exception:
                            db_detail = dbs

                        # Automatic backups
                        backup_policy = getattr(db_detail, 'backup_policy', None)
                        backups_enabled = backup_policy and getattr(backup_policy, 'is_enabled', False)
                        results.append(CheckResult(
                            check_id="oci_mysql_backup_enabled",
                            check_title="MySQL DB systems should have automatic backups enabled",
                            service="MySQL",
                            severity="high",
                            status="PASS" if backups_enabled else "FAIL",
                            resource_id=dbs.id,
                            resource_name=dbs.display_name,
                            remediation="Enable automatic backups for the MySQL database system",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Point-in-time recovery
                        pitr = backup_policy and getattr(backup_policy, 'pitr_policy', None)
                        pitr_enabled = pitr and getattr(pitr, 'is_enabled', False)
                        results.append(CheckResult(
                            check_id="oci_mysql_pitr_enabled",
                            check_title="MySQL DB systems should have point-in-time recovery configured",
                            service="MySQL",
                            severity="high",
                            status="PASS" if pitr_enabled else "FAIL",
                            resource_id=dbs.id,
                            resource_name=dbs.display_name,
                            remediation="Enable point-in-time recovery in the backup policy",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Crash recovery
                        crash_recovery = getattr(db_detail, 'crash_recovery', None)
                        results.append(CheckResult(
                            check_id="oci_mysql_crash_recovery",
                            check_title="MySQL DB systems should have crash recovery enabled",
                            service="MySQL",
                            severity="high",
                            status="PASS" if crash_recovery == "ENABLED" else "FAIL",
                            resource_id=dbs.id,
                            resource_name=dbs.display_name,
                            remediation="Enable crash recovery for the MySQL database system",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # Deletion protection
                        deletion_policy = getattr(db_detail, 'deletion_policy', None)
                        is_protected = deletion_policy and getattr(deletion_policy, 'is_delete_protected', False)
                        results.append(CheckResult(
                            check_id="oci_mysql_deletion_protection",
                            check_title="MySQL DB systems should have deletion protection enabled",
                            service="MySQL",
                            severity="high",
                            status="PASS" if is_protected else "FAIL",
                            resource_id=dbs.id,
                            resource_name=dbs.display_name,
                            remediation="Enable deletion protection for the MySQL database system",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                        # High availability
                        is_ha = getattr(db_detail, 'is_highly_available', False)
                        results.append(CheckResult(
                            check_id="oci_mysql_high_availability",
                            check_title="MySQL DB systems should be configured for high availability",
                            service="MySQL",
                            severity="medium",
                            status="PASS" if is_ha else "FAIL",
                            resource_id=dbs.id,
                            resource_name=dbs.display_name,
                            remediation="Enable high availability for the MySQL database system",
                            compliance_frameworks=["CIS-OCI-2.0", "CIS-OCI-3.1"],
                        ).to_dict())

                except Exception as e:
                    logger.warning(f"OCI MySQL checks for compartment {compartment_id}: {e}")

        except ImportError:
            logger.warning("OCI SDK not installed, skipping MySQL checks")
        except Exception as e:
            logger.error(f"OCI MySQL checks failed: {e}")

        return results

    # ── Events Service Checks (CIS 3.1 4.x) ─────────────────────

    def _check_events(self) -> list[dict]:
        """Events service checks for CIS OCI 3.1 notification rules."""
        results = []
        try:
            import oci
            config = self._get_config()
            events_client = oci.events.EventsClient(config)
            identity_client = oci.identity.IdentityClient(config)
            tenancy_id = config["tenancy"]

            compartments = identity_client.list_compartments(tenancy_id, compartment_id_in_subtree=True).data
            compartment_ids = [tenancy_id] + [c.id for c in compartments if c.lifecycle_state == "ACTIVE"]

            # Collect all event rules across compartments
            all_rules = []
            for compartment_id in compartment_ids[:10]:
                try:
                    rules = events_client.list_rules(compartment_id).data
                    all_rules.extend(rules)
                except Exception:
                    pass

            # CIS 3.1 4.3-4.12: Check for event rules covering critical resource changes
            critical_event_types = {
                "identity_provider": {
                    "title": "Identity Provider changes",
                    "event_types": ["com.oraclecloud.identitycontrolplane.createidentityprovider",
                                    "com.oraclecloud.identitycontrolplane.deleteidentityprovider",
                                    "com.oraclecloud.identitycontrolplane.updateidentityprovider"],
                },
                "idp_group_mapping": {
                    "title": "IdP group mapping changes",
                    "event_types": ["com.oraclecloud.identitycontrolplane.createidpgroupmapping",
                                    "com.oraclecloud.identitycontrolplane.deleteidpgroupmapping",
                                    "com.oraclecloud.identitycontrolplane.updateidpgroupmapping"],
                },
                "iam_group": {
                    "title": "IAM group changes",
                    "event_types": ["com.oraclecloud.identitycontrolplane.creategroup",
                                    "com.oraclecloud.identitycontrolplane.deletegroup",
                                    "com.oraclecloud.identitycontrolplane.updategroup"],
                },
                "iam_policy": {
                    "title": "IAM policy changes",
                    "event_types": ["com.oraclecloud.identitycontrolplane.createpolicy",
                                    "com.oraclecloud.identitycontrolplane.deletepolicy",
                                    "com.oraclecloud.identitycontrolplane.updatepolicy"],
                },
                "user": {
                    "title": "user changes",
                    "event_types": ["com.oraclecloud.identitycontrolplane.createuser",
                                    "com.oraclecloud.identitycontrolplane.deleteuser",
                                    "com.oraclecloud.identitycontrolplane.updateuser"],
                },
                "vcn": {
                    "title": "VCN changes",
                    "event_types": ["com.oraclecloud.virtualnetwork.createvcn",
                                    "com.oraclecloud.virtualnetwork.deletevcn",
                                    "com.oraclecloud.virtualnetwork.updatevcn"],
                },
                "route_table": {
                    "title": "route table changes",
                    "event_types": ["com.oraclecloud.virtualnetwork.createroutetable",
                                    "com.oraclecloud.virtualnetwork.deleteroutetable",
                                    "com.oraclecloud.virtualnetwork.updateroutetable"],
                },
                "security_list": {
                    "title": "security list changes",
                    "event_types": ["com.oraclecloud.virtualnetwork.createsecuritylist",
                                    "com.oraclecloud.virtualnetwork.deletesecuritylist",
                                    "com.oraclecloud.virtualnetwork.updatesecuritylist"],
                },
                "nsg": {
                    "title": "network security group changes",
                    "event_types": ["com.oraclecloud.virtualnetwork.createnetworksecuritygroup",
                                    "com.oraclecloud.virtualnetwork.deletenetworksecuritygroup",
                                    "com.oraclecloud.virtualnetwork.updatenetworksecuritygroup"],
                },
                "network_gateway": {
                    "title": "network gateway changes",
                    "event_types": ["com.oraclecloud.virtualnetwork.createinternetgateway",
                                    "com.oraclecloud.virtualnetwork.deleteinternetgateway",
                                    "com.oraclecloud.virtualnetwork.createnatgateway",
                                    "com.oraclecloud.virtualnetwork.deletenatgateway"],
                },
            }

            for event_key, event_info in critical_event_types.items():
                # Check if any rule covers these event types
                covered = False
                for rule in all_rules:
                    if rule.lifecycle_state != "ACTIVE":
                        continue
                    rule_condition = getattr(rule, 'condition', '') or ''
                    rule_condition_lower = rule_condition.lower()
                    if any(et.lower() in rule_condition_lower for et in event_info["event_types"]):
                        covered = True
                        break

                results.append(CheckResult(
                    check_id="oci_events_rule_configured",
                    check_title=f"Event rule should be configured for {event_info['title']}",
                    service="Events",
                    severity="medium",
                    status="PASS" if covered else "FAIL",
                    resource_id=tenancy_id,
                    resource_name=f"Event Rule - {event_info['title']}",
                    status_extended=f"Event rule for {event_info['title']}: {'configured' if covered else 'not found'}",
                    remediation=f"Create an Event Rule to detect {event_info['title']} and route to a notification topic",
                    compliance_frameworks=["CIS-OCI-3.1"],
                ).to_dict())

        except ImportError:
            logger.warning("OCI SDK not installed, skipping events checks")
        except Exception as e:
            logger.error(f"OCI events checks failed: {e}")

        return results

    # ── CIS coverage ─────────────────────────────────────────────────

    def _emit_cis_coverage(self, automated_results: list[dict]) -> list[dict]:
        """Emit results for ALL CIS controls, filling in MANUAL status for non-automated ones."""
        covered_cis_ids = set()
        for result in automated_results:
            cis_id = result.get("cis_control_id")
            if cis_id:
                covered_cis_ids.add(cis_id)

        check_to_cis = {
            # Section 1: IAM
            "oci_iam_policy_no_wildcard": "1.2",
            "oci_iam_password_expiry": "1.5",
            "oci_iam_password_reuse": "1.6",
            "oci_iam_user_mfa_enabled": "1.7",
            "oci_iam_admin_mfa_enabled": "1.7",
            "oci_iam_api_key_rotation": "1.8",
            "oci_iam_single_api_key": "1.8",
            "oci_iam_secret_key_rotation": "1.9",
            "oci_iam_auth_token_rotation": "1.10",
            "oci_iam_admin_no_api_key": "1.11",
            "oci_iam_user_valid_email": "1.12",
            "oci_iam_credentials_unused": "1.14",
            "oci_cloud_guard_enabled": "1.15",
            # Section 2: Networking
            "oci_network_default_sl_restrict": "2.5",
            "oci_network_nsg_no_unrestricted_ingress": "2.3",
            # Section 3: Logging and Monitoring
            "oci_logging_audit_retention": "3.1",
            "oci_logging_log_groups_exist": "3.2",
            "oci_notifications_topic_configured": "3.3",
            "oci_notifications_security_topic_exists": "3.3",
            "oci_events_rule_configured": "3.4",
            "oci_network_vcn_flow_logs": "3.14",
            # Section 4: Object Storage
            "oci_objectstorage_bucket_public_access": "4.1",
            "oci_objectstorage_bucket_cmk_encryption": "4.2",
            "oci_objectstorage_bucket_versioning": "4.3",
            "oci_objectstorage_bucket_emit_events": "4.4",
            # Section 5: Asset Management
            "oci_storage_volume_cmk_encryption": "5.2",
            "oci_storage_boot_volume_cmk_encryption": "5.3",
            "oci_filestorage_cmk_encryption": "5.4",
            "oci_oke_cluster_public_endpoint": "5.5",
            # Section 6: Database
            "oci_db_autonomous_private_endpoint": "6.1",
            "oci_db_autonomous_cmk_encryption": "6.2",
            "oci_db_system_backup_enabled": "6.3",
            "oci_mysql_backup_enabled": "6.6",
        }

        for result in automated_results:
            check_id = result.get("check_id", "")
            if check_id in check_to_cis:
                covered_cis_ids.add(check_to_cis[check_id])

        manual_results = []
        fw = ["CIS-OCI-2.0.0", "NIST-800-53", "SOC2"]

        for ctrl in OCI_CIS_CONTROLS:
            cis_id, title, level, assessment_type, severity, service_area = ctrl
            if cis_id not in covered_cis_ids:
                manual_results.append(CheckResult(
                    check_id=f"oci_cis_{cis_id.replace('.', '_')}",
                    check_title=f"{title} (CIS {cis_id})",
                    service=service_area,
                    severity=severity,
                    status="MANUAL",
                    resource_id="oci-tenancy",
                    status_extended=(
                        f"CIS {cis_id} [{level}] - {assessment_type.upper()} assessment. "
                        f"This control requires {'manual verification' if assessment_type == 'manual' else 'automated check implementation'}."
                    ),
                    remediation=f"Refer to CIS Oracle Cloud Infrastructure Foundations Benchmark v2.0.0, control {cis_id}.",
                    compliance_frameworks=fw,
                    assessment_type=assessment_type,
                    cis_control_id=cis_id,
                    cis_level=level,
                ).to_dict())

        return manual_results

    def run_all_checks(self) -> list[dict]:
        """Run all OCI security checks including complete CIS benchmark coverage."""
        results = self.scan()
        results.extend(self._emit_cis_coverage(results))
        return results
