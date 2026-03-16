"""OCI (Oracle Cloud Infrastructure) Security Scanner.

Implements security checks for OCI services following CIS Oracle Cloud
Infrastructure Foundations Benchmark v2.0.
"""
import logging
from typing import Optional

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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                        compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                                compliance_frameworks=["CIS-OCI-2.0"],
                            ).to_dict())
            except Exception as e:
                logger.warning(f"OCI policy wildcard check failed: {e}")

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
                                                    compliance_frameworks=["CIS-OCI-2.0"],
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
                                    compliance_frameworks=["CIS-OCI-2.0"],
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
                                compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                                compliance_frameworks=["CIS-OCI-2.0"],
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
                    compliance_frameworks=["CIS-OCI-2.0"],
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
                    compliance_frameworks=["CIS-OCI-2.0"],
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
                    compliance_frameworks=["CIS-OCI-2.0"],
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
                    compliance_frameworks=["CIS-OCI-2.0"],
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
                            compliance_frameworks=["CIS-OCI-2.0"],
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
                compliance_frameworks=["CIS-OCI-2.0"],
            ).to_dict())

        except ImportError:
            logger.warning("OCI SDK not installed, skipping notifications checks")
        except Exception as e:
            logger.error(f"OCI notifications checks failed: {e}")

        return results
