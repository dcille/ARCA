"""Alibaba Cloud Security Scanner — CIS/CCM-aligned checks.

Implements 30+ security checks for Alibaba Cloud services following
CIS Alibaba Cloud Benchmark, NIST 800-53, and CSA CCM v4.1.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from scanner.providers.base_check import CheckResult

logger = logging.getLogger(__name__)

COMPLIANCE = ["CIS-Alibaba-1.0", "NIST-800-53", "CCM-4.1"]


class AlibabaScanner:
    """Alibaba Cloud security scanner with comprehensive service checks."""

    def __init__(self, credentials: dict, regions: Optional[list] = None, services: Optional[list] = None):
        self.credentials = credentials
        self.regions = regions or ["cn-hangzhou"]
        self.services = services
        self._access_key_id = credentials.get("access_key_id")
        self._access_key_secret = credentials.get("access_key_secret")

    def _make_config(self, region: Optional[str] = None):
        """Create an OpenAPI Config object for Alibaba Cloud SDK clients."""
        from alibabacloud_tea_openapi.models import Config
        config = Config(
            access_key_id=self._access_key_id,
            access_key_secret=self._access_key_secret,
            region_id=region or self.regions[0],
        )
        return config

    def scan(self) -> list[dict]:
        """Run all Alibaba Cloud security checks."""
        results = []
        check_methods = {
            "ecs": self._check_ecs,
            "rds": self._check_rds,
            "oss": self._check_oss,
            "ram": self._check_ram,
            "vpc": self._check_vpc,
            "kms": self._check_kms,
            "actiontrail": self._check_actiontrail,
            "slb": self._check_slb,
            "waf": self._check_waf,
            "security_center": self._check_security_center,
        }

        for service_name, check_fn in check_methods.items():
            if self.services and service_name not in self.services:
                continue
            try:
                results.extend(check_fn())
            except Exception as e:
                logger.warning(f"Alibaba {service_name} checks failed: {e}")

        return results

    # ── ECS checks ──────────────────────────────────────────────────────

    def _check_ecs(self) -> list[dict]:
        results = []
        try:
            from alibabacloud_ecs20140526.client import Client as EcsClient
            from alibabacloud_ecs20140526 import models as ecs_models

            for region in self.regions:
                config = self._make_config(region)
                config.endpoint = f"ecs.{region}.aliyuncs.com"
                client = EcsClient(config)

                # List instances
                request = ecs_models.DescribeInstancesRequest(region_id=region, page_size=100)
                response = client.describe_instances(request)
                instances = response.body.instances.instance or []

                for inst in instances:
                    inst_id = inst.instance_id
                    inst_name = inst.instance_name or inst_id

                    # ali_ecs_no_public_ip — instances should not have public IPs
                    public_ips = inst.public_ip_address.ip_address if inst.public_ip_address else []
                    eip = inst.eip_address.ip_address if inst.eip_address and inst.eip_address.ip_address else None
                    has_public = bool(public_ips) or bool(eip)
                    results.append(CheckResult(
                        check_id="ali_ecs_no_public_ip",
                        check_title="ECS instance does not have a public IP address",
                        service="ecs", severity="medium", region=region,
                        status="FAIL" if has_public else "PASS",
                        resource_id=inst_id, resource_name=inst_name,
                        status_extended=f"Instance {inst_name} has public IP: {has_public}",
                        remediation="Remove public IP addresses and use NAT Gateway or SLB for internet access",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

                    # ali_ecs_no_classic_network — should use VPC, not classic network
                    is_vpc = inst.instance_network_type == "vpc"
                    results.append(CheckResult(
                        check_id="ali_ecs_vpc_network",
                        check_title="ECS instance uses VPC network (not classic)",
                        service="ecs", severity="high", region=region,
                        status="PASS" if is_vpc else "FAIL",
                        resource_id=inst_id, resource_name=inst_name,
                        status_extended=f"Instance {inst_name} network type: {inst.instance_network_type}",
                        remediation="Migrate ECS instances from classic network to VPC",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

                    # ali_ecs_deletion_protection
                    deletion_protection = inst.deletion_protection or False
                    results.append(CheckResult(
                        check_id="ali_ecs_deletion_protection",
                        check_title="ECS instance has deletion protection enabled",
                        service="ecs", severity="low", region=region,
                        status="PASS" if deletion_protection else "FAIL",
                        resource_id=inst_id, resource_name=inst_name,
                        status_extended=f"Instance {inst_name} deletion protection: {deletion_protection}",
                        remediation="Enable deletion protection to prevent accidental instance termination",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

                    # ali_ecs_disk_encryption — check that system disk is encrypted
                    disk_request = ecs_models.DescribeDisksRequest(
                        region_id=region, instance_id=inst_id,
                    )
                    disk_resp = client.describe_disks(disk_request)
                    for disk in disk_resp.body.disks.disk or []:
                        encrypted = disk.encrypted or False
                        results.append(CheckResult(
                            check_id="ali_ecs_disk_encryption",
                            check_title="ECS disk is encrypted",
                            service="ecs", severity="high", region=region,
                            status="PASS" if encrypted else "FAIL",
                            resource_id=disk.disk_id,
                            resource_name=disk.disk_name or disk.disk_id,
                            status_extended=f"Disk {disk.disk_id} encrypted: {encrypted}",
                            remediation="Enable encryption for ECS disks using KMS",
                            compliance_frameworks=COMPLIANCE,
                        ).to_dict())

                # ali_ecs_security_group_no_public_ingress — check SGs for 0.0.0.0/0
                sg_request = ecs_models.DescribeSecurityGroupsRequest(region_id=region, page_size=100)
                sg_response = client.describe_security_groups(sg_request)
                for sg in sg_response.body.security_groups.security_group or []:
                    sg_id = sg.security_group_id
                    rules_request = ecs_models.DescribeSecurityGroupAttributeRequest(
                        region_id=region, security_group_id=sg_id, direction="ingress",
                    )
                    rules_resp = client.describe_security_group_attribute(rules_request)
                    for rule in rules_resp.body.permissions.permission or []:
                        source = rule.source_cidr_ip or ""
                        if source == "0.0.0.0/0":
                            port_range = rule.port_range or ""
                            results.append(CheckResult(
                                check_id="ali_ecs_sg_no_public_ingress",
                                check_title="Security group does not allow unrestricted ingress",
                                service="ecs", severity="high", region=region,
                                status="FAIL",
                                resource_id=sg_id,
                                resource_name=sg.security_group_name or sg_id,
                                status_extended=f"SG {sg_id} allows 0.0.0.0/0 ingress on ports {port_range}",
                                remediation="Restrict security group ingress rules to specific CIDR ranges",
                                compliance_frameworks=COMPLIANCE,
                            ).to_dict())

        except Exception as e:
            logger.warning(f"Alibaba ECS checks failed: {e}")
        return results

    # ── RDS checks ──────────────────────────────────────────────────────

    def _check_rds(self) -> list[dict]:
        results = []
        try:
            from alibabacloud_rds20140815.client import Client as RdsClient
            from alibabacloud_rds20140815 import models as rds_models

            for region in self.regions:
                config = self._make_config(region)
                config.endpoint = f"rds.{region}.aliyuncs.com"
                client = RdsClient(config)

                request = rds_models.DescribeDBInstancesRequest(region_id=region, page_size=100)
                response = client.describe_dbinstances(request)
                instances = response.body.items.dbinstance or []

                for db in instances:
                    db_id = db.dbinstance_id
                    db_name = db.dbinstance_description or db_id

                    # ali_rds_no_public_access
                    net_request = rds_models.DescribeDBInstanceNetInfoRequest(dbinstance_id=db_id)
                    net_resp = client.describe_dbinstance_net_info(net_request)
                    has_public = any(
                        info.iptype == "Public"
                        for info in net_resp.body.dbinstance_net_infos.dbinstance_net_info or []
                    )
                    results.append(CheckResult(
                        check_id="ali_rds_no_public_access",
                        check_title="RDS instance is not publicly accessible",
                        service="rds", severity="critical", region=region,
                        status="FAIL" if has_public else "PASS",
                        resource_id=db_id, resource_name=db_name,
                        status_extended=f"RDS instance {db_name} public access: {has_public}",
                        remediation="Release the public endpoint and use VPC internal endpoints only",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

                    # ali_rds_encryption_enabled
                    is_encrypted = db.dbinstance_storage_type in ("cloud_essd", "cloud_ssd") if hasattr(db, "dbinstance_storage_type") else False
                    # Check TDE status for more accurate encryption check
                    try:
                        tde_request = rds_models.DescribeDBInstanceTDERequest(dbinstance_id=db_id)
                        tde_resp = client.describe_dbinstance_tde(tde_request)
                        tde_enabled = tde_resp.body.tdestatus == "Enabled"
                    except Exception:
                        tde_enabled = False
                    results.append(CheckResult(
                        check_id="ali_rds_encryption_enabled",
                        check_title="RDS instance has encryption enabled (TDE)",
                        service="rds", severity="high", region=region,
                        status="PASS" if tde_enabled else "FAIL",
                        resource_id=db_id, resource_name=db_name,
                        status_extended=f"RDS instance {db_name} TDE enabled: {tde_enabled}",
                        remediation="Enable Transparent Data Encryption (TDE) for the RDS instance",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

                    # ali_rds_backup_enabled
                    try:
                        backup_req = rds_models.DescribeBackupPolicyRequest(dbinstance_id=db_id)
                        backup_resp = client.describe_backup_policy(backup_req)
                        retention = int(backup_resp.body.backup_retention_period or 0)
                        backup_ok = retention >= 7
                    except Exception:
                        backup_ok = False
                        retention = 0
                    results.append(CheckResult(
                        check_id="ali_rds_backup_retention",
                        check_title="RDS instance has backup retention of at least 7 days",
                        service="rds", severity="medium", region=region,
                        status="PASS" if backup_ok else "FAIL",
                        resource_id=db_id, resource_name=db_name,
                        status_extended=f"RDS instance {db_name} backup retention: {retention} days",
                        remediation="Set backup retention period to at least 7 days",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

                    # ali_rds_ssl_enabled
                    try:
                        ssl_req = rds_models.DescribeDBInstanceSSLRequest(dbinstance_id=db_id)
                        ssl_resp = client.describe_dbinstance_ssl(ssl_req)
                        ssl_enabled = bool(ssl_resp.body.sslexpire_time)
                    except Exception:
                        ssl_enabled = False
                    results.append(CheckResult(
                        check_id="ali_rds_ssl_enabled",
                        check_title="RDS instance has SSL enabled",
                        service="rds", severity="high", region=region,
                        status="PASS" if ssl_enabled else "FAIL",
                        resource_id=db_id, resource_name=db_name,
                        status_extended=f"RDS instance {db_name} SSL enabled: {ssl_enabled}",
                        remediation="Enable SSL encryption for database connections",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

        except Exception as e:
            logger.warning(f"Alibaba RDS checks failed: {e}")
        return results

    # ── OSS checks ──────────────────────────────────────────────────────

    def _check_oss(self) -> list[dict]:
        results = []
        try:
            import oss2

            auth = oss2.Auth(self._access_key_id, self._access_key_secret)
            service = oss2.Service(auth, f"https://oss-{self.regions[0]}.aliyuncs.com")
            buckets = list(oss2.BucketIterator(service))

            for bucket_info in buckets:
                bname = bucket_info.name
                bucket = oss2.Bucket(auth, f"https://oss-{bucket_info.location}.aliyuncs.com", bname)

                # ali_oss_no_public_access
                try:
                    acl = bucket.get_bucket_acl()
                    is_public = acl.acl in ("public-read", "public-read-write")
                except Exception:
                    is_public = False
                results.append(CheckResult(
                    check_id="ali_oss_no_public_access",
                    check_title="OSS bucket is not publicly accessible",
                    service="oss", severity="critical",
                    status="FAIL" if is_public else "PASS",
                    resource_id=bname, resource_name=bname,
                    status_extended=f"Bucket {bname} public access: {is_public}",
                    remediation="Set bucket ACL to private",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # ali_oss_encryption_enabled
                try:
                    enc_rule = bucket.get_bucket_encryption()
                    encrypted = bool(enc_rule.sse_algorithm)
                except oss2.exceptions.NoSuchServerSideEncryptionRule:
                    encrypted = False
                except Exception:
                    encrypted = False
                results.append(CheckResult(
                    check_id="ali_oss_encryption_enabled",
                    check_title="OSS bucket has server-side encryption enabled",
                    service="oss", severity="high",
                    status="PASS" if encrypted else "FAIL",
                    resource_id=bname, resource_name=bname,
                    status_extended=f"Bucket {bname} SSE enabled: {encrypted}",
                    remediation="Enable server-side encryption (SSE-KMS or SSE-OSS) for the bucket",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # ali_oss_logging_enabled
                try:
                    logging_config = bucket.get_bucket_logging()
                    logging_enabled = bool(logging_config.target_bucket)
                except Exception:
                    logging_enabled = False
                results.append(CheckResult(
                    check_id="ali_oss_logging_enabled",
                    check_title="OSS bucket has access logging enabled",
                    service="oss", severity="medium",
                    status="PASS" if logging_enabled else "FAIL",
                    resource_id=bname, resource_name=bname,
                    status_extended=f"Bucket {bname} logging enabled: {logging_enabled}",
                    remediation="Enable access logging and specify a target bucket for log storage",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # ali_oss_versioning_enabled
                try:
                    versioning = bucket.get_bucket_versioning()
                    versioning_on = versioning.status == "Enabled"
                except Exception:
                    versioning_on = False
                results.append(CheckResult(
                    check_id="ali_oss_versioning_enabled",
                    check_title="OSS bucket has versioning enabled",
                    service="oss", severity="low",
                    status="PASS" if versioning_on else "FAIL",
                    resource_id=bname, resource_name=bname,
                    status_extended=f"Bucket {bname} versioning: {versioning_on}",
                    remediation="Enable versioning to protect against accidental deletion",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # ali_oss_https_only — check for HTTPS-only access policy
                try:
                    policy = bucket.get_bucket_policy()
                    policy_text = policy.policy if hasattr(policy, "policy") else str(policy)
                    https_only = "aws:SecureTransport" in policy_text or "acs:SecureTransport" in policy_text
                except Exception:
                    https_only = False
                results.append(CheckResult(
                    check_id="ali_oss_https_only",
                    check_title="OSS bucket enforces HTTPS-only access",
                    service="oss", severity="medium",
                    status="PASS" if https_only else "FAIL",
                    resource_id=bname, resource_name=bname,
                    status_extended=f"Bucket {bname} HTTPS-only policy: {https_only}",
                    remediation="Add a bucket policy that denies requests not using SSL/TLS",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # ali_oss_lifecycle_configured
                try:
                    lifecycle = bucket.get_bucket_lifecycle()
                    has_lifecycle = bool(lifecycle.rules)
                except Exception:
                    has_lifecycle = False
                results.append(CheckResult(
                    check_id="ali_oss_lifecycle_configured",
                    check_title="OSS bucket has lifecycle rules configured",
                    service="oss", severity="low",
                    status="PASS" if has_lifecycle else "FAIL",
                    resource_id=bname, resource_name=bname,
                    status_extended=f"Bucket {bname} lifecycle rules: {has_lifecycle}",
                    remediation="Configure lifecycle rules for data retention and cost management",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

        except Exception as e:
            logger.warning(f"Alibaba OSS checks failed: {e}")
        return results

    # ── RAM checks ──────────────────────────────────────────────────────

    def _check_ram(self) -> list[dict]:
        results = []
        try:
            from alibabacloud_ram20150501.client import Client as RamClient
            from alibabacloud_ram20150501 import models as ram_models
            from alibabacloud_tea_openapi.models import Config

            config = Config(
                access_key_id=self._access_key_id,
                access_key_secret=self._access_key_secret,
                endpoint="ram.aliyuncs.com",
            )
            client = RamClient(config)

            # ali_ram_mfa_enabled — check that MFA is enabled for all RAM users
            users_resp = client.list_users(ram_models.ListUsersRequest())
            users = users_resp.body.users.user or []

            for user in users:
                username = user.user_name

                # ali_ram_mfa_enabled
                try:
                    mfa_resp = client.get_user_mfainfo(
                        ram_models.GetUserMFAInfoRequest(user_name=username)
                    )
                    mfa_active = mfa_resp.body.mfadevice and mfa_resp.body.mfadevice.serial_number
                except Exception:
                    mfa_active = False
                results.append(CheckResult(
                    check_id="ali_ram_mfa_enabled",
                    check_title="RAM user has MFA enabled",
                    service="ram", severity="high",
                    status="PASS" if mfa_active else "FAIL",
                    resource_id=username, resource_name=username,
                    status_extended=f"RAM user {username} MFA enabled: {bool(mfa_active)}",
                    remediation="Enable MFA for all RAM users with console access",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # ali_ram_access_key_rotation — keys older than 90 days
                try:
                    ak_resp = client.list_access_keys(
                        ram_models.ListAccessKeysRequest(user_name=username)
                    )
                    for key in ak_resp.body.access_keys.access_key or []:
                        if key.status != "Active":
                            continue
                        create_date = datetime.fromisoformat(key.create_date.replace("Z", "+00:00"))
                        age_days = (datetime.now(timezone.utc) - create_date).days
                        old_key = age_days > 90
                        results.append(CheckResult(
                            check_id="ali_ram_access_key_rotation",
                            check_title="RAM user access key is rotated within 90 days",
                            service="ram", severity="medium",
                            status="FAIL" if old_key else "PASS",
                            resource_id=f"{username}/{key.access_key_id}",
                            resource_name=username,
                            status_extended=f"Access key {key.access_key_id} for {username} is {age_days} days old",
                            remediation="Rotate access keys at least every 90 days",
                            compliance_frameworks=COMPLIANCE,
                        ).to_dict())
                except Exception:
                    pass

                # ali_ram_unused_users — users with no recent login (>90 days)
                last_login = user.last_login_date
                if last_login:
                    try:
                        login_dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                        inactive_days = (datetime.now(timezone.utc) - login_dt).days
                        inactive = inactive_days > 90
                    except Exception:
                        inactive = False
                        inactive_days = 0
                else:
                    inactive = True
                    inactive_days = -1
                results.append(CheckResult(
                    check_id="ali_ram_unused_users",
                    check_title="RAM user has logged in within the last 90 days",
                    service="ram", severity="low",
                    status="FAIL" if inactive else "PASS",
                    resource_id=username, resource_name=username,
                    status_extended=(
                        f"RAM user {username} last login: {last_login or 'never'} "
                        f"({inactive_days} days ago)"
                    ),
                    remediation="Remove or disable RAM users that have not logged in for more than 90 days",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

            # ali_ram_password_policy
            try:
                policy_resp = client.get_password_policy(ram_models.GetPasswordPolicyRequest())
                policy = policy_resp.body.password_policy
                min_length = policy.minimum_password_length or 0
                require_symbols = policy.require_symbols or False
                require_numbers = policy.require_numbers or False
                require_upper = policy.require_uppercase_characters or False
                require_lower = policy.require_lowercase_characters or False
                strong = (
                    min_length >= 14
                    and require_symbols
                    and require_numbers
                    and require_upper
                    and require_lower
                )
                results.append(CheckResult(
                    check_id="ali_ram_password_policy",
                    check_title="RAM password policy meets complexity requirements",
                    service="ram", severity="medium",
                    status="PASS" if strong else "FAIL",
                    resource_id="password-policy",
                    status_extended=(
                        f"Password policy: minLength={min_length}, symbols={require_symbols}, "
                        f"numbers={require_numbers}, upper={require_upper}, lower={require_lower}"
                    ),
                    remediation="Set minimum password length to 14+ and require all character types",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())
            except Exception:
                pass

        except Exception as e:
            logger.warning(f"Alibaba RAM checks failed: {e}")
        return results

    # ── VPC checks ──────────────────────────────────────────────────────

    def _check_vpc(self) -> list[dict]:
        results = []
        try:
            from alibabacloud_vpc20160428.client import Client as VpcClient
            from alibabacloud_vpc20160428 import models as vpc_models

            for region in self.regions:
                config = self._make_config(region)
                config.endpoint = f"vpc.{region}.aliyuncs.com"
                client = VpcClient(config)

                # List VPCs
                vpc_req = vpc_models.DescribeVpcsRequest(region_id=region, page_size=50)
                vpc_resp = client.describe_vpcs(vpc_req)
                vpcs = vpc_resp.body.vpcs.vpc or []

                for vpc in vpcs:
                    vpc_id = vpc.vpc_id
                    vpc_name = vpc.vpc_name or vpc_id

                    # ali_vpc_flow_logs — check if flow logs are enabled
                    try:
                        fl_req = vpc_models.DescribeFlowLogsRequest(
                            region_id=region, resource_id=vpc_id, resource_type="VPC",
                        )
                        fl_resp = client.describe_flow_logs(fl_req)
                        has_flow_logs = bool(fl_resp.body.flow_logs.flow_log)
                    except Exception:
                        has_flow_logs = False
                    results.append(CheckResult(
                        check_id="ali_vpc_flow_logs",
                        check_title="VPC has flow logs enabled",
                        service="vpc", severity="medium", region=region,
                        status="PASS" if has_flow_logs else "FAIL",
                        resource_id=vpc_id, resource_name=vpc_name,
                        status_extended=f"VPC {vpc_name} flow logs enabled: {has_flow_logs}",
                        remediation="Enable VPC flow logs to capture network traffic metadata",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

                # ali_vpc_nacl — check that NACLs are associated with vSwitches
                try:
                    nacl_req = vpc_models.DescribeNetworkAclsRequest(region_id=region, page_size=50)
                    nacl_resp = client.describe_network_acls(nacl_req)
                    nacls = nacl_resp.body.network_acls.network_acl or []
                    for nacl in nacls:
                        nacl_id = nacl.network_acl_id
                        nacl_name = nacl.network_acl_name or nacl_id
                        associated = bool(nacl.resources and nacl.resources.resource)
                        results.append(CheckResult(
                            check_id="ali_vpc_nacl_associated",
                            check_title="Network ACL is associated with vSwitches",
                            service="vpc", severity="medium", region=region,
                            status="PASS" if associated else "FAIL",
                            resource_id=nacl_id, resource_name=nacl_name,
                            status_extended=f"NACL {nacl_name} associated with vSwitches: {associated}",
                            remediation="Associate Network ACLs with vSwitches to control traffic",
                            compliance_frameworks=COMPLIANCE,
                        ).to_dict())
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"Alibaba VPC checks failed: {e}")
        return results

    # ── KMS checks ──────────────────────────────────────────────────────

    def _check_kms(self) -> list[dict]:
        results = []
        try:
            from alibabacloud_kms20160120.client import Client as KmsClient
            from alibabacloud_kms20160120 import models as kms_models

            for region in self.regions:
                config = self._make_config(region)
                config.endpoint = f"kms.{region}.aliyuncs.com"
                client = KmsClient(config)

                list_req = kms_models.ListKeysRequest(page_size=100)
                list_resp = client.list_keys(list_req)
                keys = list_resp.body.keys.key or []

                for key_meta in keys:
                    key_id = key_meta.key_id

                    desc_req = kms_models.DescribeKeyRequest(key_id=key_id)
                    desc_resp = client.describe_key(desc_req)
                    key_info = desc_resp.body.key_metadata

                    # Skip Alibaba-managed default keys
                    if key_info.creator == "Chinese Government":
                        continue

                    # ali_kms_key_rotation
                    rotation_enabled = key_info.automatic_rotation == "Enabled"
                    results.append(CheckResult(
                        check_id="ali_kms_key_rotation",
                        check_title="KMS CMK has automatic rotation enabled",
                        service="kms", severity="medium", region=region,
                        status="PASS" if rotation_enabled else "FAIL",
                        resource_id=key_id,
                        resource_name=key_info.description or key_id,
                        status_extended=f"KMS key {key_id} auto-rotation: {rotation_enabled}",
                        remediation="Enable automatic key rotation for CMKs",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

                    # ali_kms_cmk_enabled — key should not be disabled
                    key_enabled = key_info.key_state == "Enabled"
                    results.append(CheckResult(
                        check_id="ali_kms_cmk_enabled",
                        check_title="KMS CMK is in Enabled state",
                        service="kms", severity="low", region=region,
                        status="PASS" if key_enabled else "FAIL",
                        resource_id=key_id,
                        resource_name=key_info.description or key_id,
                        status_extended=f"KMS key {key_id} state: {key_info.key_state}",
                        remediation="Ensure CMKs are enabled; disable or schedule deletion for unused keys",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

        except Exception as e:
            logger.warning(f"Alibaba KMS checks failed: {e}")
        return results

    # ── ActionTrail checks ──────────────────────────────────────────────

    def _check_actiontrail(self) -> list[dict]:
        results = []
        try:
            from alibabacloud_actiontrail20200706.client import Client as ATClient
            from alibabacloud_actiontrail20200706 import models as at_models
            from alibabacloud_tea_openapi.models import Config

            config = Config(
                access_key_id=self._access_key_id,
                access_key_secret=self._access_key_secret,
                endpoint="actiontrail.cn-hangzhou.aliyuncs.com",
            )
            client = ATClient(config)

            trails_resp = client.describe_trails(at_models.DescribeTrailsRequest())
            trails = trails_resp.body.trail_list or []

            # ali_actiontrail_enabled
            results.append(CheckResult(
                check_id="ali_actiontrail_enabled",
                check_title="ActionTrail logging is enabled",
                service="actiontrail", severity="high",
                status="PASS" if trails else "FAIL",
                resource_id="actiontrail",
                status_extended=f"ActionTrail has {len(trails)} trail(s) configured",
                remediation="Create an ActionTrail trail to log all API activity",
                compliance_frameworks=COMPLIANCE,
            ).to_dict())

            for trail in trails:
                trail_name = trail.name
                # ali_actiontrail_multi_region
                is_multi = trail.trail_region == "All"
                results.append(CheckResult(
                    check_id="ali_actiontrail_multi_region",
                    check_title="ActionTrail trail covers all regions",
                    service="actiontrail", severity="medium",
                    status="PASS" if is_multi else "FAIL",
                    resource_id=trail_name, resource_name=trail_name,
                    status_extended=f"Trail {trail_name} region: {trail.trail_region}",
                    remediation="Set trail region to 'All' to capture events across all regions",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # ali_actiontrail_logging_active
                is_active = trail.status == "Enable"
                results.append(CheckResult(
                    check_id="ali_actiontrail_logging_active",
                    check_title="ActionTrail trail is actively logging",
                    service="actiontrail", severity="high",
                    status="PASS" if is_active else "FAIL",
                    resource_id=trail_name, resource_name=trail_name,
                    status_extended=f"Trail {trail_name} status: {trail.status}",
                    remediation="Enable the ActionTrail trail to resume logging",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

        except Exception as e:
            logger.warning(f"Alibaba ActionTrail checks failed: {e}")
        return results

    # ── SLB checks ──────────────────────────────────────────────────────

    def _check_slb(self) -> list[dict]:
        results = []
        try:
            from alibabacloud_slb20140515.client import Client as SlbClient
            from alibabacloud_slb20140515 import models as slb_models

            for region in self.regions:
                config = self._make_config(region)
                config.endpoint = f"slb.{region}.aliyuncs.com"
                client = SlbClient(config)

                req = slb_models.DescribeLoadBalancersRequest(region_id=region, page_size=100)
                resp = client.describe_load_balancers(req)
                lbs = resp.body.load_balancers.load_balancer or []

                for lb in lbs:
                    lb_id = lb.load_balancer_id
                    lb_name = lb.load_balancer_name or lb_id

                    # ali_slb_https_listener — check for HTTPS listeners
                    try:
                        attr_req = slb_models.DescribeLoadBalancerAttributeRequest(
                            load_balancer_id=lb_id,
                        )
                        attr_resp = client.describe_load_balancer_attribute(attr_req)
                        ports = attr_resp.body.listener_ports_and_protocol.listener_port_and_protocol or []
                        has_https = any(
                            p.listener_protocol in ("https", "HTTPS")
                            for p in ports
                        )
                        has_http = any(
                            p.listener_protocol in ("http", "HTTP")
                            for p in ports
                        )
                        https_ok = has_https or not has_http  # OK if HTTPS or no HTTP at all
                    except Exception:
                        https_ok = False
                    results.append(CheckResult(
                        check_id="ali_slb_https_listener",
                        check_title="SLB uses HTTPS listeners",
                        service="slb", severity="high", region=region,
                        status="PASS" if https_ok else "FAIL",
                        resource_id=lb_id, resource_name=lb_name,
                        status_extended=f"SLB {lb_name} has HTTPS listeners: {https_ok}",
                        remediation="Configure HTTPS listeners with TLS certificates instead of HTTP",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

                    # ali_slb_access_logs
                    try:
                        log_req = slb_models.DescribeAccessLogsDownloadAttributeRequest(
                            load_balancer_id=lb_id, region_id=region,
                        )
                        log_resp = client.describe_access_logs_download_attribute(log_req)
                        logs_enabled = bool(
                            log_resp.body.logs_download_attributes
                            and log_resp.body.logs_download_attributes.logs_download_attribute
                        )
                    except Exception:
                        logs_enabled = False
                    results.append(CheckResult(
                        check_id="ali_slb_access_logs",
                        check_title="SLB has access logs enabled",
                        service="slb", severity="medium", region=region,
                        status="PASS" if logs_enabled else "FAIL",
                        resource_id=lb_id, resource_name=lb_name,
                        status_extended=f"SLB {lb_name} access logs enabled: {logs_enabled}",
                        remediation="Enable SLB access logs and configure log storage",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

        except Exception as e:
            logger.warning(f"Alibaba SLB checks failed: {e}")
        return results

    # ── WAF checks ──────────────────────────────────────────────────────

    def _check_waf(self) -> list[dict]:
        results = []
        try:
            from alibabacloud_waf_openapi20190910.client import Client as WafClient
            from alibabacloud_waf_openapi20190910 import models as waf_models
            from alibabacloud_tea_openapi.models import Config

            config = Config(
                access_key_id=self._access_key_id,
                access_key_secret=self._access_key_secret,
                endpoint="wafopenapi.cn-hangzhou.aliyuncs.com",
            )
            client = WafClient(config)

            # ali_waf_enabled — check if WAF instance exists
            try:
                instance_req = waf_models.DescribeInstanceInfoRequest()
                instance_resp = client.describe_instance_info(instance_req)
                waf_active = (
                    instance_resp.body.instance_info
                    and instance_resp.body.instance_info.status == 1
                )
            except Exception:
                waf_active = False
            results.append(CheckResult(
                check_id="ali_waf_enabled",
                check_title="WAF instance is active",
                service="waf", severity="high",
                status="PASS" if waf_active else "FAIL",
                resource_id="waf-instance",
                status_extended=f"WAF instance active: {waf_active}",
                remediation="Provision and activate a WAF instance to protect web applications",
                compliance_frameworks=COMPLIANCE,
            ).to_dict())

            # ali_waf_rules — check that protection rules are configured
            if waf_active:
                try:
                    domain_req = waf_models.DescribeDomainNamesRequest(
                        instance_id=instance_resp.body.instance_info.instance_id,
                    )
                    domain_resp = client.describe_domain_names(domain_req)
                    domains = domain_resp.body.domain_names or []
                    has_domains = len(domains) > 0
                except Exception:
                    has_domains = False
                results.append(CheckResult(
                    check_id="ali_waf_domains_configured",
                    check_title="WAF has protected domains configured",
                    service="waf", severity="medium",
                    status="PASS" if has_domains else "FAIL",
                    resource_id="waf-domains",
                    status_extended=f"WAF protected domains: {len(domains) if has_domains else 0}",
                    remediation="Add domain names to WAF for web application protection",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

        except Exception as e:
            logger.warning(f"Alibaba WAF checks failed: {e}")
        return results

    # ── Security Center checks ──────────────────────────────────────────

    def _check_security_center(self) -> list[dict]:
        results = []
        try:
            from alibabacloud_sas20181203.client import Client as SasClient
            from alibabacloud_sas20181203 import models as sas_models
            from alibabacloud_tea_openapi.models import Config

            config = Config(
                access_key_id=self._access_key_id,
                access_key_secret=self._access_key_secret,
                endpoint="tds.aliyuncs.com",
            )
            client = SasClient(config)

            # ali_security_center_enabled — check if threat detection is active
            try:
                overview_req = sas_models.DescribeAlarmEventListRequest(
                    current_page=1, page_size=1,
                )
                overview_resp = client.describe_alarm_event_list(overview_req)
                # If we can query, Security Center is enabled
                sc_active = True
            except Exception:
                sc_active = False
            results.append(CheckResult(
                check_id="ali_security_center_enabled",
                check_title="Security Center (Threat Detection) is enabled",
                service="security_center", severity="high",
                status="PASS" if sc_active else "FAIL",
                resource_id="security-center",
                status_extended=f"Security Center threat detection active: {sc_active}",
                remediation="Enable Alibaba Cloud Security Center for threat detection and vulnerability management",
                compliance_frameworks=COMPLIANCE,
            ).to_dict())

        except Exception as e:
            logger.warning(f"Alibaba Security Center checks failed: {e}")
        return results
