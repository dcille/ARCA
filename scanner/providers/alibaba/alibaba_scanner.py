"""Alibaba Cloud Security Scanner — CIS/CCM-aligned checks.

Implements 60+ security checks for Alibaba Cloud services following
CIS Alibaba Cloud Foundation Benchmark v1.0 and v2.0, NIST 800-53, and CSA CCM v4.1.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from scanner.providers.base_check import CheckResult
from scanner.cis_controls.alibaba_cis_controls import ALIBABA_CIS_CONTROLS

logger = logging.getLogger(__name__)

COMPLIANCE = ["CIS-Alibaba-1.0", "CIS-Alibaba-2.0", "NIST-800-53", "CCM-4.1"]


def _port_range_includes(port_range: str, port: int) -> bool:
    """Check if an Alibaba security group port range string includes a given port."""
    if not port_range or port_range == "-1/-1":
        return True  # -1/-1 means all ports
    try:
        parts = port_range.split("/")
        lo, hi = int(parts[0]), int(parts[1])
        return lo <= port <= hi
    except (ValueError, IndexError):
        return False


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
            "ack": self._check_ack,
            "sls": self._check_sls,
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

                            # CIS 2.0 4.3 — SSH port 22 specific check
                            if _port_range_includes(port_range, 22):
                                results.append(CheckResult(
                                    check_id="ali_ecs_sg_no_ssh_open",
                                    check_title="Security group does not allow unrestricted SSH (port 22) from 0.0.0.0/0",
                                    service="ecs", severity="high", region=region,
                                    status="FAIL",
                                    resource_id=sg_id,
                                    resource_name=sg.security_group_name or sg_id,
                                    status_extended=f"SG {sg_id} allows SSH (port 22) from 0.0.0.0/0",
                                    remediation="Restrict port 22 access to specific trusted IP ranges or use bastion hosts",
                                    remediation_url="https://www.alibabacloud.com/help/doc-detail/51170.htm",
                                    compliance_frameworks=COMPLIANCE,
                                ).to_dict())

                            # CIS 2.0 4.4 — RDP port 3389 specific check
                            if _port_range_includes(port_range, 3389):
                                results.append(CheckResult(
                                    check_id="ali_ecs_sg_no_rdp_open",
                                    check_title="Security group does not allow unrestricted RDP (port 3389) from 0.0.0.0/0",
                                    service="ecs", severity="high", region=region,
                                    status="FAIL",
                                    resource_id=sg_id,
                                    resource_name=sg.security_group_name or sg_id,
                                    status_extended=f"SG {sg_id} allows RDP (port 3389) from 0.0.0.0/0",
                                    remediation="Restrict port 3389 access to specific trusted IP ranges",
                                    remediation_url="https://www.alibabacloud.com/help/doc-detail/51170.htm",
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

                    # CIS 2.0 6.2 — RDS not open to the world (whitelist check)
                    try:
                        ip_req = rds_models.DescribeDBInstanceIPArrayListRequest(dbinstance_id=db_id)
                        ip_resp = client.describe_dbinstance_iparray_list(ip_req)
                        open_world = False
                        for ip_arr in ip_resp.body.items.dbinstance_iparray or []:
                            ips = ip_arr.security_iplist or ""
                            if "0.0.0.0/0" in ips or "0.0.0.0" in ips.split(","):
                                open_world = True
                                break
                        results.append(CheckResult(
                            check_id="ali_rds_not_open_world",
                            check_title="RDS instance whitelist does not allow 0.0.0.0/0",
                            service="rds", severity="critical", region=region,
                            status="FAIL" if open_world else "PASS",
                            resource_id=db_id, resource_name=db_name,
                            status_extended=f"RDS {db_name} open to world: {open_world}",
                            remediation="Remove 0.0.0.0/0 from the RDS IP whitelist and restrict to specific IPs",
                            remediation_url="https://www.alibabacloud.com/help/doc-detail/26198.htm",
                            compliance_frameworks=COMPLIANCE,
                        ).to_dict())
                    except Exception:
                        pass

                    # CIS 2.0 6.3 — SQL Auditing enabled
                    try:
                        audit_req = rds_models.DescribeSQLCollectorPolicyRequest(dbinstance_id=db_id)
                        audit_resp = client.describe_sqlcollector_policy(audit_req)
                        audit_enabled = audit_resp.body.sqlcollector_status == "Enable"
                    except Exception:
                        audit_enabled = False
                    results.append(CheckResult(
                        check_id="ali_rds_audit_enabled",
                        check_title="RDS instance has SQL auditing (SQL Explorer) enabled",
                        service="rds", severity="medium", region=region,
                        status="PASS" if audit_enabled else "FAIL",
                        resource_id=db_id, resource_name=db_name,
                        status_extended=f"RDS {db_name} SQL audit: {audit_enabled}",
                        remediation="Enable SQL Explorer/Auditing for the RDS instance via the console",
                        remediation_url="https://www.alibabacloud.com/help/doc-detail/96123.htm",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())

                    # CIS 2.0 6.7/6.8/6.9 — PostgreSQL specific parameters
                    engine = getattr(db, 'engine', '') or ''
                    if engine.lower() == 'postgresql':
                        try:
                            param_req = rds_models.DescribeParametersRequest(dbinstance_id=db_id)
                            param_resp = client.describe_parameters(param_req)
                            running_params = {}
                            for p in param_resp.body.running_parameters.dbinstance_parameter or []:
                                running_params[p.parameter_name] = p.parameter_value

                            for param_name, check_id, title in [
                                ("log_connections", "ali_rds_pg_log_connections",
                                 "PostgreSQL log_connections is set to ON"),
                                ("log_disconnections", "ali_rds_pg_log_disconnections",
                                 "PostgreSQL log_disconnections is set to ON"),
                                ("log_duration", "ali_rds_pg_log_duration",
                                 "PostgreSQL log_duration is set to ON"),
                            ]:
                                val = running_params.get(param_name, "off")
                                results.append(CheckResult(
                                    check_id=check_id,
                                    check_title=title,
                                    service="rds", severity="medium", region=region,
                                    status="PASS" if val.lower() == "on" else "FAIL",
                                    resource_id=db_id, resource_name=db_name,
                                    status_extended=f"RDS {db_name} {param_name}: {val}",
                                    remediation=f"Set parameter '{param_name}' to 'ON' in RDS instance parameters",
                                    remediation_url="https://www.alibabacloud.com/help/doc-detail/96751.htm",
                                    compliance_frameworks=COMPLIANCE,
                                ).to_dict())
                        except Exception:
                            pass

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

            # ali_ram_password_policy (aggregate check)
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

                # CIS 2.0 1.7 — Granular: requires uppercase
                results.append(CheckResult(
                    check_id="ali_ram_password_uppercase",
                    check_title="RAM password policy requires at least one uppercase letter",
                    service="ram", severity="medium",
                    status="PASS" if require_upper else "FAIL",
                    resource_id="password-policy",
                    remediation="Run: aliyun ram SetPasswordPolicy --RequireUppercaseCharacters true",
                    remediation_url="https://www.alibabacloud.com/help/doc-detail/116413.htm",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # CIS 2.0 1.8 — Granular: requires lowercase
                results.append(CheckResult(
                    check_id="ali_ram_password_lowercase",
                    check_title="RAM password policy requires at least one lowercase letter",
                    service="ram", severity="medium",
                    status="PASS" if require_lower else "FAIL",
                    resource_id="password-policy",
                    remediation="Run: aliyun ram SetPasswordPolicy --RequireLowercaseCharacters true",
                    remediation_url="https://www.alibabacloud.com/help/doc-detail/116413.htm",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # CIS 2.0 1.9 — Granular: requires symbol
                results.append(CheckResult(
                    check_id="ali_ram_password_symbol",
                    check_title="RAM password policy requires at least one symbol",
                    service="ram", severity="medium",
                    status="PASS" if require_symbols else "FAIL",
                    resource_id="password-policy",
                    remediation="Run: aliyun ram SetPasswordPolicy --RequireSymbols true",
                    remediation_url="https://www.alibabacloud.com/help/doc-detail/116413.htm",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # CIS 2.0 1.10 — Granular: requires number
                results.append(CheckResult(
                    check_id="ali_ram_password_number",
                    check_title="RAM password policy requires at least one number",
                    service="ram", severity="medium",
                    status="PASS" if require_numbers else "FAIL",
                    resource_id="password-policy",
                    remediation="Run: aliyun ram SetPasswordPolicy --RequireNumbers true",
                    remediation_url="https://www.alibabacloud.com/help/doc-detail/116413.htm",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # CIS 2.0 1.11 — Granular: minimum length >= 14
                results.append(CheckResult(
                    check_id="ali_ram_password_length",
                    check_title="RAM password policy requires minimum length of 14 or greater",
                    service="ram", severity="medium",
                    status="PASS" if min_length >= 14 else "FAIL",
                    resource_id="password-policy",
                    status_extended=f"Minimum password length: {min_length}",
                    remediation="Run: aliyun ram SetPasswordPolicy --MinimumPasswordLength 14",
                    remediation_url="https://www.alibabacloud.com/help/doc-detail/116413.htm",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # CIS 2.0 1.12 — Password reuse prevention
                reuse_prevention = getattr(policy, 'password_reuse_prevention', 0) or 0
                results.append(CheckResult(
                    check_id="ali_ram_password_reuse",
                    check_title="RAM password policy prevents password reuse",
                    service="ram", severity="medium",
                    status="PASS" if reuse_prevention >= 5 else "FAIL",
                    resource_id="password-policy",
                    status_extended=f"Password reuse prevention: {reuse_prevention} previous passwords",
                    remediation="Run: aliyun ram SetPasswordPolicy --PasswordReusePrevention 5",
                    remediation_url="https://www.alibabacloud.com/help/doc-detail/116413.htm",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # CIS 2.0 1.13 — Password expiry <= 365 days
                max_age = getattr(policy, 'max_password_age', 0) or 0
                expiry_ok = 0 < max_age <= 365 if max_age else False
                results.append(CheckResult(
                    check_id="ali_ram_password_expiry",
                    check_title="RAM password policy expires passwords within 365 days",
                    service="ram", severity="medium",
                    status="PASS" if expiry_ok else "FAIL",
                    resource_id="password-policy",
                    status_extended=f"Max password age: {max_age} days" if max_age else "Password expiry not configured",
                    remediation="Run: aliyun ram SetPasswordPolicy --MaxPasswordAge 365",
                    remediation_url="https://www.alibabacloud.com/help/doc-detail/116413.htm",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # CIS 2.0 1.14 — Lockout after 5 failed attempts
                max_attempts = getattr(policy, 'max_login_attemps', 0) or 0
                results.append(CheckResult(
                    check_id="ali_ram_password_lockout",
                    check_title="RAM password policy blocks logon after 5 incorrect attempts",
                    service="ram", severity="medium",
                    status="PASS" if 0 < max_attempts <= 5 else "FAIL",
                    resource_id="password-policy",
                    status_extended=f"Max login attempts: {max_attempts}" if max_attempts else "Lockout not configured",
                    remediation="Run: aliyun ram SetPasswordPolicy --MaxLoginAttemps 5",
                    remediation_url="https://www.alibabacloud.com/help/doc-detail/116413.htm",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())
            except Exception:
                pass

            # CIS 2.0 1.15 — No wildcard administrative policies
            try:
                policies_resp = client.list_policies(ram_models.ListPoliciesRequest(policy_type="Custom", max_items=200))
                for pol in policies_resp.body.policies.policy or []:
                    pol_name = pol.policy_name
                    try:
                        detail_resp = client.get_policy(ram_models.GetPolicyRequest(
                            policy_name=pol_name, policy_type="Custom",
                        ))
                        doc = detail_resp.body.default_policy_version.policy_document or ""
                        has_admin = '"Action": "*"' in doc and '"Resource": "*"' in doc and '"Effect": "Allow"' in doc
                        if has_admin:
                            results.append(CheckResult(
                                check_id="ali_ram_no_wildcard_policy",
                                check_title="RAM policy does not allow full *:* administrative privileges",
                                service="ram", severity="critical",
                                status="FAIL",
                                resource_id=pol_name, resource_name=pol_name,
                                status_extended=f"Policy '{pol_name}' grants full *:* administrative privileges",
                                remediation="Edit the policy to grant least-privilege permissions or detach from all identities",
                                remediation_url="https://www.alibabacloud.com/help/doc-detail/93733.htm",
                                compliance_frameworks=COMPLIANCE,
                            ).to_dict())
                    except Exception:
                        pass
            except Exception:
                pass

            # CIS 2.0 1.16 — Policies attached only to groups/roles
            try:
                for user in users:
                    username = user.user_name
                    try:
                        pol_resp = client.list_policies_for_user(ram_models.ListPoliciesForUserRequest(user_name=username))
                        user_policies = pol_resp.body.policies.policy or []
                        if user_policies:
                            results.append(CheckResult(
                                check_id="ali_ram_policies_groups_only",
                                check_title="RAM policies should be attached to groups/roles, not directly to users",
                                service="ram", severity="medium",
                                status="FAIL",
                                resource_id=username, resource_name=username,
                                status_extended=f"User '{username}' has {len(user_policies)} direct policy attachment(s)",
                                remediation="Detach policies from users and attach to groups or roles instead",
                                remediation_url="https://www.alibabacloud.com/help/doc-detail/116809.htm",
                                compliance_frameworks=COMPLIANCE,
                            ).to_dict())
                    except Exception:
                        pass
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

            # ali_actiontrail_oss_not_public — CIS 2.2 OSS bucket for trail not public
            for trail in trails:
                trail_name = trail.name
                oss_bucket = getattr(trail, 'oss_bucket_name', None)
                if oss_bucket:
                    try:
                        import oss2
                        auth = oss2.Auth(self._access_key_id, self._access_key_secret)
                        oss_loc = getattr(trail, 'oss_bucket_location', None) or f"oss-{self.regions[0]}"
                        bucket = oss2.Bucket(auth, f"https://{oss_loc}.aliyuncs.com", oss_bucket)
                        acl = bucket.get_bucket_acl()
                        is_public = acl.acl in ("public-read", "public-read-write")
                    except Exception:
                        is_public = False
                    results.append(CheckResult(
                        check_id="ali_actiontrail_oss_not_public",
                        check_title="ActionTrail log OSS bucket is not publicly accessible",
                        service="actiontrail", severity="critical",
                        status="FAIL" if is_public else "PASS",
                        resource_id=oss_bucket, resource_name=oss_bucket,
                        status_extended=f"ActionTrail OSS bucket {oss_bucket} public: {is_public}",
                        remediation="Set the ActionTrail log delivery OSS bucket ACL to private",
                        remediation_url="https://www.alibabacloud.com/help/doc-detail/China/China",
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

            # ali_security_center_enabled — CIS 8.1 check if threat detection is active
            sc_active = False
            sc_version = None
            try:
                overview_req = sas_models.DescribeAlarmEventListRequest(
                    current_page=1, page_size=1,
                )
                overview_resp = client.describe_alarm_event_list(overview_req)
                sc_active = True
            except Exception:
                pass
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

            # ali_sas_advanced_edition — CIS 8.1 Security Center should be Advanced/Enterprise
            try:
                version_req = sas_models.DescribeVersionConfigRequest()
                version_resp = client.describe_version_config(version_req)
                sc_version = version_resp.body.version
                is_advanced = sc_version and int(sc_version) >= 3  # 3=Advanced, 5=Enterprise
            except Exception:
                is_advanced = False
            results.append(CheckResult(
                check_id="ali_sas_advanced_edition",
                check_title="Security Center is at least Advanced edition",
                service="security_center", severity="high",
                status="PASS" if is_advanced else "FAIL",
                resource_id="security-center-edition",
                status_extended=f"Security Center version: {sc_version or 'unknown'} (3=Advanced, 5=Enterprise)",
                remediation="Upgrade Security Center to Advanced or Enterprise edition for full threat detection",
                remediation_url="https://www.alibabacloud.com/help/doc-detail/42306.htm",
                compliance_frameworks=COMPLIANCE,
            ).to_dict())

            # ali_sas_agents_installed — CIS 8.2 all ECS instances have agent
            if sc_active:
                try:
                    agent_req = sas_models.DescribeCloudCenterInstancesRequest(
                        current_page=1, page_size=100,
                    )
                    agent_resp = client.describe_cloud_center_instances(agent_req)
                    total_instances = agent_resp.body.page_info.total_count or 0
                    online_count = 0
                    for inst in agent_resp.body.instances or []:
                        if inst.client_status == "online":
                            online_count += 1
                    all_online = online_count == total_instances and total_instances > 0
                    results.append(CheckResult(
                        check_id="ali_sas_agents_installed",
                        check_title="Security Center agents installed and online on all instances",
                        service="security_center", severity="high",
                        status="PASS" if all_online else "FAIL",
                        resource_id="security-center-agents",
                        status_extended=f"Agents online: {online_count}/{total_instances}",
                        remediation="Install and activate the Security Center agent on all ECS instances",
                        remediation_url="https://www.alibabacloud.com/help/doc-detail/68600.htm",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())
                except Exception:
                    pass

            # ali_sas_notification_enabled — CIS 8.5 notifications configured
            if sc_active:
                try:
                    notif_req = sas_models.DescribeNoticeConfigRequest()
                    notif_resp = client.describe_notice_config(notif_req)
                    configs = notif_resp.body.notice_config_list or []
                    has_notification = len(configs) > 0
                    results.append(CheckResult(
                        check_id="ali_sas_notification_enabled",
                        check_title="Security Center notification contacts are configured",
                        service="security_center", severity="medium",
                        status="PASS" if has_notification else "FAIL",
                        resource_id="security-center-notifications",
                        status_extended=f"Notification configs: {len(configs)}",
                        remediation="Configure notification contacts in Security Center for alerts on vulnerabilities and threats",
                        remediation_url="https://www.alibabacloud.com/help/doc-detail/China/China/China/China",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())
                except Exception:
                    pass

            # ali_sas_vuln_scan_enabled — CIS 8.7 vulnerability scanning
            if sc_active:
                try:
                    vuln_req = sas_models.DescribeGroupedVulRequest(
                        current_page=1, page_size=1, type="cve",
                    )
                    vuln_resp = client.describe_grouped_vul(vuln_req)
                    vuln_scan_active = vuln_resp.body.total_count is not None
                    results.append(CheckResult(
                        check_id="ali_sas_vuln_scan_enabled",
                        check_title="Security Center vulnerability scanning is active",
                        service="security_center", severity="medium",
                        status="PASS" if vuln_scan_active else "FAIL",
                        resource_id="security-center-vuln-scan",
                        status_extended=f"Vulnerability scanning active: {vuln_scan_active}",
                        remediation="Enable automatic vulnerability scanning in Security Center settings",
                        compliance_frameworks=COMPLIANCE,
                    ).to_dict())
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"Alibaba Security Center checks failed: {e}")
        return results

    # ── ACK (Container Service for Kubernetes) checks ─────────────────

    def _check_ack(self) -> list[dict]:
        """CIS Alibaba 2.0 Domain 7 — Kubernetes Engine (ACK) checks."""
        results = []
        try:
            from alibabacloud_cs20151215.client import Client as CsClient
            from alibabacloud_cs20151215 import models as cs_models
            from alibabacloud_tea_openapi.models import Config

            config = Config(
                access_key_id=self._access_key_id,
                access_key_secret=self._access_key_secret,
                endpoint="cs.aliyuncs.com",
            )
            client = CsClient(config)

            clusters_resp = client.describe_clusters_v1(cs_models.DescribeClustersV1Request(page_size=50))
            clusters = clusters_resp.body.clusters or []

            for cluster in clusters:
                cluster_id = cluster.cluster_id
                cluster_name = cluster.name or cluster_id
                cluster_type = cluster.cluster_type or ""
                region = cluster.region_id or self.regions[0]

                # ali_ack_log_service — CIS 7.1 logging to SLS enabled
                log_enabled = False
                try:
                    log_config = cluster.meta_data
                    if log_config:
                        import json as _json
                        meta = _json.loads(log_config) if isinstance(log_config, str) else log_config
                        log_enabled = bool(meta.get("Addons", {}).get("China", {}).get("China", False))
                except Exception:
                    pass
                # Check cluster tags/addons for log service
                try:
                    detail_resp = client.describe_cluster_detail(cluster_id)
                    detail = detail_resp.body
                    if hasattr(detail, 'meta_data') and detail.meta_data:
                        import json as _json
                        meta = _json.loads(detail.meta_data) if isinstance(detail.meta_data, str) else detail.meta_data
                        addons = meta.get("Addons") or []
                        for addon in addons:
                            if isinstance(addon, dict) and addon.get("name") in ("logtail-ds", "alibaba-log-controller"):
                                log_enabled = True
                                break
                except Exception:
                    pass
                results.append(CheckResult(
                    check_id="ali_ack_log_service",
                    check_title="ACK cluster has Log Service (SLS) integration enabled",
                    service="ack", severity="high", region=region,
                    status="PASS" if log_enabled else "FAIL",
                    resource_id=cluster_id, resource_name=cluster_name,
                    status_extended=f"ACK cluster {cluster_name} log service: {log_enabled}",
                    remediation="Enable Log Service (SLS) for ACK cluster to collect audit and container logs",
                    remediation_url="https://www.alibabacloud.com/help/doc-detail/China/China",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # ali_ack_cloud_monitor — CIS 7.2 cloud monitoring enabled
                monitoring_enabled = False
                try:
                    if hasattr(detail, 'meta_data') and detail.meta_data:
                        import json as _json
                        meta = _json.loads(detail.meta_data) if isinstance(detail.meta_data, str) else detail.meta_data
                        addons = meta.get("Addons") or []
                        for addon in addons:
                            if isinstance(addon, dict) and addon.get("name") in ("arms-prometheus", "metrics-server"):
                                monitoring_enabled = True
                                break
                except Exception:
                    pass
                results.append(CheckResult(
                    check_id="ali_ack_cloud_monitor",
                    check_title="ACK cluster has Cloud Monitor integration enabled",
                    service="ack", severity="medium", region=region,
                    status="PASS" if monitoring_enabled else "FAIL",
                    resource_id=cluster_id, resource_name=cluster_name,
                    status_extended=f"ACK cluster {cluster_name} cloud monitoring: {monitoring_enabled}",
                    remediation="Enable ARMS Prometheus or CloudMonitor agent for ACK cluster monitoring",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # ali_ack_rbac_enabled — CIS 7.3 RBAC authorization
                rbac_enabled = False
                try:
                    if hasattr(detail, 'parameters') and detail.parameters:
                        import json as _json
                        params = _json.loads(detail.parameters) if isinstance(detail.parameters, str) else detail.parameters
                        rbac_enabled = params.get("KubernetesVersion", "") >= "1.12"
                    # Managed clusters always have RBAC
                    if cluster_type in ("ManagedKubernetes", "Ask"):
                        rbac_enabled = True
                except Exception:
                    if cluster_type in ("ManagedKubernetes", "Ask"):
                        rbac_enabled = True
                results.append(CheckResult(
                    check_id="ali_ack_rbac_enabled",
                    check_title="ACK cluster has RBAC authorization enabled",
                    service="ack", severity="high", region=region,
                    status="PASS" if rbac_enabled else "FAIL",
                    resource_id=cluster_id, resource_name=cluster_name,
                    status_extended=f"ACK cluster {cluster_name} RBAC: {rbac_enabled}",
                    remediation="Enable RBAC for the ACK cluster (managed clusters have it by default)",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # ali_ack_no_basic_auth — CIS 7.6 no basic authentication
                basic_auth_disabled = True
                try:
                    if hasattr(detail, 'parameters') and detail.parameters:
                        import json as _json
                        params = _json.loads(detail.parameters) if isinstance(detail.parameters, str) else detail.parameters
                        if params.get("BasicAuth") or params.get("basic_auth"):
                            basic_auth_disabled = False
                    # Managed clusters >= 1.20 always disable basic auth
                    if cluster_type in ("ManagedKubernetes", "Ask"):
                        basic_auth_disabled = True
                except Exception:
                    pass
                results.append(CheckResult(
                    check_id="ali_ack_no_basic_auth",
                    check_title="ACK cluster does not use basic authentication",
                    service="ack", severity="high", region=region,
                    status="PASS" if basic_auth_disabled else "FAIL",
                    resource_id=cluster_id, resource_name=cluster_name,
                    status_extended=f"ACK cluster {cluster_name} basic auth disabled: {basic_auth_disabled}",
                    remediation="Disable basic authentication and use certificate-based authentication or OIDC",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # ali_ack_network_policy — CIS 7.7 network policy enabled (Terway/Calico)
                network_policy = False
                try:
                    network_type = getattr(detail, 'network_mode', '') or ''
                    if 'terway' in network_type.lower():
                        network_policy = True
                    if hasattr(detail, 'meta_data') and detail.meta_data:
                        import json as _json
                        meta = _json.loads(detail.meta_data) if isinstance(detail.meta_data, str) else detail.meta_data
                        addons = meta.get("Addons") or []
                        for addon in addons:
                            if isinstance(addon, dict) and addon.get("name") in ("terway-eniip", "calico"):
                                network_policy = True
                                break
                except Exception:
                    pass
                results.append(CheckResult(
                    check_id="ali_ack_network_policy",
                    check_title="ACK cluster has network policy plugin enabled (Terway/Calico)",
                    service="ack", severity="medium", region=region,
                    status="PASS" if network_policy else "FAIL",
                    resource_id=cluster_id, resource_name=cluster_name,
                    status_extended=f"ACK cluster {cluster_name} network policy: {network_policy}",
                    remediation="Enable Terway or Calico network policy plugin for pod-level network isolation",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

                # ali_ack_private_cluster — CIS 7.9 API server not public
                is_private = True
                try:
                    endpoint = getattr(detail, 'master_url', '') or ''
                    external_endpoint = getattr(detail, 'external_loadbalancer_id', '') or ''
                    if external_endpoint:
                        is_private = False
                    # Check if public access is explicitly enabled
                    maintenance_info = getattr(detail, 'maintenance_window', None)
                    api_public = getattr(detail, 'public_access_enabled', None)
                    if api_public is True:
                        is_private = False
                except Exception:
                    pass
                results.append(CheckResult(
                    check_id="ali_ack_private_cluster",
                    check_title="ACK cluster API server is not publicly accessible",
                    service="ack", severity="high", region=region,
                    status="PASS" if is_private else "FAIL",
                    resource_id=cluster_id, resource_name=cluster_name,
                    status_extended=f"ACK cluster {cluster_name} private: {is_private}",
                    remediation="Disable public access to the cluster API server and use internal endpoints or VPN",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

        except Exception as e:
            logger.warning(f"Alibaba ACK checks failed: {e}")
        return results

    # ── SLS / Log Monitoring checks ──────────────────────────────────

    def _check_sls(self) -> list[dict]:
        """CIS Alibaba 2.0 Domain 2 — Log Service monitoring and alerts."""
        results = []
        try:
            from alibabacloud_sls20201230.client import Client as SlsClient
            from alibabacloud_sls20201230 import models as sls_models
            from alibabacloud_tea_openapi.models import Config

            config = Config(
                access_key_id=self._access_key_id,
                access_key_secret=self._access_key_secret,
                endpoint=f"{self.regions[0]}.log.aliyuncs.com",
            )
            client = SlsClient(config)

            # Collect all projects and their alert configs
            projects = []
            try:
                proj_resp = client.list_project(sls_models.ListProjectRequest(size=100))
                projects = proj_resp.body.projects or []
            except Exception:
                pass

            has_any_alert = False
            alert_categories_found = set()

            # Map CIS 2.0 monitoring controls to expected log alert categories
            ALERT_CATEGORIES = {
                "unauthorized_api": "ali_sls_alert_unauthorized_api",       # CIS 2.10
                "console_no_mfa": "ali_sls_alert_console_no_mfa",           # CIS 2.11
                "root_usage": "ali_sls_alert_root_usage",                   # CIS 2.12
                "ram_policy_change": "ali_sls_alert_ram_policy_change",     # CIS 2.13
                "iam_change": "ali_sls_alert_iam_change",                   # CIS 2.14
                "vpc_change": "ali_sls_alert_vpc_change",                   # CIS 2.15
                "route_table_change": "ali_sls_alert_route_change",         # CIS 2.16
                "security_group_change": "ali_sls_alert_sg_change",         # CIS 2.17
                "nacl_change": "ali_sls_alert_nacl_change",                 # CIS 2.18
                "slb_change": "ali_sls_alert_slb_change",                   # CIS 2.19
                "rds_change": "ali_sls_alert_rds_change",                   # CIS 2.20
                "oss_policy_change": "ali_sls_alert_oss_change",            # CIS 2.21
                "actiontrail_change": "ali_sls_alert_actiontrail_change",   # CIS 2.22
            }

            for project in projects:
                project_name = project.project_name if hasattr(project, 'project_name') else str(project)
                try:
                    alert_resp = client.list_alerts(project_name, sls_models.ListAlertsRequest(size=100))
                    alerts = alert_resp.body.results or []
                    if alerts:
                        has_any_alert = True
                    for alert in alerts:
                        alert_name = (getattr(alert, 'name', '') or '').lower()
                        alert_query = (getattr(alert, 'display_name', '') or '').lower()
                        combined = f"{alert_name} {alert_query}"
                        # Heuristic matching of alerts to CIS categories
                        if "unauthorized" in combined or "accessdenied" in combined:
                            alert_categories_found.add("unauthorized_api")
                        if "mfa" in combined or "nomfa" in combined:
                            alert_categories_found.add("console_no_mfa")
                        if "root" in combined:
                            alert_categories_found.add("root_usage")
                        if "policy" in combined and ("ram" in combined or "iam" in combined):
                            alert_categories_found.add("ram_policy_change")
                        if "iam" in combined or ("ram" in combined and "change" in combined):
                            alert_categories_found.add("iam_change")
                        if "vpc" in combined:
                            alert_categories_found.add("vpc_change")
                        if "route" in combined:
                            alert_categories_found.add("route_table_change")
                        if "security" in combined and "group" in combined:
                            alert_categories_found.add("security_group_change")
                        if "nacl" in combined or "acl" in combined:
                            alert_categories_found.add("nacl_change")
                        if "slb" in combined or "loadbalancer" in combined:
                            alert_categories_found.add("slb_change")
                        if "rds" in combined or "database" in combined:
                            alert_categories_found.add("rds_change")
                        if "oss" in combined or "bucket" in combined:
                            alert_categories_found.add("oss_policy_change")
                        if "actiontrail" in combined or "trail" in combined:
                            alert_categories_found.add("actiontrail_change")
                except Exception:
                    pass

                # CIS 2.23 — Log retention >= 365 days
                try:
                    logstores_resp = client.list_logstore(project_name, sls_models.ListLogstoreRequest(size=100))
                    for ls in logstores_resp.body.logstores or []:
                        ls_name = ls if isinstance(ls, str) else getattr(ls, 'logstore_name', str(ls))
                        try:
                            ls_detail = client.get_logstore(project_name, ls_name)
                            ttl = getattr(ls_detail.body, 'ttl', 0) or 0
                            results.append(CheckResult(
                                check_id="ali_sls_retention_365",
                                check_title="SLS log store retention is at least 365 days",
                                service="sls", severity="medium",
                                status="PASS" if ttl >= 365 else "FAIL",
                                resource_id=f"{project_name}/{ls_name}",
                                resource_name=ls_name,
                                status_extended=f"Log store {ls_name} TTL: {ttl} days",
                                remediation="Set log store retention (TTL) to at least 365 days",
                                compliance_frameworks=COMPLIANCE,
                            ).to_dict())
                        except Exception:
                            pass
                except Exception:
                    pass

            # Emit a result for each CIS 2.10-2.22 monitoring alert category
            for cat_key, check_id in ALERT_CATEGORIES.items():
                found = cat_key in alert_categories_found
                friendly_name = cat_key.replace("_", " ")
                results.append(CheckResult(
                    check_id=check_id,
                    check_title=f"Log monitoring alert exists for {friendly_name}",
                    service="sls", severity="medium",
                    status="PASS" if found else "FAIL",
                    resource_id=f"sls-alert-{cat_key}",
                    status_extended=f"Log alert for {friendly_name}: {'configured' if found else 'not found'}",
                    remediation=f"Create a log alert in SLS to detect {friendly_name} events from ActionTrail logs",
                    compliance_frameworks=COMPLIANCE,
                ).to_dict())

        except Exception as e:
            logger.warning(f"Alibaba SLS checks failed: {e}")
        return results

    # ------------------------------------------------------------------
    # CIS benchmark coverage
    # ------------------------------------------------------------------

    def _emit_cis_coverage(self, existing_results: list[dict]) -> list[dict]:
        """Emit MANUAL results for CIS controls not covered by automated checks."""
        covered_cis_ids: set[str] = set()
        check_to_cis = {}
        for ctrl in ALIBABA_CIS_CONTROLS:
            cis_id = ctrl["cis_id"]
            check_to_cis[f"ali_cis_{cis_id.replace('.', '_')}"] = cis_id

        for result in existing_results:
            check_id = result.get("check_id", "")
            if check_id in check_to_cis:
                covered_cis_ids.add(check_to_cis[check_id])

        manual_results = []
        fw = ["CIS-Alibaba-2.0", "NIST-800-53", "CCM-4.1"]

        for ctrl in ALIBABA_CIS_CONTROLS:
            cis_id = ctrl["cis_id"]
            title = ctrl["title"]
            level = ctrl["cis_level"]
            assessment_type = ctrl["assessment_type"]
            severity = ctrl["severity"]
            service_area = ctrl["service_area"]
            if cis_id not in covered_cis_ids:
                manual_results.append(CheckResult(
                    check_id=f"ali_cis_{cis_id.replace('.', '_')}",
                    check_title=f"{title} (CIS {cis_id})",
                    service=service_area,
                    severity=severity,
                    status="MANUAL",
                    resource_id="alibaba-account",
                    status_extended=(
                        f"CIS {cis_id} [{level}] - {assessment_type.upper()} assessment. "
                        f"This control requires {'manual verification' if assessment_type == 'manual' else 'automated check implementation'}."
                    ),
                    remediation=ctrl.get("remediation", f"Refer to CIS Alibaba Cloud Foundation Benchmark v2.0.0, control {cis_id}."),
                    compliance_frameworks=fw,
                    assessment_type=assessment_type,
                    cis_control_id=cis_id,
                    cis_level=level,
                ).to_dict())

        return manual_results

    def run_all_checks(self) -> list[dict]:
        """Run all Alibaba Cloud security checks including complete CIS benchmark coverage."""
        results = self.scan()
        results.extend(self._emit_cis_coverage(results))
        return results
