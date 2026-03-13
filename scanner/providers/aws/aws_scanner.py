"""AWS Security Scanner.

Implements security checks for AWS services following CIS, NIST, and other frameworks.
"""
import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from scanner.providers.base_check import CheckResult

logger = logging.getLogger(__name__)


class AWSScanner:
    """AWS cloud security scanner with comprehensive service checks."""

    def __init__(self, credentials: dict, regions: Optional[list] = None, services: Optional[list] = None):
        self.credentials = credentials
        self.regions = regions or ["us-east-1"]
        self.services = services
        self._session = None

    def _get_session(self) -> boto3.Session:
        if not self._session:
            self._session = boto3.Session(
                aws_access_key_id=self.credentials.get("access_key_id"),
                aws_secret_access_key=self.credentials.get("secret_access_key"),
                aws_session_token=self.credentials.get("session_token"),
                region_name=self.regions[0] if self.regions else "us-east-1",
            )
        return self._session

    def scan(self) -> list[dict]:
        """Run all AWS security checks."""
        results = []
        check_methods = {
            "iam": self._check_iam,
            "s3": self._check_s3,
            "ec2": self._check_ec2,
            "rds": self._check_rds,
            "cloudtrail": self._check_cloudtrail,
            "kms": self._check_kms,
            "vpc": self._check_vpc,
            "lambda": self._check_lambda,
            "ecs": self._check_ecs,
            "guardduty": self._check_guardduty,
            "config": self._check_config,
            "sns": self._check_sns,
            "sqs": self._check_sqs,
            "secretsmanager": self._check_secretsmanager,
            "elasticsearch": self._check_elasticsearch,
            "cloudwatch": self._check_cloudwatch,
            "dynamodb": self._check_dynamodb,
            "efs": self._check_efs,
            "eks": self._check_eks,
            "elasticache": self._check_elasticache,
        }

        for service_name, check_fn in check_methods.items():
            if self.services and service_name not in self.services:
                continue
            try:
                service_results = check_fn()
                results.extend(service_results)
            except (ClientError, NoCredentialsError) as e:
                logger.warning(f"AWS {service_name} check failed: {e}")
            except Exception as e:
                logger.error(f"Unexpected error in AWS {service_name}: {e}")

        return results

    def _check_iam(self) -> list[dict]:
        """IAM security checks."""
        results = []
        session = self._get_session()
        iam = session.client("iam")

        try:
            # Check root account MFA
            summary = iam.get_account_summary()["SummaryMap"]
            mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
            results.append(CheckResult(
                check_id="iam_root_mfa_enabled",
                check_title="Root account has MFA enabled",
                service="iam",
                severity="critical",
                status="PASS" if mfa_enabled else "FAIL",
                resource_id="root",
                resource_name="Root Account",
                status_extended="Root account MFA is enabled" if mfa_enabled else "Root account does not have MFA enabled",
                remediation="Enable MFA for the root account using a hardware or virtual MFA device",
                compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-3.2.1"],
            ).to_dict())

            # Check password policy
            try:
                policy = iam.get_account_password_policy()["PasswordPolicy"]
                min_length = policy.get("MinimumPasswordLength", 0)
                has_uppercase = policy.get("RequireUppercaseCharacters", False)
                has_lowercase = policy.get("RequireLowercaseCharacters", False)
                has_numbers = policy.get("RequireNumbers", False)
                has_symbols = policy.get("RequireSymbols", False)
                max_age = policy.get("MaxPasswordAge", 0)

                strong = min_length >= 14 and has_uppercase and has_lowercase and has_numbers and has_symbols
                results.append(CheckResult(
                    check_id="iam_password_policy_strong",
                    check_title="IAM password policy requires strong passwords",
                    service="iam",
                    severity="medium",
                    status="PASS" if strong else "FAIL",
                    resource_id="password-policy",
                    status_extended=f"Password min length: {min_length}, requirements met: {strong}",
                    remediation="Set minimum password length to 14 and require uppercase, lowercase, numbers, and symbols",
                    compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53"],
                ).to_dict())

                has_rotation = 0 < max_age <= 90
                results.append(CheckResult(
                    check_id="iam_password_policy_rotation",
                    check_title="IAM password policy enforces rotation within 90 days",
                    service="iam",
                    severity="medium",
                    status="PASS" if has_rotation else "FAIL",
                    resource_id="password-policy",
                    status_extended=f"Max password age: {max_age} days",
                    remediation="Set password rotation to 90 days or less",
                    compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53"],
                ).to_dict())
            except ClientError:
                results.append(CheckResult(
                    check_id="iam_password_policy_exists",
                    check_title="IAM password policy is configured",
                    service="iam",
                    severity="medium",
                    status="FAIL",
                    resource_id="password-policy",
                    status_extended="No custom password policy configured",
                    remediation="Create an IAM password policy with strong requirements",
                    compliance_frameworks=["CIS-AWS-1.5"],
                ).to_dict())

            # Check users for MFA and access key rotation
            users = iam.list_users()["Users"]
            for user in users:
                username = user["UserName"]

                mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
                results.append(CheckResult(
                    check_id="iam_user_mfa_enabled",
                    check_title="IAM user has MFA enabled",
                    service="iam",
                    severity="high",
                    status="PASS" if mfa_devices else "FAIL",
                    resource_id=user["Arn"],
                    resource_name=username,
                    status_extended=f"User {username} {'has' if mfa_devices else 'does not have'} MFA enabled",
                    remediation="Enable MFA for the IAM user",
                    compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-3.2.1"],
                ).to_dict())

                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                for key in keys:
                    from datetime import datetime, timezone
                    key_age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                    results.append(CheckResult(
                        check_id="iam_access_key_rotation",
                        check_title="IAM access key is rotated within 90 days",
                        service="iam",
                        severity="medium",
                        status="PASS" if key_age <= 90 else "FAIL",
                        resource_id=key["AccessKeyId"],
                        resource_name=f"{username}/{key['AccessKeyId']}",
                        status_extended=f"Access key is {key_age} days old",
                        remediation="Rotate access keys every 90 days",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53"],
                    ).to_dict())

        except Exception as e:
            logger.warning(f"IAM checks partial failure: {e}")

        return results

    def _check_s3(self) -> list[dict]:
        """S3 bucket security checks."""
        results = []
        session = self._get_session()
        s3 = session.client("s3")

        try:
            buckets = s3.list_buckets()["Buckets"]
            for bucket in buckets:
                name = bucket["Name"]

                # Public access block
                try:
                    pub_access = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                    all_blocked = all([
                        pub_access.get("BlockPublicAcls", False),
                        pub_access.get("IgnorePublicAcls", False),
                        pub_access.get("BlockPublicPolicy", False),
                        pub_access.get("RestrictPublicBuckets", False),
                    ])
                    results.append(CheckResult(
                        check_id="s3_bucket_public_access_blocked",
                        check_title="S3 bucket has public access blocked",
                        service="s3",
                        severity="high",
                        status="PASS" if all_blocked else "FAIL",
                        resource_id=f"arn:aws:s3:::{name}",
                        resource_name=name,
                        status_extended=f"Bucket {name} public access {'is fully blocked' if all_blocked else 'is not fully blocked'}",
                        remediation="Enable all public access block settings for the bucket",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-3.2.1"],
                    ).to_dict())
                except ClientError:
                    results.append(CheckResult(
                        check_id="s3_bucket_public_access_blocked",
                        check_title="S3 bucket has public access blocked",
                        service="s3", severity="high", status="FAIL",
                        resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                        status_extended=f"Bucket {name} has no public access block configured",
                        remediation="Enable public access block for the bucket",
                        compliance_frameworks=["CIS-AWS-1.5"],
                    ).to_dict())

                # Encryption
                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                    results.append(CheckResult(
                        check_id="s3_bucket_encryption_enabled",
                        check_title="S3 bucket has default encryption enabled",
                        service="s3", severity="medium", status="PASS",
                        resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                        status_extended=f"Bucket {name} has default encryption enabled",
                        remediation="Enable default encryption for the bucket",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "HIPAA"],
                    ).to_dict())
                except ClientError:
                    results.append(CheckResult(
                        check_id="s3_bucket_encryption_enabled",
                        check_title="S3 bucket has default encryption enabled",
                        service="s3", severity="medium", status="FAIL",
                        resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                        status_extended=f"Bucket {name} does not have default encryption",
                        remediation="Enable default AES-256 or KMS encryption for the bucket",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "HIPAA"],
                    ).to_dict())

                # Versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=name)
                    enabled = versioning.get("Status") == "Enabled"
                    results.append(CheckResult(
                        check_id="s3_bucket_versioning_enabled",
                        check_title="S3 bucket has versioning enabled",
                        service="s3", severity="low",
                        status="PASS" if enabled else "FAIL",
                        resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                        status_extended=f"Bucket {name} versioning is {'enabled' if enabled else 'not enabled'}",
                        remediation="Enable versioning on the bucket for data protection",
                        compliance_frameworks=["NIST-800-53", "SOC2"],
                    ).to_dict())
                except ClientError:
                    pass

                # Logging
                try:
                    logging_config = s3.get_bucket_logging(Bucket=name)
                    has_logging = "LoggingEnabled" in logging_config
                    results.append(CheckResult(
                        check_id="s3_bucket_logging_enabled",
                        check_title="S3 bucket has access logging enabled",
                        service="s3", severity="medium",
                        status="PASS" if has_logging else "FAIL",
                        resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                        status_extended=f"Bucket {name} logging is {'enabled' if has_logging else 'not enabled'}",
                        remediation="Enable server access logging for the bucket",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-3.2.1"],
                    ).to_dict())
                except ClientError:
                    pass

        except Exception as e:
            logger.warning(f"S3 checks failed: {e}")

        return results

    def _check_ec2(self) -> list[dict]:
        """EC2 security checks."""
        results = []
        session = self._get_session()

        for region in self.regions:
            ec2 = session.client("ec2", region_name=region)
            try:
                # Security groups
                sgs = ec2.describe_security_groups()["SecurityGroups"]
                for sg in sgs:
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", "")

                    for perm in sg.get("IpPermissions", []):
                        for ip_range in perm.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                port = perm.get("FromPort", "all")
                                if port in (22, 3389, "all"):
                                    results.append(CheckResult(
                                        check_id=f"ec2_sg_open_port_{port}",
                                        check_title=f"Security group allows unrestricted access to port {port}",
                                        service="ec2", severity="high" if port != "all" else "critical",
                                        status="FAIL", region=region,
                                        resource_id=sg_id, resource_name=sg_name,
                                        status_extended=f"Security group {sg_name} ({sg_id}) allows 0.0.0.0/0 on port {port}",
                                        remediation=f"Restrict port {port} access to specific IP ranges",
                                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-3.2.1"],
                                    ).to_dict())

                # EBS encryption
                volumes = ec2.describe_volumes()["Volumes"]
                for vol in volumes:
                    encrypted = vol.get("Encrypted", False)
                    results.append(CheckResult(
                        check_id="ec2_ebs_volume_encrypted",
                        check_title="EBS volume is encrypted",
                        service="ec2", severity="medium",
                        status="PASS" if encrypted else "FAIL",
                        region=region,
                        resource_id=vol["VolumeId"],
                        status_extended=f"Volume {vol['VolumeId']} is {'encrypted' if encrypted else 'not encrypted'}",
                        remediation="Enable encryption for EBS volumes",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "HIPAA"],
                    ).to_dict())

                # IMDSv2
                instances = ec2.describe_instances()
                for reservation in instances["Reservations"]:
                    for instance in reservation["Instances"]:
                        inst_id = instance["InstanceId"]
                        metadata_opts = instance.get("MetadataOptions", {})
                        http_tokens = metadata_opts.get("HttpTokens", "optional")
                        imdsv2 = http_tokens == "required"
                        results.append(CheckResult(
                            check_id="ec2_imdsv2_required",
                            check_title="EC2 instance requires IMDSv2",
                            service="ec2", severity="high",
                            status="PASS" if imdsv2 else "FAIL",
                            region=region, resource_id=inst_id,
                            status_extended=f"Instance {inst_id} IMDSv2 is {'required' if imdsv2 else 'not required'}",
                            remediation="Configure instance to require IMDSv2 (HttpTokens=required)",
                            compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53"],
                        ).to_dict())

            except Exception as e:
                logger.warning(f"EC2 checks in {region} failed: {e}")

        return results

    def _check_rds(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            rds = session.client("rds", region_name=region)
            try:
                instances = rds.describe_db_instances()["DBInstances"]
                for db in instances:
                    db_id = db["DBInstanceIdentifier"]

                    results.append(CheckResult(
                        check_id="rds_encryption_enabled",
                        check_title="RDS instance has encryption enabled",
                        service="rds", severity="high",
                        status="PASS" if db.get("StorageEncrypted") else "FAIL",
                        region=region, resource_id=db.get("DBInstanceArn", db_id), resource_name=db_id,
                        status_extended=f"RDS instance {db_id} encryption: {db.get('StorageEncrypted')}",
                        remediation="Enable encryption at rest for the RDS instance",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "HIPAA", "PCI-DSS-3.2.1"],
                    ).to_dict())

                    results.append(CheckResult(
                        check_id="rds_public_access_disabled",
                        check_title="RDS instance is not publicly accessible",
                        service="rds", severity="critical",
                        status="PASS" if not db.get("PubliclyAccessible") else "FAIL",
                        region=region, resource_id=db.get("DBInstanceArn", db_id), resource_name=db_id,
                        status_extended=f"RDS instance {db_id} public access: {db.get('PubliclyAccessible')}",
                        remediation="Disable public accessibility for the RDS instance",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-3.2.1"],
                    ).to_dict())

                    results.append(CheckResult(
                        check_id="rds_multi_az_enabled",
                        check_title="RDS instance has Multi-AZ enabled",
                        service="rds", severity="medium",
                        status="PASS" if db.get("MultiAZ") else "FAIL",
                        region=region, resource_id=db.get("DBInstanceArn", db_id), resource_name=db_id,
                        status_extended=f"RDS instance {db_id} Multi-AZ: {db.get('MultiAZ')}",
                        remediation="Enable Multi-AZ for high availability",
                        compliance_frameworks=["NIST-800-53", "SOC2"],
                    ).to_dict())

                    backup_days = db.get("BackupRetentionPeriod", 0)
                    results.append(CheckResult(
                        check_id="rds_backup_enabled",
                        check_title="RDS instance has automated backups enabled",
                        service="rds", severity="medium",
                        status="PASS" if backup_days >= 7 else "FAIL",
                        region=region, resource_id=db.get("DBInstanceArn", db_id), resource_name=db_id,
                        status_extended=f"RDS instance {db_id} backup retention: {backup_days} days",
                        remediation="Set backup retention period to at least 7 days",
                        compliance_frameworks=["NIST-800-53", "SOC2", "HIPAA"],
                    ).to_dict())

            except Exception as e:
                logger.warning(f"RDS checks in {region} failed: {e}")
        return results

    def _check_cloudtrail(self) -> list[dict]:
        results = []
        session = self._get_session()
        ct = session.client("cloudtrail")
        try:
            trails = ct.describe_trails()["trailList"]
            if not trails:
                results.append(CheckResult(
                    check_id="cloudtrail_enabled",
                    check_title="CloudTrail is enabled",
                    service="cloudtrail", severity="critical", status="FAIL",
                    resource_id="cloudtrail",
                    status_extended="No CloudTrail trails configured",
                    remediation="Enable CloudTrail with a multi-region trail",
                    compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-3.2.1", "HIPAA", "SOC2"],
                ).to_dict())
            else:
                for trail in trails:
                    trail_name = trail["Name"]
                    trail_arn = trail.get("TrailARN", trail_name)
                    is_multi = trail.get("IsMultiRegionTrail", False)
                    has_log_validation = trail.get("LogFileValidationEnabled", False)
                    is_encrypted = trail.get("KmsKeyId") is not None

                    results.append(CheckResult(
                        check_id="cloudtrail_multiregion",
                        check_title="CloudTrail is multi-region",
                        service="cloudtrail", severity="high",
                        status="PASS" if is_multi else "FAIL",
                        resource_id=trail_arn, resource_name=trail_name,
                        status_extended=f"Trail {trail_name} multi-region: {is_multi}",
                        remediation="Enable multi-region for the CloudTrail trail",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53"],
                    ).to_dict())

                    results.append(CheckResult(
                        check_id="cloudtrail_log_validation",
                        check_title="CloudTrail log file validation is enabled",
                        service="cloudtrail", severity="medium",
                        status="PASS" if has_log_validation else "FAIL",
                        resource_id=trail_arn, resource_name=trail_name,
                        status_extended=f"Trail {trail_name} log validation: {has_log_validation}",
                        remediation="Enable log file validation for the CloudTrail trail",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-3.2.1"],
                    ).to_dict())

                    results.append(CheckResult(
                        check_id="cloudtrail_encrypted",
                        check_title="CloudTrail logs are encrypted with KMS",
                        service="cloudtrail", severity="medium",
                        status="PASS" if is_encrypted else "FAIL",
                        resource_id=trail_arn, resource_name=trail_name,
                        status_extended=f"Trail {trail_name} KMS encryption: {is_encrypted}",
                        remediation="Enable KMS encryption for CloudTrail logs",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "HIPAA"],
                    ).to_dict())

        except Exception as e:
            logger.warning(f"CloudTrail checks failed: {e}")
        return results

    def _check_kms(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            kms = session.client("kms", region_name=region)
            try:
                keys = kms.list_keys()["Keys"]
                for key_meta in keys:
                    key_id = key_meta["KeyId"]
                    try:
                        key_info = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                        if key_info.get("KeyManager") != "CUSTOMER":
                            continue
                        rotation = kms.get_key_rotation_status(KeyId=key_id)
                        results.append(CheckResult(
                            check_id="kms_key_rotation_enabled",
                            check_title="KMS key rotation is enabled",
                            service="kms", severity="medium",
                            status="PASS" if rotation.get("KeyRotationEnabled") else "FAIL",
                            region=region, resource_id=key_info.get("Arn", key_id),
                            status_extended=f"KMS key {key_id} rotation: {rotation.get('KeyRotationEnabled')}",
                            remediation="Enable automatic key rotation for the KMS key",
                            compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-3.2.1"],
                        ).to_dict())
                    except ClientError:
                        pass
            except Exception as e:
                logger.warning(f"KMS checks in {region} failed: {e}")
        return results

    def _check_vpc(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            ec2 = session.client("ec2", region_name=region)
            try:
                vpcs = ec2.describe_vpcs()["Vpcs"]
                for vpc in vpcs:
                    vpc_id = vpc["VpcId"]

                    flow_logs = ec2.describe_flow_logs(
                        Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                    )["FlowLogs"]
                    results.append(CheckResult(
                        check_id="vpc_flow_logs_enabled",
                        check_title="VPC flow logs are enabled",
                        service="vpc", severity="medium",
                        status="PASS" if flow_logs else "FAIL",
                        region=region, resource_id=vpc_id,
                        status_extended=f"VPC {vpc_id} has {len(flow_logs)} flow log(s)",
                        remediation="Enable VPC flow logs for network monitoring",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-3.2.1"],
                    ).to_dict())

            except Exception as e:
                logger.warning(f"VPC checks in {region} failed: {e}")
        return results

    def _check_lambda(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            lmb = session.client("lambda", region_name=region)
            try:
                functions = lmb.list_functions()["Functions"]
                for fn in functions:
                    fn_name = fn["FunctionName"]
                    fn_arn = fn["FunctionArn"]

                    # Check runtime deprecation
                    runtime = fn.get("Runtime", "")
                    deprecated_runtimes = ["python2.7", "python3.6", "nodejs10.x", "nodejs12.x", "ruby2.5", "java8", "dotnetcore2.1"]
                    results.append(CheckResult(
                        check_id="lambda_runtime_supported",
                        check_title="Lambda function uses supported runtime",
                        service="lambda", severity="medium",
                        status="FAIL" if runtime in deprecated_runtimes else "PASS",
                        region=region, resource_id=fn_arn, resource_name=fn_name,
                        status_extended=f"Lambda {fn_name} uses runtime {runtime}",
                        remediation="Update Lambda function to use a supported runtime version",
                        compliance_frameworks=["NIST-800-53"],
                    ).to_dict())

                    # Check VPC configuration
                    has_vpc = bool(fn.get("VpcConfig", {}).get("SubnetIds"))
                    results.append(CheckResult(
                        check_id="lambda_vpc_configured",
                        check_title="Lambda function runs in VPC",
                        service="lambda", severity="low",
                        status="PASS" if has_vpc else "FAIL",
                        region=region, resource_id=fn_arn, resource_name=fn_name,
                        status_extended=f"Lambda {fn_name} {'is' if has_vpc else 'is not'} deployed in a VPC",
                        remediation="Configure Lambda to run within a VPC for network isolation",
                        compliance_frameworks=["NIST-800-53"],
                    ).to_dict())

            except Exception as e:
                logger.warning(f"Lambda checks in {region} failed: {e}")
        return results

    def _check_ecs(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            ecs = session.client("ecs", region_name=region)
            try:
                clusters = ecs.list_clusters()["clusterArns"]
                for cluster_arn in clusters:
                    cluster_info = ecs.describe_clusters(clusters=[cluster_arn], include=["SETTINGS"])["clusters"]
                    if cluster_info:
                        cluster = cluster_info[0]
                        settings = {s["name"]: s["value"] for s in cluster.get("settings", [])}
                        container_insights = settings.get("containerInsights") == "enabled"
                        results.append(CheckResult(
                            check_id="ecs_cluster_container_insights",
                            check_title="ECS cluster has Container Insights enabled",
                            service="ecs", severity="low",
                            status="PASS" if container_insights else "FAIL",
                            region=region, resource_id=cluster_arn,
                            resource_name=cluster.get("clusterName"),
                            status_extended=f"Container Insights: {'enabled' if container_insights else 'disabled'}",
                            remediation="Enable Container Insights for ECS monitoring",
                            compliance_frameworks=["NIST-800-53"],
                        ).to_dict())
            except Exception as e:
                logger.warning(f"ECS checks in {region} failed: {e}")
        return results

    def _check_guardduty(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            gd = session.client("guardduty", region_name=region)
            try:
                detectors = gd.list_detectors()["DetectorIds"]
                results.append(CheckResult(
                    check_id="guardduty_enabled",
                    check_title="GuardDuty is enabled",
                    service="guardduty", severity="high",
                    status="PASS" if detectors else "FAIL",
                    region=region, resource_id="guardduty",
                    status_extended=f"GuardDuty {'is enabled' if detectors else 'is not enabled'} in {region}",
                    remediation="Enable Amazon GuardDuty for threat detection",
                    compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-3.2.1"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"GuardDuty checks in {region} failed: {e}")
        return results

    def _check_config(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            config = session.client("config", region_name=region)
            try:
                recorders = config.describe_configuration_recorders()["ConfigurationRecorders"]
                results.append(CheckResult(
                    check_id="config_recorder_enabled",
                    check_title="AWS Config recorder is enabled",
                    service="config", severity="medium",
                    status="PASS" if recorders else "FAIL",
                    region=region, resource_id="config-recorder",
                    status_extended=f"Config recorder {'is' if recorders else 'is not'} enabled in {region}",
                    remediation="Enable AWS Config recorder to track resource changes",
                    compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Config checks in {region} failed: {e}")
        return results

    def _check_sns(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            sns = session.client("sns", region_name=region)
            try:
                topics = sns.list_topics().get("Topics", [])
                for topic in topics:
                    arn = topic["TopicArn"]
                    attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
                    encrypted = attrs.get("KmsMasterKeyId") is not None
                    results.append(CheckResult(
                        check_id="sns_topic_encrypted",
                        check_title="SNS topic is encrypted",
                        service="sns", severity="medium",
                        status="PASS" if encrypted else "FAIL",
                        region=region, resource_id=arn,
                        status_extended=f"SNS topic {arn.split(':')[-1]} encryption: {encrypted}",
                        remediation="Enable server-side encryption for the SNS topic",
                        compliance_frameworks=["NIST-800-53", "HIPAA"],
                    ).to_dict())
            except Exception as e:
                logger.warning(f"SNS checks in {region} failed: {e}")
        return results

    def _check_sqs(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            sqs = session.client("sqs", region_name=region)
            try:
                queues = sqs.list_queues().get("QueueUrls", [])
                for queue_url in queues:
                    attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])["Attributes"]
                    encrypted = attrs.get("KmsMasterKeyId") is not None or attrs.get("SqsManagedSseEnabled") == "true"
                    results.append(CheckResult(
                        check_id="sqs_queue_encrypted",
                        check_title="SQS queue is encrypted",
                        service="sqs", severity="medium",
                        status="PASS" if encrypted else "FAIL",
                        region=region, resource_id=attrs.get("QueueArn", queue_url),
                        status_extended=f"SQS queue encryption: {encrypted}",
                        remediation="Enable server-side encryption for the SQS queue",
                        compliance_frameworks=["NIST-800-53", "HIPAA"],
                    ).to_dict())
            except Exception as e:
                logger.warning(f"SQS checks in {region} failed: {e}")
        return results

    def _check_secretsmanager(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            sm = session.client("secretsmanager", region_name=region)
            try:
                secrets = sm.list_secrets().get("SecretList", [])
                for secret in secrets:
                    name = secret["Name"]
                    arn = secret["ARN"]
                    rotation_enabled = secret.get("RotationEnabled", False)
                    results.append(CheckResult(
                        check_id="secretsmanager_rotation_enabled",
                        check_title="Secrets Manager secret has rotation enabled",
                        service="secretsmanager", severity="medium",
                        status="PASS" if rotation_enabled else "FAIL",
                        region=region, resource_id=arn, resource_name=name,
                        status_extended=f"Secret {name} rotation: {rotation_enabled}",
                        remediation="Enable automatic rotation for the secret",
                        compliance_frameworks=["NIST-800-53", "SOC2"],
                    ).to_dict())
            except Exception as e:
                logger.warning(f"SecretsManager checks in {region} failed: {e}")
        return results

    def _check_elasticsearch(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            es = session.client("es", region_name=region)
            try:
                domains = es.list_domain_names().get("DomainNames", [])
                for domain in domains:
                    name = domain["DomainName"]
                    config = es.describe_elasticsearch_domain(DomainName=name)["DomainStatus"]
                    encrypted = config.get("EncryptionAtRestOptions", {}).get("Enabled", False)
                    node_to_node = config.get("NodeToNodeEncryptionOptions", {}).get("Enabled", False)

                    results.append(CheckResult(
                        check_id="es_encryption_at_rest",
                        check_title="Elasticsearch domain has encryption at rest",
                        service="elasticsearch", severity="high",
                        status="PASS" if encrypted else "FAIL",
                        region=region, resource_id=config.get("ARN", name), resource_name=name,
                        status_extended=f"ES domain {name} encryption at rest: {encrypted}",
                        remediation="Enable encryption at rest for the Elasticsearch domain",
                        compliance_frameworks=["NIST-800-53", "HIPAA", "PCI-DSS-3.2.1"],
                    ).to_dict())

                    results.append(CheckResult(
                        check_id="es_node_to_node_encryption",
                        check_title="Elasticsearch domain has node-to-node encryption",
                        service="elasticsearch", severity="medium",
                        status="PASS" if node_to_node else "FAIL",
                        region=region, resource_id=config.get("ARN", name), resource_name=name,
                        status_extended=f"ES domain {name} node-to-node encryption: {node_to_node}",
                        remediation="Enable node-to-node encryption for the Elasticsearch domain",
                        compliance_frameworks=["NIST-800-53", "HIPAA"],
                    ).to_dict())
            except Exception as e:
                logger.warning(f"Elasticsearch checks in {region} failed: {e}")
        return results

    def _check_cloudwatch(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            cw = session.client("cloudwatch", region_name=region)
            logs = session.client("logs", region_name=region)
            try:
                log_groups = logs.describe_log_groups().get("logGroups", [])
                for lg in log_groups:
                    name = lg["logGroupName"]
                    encrypted = lg.get("kmsKeyId") is not None
                    retention = lg.get("retentionInDays")

                    results.append(CheckResult(
                        check_id="cloudwatch_log_group_encrypted",
                        check_title="CloudWatch log group is encrypted",
                        service="cloudwatch", severity="medium",
                        status="PASS" if encrypted else "FAIL",
                        region=region, resource_id=lg.get("arn", name), resource_name=name,
                        status_extended=f"Log group {name} encryption: {encrypted}",
                        remediation="Enable KMS encryption for the CloudWatch log group",
                        compliance_frameworks=["NIST-800-53", "HIPAA"],
                    ).to_dict())

                    results.append(CheckResult(
                        check_id="cloudwatch_log_group_retention",
                        check_title="CloudWatch log group has retention policy",
                        service="cloudwatch", severity="low",
                        status="PASS" if retention else "FAIL",
                        region=region, resource_id=lg.get("arn", name), resource_name=name,
                        status_extended=f"Log group {name} retention: {retention or 'never expires'} days",
                        remediation="Set a retention policy for the log group",
                        compliance_frameworks=["NIST-800-53", "SOC2"],
                    ).to_dict())
            except Exception as e:
                logger.warning(f"CloudWatch checks in {region} failed: {e}")
        return results

    def _check_dynamodb(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            ddb = session.client("dynamodb", region_name=region)
            try:
                tables = ddb.list_tables().get("TableNames", [])
                for table_name in tables:
                    table = ddb.describe_table(TableName=table_name)["Table"]
                    sse = table.get("SSEDescription", {})
                    encrypted = sse.get("Status") == "ENABLED"
                    pitr = ddb.describe_continuous_backups(TableName=table_name)
                    pitr_enabled = pitr.get("ContinuousBackupsDescription", {}).get(
                        "PointInTimeRecoveryDescription", {}
                    ).get("PointInTimeRecoveryStatus") == "ENABLED"

                    results.append(CheckResult(
                        check_id="dynamodb_table_encrypted_kms",
                        check_title="DynamoDB table is encrypted with KMS",
                        service="dynamodb", severity="medium",
                        status="PASS" if encrypted else "FAIL",
                        region=region, resource_id=table.get("TableArn", table_name), resource_name=table_name,
                        status_extended=f"DynamoDB table {table_name} KMS encryption: {encrypted}",
                        remediation="Enable KMS encryption for the DynamoDB table",
                        compliance_frameworks=["NIST-800-53", "HIPAA"],
                    ).to_dict())

                    results.append(CheckResult(
                        check_id="dynamodb_pitr_enabled",
                        check_title="DynamoDB table has PITR enabled",
                        service="dynamodb", severity="medium",
                        status="PASS" if pitr_enabled else "FAIL",
                        region=region, resource_id=table.get("TableArn", table_name), resource_name=table_name,
                        status_extended=f"DynamoDB table {table_name} PITR: {pitr_enabled}",
                        remediation="Enable Point-in-Time Recovery for the DynamoDB table",
                        compliance_frameworks=["NIST-800-53", "SOC2"],
                    ).to_dict())
            except Exception as e:
                logger.warning(f"DynamoDB checks in {region} failed: {e}")
        return results

    def _check_efs(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            efs = session.client("efs", region_name=region)
            try:
                filesystems = efs.describe_file_systems().get("FileSystems", [])
                for fs in filesystems:
                    fs_id = fs["FileSystemId"]
                    encrypted = fs.get("Encrypted", False)
                    results.append(CheckResult(
                        check_id="efs_encryption_enabled",
                        check_title="EFS file system is encrypted",
                        service="efs", severity="high",
                        status="PASS" if encrypted else "FAIL",
                        region=region, resource_id=fs_id,
                        status_extended=f"EFS {fs_id} encryption: {encrypted}",
                        remediation="Enable encryption at rest for the EFS file system",
                        compliance_frameworks=["NIST-800-53", "HIPAA"],
                    ).to_dict())
            except Exception as e:
                logger.warning(f"EFS checks in {region} failed: {e}")
        return results

    def _check_eks(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            eks = session.client("eks", region_name=region)
            try:
                clusters = eks.list_clusters().get("clusters", [])
                for cluster_name in clusters:
                    cluster = eks.describe_cluster(name=cluster_name)["cluster"]
                    arn = cluster["arn"]

                    logging_config = cluster.get("logging", {}).get("clusterLogging", [])
                    api_logging = any(
                        lt.get("enabled") for lt in logging_config
                        if "api" in lt.get("types", [])
                    )
                    results.append(CheckResult(
                        check_id="eks_cluster_logging",
                        check_title="EKS cluster has API logging enabled",
                        service="eks", severity="medium",
                        status="PASS" if api_logging else "FAIL",
                        region=region, resource_id=arn, resource_name=cluster_name,
                        status_extended=f"EKS cluster {cluster_name} API logging: {api_logging}",
                        remediation="Enable control plane logging for the EKS cluster",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53"],
                    ).to_dict())

                    public_access = cluster.get("resourcesVpcConfig", {}).get("endpointPublicAccess", True)
                    results.append(CheckResult(
                        check_id="eks_endpoint_public_access",
                        check_title="EKS cluster endpoint is not publicly accessible",
                        service="eks", severity="high",
                        status="FAIL" if public_access else "PASS",
                        region=region, resource_id=arn, resource_name=cluster_name,
                        status_extended=f"EKS cluster {cluster_name} public endpoint: {public_access}",
                        remediation="Disable public endpoint access for the EKS cluster",
                        compliance_frameworks=["CIS-AWS-1.5", "NIST-800-53"],
                    ).to_dict())
            except Exception as e:
                logger.warning(f"EKS checks in {region} failed: {e}")
        return results

    def _check_elasticache(self) -> list[dict]:
        results = []
        session = self._get_session()
        for region in self.regions:
            ec = session.client("elasticache", region_name=region)
            try:
                clusters = ec.describe_cache_clusters().get("CacheClusters", [])
                for cluster in clusters:
                    cluster_id = cluster["CacheClusterId"]
                    encrypted_transit = cluster.get("TransitEncryptionEnabled", False)
                    encrypted_rest = cluster.get("AtRestEncryptionEnabled", False)

                    results.append(CheckResult(
                        check_id="elasticache_encryption_transit",
                        check_title="ElastiCache cluster has encryption in transit",
                        service="elasticache", severity="high",
                        status="PASS" if encrypted_transit else "FAIL",
                        region=region, resource_id=cluster.get("ARN", cluster_id), resource_name=cluster_id,
                        status_extended=f"ElastiCache {cluster_id} transit encryption: {encrypted_transit}",
                        remediation="Enable encryption in transit for ElastiCache",
                        compliance_frameworks=["NIST-800-53", "HIPAA", "PCI-DSS-3.2.1"],
                    ).to_dict())

                    results.append(CheckResult(
                        check_id="elasticache_encryption_rest",
                        check_title="ElastiCache cluster has encryption at rest",
                        service="elasticache", severity="high",
                        status="PASS" if encrypted_rest else "FAIL",
                        region=region, resource_id=cluster.get("ARN", cluster_id), resource_name=cluster_id,
                        status_extended=f"ElastiCache {cluster_id} at-rest encryption: {encrypted_rest}",
                        remediation="Enable encryption at rest for ElastiCache",
                        compliance_frameworks=["NIST-800-53", "HIPAA"],
                    ).to_dict())
            except Exception as e:
                logger.warning(f"ElastiCache checks in {region} failed: {e}")
        return results
