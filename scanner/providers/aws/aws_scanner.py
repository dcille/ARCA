"""AWS Security Scanner — comprehensive CIS/NIST/CCM-aligned checks.

Implements 80+ security checks across AWS services following CIS AWS Foundations
Benchmark v3.0, NIST 800-53, SOC 2, and CSA CCM v4.1 frameworks.

Provides complete CIS AWS Foundations Benchmark v3.0 coverage: automated checks
emit PASS/FAIL results, while uncovered controls are emitted as MANUAL results
requiring human review.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from scanner.cis_controls.aws_cis_controls import AWS_CIS_CONTROLS
from scanner.providers.base_check import CheckResult

logger = logging.getLogger(__name__)


class AWSScanner:
    """AWS cloud security scanner with comprehensive service checks and complete CIS coverage."""

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
            "redshift": self._check_redshift,
            "ecr": self._check_ecr,
            "cloudfront": self._check_cloudfront,
            "waf": self._check_waf,
            "ssm": self._check_ssm,
            "backup": self._check_backup,
            "acm": self._check_acm,
            "apigateway": self._check_apigateway,
            "macie": self._check_macie,
            "securityhub": self._check_securityhub,
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

                # CIS 2.8: Password reuse prevention
                reuse_prevention = policy.get("PasswordReusePrevention", 0)
                reuse_ok = reuse_prevention >= 24
                results.append(CheckResult(
                    check_id="iam_password_policy_reuse_prevention",
                    check_title="IAM password policy prevents password reuse (24 or more)",
                    service="iam",
                    severity="medium",
                    status="PASS" if reuse_ok else "FAIL",
                    resource_id="password-policy",
                    status_extended=f"Password reuse prevention: {reuse_prevention} (requires >= 24)",
                    remediation="Set password reuse prevention to 24 or greater: aws iam update-account-password-policy --password-reuse-prevention 24",
                    compliance_frameworks=["CIS-AWS-6.0", "NIST-800-53"],
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

                # Check for inline policies on user
                inline_policies = iam.list_user_policies(UserName=username)["PolicyNames"]
                results.append(CheckResult(
                    check_id="iam_user_no_inline_policies",
                    check_title="IAM user does not have inline policies",
                    service="iam",
                    severity="medium",
                    status="PASS" if not inline_policies else "FAIL",
                    resource_id=user["Arn"],
                    resource_name=username,
                    status_extended=f"User {username} has {len(inline_policies)} inline policy(ies)" if inline_policies else f"User {username} has no inline policies",
                    remediation="Move inline policies to managed policies for better governance",
                    compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                ).to_dict())

                # Check for unused credentials (45 days)
                try:
                    cred_report_user = None
                    try:
                        iam.generate_credential_report()
                    except ClientError:
                        pass
                    report = iam.get_credential_report()
                    import csv
                    import io
                    reader = csv.DictReader(io.StringIO(report["Content"].decode("utf-8")))
                    for row in reader:
                        if row["user"] == username:
                            cred_report_user = row
                            break
                    if cred_report_user:
                        last_used = cred_report_user.get("password_last_used", "N/A")
                        unused = False
                        if last_used not in ("N/A", "no_information", "not_supported"):
                            last_used_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00").replace("+00:00", "+00:00"))
                            days_since = (datetime.now(timezone.utc) - last_used_dt).days
                            unused = days_since > 45
                        results.append(CheckResult(
                            check_id="iam_user_unused_credentials_45days",
                            check_title="IAM user credentials used within last 45 days",
                            service="iam",
                            severity="medium",
                            status="FAIL" if unused else "PASS",
                            resource_id=user["Arn"],
                            resource_name=username,
                            status_extended=f"User {username} last used password: {last_used}",
                            remediation="Remove or deactivate credentials not used in the last 45 days",
                            compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                        ).to_dict())
                except (ClientError, Exception):
                    pass

                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                for key in keys:
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

                # CIS 2.12: Only one active access key per user
                active_keys = [k for k in keys if k.get("Status") == "Active"]
                results.append(CheckResult(
                    check_id="iam_user_single_active_access_key",
                    check_title="IAM user has at most one active access key",
                    service="iam",
                    severity="medium",
                    status="PASS" if len(active_keys) <= 1 else "FAIL",
                    resource_id=user["Arn"],
                    resource_name=username,
                    status_extended=f"User {username} has {len(active_keys)} active access key(s)",
                    remediation="Deactivate or delete extra access keys so only one remains active per user",
                    compliance_frameworks=["CIS-AWS-6.0", "NIST-800-53"],
                ).to_dict())

                # CIS 2.14: Check user also has no directly attached managed policies
                attached_user_policies = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
                results.append(CheckResult(
                    check_id="iam_user_no_attached_policies",
                    check_title="IAM user receives permissions only through groups",
                    service="iam",
                    severity="medium",
                    status="PASS" if not inline_policies and not attached_user_policies else "FAIL",
                    resource_id=user["Arn"],
                    resource_name=username,
                    status_extended=f"User {username} has {len(inline_policies)} inline and {len(attached_user_policies)} attached policy(ies)",
                    remediation="Remove all inline and directly attached policies; grant permissions only through IAM groups",
                    compliance_frameworks=["CIS-AWS-6.0", "NIST-800-53"],
                ).to_dict())

            # Check root account has no access keys
            root_access_keys = summary.get("AccountAccessKeysPresent", 0)
            results.append(CheckResult(
                check_id="iam_no_root_access_key",
                check_title="Root account has no access keys",
                service="iam",
                severity="critical",
                status="PASS" if root_access_keys == 0 else "FAIL",
                resource_id="root",
                resource_name="Root Account",
                status_extended=f"Root account has {root_access_keys} access key(s)" if root_access_keys else "Root account has no access keys",
                remediation="Delete all access keys for the root account",
                compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
            ).to_dict())

            # Check IAM groups for inline policies
            try:
                groups = iam.list_groups()["Groups"]
                for group in groups:
                    group_name = group["GroupName"]
                    group_inline = iam.list_group_policies(GroupName=group_name)["PolicyNames"]
                    results.append(CheckResult(
                        check_id="iam_group_no_inline_policies",
                        check_title="IAM group does not have inline policies",
                        service="iam",
                        severity="medium",
                        status="PASS" if not group_inline else "FAIL",
                        resource_id=group["Arn"],
                        resource_name=group_name,
                        status_extended=f"Group {group_name} has {len(group_inline)} inline policy(ies)" if group_inline else f"Group {group_name} has no inline policies",
                        remediation="Move inline policies to managed policies for better governance",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                    ).to_dict())
            except ClientError:
                pass

            # Check for policies with full admin (*:*) access
            try:
                policies = iam.list_policies(Scope="Local", OnlyAttached=True)["Policies"]
                for pol in policies:
                    pol_arn = pol["Arn"]
                    pol_name = pol["PolicyName"]
                    version = iam.get_policy_version(
                        PolicyArn=pol_arn,
                        VersionId=pol["DefaultVersionId"]
                    )["PolicyVersion"]
                    import urllib.parse
                    doc = version["Document"]
                    if isinstance(doc, str):
                        doc = json.loads(urllib.parse.unquote(doc))
                    statements = doc.get("Statement", [])
                    has_star = False
                    for stmt in statements:
                        if stmt.get("Effect") == "Allow":
                            actions = stmt.get("Action", [])
                            resources = stmt.get("Resource", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            if "*" in actions and "*" in resources:
                                has_star = True
                                break
                    results.append(CheckResult(
                        check_id="iam_no_star_policies",
                        check_title="IAM policy does not allow full *:* admin access",
                        service="iam",
                        severity="high",
                        status="FAIL" if has_star else "PASS",
                        resource_id=pol_arn,
                        resource_name=pol_name,
                        status_extended=f"Policy {pol_name} {'grants' if has_star else 'does not grant'} full admin (*:*) access",
                        remediation="Restrict IAM policies to only the permissions needed (least privilege)",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                    ).to_dict())
            except ClientError:
                pass

            # Check for AWS Support role
            try:
                support_role_found = False
                attached_policies = iam.list_policies(Scope="AWS", OnlyAttached=True)["Policies"]
                for pol in attached_policies:
                    if pol["PolicyName"] == "AWSSupportAccess":
                        support_role_found = True
                        break
                results.append(CheckResult(
                    check_id="iam_support_role_created",
                    check_title="IAM Support role has been created for AWS Support access",
                    service="iam",
                    severity="medium",
                    status="PASS" if support_role_found else "FAIL",
                    resource_id="support-role",
                    resource_name="AWSSupportAccess",
                    status_extended="AWSSupportAccess policy is attached to a role" if support_role_found else "No role with AWSSupportAccess policy found",
                    remediation="Create an IAM role with the AWSSupportAccess managed policy attached",
                    compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                ).to_dict())
            except ClientError:
                pass

            # CIS 2.21: Ensure AWSCloudShellFullAccess is not attached to any entity
            try:
                cloudshell_arn = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
                cs_entities = iam.list_entities_for_policy(PolicyArn=cloudshell_arn)
                cs_roles = cs_entities.get("PolicyRoles", [])
                cs_users = cs_entities.get("PolicyUsers", [])
                cs_groups = cs_entities.get("PolicyGroups", [])
                cs_attached = bool(cs_roles or cs_users or cs_groups)
                results.append(CheckResult(
                    check_id="iam_cloudshell_fullaccess_restricted",
                    check_title="AWSCloudShellFullAccess policy is not attached to any entity",
                    service="iam",
                    severity="medium",
                    status="FAIL" if cs_attached else "PASS",
                    resource_id="AWSCloudShellFullAccess",
                    status_extended=f"AWSCloudShellFullAccess attached to {len(cs_roles)} role(s), {len(cs_users)} user(s), {len(cs_groups)} group(s)" if cs_attached else "AWSCloudShellFullAccess is not attached to any entity",
                    remediation="Detach AWSCloudShellFullAccess and use a more restrictive custom policy that denies file transfer",
                    compliance_frameworks=["CIS-AWS-6.0"],
                ).to_dict())
            except ClientError:
                pass

            # Check for expiring SSL/TLS certificates
            try:
                server_certs = iam.list_server_certificates()["ServerCertificateMetadataList"]
                for cert in server_certs:
                    cert_name = cert["ServerCertificateName"]
                    expiry = cert["Expiration"]
                    days_until = (expiry - datetime.now(timezone.utc)).days
                    results.append(CheckResult(
                        check_id="iam_ssl_certificate_expiry",
                        check_title="IAM SSL/TLS certificate is not expired or expiring soon",
                        service="iam",
                        severity="high",
                        status="PASS" if days_until > 30 else "FAIL",
                        resource_id=cert.get("Arn", cert_name),
                        resource_name=cert_name,
                        status_extended=f"Certificate {cert_name} expires in {days_until} days",
                        remediation="Rotate or replace the SSL/TLS certificate before expiry",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                    ).to_dict())
            except ClientError:
                pass

            # Check IAM Access Analyzer is enabled
            try:
                aa = session.client("accessanalyzer")
                analyzers = aa.list_analyzers(type="ACCOUNT")["analyzers"]
                results.append(CheckResult(
                    check_id="iam_access_analyzer_enabled",
                    check_title="IAM Access Analyzer is enabled",
                    service="iam",
                    severity="medium",
                    status="PASS" if analyzers else "FAIL",
                    resource_id="access-analyzer",
                    status_extended=f"IAM Access Analyzer {'is' if analyzers else 'is not'} enabled",
                    remediation="Enable IAM Access Analyzer to identify unintended resource access",
                    compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                ).to_dict())
            except ClientError:
                pass

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

                # SSL/TLS required (bucket policy with aws:SecureTransport)
                try:
                    policy_str = s3.get_bucket_policy(Bucket=name)["Policy"]
                    policy_doc = json.loads(policy_str)
                    ssl_required = False
                    for stmt in policy_doc.get("Statement", []):
                        condition = stmt.get("Condition", {})
                        if (stmt.get("Effect") == "Deny" and
                                condition.get("Bool", {}).get("aws:SecureTransport") == "false"):
                            ssl_required = True
                            break
                    results.append(CheckResult(
                        check_id="s3_bucket_ssl_required",
                        check_title="S3 bucket requires SSL/TLS for data transfer",
                        service="s3", severity="medium",
                        status="PASS" if ssl_required else "FAIL",
                        resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                        status_extended=f"Bucket {name} {'enforces' if ssl_required else 'does not enforce'} SSL-only access",
                        remediation="Add a bucket policy denying requests where aws:SecureTransport is false",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                    ).to_dict())
                except ClientError:
                    results.append(CheckResult(
                        check_id="s3_bucket_ssl_required",
                        check_title="S3 bucket requires SSL/TLS for data transfer",
                        service="s3", severity="medium", status="FAIL",
                        resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                        status_extended=f"Bucket {name} has no bucket policy enforcing SSL",
                        remediation="Add a bucket policy denying requests where aws:SecureTransport is false",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                    ).to_dict())

                # MFA Delete
                try:
                    versioning = s3.get_bucket_versioning(Bucket=name)
                    mfa_delete = versioning.get("MFADelete") == "Enabled"
                    results.append(CheckResult(
                        check_id="s3_bucket_mfa_delete",
                        check_title="S3 bucket has MFA Delete enabled",
                        service="s3", severity="medium",
                        status="PASS" if mfa_delete else "FAIL",
                        resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                        status_extended=f"Bucket {name} MFA Delete is {'enabled' if mfa_delete else 'not enabled'}",
                        remediation="Enable MFA Delete on the bucket to protect against accidental deletions",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                    ).to_dict())
                except ClientError:
                    pass

                # Object Lock
                try:
                    lock_config = s3.get_object_lock_configuration(Bucket=name)
                    lock_enabled = lock_config.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled"
                    results.append(CheckResult(
                        check_id="s3_bucket_object_lock",
                        check_title="S3 bucket has Object Lock enabled",
                        service="s3", severity="low",
                        status="PASS" if lock_enabled else "FAIL",
                        resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                        status_extended=f"Bucket {name} Object Lock is {'enabled' if lock_enabled else 'not enabled'}",
                        remediation="Enable Object Lock on the bucket for WORM protection",
                        compliance_frameworks=["NIST-800-53", "SOC2", "CCM-4.1"],
                    ).to_dict())
                except ClientError:
                    results.append(CheckResult(
                        check_id="s3_bucket_object_lock",
                        check_title="S3 bucket has Object Lock enabled",
                        service="s3", severity="low", status="FAIL",
                        resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                        status_extended=f"Bucket {name} does not have Object Lock configured",
                        remediation="Enable Object Lock on the bucket for WORM protection",
                        compliance_frameworks=["NIST-800-53", "SOC2", "CCM-4.1"],
                    ).to_dict())

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

                # CIS 6.4: Check IPv6 unrestricted access on remote admin ports
                for sg in sgs:
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", "")
                    for perm in sg.get("IpPermissions", []):
                        for ipv6_range in perm.get("Ipv6Ranges", []):
                            if ipv6_range.get("CidrIpv6") == "::/0":
                                port = perm.get("FromPort", "all")
                                if port in (22, 3389, "all") or perm.get("IpProtocol") == "-1":
                                    results.append(CheckResult(
                                        check_id="ec2_sg_no_ipv6_wide_open",
                                        check_title=f"Security group does not allow ::/0 on remote admin port {port}",
                                        service="ec2", severity="high",
                                        status="FAIL", region=region,
                                        resource_id=sg_id, resource_name=sg_name,
                                        status_extended=f"SG {sg_name} ({sg_id}) allows ::/0 on port {port}",
                                        remediation=f"Restrict IPv6 access on port {port} to specific CIDR ranges",
                                        compliance_frameworks=["CIS-AWS-6.0", "NIST-800-53"],
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

                # Default security group should have no inbound/outbound rules
                for sg in sgs:
                    if sg.get("GroupName") == "default":
                        has_ingress = bool(sg.get("IpPermissions", []))
                        has_egress = bool(sg.get("IpPermissionsEgress", []))
                        has_rules = has_ingress or has_egress
                        results.append(CheckResult(
                            check_id="ec2_default_sg_no_traffic",
                            check_title="Default security group restricts all traffic",
                            service="ec2", severity="high",
                            status="FAIL" if has_rules else "PASS",
                            region=region, resource_id=sg["GroupId"], resource_name="default",
                            status_extended=f"Default SG {sg['GroupId']} {'has' if has_rules else 'has no'} inbound/outbound rules",
                            remediation="Remove all inbound and outbound rules from the default security group",
                            compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                        ).to_dict())

                # Check for security groups with wide-open port ranges
                for sg in sgs:
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", "")
                    for perm in sg.get("IpPermissions", []):
                        for ip_range in perm.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                from_port = perm.get("FromPort", 0)
                                to_port = perm.get("ToPort", 65535)
                                if to_port - from_port > 100:
                                    results.append(CheckResult(
                                        check_id="ec2_sg_no_wide_open_ports",
                                        check_title="Security group does not allow wide port ranges to 0.0.0.0/0",
                                        service="ec2", severity="high",
                                        status="FAIL", region=region,
                                        resource_id=sg_id, resource_name=sg_name,
                                        status_extended=f"SG {sg_name} ({sg_id}) allows 0.0.0.0/0 on ports {from_port}-{to_port}",
                                        remediation="Restrict port ranges in security group rules to only required ports",
                                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                                    ).to_dict())

                # EBS default encryption
                try:
                    ebs_enc = ec2.get_ebs_encryption_by_default()
                    default_enc = ebs_enc.get("EbsEncryptionByDefault", False)
                    results.append(CheckResult(
                        check_id="ec2_ebs_default_encryption",
                        check_title="EBS default encryption is enabled",
                        service="ec2", severity="medium",
                        status="PASS" if default_enc else "FAIL",
                        region=region, resource_id="ebs-default-encryption",
                        status_extended=f"EBS default encryption is {'enabled' if default_enc else 'not enabled'} in {region}",
                        remediation="Enable EBS default encryption in the EC2 settings",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                    ).to_dict())
                except ClientError:
                    pass

                # EC2 instances with public IP
                for reservation in instances["Reservations"]:
                    for instance in reservation["Instances"]:
                        inst_id = instance["InstanceId"]
                        public_ip = instance.get("PublicIpAddress")
                        results.append(CheckResult(
                            check_id="ec2_instance_no_public_ip",
                            check_title="EC2 instance does not have a public IP address",
                            service="ec2", severity="medium",
                            status="FAIL" if public_ip else "PASS",
                            region=region, resource_id=inst_id,
                            status_extended=f"Instance {inst_id} {'has public IP ' + str(public_ip) if public_ip else 'has no public IP'}",
                            remediation="Use private subnets and NAT gateways instead of assigning public IPs to instances",
                            compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
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

                    # Auto minor version upgrade
                    auto_upgrade = db.get("AutoMinorVersionUpgrade", False)
                    results.append(CheckResult(
                        check_id="rds_auto_minor_upgrade",
                        check_title="RDS instance has auto minor version upgrade enabled",
                        service="rds", severity="low",
                        status="PASS" if auto_upgrade else "FAIL",
                        region=region, resource_id=db.get("DBInstanceArn", db_id), resource_name=db_id,
                        status_extended=f"RDS instance {db_id} auto minor upgrade: {auto_upgrade}",
                        remediation="Enable auto minor version upgrade for the RDS instance",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                    ).to_dict())

                    # Deletion protection
                    deletion_protection = db.get("DeletionProtection", False)
                    results.append(CheckResult(
                        check_id="rds_deletion_protection",
                        check_title="RDS instance has deletion protection enabled",
                        service="rds", severity="medium",
                        status="PASS" if deletion_protection else "FAIL",
                        region=region, resource_id=db.get("DBInstanceArn", db_id), resource_name=db_id,
                        status_extended=f"RDS instance {db_id} deletion protection: {deletion_protection}",
                        remediation="Enable deletion protection for the RDS instance",
                        compliance_frameworks=["NIST-800-53", "SOC2", "CCM-4.1"],
                    ).to_dict())

                    # IAM authentication
                    iam_auth = db.get("IAMDatabaseAuthenticationEnabled", False)
                    results.append(CheckResult(
                        check_id="rds_iam_auth_enabled",
                        check_title="RDS instance has IAM authentication enabled",
                        service="rds", severity="medium",
                        status="PASS" if iam_auth else "FAIL",
                        region=region, resource_id=db.get("DBInstanceArn", db_id), resource_name=db_id,
                        status_extended=f"RDS instance {db_id} IAM auth: {iam_auth}",
                        remediation="Enable IAM database authentication for the RDS instance",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
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

                    # Check S3 bucket logging for CloudTrail bucket
                    s3_bucket = trail.get("S3BucketName")
                    if s3_bucket:
                        try:
                            s3_client = session.client("s3")
                            logging_config = s3_client.get_bucket_logging(Bucket=s3_bucket)
                            has_logging = "LoggingEnabled" in logging_config
                            results.append(CheckResult(
                                check_id="cloudtrail_s3_bucket_logging",
                                check_title="CloudTrail S3 bucket has access logging enabled",
                                service="cloudtrail", severity="medium",
                                status="PASS" if has_logging else "FAIL",
                                resource_id=trail_arn, resource_name=trail_name,
                                status_extended=f"Trail {trail_name} S3 bucket {s3_bucket} logging: {'enabled' if has_logging else 'disabled'}",
                                remediation="Enable server access logging on the S3 bucket used by CloudTrail",
                                compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                            ).to_dict())
                        except ClientError:
                            pass

                    # CIS 4.8/4.9: Check object-level logging for S3
                    try:
                        event_selectors = ct.get_event_selectors(TrailName=trail_arn)
                        has_write_events = False
                        has_read_events = False

                        # Check advanced event selectors first
                        adv_selectors = event_selectors.get("AdvancedEventSelectors", [])
                        if adv_selectors:
                            for sel in adv_selectors:
                                fields = {f["Field"]: f.get("Equals", []) for f in sel.get("FieldSelectors", [])}
                                if "eventCategory" in fields and "Data" in fields.get("eventCategory", []):
                                    res_type = fields.get("resources.type", [])
                                    if "AWS::S3::Object" in res_type:
                                        read_only = fields.get("readOnly", [])
                                        if not read_only:
                                            has_write_events = True
                                            has_read_events = True
                                        elif "false" in read_only:
                                            has_write_events = True
                                        elif "true" in read_only:
                                            has_read_events = True

                        # Check basic event selectors
                        basic_selectors = event_selectors.get("EventSelectors", [])
                        for sel in basic_selectors:
                            for dr in sel.get("DataResources", []):
                                if dr.get("Type") == "AWS::S3::Object":
                                    rw_type = sel.get("ReadWriteType", "All")
                                    if rw_type in ("WriteOnly", "All"):
                                        has_write_events = True
                                    if rw_type in ("ReadOnly", "All"):
                                        has_read_events = True

                        results.append(CheckResult(
                            check_id="cloudtrail_s3_object_write_events",
                            check_title="CloudTrail logs S3 object-level write events",
                            service="cloudtrail", severity="medium",
                            status="PASS" if has_write_events else "FAIL",
                            resource_id=trail_arn, resource_name=trail_name,
                            status_extended=f"Trail {trail_name} S3 write data events: {'enabled' if has_write_events else 'disabled'}",
                            remediation="Enable S3 data event logging for write events on the CloudTrail trail",
                            compliance_frameworks=["CIS-AWS-6.0", "NIST-800-53"],
                        ).to_dict())

                        results.append(CheckResult(
                            check_id="cloudtrail_s3_object_read_events",
                            check_title="CloudTrail logs S3 object-level read events",
                            service="cloudtrail", severity="medium",
                            status="PASS" if has_read_events else "FAIL",
                            resource_id=trail_arn, resource_name=trail_name,
                            status_extended=f"Trail {trail_name} S3 read data events: {'enabled' if has_read_events else 'disabled'}",
                            remediation="Enable S3 data event logging for read events on the CloudTrail trail",
                            compliance_frameworks=["CIS-AWS-6.0", "NIST-800-53"],
                        ).to_dict())
                    except ClientError:
                        pass

                    # Check CloudWatch Logs integration
                    cw_log_group = trail.get("CloudWatchLogsLogGroupArn")
                    results.append(CheckResult(
                        check_id="cloudtrail_integrated_cloudwatch",
                        check_title="CloudTrail is integrated with CloudWatch Logs",
                        service="cloudtrail", severity="medium",
                        status="PASS" if cw_log_group else "FAIL",
                        resource_id=trail_arn, resource_name=trail_name,
                        status_extended=f"Trail {trail_name} {'is' if cw_log_group else 'is not'} integrated with CloudWatch Logs",
                        remediation="Configure CloudTrail to send logs to a CloudWatch Logs log group",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
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

                # Default security group restricts all traffic
                try:
                    sgs = ec2.describe_security_groups(
                        Filters=[
                            {"Name": "vpc-id", "Values": [vpc_id]},
                            {"Name": "group-name", "Values": ["default"]},
                        ]
                    )["SecurityGroups"]
                    for sg in sgs:
                        has_ingress = bool(sg.get("IpPermissions", []))
                        has_egress = len(sg.get("IpPermissionsEgress", [])) > 0
                        unrestricted = has_ingress or has_egress
                        results.append(CheckResult(
                            check_id="vpc_default_sg_restricts_all",
                            check_title="VPC default security group restricts all traffic",
                            service="vpc", severity="high",
                            status="FAIL" if unrestricted else "PASS",
                            region=region, resource_id=sg["GroupId"],
                            status_extended=f"VPC {vpc_id} default SG {sg['GroupId']} {'allows' if unrestricted else 'restricts all'} traffic",
                            remediation="Remove all inbound and outbound rules from the VPC default security group",
                            compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                        ).to_dict())
                except ClientError:
                    pass

                # Check NACLs for unrestricted access
                try:
                    nacls = ec2.describe_network_acls(
                        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
                    )["NetworkAcls"]
                    for nacl in nacls:
                        nacl_id = nacl["NetworkAclId"]
                        for entry in nacl.get("Entries", []):
                            if (entry.get("RuleAction") == "allow" and
                                    entry.get("CidrBlock") == "0.0.0.0/0" and
                                    entry.get("Protocol") == "-1" and
                                    not entry.get("Egress", False) and
                                    entry.get("RuleNumber", 0) != 32767):
                                results.append(CheckResult(
                                    check_id="vpc_no_unrestricted_nacl",
                                    check_title="VPC NACL does not allow unrestricted inbound traffic",
                                    service="vpc", severity="medium",
                                    status="FAIL",
                                    region=region, resource_id=nacl_id,
                                    status_extended=f"NACL {nacl_id} in VPC {vpc_id} allows all inbound traffic from 0.0.0.0/0",
                                    remediation="Restrict NACL rules to only allow required traffic",
                                    compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                                ).to_dict())
                except ClientError:
                    pass

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

                    # Check environment variables for potential secrets
                    env_vars = fn.get("Environment", {}).get("Variables", {})
                    secret_keywords = ["password", "secret", "key", "token", "api_key", "apikey"]
                    has_secrets = any(
                        any(kw in k.lower() for kw in secret_keywords)
                        for k in env_vars
                    )
                    results.append(CheckResult(
                        check_id="lambda_env_no_secrets",
                        check_title="Lambda function environment variables do not contain secrets",
                        service="lambda", severity="high",
                        status="FAIL" if has_secrets else "PASS",
                        region=region, resource_id=fn_arn, resource_name=fn_name,
                        status_extended=f"Lambda {fn_name} {'may contain secrets in environment variables' if has_secrets else 'has no obvious secrets in environment variables'}",
                        remediation="Use AWS Secrets Manager or SSM Parameter Store instead of environment variables for secrets",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
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

                    # Check for public access via policy
                    policy_str = attrs.get("Policy", "{}")
                    policy_doc = json.loads(policy_str)
                    is_public = False
                    for stmt in policy_doc.get("Statement", []):
                        principal = stmt.get("Principal", {})
                        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                            condition = stmt.get("Condition", {})
                            if not condition and stmt.get("Effect") == "Allow":
                                is_public = True
                                break
                    results.append(CheckResult(
                        check_id="sns_topic_no_public_access",
                        check_title="SNS topic does not allow public access",
                        service="sns", severity="high",
                        status="FAIL" if is_public else "PASS",
                        region=region, resource_id=arn,
                        status_extended=f"SNS topic {arn.split(':')[-1]} {'has' if is_public else 'does not have'} public access",
                        remediation="Restrict the SNS topic policy to only allow access from specific AWS accounts or services",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
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

                    # Check secrets encryption
                    enc_config = cluster.get("encryptionConfig", [])
                    secrets_encrypted = any(
                        "secrets" in cfg.get("resources", [])
                        for cfg in enc_config
                    )
                    results.append(CheckResult(
                        check_id="eks_secrets_encrypted",
                        check_title="EKS cluster has secrets encryption enabled",
                        service="eks", severity="high",
                        status="PASS" if secrets_encrypted else "FAIL",
                        region=region, resource_id=arn, resource_name=cluster_name,
                        status_extended=f"EKS cluster {cluster_name} secrets encryption: {secrets_encrypted}",
                        remediation="Enable envelope encryption for Kubernetes secrets using a KMS key",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
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

    def _check_redshift(self) -> list[dict]:
        """Redshift security checks."""
        results = []
        session = self._get_session()
        for region in self.regions:
            rs = session.client("redshift", region_name=region)
            try:
                clusters = rs.describe_clusters().get("Clusters", [])
                for cluster in clusters:
                    cluster_id = cluster["ClusterIdentifier"]
                    cluster_arn = f"arn:aws:redshift:{region}:{cluster.get('ClusterNamespaceArn', '').split(':')[4] if cluster.get('ClusterNamespaceArn') else 'unknown'}:cluster:{cluster_id}"

                    # Encryption
                    encrypted = cluster.get("Encrypted", False)
                    results.append(CheckResult(
                        check_id="redshift_cluster_encrypted",
                        check_title="Redshift cluster is encrypted at rest",
                        service="redshift", severity="high",
                        status="PASS" if encrypted else "FAIL",
                        region=region, resource_id=cluster_arn, resource_name=cluster_id,
                        status_extended=f"Redshift cluster {cluster_id} encryption: {encrypted}",
                        remediation="Enable encryption at rest for the Redshift cluster",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                    ).to_dict())

                    # Public access
                    publicly_accessible = cluster.get("PubliclyAccessible", False)
                    results.append(CheckResult(
                        check_id="redshift_cluster_no_public",
                        check_title="Redshift cluster is not publicly accessible",
                        service="redshift", severity="critical",
                        status="FAIL" if publicly_accessible else "PASS",
                        region=region, resource_id=cluster_arn, resource_name=cluster_id,
                        status_extended=f"Redshift cluster {cluster_id} public access: {publicly_accessible}",
                        remediation="Disable public accessibility for the Redshift cluster",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                    ).to_dict())

                    # Audit logging
                    try:
                        logging_status = rs.describe_logging_status(ClusterIdentifier=cluster_id)
                        audit_logging = logging_status.get("LoggingEnabled", False)
                    except ClientError:
                        audit_logging = False
                    results.append(CheckResult(
                        check_id="redshift_audit_logging",
                        check_title="Redshift cluster has audit logging enabled",
                        service="redshift", severity="medium",
                        status="PASS" if audit_logging else "FAIL",
                        region=region, resource_id=cluster_arn, resource_name=cluster_id,
                        status_extended=f"Redshift cluster {cluster_id} audit logging: {audit_logging}",
                        remediation="Enable audit logging for the Redshift cluster",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                    ).to_dict())

            except Exception as e:
                logger.warning(f"Redshift checks in {region} failed: {e}")
        return results

    def _check_ecr(self) -> list[dict]:
        """ECR security checks."""
        results = []
        session = self._get_session()
        for region in self.regions:
            ecr = session.client("ecr", region_name=region)
            try:
                repos = ecr.describe_repositories().get("repositories", [])
                for repo in repos:
                    repo_name = repo["repositoryName"]
                    repo_arn = repo["repositoryArn"]

                    # Image scanning
                    scan_config = repo.get("imageScanningConfiguration", {})
                    scan_on_push = scan_config.get("scanOnPush", False)
                    results.append(CheckResult(
                        check_id="ecr_image_scanning",
                        check_title="ECR repository has image scanning on push enabled",
                        service="ecr", severity="medium",
                        status="PASS" if scan_on_push else "FAIL",
                        region=region, resource_id=repo_arn, resource_name=repo_name,
                        status_extended=f"ECR repo {repo_name} scan on push: {scan_on_push}",
                        remediation="Enable image scanning on push for the ECR repository",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                    ).to_dict())

                    # Lifecycle policy
                    try:
                        ecr.get_lifecycle_policy(repositoryName=repo_name)
                        has_lifecycle = True
                    except ClientError:
                        has_lifecycle = False
                    results.append(CheckResult(
                        check_id="ecr_lifecycle_policy",
                        check_title="ECR repository has lifecycle policy configured",
                        service="ecr", severity="low",
                        status="PASS" if has_lifecycle else "FAIL",
                        region=region, resource_id=repo_arn, resource_name=repo_name,
                        status_extended=f"ECR repo {repo_name} lifecycle policy: {'configured' if has_lifecycle else 'not configured'}",
                        remediation="Configure a lifecycle policy to manage image retention in the ECR repository",
                        compliance_frameworks=["NIST-800-53", "SOC2", "CCM-4.1"],
                    ).to_dict())

            except Exception as e:
                logger.warning(f"ECR checks in {region} failed: {e}")
        return results

    def _check_cloudfront(self) -> list[dict]:
        """CloudFront security checks."""
        results = []
        session = self._get_session()
        cf = session.client("cloudfront")
        try:
            distributions = cf.list_distributions().get("DistributionList", {}).get("Items", [])
            for dist in distributions:
                dist_id = dist["Id"]
                dist_arn = dist["ARN"]
                domain = dist.get("DomainName", dist_id)

                # HTTPS only
                viewer_policy = dist.get("DefaultCacheBehavior", {}).get("ViewerProtocolPolicy", "")
                https_only = viewer_policy in ("https-only", "redirect-to-https")
                results.append(CheckResult(
                    check_id="cloudfront_https_only",
                    check_title="CloudFront distribution enforces HTTPS",
                    service="cloudfront", severity="high",
                    status="PASS" if https_only else "FAIL",
                    resource_id=dist_arn, resource_name=domain,
                    status_extended=f"CloudFront {dist_id} viewer protocol: {viewer_policy}",
                    remediation="Set viewer protocol policy to redirect-to-https or https-only",
                    compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                ).to_dict())

                # WAF enabled
                waf_id = dist.get("WebACLId", "")
                results.append(CheckResult(
                    check_id="cloudfront_waf_enabled",
                    check_title="CloudFront distribution has WAF enabled",
                    service="cloudfront", severity="medium",
                    status="PASS" if waf_id else "FAIL",
                    resource_id=dist_arn, resource_name=domain,
                    status_extended=f"CloudFront {dist_id} WAF: {'enabled' if waf_id else 'not enabled'}",
                    remediation="Associate a WAF Web ACL with the CloudFront distribution",
                    compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                ).to_dict())

        except Exception as e:
            logger.warning(f"CloudFront checks failed: {e}")
        return results

    def _check_waf(self) -> list[dict]:
        """WAF security checks."""
        results = []
        session = self._get_session()
        for region in self.regions:
            try:
                wafv2 = session.client("wafv2", region_name=region)
                acls = wafv2.list_web_acls(Scope="REGIONAL")["WebACLs"]
                results.append(CheckResult(
                    check_id="waf_web_acl_exists",
                    check_title="WAF Web ACL exists in region",
                    service="waf", severity="medium",
                    status="PASS" if acls else "FAIL",
                    region=region, resource_id="waf-web-acl",
                    status_extended=f"Found {len(acls)} WAF Web ACL(s) in {region}",
                    remediation="Create a WAF Web ACL to protect your web applications",
                    compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"WAF checks in {region} failed: {e}")
        return results

    def _check_ssm(self) -> list[dict]:
        """SSM security checks."""
        results = []
        session = self._get_session()
        for region in self.regions:
            ssm = session.client("ssm", region_name=region)
            try:
                # Check for managed instances
                inventory = ssm.describe_instance_information()["InstanceInformationList"]
                ec2_client = session.client("ec2", region_name=region)
                all_instances = []
                for res in ec2_client.describe_instances()["Reservations"]:
                    for inst in res["Instances"]:
                        if inst.get("State", {}).get("Name") == "running":
                            all_instances.append(inst["InstanceId"])
                managed_ids = {i["InstanceId"] for i in inventory}
                unmanaged = [i for i in all_instances if i not in managed_ids]

                results.append(CheckResult(
                    check_id="ssm_managed_instances",
                    check_title="All EC2 instances are managed by SSM",
                    service="ssm", severity="medium",
                    status="PASS" if not unmanaged else "FAIL",
                    region=region, resource_id="ssm-managed-instances",
                    status_extended=f"{len(managed_ids)} of {len(all_instances)} running instances managed by SSM in {region}" + (f" ({len(unmanaged)} unmanaged)" if unmanaged else ""),
                    remediation="Install the SSM agent and attach the AmazonSSMManagedInstanceCore policy to all instances",
                    compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"SSM checks in {region} failed: {e}")
        return results

    def _check_backup(self) -> list[dict]:
        """AWS Backup security checks."""
        results = []
        session = self._get_session()
        for region in self.regions:
            backup = session.client("backup", region_name=region)
            try:
                # Backup plan exists
                plans = backup.list_backup_plans().get("BackupPlansList", [])
                results.append(CheckResult(
                    check_id="backup_plan_exists",
                    check_title="AWS Backup plan exists in region",
                    service="backup", severity="medium",
                    status="PASS" if plans else "FAIL",
                    region=region, resource_id="backup-plans",
                    status_extended=f"Found {len(plans)} backup plan(s) in {region}",
                    remediation="Create an AWS Backup plan to protect critical resources",
                    compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                ).to_dict())

                # Backup vault encryption
                vaults = backup.list_backup_vaults().get("BackupVaultList", [])
                for vault in vaults:
                    vault_name = vault["BackupVaultName"]
                    vault_arn = vault["BackupVaultArn"]
                    encrypted = vault.get("EncryptionKeyArn") is not None
                    results.append(CheckResult(
                        check_id="backup_vault_encrypted",
                        check_title="AWS Backup vault is encrypted",
                        service="backup", severity="high",
                        status="PASS" if encrypted else "FAIL",
                        region=region, resource_id=vault_arn, resource_name=vault_name,
                        status_extended=f"Backup vault {vault_name} encryption: {'enabled' if encrypted else 'not configured'}",
                        remediation="Ensure the backup vault is encrypted with a KMS key",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                    ).to_dict())

            except Exception as e:
                logger.warning(f"Backup checks in {region} failed: {e}")
        return results

    def _check_acm(self) -> list[dict]:
        """ACM certificate security checks."""
        results = []
        session = self._get_session()
        for region in self.regions:
            acm = session.client("acm", region_name=region)
            try:
                certs = acm.list_certificates().get("CertificateSummaryList", [])
                for cert in certs:
                    cert_arn = cert["CertificateArn"]
                    cert_detail = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
                    domain = cert_detail.get("DomainName", cert_arn)
                    not_after = cert_detail.get("NotAfter")
                    if not_after:
                        days_until = (not_after - datetime.now(timezone.utc)).days
                        results.append(CheckResult(
                            check_id="acm_certificate_expiry",
                            check_title="ACM certificate is not expired or expiring soon",
                            service="acm", severity="high",
                            status="PASS" if days_until > 30 else "FAIL",
                            region=region, resource_id=cert_arn, resource_name=domain,
                            status_extended=f"ACM certificate for {domain} expires in {days_until} days",
                            remediation="Renew or replace the ACM certificate before it expires",
                            compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                        ).to_dict())
            except Exception as e:
                logger.warning(f"ACM checks in {region} failed: {e}")
        return results

    def _check_apigateway(self) -> list[dict]:
        """API Gateway security checks."""
        results = []
        session = self._get_session()
        for region in self.regions:
            apigw = session.client("apigateway", region_name=region)
            try:
                apis = apigw.get_rest_apis().get("items", [])
                for api in apis:
                    api_id = api["id"]
                    api_name = api.get("name", api_id)

                    # Check logging on stages
                    try:
                        stages = apigw.get_stages(restApiId=api_id).get("item", [])
                        for stage in stages:
                            stage_name = stage["stageName"]
                            method_settings = stage.get("methodSettings", {})
                            default_settings = method_settings.get("*/*", {})
                            logging_level = default_settings.get("loggingLevel", "OFF")
                            has_logging = logging_level in ("INFO", "ERROR")
                            results.append(CheckResult(
                                check_id="apigateway_rest_api_logging",
                                check_title="API Gateway REST API stage has logging enabled",
                                service="apigateway", severity="medium",
                                status="PASS" if has_logging else "FAIL",
                                region=region,
                                resource_id=f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}",
                                resource_name=f"{api_name}/{stage_name}",
                                status_extended=f"API {api_name} stage {stage_name} logging level: {logging_level}",
                                remediation="Enable execution logging for the API Gateway stage",
                                compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2"],
                            ).to_dict())
                    except ClientError:
                        pass

                    # Check WAF association
                    try:
                        wafv2 = session.client("wafv2", region_name=region)
                        api_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stages[0]['stageName']}" if stages else None
                        if api_arn:
                            waf_assoc = wafv2.get_web_acl_for_resource(ResourceArn=api_arn)
                            has_waf = waf_assoc.get("WebACL") is not None
                        else:
                            has_waf = False
                    except (ClientError, Exception):
                        has_waf = False
                    results.append(CheckResult(
                        check_id="apigateway_waf_enabled",
                        check_title="API Gateway REST API has WAF associated",
                        service="apigateway", severity="medium",
                        status="PASS" if has_waf else "FAIL",
                        region=region,
                        resource_id=f"arn:aws:apigateway:{region}::/restapis/{api_id}",
                        resource_name=api_name,
                        status_extended=f"API {api_name} WAF: {'associated' if has_waf else 'not associated'}",
                        remediation="Associate a WAF Web ACL with the API Gateway REST API stage",
                        compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                    ).to_dict())

            except Exception as e:
                logger.warning(f"API Gateway checks in {region} failed: {e}")
        return results

    def _check_macie(self) -> list[dict]:
        """Amazon Macie security checks."""
        results = []
        session = self._get_session()
        for region in self.regions:
            try:
                macie = session.client("macie2", region_name=region)
                status = macie.get_macie_session()
                macie_status = status.get("status") == "ENABLED"
                results.append(CheckResult(
                    check_id="macie_enabled",
                    check_title="Amazon Macie is enabled",
                    service="macie", severity="medium",
                    status="PASS" if macie_status else "FAIL",
                    region=region, resource_id="macie",
                    status_extended=f"Amazon Macie {'is' if macie_status else 'is not'} enabled in {region}",
                    remediation="Enable Amazon Macie for sensitive data discovery and monitoring",
                    compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                ).to_dict())
            except ClientError:
                results.append(CheckResult(
                    check_id="macie_enabled",
                    check_title="Amazon Macie is enabled",
                    service="macie", severity="medium", status="FAIL",
                    region=region, resource_id="macie",
                    status_extended=f"Amazon Macie is not enabled in {region}",
                    remediation="Enable Amazon Macie for sensitive data discovery and monitoring",
                    compliance_frameworks=["CIS-AWS-3.0", "NIST-800-53", "SOC2", "CCM-4.1"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"Macie checks in {region} failed: {e}")
        return results

    def _check_securityhub(self) -> list[dict]:
        """AWS Security Hub checks."""
        results = []
        session = self._get_session()
        for region in self.regions:
            try:
                sh = session.client("securityhub", region_name=region)
                hub = sh.describe_hub()
                is_enabled = "HubArn" in hub
                results.append(CheckResult(
                    check_id="securityhub_enabled",
                    check_title="AWS Security Hub is enabled",
                    service="securityhub", severity="medium",
                    status="PASS" if is_enabled else "FAIL",
                    region=region, resource_id=hub.get("HubArn", "securityhub"),
                    status_extended=f"Security Hub {'is enabled' if is_enabled else 'is not enabled'} in {region}",
                    remediation="Enable AWS Security Hub: aws securityhub enable-security-hub --enable-default-standards",
                    compliance_frameworks=["CIS-AWS-6.0", "NIST-800-53", "SOC2"],
                ).to_dict())
            except ClientError:
                results.append(CheckResult(
                    check_id="securityhub_enabled",
                    check_title="AWS Security Hub is enabled",
                    service="securityhub", severity="medium", status="FAIL",
                    region=region, resource_id="securityhub",
                    status_extended=f"Security Hub is not enabled in {region}",
                    remediation="Enable AWS Security Hub: aws securityhub enable-security-hub --enable-default-standards",
                    compliance_frameworks=["CIS-AWS-6.0", "NIST-800-53", "SOC2"],
                ).to_dict())
            except Exception as e:
                logger.warning(f"SecurityHub checks in {region} failed: {e}")
        return results

    def _emit_cis_coverage(self, automated_results: list[dict]) -> list[dict]:
        """Emit results for ALL CIS controls, filling in MANUAL status for non-automated ones.

        This ensures the framework reports on every single CIS control from the benchmark,
        marking automated controls with their actual PASS/FAIL status and manual controls
        with MANUAL status indicating human review is required.
        """
        # Build a set of CIS control IDs already covered by automated checks
        covered_cis_ids = set()
        for result in automated_results:
            cis_id = result.get("cis_control_id")
            if cis_id:
                covered_cis_ids.add(cis_id)

        # Map check_ids to CIS control IDs based on check names
        check_to_cis = {
            "iam_root_mfa_enabled": "1.5",
            "iam_no_root_access_key": "1.4",
            "iam_password_policy_strong": "1.8",
            "iam_password_policy_rotation": "1.8",
            "iam_password_policy_reuse_prevention": "1.9",
            "iam_password_policy_exists": "1.8",
            "iam_user_mfa_enabled": "1.10",
            "iam_user_no_inline_policies": "1.15",
            "iam_user_unused_credentials_45days": "1.12",
            "iam_access_key_rotation": "1.14",
            "iam_user_single_active_access_key": "1.13",
            "iam_user_no_attached_policies": "1.15",
            "iam_group_no_inline_policies": "1.16",
            "iam_no_star_policies": "1.16",
            "iam_support_role_created": "1.17",
            "iam_cloudshell_fullaccess_restricted": "1.16",
            "iam_ssl_certificate_expiry": "1.19",
            "iam_access_analyzer_enabled": "1.20",
            "s3_bucket_public_access_blocked": "2.1.4",
            "s3_bucket_encryption_enabled": "2.1.1",
            "s3_bucket_versioning_enabled": "2.1.1",
            "s3_bucket_logging_enabled": "3.6",
            "s3_bucket_ssl_required": "2.1.1",
            "s3_bucket_mfa_delete": "2.1.2",
            "s3_bucket_object_lock": "2.1.1",
            "ec2_ebs_volume_encrypted": "2.2.1",
            "ec2_ebs_default_encryption": "2.2.1",
            "ec2_imdsv2_required": "5.5",
            "ec2_default_sg_no_traffic": "5.3",
            "ec2_sg_no_wide_open_ports": "5.6",
            "ec2_sg_no_ipv6_wide_open": "5.2",
            "ec2_instance_no_public_ip": "5.6",
            "rds_encryption_enabled": "2.3.1",
            "rds_public_access_disabled": "2.3.3",
            "rds_auto_minor_upgrade": "2.3.2",
            "cloudtrail_enabled": "3.1",
            "cloudtrail_multiregion": "3.1",
            "cloudtrail_log_validation": "3.2",
            "cloudtrail_encrypted": "3.7",
            "cloudtrail_s3_bucket_logging": "3.6",
            "cloudtrail_s3_object_write_events": "3.10",
            "cloudtrail_s3_object_read_events": "3.11",
            "cloudtrail_integrated_cloudwatch": "3.4",
            "kms_key_rotation_enabled": "3.8",
            "vpc_flow_logs_enabled": "3.9",
            "vpc_default_sg_restricts_all": "5.3",
            "vpc_no_unrestricted_nacl": "5.1",
            "config_recorder_enabled": "3.5",
            "securityhub_enabled": "4.16",
        }

        for result in automated_results:
            check_id = result.get("check_id", "")
            if check_id in check_to_cis:
                covered_cis_ids.add(check_to_cis[check_id])

        # Emit MANUAL results for uncovered CIS controls
        manual_results = []
        fw = ["CIS-AWS-3.0.0", "NIST-800-53", "SOC2"]

        for ctrl in AWS_CIS_CONTROLS:
            cis_id, title, level, assessment_type, severity, service_area = ctrl
            if cis_id not in covered_cis_ids:
                manual_results.append(CheckResult(
                    check_id=f"aws_cis_{cis_id.replace('.', '_')}",
                    check_title=f"{title} (CIS {cis_id})",
                    service=service_area,
                    severity=severity,
                    status="MANUAL",
                    resource_id="aws-account",
                    status_extended=(
                        f"CIS {cis_id} [{level}] - {assessment_type.upper()} assessment. "
                        f"This control requires {'manual verification' if assessment_type == 'manual' else 'automated check implementation'}."
                    ),
                    remediation=f"Refer to CIS Amazon Web Services Foundations Benchmark v3.0.0, control {cis_id}.",
                    compliance_frameworks=fw,
                    assessment_type=assessment_type,
                    cis_control_id=cis_id,
                    cis_level=level,
                ).to_dict())

        return manual_results

    def run_all_checks(self) -> list[dict]:
        """Run all AWS security checks including complete CIS benchmark coverage."""
        results = self.scan()

        # Add MANUAL results for any CIS controls not covered by automated checks
        results.extend(self._emit_cis_coverage(results))

        return results
