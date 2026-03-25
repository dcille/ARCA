"""Centralized check library and registry for cloud security checks.

Provides a unified catalog of all available security checks across cloud
providers (AWS, Azure, GCP, OCI, Alibaba). Supports registration, lookup,
filtering, searching, and report generation for the full check inventory.
"""

import logging
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CheckDefinition:
    """Defines a single security check in the catalog."""

    check_id: str
    title: str
    description: str
    severity: str
    provider: str
    service: str
    category: str
    remediation: str
    references: list[str] = field(default_factory=list)
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    compliance_mappings: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def __post_init__(self) -> None:
        valid_severities = {"critical", "high", "medium", "low", "informational"}
        if self.severity not in valid_severities:
            raise ValueError(
                f"Invalid severity '{self.severity}'. "
                f"Must be one of: {', '.join(sorted(valid_severities))}"
            )
        valid_providers = {"aws", "azure", "gcp", "oci", "alibaba", "ibm_cloud"}
        if self.provider not in valid_providers:
            raise ValueError(
                f"Invalid provider '{self.provider}'. "
                f"Must be one of: {', '.join(sorted(valid_providers))}"
            )

    def to_dict(self) -> dict:
        """Return a plain dictionary representation."""
        return asdict(self)

    def to_json(self) -> str:
        """Return a JSON string representation."""
        return json.dumps(self.to_dict(), indent=2)

    def summary(self) -> str:
        """Return a one-line summary for display."""
        return (
            f"[{self.severity.upper():>13s}] {self.check_id:<24s} "
            f"({self.provider}/{self.service}) - {self.title}"
        )


class CheckRegistry:
    """Central registry that catalogs all available security checks.

    Usage::

        registry = CheckRegistry()
        registry.load_builtin_checks()

        # Query checks
        critical = registry.filter_by_severity("critical")
        aws_iam  = registry.filter_by_provider("aws", service="IAM")

        # Register a custom check
        registry.register_check(CheckDefinition(...))
    """

    def __init__(self) -> None:
        self._checks: dict[str, CheckDefinition] = {}
        self._custom_checks: set[str] = set()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_check(self, check: CheckDefinition, custom: bool = False) -> None:
        """Add a check to the registry.

        Args:
            check: The check definition to register.
            custom: If True, mark the check as user-provided.

        Raises:
            ValueError: If a check with the same ID already exists.
        """
        if check.check_id in self._checks:
            raise ValueError(
                f"Check '{check.check_id}' is already registered. "
                "Use a unique check_id or unregister the existing one first."
            )
        self._checks[check.check_id] = check
        if custom:
            self._custom_checks.add(check.check_id)
        logger.debug("Registered check %s (custom=%s)", check.check_id, custom)

    def register_many(self, checks: list[CheckDefinition], custom: bool = False) -> int:
        """Register a batch of checks. Returns the count of successfully registered checks."""
        count = 0
        for chk in checks:
            try:
                self.register_check(chk, custom=custom)
                count += 1
            except ValueError as exc:
                logger.warning("Skipping check: %s", exc)
        return count

    def unregister_check(self, check_id: str) -> CheckDefinition:
        """Remove and return a check from the registry.

        Raises:
            KeyError: If the check_id is not found.
        """
        if check_id not in self._checks:
            raise KeyError(f"Check '{check_id}' not found in registry.")
        check = self._checks.pop(check_id)
        self._custom_checks.discard(check_id)
        logger.debug("Unregistered check %s", check_id)
        return check

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_check(self, check_id: str) -> CheckDefinition:
        """Retrieve a check by its ID.

        Raises:
            KeyError: If the check_id is not found.
        """
        if check_id not in self._checks:
            raise KeyError(f"Check '{check_id}' not found in registry.")
        return self._checks[check_id]

    def list_checks(self, include_disabled: bool = False) -> list[CheckDefinition]:
        """Return all registered checks, optionally including disabled ones."""
        if include_disabled:
            return list(self._checks.values())
        return [c for c in self._checks.values() if c.enabled]

    def list_custom_checks(self) -> list[CheckDefinition]:
        """Return only user-registered custom checks."""
        return [self._checks[cid] for cid in self._custom_checks if cid in self._checks]

    @property
    def total_count(self) -> int:
        """Total number of registered checks."""
        return len(self._checks)

    @property
    def enabled_count(self) -> int:
        """Number of enabled checks."""
        return sum(1 for c in self._checks.values() if c.enabled)

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def filter_by_provider(
        self, provider: str, service: Optional[str] = None
    ) -> list[CheckDefinition]:
        """Return checks for a given provider, optionally narrowed by service."""
        result = [c for c in self._checks.values() if c.provider == provider and c.enabled]
        if service:
            result = [c for c in result if c.service.lower() == service.lower()]
        return result

    def filter_by_severity(self, severity: str) -> list[CheckDefinition]:
        """Return all enabled checks with the given severity level."""
        return [
            c for c in self._checks.values()
            if c.severity == severity and c.enabled
        ]

    def filter_by_category(self, category: str) -> list[CheckDefinition]:
        """Return all enabled checks within a security category."""
        cat_lower = category.lower()
        return [
            c for c in self._checks.values()
            if c.category.lower() == cat_lower and c.enabled
        ]

    def filter_by_tags(self, tags: list[str], match_all: bool = False) -> list[CheckDefinition]:
        """Return checks matching the supplied tags.

        Args:
            tags: Tags to match against.
            match_all: If True, a check must have *all* supplied tags.
        """
        tag_set = {t.lower() for t in tags}
        results: list[CheckDefinition] = []
        for chk in self._checks.values():
            chk_tags = {t.lower() for t in chk.tags}
            if match_all:
                if tag_set.issubset(chk_tags):
                    results.append(chk)
            else:
                if tag_set & chk_tags:
                    results.append(chk)
        return results

    def filter_by_compliance(self, framework: str) -> list[CheckDefinition]:
        """Return checks mapped to the given compliance framework string."""
        fw_lower = framework.lower()
        return [
            c for c in self._checks.values()
            if any(fw_lower in m.lower() for m in c.compliance_mappings)
        ]

    # ------------------------------------------------------------------
    # Searching
    # ------------------------------------------------------------------

    def search_checks(self, query: str) -> list[CheckDefinition]:
        """Full-text search across check_id, title, description, and service."""
        q = query.lower()
        results: list[CheckDefinition] = []
        for chk in self._checks.values():
            searchable = " ".join([
                chk.check_id,
                chk.title,
                chk.description,
                chk.service,
                chk.category,
                " ".join(chk.tags),
            ]).lower()
            if q in searchable:
                results.append(chk)
        return results

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_catalog_report(self) -> dict:
        """Generate a comprehensive catalog/inventory report.

        Returns a dict with summary statistics and per-provider breakdowns.
        """
        report: dict = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_checks": self.total_count,
            "enabled_checks": self.enabled_count,
            "disabled_checks": self.total_count - self.enabled_count,
            "custom_checks": len(self._custom_checks),
            "by_provider": {},
            "by_severity": {},
            "by_category": {},
            "checks": [],
        }

        for chk in self._checks.values():
            # Per-provider counts
            prov = chk.provider
            if prov not in report["by_provider"]:
                report["by_provider"][prov] = {"total": 0, "by_service": {}}
            report["by_provider"][prov]["total"] += 1
            svc = chk.service
            report["by_provider"][prov]["by_service"][svc] = (
                report["by_provider"][prov]["by_service"].get(svc, 0) + 1
            )

            # Per-severity counts
            report["by_severity"][chk.severity] = (
                report["by_severity"].get(chk.severity, 0) + 1
            )

            # Per-category counts
            report["by_category"][chk.category] = (
                report["by_category"].get(chk.category, 0) + 1
            )

            report["checks"].append(chk.to_dict())

        return report

    def generate_catalog_text(self) -> str:
        """Return a human-readable text version of the catalog."""
        lines: list[str] = []
        lines.append("=" * 80)
        lines.append("ARCA Cloud Security Check Catalog")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        lines.append(f"Total checks: {self.total_count}  "
                      f"(enabled: {self.enabled_count})")
        lines.append("=" * 80)

        # Group by provider
        providers: dict[str, list[CheckDefinition]] = {}
        for chk in self._checks.values():
            providers.setdefault(chk.provider, []).append(chk)

        for prov in sorted(providers):
            checks = providers[prov]
            lines.append("")
            lines.append(f"--- {prov.upper()} ({len(checks)} checks) ---")
            for chk in sorted(checks, key=lambda c: c.check_id):
                lines.append(chk.summary())

        lines.append("")
        lines.append("=" * 80)
        return "\n".join(lines)

    def export_json(self) -> str:
        """Export the full catalog as a JSON string."""
        return json.dumps(self.generate_catalog_report(), indent=2)

    # ------------------------------------------------------------------
    # Built-in checks
    # ------------------------------------------------------------------

    def load_builtin_checks(self) -> int:
        """Populate the registry with the default set of cloud security checks.

        Returns the number of checks registered.
        """
        checks = _builtin_checks()
        return self.register_many(checks)


# ======================================================================
# Built-in check definitions (50+)
# ======================================================================

def _builtin_checks() -> list[CheckDefinition]:
    """Return the default catalog of common cloud security checks."""
    checks: list[CheckDefinition] = []

    def _c(check_id, title, description, severity, provider, service,
           category, remediation, references=None, tags=None,
           compliance_mappings=None):
        checks.append(CheckDefinition(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            provider=provider,
            service=service,
            category=category,
            remediation=remediation,
            references=references or [],
            tags=tags or [],
            compliance_mappings=compliance_mappings or [],
        ))

    # ---- AWS checks (18) -------------------------------------------------

    _c("aws_iam_001", "Root account MFA not enabled",
       "The AWS root account does not have multi-factor authentication enabled, "
       "leaving the most privileged account vulnerable to credential compromise.",
       "critical", "aws", "IAM", "Identity",
       "Enable MFA on the root account via the IAM console Security Credentials page.",
       ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"],
       ["iam", "mfa", "root"], ["CIS AWS 1.5", "NIST 800-53 IA-2"])

    _c("aws_iam_002", "IAM user without MFA",
       "One or more IAM users do not have MFA enabled on their console access.",
       "high", "aws", "IAM", "Identity",
       "Enable virtual or hardware MFA for every IAM user with console access.",
       ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"],
       ["iam", "mfa"], ["CIS AWS 1.10"])

    _c("aws_iam_003", "IAM policies allow full administrative privileges",
       "IAM policies granting Action:* on Resource:* provide unrestricted access.",
       "critical", "aws", "IAM", "Identity",
       "Replace wildcard policies with least-privilege scoped permissions.",
       [], ["iam", "least-privilege"], ["CIS AWS 1.16"])

    _c("aws_iam_004", "Access keys older than 90 days",
       "Long-lived access keys increase the window for credential abuse.",
       "medium", "aws", "IAM", "Identity",
       "Rotate access keys every 90 days or switch to IAM roles.",
       [], ["iam", "keys", "rotation"], ["CIS AWS 1.14"])

    _c("aws_s3_001", "S3 bucket public read access",
       "An S3 bucket allows unauthenticated public read, risking data exposure.",
       "critical", "aws", "S3", "Storage",
       "Remove public ACLs and enable S3 Block Public Access at account level.",
       ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
       ["s3", "public-access"], ["CIS AWS 2.1.1"])

    _c("aws_s3_002", "S3 bucket default encryption disabled",
       "Objects stored without server-side encryption may be read if storage is compromised.",
       "high", "aws", "S3", "Encryption",
       "Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
       [], ["s3", "encryption"], ["CIS AWS 2.1.2"])

    _c("aws_s3_003", "S3 bucket versioning disabled",
       "Without versioning, deleted or overwritten objects cannot be recovered.",
       "medium", "aws", "S3", "Storage",
       "Enable versioning on the S3 bucket.", [], ["s3", "versioning"])

    _c("aws_ec2_001", "Security group allows unrestricted SSH",
       "An EC2 security group permits SSH (port 22) from 0.0.0.0/0.",
       "high", "aws", "EC2", "Networking",
       "Restrict SSH ingress to known CIDR blocks or use Systems Manager Session Manager.",
       [], ["ec2", "ssh", "security-group"], ["CIS AWS 5.2"])

    _c("aws_ec2_002", "Security group allows unrestricted RDP",
       "An EC2 security group permits RDP (port 3389) from 0.0.0.0/0.",
       "high", "aws", "EC2", "Networking",
       "Restrict RDP ingress to known CIDR blocks.",
       [], ["ec2", "rdp", "security-group"], ["CIS AWS 5.3"])

    _c("aws_ec2_003", "EBS volume not encrypted",
       "Unencrypted EBS volumes may expose data at rest.",
       "high", "aws", "EC2", "Encryption",
       "Enable encryption when creating EBS volumes or enable default encryption in EC2 settings.",
       [], ["ec2", "ebs", "encryption"], ["CIS AWS 2.2.1"])

    _c("aws_rds_001", "RDS instance publicly accessible",
       "A publicly accessible RDS instance exposes the database to the internet.",
       "critical", "aws", "RDS", "Networking",
       "Disable public accessibility and use VPC private subnets.",
       [], ["rds", "public-access"])

    _c("aws_rds_002", "RDS automated backups disabled",
       "Without automated backups, point-in-time recovery is not possible.",
       "medium", "aws", "RDS", "Storage",
       "Set the backup retention period to at least 7 days.",
       [], ["rds", "backup"])

    _c("aws_cloudtrail_001", "CloudTrail not enabled in all regions",
       "CloudTrail should log API activity across every region to ensure full audit coverage.",
       "high", "aws", "CloudTrail", "Logging",
       "Create a multi-region trail with management event logging.",
       [], ["cloudtrail", "logging"], ["CIS AWS 3.1"])

    _c("aws_cloudtrail_002", "CloudTrail log file validation disabled",
       "Without log file integrity validation, tampered logs go undetected.",
       "medium", "aws", "CloudTrail", "Logging",
       "Enable log file validation on the trail.",
       [], ["cloudtrail", "integrity"], ["CIS AWS 3.2"])

    _c("aws_kms_001", "KMS key rotation not enabled",
       "Customer-managed KMS keys should be rotated annually to reduce exposure from compromised keys.",
       "medium", "aws", "KMS", "Encryption",
       "Enable automatic key rotation for customer-managed KMS keys.",
       [], ["kms", "rotation"], ["CIS AWS 3.8"])

    _c("aws_lambda_001", "Lambda function uses outdated runtime",
       "Running an unsupported Lambda runtime means no security patches.",
       "medium", "aws", "Lambda", "Compute",
       "Update the function to a currently supported runtime version.",
       [], ["lambda", "runtime"])

    _c("aws_vpc_001", "VPC flow logs not enabled",
       "VPC flow logs provide network traffic visibility required for incident investigation.",
       "medium", "aws", "VPC", "Logging",
       "Enable VPC flow logs for all VPCs, sending to CloudWatch Logs or S3.",
       [], ["vpc", "flow-logs"], ["CIS AWS 3.9"])

    _c("aws_guardduty_001", "GuardDuty not enabled",
       "GuardDuty provides continuous threat detection; disabling it leaves blind spots.",
       "high", "aws", "GuardDuty", "Logging",
       "Enable GuardDuty in every region.",
       [], ["guardduty", "threat-detection"])

    # ---- Azure checks (12) -----------------------------------------------

    _c("azure_iam_001", "No conditional access policies configured",
       "Azure AD conditional access policies enforce adaptive access controls.",
       "high", "azure", "IAM", "Identity",
       "Configure conditional access policies requiring MFA and compliant devices.",
       [], ["iam", "conditional-access"])

    _c("azure_iam_002", "MFA not enforced for all users",
       "Users without MFA are susceptible to credential stuffing and phishing.",
       "critical", "azure", "IAM", "Identity",
       "Enforce MFA for all users through conditional access or security defaults.",
       [], ["iam", "mfa"], ["CIS Azure 1.1"])

    _c("azure_storage_001", "Storage account allows public blob access",
       "Public blob access can expose sensitive data to the internet.",
       "critical", "azure", "Storage", "Storage",
       "Disable public blob access at the storage account level.",
       [], ["storage", "public-access"], ["CIS Azure 3.5"])

    _c("azure_storage_002", "Storage account HTTPS-only not enforced",
       "Allowing HTTP exposes data in transit to interception.",
       "high", "azure", "Storage", "Encryption",
       "Enable the 'Secure transfer required' setting.",
       [], ["storage", "https"], ["CIS Azure 3.1"])

    _c("azure_sql_001", "Azure SQL auditing disabled",
       "Database auditing is required for compliance and incident forensics.",
       "high", "azure", "SQL", "Logging",
       "Enable auditing on Azure SQL databases.",
       [], ["sql", "auditing"], ["CIS Azure 4.1"])

    _c("azure_sql_002", "Azure SQL TDE disabled",
       "Transparent Data Encryption protects data at rest from physical theft.",
       "high", "azure", "SQL", "Encryption",
       "Enable TDE on all SQL databases.",
       [], ["sql", "encryption"], ["CIS Azure 4.1.2"])

    _c("azure_network_001", "NSG allows unrestricted SSH",
       "Network security groups should not allow SSH from any source.",
       "high", "azure", "Network", "Networking",
       "Restrict SSH rules to specific source IP ranges.",
       [], ["nsg", "ssh"], ["CIS Azure 6.1"])

    _c("azure_network_002", "NSG allows unrestricted RDP",
       "Network security groups should not allow RDP from any source.",
       "high", "azure", "Network", "Networking",
       "Restrict RDP rules to specific source IP ranges.",
       [], ["nsg", "rdp"], ["CIS Azure 6.2"])

    _c("azure_keyvault_001", "Key Vault soft delete disabled",
       "Without soft delete, accidentally purged secrets are unrecoverable.",
       "medium", "azure", "KeyVault", "Encryption",
       "Enable soft delete on all Key Vaults.",
       [], ["keyvault", "soft-delete"])

    _c("azure_monitor_001", "Activity log alerts not configured",
       "Critical operations should trigger alerts for rapid incident response.",
       "medium", "azure", "Monitor", "Logging",
       "Configure activity log alerts for key administrative operations.",
       [], ["monitor", "alerts"], ["CIS Azure 5.2"])

    _c("azure_vm_001", "Managed disk encryption disabled",
       "OS and data disks should use Azure Disk Encryption or SSE with CMK.",
       "high", "azure", "Compute", "Encryption",
       "Enable disk encryption for all managed disks.",
       [], ["vm", "encryption"])

    _c("azure_defender_001", "Microsoft Defender for Cloud disabled",
       "Defender for Cloud provides threat protection across Azure resources.",
       "high", "azure", "Defender", "Logging",
       "Enable Defender for Cloud on all subscriptions.",
       [], ["defender", "threat-detection"])

    # ---- GCP checks (10) -------------------------------------------------

    _c("gcp_iam_001", "Service account has admin privileges",
       "Service accounts with Owner or Editor roles violate least privilege.",
       "critical", "gcp", "IAM", "Identity",
       "Replace primitive roles with predefined or custom roles.",
       [], ["iam", "least-privilege"], ["CIS GCP 1.5"])

    _c("gcp_iam_002", "User-managed service account keys exist",
       "User-managed keys are long-lived and easily leaked.",
       "high", "gcp", "IAM", "Identity",
       "Use workload identity federation or attached service accounts instead of keys.",
       [], ["iam", "keys"], ["CIS GCP 1.4"])

    _c("gcp_storage_001", "Cloud Storage bucket publicly accessible",
       "allUsers or allAuthenticatedUsers ACLs expose bucket contents.",
       "critical", "gcp", "Storage", "Storage",
       "Remove public ACL entries and use IAM conditions.",
       [], ["storage", "public-access"], ["CIS GCP 5.1"])

    _c("gcp_storage_002", "Bucket uniform access not enabled",
       "Uniform bucket-level access simplifies permissions and prevents ACL misuse.",
       "medium", "gcp", "Storage", "Storage",
       "Enable uniform bucket-level access.",
       [], ["storage", "iam"])

    _c("gcp_compute_001", "VM instance with public IP",
       "Instances should use Cloud NAT or a load balancer instead of public IPs.",
       "high", "gcp", "Compute", "Networking",
       "Remove external IPs and route traffic through Cloud NAT.",
       [], ["compute", "public-ip"])

    _c("gcp_compute_002", "OS Login not enabled on project",
       "OS Login integrates SSH key management with IAM.",
       "medium", "gcp", "Compute", "Identity",
       "Enable OS Login at the project metadata level.",
       [], ["compute", "os-login"], ["CIS GCP 4.4"])

    _c("gcp_sql_001", "Cloud SQL instance publicly accessible",
       "Authorized networks including 0.0.0.0/0 expose the database.",
       "critical", "gcp", "SQL", "Networking",
       "Remove 0.0.0.0/0 from authorized networks and use private IP.",
       [], ["sql", "public-access"])

    _c("gcp_logging_001", "Audit logging not enabled for all services",
       "Data access logs should be enabled for forensics and compliance.",
       "high", "gcp", "Logging", "Logging",
       "Enable Data Access audit logs for all services at the organization level.",
       [], ["logging", "audit"], ["CIS GCP 2.1"])

    _c("gcp_kms_001", "KMS key rotation period exceeds 365 days",
       "Crypto keys should rotate within one year to limit key exposure.",
       "medium", "gcp", "KMS", "Encryption",
       "Set the rotation period to 365 days or less.",
       [], ["kms", "rotation"], ["CIS GCP 1.10"])

    _c("gcp_network_001", "Default network exists in project",
       "The default network has overly permissive firewall rules.",
       "medium", "gcp", "Network", "Networking",
       "Delete the default network and create custom VPC networks.",
       [], ["network", "default"], ["CIS GCP 3.1"])

    # ---- OCI checks (5) --------------------------------------------------

    _c("oci_iam_001", "Tenancy admin user without MFA",
       "The OCI tenancy administrator should have MFA enabled.",
       "critical", "oci", "IAM", "Identity",
       "Enable MFA for the tenancy admin user.",
       [], ["iam", "mfa"])

    _c("oci_iam_002", "API keys older than 90 days",
       "Long-lived API keys increase the risk of compromise.",
       "medium", "oci", "IAM", "Identity",
       "Rotate API signing keys every 90 days.",
       [], ["iam", "keys", "rotation"])

    _c("oci_storage_001", "Object Storage bucket is public",
       "Public pre-authenticated requests or public bucket settings expose data.",
       "critical", "oci", "Storage", "Storage",
       "Disable public access on the bucket and revoke public PARs.",
       [], ["storage", "public-access"])

    _c("oci_network_001", "Security list allows unrestricted SSH",
       "Ingress rules should not allow SSH from 0.0.0.0/0.",
       "high", "oci", "Network", "Networking",
       "Restrict SSH ingress to specific CIDR blocks.",
       [], ["network", "ssh"])

    _c("oci_logging_001", "Audit log retention less than 365 days",
       "Audit logs must be retained for at least one year for compliance.",
       "medium", "oci", "Logging", "Logging",
       "Set audit log retention to 365 days.",
       [], ["logging", "retention"])

    # ---- Alibaba checks (5) -----------------------------------------------

    _c("alibaba_iam_001", "RAM user without MFA",
       "RAM users with console access should have MFA enabled.",
       "high", "alibaba", "IAM", "Identity",
       "Enable MFA for all RAM users with console login enabled.",
       [], ["iam", "mfa"])

    _c("alibaba_iam_002", "AccessKey not rotated in 90 days",
       "Long-lived AccessKeys increase risk of credential misuse.",
       "medium", "alibaba", "IAM", "Identity",
       "Rotate AccessKeys every 90 days.",
       [], ["iam", "keys", "rotation"])

    _c("alibaba_oss_001", "OSS bucket allows public read",
       "Public-read ACL on an OSS bucket exposes objects to unauthenticated users.",
       "critical", "alibaba", "OSS", "Storage",
       "Set bucket ACL to private.",
       [], ["oss", "public-access"])

    _c("alibaba_ecs_001", "Security group allows unrestricted SSH",
       "ECS security groups should not permit SSH from 0.0.0.0/0.",
       "high", "alibaba", "ECS", "Networking",
       "Restrict SSH ingress rules to known IP ranges.",
       [], ["ecs", "ssh", "security-group"])

    _c("alibaba_actiontrail_001", "ActionTrail not enabled",
       "ActionTrail provides audit logging of API calls for compliance.",
       "high", "alibaba", "ActionTrail", "Logging",
       "Enable ActionTrail in all regions.",
       [], ["actiontrail", "logging"])

    return checks


# ======================================================================
# Module-level convenience functions
# ======================================================================

_default_registry: Optional[CheckRegistry] = None


def get_default_registry() -> CheckRegistry:
    """Return (and lazily initialise) the module-level default registry."""
    global _default_registry
    if _default_registry is None:
        _default_registry = CheckRegistry()
        _default_registry.load_builtin_checks()
    return _default_registry


def register_custom_check(check: CheckDefinition) -> None:
    """Register a custom check in the default registry."""
    get_default_registry().register_check(check, custom=True)


def search(query: str) -> list[CheckDefinition]:
    """Search the default registry."""
    return get_default_registry().search_checks(query)


def catalog_report() -> dict:
    """Generate a catalog report from the default registry."""
    return get_default_registry().generate_catalog_report()
