"""Data models for the check registry.

The registry is based on CIS Benchmark controls as the primary source of truth
(904 controls across 9 benchmarks). Scanner check_ids map INTO CIS controls,
and MITRE/RR references are resolved through the scanner_check_ids field.

Resolution chain:
  CIS Control (canonical) ←→ scanner_check_ids ←→ MITRE / RR references
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
import json


class ProviderType(str, Enum):
    """All supported provider types."""
    # Cloud providers
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OCI = "oci"
    ALIBABA = "alibaba"
    IBM_CLOUD = "ibm_cloud"
    KUBERNETES = "kubernetes"
    # SaaS providers
    M365 = "m365"
    GITHUB = "github"
    GOOGLE_WORKSPACE = "google_workspace"
    SALESFORCE = "salesforce"
    SERVICENOW = "servicenow"
    SNOWFLAKE = "snowflake"
    CLOUDFLARE = "cloudflare"
    OPENSTACK = "openstack"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Category(str, Enum):
    IDENTITY = "Identity"
    ENCRYPTION = "Encryption"
    STORAGE = "Storage"
    NETWORKING = "Networking"
    LOGGING = "Logging"
    COMPUTE = "Compute"
    DATABASE = "Database"
    CONTAINER = "Container"
    SERVERLESS = "Serverless"
    DATA_PROTECTION = "Data Protection"
    BACKUP = "Backup"
    COMPLIANCE = "Compliance"
    THREAT_DETECTION = "Threat Detection"
    GOVERNANCE = "Governance"
    EMAIL_SECURITY = "Email Security"
    COLLABORATION = "Collaboration"
    DEVOPS = "DevOps"
    API_SECURITY = "API Security"
    CDN = "CDN"
    DNS = "DNS"
    ANALYTICS = "Analytics"


CLOUD_PROVIDERS = {
    ProviderType.AWS, ProviderType.AZURE, ProviderType.GCP,
    ProviderType.OCI, ProviderType.ALIBABA, ProviderType.IBM_CLOUD,
    ProviderType.KUBERNETES,
}

SAAS_PROVIDERS = {
    ProviderType.M365, ProviderType.GITHUB, ProviderType.GOOGLE_WORKSPACE,
    ProviderType.SALESFORCE, ProviderType.SERVICENOW, ProviderType.SNOWFLAKE,
    ProviderType.CLOUDFLARE, ProviderType.OPENSTACK,
}


@dataclass
class CheckDefinition:
    """Defines a single security check in the registry.

    Primary source: CIS Benchmark controls.
    Scanner check_ids are linked via the scanner_check_ids field, allowing
    MITRE ATT&CK and Ransomware Readiness modules to resolve their references.
    """

    # -- Identity --
    check_id: str  # Canonical ID: "{provider}_{cis_id}" for CIS, scanner ID for supplementary
    title: str
    description: str
    severity: str
    provider: str
    service: str
    category: str

    # -- CIS Benchmark linkage --
    cis_id: Optional[str] = None  # Original CIS control ID (e.g., "2.1.1")
    cis_level: Optional[str] = None  # L1, L2
    cis_profile: Optional[str] = None  # E3, E5, etc. (SaaS)
    assessment_type: str = "automated"  # automated | manual

    # -- Scanner mapping --
    # Scanner check_ids that implement this CIS control.
    # This is the bridge for MITRE/RR resolution.
    scanner_check_ids: list[str] = field(default_factory=list)

    # -- Ransomware Readiness linkage (from CIS control metadata) --
    rr_relevant: bool = False
    rr_domains: list[str] = field(default_factory=list)  # D1..D7

    # -- DSPM linkage --
    dspm_relevant: bool = False
    dspm_categories: list[str] = field(default_factory=list)

    # -- Remediation & references --
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    compliance_mappings: list[str] = field(default_factory=list)

    # -- Metadata --
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    source: str = "cis"  # cis | scanner | custom

    def __post_init__(self) -> None:
        valid_severities = {s.value for s in Severity}
        if self.severity not in valid_severities:
            raise ValueError(
                f"Invalid severity '{self.severity}'. "
                f"Must be one of: {', '.join(sorted(valid_severities))}"
            )
        valid_providers = {p.value for p in ProviderType}
        if self.provider not in valid_providers:
            raise ValueError(
                f"Invalid provider '{self.provider}'. "
                f"Must be one of: {', '.join(sorted(valid_providers))}"
            )

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def summary(self) -> str:
        cis = f" CIS:{self.cis_id}" if self.cis_id else ""
        scanners = f" scanners:{len(self.scanner_check_ids)}" if self.scanner_check_ids else ""
        return (
            f"[{self.severity.upper():>13s}] {self.check_id:<45s} "
            f"({self.provider}/{self.service}){cis}{scanners} - {self.title}"
        )

    @property
    def is_cloud(self) -> bool:
        return self.provider in {p.value for p in CLOUD_PROVIDERS}

    @property
    def is_saas(self) -> bool:
        return self.provider in {p.value for p in SAAS_PROVIDERS}

    @property
    def is_cis_based(self) -> bool:
        return self.source == "cis"

    @property
    def is_supplementary(self) -> bool:
        return self.source == "scanner"

    @property
    def all_check_ids(self) -> set[str]:
        """Return all check_ids associated with this entry (canonical + scanner)."""
        ids = {self.check_id}
        ids.update(self.scanner_check_ids)
        return ids
