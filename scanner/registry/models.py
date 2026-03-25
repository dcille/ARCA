"""Data models for the check registry."""

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

    This is the canonical definition — every check_id used by scanners,
    MITRE mappings, or Ransomware Readiness rules should exist here.
    """

    check_id: str
    title: str
    description: str
    severity: str
    provider: str
    service: str
    category: str
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    compliance_mappings: list[str] = field(default_factory=list)
    # CIS benchmark linkage
    cis_control_id: Optional[str] = None
    cis_level: Optional[str] = None
    cis_profile: Optional[str] = None
    # Assessment type
    assessment_type: str = "automated"  # automated | manual

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
        return (
            f"[{self.severity.upper():>13s}] {self.check_id:<40s} "
            f"({self.provider}/{self.service}) - {self.title}"
        )

    @property
    def is_cloud(self) -> bool:
        return self.provider in {p.value for p in CLOUD_PROVIDERS}

    @property
    def is_saas(self) -> bool:
        return self.provider in {p.value for p in SAAS_PROVIDERS}
