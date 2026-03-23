"""DSPM data store security checks across cloud providers.

Checks data stores (S3, RDS, Azure Blob, BigQuery, etc.) for:
- Encryption at rest and in transit
- Public exposure / access policies
- Data classification presence
- Retention policies
- Backup configuration
- Access logging
"""
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DSPMCheckResult:
    check_id: str
    check_title: str
    data_store_type: str  # s3, rds, azure_blob, bigquery, gcs, etc.
    provider: str  # aws, azure, gcp
    resource_id: str
    resource_name: str
    status: str  # PASS, FAIL, WARNING
    severity: str  # critical, high, medium, low, informational
    category: str  # encryption, access, classification, retention, backup, logging
    description: str
    remediation: str
    data_classification: Optional[str] = None  # public, internal, confidential, restricted
    has_pii_risk: bool = False
    region: Optional[str] = None
    evidence: Optional[dict] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════
# DATA STORE REGISTRY — Maps provider data services to their checks
# ═══════════════════════════════════════════════════════════════════

DATA_STORE_TYPES = {
    "aws": [
        {"service": "s3", "label": "Amazon S3", "type": "object_storage"},
        {"service": "rds", "label": "Amazon RDS", "type": "relational_db"},
        {"service": "dynamodb", "label": "Amazon DynamoDB", "type": "nosql_db"},
        {"service": "redshift", "label": "Amazon Redshift", "type": "data_warehouse"},
        {"service": "efs", "label": "Amazon EFS", "type": "file_storage"},
        {"service": "elasticache", "label": "Amazon ElastiCache", "type": "cache"},
        {"service": "secretsmanager", "label": "AWS Secrets Manager", "type": "secrets"},
        {"service": "elasticsearch", "label": "Amazon OpenSearch", "type": "search_engine"},
    ],
    "azure": [
        {"service": "azure_blob", "label": "Azure Blob Storage", "type": "object_storage"},
        {"service": "azure_sql", "label": "Azure SQL Database", "type": "relational_db"},
        {"service": "cosmosdb", "label": "Azure Cosmos DB", "type": "nosql_db"},
        {"service": "azure_files", "label": "Azure Files", "type": "file_storage"},
        {"service": "keyvault", "label": "Azure Key Vault", "type": "secrets"},
    ],
    "gcp": [
        {"service": "gcs", "label": "Google Cloud Storage", "type": "object_storage"},
        {"service": "cloudsql", "label": "Cloud SQL", "type": "relational_db"},
        {"service": "bigquery", "label": "BigQuery", "type": "data_warehouse"},
        {"service": "firestore", "label": "Firestore", "type": "nosql_db"},
        {"service": "secretmanager", "label": "Secret Manager", "type": "secrets"},
    ],
}


# ═══════════════════════════════════════════════════════════════════
# CHECK DEFINITIONS — Security checks for data stores
# ═══════════════════════════════════════════════════════════════════

DSPM_CHECKS = [
    # ── Encryption ──────────────────────────────────────────────
    {
        "check_id": "dspm_encryption_at_rest",
        "title": "Data store encryption at rest",
        "category": "encryption",
        "severity": "high",
        "description": "Ensure all data stores have encryption at rest enabled using KMS or platform-managed keys.",
        "remediation": "Enable server-side encryption with customer-managed or platform-managed keys.",
        "applies_to": ["object_storage", "relational_db", "nosql_db", "data_warehouse", "file_storage", "cache", "search_engine"],
    },
    {
        "check_id": "dspm_encryption_in_transit",
        "title": "Data store encryption in transit",
        "category": "encryption",
        "severity": "high",
        "description": "Ensure all data store connections require TLS/SSL encryption.",
        "remediation": "Enable SSL/TLS enforcement on all data store connections and set minimum TLS version to 1.2.",
        "applies_to": ["relational_db", "nosql_db", "data_warehouse", "cache", "search_engine"],
    },
    {
        "check_id": "dspm_cmk_encryption",
        "title": "Customer-managed key encryption",
        "category": "encryption",
        "severity": "medium",
        "description": "Data stores containing sensitive data should use customer-managed keys (CMK) rather than platform-managed keys.",
        "remediation": "Configure customer-managed encryption keys via KMS/Key Vault for sensitive data stores.",
        "applies_to": ["object_storage", "relational_db", "data_warehouse", "secrets"],
    },

    # ── Access Control ──────────────────────────────────────────
    {
        "check_id": "dspm_public_access",
        "title": "Data store public access disabled",
        "category": "access",
        "severity": "critical",
        "description": "Data stores should not be publicly accessible from the internet.",
        "remediation": "Disable public access and restrict access to private networks or specific IP ranges.",
        "applies_to": ["object_storage", "relational_db", "nosql_db", "data_warehouse", "file_storage"],
    },
    {
        "check_id": "dspm_overly_permissive_policy",
        "title": "Data store access policy not overly permissive",
        "category": "access",
        "severity": "high",
        "description": "Data store access policies should follow least privilege and not grant wildcard access.",
        "remediation": "Review and restrict access policies to specific principals and actions.",
        "applies_to": ["object_storage", "relational_db", "nosql_db", "data_warehouse"],
    },
    {
        "check_id": "dspm_cross_account_access",
        "title": "Cross-account access controlled",
        "category": "access",
        "severity": "medium",
        "description": "Cross-account access to data stores should be explicitly authorized and documented.",
        "remediation": "Review cross-account resource policies and ensure only trusted accounts have access.",
        "applies_to": ["object_storage", "relational_db", "data_warehouse"],
    },

    # ── Data Classification ─────────────────────────────────────
    {
        "check_id": "dspm_classification_tag",
        "title": "Data classification tag present",
        "category": "classification",
        "severity": "medium",
        "description": "All data stores should have a data classification tag (public, internal, confidential, restricted).",
        "remediation": "Add a 'DataClassification' or 'data-classification' tag to all data stores.",
        "applies_to": ["object_storage", "relational_db", "nosql_db", "data_warehouse", "file_storage"],
    },
    {
        "check_id": "dspm_pii_detection",
        "title": "PII/sensitive data detection configured",
        "category": "classification",
        "severity": "high",
        "description": "Data stores should have sensitive data detection configured (Macie, Purview, DLP).",
        "remediation": "Enable Amazon Macie, Azure Purview, or GCP DLP for automated PII/sensitive data discovery.",
        "applies_to": ["object_storage", "relational_db", "data_warehouse"],
    },

    # ── Retention & Lifecycle ───────────────────────────────────
    {
        "check_id": "dspm_retention_policy",
        "title": "Data retention policy configured",
        "category": "retention",
        "severity": "medium",
        "description": "Data stores should have lifecycle/retention policies to prevent unbounded data growth and ensure compliance.",
        "remediation": "Configure lifecycle policies with appropriate retention periods based on data classification.",
        "applies_to": ["object_storage", "relational_db", "nosql_db", "data_warehouse"],
    },
    {
        "check_id": "dspm_versioning_enabled",
        "title": "Object versioning enabled",
        "category": "retention",
        "severity": "low",
        "description": "Object storage should have versioning enabled for data protection and recovery.",
        "remediation": "Enable versioning on object storage buckets/containers.",
        "applies_to": ["object_storage"],
    },

    # ── Backup & Recovery ───────────────────────────────────────
    {
        "check_id": "dspm_backup_configured",
        "title": "Automated backups configured",
        "category": "backup",
        "severity": "high",
        "description": "Database data stores should have automated backups with appropriate retention.",
        "remediation": "Enable automated backups with at least 7-day retention and test restore procedures.",
        "applies_to": ["relational_db", "nosql_db", "data_warehouse"],
    },
    {
        "check_id": "dspm_pitr_enabled",
        "title": "Point-in-time recovery enabled",
        "category": "backup",
        "severity": "medium",
        "description": "Databases should support point-in-time recovery for granular restore capability.",
        "remediation": "Enable PITR for all production databases.",
        "applies_to": ["relational_db", "nosql_db"],
    },

    # ── Logging & Monitoring ────────────────────────────────────
    {
        "check_id": "dspm_access_logging",
        "title": "Data access logging enabled",
        "category": "logging",
        "severity": "high",
        "description": "Data stores should have access logging enabled for audit and incident response.",
        "remediation": "Enable access logging (S3 server access logs, database audit logs, storage analytics).",
        "applies_to": ["object_storage", "relational_db", "nosql_db", "data_warehouse", "file_storage", "secrets"],
    },
    {
        "check_id": "dspm_deletion_protection",
        "title": "Deletion protection enabled",
        "category": "backup",
        "severity": "medium",
        "description": "Critical data stores should have deletion protection to prevent accidental data loss.",
        "remediation": "Enable deletion protection / soft delete on data stores containing important data.",
        "applies_to": ["relational_db", "nosql_db", "secrets"],
    },
]


def get_dspm_checks_for_provider(provider: str) -> list[dict]:
    """Return DSPM checks applicable to a specific cloud provider."""
    store_types = DATA_STORE_TYPES.get(provider, [])
    type_set = {s["type"] for s in store_types}

    checks = []
    for check in DSPM_CHECKS:
        applies_to = set(check["applies_to"])
        if applies_to & type_set:
            checks.append(check)
    return checks


def get_dspm_data_stores(provider: str) -> list[dict]:
    """Return data store types for a provider."""
    return DATA_STORE_TYPES.get(provider, [])


def get_all_dspm_check_ids() -> list[str]:
    """Return all DSPM check IDs."""
    return [c["check_id"] for c in DSPM_CHECKS]
