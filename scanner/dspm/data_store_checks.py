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
        {"service": "kms", "label": "AWS KMS", "type": "key_management"},
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
        {"service": "pubsub", "label": "Pub/Sub", "type": "message_queue"},
        {"service": "kms", "label": "Cloud KMS", "type": "key_management"},
        {"service": "dataproc", "label": "Dataproc", "type": "data_processing"},
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


# ═══════════════════════════════════════════════════════════════════
# PROVIDER CHECK → DSPM MAPPING
# Maps actual scanner check_ids to DSPM categories so DSPM can
# surface ALL data-related findings from provider scans.
# ═══════════════════════════════════════════════════════════════════

PROVIDER_DATA_CHECK_MAPPING: dict[str, dict] = {
    # ── AWS Data Checks ─────────────────────────────────────────
    # S3
    "s3_bucket_public_access": {"category": "access", "data_store": "s3", "provider": "aws"},
    "s3_bucket_versioning": {"category": "retention", "data_store": "s3", "provider": "aws"},
    "s3_bucket_encryption": {"category": "encryption", "data_store": "s3", "provider": "aws"},
    "s3_bucket_logging": {"category": "logging", "data_store": "s3", "provider": "aws"},
    "s3_bucket_mfa_delete": {"category": "backup", "data_store": "s3", "provider": "aws"},
    "s3_bucket_ssl_requests": {"category": "encryption", "data_store": "s3", "provider": "aws"},
    "s3_bucket_policy_public": {"category": "access", "data_store": "s3", "provider": "aws"},
    "s3_bucket_acl_public": {"category": "access", "data_store": "s3", "provider": "aws"},
    "s3_bucket_lifecycle": {"category": "retention", "data_store": "s3", "provider": "aws"},
    "s3_bucket_cross_region": {"category": "backup", "data_store": "s3", "provider": "aws"},
    # RDS
    "rds_encryption": {"category": "encryption", "data_store": "rds", "provider": "aws"},
    "rds_public": {"category": "access", "data_store": "rds", "provider": "aws"},
    "rds_multi_az": {"category": "backup", "data_store": "rds", "provider": "aws"},
    "rds_backup_enabled": {"category": "backup", "data_store": "rds", "provider": "aws"},
    "rds_deletion_protection": {"category": "backup", "data_store": "rds", "provider": "aws"},
    "rds_auto_minor_upgrade": {"category": "access", "data_store": "rds", "provider": "aws"},
    "rds_iam_auth": {"category": "access", "data_store": "rds", "provider": "aws"},
    "rds_audit_logging": {"category": "logging", "data_store": "rds", "provider": "aws"},
    # DynamoDB
    "dynamodb_table_encrypted": {"category": "encryption", "data_store": "dynamodb", "provider": "aws"},
    "dynamodb_pitr_enabled": {"category": "backup", "data_store": "dynamodb", "provider": "aws"},
    "dynamodb_deletion_protection": {"category": "backup", "data_store": "dynamodb", "provider": "aws"},
    # EFS
    "efs_encryption": {"category": "encryption", "data_store": "efs", "provider": "aws"},
    # ElastiCache
    "elasticache_encryption_at_rest": {"category": "encryption", "data_store": "elasticache", "provider": "aws"},
    "elasticache_encryption_in_transit": {"category": "encryption", "data_store": "elasticache", "provider": "aws"},
    # Redshift
    "redshift_encryption": {"category": "encryption", "data_store": "redshift", "provider": "aws"},
    "redshift_public": {"category": "access", "data_store": "redshift", "provider": "aws"},
    "redshift_audit_logging": {"category": "logging", "data_store": "redshift", "provider": "aws"},
    # Secrets Manager
    "secretsmanager_rotation": {"category": "access", "data_store": "secretsmanager", "provider": "aws"},
    # OpenSearch
    "opensearch_encryption": {"category": "encryption", "data_store": "elasticsearch", "provider": "aws"},
    "opensearch_public": {"category": "access", "data_store": "elasticsearch", "provider": "aws"},
    "opensearch_logging": {"category": "logging", "data_store": "elasticsearch", "provider": "aws"},

    # ── Azure Data Checks ───────────────────────────────────────
    # Storage
    "azure_storage_encryption": {"category": "encryption", "data_store": "azure_blob", "provider": "azure"},
    "azure_storage_https_only": {"category": "encryption", "data_store": "azure_blob", "provider": "azure"},
    "azure_storage_public_access": {"category": "access", "data_store": "azure_blob", "provider": "azure"},
    "azure_storage_blob_public_access": {"category": "access", "data_store": "azure_blob", "provider": "azure"},
    "azure_storage_soft_delete": {"category": "backup", "data_store": "azure_blob", "provider": "azure"},
    "azure_storage_logging": {"category": "logging", "data_store": "azure_blob", "provider": "azure"},
    "azure_storage_cmk": {"category": "encryption", "data_store": "azure_blob", "provider": "azure"},
    "azure_storage_network_rules": {"category": "access", "data_store": "azure_blob", "provider": "azure"},
    "azure_storage_min_tls": {"category": "encryption", "data_store": "azure_blob", "provider": "azure"},
    "azure_storage_private_endpoint": {"category": "access", "data_store": "azure_blob", "provider": "azure"},
    "azure_storage_immutable_blob": {"category": "retention", "data_store": "azure_blob", "provider": "azure"},
    # SQL
    "azure_sql_tde_enabled": {"category": "encryption", "data_store": "azure_sql", "provider": "azure"},
    "azure_sql_auditing": {"category": "logging", "data_store": "azure_sql", "provider": "azure"},
    "azure_sql_threat_detection": {"category": "logging", "data_store": "azure_sql", "provider": "azure"},
    "azure_sql_public_access": {"category": "access", "data_store": "azure_sql", "provider": "azure"},
    "azure_sql_firewall_rules": {"category": "access", "data_store": "azure_sql", "provider": "azure"},
    "azure_sql_ad_admin": {"category": "access", "data_store": "azure_sql", "provider": "azure"},
    "azure_sql_min_tls": {"category": "encryption", "data_store": "azure_sql", "provider": "azure"},
    "azure_sql_cmk": {"category": "encryption", "data_store": "azure_sql", "provider": "azure"},
    "azure_sql_va_enabled": {"category": "logging", "data_store": "azure_sql", "provider": "azure"},
    "azure_sql_geo_backup": {"category": "backup", "data_store": "azure_sql", "provider": "azure"},
    # Cosmos DB
    "azure_cosmosdb_encryption": {"category": "encryption", "data_store": "cosmosdb", "provider": "azure"},
    "azure_cosmosdb_firewall": {"category": "access", "data_store": "cosmosdb", "provider": "azure"},
    "azure_cosmosdb_private_endpoint": {"category": "access", "data_store": "cosmosdb", "provider": "azure"},
    "azure_cosmosdb_backup": {"category": "backup", "data_store": "cosmosdb", "provider": "azure"},
    # Key Vault
    "azure_keyvault_soft_delete": {"category": "backup", "data_store": "keyvault", "provider": "azure"},
    "azure_keyvault_purge_protection": {"category": "backup", "data_store": "keyvault", "provider": "azure"},
    "azure_keyvault_private_endpoint": {"category": "access", "data_store": "keyvault", "provider": "azure"},
    "azure_keyvault_logging": {"category": "logging", "data_store": "keyvault", "provider": "azure"},
    "azure_keyvault_rbac": {"category": "access", "data_store": "keyvault", "provider": "azure"},
    "azure_keyvault_key_rotation": {"category": "encryption", "data_store": "keyvault", "provider": "azure"},
    "azure_keyvault_key_expiry": {"category": "encryption", "data_store": "keyvault", "provider": "azure"},
    "azure_keyvault_secret_expiry": {"category": "access", "data_store": "keyvault", "provider": "azure"},
    "azure_keyvault_network_acl": {"category": "access", "data_store": "keyvault", "provider": "azure"},

    # ── GCP Data Checks ─────────────────────────────────────────
    # Cloud Storage
    "gcp_storage_no_public_access": {"category": "access", "data_store": "gcs", "provider": "gcp"},
    "gcp_storage_uniform_access": {"category": "access", "data_store": "gcs", "provider": "gcp"},
    "gcp_storage_versioning": {"category": "retention", "data_store": "gcs", "provider": "gcp"},
    "gcp_storage_logging_enabled": {"category": "logging", "data_store": "gcs", "provider": "gcp"},
    "gcp_storage_retention_policy": {"category": "retention", "data_store": "gcs", "provider": "gcp"},
    "gcp_storage_cmek_encryption": {"category": "encryption", "data_store": "gcs", "provider": "gcp"},
    # Cloud SQL
    "gcp_sql_no_public_ip": {"category": "access", "data_store": "cloudsql", "provider": "gcp"},
    "gcp_sql_ssl_required": {"category": "encryption", "data_store": "cloudsql", "provider": "gcp"},
    "gcp_sql_backup_enabled": {"category": "backup", "data_store": "cloudsql", "provider": "gcp"},
    "gcp_sql_pitr_enabled": {"category": "backup", "data_store": "cloudsql", "provider": "gcp"},
    "gcp_sql_no_public_networks": {"category": "access", "data_store": "cloudsql", "provider": "gcp"},
    "gcp_sql_cmek_encryption": {"category": "encryption", "data_store": "cloudsql", "provider": "gcp"},
    "gcp_sql_audit_logging": {"category": "logging", "data_store": "cloudsql", "provider": "gcp"},
    "gcp_sql_auto_storage_increase": {"category": "backup", "data_store": "cloudsql", "provider": "gcp"},
    # BigQuery
    "gcp_bigquery_dataset_no_public": {"category": "access", "data_store": "bigquery", "provider": "gcp"},
    "gcp_bigquery_cmek_encryption": {"category": "encryption", "data_store": "bigquery", "provider": "gcp"},
    "gcp_bigquery_table_encrypted": {"category": "encryption", "data_store": "bigquery", "provider": "gcp"},
    "gcp_bigquery_audit_logging": {"category": "logging", "data_store": "bigquery", "provider": "gcp"},
    "gcp_bigquery_classification": {"category": "classification", "data_store": "bigquery", "provider": "gcp"},
    # Pub/Sub (data in transit)
    "gcp_pubsub_no_public_access": {"category": "access", "data_store": "pubsub", "provider": "gcp"},
    "gcp_pubsub_encrypted": {"category": "encryption", "data_store": "pubsub", "provider": "gcp"},
    # KMS (key management for data)
    "gcp_kms_key_rotation": {"category": "encryption", "data_store": "kms", "provider": "gcp"},
    "gcp_kms_no_public_access": {"category": "access", "data_store": "kms", "provider": "gcp"},
    # Dataproc (data processing)
    "gcp_dataproc_encrypted": {"category": "encryption", "data_store": "dataproc", "provider": "gcp"},
    # Firestore
    "gcp_firestore_cmek": {"category": "encryption", "data_store": "firestore", "provider": "gcp"},
    # Secret Manager
    "gcp_secretmanager_rotation": {"category": "access", "data_store": "secretmanager", "provider": "gcp"},
}


def get_data_check_ids() -> set[str]:
    """Return all check_ids that are data-related across all providers."""
    return set(PROVIDER_DATA_CHECK_MAPPING.keys())


def get_data_checks_for_provider(provider: str) -> dict[str, dict]:
    """Return data check mappings for a specific provider."""
    return {
        cid: info for cid, info in PROVIDER_DATA_CHECK_MAPPING.items()
        if info["provider"] == provider
    }


def get_data_checks_by_category(category: str) -> dict[str, dict]:
    """Return data check mappings for a specific DSPM category."""
    return {
        cid: info for cid, info in PROVIDER_DATA_CHECK_MAPPING.items()
        if info["category"] == category
    }


def get_data_checks_by_store(data_store: str) -> dict[str, dict]:
    """Return data check mappings for a specific data store type."""
    return {
        cid: info for cid, info in PROVIDER_DATA_CHECK_MAPPING.items()
        if info["data_store"] == data_store
    }
