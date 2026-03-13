"""Compliance framework definitions and check mappings."""

FRAMEWORKS = {
    "CIS-AWS-1.5": {
        "name": "CIS Amazon Web Services Foundations Benchmark v1.5",
        "description": "Center for Internet Security AWS benchmark",
        "checks": [
            "iam_root_mfa_enabled", "iam_password_policy_strong", "iam_password_policy_rotation",
            "iam_user_mfa_enabled", "iam_access_key_rotation", "s3_bucket_public_access_blocked",
            "s3_bucket_encryption_enabled", "s3_bucket_logging_enabled", "ec2_sg_open_port_22",
            "ec2_sg_open_port_3389", "ec2_ebs_volume_encrypted", "ec2_imdsv2_required",
            "rds_encryption_enabled", "rds_public_access_disabled", "cloudtrail_multiregion",
            "cloudtrail_log_validation", "cloudtrail_encrypted", "kms_key_rotation_enabled",
            "vpc_flow_logs_enabled", "guardduty_enabled", "config_recorder_enabled",
            "eks_cluster_logging", "eks_endpoint_public_access",
        ],
    },
    "CIS-Azure-2.0": {
        "name": "CIS Microsoft Azure Foundations Benchmark v2.0",
        "description": "Center for Internet Security Azure benchmark",
        "checks": [
            "azure_iam_owner_count", "azure_storage_https_only", "azure_storage_tls_12",
            "azure_storage_no_public_access", "azure_nsg_open_port_22", "azure_nsg_open_port_3389",
            "azure_network_watcher_enabled", "azure_vm_disk_encryption", "azure_sql_auditing_enabled",
            "azure_sql_tls_12", "azure_keyvault_soft_delete", "azure_keyvault_purge_protection",
            "azure_monitor_log_profile", "azure_appservice_https_only", "azure_appservice_tls_12",
        ],
    },
    "CIS-GCP-2.0": {
        "name": "CIS Google Cloud Platform Foundation Benchmark v2.0",
        "description": "Center for Internet Security GCP benchmark",
        "checks": [
            "gcp_iam_no_public_access", "gcp_compute_no_external_ip", "gcp_compute_os_login",
            "gcp_storage_uniform_access", "gcp_sql_no_public_ip", "gcp_sql_ssl_required",
            "gcp_kms_key_rotation", "gcp_gke_private_cluster", "gcp_gke_network_policy",
            "gcp_firewall_open_22", "gcp_firewall_open_3389",
        ],
    },
    "NIST-800-53": {
        "name": "NIST SP 800-53 Rev. 5",
        "description": "Security and Privacy Controls for Information Systems",
        "checks": "all",
    },
    "NIST-CSF": {
        "name": "NIST Cybersecurity Framework",
        "description": "Framework for Improving Critical Infrastructure Cybersecurity",
        "checks": "all_saas",
    },
    "ISO-27001": {
        "name": "ISO/IEC 27001:2022",
        "description": "Information security management systems",
        "checks": "all_saas",
    },
    "PCI-DSS-3.2.1": {
        "name": "PCI DSS v3.2.1",
        "description": "Payment Card Industry Data Security Standard",
        "checks": [
            "iam_root_mfa_enabled", "iam_user_mfa_enabled", "s3_bucket_public_access_blocked",
            "s3_bucket_encryption_enabled", "s3_bucket_logging_enabled",
            "rds_encryption_enabled", "rds_public_access_disabled",
            "cloudtrail_log_validation", "cloudtrail_encrypted",
            "kms_key_rotation_enabled", "vpc_flow_logs_enabled", "guardduty_enabled",
        ],
    },
    "HIPAA": {
        "name": "HIPAA Security Rule",
        "description": "Health Insurance Portability and Accountability Act",
        "checks": [
            "s3_bucket_encryption_enabled", "ec2_ebs_volume_encrypted",
            "rds_encryption_enabled", "rds_backup_enabled",
            "cloudtrail_encrypted", "sns_topic_encrypted", "sqs_queue_encrypted",
            "efs_encryption_enabled", "dynamodb_table_encrypted_kms",
        ],
    },
    "SOC2": {
        "name": "SOC 2 Type II",
        "description": "Service Organization Control 2",
        "checks": [
            "s3_bucket_versioning_enabled", "rds_multi_az_enabled", "rds_backup_enabled",
            "secretsmanager_rotation_enabled", "dynamodb_pitr_enabled",
            "cloudwatch_log_group_retention",
        ],
    },
    "GDPR": {
        "name": "GDPR",
        "description": "General Data Protection Regulation",
        "checks": [
            "s3_bucket_encryption_enabled", "rds_encryption_enabled",
            "ec2_ebs_volume_encrypted", "cloudtrail_encrypted",
        ],
    },
}
