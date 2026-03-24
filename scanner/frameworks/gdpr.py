"""GDPR -- General Data Protection Regulation (EU) 2016/679.

Comprehensive compliance framework mapping GDPR articles and recitals to
cloud security checks across AWS, Azure, GCP, OCI, Alibaba Cloud and
Kubernetes.
"""

FRAMEWORK = {
    "GDPR": {
        "name": "General Data Protection Regulation (EU) 2016/679",
        "description": (
            "European Union regulation on data protection and privacy for all "
            "individuals within the EU and EEA. It addresses the transfer of "
            "personal data outside the EU and EEA areas."
        ),
        "category": "regulatory",
        "controls": [
            # ── Chapter II: Principles ────────────────────────────────────
            {
                "id": "Art.5(1)(a)",
                "title": "Lawfulness, fairness and transparency",
                "description": (
                    "Personal data shall be processed lawfully, fairly and in "
                    "a transparent manner in relation to the data subject."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation"],
                    "azure": ["azure_monitor_log_profile", "azure_monitor_diagnostic_settings"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_logging_sinks_configured"],
                },
            },
            {
                "id": "Art.5(1)(b)",
                "title": "Purpose limitation",
                "description": (
                    "Personal data shall be collected for specified, explicit and "
                    "legitimate purposes and not further processed in a manner "
                    "incompatible with those purposes."
                ),
                "checks": {
                    "aws": ["iam_no_star_policies", "iam_user_no_attached_policies"],
                    "azure": ["azure_iam_no_custom_owner_roles", "azure_policy_assignments_exist"],
                    "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_separation_of_duties"],
                },
            },
            {
                "id": "Art.5(1)(c)",
                "title": "Data minimisation",
                "description": (
                    "Personal data shall be adequate, relevant and limited to "
                    "what is necessary in relation to the purposes for which "
                    "they are processed."
                ),
                "checks": {
                    "aws": ["s3_bucket_public_access_blocked", "rds_public_access_disabled", "macie_enabled"],
                    "azure": ["azure_storage_no_public_access", "azure_sql_public_access_disabled"],
                    "gcp": ["gcp_storage_no_public_access", "gcp_sql_no_public_ip", "gcp_bigquery_dataset_no_public"],
                },
            },
            {
                "id": "Art.5(1)(d)",
                "title": "Accuracy",
                "description": (
                    "Personal data shall be accurate and, where necessary, kept "
                    "up to date; every reasonable step must be taken to ensure "
                    "that inaccurate data is erased or rectified without delay."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "cloudtrail_multiregion"],
                    "azure": ["azure_monitor_diagnostic_settings"],
                    "gcp": ["gcp_logging_cloud_asset_inventory"],
                },
            },
            {
                "id": "Art.5(1)(e)",
                "title": "Storage limitation",
                "description": (
                    "Personal data shall be kept in a form which permits "
                    "identification of data subjects for no longer than is "
                    "necessary for the purposes for which the data is processed."
                ),
                "checks": {
                    "aws": ["cloudwatch_log_group_retention", "s3_bucket_object_lock"],
                    "azure": ["azure_monitor_log_retention_365", "azure_storage_soft_delete_blobs"],
                    "gcp": ["gcp_logging_bucket_retention", "gcp_storage_retention_policy"],
                },
            },
            {
                "id": "Art.5(1)(f)",
                "title": "Integrity and confidentiality",
                "description": (
                    "Personal data shall be processed in a manner that ensures "
                    "appropriate security, including protection against "
                    "unauthorised or unlawful processing and against accidental "
                    "loss, destruction or damage."
                ),
                "checks": {
                    "aws": [
                        "s3_bucket_encryption_enabled", "ec2_ebs_volume_encrypted",
                        "rds_encryption_enabled", "cloudtrail_encrypted",
                        "kms_key_rotation_enabled", "efs_encryption_enabled",
                    ],
                    "azure": [
                        "azure_vm_disk_encryption", "azure_storage_https_only",
                        "azure_storage_tls_12", "azure_storage_infrastructure_encryption",
                    ],
                    "gcp": [
                        "gcp_kms_key_rotation", "gcp_sql_ssl_required",
                        "gcp_storage_uniform_access", "gcp_storage_cmek_encryption",
                    ],
                    "oci": ["oci_vault_key_rotation", "oci_objectstorage_bucket_cmk_encryption"],
                    "alibaba": ["alibaba_storage_oss_encryption_enabled", "alibaba_kms_key_rotation_enabled"],
                },
            },
            {
                "id": "Art.5(2)",
                "title": "Accountability",
                "description": (
                    "The controller shall be responsible for, and be able to "
                    "demonstrate compliance with, the data protection principles."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "config_recorder_enabled", "securityhub_enabled"],
                    "azure": ["azure_policy_assignments_exist", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_logging_sinks_configured"],
                },
            },
            # ── Chapter III: Rights of the data subject ───────────────────
            {
                "id": "Art.12",
                "title": "Transparent information and communication",
                "description": (
                    "The controller shall take appropriate measures to provide "
                    "information relating to processing in a concise, transparent, "
                    "intelligible and easily accessible form."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation"],
                    "azure": ["azure_monitor_log_profile"],
                    "gcp": ["gcp_logging_audit_logs_enabled"],
                },
            },
            {
                "id": "Art.15",
                "title": "Right of access by the data subject",
                "description": (
                    "The data subject shall have the right to obtain from the "
                    "controller confirmation as to whether personal data "
                    "concerning them is being processed."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "macie_enabled"],
                    "azure": ["azure_monitor_diagnostic_settings"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_bigquery_classification"],
                },
            },
            {
                "id": "Art.17",
                "title": "Right to erasure (right to be forgotten)",
                "description": (
                    "The data subject shall have the right to obtain from the "
                    "controller the erasure of personal data without undue delay."
                ),
                "checks": {
                    "aws": ["s3_bucket_versioning_enabled", "cloudwatch_log_group_retention"],
                    "azure": ["azure_storage_soft_delete_blobs"],
                    "gcp": ["gcp_storage_retention_policy", "gcp_logging_bucket_retention"],
                },
            },
            {
                "id": "Art.20",
                "title": "Right to data portability",
                "description": (
                    "The data subject shall have the right to receive personal "
                    "data in a structured, commonly used and machine-readable "
                    "format."
                ),
                "checks": {
                    "aws": ["s3_bucket_encryption_enabled", "s3_bucket_logging_enabled"],
                    "azure": ["azure_storage_https_only"],
                    "gcp": ["gcp_storage_uniform_access"],
                },
            },
            # ── Chapter IV: Controller and processor ──────────────────────
            {
                "id": "Art.24",
                "title": "Responsibility of the controller",
                "description": (
                    "The controller shall implement appropriate technical and "
                    "organisational measures to ensure and demonstrate that "
                    "processing is performed in accordance with this Regulation."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "securityhub_enabled", "guardduty_enabled"],
                    "azure": [
                        "azure_policy_assignments_exist", "azure_policy_security_initiative",
                        "azure_defender_auto_provisioning",
                    ],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_logging_sinks_configured"],
                    "oci": ["oci_cloud_guard_enabled"],
                },
            },
            {
                "id": "Art.25(1)",
                "title": "Data protection by design",
                "description": (
                    "The controller shall implement appropriate technical and "
                    "organisational measures designed to implement data protection "
                    "principles in an effective manner."
                ),
                "checks": {
                    "aws": [
                        "s3_bucket_public_access_blocked", "rds_public_access_disabled",
                        "ec2_sg_open_port_22", "ec2_sg_open_port_3389",
                        "ec2_imdsv2_required",
                    ],
                    "azure": [
                        "azure_storage_no_public_access", "azure_nsg_unrestricted_port_22",
                        "azure_nsg_unrestricted_port_3389", "azure_private_endpoints_used",
                    ],
                    "gcp": [
                        "gcp_iam_no_public_access", "gcp_compute_no_external_ip",
                        "gcp_gke_private_cluster",
                    ],
                    "kubernetes": ["k8s_namespace_network_policy", "k8s_network_deny_all_default"],
                },
            },
            {
                "id": "Art.25(2)",
                "title": "Data protection by default",
                "description": (
                    "The controller shall implement appropriate technical and "
                    "organisational measures for ensuring that, by default, only "
                    "personal data which are necessary for each specific purpose "
                    "of the processing are processed."
                ),
                "checks": {
                    "aws": [
                        "iam_no_star_policies", "vpc_default_sg_restricts_all",
                        "ec2_default_sg_no_traffic",
                    ],
                    "azure": [
                        "azure_nsg_default_deny_inbound", "azure_storage_network_default_deny",
                        "azure_storage_shared_key_disabled",
                    ],
                    "gcp": [
                        "gcp_network_no_default_network", "gcp_compute_no_default_sa",
                        "gcp_compute_no_full_api_access",
                    ],
                    "kubernetes": ["k8s_rbac_no_wildcard_verbs", "k8s_rbac_no_wildcard_cluster_admin"],
                },
            },
            {
                "id": "Art.28",
                "title": "Processor obligations",
                "description": (
                    "Processing by a processor shall be governed by a contract "
                    "that sets out the subject-matter and duration of the "
                    "processing, the nature and purpose of the processing."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "config_recorder_enabled"],
                    "azure": ["azure_policy_assignments_exist"],
                    "gcp": ["gcp_logging_audit_logs_enabled"],
                },
            },
            {
                "id": "Art.30",
                "title": "Records of processing activities",
                "description": (
                    "Each controller shall maintain a record of processing "
                    "activities under its responsibility."
                ),
                "checks": {
                    "aws": [
                        "cloudtrail_multiregion", "cloudtrail_log_validation",
                        "cloudtrail_s3_bucket_logging",
                    ],
                    "azure": ["azure_monitor_log_profile", "azure_monitor_log_retention_365"],
                    "gcp": [
                        "gcp_logging_audit_logs_enabled", "gcp_logging_sinks_configured",
                        "gcp_logging_bucket_retention",
                    ],
                    "oci": ["oci_logging_log_groups_exist", "oci_logging_audit_retention"],
                },
            },
            # ── Chapter IV, Section 2: Security of personal data ──────────
            {
                "id": "Art.32(1)(a)",
                "title": "Pseudonymisation and encryption of personal data",
                "description": (
                    "The controller and processor shall implement appropriate "
                    "measures including the pseudonymisation and encryption of "
                    "personal data."
                ),
                "checks": {
                    "aws": [
                        "s3_bucket_encryption_enabled", "ec2_ebs_volume_encrypted",
                        "rds_encryption_enabled", "efs_encryption_enabled",
                        "kms_key_rotation_enabled",
                    ],
                    "azure": [
                        "azure_vm_disk_encryption", "azure_sql_tde_enabled",
                        "azure_storage_infrastructure_encryption", "azure_storage_cmk_encryption",
                    ],
                    "gcp": [
                        "gcp_kms_key_rotation", "gcp_storage_cmek_encryption",
                        "gcp_bigquery_cmek_encryption", "gcp_dataproc_encrypted",
                    ],
                    "oci": ["oci_objectstorage_bucket_cmk_encryption", "oci_filestorage_cmk_encryption"],
                    "alibaba": ["alibaba_storage_oss_encryption_enabled", "alibaba_database_rds_encryption_enabled"],
                },
            },
            {
                "id": "Art.32(1)(b)",
                "title": "Ensure ongoing confidentiality, integrity, availability and resilience",
                "description": (
                    "The ability to ensure the ongoing confidentiality, integrity, "
                    "availability and resilience of processing systems and services."
                ),
                "checks": {
                    "aws": [
                        "iam_root_mfa_enabled", "iam_user_mfa_enabled",
                        "rds_multi_az_enabled", "rds_backup_enabled",
                        "vpc_flow_logs_enabled", "guardduty_enabled",
                    ],
                    "azure": [
                        "azure_iam_mfa_enabled_all_users", "azure_iam_owner_count",
                        "azure_backup_vault_exists", "azure_backup_vault_redundancy",
                        "azure_defender_vm",
                    ],
                    "gcp": [
                        "gcp_sql_backup_enabled", "gcp_gke_private_cluster",
                        "gcp_network_flow_logs_enabled",
                    ],
                    "oci": ["oci_iam_user_mfa_enabled", "oci_iam_admin_mfa_enabled", "oci_cloud_guard_enabled"],
                    "alibaba": ["alibaba_iam_ram_root_mfa_enabled", "alibaba_iam_ram_user_mfa_enabled"],
                },
            },
            {
                "id": "Art.32(1)(c)",
                "title": "Ability to restore availability and access to personal data",
                "description": (
                    "The ability to restore the availability and access to "
                    "personal data in a timely manner in the event of a physical "
                    "or technical incident."
                ),
                "checks": {
                    "aws": [
                        "rds_backup_enabled", "rds_multi_az_enabled",
                        "backup_plan_exists", "dynamodb_pitr_enabled",
                        "s3_bucket_versioning_enabled",
                    ],
                    "azure": [
                        "azure_backup_vault_exists", "azure_backup_vault_redundancy",
                        "azure_keyvault_soft_delete", "azure_keyvault_purge_protection",
                    ],
                    "gcp": ["gcp_sql_backup_enabled", "gcp_sql_pitr_enabled"],
                },
            },
            {
                "id": "Art.32(1)(d)",
                "title": "Process for regularly testing, assessing and evaluating security",
                "description": (
                    "A process for regularly testing, assessing and evaluating "
                    "the effectiveness of technical and organisational measures "
                    "for ensuring the security of the processing."
                ),
                "checks": {
                    "aws": ["securityhub_enabled", "guardduty_enabled", "config_recorder_enabled"],
                    "azure": [
                        "azure_defender_auto_provisioning", "azure_sql_vulnerability_assessment",
                        "azure_policy_compliance_rate",
                    ],
                    "gcp": ["gcp_logging_audit_logs_enabled"],
                    "oci": ["oci_cloud_guard_enabled"],
                },
            },
            {
                "id": "Art.32(2)",
                "title": "Risk-appropriate security measures",
                "description": (
                    "In assessing the appropriate level of security, account "
                    "shall be taken of the risks presented by processing, in "
                    "particular from accidental or unlawful destruction, loss, "
                    "alteration, unauthorised disclosure of, or access to "
                    "personal data."
                ),
                "checks": {
                    "aws": [
                        "ec2_sg_open_port_22", "ec2_sg_open_port_3389",
                        "vpc_flow_logs_enabled", "waf_web_acl_exists",
                    ],
                    "azure": [
                        "azure_nsg_unrestricted_port_22", "azure_nsg_unrestricted_port_3389",
                        "azure_nsg_flow_logs_enabled", "azure_appgw_waf_enabled",
                    ],
                    "gcp": [
                        "gcp_firewall_open_22", "gcp_firewall_open_3389",
                        "gcp_logging_vpc_flow_logs",
                    ],
                },
            },
            # ── Chapter IV, Section 2: Notification ───────────────────────
            {
                "id": "Art.33(1)",
                "title": "Notification of breach to supervisory authority",
                "description": (
                    "In the case of a personal data breach, the controller shall "
                    "without undue delay and, where feasible, not later than 72 "
                    "hours after having become aware of it, notify the personal "
                    "data breach to the supervisory authority."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "securityhub_enabled", "cloudtrail_multiregion"],
                    "azure": [
                        "azure_security_contact_configured", "azure_security_alert_notifications",
                        "azure_monitor_log_profile",
                    ],
                    "gcp": ["gcp_iam_essential_contacts", "gcp_logging_audit_logs_enabled"],
                    "oci": ["oci_notifications_topic_configured", "oci_notifications_security_topic_exists"],
                },
            },
            {
                "id": "Art.33(3)",
                "title": "Content of breach notification",
                "description": (
                    "The notification shall describe the nature of the personal "
                    "data breach, the categories and approximate number of data "
                    "subjects concerned, and the likely consequences."
                ),
                "checks": {
                    "aws": [
                        "cloudtrail_multiregion", "cloudtrail_log_validation",
                        "cloudtrail_integrated_cloudwatch",
                    ],
                    "azure": ["azure_monitor_diagnostic_settings", "azure_sql_auditing_enabled"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_logging_sinks_configured"],
                },
            },
            {
                "id": "Art.34",
                "title": "Communication of breach to data subject",
                "description": (
                    "When the personal data breach is likely to result in a high "
                    "risk to the rights and freedoms of natural persons, the "
                    "controller shall communicate the breach to the data subject "
                    "without undue delay."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "securityhub_enabled"],
                    "azure": ["azure_security_alert_notifications", "azure_security_contact_configured"],
                    "gcp": ["gcp_iam_essential_contacts"],
                },
            },
            # ── Chapter IV, Section 3: DPIA ───────────────────────────────
            {
                "id": "Art.35",
                "title": "Data protection impact assessment",
                "description": (
                    "Where a type of processing is likely to result in a high "
                    "risk to the rights and freedoms of natural persons, the "
                    "controller shall carry out an assessment of the impact of "
                    "the envisaged processing operations."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "securityhub_enabled", "macie_enabled"],
                    "azure": [
                        "azure_policy_assignments_exist", "azure_policy_security_initiative",
                        "azure_defender_auto_provisioning",
                    ],
                    "gcp": ["gcp_logging_cloud_asset_inventory"],
                },
            },
            # ── Chapter V: Transfers ──────────────────────────────────────
            {
                "id": "Art.44",
                "title": "General principle for transfers to third countries",
                "description": (
                    "Any transfer of personal data to a third country or "
                    "international organisation shall take place only under "
                    "conditions laid down in this Chapter."
                ),
                "checks": {
                    "aws": ["vpc_flow_logs_enabled", "s3_bucket_ssl_required"],
                    "azure": ["azure_storage_https_only", "azure_storage_tls_12"],
                    "gcp": ["gcp_sql_ssl_required", "gcp_network_ssl_policy"],
                },
            },
            {
                "id": "Art.46",
                "title": "Transfers subject to appropriate safeguards",
                "description": (
                    "A transfer of personal data to a third country may take "
                    "place where the controller or processor has provided "
                    "appropriate safeguards including encryption in transit."
                ),
                "checks": {
                    "aws": [
                        "s3_bucket_ssl_required", "cloudfront_https_only",
                        "ec2_imdsv2_required",
                    ],
                    "azure": [
                        "azure_appservice_https_only", "azure_appservice_tls_12",
                        "azure_sql_tls_12",
                    ],
                    "gcp": ["gcp_sql_ssl_required", "gcp_network_ssl_policy"],
                },
            },
            # ── Additional technical controls derived from GDPR ───────────
            {
                "id": "Art.5(1)(f)-net",
                "title": "Network-level integrity controls",
                "description": (
                    "Network security controls to protect against unauthorised "
                    "access to systems processing personal data."
                ),
                "checks": {
                    "aws": [
                        "ec2_sg_open_port_22", "ec2_sg_open_port_3389",
                        "vpc_no_unrestricted_nacl", "vpc_default_sg_restricts_all",
                    ],
                    "azure": [
                        "azure_nsg_unrestricted_port_22", "azure_nsg_unrestricted_port_3389",
                        "azure_nsg_default_deny_inbound", "azure_subnet_has_nsg",
                    ],
                    "gcp": [
                        "gcp_firewall_open_22", "gcp_firewall_open_3389",
                        "gcp_network_no_legacy_network",
                    ],
                    "kubernetes": [
                        "k8s_namespace_network_policy", "k8s_network_deny_all_default",
                        "k8s_network_ingress_rules",
                    ],
                },
            },
            {
                "id": "Art.5(1)(f)-iam",
                "title": "Identity and access management controls",
                "description": (
                    "Strong authentication and least-privilege access controls "
                    "to protect personal data from unauthorised access."
                ),
                "checks": {
                    "aws": [
                        "iam_root_mfa_enabled", "iam_user_mfa_enabled",
                        "iam_access_key_rotation", "iam_password_policy_strong",
                        "iam_no_star_policies", "iam_no_root_access_key",
                    ],
                    "azure": [
                        "azure_iam_mfa_enabled_all_users", "azure_iam_owner_count",
                        "azure_classic_admins_removed", "azure_iam_guest_users_reviewed",
                    ],
                    "gcp": [
                        "gcp_iam_no_public_access", "gcp_iam_no_primitive_roles",
                        "gcp_iam_separation_of_duties", "gcp_iam_corp_login_required",
                    ],
                    "oci": [
                        "oci_iam_user_mfa_enabled", "oci_iam_admin_mfa_enabled",
                        "oci_iam_policy_no_wildcard", "oci_iam_api_key_rotation",
                    ],
                    "alibaba": [
                        "alibaba_iam_ram_root_mfa_enabled", "alibaba_iam_ram_user_mfa_enabled",
                        "alibaba_iam_ram_no_wildcard_policy",
                    ],
                },
            },
            {
                "id": "Art.5(1)(f)-log",
                "title": "Logging and monitoring of data processing",
                "description": (
                    "Comprehensive logging and monitoring to detect, investigate "
                    "and respond to incidents involving personal data."
                ),
                "checks": {
                    "aws": [
                        "cloudtrail_multiregion", "cloudtrail_log_validation",
                        "cloudtrail_encrypted", "cloudwatch_log_group_retention",
                        "vpc_flow_logs_enabled", "s3_bucket_logging_enabled",
                    ],
                    "azure": [
                        "azure_monitor_log_profile", "azure_monitor_log_retention_365",
                        "azure_monitor_diagnostic_settings", "azure_nsg_flow_logs_enabled",
                        "azure_appservice_http_logging",
                    ],
                    "gcp": [
                        "gcp_logging_audit_logs_enabled", "gcp_logging_sinks_configured",
                        "gcp_logging_bucket_retention", "gcp_logging_vpc_flow_logs",
                        "gcp_logging_dns_logging",
                    ],
                    "oci": [
                        "oci_logging_log_groups_exist", "oci_logging_audit_retention",
                        "oci_network_vcn_flow_logs",
                    ],
                    "alibaba": [
                        "alibaba_logging_actiontrail_enabled",
                        "alibaba_logging_sls_audit_enabled",
                    ],
                },
            },
            {
                "id": "Art.5(1)(f)-enc-transit",
                "title": "Encryption in transit",
                "description": (
                    "All personal data transmitted over networks shall be "
                    "encrypted using strong, up-to-date cryptographic protocols."
                ),
                "checks": {
                    "aws": [
                        "s3_bucket_ssl_required", "cloudfront_https_only",
                        "ec2_imdsv2_required",
                    ],
                    "azure": [
                        "azure_storage_https_only", "azure_storage_tls_12",
                        "azure_appservice_https_only", "azure_appservice_tls_12",
                        "azure_sql_tls_12",
                    ],
                    "gcp": ["gcp_sql_ssl_required", "gcp_network_ssl_policy"],
                    "oci": ["oci_compute_boot_volume_transit_encryption"],
                    "alibaba": ["alibaba_apigateway_https_enforcement"],
                },
            },
            {
                "id": "Art.5(1)(f)-enc-rest",
                "title": "Encryption at rest",
                "description": (
                    "All personal data stored at rest shall be encrypted using "
                    "industry-standard algorithms and regularly rotated keys."
                ),
                "checks": {
                    "aws": [
                        "s3_bucket_encryption_enabled", "ec2_ebs_volume_encrypted",
                        "ec2_ebs_default_encryption", "rds_encryption_enabled",
                        "efs_encryption_enabled", "kms_key_rotation_enabled",
                        "cloudwatch_log_group_encrypted",
                    ],
                    "azure": [
                        "azure_vm_disk_encryption", "azure_sql_tde_enabled",
                        "azure_storage_infrastructure_encryption",
                        "azure_storage_cmk_encryption",
                        "azure_disk_unattached_encrypted",
                    ],
                    "gcp": [
                        "gcp_kms_key_rotation", "gcp_storage_cmek_encryption",
                        "gcp_bigquery_cmek_encryption", "gcp_bigquery_table_encrypted",
                        "gcp_dataproc_encrypted",
                    ],
                    "oci": [
                        "oci_objectstorage_bucket_cmk_encryption",
                        "oci_filestorage_cmk_encryption",
                        "oci_storage_volume_cmk_encryption",
                        "oci_vault_key_rotation",
                    ],
                    "alibaba": [
                        "alibaba_storage_oss_encryption_enabled",
                        "alibaba_database_rds_encryption_enabled",
                        "alibaba_kms_key_rotation_enabled",
                    ],
                },
            },
            {
                "id": "Art.25-k8s",
                "title": "Data protection by design -- container and orchestration controls",
                "description": (
                    "Kubernetes and container security controls to ensure data "
                    "protection by design in containerised environments."
                ),
                "checks": {
                    "aws": ["eks_cluster_logging", "eks_endpoint_public_access", "ecr_image_scanning"],
                    "azure": [
                        "azure_aks_rbac_enabled", "azure_aks_aad_integration",
                        "azure_aks_network_policy", "azure_aks_authorized_ip_ranges",
                    ],
                    "gcp": [
                        "gcp_gke_private_cluster", "gcp_gke_network_policy",
                        "gcp_gke_workload_identity", "gcp_gke_shielded_nodes",
                        "gcp_gke_binary_auth",
                    ],
                    "kubernetes": [
                        "k8s_admission_pod_security", "k8s_secrets_encrypted_etcd",
                        "k8s_secrets_no_env_vars", "k8s_rbac_no_default_sa_token",
                    ],
                },
            },
            {
                "id": "Art.32-vuln",
                "title": "Vulnerability management and patching",
                "description": (
                    "Regular vulnerability assessment and timely patching of "
                    "systems that process personal data."
                ),
                "checks": {
                    "aws": [
                        "rds_auto_minor_upgrade", "ssm_managed_instances",
                        "ecr_image_scanning", "lambda_runtime_supported",
                    ],
                    "azure": [
                        "azure_sql_vulnerability_assessment", "azure_sql_atp_enabled",
                        "azure_vm_antimalware_extension",
                    ],
                    "gcp": ["gcp_gke_shielded_nodes", "gcp_compute_shielded_vm"],
                    "oci": ["oci_compute_secure_boot"],
                },
            },
            {
                "id": "Art.32-kms",
                "title": "Cryptographic key management",
                "description": (
                    "Proper management of cryptographic keys including rotation, "
                    "access control and protection of key material."
                ),
                "checks": {
                    "aws": ["kms_key_rotation_enabled"],
                    "azure": [
                        "azure_keyvault_soft_delete", "azure_keyvault_purge_protection",
                        "azure_keyvault_rbac_authorization", "azure_keyvault_network_acls",
                        "azure_keyvault_key_expiration", "azure_keyvault_secret_expiration",
                    ],
                    "gcp": [
                        "gcp_kms_key_rotation", "gcp_kms_no_public_access",
                        "gcp_kms_hsm_protection", "gcp_iam_kms_separation_of_duties",
                    ],
                    "oci": ["oci_vault_key_rotation"],
                    "alibaba": ["alibaba_kms_key_rotation_enabled", "alibaba_kms_key_deletion_protection"],
                },
            },
            {
                "id": "Art.32-waf",
                "title": "Web application firewall and DDoS protection",
                "description": (
                    "Protect web applications processing personal data with WAF "
                    "rules and DDoS mitigation."
                ),
                "checks": {
                    "aws": ["waf_web_acl_exists", "apigateway_waf_enabled"],
                    "azure": ["azure_appgw_waf_enabled", "azure_public_ip_ddos_protection"],
                    "gcp": [],
                    "alibaba": ["ali_waf_enabled", "ali_waf_domains_configured"],
                },
            },
            {
                "id": "Art.32-db",
                "title": "Database security for personal data stores",
                "description": (
                    "Database-level security controls including encryption, "
                    "auditing, access restriction and backup for stores "
                    "containing personal data."
                ),
                "checks": {
                    "aws": [
                        "rds_encryption_enabled", "rds_public_access_disabled",
                        "rds_backup_enabled", "rds_multi_az_enabled",
                        "rds_auto_minor_upgrade",
                    ],
                    "azure": [
                        "azure_sql_tde_enabled", "azure_sql_auditing_enabled",
                        "azure_sql_public_access_disabled", "azure_sql_atp_enabled",
                        "azure_sql_ad_admin_configured", "azure_sql_tls_12",
                    ],
                    "gcp": [
                        "gcp_sql_no_public_ip", "gcp_sql_no_public_networks",
                        "gcp_sql_ssl_required", "gcp_sql_backup_enabled",
                    ],
                    "oci": ["oci_db_autonomous_private_endpoint"],
                    "alibaba": [
                        "alibaba_database_rds_encryption_enabled",
                        "alibaba_database_rds_public_access_disabled",
                        "alibaba_database_rds_backup_enabled",
                    ],
                },
            },
            {
                "id": "Art.32-secrets",
                "title": "Secrets and credential management",
                "description": (
                    "Secure management of secrets, API keys and credentials "
                    "used in systems that process personal data."
                ),
                "checks": {
                    "aws": [
                        "iam_access_key_rotation", "iam_no_root_access_key",
                        "iam_user_single_active_access_key",
                    ],
                    "azure": [
                        "azure_keyvault_secret_expiration", "azure_keyvault_rbac_authorization",
                        "azure_appservice_managed_identity",
                    ],
                    "gcp": [
                        "gcp_iam_no_user_managed_sa_keys", "gcp_iam_sa_key_rotation",
                        "gcp_iam_no_sa_admin_key", "gcp_iam_secrets_in_functions",
                    ],
                    "oci": [
                        "oci_iam_api_key_rotation", "oci_iam_auth_token_rotation",
                        "oci_iam_secret_key_rotation",
                    ],
                },
            },
            {
                "id": "Art.33-detect",
                "title": "Threat detection and incident response",
                "description": (
                    "Automated threat detection and incident response "
                    "capabilities to support the 72-hour breach notification "
                    "requirement."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "securityhub_enabled", "macie_enabled"],
                    "azure": [
                        "azure_defender_vm", "azure_defender_sql",
                        "azure_defender_storage", "azure_defender_keyvault",
                        "azure_defender_arm", "azure_defender_dns",
                    ],
                    "gcp": ["gcp_logging_audit_logs_enabled"],
                    "oci": ["oci_cloud_guard_enabled", "oci_events_rule_configured"],
                    "alibaba": ["ali_security_center_enabled", "ali_sas_advanced_edition"],
                },
            },
            {
                "id": "Art.35-monitor",
                "title": "Continuous compliance monitoring for DPIA",
                "description": (
                    "Continuous monitoring and compliance assessment to support "
                    "ongoing data protection impact assessments."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "securityhub_enabled"],
                    "azure": [
                        "azure_policy_compliance_rate", "azure_policy_security_initiative",
                        "azure_defender_auto_provisioning",
                    ],
                    "gcp": ["gcp_logging_cloud_asset_inventory"],
                },
            },
            {
                "id": "Art.5(1)(f)-saas",
                "title": "SaaS platform security for personal data processing",
                "description": (
                    "Security controls for SaaS platforms (M365, Snowflake, "
                    "Salesforce) that process personal data."
                ),
                "checks": {
                    "m365": [
                        "m365_admin_mfa_enforced", "m365_user_mfa_registered",
                        "m365_dlp_policies_configured", "m365_sensitivity_labels_enabled",
                        "m365_aip_encryption_enabled", "m365_external_sharing_restricted",
                    ],
                    "snowflake": [
                        "snowflake_user_mfa_enabled", "snowflake_account_password_policy",
                        "snowflake_column_masking_policies",
                    ],
                    "salesforce": ["salesforce_user_mfa_enabled", "salesforce_setup_audit_trail"],
                },
            },
        ],
    },
}
