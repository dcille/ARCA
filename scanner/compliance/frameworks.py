"""Compliance framework definitions with control-level structure and check mappings."""

FRAMEWORKS = {
    # ═══════════════════════════════════════════════════════════════════
    # CIS BENCHMARKS
    # ═══════════════════════════════════════════════════════════════════
    "CIS-AWS-1.5": {
        "name": "CIS Amazon Web Services Foundations Benchmark v1.5",
        "description": "Center for Internet Security best-practice configuration guidelines for AWS accounts",
        "category": "cis",
        "controls": [
            {
                "id": "1.1",
                "title": "Maintain current contact details",
                "description": "Ensure IAM root user account has MFA enabled and access keys are not present. The root account is the most privileged user in an AWS account.",
                "checks": {"aws": ["iam_root_mfa_enabled"]},
            },
            {
                "id": "1.4",
                "title": "Ensure IAM password policy requires strong passwords",
                "description": "IAM password policies can require passwords to be rotated or expired after a given number of days. Ensure the password policy is sufficiently strong.",
                "checks": {"aws": ["iam_password_policy_strong", "iam_password_policy_rotation"]},
            },
            {
                "id": "1.5",
                "title": "Ensure MFA is enabled for all IAM users with console access",
                "description": "Multi-Factor Authentication adds an extra layer of protection on top of a username and password. Enable MFA for all IAM users.",
                "checks": {"aws": ["iam_user_mfa_enabled"]},
            },
            {
                "id": "1.14",
                "title": "Ensure access keys are rotated every 90 days or less",
                "description": "Access keys consist of an access key ID and secret access key. Rotating keys reduces the window of opportunity for a compromised key.",
                "checks": {"aws": ["iam_access_key_rotation"]},
            },
            {
                "id": "2.1",
                "title": "Ensure S3 buckets employ encryption and block public access",
                "description": "Amazon S3 provides multiple encryption options. Ensure all buckets have encryption at rest and block public access settings enabled.",
                "checks": {"aws": ["s3_bucket_public_access_blocked", "s3_bucket_encryption_enabled", "s3_bucket_logging_enabled"]},
            },
            {
                "id": "2.2",
                "title": "Ensure EBS volumes and RDS instances are encrypted",
                "description": "EBS volumes and RDS instances should use encryption to protect data at rest from unauthorized access.",
                "checks": {"aws": ["ec2_ebs_volume_encrypted", "rds_encryption_enabled", "rds_public_access_disabled"]},
            },
            {
                "id": "2.3",
                "title": "Ensure EC2 instances use IMDSv2 and security groups restrict access",
                "description": "Instance Metadata Service Version 2 (IMDSv2) mitigates SSRF attacks. Security groups should restrict SSH/RDP.",
                "checks": {"aws": ["ec2_imdsv2_required", "ec2_sg_open_port_22", "ec2_sg_open_port_3389"]},
            },
            {
                "id": "3.1",
                "title": "Ensure CloudTrail is enabled in all regions",
                "description": "AWS CloudTrail records API calls. Ensure it is enabled in all regions with log file validation and encryption.",
                "checks": {"aws": ["cloudtrail_multiregion", "cloudtrail_log_validation", "cloudtrail_encrypted"]},
            },
            {
                "id": "3.7",
                "title": "Ensure KMS key rotation is enabled",
                "description": "AWS KMS allows automatic annual rotation of customer-managed keys to limit the exposure of compromised key material.",
                "checks": {"aws": ["kms_key_rotation_enabled"]},
            },
            {
                "id": "4.1",
                "title": "Ensure VPC Flow Logs and monitoring services are enabled",
                "description": "VPC Flow Logs capture information about IP traffic. GuardDuty and Config provide continuous monitoring and compliance.",
                "checks": {"aws": ["vpc_flow_logs_enabled", "guardduty_enabled", "config_recorder_enabled"]},
            },
            {
                "id": "5.1",
                "title": "Ensure EKS clusters are properly configured",
                "description": "EKS cluster logging should be enabled and public endpoint access restricted to authorized networks.",
                "checks": {"aws": ["eks_cluster_logging", "eks_endpoint_public_access"]},
            },
        ],
    },

    "CIS-Azure-2.0": {
        "name": "CIS Microsoft Azure Foundations Benchmark v2.0",
        "description": "Center for Internet Security best-practice security configuration for Microsoft Azure",
        "category": "cis",
        "controls": [
            {
                "id": "1.1",
                "title": "Ensure that the number of subscription owners is limited",
                "description": "Limit the number of subscription owners to reduce the risk of excessive administrative access and potential breach impact.",
                "checks": {"azure": ["azure_iam_owner_count"]},
            },
            {
                "id": "3.1",
                "title": "Ensure storage accounts enforce secure transfer and TLS 1.2",
                "description": "Storage accounts should require HTTPS and TLS 1.2 minimum, and disable public access to protect data in transit and at rest.",
                "checks": {"azure": ["azure_storage_https_only", "azure_storage_tls_12", "azure_storage_no_public_access"]},
            },
            {
                "id": "4.1",
                "title": "Ensure SQL Server auditing and TLS are configured",
                "description": "Enable auditing on SQL Server instances and enforce minimum TLS 1.2 to ensure database security and compliance.",
                "checks": {"azure": ["azure_sql_auditing_enabled", "azure_sql_tls_12"]},
            },
            {
                "id": "5.1",
                "title": "Ensure Network Security Groups restrict SSH and RDP",
                "description": "NSGs should not allow unrestricted inbound access on SSH (22) or RDP (3389) ports from the internet.",
                "checks": {"azure": ["azure_nsg_open_port_22", "azure_nsg_open_port_3389", "azure_network_watcher_enabled"]},
            },
            {
                "id": "6.1",
                "title": "Ensure virtual machine disk encryption is enabled",
                "description": "Azure Disk Encryption helps protect and safeguard data on VM OS and data disks using industry-standard encryption.",
                "checks": {"azure": ["azure_vm_disk_encryption"]},
            },
            {
                "id": "7.1",
                "title": "Ensure Key Vault has soft delete and purge protection",
                "description": "Soft-delete and purge protection prevent accidental or malicious deletion of key vaults and their contents.",
                "checks": {"azure": ["azure_keyvault_soft_delete", "azure_keyvault_purge_protection"]},
            },
            {
                "id": "8.1",
                "title": "Ensure activity log monitoring is configured",
                "description": "A log profile should exist to export activity logs for security analysis and long-term retention.",
                "checks": {"azure": ["azure_monitor_log_profile"]},
            },
            {
                "id": "9.1",
                "title": "Ensure App Service enforces HTTPS and minimum TLS",
                "description": "Web applications should redirect HTTP to HTTPS and enforce TLS 1.2 minimum to protect data in transit.",
                "checks": {"azure": ["azure_appservice_https_only", "azure_appservice_tls_12"]},
            },
        ],
    },

    "CIS-GCP-2.0": {
        "name": "CIS Google Cloud Platform Foundation Benchmark v2.0",
        "description": "Center for Internet Security best-practice security configuration for Google Cloud Platform",
        "category": "cis",
        "controls": [
            {
                "id": "1.1",
                "title": "Ensure IAM bindings do not grant public access",
                "description": "IAM policies should not include allUsers or allAuthenticatedUsers bindings that grant access to anyone on the internet.",
                "checks": {"gcp": ["gcp_iam_no_public_access"]},
            },
            {
                "id": "2.1",
                "title": "Ensure compute instances do not have external IPs and use OS Login",
                "description": "VM instances should not have external IP addresses when possible and should use OS Login for SSH key management.",
                "checks": {"gcp": ["gcp_compute_no_external_ip", "gcp_compute_os_login"]},
            },
            {
                "id": "3.1",
                "title": "Ensure Cloud Storage uses uniform access and Cloud SQL is secured",
                "description": "Uniform bucket-level access simplifies permissions. Cloud SQL should not have public IPs and must require SSL.",
                "checks": {"gcp": ["gcp_storage_uniform_access", "gcp_sql_no_public_ip", "gcp_sql_ssl_required"]},
            },
            {
                "id": "3.5",
                "title": "Ensure KMS encryption keys are rotated within 365 days",
                "description": "Regular key rotation limits the amount of data encrypted with a single key version, reducing the impact of a compromised key.",
                "checks": {"gcp": ["gcp_kms_key_rotation"]},
            },
            {
                "id": "4.1",
                "title": "Ensure firewall rules do not allow unrestricted ingress",
                "description": "VPC firewall rules should not allow SSH (22) or RDP (3389) from 0.0.0.0/0 to reduce the attack surface.",
                "checks": {"gcp": ["gcp_firewall_open_22", "gcp_firewall_open_3389"]},
            },
            {
                "id": "5.1",
                "title": "Ensure GKE clusters are private with network policies",
                "description": "GKE clusters should use private endpoints and enable network policies to control pod-to-pod communication.",
                "checks": {"gcp": ["gcp_gke_private_cluster", "gcp_gke_network_policy"]},
            },
        ],
    },

    "CIS-OCI-2.0": {
        "name": "CIS Oracle Cloud Infrastructure Foundations Benchmark v2.0",
        "description": "Center for Internet Security best-practice security configuration for Oracle Cloud Infrastructure",
        "category": "cis",
        "controls": [
            {
                "id": "1.1",
                "title": "Ensure IAM policies enforce MFA and strong passwords",
                "description": "IAM policies should require MFA for all users, enforce strong password requirements, and rotate API keys regularly.",
                "checks": {"oci": [
                    "oci_iam_api_key_rotation", "oci_iam_user_mfa_enabled", "oci_iam_admin_mfa_enabled",
                    "oci_iam_password_length", "oci_iam_password_uppercase", "oci_iam_password_lowercase",
                    "oci_iam_password_numeric", "oci_iam_password_special", "oci_iam_secret_key_rotation",
                    "oci_iam_policy_no_wildcard",
                ]},
            },
            {
                "id": "2.1",
                "title": "Ensure network security lists and NSGs restrict access",
                "description": "Security lists and NSGs should not allow unrestricted SSH or RDP ingress. VCN flow logs should be enabled.",
                "checks": {"oci": [
                    "oci_network_sl_no_ssh_open", "oci_network_sl_no_rdp_open",
                    "oci_network_nsg_no_unrestricted_ingress", "oci_network_vcn_flow_logs",
                ]},
            },
            {
                "id": "3.1",
                "title": "Ensure compute instances use secure boot and encrypted volumes",
                "description": "Compute instances should use measured/secure boot, IMDSv2, and encrypt boot and block volumes with customer-managed keys.",
                "checks": {"oci": [
                    "oci_compute_secure_boot", "oci_compute_imds_v2",
                    "oci_compute_boot_volume_transit_encryption",
                    "oci_storage_volume_cmk_encryption", "oci_storage_boot_volume_cmk_encryption",
                ]},
            },
            {
                "id": "4.1",
                "title": "Ensure Object Storage buckets are private and encrypted",
                "description": "Object Storage buckets should block public access, use CMK encryption, enable versioning, and emit events for auditing.",
                "checks": {"oci": [
                    "oci_objectstorage_bucket_public_access", "oci_objectstorage_bucket_cmk_encryption",
                    "oci_objectstorage_bucket_versioning", "oci_objectstorage_bucket_emit_events",
                ]},
            },
            {
                "id": "5.1",
                "title": "Ensure databases use encryption and private endpoints",
                "description": "Autonomous databases should use CMK encryption and private endpoints. DB Systems should have backups enabled.",
                "checks": {"oci": [
                    "oci_db_autonomous_cmk_encryption", "oci_db_autonomous_private_endpoint",
                    "oci_db_system_backup_enabled",
                ]},
            },
            {
                "id": "6.1",
                "title": "Ensure Vault keys are rotated and logging is configured",
                "description": "Vault key rotation limits cryptographic exposure. Audit logs should have adequate retention and log groups should exist.",
                "checks": {"oci": [
                    "oci_vault_key_rotation", "oci_logging_audit_retention",
                    "oci_logging_log_groups_exist", "oci_cloud_guard_enabled",
                    "oci_notifications_security_topic_exists",
                ]},
            },
            {
                "id": "7.1",
                "title": "Ensure serverless functions and container services are secure",
                "description": "Functions should use NSGs and tracing. Container instances should have restart policies and graceful shutdown. Registries should restrict public repos.",
                "checks": {"oci": [
                    "oci_functions_app_nsg_assigned", "oci_functions_app_tracing_enabled",
                    "oci_functions_provisioned_concurrency",
                    "oci_container_instance_restart_policy", "oci_container_instance_graceful_shutdown",
                    "oci_container_registry_public_repo", "oci_container_registry_immutable_artifacts",
                ]},
            },
            {
                "id": "8.1",
                "title": "Ensure file storage and load balancers are properly secured",
                "description": "File storage should use CMK encryption with NSG-protected mount targets. Load balancers should use HTTPS listeners and NSGs.",
                "checks": {"oci": [
                    "oci_filestorage_cmk_encryption", "oci_filestorage_mount_target_nsg",
                    "oci_filestorage_export_privileged_port",
                    "oci_lb_nsg_assigned", "oci_lb_listener_https", "oci_lb_backend_health",
                ]},
            },
            {
                "id": "9.1",
                "title": "Ensure OKE clusters and MySQL are properly configured",
                "description": "OKE clusters should restrict public endpoints, use NSGs, verify images, and run current Kubernetes versions. MySQL should have backups, PITR, and HA.",
                "checks": {"oci": [
                    "oci_oke_cluster_public_endpoint", "oci_oke_cluster_nsg_assigned",
                    "oci_oke_image_verification", "oci_oke_kubernetes_version",
                    "oci_oke_nodepool_nsg_assigned",
                    "oci_mysql_backup_enabled", "oci_mysql_pitr_enabled", "oci_mysql_crash_recovery",
                    "oci_mysql_deletion_protection", "oci_mysql_high_availability",
                ]},
            },
        ],
    },

    "CIS-Alibaba-1.0": {
        "name": "CIS Alibaba Cloud Foundation Benchmark v1.0",
        "description": "Center for Internet Security best-practice security configuration for Alibaba Cloud",
        "category": "cis",
        "controls": [
            {
                "id": "1.1",
                "title": "Ensure RAM policies enforce MFA and strong passwords",
                "description": "RAM should require MFA for root and all users, enforce strong password policies, rotate access keys, and avoid wildcard permissions.",
                "checks": {"alibaba": [
                    "alibaba_iam_ram_root_mfa_enabled", "alibaba_iam_ram_user_mfa_enabled",
                    "alibaba_iam_ram_password_length", "alibaba_iam_ram_password_uppercase",
                    "alibaba_iam_ram_password_lowercase", "alibaba_iam_ram_password_numeric",
                    "alibaba_iam_ram_password_special", "alibaba_iam_ram_access_key_rotation",
                    "alibaba_iam_ram_no_wildcard_policy", "alibaba_iam_ram_console_login_disabled",
                ]},
            },
            {
                "id": "2.1",
                "title": "Ensure security groups and VPC networking restrict access",
                "description": "Security groups should not allow unrestricted SSH/RDP. VPC flow logs and multi-AZ vSwitch configurations should be enabled.",
                "checks": {"alibaba": [
                    "alibaba_network_sg_no_ssh_open", "alibaba_network_sg_no_rdp_open",
                    "alibaba_network_sg_no_unrestricted_ingress", "alibaba_network_vpc_flow_logs",
                    "alibaba_network_vswitch_multi_az",
                ]},
            },
            {
                "id": "3.1",
                "title": "Ensure ECS instances are encrypted and properly secured",
                "description": "ECS instances should use disk encryption, IMDSv2, and restrictive security groups. Public IPs should be avoided when possible.",
                "checks": {"alibaba": [
                    "alibaba_compute_ecs_disk_encryption", "alibaba_compute_ecs_imdsv2",
                    "alibaba_compute_ecs_public_ip", "alibaba_compute_ecs_sg_restrictive",
                ]},
            },
            {
                "id": "4.1",
                "title": "Ensure OSS buckets enforce encryption and access controls",
                "description": "Object Storage Service buckets should block public access, enable encryption, logging, versioning, and restrict CORS.",
                "checks": {"alibaba": [
                    "alibaba_storage_oss_public_access_blocked", "alibaba_storage_oss_encryption_enabled",
                    "alibaba_storage_oss_logging_enabled", "alibaba_storage_oss_versioning_enabled",
                    "alibaba_storage_oss_cors_restrictive",
                ]},
            },
            {
                "id": "5.1",
                "title": "Ensure RDS instances are encrypted with backups and auditing",
                "description": "RDS database instances should use encryption, disable public access, enable backups, require SSL, and enable audit logging.",
                "checks": {"alibaba": [
                    "alibaba_database_rds_encryption_enabled", "alibaba_database_rds_public_access_disabled",
                    "alibaba_database_rds_backup_enabled", "alibaba_database_rds_ssl_enabled",
                    "alibaba_database_rds_audit_log_enabled",
                ]},
            },
            {
                "id": "6.1",
                "title": "Ensure KMS keys are rotated with deletion protection",
                "description": "KMS keys should be automatically rotated and have deletion protection enabled to prevent accidental key loss.",
                "checks": {"alibaba": ["alibaba_kms_key_rotation_enabled", "alibaba_kms_key_deletion_protection"]},
            },
            {
                "id": "7.1",
                "title": "Ensure logging and monitoring services are enabled",
                "description": "ActionTrail, Cloud Monitor, and SLS audit should be enabled with appropriate log delivery configurations.",
                "checks": {"alibaba": [
                    "alibaba_logging_actiontrail_enabled", "alibaba_logging_actiontrail_oss_delivery",
                    "alibaba_logging_cloud_monitor_alarms", "alibaba_logging_sls_audit_enabled",
                ]},
            },
            {
                "id": "8.1",
                "title": "Ensure ACK clusters and API Gateways are properly secured",
                "description": "ACK Kubernetes clusters should use private endpoints, RBAC, logging, and run current versions. API Gateways should enforce HTTPS and authentication.",
                "checks": {"alibaba": [
                    "alibaba_container_ack_private_endpoint", "alibaba_container_ack_logging",
                    "alibaba_container_ack_rbac_enabled", "alibaba_container_ack_kubernetes_version",
                    "alibaba_apigateway_https_enforcement", "alibaba_apigateway_authentication_enabled",
                ]},
            },
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    # REGULATORY FRAMEWORKS
    # ═══════════════════════════════════════════════════════════════════
    "PCI-DSS-3.2.1": {
        "name": "PCI DSS v3.2.1",
        "description": "Payment Card Industry Data Security Standard — requirements for organizations handling cardholder data",
        "category": "regulatory",
        "controls": [
            {
                "id": "1.3",
                "title": "Prohibit direct public access between the Internet and CDE",
                "description": "Prohibit direct public access between the Internet and any system component in the cardholder data environment. Implement firewall rules to restrict connections.",
                "checks": {
                    "aws": ["vpc_flow_logs_enabled", "ec2_sg_open_port_22", "ec2_sg_open_port_3389"],
                    "azure": ["azure_nsg_open_port_22", "azure_nsg_open_port_3389", "azure_network_watcher_enabled"],
                    "gcp": ["gcp_firewall_open_22", "gcp_firewall_open_3389"],
                },
            },
            {
                "id": "2.3",
                "title": "Encrypt all non-console administrative access using strong cryptography",
                "description": "Use strong cryptography to encrypt all non-console administrative access. Enforce HTTPS/TLS for all management interfaces.",
                "checks": {
                    "aws": ["ec2_imdsv2_required"],
                    "azure": ["azure_storage_https_only", "azure_storage_tls_12", "azure_appservice_https_only", "azure_appservice_tls_12"],
                    "gcp": ["gcp_sql_ssl_required"],
                },
            },
            {
                "id": "3.4",
                "title": "Render PAN unreadable anywhere it is stored",
                "description": "Render the primary account number unreadable anywhere it is stored through encryption, truncation, tokenization, or hashing.",
                "checks": {
                    "aws": ["s3_bucket_encryption_enabled", "ec2_ebs_volume_encrypted", "rds_encryption_enabled"],
                    "azure": ["azure_vm_disk_encryption", "azure_storage_no_public_access"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_storage_uniform_access"],
                },
            },
            {
                "id": "7.1",
                "title": "Limit access to system components to individuals whose job requires such access",
                "description": "Establish an access control system that restricts access based on a user's need-to-know and is set to deny all unless specifically allowed.",
                "checks": {
                    "aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled", "iam_access_key_rotation"],
                    "azure": ["azure_iam_owner_count"],
                    "gcp": ["gcp_iam_no_public_access"],
                },
            },
            {
                "id": "8.2",
                "title": "Ensure proper user identification and authentication management",
                "description": "Employ at least one method to authenticate all users: password/passphrase, token device, biometric. Assign unique IDs before allowing access.",
                "checks": {
                    "aws": ["iam_password_policy_strong", "iam_user_mfa_enabled"],
                    "azure": ["azure_sql_tls_12"],
                },
            },
            {
                "id": "10.1",
                "title": "Implement audit trails to link access to individual users",
                "description": "Implement automated audit trails for all system components to reconstruct events including user activities and security events.",
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation", "cloudtrail_encrypted", "guardduty_enabled"],
                    "azure": ["azure_sql_auditing_enabled", "azure_monitor_log_profile"],
                    "gcp": ["gcp_sql_no_public_ip"],
                },
            },
            {
                "id": "10.5",
                "title": "Secure audit trails so they cannot be altered",
                "description": "Protect audit trails from unauthorized modifications. Use encryption and integrity verification for log files.",
                "checks": {
                    "aws": ["cloudtrail_encrypted", "kms_key_rotation_enabled", "s3_bucket_logging_enabled"],
                    "azure": ["azure_keyvault_soft_delete", "azure_keyvault_purge_protection"],
                },
            },
            {
                "id": "11.5",
                "title": "Deploy intrusion detection and file integrity monitoring",
                "description": "Deploy a change-detection mechanism to alert on unauthorized modification of critical system files, configuration files, or content files.",
                "checks": {
                    "aws": ["guardduty_enabled", "config_recorder_enabled"],
                },
            },
            {
                "id": "6.2",
                "title": "Protect systems against known vulnerabilities with security patches",
                "description": "Ensure that all system components and software are protected from known vulnerabilities by installing applicable vendor-supplied patches.",
                "checks": {
                    "aws": ["rds_public_access_disabled", "s3_bucket_public_access_blocked", "eks_endpoint_public_access"],
                },
            },
        ],
    },

    "HIPAA": {
        "name": "HIPAA Security Rule",
        "description": "Health Insurance Portability and Accountability Act — safeguards for electronic protected health information (ePHI)",
        "category": "regulatory",
        "controls": [
            {
                "id": "164.312(a)(1)",
                "title": "Access Control — Technical safeguards",
                "description": "Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons or software programs.",
                "checks": {
                    "aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled", "iam_access_key_rotation"],
                    "azure": ["azure_iam_owner_count"],
                    "gcp": ["gcp_iam_no_public_access"],
                },
            },
            {
                "id": "164.312(a)(2)(iv)",
                "title": "Encryption and Decryption",
                "description": "Implement a mechanism to encrypt and decrypt ePHI at rest and in transit. Use industry-standard encryption algorithms.",
                "checks": {
                    "aws": ["s3_bucket_encryption_enabled", "ec2_ebs_volume_encrypted", "rds_encryption_enabled",
                            "cloudtrail_encrypted", "kms_key_rotation_enabled", "sns_topic_encrypted",
                            "sqs_queue_encrypted", "efs_encryption_enabled", "dynamodb_table_encrypted_kms"],
                    "azure": ["azure_vm_disk_encryption", "azure_storage_https_only", "azure_storage_tls_12",
                              "azure_keyvault_soft_delete", "azure_keyvault_purge_protection"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_sql_ssl_required", "gcp_storage_uniform_access"],
                },
            },
            {
                "id": "164.312(b)",
                "title": "Audit Controls",
                "description": "Implement hardware, software, and/or procedural mechanisms that record and examine activity in systems that contain or use ePHI.",
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation", "rds_backup_enabled"],
                    "azure": ["azure_sql_auditing_enabled", "azure_sql_tls_12", "azure_monitor_log_profile"],
                },
            },
            {
                "id": "164.312(e)(1)",
                "title": "Transmission Security",
                "description": "Implement technical security measures to guard against unauthorized access to ePHI that is being transmitted over an electronic communications network.",
                "checks": {
                    "aws": ["s3_bucket_public_access_blocked", "rds_public_access_disabled"],
                    "azure": ["azure_storage_no_public_access", "azure_appservice_https_only"],
                    "gcp": ["gcp_sql_no_public_ip", "gcp_compute_no_external_ip"],
                },
            },
        ],
    },

    "SOC2": {
        "name": "SOC 2 Type II",
        "description": "Service Organization Control 2 — Trust Service Criteria for service organizations",
        "category": "regulatory",
        "controls": [
            {
                "id": "CC6.1",
                "title": "Logical and Physical Access Controls",
                "description": "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
                "checks": {
                    "aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled", "iam_access_key_rotation",
                            "ec2_sg_open_port_22", "ec2_sg_open_port_3389", "eks_endpoint_public_access"],
                    "azure": ["azure_iam_owner_count", "azure_nsg_open_port_22", "azure_nsg_open_port_3389"],
                    "gcp": ["gcp_iam_no_public_access", "gcp_firewall_open_22", "gcp_firewall_open_3389"],
                },
            },
            {
                "id": "CC6.7",
                "title": "Restrict Data Transmission and Movement",
                "description": "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.",
                "checks": {
                    "aws": ["s3_bucket_public_access_blocked", "rds_public_access_disabled"],
                    "azure": ["azure_storage_no_public_access", "azure_storage_https_only"],
                    "gcp": ["gcp_sql_no_public_ip", "gcp_storage_uniform_access"],
                },
            },
            {
                "id": "CC7.2",
                "title": "System Operations — Monitoring",
                "description": "The entity monitors system components and the operation of those components for anomalies and indicators of compromise.",
                "checks": {
                    "aws": ["cloudtrail_multiregion", "guardduty_enabled", "config_recorder_enabled",
                            "cloudwatch_log_group_retention"],
                    "azure": ["azure_monitor_log_profile", "azure_network_watcher_enabled"],
                    "gcp": ["gcp_gke_private_cluster"],
                },
            },
            {
                "id": "CC8.1",
                "title": "Change Management",
                "description": "The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure and software.",
                "checks": {
                    "aws": ["cloudtrail_log_validation", "s3_bucket_versioning_enabled"],
                    "azure": ["azure_sql_auditing_enabled"],
                },
            },
            {
                "id": "A1.2",
                "title": "Availability — Recovery and Backup",
                "description": "The entity authorizes, designs, develops, implements, operates, approves, maintains, and monitors environmental protections and data recovery.",
                "checks": {
                    "aws": ["rds_multi_az_enabled", "rds_backup_enabled", "s3_bucket_logging_enabled",
                            "secretsmanager_rotation_enabled", "dynamodb_pitr_enabled"],
                    "azure": ["azure_keyvault_soft_delete", "azure_keyvault_purge_protection"],
                    "gcp": ["gcp_sql_no_public_ip"],
                },
            },
        ],
    },

    "GDPR": {
        "name": "GDPR",
        "description": "General Data Protection Regulation — EU regulation for the protection of personal data and privacy",
        "category": "regulatory",
        "controls": [
            {
                "id": "Art.5(1)(f)",
                "title": "Integrity and confidentiality principle",
                "description": "Personal data shall be processed in a manner that ensures appropriate security, including protection against unauthorised or unlawful processing, accidental loss, destruction or damage, using appropriate technical or organisational measures.",
                "checks": {
                    "aws": ["s3_bucket_encryption_enabled", "ec2_ebs_volume_encrypted", "rds_encryption_enabled",
                            "cloudtrail_encrypted", "kms_key_rotation_enabled"],
                    "azure": ["azure_vm_disk_encryption", "azure_storage_https_only", "azure_storage_tls_12"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_sql_ssl_required"],
                },
            },
            {
                "id": "Art.25",
                "title": "Data protection by design and by default",
                "description": "The controller shall implement appropriate technical and organisational measures for ensuring that, by default, only personal data necessary for each specific purpose is processed.",
                "checks": {
                    "aws": ["s3_bucket_public_access_blocked", "rds_public_access_disabled",
                            "ec2_sg_open_port_22", "ec2_sg_open_port_3389"],
                    "azure": ["azure_storage_no_public_access", "azure_nsg_open_port_22", "azure_nsg_open_port_3389"],
                    "gcp": ["gcp_iam_no_public_access", "gcp_compute_no_external_ip"],
                },
            },
            {
                "id": "Art.32",
                "title": "Security of processing",
                "description": "The controller and processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk, including encryption and pseudonymisation.",
                "checks": {
                    "aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled", "vpc_flow_logs_enabled"],
                    "azure": ["azure_iam_owner_count", "azure_keyvault_soft_delete"],
                    "gcp": ["gcp_storage_uniform_access", "gcp_gke_private_cluster"],
                },
            },
            {
                "id": "Art.33",
                "title": "Notification of personal data breach to supervisory authority",
                "description": "In the case of a personal data breach, the controller shall notify the supervisory authority within 72 hours. Logging and monitoring must support breach detection.",
                "checks": {
                    "aws": ["cloudtrail_multiregion", "guardduty_enabled"],
                    "azure": ["azure_monitor_log_profile", "azure_sql_auditing_enabled"],
                },
            },
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    # INDUSTRY STANDARDS
    # ═══════════════════════════════════════════════════════════════════
    "ISO-27001": {
        "name": "ISO/IEC 27001:2022",
        "description": "Information security management systems — Annex A reference controls for establishing, implementing, and improving an ISMS",
        "category": "standard",
        "controls": [
            {
                "id": "A.5.15",
                "title": "Access control",
                "description": "Rules to control physical and logical access to information and other associated assets shall be established and implemented based on business and information security requirements.",
                "checks": {
                    "aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled", "iam_password_policy_strong", "iam_access_key_rotation"],
                    "azure": ["azure_iam_owner_count"],
                    "gcp": ["gcp_iam_no_public_access"],
                    "oci": ["oci_iam_user_mfa_enabled", "oci_iam_admin_mfa_enabled", "oci_iam_policy_no_wildcard"],
                    "alibaba": ["alibaba_iam_ram_root_mfa_enabled", "alibaba_iam_ram_user_mfa_enabled", "alibaba_iam_ram_no_wildcard_policy"],
                },
            },
            {
                "id": "A.8.9",
                "title": "Configuration management",
                "description": "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.",
                "checks": {
                    "aws": ["ec2_imdsv2_required", "ec2_sg_open_port_22", "ec2_sg_open_port_3389", "config_recorder_enabled"],
                    "azure": ["azure_nsg_open_port_22", "azure_nsg_open_port_3389", "azure_network_watcher_enabled"],
                    "gcp": ["gcp_firewall_open_22", "gcp_firewall_open_3389", "gcp_compute_os_login"],
                    "oci": ["oci_network_sl_no_ssh_open", "oci_network_sl_no_rdp_open", "oci_network_nsg_no_unrestricted_ingress"],
                    "alibaba": ["alibaba_network_sg_no_ssh_open", "alibaba_network_sg_no_rdp_open"],
                },
            },
            {
                "id": "A.8.24",
                "title": "Use of cryptography",
                "description": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
                "checks": {
                    "aws": ["s3_bucket_encryption_enabled", "ec2_ebs_volume_encrypted", "rds_encryption_enabled",
                            "cloudtrail_encrypted", "kms_key_rotation_enabled"],
                    "azure": ["azure_vm_disk_encryption", "azure_storage_https_only", "azure_storage_tls_12",
                              "azure_keyvault_soft_delete", "azure_keyvault_purge_protection"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_sql_ssl_required", "gcp_storage_uniform_access"],
                    "oci": ["oci_vault_key_rotation", "oci_objectstorage_bucket_cmk_encryption", "oci_storage_volume_cmk_encryption"],
                    "alibaba": ["alibaba_storage_oss_encryption_enabled", "alibaba_kms_key_rotation_enabled", "alibaba_database_rds_encryption_enabled"],
                },
            },
            {
                "id": "A.8.15",
                "title": "Logging",
                "description": "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.",
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation", "vpc_flow_logs_enabled",
                            "s3_bucket_logging_enabled", "guardduty_enabled"],
                    "azure": ["azure_monitor_log_profile", "azure_sql_auditing_enabled"],
                    "gcp": ["gcp_sql_no_public_ip"],
                    "oci": ["oci_logging_audit_retention", "oci_logging_log_groups_exist", "oci_cloud_guard_enabled"],
                    "alibaba": ["alibaba_logging_actiontrail_enabled", "alibaba_logging_sls_audit_enabled"],
                },
            },
            {
                "id": "A.8.20",
                "title": "Networks security",
                "description": "Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.",
                "checks": {
                    "aws": ["vpc_flow_logs_enabled", "eks_endpoint_public_access", "eks_cluster_logging"],
                    "azure": ["azure_appservice_https_only", "azure_appservice_tls_12"],
                    "gcp": ["gcp_gke_private_cluster", "gcp_gke_network_policy", "gcp_compute_no_external_ip"],
                    "oci": ["oci_network_vcn_flow_logs", "oci_oke_cluster_public_endpoint"],
                    "alibaba": ["alibaba_network_vpc_flow_logs", "alibaba_container_ack_private_endpoint"],
                },
            },
            {
                "id": "A.8.25",
                "title": "Secure development life cycle",
                "description": "Rules for the secure development of software and systems shall be established and applied. Data storage resources must be protected.",
                "checks": {
                    "aws": ["s3_bucket_public_access_blocked", "rds_public_access_disabled"],
                    "azure": ["azure_storage_no_public_access", "azure_sql_tls_12"],
                    "gcp": ["gcp_sql_no_public_ip"],
                    "oci": ["oci_objectstorage_bucket_public_access", "oci_db_autonomous_private_endpoint"],
                    "alibaba": ["alibaba_storage_oss_public_access_blocked", "alibaba_database_rds_public_access_disabled"],
                },
            },
        ],
    },

    "NIST-CSF": {
        "name": "NIST Cybersecurity Framework v1.1",
        "description": "Framework for Improving Critical Infrastructure Cybersecurity — five core functions: Identify, Protect, Detect, Respond, Recover",
        "category": "standard",
        "controls": [
            {
                "id": "ID.AM",
                "title": "Identify — Asset Management",
                "description": "The data, personnel, devices, systems, and facilities that enable the organization to achieve business purposes are identified and managed consistent with their relative importance.",
                "checks": {
                    "aws": ["config_recorder_enabled"],
                    "azure": ["azure_network_watcher_enabled"],
                    "oci": ["oci_cloud_guard_enabled"],
                },
            },
            {
                "id": "PR.AC",
                "title": "Protect — Identity Management and Access Control",
                "description": "Access to physical and logical assets and associated facilities is limited to authorized users, processes, and devices, and is managed consistent with the assessed risk.",
                "checks": {
                    "aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled", "iam_password_policy_strong",
                            "iam_access_key_rotation", "ec2_sg_open_port_22", "ec2_sg_open_port_3389"],
                    "azure": ["azure_iam_owner_count", "azure_nsg_open_port_22", "azure_nsg_open_port_3389"],
                    "gcp": ["gcp_iam_no_public_access", "gcp_firewall_open_22", "gcp_firewall_open_3389"],
                    "oci": ["oci_iam_user_mfa_enabled", "oci_iam_admin_mfa_enabled", "oci_iam_api_key_rotation",
                            "oci_network_sl_no_ssh_open", "oci_network_sl_no_rdp_open"],
                    "alibaba": ["alibaba_iam_ram_root_mfa_enabled", "alibaba_iam_ram_user_mfa_enabled",
                                "alibaba_network_sg_no_ssh_open", "alibaba_network_sg_no_rdp_open"],
                },
            },
            {
                "id": "PR.DS",
                "title": "Protect — Data Security",
                "description": "Information and records (data) are managed consistent with the organization's risk strategy to protect the confidentiality, integrity, and availability of information.",
                "checks": {
                    "aws": ["s3_bucket_encryption_enabled", "ec2_ebs_volume_encrypted", "rds_encryption_enabled",
                            "cloudtrail_encrypted", "kms_key_rotation_enabled", "s3_bucket_public_access_blocked",
                            "rds_public_access_disabled"],
                    "azure": ["azure_vm_disk_encryption", "azure_storage_https_only", "azure_storage_tls_12",
                              "azure_storage_no_public_access", "azure_keyvault_soft_delete"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_sql_ssl_required", "gcp_storage_uniform_access",
                            "gcp_sql_no_public_ip"],
                    "oci": ["oci_objectstorage_bucket_cmk_encryption", "oci_objectstorage_bucket_public_access",
                            "oci_storage_volume_cmk_encryption", "oci_vault_key_rotation"],
                    "alibaba": ["alibaba_storage_oss_encryption_enabled", "alibaba_storage_oss_public_access_blocked",
                                "alibaba_kms_key_rotation_enabled", "alibaba_database_rds_encryption_enabled"],
                },
            },
            {
                "id": "PR.PT",
                "title": "Protect — Protective Technology",
                "description": "Technical security solutions are managed to ensure the security and resilience of systems and assets, consistent with related policies and agreements.",
                "checks": {
                    "aws": ["ec2_imdsv2_required", "vpc_flow_logs_enabled", "eks_endpoint_public_access"],
                    "azure": ["azure_appservice_https_only", "azure_appservice_tls_12", "azure_sql_tls_12"],
                    "gcp": ["gcp_compute_no_external_ip", "gcp_compute_os_login", "gcp_gke_private_cluster"],
                    "oci": ["oci_compute_secure_boot", "oci_compute_imds_v2"],
                    "alibaba": ["alibaba_compute_ecs_imdsv2", "alibaba_apigateway_https_enforcement"],
                },
            },
            {
                "id": "DE.CM",
                "title": "Detect — Security Continuous Monitoring",
                "description": "The information system and assets are monitored to identify cybersecurity events and verify the effectiveness of protective measures.",
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation", "guardduty_enabled",
                            "s3_bucket_logging_enabled"],
                    "azure": ["azure_monitor_log_profile", "azure_sql_auditing_enabled"],
                    "oci": ["oci_logging_audit_retention", "oci_logging_log_groups_exist",
                            "oci_cloud_guard_enabled", "oci_notifications_security_topic_exists"],
                    "alibaba": ["alibaba_logging_actiontrail_enabled", "alibaba_logging_cloud_monitor_alarms",
                                "alibaba_logging_sls_audit_enabled"],
                },
            },
            {
                "id": "RC.RP",
                "title": "Recover — Recovery Planning",
                "description": "Recovery processes and procedures are executed and maintained to ensure restoration of systems or assets affected by cybersecurity incidents.",
                "checks": {
                    "aws": ["rds_backup_enabled", "rds_multi_az_enabled", "s3_bucket_versioning_enabled",
                            "dynamodb_pitr_enabled"],
                    "azure": ["azure_keyvault_purge_protection"],
                    "oci": ["oci_db_system_backup_enabled", "oci_mysql_backup_enabled", "oci_mysql_pitr_enabled",
                            "oci_mysql_high_availability"],
                    "alibaba": ["alibaba_database_rds_backup_enabled", "alibaba_storage_oss_versioning_enabled"],
                },
            },
        ],
    },

    "NIST-800-53": {
        "name": "NIST SP 800-53 Rev. 5",
        "description": "Security and Privacy Controls for Information Systems and Organizations — comprehensive catalog of security controls",
        "category": "standard",
        "controls": [
            {
                "id": "AC",
                "title": "Access Control",
                "description": "Policies and procedures for granting access to information system resources only to authorized users, processes, and devices.",
                "checks": {
                    "aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled", "iam_password_policy_strong",
                            "iam_password_policy_rotation", "iam_access_key_rotation"],
                    "azure": ["azure_iam_owner_count"],
                    "gcp": ["gcp_iam_no_public_access"],
                    "oci": ["oci_iam_user_mfa_enabled", "oci_iam_admin_mfa_enabled", "oci_iam_policy_no_wildcard"],
                    "alibaba": ["alibaba_iam_ram_root_mfa_enabled", "alibaba_iam_ram_user_mfa_enabled",
                                "alibaba_iam_ram_no_wildcard_policy"],
                },
            },
            {
                "id": "AU",
                "title": "Audit and Accountability",
                "description": "Policies and procedures for creating, protecting, and retaining audit records to enable monitoring, analysis, and investigation of unauthorized activity.",
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation", "cloudtrail_encrypted",
                            "s3_bucket_logging_enabled", "vpc_flow_logs_enabled"],
                    "azure": ["azure_monitor_log_profile", "azure_sql_auditing_enabled"],
                    "oci": ["oci_logging_audit_retention", "oci_logging_log_groups_exist"],
                    "alibaba": ["alibaba_logging_actiontrail_enabled", "alibaba_logging_actiontrail_oss_delivery",
                                "alibaba_logging_sls_audit_enabled"],
                },
            },
            {
                "id": "CM",
                "title": "Configuration Management",
                "description": "Establish and maintain baseline configurations and inventories of organizational systems throughout their life cycles.",
                "checks": {
                    "aws": ["config_recorder_enabled", "ec2_imdsv2_required", "ec2_sg_open_port_22", "ec2_sg_open_port_3389"],
                    "azure": ["azure_nsg_open_port_22", "azure_nsg_open_port_3389", "azure_network_watcher_enabled"],
                    "gcp": ["gcp_firewall_open_22", "gcp_firewall_open_3389", "gcp_compute_os_login"],
                    "oci": ["oci_network_sl_no_ssh_open", "oci_network_sl_no_rdp_open", "oci_network_nsg_no_unrestricted_ingress"],
                    "alibaba": ["alibaba_network_sg_no_ssh_open", "alibaba_network_sg_no_rdp_open",
                                "alibaba_network_sg_no_unrestricted_ingress"],
                },
            },
            {
                "id": "IA",
                "title": "Identification and Authentication",
                "description": "Identify and authenticate organizational users, processes, and devices as a prerequisite for granting access to resources.",
                "checks": {
                    "aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled", "iam_password_policy_strong"],
                    "azure": ["azure_sql_tls_12", "azure_storage_tls_12", "azure_appservice_tls_12"],
                    "gcp": ["gcp_sql_ssl_required"],
                    "oci": ["oci_iam_password_length", "oci_iam_password_special", "oci_iam_api_key_rotation"],
                    "alibaba": ["alibaba_iam_ram_password_length", "alibaba_iam_ram_password_special",
                                "alibaba_iam_ram_access_key_rotation"],
                },
            },
            {
                "id": "SC",
                "title": "System and Communications Protection",
                "description": "Monitor, control, and protect organizational communications at external and key internal boundaries. Employ cryptographic mechanisms to protect confidentiality.",
                "checks": {
                    "aws": ["s3_bucket_encryption_enabled", "ec2_ebs_volume_encrypted", "rds_encryption_enabled",
                            "kms_key_rotation_enabled", "s3_bucket_public_access_blocked", "rds_public_access_disabled"],
                    "azure": ["azure_vm_disk_encryption", "azure_storage_https_only", "azure_storage_no_public_access",
                              "azure_keyvault_soft_delete", "azure_keyvault_purge_protection",
                              "azure_appservice_https_only"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_storage_uniform_access", "gcp_sql_no_public_ip",
                            "gcp_compute_no_external_ip", "gcp_gke_private_cluster", "gcp_gke_network_policy"],
                    "oci": ["oci_vault_key_rotation", "oci_objectstorage_bucket_cmk_encryption",
                            "oci_storage_volume_cmk_encryption", "oci_objectstorage_bucket_public_access",
                            "oci_network_vcn_flow_logs"],
                    "alibaba": ["alibaba_storage_oss_encryption_enabled", "alibaba_kms_key_rotation_enabled",
                                "alibaba_storage_oss_public_access_blocked", "alibaba_database_rds_encryption_enabled",
                                "alibaba_network_vpc_flow_logs"],
                },
            },
            {
                "id": "SI",
                "title": "System and Information Integrity",
                "description": "Identify, report, and correct system flaws. Provide protection from malicious code. Monitor system security alerts and advisories.",
                "checks": {
                    "aws": ["guardduty_enabled", "config_recorder_enabled", "eks_cluster_logging",
                            "eks_endpoint_public_access"],
                    "azure": ["azure_appservice_tls_12"],
                    "gcp": ["gcp_compute_no_external_ip"],
                    "oci": ["oci_cloud_guard_enabled", "oci_notifications_security_topic_exists"],
                    "alibaba": ["alibaba_logging_cloud_monitor_alarms"],
                },
            },
            {
                "id": "CP",
                "title": "Contingency Planning",
                "description": "Establish, implement, and maintain plans for emergency response, backup operations, and post-disaster recovery to ensure availability.",
                "checks": {
                    "aws": ["rds_backup_enabled", "rds_multi_az_enabled", "s3_bucket_versioning_enabled",
                            "dynamodb_pitr_enabled", "secretsmanager_rotation_enabled"],
                    "oci": ["oci_db_system_backup_enabled", "oci_mysql_backup_enabled", "oci_mysql_pitr_enabled",
                            "oci_mysql_high_availability", "oci_mysql_crash_recovery", "oci_mysql_deletion_protection"],
                    "alibaba": ["alibaba_database_rds_backup_enabled", "alibaba_storage_oss_versioning_enabled"],
                },
            },
        ],
    },
}


# ═══════════════════════════════════════════════════════════════════════
# Helper functions
# ═══════════════════════════════════════════════════════════════════════

def get_all_checks_for_framework(framework_id: str) -> list[str]:
    """Return flat list of all unique check_ids across all providers for a framework."""
    fw = FRAMEWORKS.get(framework_id)
    if not fw:
        return []
    controls = fw.get("controls", [])
    check_ids: set[str] = set()
    for control in controls:
        checks = control.get("checks", {})
        if isinstance(checks, dict):
            for provider_checks in checks.values():
                check_ids.update(provider_checks)
        elif isinstance(checks, list):
            check_ids.update(checks)
    return sorted(check_ids)


def get_frameworks_for_check(check_id: str) -> list[str]:
    """Return all framework IDs that a given check_id maps to."""
    frameworks = []
    for fw_id, fw_data in FRAMEWORKS.items():
        controls = fw_data.get("controls", [])
        for control in controls:
            checks = control.get("checks", {})
            if isinstance(checks, dict):
                for provider_checks in checks.values():
                    if check_id in provider_checks:
                        frameworks.append(fw_id)
                        break
                else:
                    continue
                break
            elif isinstance(checks, list) and check_id in checks:
                frameworks.append(fw_id)
                break
    return frameworks


def get_framework_controls(framework_id: str) -> list[dict]:
    """Return all controls for a framework with their check mappings."""
    fw = FRAMEWORKS.get(framework_id)
    if not fw:
        return []
    return fw.get("controls", [])
