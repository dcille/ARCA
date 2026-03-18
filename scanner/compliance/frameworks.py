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
                "description": "Limit the number of subscription owners to reduce the risk of excessive administrative access.",
                "checks": {"azure": ["azure_iam_owner_count", "azure_iam_no_custom_owner_roles"]},
            },
            {
                "id": "1.2",
                "title": "Ensure MFA is enabled for all users and privileged access is secured",
                "description": "MFA adds extra protection. Remove classic administrators and limit high-privilege service principals.",
                "checks": {"azure": ["azure_iam_mfa_enabled_all_users", "azure_classic_admins_removed", "azure_iam_sp_high_privilege"]},
            },
            {
                "id": "1.3",
                "title": "Ensure guest users are reviewed and resource locks are applied",
                "description": "Review guest/external access and protect critical resources with locks.",
                "checks": {"azure": ["azure_iam_guest_users_reviewed", "azure_resource_locks_configured"]},
            },
            {
                "id": "2.1",
                "title": "Ensure Microsoft Defender for Cloud is enabled for all services",
                "description": "Enable Microsoft Defender plans and configure security contacts and notifications.",
                "checks": {"azure": [
                    "azure_defender_vm", "azure_defender_sql", "azure_defender_appservice",
                    "azure_defender_storage", "azure_defender_keyvault", "azure_defender_kubernetes",
                    "azure_defender_containers", "azure_defender_arm", "azure_defender_dns",
                    "azure_security_contact_configured", "azure_security_alert_notifications",
                    "azure_defender_auto_provisioning",
                ]},
            },
            {
                "id": "3.1",
                "title": "Ensure storage accounts enforce secure transfer and restrict access",
                "description": "Storage accounts should require HTTPS, TLS 1.2, block public access, and use network rules.",
                "checks": {"azure": [
                    "azure_storage_https_only", "azure_storage_tls_12", "azure_storage_no_public_access",
                    "azure_storage_network_default_deny", "azure_storage_soft_delete_blobs",
                    "azure_storage_infrastructure_encryption", "azure_storage_shared_key_disabled",
                ]},
            },
            {
                "id": "4.1",
                "title": "Ensure SQL Server auditing, encryption, and access are configured",
                "description": "Enable auditing, TDE, TLS 1.2, Azure AD admin, and disable public access for SQL.",
                "checks": {"azure": [
                    "azure_sql_auditing_enabled", "azure_sql_tls_12", "azure_sql_public_access_disabled",
                    "azure_sql_atp_enabled", "azure_sql_vulnerability_assessment", "azure_sql_tde_enabled",
                    "azure_sql_ad_admin_configured", "azure_postgresql_public_access",
                ]},
            },
            {
                "id": "5.1",
                "title": "Ensure Network Security Groups and network controls restrict access",
                "description": "NSGs should restrict SSH/RDP, have default deny, subnets should have NSGs, and WAF should be enabled.",
                "checks": {"azure": [
                    "azure_nsg_unrestricted_port_22", "azure_nsg_unrestricted_port_3389",
                    "azure_nsg_unrestricted_port_*", "azure_nsg_default_deny_inbound",
                    "azure_network_watcher_enabled", "azure_nsg_flow_logs_enabled",
                    "azure_subnet_has_nsg", "azure_appgw_waf_enabled", "azure_private_endpoints_used",
                ]},
            },
            {
                "id": "6.1",
                "title": "Ensure virtual machine security is configured",
                "description": "VMs should have disk encryption, antimalware, managed disks, and trusted launch.",
                "checks": {"azure": [
                    "azure_vm_disk_encryption", "azure_vm_antimalware_extension",
                    "azure_vm_trusted_launch", "azure_vm_managed_disks",
                    "azure_disk_unattached_encrypted",
                ]},
            },
            {
                "id": "7.1",
                "title": "Ensure Key Vault is properly secured",
                "description": "Key Vaults should have soft delete, purge protection, RBAC, network ACLs, and key/secret expiration.",
                "checks": {"azure": [
                    "azure_keyvault_soft_delete", "azure_keyvault_purge_protection",
                    "azure_keyvault_rbac_authorization", "azure_keyvault_network_acls",
                    "azure_keyvault_key_expiration", "azure_keyvault_secret_expiration",
                ]},
            },
            {
                "id": "8.1",
                "title": "Ensure monitoring and alerting is configured",
                "description": "Activity log profiles, diagnostic settings, retention, and alerts for critical operations.",
                "checks": {"azure": [
                    "azure_monitor_log_profile", "azure_monitor_log_retention_365",
                    "azure_monitor_diagnostic_settings",
                    "azure_alert_create_policy_assignment", "azure_alert_delete_nsg",
                    "azure_alert_create_update_nsg_rule", "azure_alert_delete_security_solution",
                    "azure_alert_create_update_sql_firewall",
                ]},
            },
            {
                "id": "9.1",
                "title": "Ensure App Service enforces HTTPS, TLS, and security best practices",
                "description": "Web apps should use HTTPS, TLS 1.2, managed identity, disable FTP/debugging, and enable logging.",
                "checks": {"azure": [
                    "azure_appservice_https_only", "azure_appservice_tls_12",
                    "azure_appservice_managed_identity", "azure_appservice_ftp_disabled",
                    "azure_appservice_remote_debugging_off", "azure_appservice_client_certs",
                    "azure_appservice_http_logging",
                ]},
            },
            {
                "id": "10.1",
                "title": "Ensure AKS clusters are secured",
                "description": "AKS clusters should have RBAC, AAD integration, authorized IP ranges, network policies, and Azure Policy.",
                "checks": {"azure": [
                    "azure_aks_authorized_ip_ranges", "azure_aks_rbac_enabled",
                    "azure_aks_network_policy", "azure_aks_aad_integration",
                    "azure_aks_azure_policy_addon",
                ]},
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

    # ═══════════════════════════════════════════════════════════════════
    # MICROSOFT CLOUD SECURITY BENCHMARK (MCSB) v2
    # ═══════════════════════════════════════════════════════════════════
    "MCSB-Azure-1.0": {
        "name": "Microsoft Cloud Security Benchmark (MCSB) v2 - Azure",
        "description": "Microsoft's comprehensive security benchmark with 12 domains and 78 controls covering network security, identity, data protection, logging, and governance for Azure",
        "category": "regulatory",
        "controls": [
            # ── Network Security (NS) ──────────────────────────────────
            {
                "id": "NS-1",
                "domain": "Network Security",
                "title": "Establish network segmentation boundaries",
                "description": "Ensure proper network segmentation using NSGs, VNets, and subnets to limit blast radius.",
                "checks": {"azure": ["azure_nsg_unrestricted_port_22", "azure_nsg_unrestricted_port_3389", "azure_nsg_unrestricted_port_*", "azure_nsg_default_deny_inbound", "azure_subnet_has_nsg"]},
            },
            {
                "id": "NS-2",
                "domain": "Network Security",
                "title": "Secure cloud native services with network controls",
                "description": "Use network ACLs, private endpoints, and firewalls to secure PaaS services.",
                "checks": {"azure": ["azure_storage_network_default_deny", "azure_keyvault_network_acls", "azure_sql_public_access_disabled", "azure_private_endpoints_used"]},
            },
            {
                "id": "NS-3",
                "domain": "Network Security",
                "title": "Deploy firewall at the edge of enterprise network",
                "description": "Use Azure Firewall or NVAs to inspect and control traffic at network boundaries.",
                "checks": {"azure": ["azure_network_watcher_enabled"]},
            },
            {
                "id": "NS-4",
                "domain": "Network Security",
                "title": "Deploy intrusion detection/intrusion prevention systems (IDS/IPS)",
                "description": "Deploy network IDS/IPS to inspect network traffic for threats.",
                "checks": {"azure": ["azure_nsg_flow_logs_enabled"]},
            },
            {
                "id": "NS-5",
                "domain": "Network Security",
                "title": "Deploy DDoS protection",
                "description": "Enable Azure DDoS Protection Standard for public-facing resources.",
                "checks": {"azure": ["azure_public_ip_ddos_protection"]},
            },
            {
                "id": "NS-6",
                "domain": "Network Security",
                "title": "Deploy web application firewall",
                "description": "Deploy WAF on Application Gateway for web application protection.",
                "checks": {"azure": ["azure_appgw_waf_enabled"]},
            },
            {
                "id": "NS-7",
                "domain": "Network Security",
                "title": "Simplify network security configuration",
                "description": "Centralize and simplify network security management and monitoring.",
                "checks": {"azure": ["azure_network_watcher_enabled", "azure_nsg_flow_logs_enabled"]},
            },
            {
                "id": "NS-8",
                "domain": "Network Security",
                "title": "Detect and disable insecure services and protocols",
                "description": "Disable insecure protocols like FTP and enforce TLS 1.2+.",
                "checks": {"azure": ["azure_storage_tls_12", "azure_sql_tls_12", "azure_appservice_tls_12", "azure_appservice_ftp_disabled"]},
            },
            {
                "id": "NS-9",
                "domain": "Network Security",
                "title": "Connect on-premises or cloud network privately",
                "description": "Use private connectivity (ExpressRoute, VPN, Private Link) instead of public internet.",
                "checks": {"azure": ["azure_private_endpoints_used"]},
            },
            {
                "id": "NS-10",
                "domain": "Network Security",
                "title": "Ensure Domain Name System (DNS) security",
                "description": "Protect DNS configuration against known vulnerabilities.",
                "checks": {"azure": ["azure_defender_dns"]},
            },
            # ── Identity Management (IM) ───────────────────────────────
            {
                "id": "IM-1",
                "domain": "Identity Management",
                "title": "Use centralized identity and authentication system",
                "description": "Centralize identity management using Azure AD for all authentication.",
                "checks": {"azure": ["azure_sql_ad_admin_configured", "azure_aks_aad_integration"]},
            },
            {
                "id": "IM-2",
                "domain": "Identity Management",
                "title": "Protect identity and authentication systems",
                "description": "Protect Azure AD and identity infrastructure from attacks.",
                "checks": {"azure": ["azure_defender_arm"]},
            },
            {
                "id": "IM-3",
                "domain": "Identity Management",
                "title": "Manage application identities securely and automatically",
                "description": "Use managed identities instead of service principal secrets.",
                "checks": {"azure": ["azure_iam_managed_identity_usage", "azure_appservice_managed_identity"]},
            },
            {
                "id": "IM-4",
                "domain": "Identity Management",
                "title": "Authenticate server and services",
                "description": "Use strong authentication for server-to-server communication.",
                "checks": {"azure": ["azure_appservice_client_certs"]},
            },
            {
                "id": "IM-5",
                "domain": "Identity Management",
                "title": "Use single sign-on (SSO) for application access",
                "description": "Use Azure AD SSO for application access management.",
                "checks": {"azure": []},
            },
            {
                "id": "IM-6",
                "domain": "Identity Management",
                "title": "Use strong authentication controls",
                "description": "Enforce MFA for all users, especially privileged accounts.",
                "checks": {"azure": ["azure_iam_mfa_enabled_all_users"]},
            },
            {
                "id": "IM-7",
                "domain": "Identity Management",
                "title": "Restrict resource access based on conditions",
                "description": "Use Conditional Access policies for risk-based access decisions.",
                "checks": {"azure": []},
            },
            {
                "id": "IM-8",
                "domain": "Identity Management",
                "title": "Restrict the exposure of credentials and secrets",
                "description": "Manage and rotate credentials, use Key Vault for secrets.",
                "checks": {"azure": ["azure_keyvault_secret_expiration", "azure_keyvault_key_expiration", "azure_storage_shared_key_disabled"]},
            },
            # ── Privileged Access (PA) ─────────────────────────────────
            {
                "id": "PA-1",
                "domain": "Privileged Access",
                "title": "Separate and limit highly privileged/administrative users",
                "description": "Limit subscription owners and high-privilege roles.",
                "checks": {"azure": ["azure_iam_owner_count", "azure_iam_no_custom_owner_roles", "azure_iam_sp_high_privilege"]},
            },
            {
                "id": "PA-2",
                "domain": "Privileged Access",
                "title": "Avoid standing access for user accounts and permissions",
                "description": "Use just-in-time access via PIM instead of permanent privileged roles.",
                "checks": {"azure": ["azure_pim_jit_access", "azure_classic_admins_removed"]},
            },
            {
                "id": "PA-3",
                "domain": "Privileged Access",
                "title": "Manage lifecycle of identities and entitlements",
                "description": "Implement identity lifecycle management for provisioning and deprovisioning.",
                "checks": {"azure": []},
            },
            {
                "id": "PA-4",
                "domain": "Privileged Access",
                "title": "Review and reconcile user access regularly",
                "description": "Conduct regular access reviews of privileged and guest users.",
                "checks": {"azure": ["azure_iam_guest_users_reviewed", "azure_iam_contributor_count"]},
            },
            {
                "id": "PA-5",
                "domain": "Privileged Access",
                "title": "Set up emergency access",
                "description": "Ensure break-glass accounts exist for emergency access.",
                "checks": {"azure": []},
            },
            {
                "id": "PA-6",
                "domain": "Privileged Access",
                "title": "Use privileged access workstations",
                "description": "Use secure, dedicated workstations for privileged operations.",
                "checks": {"azure": []},
            },
            {
                "id": "PA-7",
                "domain": "Privileged Access",
                "title": "Follow just enough administration (least privilege) principle",
                "description": "Use RBAC with least privilege and avoid broad roles like Contributor.",
                "checks": {"azure": ["azure_iam_contributor_count", "azure_aks_rbac_enabled", "azure_keyvault_rbac_authorization"]},
            },
            {
                "id": "PA-8",
                "domain": "Privileged Access",
                "title": "Determine access process for cloud provider support",
                "description": "Establish process for granting Microsoft support access via Customer Lockbox.",
                "checks": {"azure": []},
            },
            # ── Data Protection (DP) ───────────────────────────────────
            {
                "id": "DP-1",
                "domain": "Data Protection",
                "title": "Discover, classify, and label sensitive data",
                "description": "Use data classification and labeling to identify sensitive data.",
                "checks": {"azure": []},
            },
            {
                "id": "DP-2",
                "domain": "Data Protection",
                "title": "Monitor anomalies and threats targeting sensitive data",
                "description": "Monitor for unusual access patterns to sensitive data stores.",
                "checks": {"azure": ["azure_sql_atp_enabled", "azure_defender_storage", "azure_storage_no_public_access"]},
            },
            {
                "id": "DP-3",
                "domain": "Data Protection",
                "title": "Encrypt sensitive data in transit",
                "description": "Enforce HTTPS/TLS 1.2+ for all data in transit.",
                "checks": {"azure": ["azure_storage_https_only", "azure_storage_tls_12", "azure_sql_tls_12", "azure_appservice_https_only", "azure_appservice_tls_12"]},
            },
            {
                "id": "DP-4",
                "domain": "Data Protection",
                "title": "Enable data at rest encryption by default",
                "description": "Ensure all data stores have encryption at rest enabled.",
                "checks": {"azure": ["azure_vm_disk_encryption", "azure_sql_tde_enabled", "azure_storage_infrastructure_encryption", "azure_disk_unattached_encrypted"]},
            },
            {
                "id": "DP-5",
                "domain": "Data Protection",
                "title": "Use customer-managed key option in data at rest encryption when required",
                "description": "Use CMK for sensitive data that requires it for compliance.",
                "checks": {"azure": ["azure_storage_cmk_encryption"]},
            },
            {
                "id": "DP-6",
                "domain": "Data Protection",
                "title": "Use a secure key management process",
                "description": "Use Key Vault with proper lifecycle management for cryptographic keys.",
                "checks": {"azure": ["azure_keyvault_soft_delete", "azure_keyvault_purge_protection", "azure_keyvault_key_expiration"]},
            },
            {
                "id": "DP-7",
                "domain": "Data Protection",
                "title": "Use a secure certificate management process",
                "description": "Manage certificates with expiration tracking and rotation.",
                "checks": {"azure": ["azure_keyvault_secret_expiration"]},
            },
            {
                "id": "DP-8",
                "domain": "Data Protection",
                "title": "Ensure security of key and certificate repository",
                "description": "Secure Key Vault access with RBAC and network controls.",
                "checks": {"azure": ["azure_keyvault_rbac_authorization", "azure_keyvault_network_acls"]},
            },
            # ── Asset Management (AM) ──────────────────────────────────
            {
                "id": "AM-1",
                "domain": "Asset Management",
                "title": "Track asset inventory and their risks",
                "description": "Maintain an inventory of all cloud resources and their security posture.",
                "checks": {"azure": ["azure_resource_locks_configured"]},
            },
            {
                "id": "AM-2",
                "domain": "Asset Management",
                "title": "Use only approved services",
                "description": "Restrict allowed services using Azure Policy.",
                "checks": {"azure": ["azure_policy_assignments_exist", "azure_policy_security_initiative"]},
            },
            {
                "id": "AM-3",
                "domain": "Asset Management",
                "title": "Ensure security of asset lifecycle management",
                "description": "Ensure resources are securely decommissioned and data is cleaned.",
                "checks": {"azure": ["azure_storage_soft_delete_blobs"]},
            },
            {
                "id": "AM-4",
                "domain": "Asset Management",
                "title": "Limit access to asset management",
                "description": "Restrict who can manage Azure resources using RBAC.",
                "checks": {"azure": ["azure_iam_owner_count", "azure_iam_contributor_count"]},
            },
            {
                "id": "AM-5",
                "domain": "Asset Management",
                "title": "Use only approved applications in virtual machine",
                "description": "Restrict applications running on VMs using adaptive application controls.",
                "checks": {"azure": ["azure_vm_managed_disks", "azure_vm_antimalware_extension"]},
            },
            # ── Logging and Threat Detection (LT) ─────────────────────
            {
                "id": "LT-1",
                "domain": "Logging and Threat Detection",
                "title": "Enable threat detection capabilities",
                "description": "Enable Microsoft Defender for Cloud for all resource types.",
                "checks": {"azure": [
                    "azure_defender_vm", "azure_defender_sql", "azure_defender_appservice",
                    "azure_defender_storage", "azure_defender_keyvault", "azure_defender_kubernetes",
                    "azure_defender_containers", "azure_defender_arm", "azure_defender_dns",
                    "azure_defender_osrdb",
                ]},
            },
            {
                "id": "LT-2",
                "domain": "Logging and Threat Detection",
                "title": "Enable threat detection for identity and access management",
                "description": "Monitor for identity-based threats using Defender for Identity.",
                "checks": {"azure": ["azure_security_contact_configured", "azure_security_alert_notifications"]},
            },
            {
                "id": "LT-3",
                "domain": "Logging and Threat Detection",
                "title": "Enable logging for security investigation",
                "description": "Enable diagnostic logging on all services for security analysis.",
                "checks": {"azure": ["azure_monitor_log_profile", "azure_monitor_diagnostic_settings", "azure_sql_auditing_enabled", "azure_appservice_http_logging", "azure_nsg_flow_logs_enabled"]},
            },
            {
                "id": "LT-4",
                "domain": "Logging and Threat Detection",
                "title": "Enable network logging for security investigation",
                "description": "Enable NSG flow logs and traffic analytics.",
                "checks": {"azure": ["azure_nsg_flow_logs_enabled", "azure_network_watcher_enabled"]},
            },
            {
                "id": "LT-5",
                "domain": "Logging and Threat Detection",
                "title": "Centralize security log management and analysis",
                "description": "Send logs to a central Log Analytics workspace for SIEM integration.",
                "checks": {"azure": ["azure_monitor_diagnostic_settings"]},
            },
            {
                "id": "LT-6",
                "domain": "Logging and Threat Detection",
                "title": "Configure log storage retention",
                "description": "Set appropriate retention periods for security logs (365+ days).",
                "checks": {"azure": ["azure_monitor_log_retention_365"]},
            },
            {
                "id": "LT-7",
                "domain": "Logging and Threat Detection",
                "title": "Use approved time synchronization sources",
                "description": "Use NTP from approved sources for accurate timestamps.",
                "checks": {"azure": []},
            },
            # ── Incident Response (IR) ─────────────────────────────────
            {
                "id": "IR-1",
                "domain": "Incident Response",
                "title": "Preparation - update incident response plan",
                "description": "Maintain and test incident response procedures.",
                "checks": {"azure": []},
            },
            {
                "id": "IR-2",
                "domain": "Incident Response",
                "title": "Preparation - setup incident notification",
                "description": "Configure security alert notifications to appropriate teams.",
                "checks": {"azure": ["azure_security_contact_configured", "azure_security_alert_notifications"]},
            },
            {
                "id": "IR-3",
                "domain": "Incident Response",
                "title": "Detection and analysis - create incidents based on high-quality alerts",
                "description": "Use Defender for Cloud and Sentinel for alert correlation.",
                "checks": {"azure": [
                    "azure_alert_create_policy_assignment", "azure_alert_delete_nsg",
                    "azure_alert_create_update_nsg_rule", "azure_alert_delete_security_solution",
                    "azure_alert_create_update_sql_firewall",
                ]},
            },
            {
                "id": "IR-4",
                "domain": "Incident Response",
                "title": "Detection and analysis - investigate an incident",
                "description": "Ensure investigation tools and logs are available.",
                "checks": {"azure": ["azure_monitor_diagnostic_settings", "azure_nsg_flow_logs_enabled"]},
            },
            {
                "id": "IR-5",
                "domain": "Incident Response",
                "title": "Detection and analysis - prioritize incidents",
                "description": "Use severity and impact to prioritize incident response.",
                "checks": {"azure": []},
            },
            {
                "id": "IR-6",
                "domain": "Incident Response",
                "title": "Containment, eradication and recovery - automate incident handling",
                "description": "Use automation (Logic Apps, playbooks) for incident response.",
                "checks": {"azure": []},
            },
            {
                "id": "IR-7",
                "domain": "Incident Response",
                "title": "Post-incident activity - conduct lessons learned",
                "description": "Conduct post-incident reviews and retain evidence.",
                "checks": {"azure": ["azure_monitor_log_retention_365"]},
            },
            # ── Posture and Vulnerability Management (PV) ──────────────
            {
                "id": "PV-1",
                "domain": "Posture and Vulnerability Management",
                "title": "Define and establish secure configurations",
                "description": "Define security baselines for Azure services using Azure Policy.",
                "checks": {"azure": ["azure_policy_assignments_exist", "azure_policy_security_initiative", "azure_defender_auto_provisioning"]},
            },
            {
                "id": "PV-2",
                "domain": "Posture and Vulnerability Management",
                "title": "Audit and enforce secure configurations",
                "description": "Monitor and enforce configuration compliance via Policy.",
                "checks": {"azure": ["azure_policy_compliance_rate"]},
            },
            {
                "id": "PV-3",
                "domain": "Posture and Vulnerability Management",
                "title": "Define and establish secure configurations for compute resources",
                "description": "Harden VM, container, and serverless compute configurations.",
                "checks": {"azure": ["azure_vm_trusted_launch", "azure_vm_antimalware_extension", "azure_aks_authorized_ip_ranges"]},
            },
            {
                "id": "PV-4",
                "domain": "Posture and Vulnerability Management",
                "title": "Audit and enforce secure configurations for compute resources",
                "description": "Monitor compute resource compliance with security baselines.",
                "checks": {"azure": ["azure_appservice_ftp_disabled", "azure_appservice_remote_debugging_off", "azure_aks_azure_policy_addon"]},
            },
            {
                "id": "PV-5",
                "domain": "Posture and Vulnerability Management",
                "title": "Perform vulnerability assessments",
                "description": "Run regular vulnerability assessments on all resources.",
                "checks": {"azure": ["azure_sql_vulnerability_assessment", "azure_defender_vm"]},
            },
            {
                "id": "PV-6",
                "domain": "Posture and Vulnerability Management",
                "title": "Rapidly and automatically remediate vulnerabilities",
                "description": "Automate vulnerability remediation where possible.",
                "checks": {"azure": []},
            },
            {
                "id": "PV-7",
                "domain": "Posture and Vulnerability Management",
                "title": "Conduct regular red team operations",
                "description": "Perform penetration testing and red team exercises.",
                "checks": {"azure": []},
            },
            # ── Endpoint Security (ES) ─────────────────────────────────
            {
                "id": "ES-1",
                "domain": "Endpoint Security",
                "title": "Use Endpoint Detection and Response (EDR)",
                "description": "Deploy EDR solution on all endpoints.",
                "checks": {"azure": ["azure_defender_vm", "azure_vm_antimalware_extension"]},
            },
            {
                "id": "ES-2",
                "domain": "Endpoint Security",
                "title": "Use modern anti-malware software",
                "description": "Deploy modern anti-malware with real-time protection.",
                "checks": {"azure": ["azure_vm_antimalware_extension"]},
            },
            {
                "id": "ES-3",
                "domain": "Endpoint Security",
                "title": "Ensure anti-malware software and signatures are updated",
                "description": "Keep anti-malware signatures current.",
                "checks": {"azure": ["azure_vm_antimalware_extension"]},
            },
            # ── Backup and Recovery (BR) ───────────────────────────────
            {
                "id": "BR-1",
                "domain": "Backup and Recovery",
                "title": "Ensure regular automated backups",
                "description": "Configure automated backups with Recovery Services vaults.",
                "checks": {"azure": ["azure_backup_vault_exists"]},
            },
            {
                "id": "BR-2",
                "domain": "Backup and Recovery",
                "title": "Protect backup and recovery data",
                "description": "Encrypt backup data and ensure redundancy.",
                "checks": {"azure": ["azure_backup_vault_redundancy"]},
            },
            {
                "id": "BR-3",
                "domain": "Backup and Recovery",
                "title": "Monitor backups",
                "description": "Monitor backup operations for failures.",
                "checks": {"azure": ["azure_backup_vault_exists"]},
            },
            {
                "id": "BR-4",
                "domain": "Backup and Recovery",
                "title": "Regularly test backup",
                "description": "Periodically test backup restoration procedures.",
                "checks": {"azure": []},
            },
            # ── DevOps Security (DS) ───────────────────────────────────
            {
                "id": "DS-1",
                "domain": "DevOps Security",
                "title": "Conduct threat modeling",
                "description": "Perform threat modeling for applications and infrastructure.",
                "checks": {"azure": []},
            },
            {
                "id": "DS-2",
                "domain": "DevOps Security",
                "title": "Ensure software supply chain security",
                "description": "Secure CI/CD pipelines and validate dependencies.",
                "checks": {"azure": []},
            },
            {
                "id": "DS-3",
                "domain": "DevOps Security",
                "title": "Secure DevOps infrastructure",
                "description": "Harden DevOps tools, agents, and environments.",
                "checks": {"azure": []},
            },
            {
                "id": "DS-4",
                "domain": "DevOps Security",
                "title": "Integrate static application security testing into DevOps pipeline",
                "description": "Run SAST tools in CI/CD pipelines.",
                "checks": {"azure": []},
            },
            {
                "id": "DS-5",
                "domain": "DevOps Security",
                "title": "Integrate dynamic application security testing into DevOps pipeline",
                "description": "Run DAST tools against deployed applications.",
                "checks": {"azure": []},
            },
            {
                "id": "DS-6",
                "domain": "DevOps Security",
                "title": "Enforce security of workload throughout DevOps lifecycle",
                "description": "Enforce security gates throughout the development lifecycle.",
                "checks": {"azure": ["azure_aks_azure_policy_addon"]},
            },
            {
                "id": "DS-7",
                "domain": "DevOps Security",
                "title": "Enable logging and monitoring in DevOps",
                "description": "Enable audit logging for DevOps platforms.",
                "checks": {"azure": []},
            },
            # ── Governance and Strategy (GS) ───────────────────────────
            {
                "id": "GS-1",
                "domain": "Governance and Strategy",
                "title": "Align organization roles, responsibilities and accountabilities",
                "description": "Define clear security roles and governance structure.",
                "checks": {"azure": ["azure_policy_assignments_exist"]},
            },
            {
                "id": "GS-2",
                "domain": "Governance and Strategy",
                "title": "Define and implement enterprise segmentation/separation of duties strategy",
                "description": "Implement subscription and resource group segmentation.",
                "checks": {"azure": ["azure_policy_security_initiative"]},
            },
            {
                "id": "GS-3",
                "domain": "Governance and Strategy",
                "title": "Define and implement data protection strategy",
                "description": "Establish data classification and encryption standards.",
                "checks": {"azure": ["azure_storage_cmk_encryption", "azure_storage_infrastructure_encryption"]},
            },
            {
                "id": "GS-4",
                "domain": "Governance and Strategy",
                "title": "Define and implement network security strategy",
                "description": "Establish network security architecture and controls.",
                "checks": {"azure": ["azure_subnet_has_nsg", "azure_nsg_default_deny_inbound"]},
            },
            {
                "id": "GS-5",
                "domain": "Governance and Strategy",
                "title": "Define and implement security posture management strategy",
                "description": "Implement continuous security posture assessment using Defender for Cloud.",
                "checks": {"azure": ["azure_policy_compliance_rate", "azure_defender_auto_provisioning"]},
            },
            {
                "id": "GS-6",
                "domain": "Governance and Strategy",
                "title": "Define and implement identity and privileged access strategy",
                "description": "Establish identity governance and privileged access management.",
                "checks": {"azure": ["azure_iam_mfa_enabled_all_users", "azure_pim_jit_access"]},
            },
            {
                "id": "GS-7",
                "domain": "Governance and Strategy",
                "title": "Define and implement logging, threat detection and incident response strategy",
                "description": "Establish monitoring, detection, and response processes.",
                "checks": {"azure": ["azure_security_contact_configured", "azure_security_alert_notifications"]},
            },
            {
                "id": "GS-8",
                "domain": "Governance and Strategy",
                "title": "Define and implement backup and recovery strategy",
                "description": "Establish backup policies and disaster recovery procedures.",
                "checks": {"azure": ["azure_backup_vault_exists", "azure_backup_vault_redundancy"]},
            },
            {
                "id": "GS-9",
                "domain": "Governance and Strategy",
                "title": "Define and implement endpoint security strategy",
                "description": "Establish endpoint protection standards and monitoring.",
                "checks": {"azure": ["azure_vm_antimalware_extension", "azure_defender_vm"]},
            },
            {
                "id": "GS-10",
                "domain": "Governance and Strategy",
                "title": "Define and implement DevOps security strategy",
                "description": "Integrate security into DevOps practices and toolchain.",
                "checks": {"azure": []},
            },
        ],
    },

    # ═══════════════════════════════════════════════════════════════════
    # CIS AWS Foundations Benchmark v3.0
    # ═══════════════════════════════════════════════════════════════════
    "CIS-AWS-3.0": {
        "name": "CIS Amazon Web Services Foundations Benchmark v3.0",
        "description": "CIS Benchmark for AWS providing prescriptive guidance for configuring security options, aligned with CIS Controls v8.",
        "category": "cis",
        "controls": [
            {
                "id": "1.1",
                "title": "Maintain current contact details",
                "description": "Ensure contact email and security contacts are current for AWS account.",
                "checks": {"aws": ["iam_root_mfa_enabled"]},
            },
            {
                "id": "1.4",
                "title": "Ensure no root user access key exists",
                "description": "The root user is the most privileged user. Remove all access keys associated with the root user.",
                "checks": {"aws": ["iam_no_root_access_key", "iam_root_mfa_enabled"]},
            },
            {
                "id": "1.5",
                "title": "Ensure MFA is enabled for the root user account",
                "description": "Enable hardware or virtual MFA for the root user to add an extra layer of protection.",
                "checks": {"aws": ["iam_root_mfa_enabled"]},
            },
            {
                "id": "1.8",
                "title": "Ensure IAM password policy requires minimum length of 14 or greater",
                "description": "Set the password policy to require at least 14 characters.",
                "checks": {"aws": ["iam_password_policy_strong", "iam_password_policy_exists"]},
            },
            {
                "id": "1.10",
                "title": "Ensure multi-factor authentication (MFA) is enabled for all IAM users",
                "description": "Enable MFA for all IAM users that have a console password.",
                "checks": {"aws": ["iam_user_mfa_enabled"]},
            },
            {
                "id": "1.12",
                "title": "Ensure credentials unused for 45 days or greater are disabled",
                "description": "Disable credentials that have not been used within 45 days.",
                "checks": {"aws": ["iam_user_unused_credentials_45days"]},
            },
            {
                "id": "1.14",
                "title": "Ensure access keys are rotated every 90 days or less",
                "description": "Rotate access keys regularly to reduce risk of compromised keys.",
                "checks": {"aws": ["iam_access_key_rotation"]},
            },
            {
                "id": "1.15",
                "title": "Ensure IAM Users Receive Permissions Only Through Groups",
                "description": "Do not attach policies directly to users; use groups instead.",
                "checks": {"aws": ["iam_user_no_inline_policies", "iam_group_no_inline_policies"]},
            },
            {
                "id": "1.16",
                "title": "Ensure IAM policies that allow full administrative privileges are not attached",
                "description": "Do not create IAM policies with Statement Effect Allow and Action * on Resource *.",
                "checks": {"aws": ["iam_no_star_policies"]},
            },
            {
                "id": "1.17",
                "title": "Ensure a support role has been created to manage incidents with AWS Support",
                "description": "Create an IAM role for managing incidents with AWS Support.",
                "checks": {"aws": ["iam_support_role_created"]},
            },
            {
                "id": "1.20",
                "title": "Ensure that IAM Access Analyzer is enabled for all regions",
                "description": "Enable IAM Access Analyzer to identify resources shared with external entities.",
                "checks": {"aws": ["iam_access_analyzer_enabled"]},
            },
            {
                "id": "2.1.1",
                "title": "Ensure S3 Bucket Policy is set to deny HTTP requests",
                "description": "At the S3 bucket level, configure a bucket policy to deny any HTTP requests.",
                "checks": {"aws": ["s3_bucket_ssl_required", "s3_bucket_encryption_enabled"]},
            },
            {
                "id": "2.1.2",
                "title": "Ensure MFA Delete is enabled on S3 buckets",
                "description": "Enable MFA Delete to add an additional layer of security for S3 bucket versioning.",
                "checks": {"aws": ["s3_bucket_mfa_delete"]},
            },
            {
                "id": "2.1.4",
                "title": "Ensure S3 buckets have block public access enabled",
                "description": "Block all public access to S3 buckets by default.",
                "checks": {"aws": ["s3_bucket_public_access_blocked"]},
            },
            {
                "id": "2.1.5",
                "title": "Ensure S3 buckets have Object Lock enabled",
                "description": "Enable Object Lock on S3 buckets for WORM compliance.",
                "checks": {"aws": ["s3_bucket_object_lock"]},
            },
            {
                "id": "2.2.1",
                "title": "Ensure EBS Volume Encryption is Enabled in all Regions",
                "description": "Enable default EBS encryption to ensure all new EBS volumes are encrypted.",
                "checks": {"aws": ["ec2_ebs_default_encryption", "ec2_ebs_volume_encrypted"]},
            },
            {
                "id": "2.3.1",
                "title": "Ensure RDS instances are encrypted at rest",
                "description": "Ensure all RDS instances have encryption at rest enabled.",
                "checks": {"aws": ["rds_encryption_enabled", "rds_public_access_disabled"]},
            },
            {
                "id": "2.4.1",
                "title": "Ensure EFS is encrypted at rest",
                "description": "EFS file systems should be encrypted at rest.",
                "checks": {"aws": ["efs_encryption_enabled"]},
            },
            {
                "id": "3.1",
                "title": "Ensure CloudTrail is enabled in all regions",
                "description": "Enable CloudTrail across all regions and ensure log file validation.",
                "checks": {"aws": ["cloudtrail_multiregion", "cloudtrail_enabled", "cloudtrail_log_validation"]},
            },
            {
                "id": "3.2",
                "title": "Ensure CloudTrail log file validation is enabled",
                "description": "Enable log file validation to detect unauthorized modification of log files.",
                "checks": {"aws": ["cloudtrail_log_validation"]},
            },
            {
                "id": "3.4",
                "title": "Ensure CloudTrail trails are integrated with CloudWatch Logs",
                "description": "Send CloudTrail logs to CloudWatch for real-time monitoring.",
                "checks": {"aws": ["cloudtrail_integrated_cloudwatch"]},
            },
            {
                "id": "3.5",
                "title": "Ensure AWS Config is enabled in all regions",
                "description": "Enable AWS Config to record configuration changes across all regions.",
                "checks": {"aws": ["config_recorder_enabled"]},
            },
            {
                "id": "3.6",
                "title": "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
                "description": "Enable server access logging on the S3 bucket that stores CloudTrail logs.",
                "checks": {"aws": ["cloudtrail_s3_bucket_logging"]},
            },
            {
                "id": "3.7",
                "title": "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
                "description": "Configure CloudTrail to use SSE-KMS encryption for log files.",
                "checks": {"aws": ["cloudtrail_encrypted", "kms_key_rotation_enabled"]},
            },
            {
                "id": "3.8",
                "title": "Ensure rotation for customer-created symmetric CMKs is enabled",
                "description": "Enable automatic annual rotation for customer-managed symmetric KMS keys.",
                "checks": {"aws": ["kms_key_rotation_enabled"]},
            },
            {
                "id": "3.9",
                "title": "Ensure VPC flow logging is enabled in all VPCs",
                "description": "Enable VPC flow logs to capture information about IP traffic.",
                "checks": {"aws": ["vpc_flow_logs_enabled"]},
            },
            {
                "id": "4.1",
                "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
                "description": "Remove inbound rules that allow unrestricted SSH access.",
                "checks": {"aws": ["ec2_default_sg_no_traffic", "ec2_sg_no_wide_open_ports"]},
            },
            {
                "id": "4.2",
                "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
                "description": "Remove inbound rules that allow unrestricted RDP access.",
                "checks": {"aws": ["ec2_default_sg_no_traffic", "ec2_sg_no_wide_open_ports"]},
            },
            {
                "id": "4.3",
                "title": "Ensure the default security group of every VPC restricts all traffic",
                "description": "Configure the default security group to restrict all traffic.",
                "checks": {"aws": ["vpc_default_sg_restricts_all", "ec2_default_sg_no_traffic"]},
            },
            {
                "id": "5.1",
                "title": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to all ports",
                "description": "Remove unrestricted inbound rules from Network ACLs.",
                "checks": {"aws": ["vpc_no_unrestricted_nacl"]},
            },
            {
                "id": "5.2",
                "title": "Ensure EC2 instances do not have public IP addresses",
                "description": "Launch EC2 instances without public IP addresses unless necessary.",
                "checks": {"aws": ["ec2_instance_no_public_ip"]},
            },
            {
                "id": "5.6",
                "title": "Ensure IMDSv2 is enabled on all EC2 instances",
                "description": "Require IMDSv2 on all EC2 instances to mitigate SSRF attacks.",
                "checks": {"aws": ["ec2_imdsv2_required"]},
            },
        ],
    },
    # ═══════════════════════════════════════════════════════════════════
    # CIS GCP Foundations Benchmark v3.0
    # ═══════════════════════════════════════════════════════════════════
    "CIS-GCP-3.0": {
        "name": "CIS Google Cloud Platform Foundation Benchmark v3.0",
        "description": "CIS Benchmark for GCP providing prescriptive guidance for configuring security options, aligned with CIS Controls v8.",
        "category": "cis",
        "controls": [
            {
                "id": "1.1",
                "title": "Ensure that corporate login credentials are used",
                "description": "Use corporate login credentials instead of personal accounts.",
                "checks": {"gcp": ["gcp_iam_corp_login_required"]},
            },
            {
                "id": "1.4",
                "title": "Ensure that there are only GCP-managed service account keys",
                "description": "Eliminate user-managed service account keys where possible.",
                "checks": {"gcp": ["gcp_iam_no_user_managed_sa_keys", "gcp_iam_sa_key_rotation"]},
            },
            {
                "id": "1.5",
                "title": "Ensure that Service Account has no admin privileges",
                "description": "Service accounts should not have admin or owner-level privileges.",
                "checks": {"gcp": ["gcp_iam_no_sa_admin_key", "gcp_iam_no_primitive_roles"]},
            },
            {
                "id": "1.6",
                "title": "Ensure IAM users are not assigned the Service Account User or Token Creator roles at project level",
                "description": "Restrict Service Account User and Token Creator roles.",
                "checks": {"gcp": ["gcp_iam_separation_of_duties"]},
            },
            {
                "id": "1.8",
                "title": "Ensure that Separation of Duties is enforced",
                "description": "No user should have both Service Account Admin and Service Account User roles.",
                "checks": {"gcp": ["gcp_iam_separation_of_duties"]},
            },
            {
                "id": "1.10",
                "title": "Ensure KMS encryption keys are rotated within a period of 90 days",
                "description": "Set a key rotation period of 90 days or less for KMS keys.",
                "checks": {"gcp": ["gcp_kms_key_rotation"]},
            },
            {
                "id": "1.11",
                "title": "Ensure that Separation of Duties is enforced while assigning KMS related roles",
                "description": "No user should have both KMS Admin and any CryptoKey role.",
                "checks": {"gcp": ["gcp_kms_no_public_access"]},
            },
            {
                "id": "1.15",
                "title": "Ensure API Keys are restricted to only APIs that application needs access",
                "description": "Restrict API keys to limit their use to specific APIs.",
                "checks": {"gcp": ["gcp_iam_api_keys_restricted"]},
            },
            {
                "id": "2.1",
                "title": "Ensure that Cloud Audit Logging is configured properly",
                "description": "Enable Data Access audit logs for all services and all users.",
                "checks": {"gcp": ["gcp_logging_audit_logs_enabled", "gcp_logging_sinks_configured"]},
            },
            {
                "id": "2.2",
                "title": "Ensure that sinks are configured for all log entries",
                "description": "Create a sink that captures all activity logs.",
                "checks": {"gcp": ["gcp_logging_sinks_configured"]},
            },
            {
                "id": "2.5",
                "title": "Ensure that Logging is enabled for Cloud Storage buckets",
                "description": "Enable access logging and storage logging on Cloud Storage buckets.",
                "checks": {"gcp": ["gcp_storage_logging_enabled"]},
            },
            {
                "id": "2.6",
                "title": "Ensure that retention policies on Cloud Storage buckets are configured using Bucket Lock",
                "description": "Set retention policies with Bucket Lock on storage buckets.",
                "checks": {"gcp": ["gcp_logging_bucket_retention", "gcp_storage_retention_policy"]},
            },
            {
                "id": "2.12",
                "title": "Ensure that Cloud DNS logging is enabled for all VPC networks",
                "description": "Enable DNS logging for each VPC to record DNS queries.",
                "checks": {"gcp": ["gcp_logging_dns_logging"]},
            },
            {
                "id": "3.1",
                "title": "Ensure that the default network does not exist in a project",
                "description": "Delete the default network to enforce intentional network architecture.",
                "checks": {"gcp": ["gcp_firewall_no_default_allow"]},
            },
            {
                "id": "3.6",
                "title": "Ensure SSH access is restricted from the internet",
                "description": "GCP firewall rules should not allow SSH from 0.0.0.0/0.",
                "checks": {"gcp": ["gcp_firewall_open_22"]},
            },
            {
                "id": "3.7",
                "title": "Ensure RDP access is restricted from the internet",
                "description": "GCP firewall rules should not allow RDP from 0.0.0.0/0.",
                "checks": {"gcp": ["gcp_firewall_open_3389"]},
            },
            {
                "id": "3.8",
                "title": "Ensure VPC Flow logs are enabled for every subnet",
                "description": "Enable VPC Flow Logs on every VPC subnet for network monitoring.",
                "checks": {"gcp": ["gcp_logging_vpc_flow_logs", "gcp_network_flow_logs_enabled"]},
            },
            {
                "id": "3.9",
                "title": "Ensure Private Google Access is enabled for all VPC subnets",
                "description": "Enable Private Google Access for subnets with private instances.",
                "checks": {"gcp": ["gcp_network_private_google_access"]},
            },
            {
                "id": "4.1",
                "title": "Ensure that instances are not configured to use default service accounts",
                "description": "Do not use the default Compute Engine service account for VM instances.",
                "checks": {"gcp": ["gcp_compute_no_default_sa"]},
            },
            {
                "id": "4.3",
                "title": "Ensure Compute instances do not have public IP addresses",
                "description": "Launch instances without external IP addresses unless necessary.",
                "checks": {"gcp": ["gcp_compute_no_external_ip"]},
            },
            {
                "id": "4.4",
                "title": "Ensure Shielded VM is enabled on Compute instances",
                "description": "Enable Shielded VM features (Secure Boot, vTPM, Integrity Monitoring).",
                "checks": {"gcp": ["gcp_compute_shielded_vm"]},
            },
            {
                "id": "4.5",
                "title": "Ensure OS Login is enabled for all Compute instances",
                "description": "Use OS Login to manage SSH access using IAM roles.",
                "checks": {"gcp": ["gcp_compute_os_login"]},
            },
            {
                "id": "4.6",
                "title": "Ensure serial port connection is disabled for Compute instances",
                "description": "Disable serial port access to prevent interactive console access.",
                "checks": {"gcp": ["gcp_compute_serial_port_disabled"]},
            },
            {
                "id": "4.8",
                "title": "Ensure Compute instances are launched with Confidential Computing",
                "description": "Enable Confidential Computing for memory encryption on VMs.",
                "checks": {"gcp": ["gcp_compute_confidential_computing"]},
            },
            {
                "id": "4.11",
                "title": "Ensure that Compute instances have IP forwarding disabled",
                "description": "Disable IP forwarding unless the instance is used as a router.",
                "checks": {"gcp": ["gcp_compute_ip_forwarding_disabled"]},
            },
            {
                "id": "5.1",
                "title": "Ensure uniform bucket-level access is enabled on Cloud Storage",
                "description": "Use uniform bucket-level access for consistent permissions.",
                "checks": {"gcp": ["gcp_storage_uniform_access"]},
            },
            {
                "id": "5.2",
                "title": "Ensure Cloud Storage buckets are not anonymously or publicly accessible",
                "description": "Remove public access from Cloud Storage buckets.",
                "checks": {"gcp": ["gcp_storage_no_public_access"]},
            },
            {
                "id": "6.1",
                "title": "Ensure Cloud SQL instances require all incoming connections to use SSL",
                "description": "Configure Cloud SQL to require SSL/TLS for all connections.",
                "checks": {"gcp": ["gcp_sql_ssl_required"]},
            },
            {
                "id": "6.2",
                "title": "Ensure Cloud SQL database instances do not have public IPs",
                "description": "Configure Cloud SQL instances with private IPs only.",
                "checks": {"gcp": ["gcp_sql_no_public_ip", "gcp_sql_no_public_networks"]},
            },
            {
                "id": "6.3",
                "title": "Ensure automated backups are configured for Cloud SQL",
                "description": "Enable automated backups and PITR for Cloud SQL instances.",
                "checks": {"gcp": ["gcp_sql_backup_enabled", "gcp_sql_pitr_enabled"]},
            },
            {
                "id": "7.1",
                "title": "Ensure GKE clusters have Stackdriver Logging enabled",
                "description": "Enable Stackdriver Logging for GKE clusters.",
                "checks": {"gcp": ["gcp_gke_cluster_logging"]},
            },
            {
                "id": "7.3",
                "title": "Ensure private cluster is enabled for GKE",
                "description": "Enable private cluster to restrict public access to the API server.",
                "checks": {"gcp": ["gcp_gke_private_cluster"]},
            },
            {
                "id": "7.4",
                "title": "Ensure Master Authorized Networks is enabled",
                "description": "Restrict access to the GKE cluster master endpoint.",
                "checks": {"gcp": ["gcp_gke_master_auth_networks"]},
            },
            {
                "id": "7.5",
                "title": "Ensure Network Policy is enabled on GKE",
                "description": "Enable Network Policy to control pod-to-pod communication.",
                "checks": {"gcp": ["gcp_gke_network_policy"]},
            },
            {
                "id": "7.7",
                "title": "Ensure Workload Identity is enabled for GKE",
                "description": "Use Workload Identity for secure IAM authentication from pods.",
                "checks": {"gcp": ["gcp_gke_workload_identity"]},
            },
            {
                "id": "7.8",
                "title": "Ensure Shielded GKE Nodes are enabled",
                "description": "Enable Shielded GKE Nodes for integrity verification.",
                "checks": {"gcp": ["gcp_gke_shielded_nodes"]},
            },
            {
                "id": "7.10",
                "title": "Ensure Binary Authorization is configured for GKE",
                "description": "Enable Binary Authorization to deploy only trusted container images.",
                "checks": {"gcp": ["gcp_gke_binary_auth"]},
            },
        ],
    },
    # ═══════════════════════════════════════════════════════════════════
    # CIS Kubernetes Benchmark v1.8
    # ═══════════════════════════════════════════════════════════════════
    "CIS-K8s-1.8": {
        "name": "CIS Kubernetes Benchmark v1.8",
        "description": "CIS Benchmark for Kubernetes providing configuration guidelines for securing Kubernetes clusters.",
        "category": "cis",
        "controls": [
            {
                "id": "1.2.1",
                "title": "Ensure audit logging is enabled",
                "description": "Enable audit logging for the API server to record all requests.",
                "checks": {"kubernetes": ["k8s_api_audit_logging"]},
            },
            {
                "id": "1.2.6",
                "title": "Ensure the API server TLS certificates are valid",
                "description": "Use valid TLS certificates for API server communication.",
                "checks": {"kubernetes": ["k8s_api_tls_enabled"]},
            },
            {
                "id": "4.1.1",
                "title": "Ensure RBAC is properly configured",
                "description": "Do not grant cluster-admin to non-admin subjects. Avoid wildcards.",
                "checks": {"kubernetes": ["k8s_rbac_no_wildcard_cluster_admin", "k8s_rbac_no_wildcard_verbs"]},
            },
            {
                "id": "4.1.5",
                "title": "Ensure default service account tokens are not automounted",
                "description": "Disable automatic mounting of default service account tokens.",
                "checks": {"kubernetes": ["k8s_rbac_no_default_sa_token"]},
            },
            {
                "id": "4.1.8",
                "title": "Limit access to Secrets",
                "description": "Restrict access to the secrets resource to only authorized subjects.",
                "checks": {"kubernetes": ["k8s_rbac_limit_secrets_access"]},
            },
            {
                "id": "5.1.1",
                "title": "Ensure pods do not run in the default namespace",
                "description": "Create namespaces for workloads to isolate and manage resources.",
                "checks": {"kubernetes": ["k8s_no_pods_in_default"]},
            },
            {
                "id": "5.1.3",
                "title": "Ensure namespaces have network policies defined",
                "description": "Define network policies per namespace to control pod traffic.",
                "checks": {"kubernetes": ["k8s_namespace_network_policy", "k8s_network_deny_all_default"]},
            },
            {
                "id": "5.1.4",
                "title": "Ensure resource quotas and limit ranges are set per namespace",
                "description": "Set resource quotas and limit ranges to prevent resource exhaustion.",
                "checks": {"kubernetes": ["k8s_namespace_resource_quotas", "k8s_namespace_limit_ranges"]},
            },
            {
                "id": "5.2.1",
                "title": "Ensure Pod Security Admission is configured",
                "description": "Configure Pod Security Admission to enforce pod security standards.",
                "checks": {"kubernetes": ["k8s_admission_pod_security"]},
            },
            {
                "id": "5.4.1",
                "title": "Ensure Secrets are encrypted at rest in etcd",
                "description": "Configure encryption providers to encrypt Secrets stored in etcd.",
                "checks": {"kubernetes": ["k8s_secrets_encrypted_etcd"]},
            },
            {
                "id": "5.4.2",
                "title": "Ensure Secrets are not stored as environment variables",
                "description": "Use volume mounts for Secrets instead of environment variables.",
                "checks": {"kubernetes": ["k8s_secrets_no_env_vars"]},
            },
            {
                "id": "5.7.1",
                "title": "Ensure Services of type LoadBalancer are not exposed publicly",
                "description": "Restrict LoadBalancer Services to internal use or use ingress controllers.",
                "checks": {"kubernetes": ["k8s_service_no_loadbalancer_public"]},
            },
            {
                "id": "5.7.2",
                "title": "Ensure Services of type NodePort are avoided",
                "description": "Avoid NodePort services; use ClusterIP and Ingress instead.",
                "checks": {"kubernetes": ["k8s_service_no_nodeport"]},
            },
            {
                "id": "5.7.4",
                "title": "Ensure Network Policies define ingress rules",
                "description": "Ensure all network policies have explicit ingress rules.",
                "checks": {"kubernetes": ["k8s_network_ingress_rules"]},
            },
        ],
    },
    # ═══════════════════════════════════════════════════════════════════
    # CIS Microsoft 365 Foundations Benchmark v3.0
    # ═══════════════════════════════════════════════════════════════════
    "CIS-M365-3.0": {
        "name": "CIS Microsoft 365 Foundations Benchmark v3.0",
        "description": "CIS Benchmark for Microsoft 365 tenant security covering identity, data protection, email security, and collaboration settings.",
        "category": "cis",
        "controls": [
            {
                "id": "1.1.1",
                "title": "Ensure Administrative Accounts Use MFA",
                "description": "All admin accounts should have MFA enabled.",
                "checks": {"m365": ["m365_admin_mfa_enforced", "m365_user_mfa_registered"]},
            },
            {
                "id": "1.1.3",
                "title": "Ensure Security Defaults are enabled or Conditional Access policies are configured",
                "description": "Enable Security Defaults or equivalent Conditional Access policies.",
                "checks": {"m365": ["m365_security_defaults_enabled", "m365_ca_policies_configured"]},
            },
            {
                "id": "1.1.4",
                "title": "Ensure Conditional Access policies are configured to require MFA",
                "description": "Require MFA via Conditional Access policies for all users.",
                "checks": {"m365": ["m365_ca_require_mfa", "m365_ca_sign_in_risk"]},
            },
            {
                "id": "1.1.6",
                "title": "Ensure that legacy authentication is blocked via Conditional Access",
                "description": "Block legacy authentication protocols that cannot enforce MFA.",
                "checks": {"m365": ["m365_ca_block_legacy_auth", "m365_legacy_auth_blocked"]},
            },
            {
                "id": "1.2.1",
                "title": "Ensure the admin portal is restricted to admins",
                "description": "Limit the number of users with admin privileges.",
                "checks": {"m365": ["m365_privileged_accounts_limited"]},
            },
            {
                "id": "1.3.1",
                "title": "Ensure password policies do not expire",
                "description": "Set passwords to never expire (rely on MFA and breach detection instead).",
                "checks": {"m365": ["m365_password_never_expire_disabled"]},
            },
            {
                "id": "1.3.3",
                "title": "Ensure Self-Service Password Reset is enabled",
                "description": "Enable SSPR to reduce helpdesk calls and improve security.",
                "checks": {"m365": ["m365_self_service_password_reset"]},
            },
            {
                "id": "2.1.1",
                "title": "Ensure Microsoft Defender for Endpoint is enabled",
                "description": "Enable Defender for Endpoint for threat detection.",
                "checks": {"m365": ["m365_defender_sensor_active"]},
            },
            {
                "id": "2.1.4",
                "title": "Ensure Safe Attachments policy is enabled",
                "description": "Enable Safe Attachments in Exchange Online Protection.",
                "checks": {"m365": ["m365_safe_attachments_enabled"]},
            },
            {
                "id": "2.1.5",
                "title": "Ensure Safe Links policy is enabled",
                "description": "Enable Safe Links to protect users from malicious URLs.",
                "checks": {"m365": ["m365_safe_links_enabled"]},
            },
            {
                "id": "2.1.6",
                "title": "Ensure anti-phishing policy is configured",
                "description": "Configure anti-phishing policies with impersonation protection.",
                "checks": {"m365": ["m365_anti_phishing_policy"]},
            },
            {
                "id": "3.1.1",
                "title": "Ensure DLP policies are configured",
                "description": "Configure Data Loss Prevention policies for sensitive data.",
                "checks": {"m365": ["m365_dlp_policies_configured"]},
            },
            {
                "id": "3.2.1",
                "title": "Ensure sensitivity labels are published and in use",
                "description": "Publish sensitivity labels for document and email classification.",
                "checks": {"m365": ["m365_sensitivity_labels_enabled"]},
            },
            {
                "id": "3.2.2",
                "title": "Ensure Azure Information Protection encryption is enabled",
                "description": "Enable AIP encryption for sensitive content protection.",
                "checks": {"m365": ["m365_aip_encryption_enabled"]},
            },
            {
                "id": "4.1.1",
                "title": "Ensure SPF records are configured",
                "description": "Configure SPF records to prevent email spoofing.",
                "checks": {"m365": ["m365_spf_configured"]},
            },
            {
                "id": "4.1.2",
                "title": "Ensure DKIM is configured for all domains",
                "description": "Enable DKIM signing for email authentication.",
                "checks": {"m365": ["m365_dkim_configured"]},
            },
            {
                "id": "4.1.3",
                "title": "Ensure DMARC is configured for all domains",
                "description": "Configure DMARC records for email authentication and reporting.",
                "checks": {"m365": ["m365_dmarc_configured"]},
            },
            {
                "id": "5.1.1",
                "title": "Ensure external sharing in SharePoint is restricted",
                "description": "Restrict external sharing in SharePoint and OneDrive.",
                "checks": {"m365": ["m365_sharepoint_sharing_restricted", "m365_external_sharing_restricted"]},
            },
            {
                "id": "5.2.1",
                "title": "Ensure Teams external access is restricted",
                "description": "Restrict external access in Microsoft Teams.",
                "checks": {"m365": ["m365_teams_external_access_restricted"]},
            },
            {
                "id": "5.2.2",
                "title": "Ensure guest access in Teams is restricted",
                "description": "Limit guest access capabilities in Microsoft Teams.",
                "checks": {"m365": ["m365_guest_access_restricted"]},
            },
            {
                "id": "5.3.1",
                "title": "Ensure OneDrive sync is restricted",
                "description": "Restrict OneDrive sync to managed devices.",
                "checks": {"m365": ["m365_onedrive_sync_restricted"]},
            },
        ],
    },
    # ═══════════════════════════════════════════════════════════════════
    # CSA Cloud Controls Matrix (CCM) v4.1
    # ═══════════════════════════════════════════════════════════════════
    "CCM-4.1": {
        "name": "CSA Cloud Controls Matrix v4.1",
        "description": "Cloud Security Alliance Cloud Controls Matrix - a cybersecurity control framework for cloud computing aligned with CSA best practices, ISO 27001/27002, NIST, PCI-DSS and AICPA TSC.",
        "category": "industry",
        "controls": [
            {
                "id": "AIS-01",
                "domain": "Application & Interface Security",
                "title": "Application Security",
                "description": "Establish policies and procedures for application security including secure SDLC, code review, and API protection.",
                "checks": {
                    "aws": ["lambda_runtime_supported", "lambda_vpc_configured", "apigateway_rest_api_logging", "apigateway_waf_enabled"],
                    "gcp": ["gcp_gke_binary_auth"],
                    "kubernetes": ["k8s_admission_pod_security"],
                },
            },
            {
                "id": "AIS-02",
                "domain": "Application & Interface Security",
                "title": "Application Security Testing",
                "description": "Perform application security testing (SAST, DAST) for all deployed applications.",
                "checks": {
                    "aws": ["ecr_image_scanning"],
                    "gcp": ["gcp_gke_binary_auth"],
                },
            },
            {
                "id": "AIS-04",
                "domain": "Application & Interface Security",
                "title": "Secure Application Design",
                "description": "Implement application security controls including input validation, output encoding, and error handling.",
                "checks": {
                    "aws": ["waf_web_acl_exists", "cloudfront_waf_enabled"],
                    "gcp": [],
                },
            },
            {
                "id": "BCR-01",
                "domain": "Business Continuity Management & Operational Resilience",
                "title": "Business Continuity Planning",
                "description": "Establish and maintain a business continuity plan to ensure operational resilience.",
                "checks": {
                    "aws": ["rds_multi_az_enabled", "rds_backup_enabled", "backup_plan_exists", "dynamodb_pitr_enabled"],
                    "gcp": ["gcp_sql_backup_enabled", "gcp_sql_pitr_enabled"],
                },
            },
            {
                "id": "BCR-03",
                "domain": "Business Continuity Management & Operational Resilience",
                "title": "Backup and Recovery",
                "description": "Perform periodic backup and restoration testing to ensure data recovery capabilities.",
                "checks": {
                    "aws": ["backup_plan_exists", "backup_vault_encrypted", "rds_backup_enabled", "s3_bucket_versioning_enabled"],
                    "gcp": ["gcp_sql_backup_enabled", "gcp_storage_versioning"],
                    "alibaba": ["ali_rds_backup_retention", "ali_oss_versioning_enabled"],
                    "snowflake": ["snowflake_data_retention_configured", "snowflake_failover_configured"],
                },
            },
            {
                "id": "CCC-01",
                "domain": "Change Control & Configuration Management",
                "title": "Change Management Policy",
                "description": "Establish change management policies and procedures for all IT infrastructure changes.",
                "checks": {
                    "aws": ["config_recorder_enabled"],
                    "gcp": ["gcp_logging_audit_logs_enabled"],
                    "servicenow": ["servicenow_change_management"],
                },
            },
            {
                "id": "CEK-01",
                "domain": "Cryptography, Encryption & Key Management",
                "title": "Encryption and Key Management Policy",
                "description": "Define cryptographic standards, approved algorithms, and key management procedures.",
                "checks": {
                    "aws": ["kms_key_rotation_enabled", "cloudtrail_encrypted", "s3_bucket_encryption_enabled"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_kms_hsm_protection"],
                    "alibaba": ["ali_kms_key_rotation", "ali_kms_cmk_enabled"],
                },
            },
            {
                "id": "CEK-03",
                "domain": "Cryptography, Encryption & Key Management",
                "title": "Data Encryption",
                "description": "Encrypt data at rest and in transit using approved encryption standards.",
                "checks": {
                    "aws": ["ec2_ebs_volume_encrypted", "ec2_ebs_default_encryption", "rds_encryption_enabled", "s3_bucket_encryption_enabled", "efs_encryption_enabled", "es_encryption_at_rest", "dynamodb_table_encrypted_kms", "sqs_queue_encrypted", "sns_topic_encrypted", "redshift_cluster_encrypted"],
                    "gcp": ["gcp_compute_disk_encryption_cmek", "gcp_storage_cmek_encryption", "gcp_sql_cmek_encryption", "gcp_bigquery_cmek_encryption"],
                    "alibaba": ["ali_ecs_disk_encryption", "ali_rds_encryption_enabled", "ali_oss_encryption_enabled"],
                    "kubernetes": ["k8s_secrets_encrypted_etcd"],
                    "snowflake": ["snowflake_stages_encrypted"],
                },
            },
            {
                "id": "CEK-04",
                "domain": "Cryptography, Encryption & Key Management",
                "title": "Encryption in Transit",
                "description": "Implement encryption for data in transit using TLS 1.2 or higher.",
                "checks": {
                    "aws": ["s3_bucket_ssl_required", "cloudfront_https_only", "es_node_to_node_encryption", "elasticache_encryption_transit"],
                    "gcp": ["gcp_sql_ssl_required"],
                    "alibaba": ["ali_rds_ssl_enabled", "ali_oss_https_only", "ali_slb_https_listener"],
                    "m365": ["m365_spf_configured", "m365_dkim_configured", "m365_dmarc_configured"],
                    "servicenow": ["servicenow_tls_enforced"],
                    "salesforce": ["salesforce_tls_enforced"],
                },
            },
            {
                "id": "CEK-05",
                "domain": "Cryptography, Encryption & Key Management",
                "title": "Key Rotation",
                "description": "Rotate encryption keys per defined cryptoperiods.",
                "checks": {
                    "aws": ["kms_key_rotation_enabled", "iam_access_key_rotation"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_iam_sa_key_rotation"],
                    "alibaba": ["ali_kms_key_rotation", "ali_ram_access_key_rotation"],
                    "snowflake": ["snowflake_user_password_rotation"],
                },
            },
            {
                "id": "DSP-01",
                "domain": "Data Security & Privacy Lifecycle Management",
                "title": "Data Security Policy",
                "description": "Establish data classification, handling, and protection policies.",
                "checks": {
                    "aws": ["macie_enabled", "s3_bucket_public_access_blocked"],
                    "gcp": ["gcp_storage_no_public_access", "gcp_bigquery_dataset_no_public"],
                    "alibaba": ["ali_oss_no_public_access"],
                    "m365": ["m365_dlp_policies_configured", "m365_sensitivity_labels_enabled"],
                    "snowflake": ["snowflake_column_masking_policies", "snowflake_row_access_policies"],
                    "servicenow": ["servicenow_data_classification"],
                },
            },
            {
                "id": "DSP-04",
                "domain": "Data Security & Privacy Lifecycle Management",
                "title": "Data Access Control",
                "description": "Implement data access controls aligned with classification levels.",
                "checks": {
                    "aws": ["s3_bucket_public_access_blocked", "rds_public_access_disabled", "redshift_cluster_no_public"],
                    "gcp": ["gcp_storage_no_public_access", "gcp_sql_no_public_ip", "gcp_bigquery_dataset_no_public"],
                    "alibaba": ["ali_oss_no_public_access", "ali_rds_no_public_access"],
                    "salesforce": ["salesforce_field_level_security", "salesforce_sharing_rules_reviewed"],
                },
            },
            {
                "id": "GRC-01",
                "domain": "Governance, Risk & Compliance",
                "title": "Governance Program",
                "description": "Establish an information security governance program including policies and procedures.",
                "checks": {
                    "aws": ["config_recorder_enabled", "guardduty_enabled"],
                    "gcp": ["gcp_logging_audit_logs_enabled"],
                    "servicenow": ["servicenow_incident_management", "servicenow_change_management"],
                },
            },
            {
                "id": "HRS-04",
                "domain": "Human Resources",
                "title": "Security Awareness Training",
                "description": "Provide security awareness training to all personnel.",
                "checks": {},
            },
            {
                "id": "IAM-01",
                "domain": "Identity & Access Management",
                "title": "Identity and Access Management Policy",
                "description": "Establish identity and access management policies including least privilege and MFA.",
                "checks": {
                    "aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled", "iam_password_policy_strong"],
                    "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_no_public_access"],
                    "alibaba": ["ali_ram_mfa_enabled", "ali_ram_password_policy"],
                    "m365": ["m365_admin_mfa_enforced", "m365_ca_require_mfa", "m365_security_defaults_enabled"],
                    "salesforce": ["salesforce_user_mfa_enabled", "salesforce_sso_configured"],
                    "snowflake": ["snowflake_user_mfa_enabled", "snowflake_account_sso_configured"],
                    "servicenow": ["servicenow_users_mfa_enabled"],
                },
            },
            {
                "id": "IAM-02",
                "domain": "Identity & Access Management",
                "title": "Strong Authentication",
                "description": "Implement multi-factor authentication for all interactive access.",
                "checks": {
                    "aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled"],
                    "alibaba": ["ali_ram_mfa_enabled"],
                    "m365": ["m365_admin_mfa_enforced", "m365_user_mfa_registered", "m365_user_phishing_resistant_mfa"],
                    "salesforce": ["salesforce_user_mfa_enabled"],
                    "snowflake": ["snowflake_user_mfa_enabled"],
                    "servicenow": ["servicenow_users_mfa_enabled"],
                },
            },
            {
                "id": "IAM-04",
                "domain": "Identity & Access Management",
                "title": "Policies and Procedures",
                "description": "Implement least privilege access control with regular reviews.",
                "checks": {
                    "aws": ["iam_no_star_policies", "iam_user_no_inline_policies", "iam_group_no_inline_policies"],
                    "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_separation_of_duties"],
                    "kubernetes": ["k8s_rbac_no_wildcard_cluster_admin", "k8s_rbac_no_wildcard_verbs", "k8s_rbac_limit_secrets_access"],
                    "servicenow": ["servicenow_role_separation"],
                },
            },
            {
                "id": "IAM-07",
                "domain": "Identity & Access Management",
                "title": "User Access Review",
                "description": "Review user access rights regularly and remove unused credentials.",
                "checks": {
                    "aws": ["iam_user_unused_credentials_45days"],
                    "alibaba": ["ali_ram_unused_users"],
                    "snowflake": ["snowflake_user_not_inactive"],
                    "salesforce": ["salesforce_user_not_stale"],
                },
            },
            {
                "id": "IVS-01",
                "domain": "Infrastructure & Virtualization Security",
                "title": "Infrastructure Security Policy",
                "description": "Define infrastructure security controls including network segmentation and hardening.",
                "checks": {
                    "aws": ["vpc_flow_logs_enabled", "ec2_default_sg_no_traffic", "vpc_default_sg_restricts_all", "ec2_imdsv2_required"],
                    "gcp": ["gcp_compute_shielded_vm", "gcp_compute_os_login", "gcp_logging_vpc_flow_logs"],
                    "alibaba": ["ali_vpc_flow_logs", "ali_ecs_vpc_network"],
                    "kubernetes": ["k8s_namespace_network_policy", "k8s_network_deny_all_default"],
                },
            },
            {
                "id": "IVS-03",
                "domain": "Infrastructure & Virtualization Security",
                "title": "Network Security",
                "description": "Segment networks and restrict traffic to only required communication paths.",
                "checks": {
                    "aws": ["ec2_sg_no_wide_open_ports", "ec2_default_sg_no_traffic", "vpc_no_unrestricted_nacl", "ec2_instance_no_public_ip"],
                    "gcp": ["gcp_firewall_no_default_allow", "gcp_gke_network_policy", "gcp_gke_private_cluster"],
                    "alibaba": ["ali_ecs_no_public_ip", "ali_ecs_sg_no_public_ingress"],
                    "kubernetes": ["k8s_namespace_network_policy", "k8s_service_no_loadbalancer_public", "k8s_service_no_nodeport"],
                },
            },
            {
                "id": "IVS-09",
                "domain": "Infrastructure & Virtualization Security",
                "title": "Firewall and Network Protection",
                "description": "Implement firewall rules and WAF protection for internet-facing applications.",
                "checks": {
                    "aws": ["waf_web_acl_exists", "cloudfront_waf_enabled", "apigateway_waf_enabled"],
                    "alibaba": ["ali_waf_enabled", "ali_waf_domains_configured"],
                },
            },
            {
                "id": "LOG-01",
                "domain": "Logging & Monitoring",
                "title": "Logging and Monitoring Policy",
                "description": "Establish logging and monitoring policies. Collect and retain audit logs.",
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_enabled", "cloudtrail_log_validation", "cloudwatch_log_group_retention"],
                    "gcp": ["gcp_logging_sinks_configured", "gcp_logging_audit_logs_enabled", "gcp_logging_bucket_retention"],
                    "alibaba": ["ali_actiontrail_enabled", "ali_actiontrail_multi_region", "ali_actiontrail_logging_active"],
                    "snowflake": ["snowflake_audit_logging_enabled", "snowflake_query_history_retention"],
                    "servicenow": ["servicenow_admin_audit_logging"],
                    "salesforce": ["salesforce_setup_audit_trail", "salesforce_event_monitoring"],
                },
            },
            {
                "id": "LOG-03",
                "domain": "Logging & Monitoring",
                "title": "Security Monitoring and Alerting",
                "description": "Implement security monitoring with automated alerting for anomalous activities.",
                "checks": {
                    "aws": ["guardduty_enabled", "cloudtrail_integrated_cloudwatch", "config_recorder_enabled"],
                    "gcp": ["gcp_logging_metric_filters"],
                    "alibaba": ["ali_security_center_enabled"],
                    "m365": ["m365_defender_sensor_active"],
                },
            },
            {
                "id": "SEF-02",
                "domain": "Security Incident Management",
                "title": "Incident Management",
                "description": "Establish incident management procedures with defined response and escalation processes.",
                "checks": {
                    "aws": ["guardduty_enabled", "iam_support_role_created"],
                    "servicenow": ["servicenow_incident_management"],
                },
            },
            {
                "id": "TVM-01",
                "domain": "Threat & Vulnerability Management",
                "title": "Threat and Vulnerability Management Policy",
                "description": "Establish processes for vulnerability identification, assessment, and remediation.",
                "checks": {
                    "aws": ["ecr_image_scanning", "guardduty_enabled", "rds_auto_minor_upgrade"],
                    "gcp": ["gcp_gke_binary_auth"],
                    "m365": ["m365_defender_low_risk", "m365_no_high_risk_users"],
                },
            },
            {
                "id": "TVM-04",
                "domain": "Threat & Vulnerability Management",
                "title": "Detection Updates",
                "description": "Keep threat detection signatures and rules up to date.",
                "checks": {
                    "aws": ["guardduty_enabled", "lambda_runtime_supported"],
                    "m365": ["m365_safe_attachments_enabled", "m365_safe_links_enabled", "m365_anti_phishing_policy"],
                },
            },
            {
                "id": "UEM-01",
                "domain": "Universal Endpoint Management",
                "title": "Endpoint Device Policy",
                "description": "Establish endpoint security policies including device compliance requirements.",
                "checks": {
                    "m365": ["m365_ca_require_compliant_device"],
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
