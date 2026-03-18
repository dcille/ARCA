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
