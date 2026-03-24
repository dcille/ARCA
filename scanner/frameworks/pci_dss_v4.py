"""PCI DSS v4.0 -- Payment Card Industry Data Security Standard.

Compliance framework mapping PCI DSS v4.0 requirements to cloud security
checks across AWS, Azure, GCP, OCI, and Alibaba Cloud.
"""

FRAMEWORK = {
    "PCI-DSS-v4.0": {
        "name": "Payment Card Industry Data Security Standard v4.0",
        "description": (
            "Global security standard for all entities that store, process, "
            "or transmit cardholder data. PCI DSS v4.0 provides a baseline "
            "of technical and operational requirements to protect payment "
            "account data."
        ),
        "category": "industry",
        "controls": [
            # ── Requirement 1: Network Security Controls ────────────────────
            {
                "id": "1.2.1",
                "title": "Network security controls are configured and maintained",
                "description": (
                    "Configuration standards for NSCs are defined, implemented, "
                    "and maintained."
                ),
                "checks": {
                    "aws": ["vpc_default_security_group_closed", "vpc_security_groups_restrictive"],
                    "azure": ["azure_nsg_no_unrestricted_access", "azure_nsg_default_deny"],
                    "gcp": ["gcp_compute_firewall_no_open_ports", "gcp_vpc_default_firewall_rules"],
                },
            },
            {
                "id": "1.2.5",
                "title": "All services, protocols, and ports allowed are identified and approved",
                "description": (
                    "All services, protocols, and ports that are allowed are "
                    "identified, approved, and have a defined business need."
                ),
                "checks": {
                    "aws": ["ec2_no_unrestricted_ssh", "ec2_no_unrestricted_rdp", "vpc_flow_logs_enabled"],
                    "azure": ["azure_nsg_unrestricted_port_22", "azure_nsg_unrestricted_port_3389"],
                    "gcp": ["gcp_compute_firewall_no_ssh_open", "gcp_compute_firewall_no_rdp_open"],
                },
            },
            {
                "id": "1.3.1",
                "title": "Inbound traffic to the CDE is restricted",
                "description": (
                    "Inbound traffic to the cardholder data environment (CDE) "
                    "is restricted to only necessary traffic."
                ),
                "checks": {
                    "aws": ["vpc_security_groups_restrictive", "ec2_no_public_ip"],
                    "azure": ["azure_nsg_no_unrestricted_access", "azure_vm_no_public_ip"],
                    "gcp": ["gcp_compute_firewall_no_open_ports", "gcp_compute_no_public_ip"],
                },
            },
            {
                "id": "1.3.2",
                "title": "Outbound traffic from the CDE is restricted",
                "description": (
                    "Outbound traffic from the CDE is restricted to only "
                    "necessary traffic."
                ),
                "checks": {
                    "aws": ["vpc_security_groups_egress_restrictive", "vpc_nacl_restrictive"],
                    "azure": ["azure_nsg_egress_restricted", "azure_firewall_configured"],
                    "gcp": ["gcp_vpc_egress_rules", "gcp_compute_firewall_egress"],
                },
            },
            {
                "id": "1.4.1",
                "title": "NSCs between trusted and untrusted networks",
                "description": (
                    "NSCs are implemented between trusted and untrusted networks."
                ),
                "checks": {
                    "aws": ["vpc_public_private_subnets", "waf_web_acl_configured"],
                    "azure": ["azure_firewall_configured", "azure_waf_enabled"],
                    "gcp": ["gcp_cloud_armor_enabled", "gcp_vpc_private_google_access"],
                },
            },
            {
                "id": "1.5.1",
                "title": "Security controls on computing devices connecting to untrusted networks",
                "description": (
                    "Security controls are implemented on any computing devices "
                    "that connect to both untrusted and trusted networks."
                ),
                "checks": {
                    "aws": ["ec2_imdsv2_required", "ssm_managed_instances"],
                    "azure": ["azure_endpoint_protection_installed", "azure_vm_auto_updates"],
                    "gcp": ["gcp_compute_shielded_vm", "gcp_compute_os_login"],
                },
            },
            # ── Requirement 2: Secure Configurations ────────────────────────
            {
                "id": "2.2.1",
                "title": "Configuration standards are developed and maintained",
                "description": (
                    "Configuration standards cover all system components, "
                    "address known vulnerabilities, and are consistent with "
                    "hardening standards."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "config_rules_active"],
                    "azure": ["azure_policy_assignments_exist", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_org_policy_constraints", "gcp_scc_enabled"],
                },
            },
            {
                "id": "2.2.2",
                "title": "Vendor default accounts managed",
                "description": (
                    "Vendor default accounts are managed: changed, removed, "
                    "or disabled before installing a system on the network."
                ),
                "checks": {
                    "aws": ["iam_no_root_access_key", "iam_root_mfa_enabled"],
                    "azure": ["azure_ad_default_admin_secured", "azure_ad_mfa_enabled"],
                    "gcp": ["gcp_iam_no_default_sa_with_keys", "gcp_compute_no_default_sa"],
                },
            },
            {
                "id": "2.2.5",
                "title": "Only necessary services and protocols enabled",
                "description": (
                    "All unnecessary functionality is removed or disabled."
                ),
                "checks": {
                    "aws": ["ec2_no_unrestricted_ssh", "rds_no_public_access"],
                    "azure": ["azure_nsg_no_unrestricted_access", "azure_sql_public_access_disabled"],
                    "gcp": ["gcp_compute_firewall_no_open_ports", "gcp_sql_no_public_ip"],
                },
            },
            {
                "id": "2.2.7",
                "title": "All non-console administrative access is encrypted",
                "description": (
                    "All non-console administrative access is encrypted using "
                    "strong cryptography."
                ),
                "checks": {
                    "aws": ["elb_tls_listener", "s3_ssl_requests_only"],
                    "azure": ["azure_storage_https_only", "azure_appservice_https_only"],
                    "gcp": ["gcp_sql_ssl_enforced", "gcp_lb_ssl_policy"],
                },
            },
            # ── Requirement 3: Protect Stored Account Data ──────────────────
            {
                "id": "3.1.1",
                "title": "All processes for storing account data are defined",
                "description": (
                    "All processes for storing account data are defined and "
                    "documented."
                ),
                "checks": {
                    "aws": ["macie_enabled", "config_recorder_enabled"],
                    "azure": ["azure_purview_enabled", "azure_policy_assignments_exist"],
                    "gcp": ["gcp_dlp_enabled", "gcp_asset_inventory_enabled"],
                },
            },
            {
                "id": "3.4.1",
                "title": "PAN is masked when displayed",
                "description": (
                    "PAN is masked when displayed so only authorized personnel "
                    "can see more than the BIN and last four digits."
                ),
                "checks": {
                    "aws": ["macie_enabled", "cloudtrail_log_validation"],
                    "azure": ["azure_purview_enabled", "azure_sql_data_masking"],
                    "gcp": ["gcp_dlp_enabled", "gcp_bigquery_column_security"],
                },
            },
            {
                "id": "3.5.1",
                "title": "PAN is secured with strong cryptography if stored",
                "description": (
                    "PAN is rendered unreadable anywhere it is stored using "
                    "strong cryptography."
                ),
                "checks": {
                    "aws": ["s3_default_encryption", "rds_encryption_at_rest", "ebs_encryption_enabled"],
                    "azure": ["azure_storage_encryption_cmk", "azure_sql_tde_enabled", "azure_disk_encryption"],
                    "gcp": ["gcp_storage_cmek", "gcp_sql_encryption_cmek", "gcp_compute_disk_cmek"],
                },
            },
            {
                "id": "3.6.1",
                "title": "Cryptographic key management processes are defined",
                "description": (
                    "Procedures for protecting cryptographic keys are defined "
                    "and implemented."
                ),
                "checks": {
                    "aws": ["kms_key_rotation_enabled", "kms_cmk_policies_restrictive"],
                    "azure": ["azure_keyvault_key_rotation", "azure_keyvault_no_public_access"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_kms_key_not_publicly_accessible"],
                },
            },
            {
                "id": "3.7.1",
                "title": "Key-management policies and procedures are implemented",
                "description": (
                    "Key management policies for cryptographic keys used to "
                    "protect stored account data include generation, distribution, "
                    "storage, access, and retirement."
                ),
                "checks": {
                    "aws": ["kms_key_rotation_enabled", "kms_grants_restrictive"],
                    "azure": ["azure_keyvault_key_rotation", "azure_keyvault_rbac_enabled"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_kms_separation_of_duties"],
                },
            },
            # ── Requirement 4: Encrypt Transmissions ────────────────────────
            {
                "id": "4.2.1",
                "title": "Strong cryptography for PAN transmission over open networks",
                "description": (
                    "Strong cryptography is used during transmission of PAN "
                    "over open, public networks."
                ),
                "checks": {
                    "aws": ["elb_tls_listener", "cloudfront_tls_minimum_version", "s3_ssl_requests_only"],
                    "azure": ["azure_appservice_tls_minimum", "azure_storage_https_only"],
                    "gcp": ["gcp_lb_ssl_policy", "gcp_sql_ssl_enforced"],
                },
            },
            {
                "id": "4.2.1.1",
                "title": "Trusted keys and certificates are maintained",
                "description": (
                    "An inventory of trusted keys and certificates is maintained."
                ),
                "checks": {
                    "aws": ["acm_certificate_expiry", "acm_certificate_transparency"],
                    "azure": ["azure_keyvault_certificate_expiry", "azure_appservice_certificate_managed"],
                    "gcp": ["gcp_ssl_certificate_expiry", "gcp_certificate_manager_configured"],
                },
            },
            # ── Requirement 5: Protect Against Malware ──────────────────────
            {
                "id": "5.2.1",
                "title": "Anti-malware solution deployed on all applicable systems",
                "description": (
                    "An anti-malware solution is deployed on all system "
                    "components, except those identified as not at risk."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "guardduty_malware_protection"],
                    "azure": ["azure_endpoint_protection_installed", "azure_vm_antimalware_extension"],
                    "gcp": ["gcp_scc_enabled", "gcp_compute_shielded_vm"],
                },
            },
            {
                "id": "5.2.3",
                "title": "System components not at risk are evaluated periodically",
                "description": (
                    "Any system components not at risk for malware are evaluated "
                    "periodically to confirm continued low risk."
                ),
                "checks": {
                    "aws": ["inspector_enabled", "ssm_patch_compliance"],
                    "azure": ["azure_defender_vulnerability_assessment", "azure_vm_vulnerability_assessment"],
                    "gcp": ["gcp_scc_enabled", "gcp_web_security_scanner"],
                },
            },
            {
                "id": "5.3.1",
                "title": "Anti-malware is kept current",
                "description": (
                    "The anti-malware solution is kept current via automatic updates."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "ssm_patch_compliance"],
                    "azure": ["azure_vm_antimalware_extension", "azure_vm_auto_updates"],
                    "gcp": ["gcp_compute_shielded_vm", "gcp_os_patch_management"],
                },
            },
            # ── Requirement 6: Secure Systems and Software ──────────────────
            {
                "id": "6.2.1",
                "title": "Bespoke and custom software developed securely",
                "description": (
                    "Bespoke and custom software are developed securely."
                ),
                "checks": {
                    "aws": ["codebuild_build_project_envvar_no_credentials"],
                    "azure": ["azure_devops_security_enabled", "azure_devops_secret_scanning"],
                    "gcp": ["gcp_cloud_build_no_secrets", "gcp_artifact_registry_vuln_scan"],
                },
            },
            {
                "id": "6.3.1",
                "title": "Security vulnerabilities are identified and managed",
                "description": (
                    "Security vulnerabilities are identified and managed with "
                    "a formal vulnerability management process."
                ),
                "checks": {
                    "aws": ["inspector_enabled", "ecr_image_scan_on_push"],
                    "azure": ["azure_defender_vulnerability_assessment", "azure_acr_vulnerability_scan"],
                    "gcp": ["gcp_scc_enabled", "gcp_artifact_registry_vuln_scan"],
                },
            },
            {
                "id": "6.3.3",
                "title": "Security patches installed within defined timeframe",
                "description": (
                    "All security patches and updates are installed within "
                    "the applicable timeframe after release."
                ),
                "checks": {
                    "aws": ["ssm_patch_compliance", "rds_auto_minor_version_upgrade"],
                    "azure": ["azure_vm_auto_updates", "azure_sql_auto_patching"],
                    "gcp": ["gcp_os_patch_management", "gcp_sql_maintenance_window"],
                },
            },
            {
                "id": "6.4.1",
                "title": "Public-facing web applications are protected",
                "description": (
                    "Public-facing web applications are protected against attacks."
                ),
                "checks": {
                    "aws": ["waf_web_acl_configured", "cloudfront_waf_enabled"],
                    "azure": ["azure_waf_enabled", "azure_frontdoor_waf_enabled"],
                    "gcp": ["gcp_cloud_armor_enabled", "gcp_cloud_armor_rules_configured"],
                },
            },
            # ── Requirement 7: Restrict Access ──────────────────────────────
            {
                "id": "7.2.1",
                "title": "Access control model defined for system components",
                "description": (
                    "An access control model is defined and includes granting "
                    "access based on job classification and function."
                ),
                "checks": {
                    "aws": ["iam_no_star_policies", "iam_policies_attached_to_groups"],
                    "azure": ["azure_rbac_least_privilege", "azure_ad_pim_enabled"],
                    "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_separation_of_duties"],
                },
            },
            {
                "id": "7.2.2",
                "title": "Access assigned based on job classification and function",
                "description": (
                    "Access is assigned based on an individual's job classification "
                    "and function following the principle of least privilege."
                ),
                "checks": {
                    "aws": ["iam_no_star_policies", "iam_user_no_attached_policies"],
                    "azure": ["azure_rbac_least_privilege", "azure_iam_no_custom_owner_roles"],
                    "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_no_public_access"],
                },
            },
            {
                "id": "7.2.5",
                "title": "All application and system accounts assigned and managed",
                "description": (
                    "All application and system accounts and related access "
                    "privileges are managed and assigned using least privilege."
                ),
                "checks": {
                    "aws": ["iam_user_unused_credentials", "iam_access_key_rotation"],
                    "azure": ["azure_ad_stale_accounts", "azure_ad_access_reviews"],
                    "gcp": ["gcp_iam_unused_sa_keys", "gcp_iam_user_sa_key_rotation"],
                },
            },
            # ── Requirement 8: Identify Users ───────────────────────────────
            {
                "id": "8.2.1",
                "title": "All users are assigned a unique ID",
                "description": (
                    "All users are assigned a unique ID before access to "
                    "system components or cardholder data is allowed."
                ),
                "checks": {
                    "aws": ["iam_no_root_access_key", "iam_users_in_groups"],
                    "azure": ["azure_ad_individual_accounts", "azure_ad_no_guest_admin"],
                    "gcp": ["gcp_iam_no_sa_admin_privilege", "gcp_iam_workload_identity"],
                },
            },
            {
                "id": "8.3.1",
                "title": "All user access authenticated using at least one factor",
                "description": (
                    "All user access to system components for users and "
                    "administrators is authenticated via at least one factor."
                ),
                "checks": {
                    "aws": ["iam_password_policy_strong", "iam_mfa_enabled_for_console"],
                    "azure": ["azure_ad_password_policy", "azure_ad_mfa_enabled"],
                    "gcp": ["gcp_iam_2fa_enforced", "gcp_compute_os_login"],
                },
            },
            {
                "id": "8.3.6",
                "title": "Password complexity requirements enforced",
                "description": (
                    "If passwords/passphrases are used, they meet minimum "
                    "complexity: 12 characters containing both numeric and "
                    "alphabetic characters."
                ),
                "checks": {
                    "aws": ["iam_password_policy_strong", "iam_password_min_length_14"],
                    "azure": ["azure_ad_password_policy", "azure_ad_password_protection"],
                    "gcp": ["gcp_org_password_policy", "gcp_iam_2fa_enforced"],
                },
            },
            {
                "id": "8.4.2",
                "title": "MFA for all access into the CDE",
                "description": (
                    "MFA is implemented for all access into the cardholder "
                    "data environment."
                ),
                "checks": {
                    "aws": ["iam_mfa_enabled_for_console", "iam_root_mfa_enabled"],
                    "azure": ["azure_ad_mfa_enabled", "azure_ad_conditional_access"],
                    "gcp": ["gcp_iam_2fa_enforced", "gcp_org_policy_constraints"],
                },
            },
            {
                "id": "8.6.1",
                "title": "Interactive login for system/application accounts managed",
                "description": (
                    "If accounts used by systems or applications can be used "
                    "for interactive login, they are managed with proper controls."
                ),
                "checks": {
                    "aws": ["iam_user_unused_credentials", "iam_access_key_rotation"],
                    "azure": ["azure_ad_stale_accounts", "azure_ad_service_principal_secrets"],
                    "gcp": ["gcp_iam_unused_sa_keys", "gcp_iam_no_default_sa_with_keys"],
                },
            },
            # ── Requirement 9: Restrict Physical Access ─────────────────────
            {
                "id": "9.4.1",
                "title": "Media with cardholder data is physically secured",
                "description": (
                    "All media with cardholder data is physically secured."
                ),
                "checks": {
                    "aws": ["ebs_encryption_enabled", "s3_default_encryption"],
                    "azure": ["azure_disk_encryption", "azure_storage_encryption_cmk"],
                    "gcp": ["gcp_compute_disk_cmek", "gcp_storage_cmek"],
                },
            },
            {
                "id": "9.4.6",
                "title": "Hard-copy materials with cardholder data destroyed",
                "description": (
                    "Hard-copy materials with cardholder data are destroyed "
                    "when no longer needed for business or legal reasons."
                ),
                "checks": {
                    "aws": ["s3_lifecycle_policy", "ebs_snapshot_lifecycle"],
                    "azure": ["azure_storage_lifecycle_management", "azure_snapshot_lifecycle"],
                    "gcp": ["gcp_storage_lifecycle_policy", "gcp_compute_snapshot_policy"],
                },
            },
            # ── Requirement 10: Log and Monitor ─────────────────────────────
            {
                "id": "10.2.1",
                "title": "Audit logs capture all individual user access to CHD",
                "description": (
                    "Audit logs are enabled and active for all system components "
                    "that store, process, or transmit CHD."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation", "rds_audit_logging"],
                    "azure": ["azure_monitor_log_profile", "azure_sql_auditing_enabled"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_sql_audit_logging"],
                },
            },
            {
                "id": "10.2.1.2",
                "title": "Audit logs capture all administrative actions",
                "description": (
                    "Audit logs capture all actions taken by any individual "
                    "with administrative access."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_iam_changes_alarm"],
                    "azure": ["azure_monitor_activity_log", "azure_monitor_iam_changes"],
                    "gcp": ["gcp_logging_admin_activity", "gcp_logging_iam_changes"],
                },
            },
            {
                "id": "10.2.2",
                "title": "Audit logs record required details for each event",
                "description": (
                    "Audit logs record user identification, type of event, "
                    "date/time, success/failure, origination, and identity of "
                    "affected data/resource."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "vpc_flow_logs_enabled"],
                    "azure": ["azure_monitor_diagnostic_settings", "azure_nsg_flow_logs_enabled"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_vpc_flow_logs_enabled"],
                },
            },
            {
                "id": "10.3.1",
                "title": "Audit log access is restricted",
                "description": (
                    "Read access to audit logs is limited to those with a "
                    "job-related need."
                ),
                "checks": {
                    "aws": ["cloudtrail_s3_bucket_not_public", "cloudtrail_log_validation"],
                    "azure": ["azure_storage_no_public_access", "azure_log_analytics_rbac"],
                    "gcp": ["gcp_logging_log_bucket_locked", "gcp_storage_no_public_access"],
                },
            },
            {
                "id": "10.3.3",
                "title": "Audit logs are protected from modification",
                "description": (
                    "Audit logs are protected from modification and destruction "
                    "through access controls, physical/logical segregation, and "
                    "integrity monitoring."
                ),
                "checks": {
                    "aws": ["cloudtrail_log_validation", "s3_object_lock_enabled", "cloudtrail_s3_bucket_not_public"],
                    "azure": ["azure_storage_immutability_policy", "azure_storage_no_public_access"],
                    "gcp": ["gcp_logging_log_bucket_locked", "gcp_storage_retention_policy"],
                },
            },
            {
                "id": "10.5.1",
                "title": "Audit log history retained for at least 12 months",
                "description": (
                    "Retain audit log history for at least 12 months, with at "
                    "least the most recent three months immediately available."
                ),
                "checks": {
                    "aws": ["cloudtrail_s3_retention", "cloudwatch_log_retention"],
                    "azure": ["azure_log_analytics_retention", "azure_storage_lifecycle_management"],
                    "gcp": ["gcp_logging_log_bucket_retention", "gcp_storage_lifecycle_policy"],
                },
            },
            {
                "id": "10.7.1",
                "title": "Failures of critical security controls detected and addressed",
                "description": (
                    "Failures of critical security control systems are detected, "
                    "alerted, and addressed promptly."
                ),
                "checks": {
                    "aws": ["cloudwatch_alarm_actions", "sns_topics_configured", "guardduty_enabled"],
                    "azure": ["azure_action_groups_configured", "azure_alert_notifications_enabled"],
                    "gcp": ["gcp_logging_alert_policies", "gcp_scc_notifications_configured"],
                },
            },
            # ── Requirement 11: Test Security ───────────────────────────────
            {
                "id": "11.3.1",
                "title": "Internal vulnerability scans performed quarterly",
                "description": (
                    "Internal vulnerability scans are performed at least once "
                    "every three months."
                ),
                "checks": {
                    "aws": ["inspector_enabled", "ecr_image_scan_on_push"],
                    "azure": ["azure_defender_vulnerability_assessment", "azure_acr_vulnerability_scan"],
                    "gcp": ["gcp_scc_enabled", "gcp_web_security_scanner"],
                },
            },
            {
                "id": "11.4.1",
                "title": "External and internal penetration testing performed",
                "description": (
                    "External and internal penetration testing is regularly "
                    "performed and exploitable vulnerabilities are corrected."
                ),
                "checks": {
                    "aws": ["inspector_enabled", "securityhub_enabled"],
                    "azure": ["azure_defender_enabled", "azure_defender_vulnerability_assessment"],
                    "gcp": ["gcp_scc_enabled", "gcp_web_security_scanner"],
                },
            },
            {
                "id": "11.5.1",
                "title": "Intrusion-detection/prevention techniques detect intrusions",
                "description": (
                    "Intrusion-detection and/or intrusion-prevention techniques "
                    "are used to detect and/or prevent intrusions into the network."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "waf_web_acl_configured"],
                    "azure": ["azure_defender_enabled", "azure_waf_enabled"],
                    "gcp": ["gcp_scc_enabled", "gcp_cloud_armor_enabled"],
                },
            },
            {
                "id": "11.5.2",
                "title": "Change-detection mechanism deployed",
                "description": (
                    "A change-detection mechanism is deployed on critical systems "
                    "to alert on unauthorized modification of files."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "cloudtrail_log_validation"],
                    "azure": ["azure_monitor_diagnostic_settings", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_scc_enabled", "gcp_asset_inventory_enabled"],
                },
            },
            # ── Requirement 12: Information Security Policy ─────────────────
            {
                "id": "12.1.1",
                "title": "Overall information security policy established",
                "description": (
                    "An overall information security policy is established, "
                    "published, maintained, and disseminated."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "organizations_scp_enabled"],
                    "azure": ["azure_policy_assignments_exist", "azure_policy_security_initiative"],
                    "gcp": ["gcp_org_policy_constraints", "gcp_resource_hierarchy"],
                },
            },
            {
                "id": "12.3.1",
                "title": "Cryptographic cipher suites and protocols documented",
                "description": (
                    "Each PCI DSS requirement affected by cryptographic "
                    "architecture is addressed with documentation."
                ),
                "checks": {
                    "aws": ["kms_key_rotation_enabled", "elb_tls_listener"],
                    "azure": ["azure_keyvault_key_rotation", "azure_appservice_tls_minimum"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_lb_ssl_policy"],
                },
            },
            {
                "id": "12.5.2",
                "title": "PCI DSS scope documented and confirmed annually",
                "description": (
                    "PCI DSS scope is documented and confirmed at least once "
                    "every 12 months and upon significant change."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "cloudtrail_multiregion"],
                    "azure": ["azure_monitor_diagnostic_settings", "azure_policy_assignments_exist"],
                    "gcp": ["gcp_asset_inventory_enabled", "gcp_scc_enabled"],
                },
            },
            {
                "id": "12.10.1",
                "title": "Incident response plan exists and is ready",
                "description": (
                    "An incident response plan exists and is ready to be "
                    "activated in the event of a suspected or confirmed "
                    "security incident."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "securityhub_enabled", "sns_topics_configured"],
                    "azure": ["azure_sentinel_automation_rules", "azure_action_groups_configured"],
                    "gcp": ["gcp_scc_notifications_configured", "gcp_logging_alert_policies"],
                },
            },
        ],
    },
}
