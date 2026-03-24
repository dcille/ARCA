"""HIPAA -- Health Insurance Portability and Accountability Act of 1996.

Compliance framework mapping HIPAA Security Rule safeguards (45 CFR Part 160
and Subparts A and C of Part 164) to cloud security checks across AWS, Azure,
GCP, OCI, and Alibaba Cloud.
"""

FRAMEWORK = {
    "HIPAA": {
        "name": "Health Insurance Portability and Accountability Act (HIPAA) Security Rule",
        "description": (
            "United States federal law that establishes national standards to "
            "protect individuals' electronic personal health information (ePHI) "
            "created, received, used, or maintained by covered entities and "
            "business associates."
        ),
        "category": "regulatory",
        "controls": [
            # ── Administrative Safeguards (§164.308) ────────────────────────
            {
                "id": "164.308(a)(1)(i)",
                "title": "Security Management Process",
                "description": (
                    "Implement policies and procedures to prevent, detect, "
                    "contain, and correct security violations."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "securityhub_enabled", "config_recorder_enabled"],
                    "azure": ["azure_defender_enabled", "azure_policy_assignments_exist"],
                    "gcp": ["gcp_scc_enabled", "gcp_logging_audit_logs_enabled"],
                },
            },
            {
                "id": "164.308(a)(1)(ii)(A)",
                "title": "Risk Analysis",
                "description": (
                    "Conduct an accurate and thorough assessment of potential "
                    "risks and vulnerabilities to ePHI."
                ),
                "checks": {
                    "aws": ["inspector_enabled", "securityhub_enabled"],
                    "azure": ["azure_defender_vulnerability_assessment", "azure_security_contact_configured"],
                    "gcp": ["gcp_scc_enabled", "gcp_web_security_scanner"],
                },
            },
            {
                "id": "164.308(a)(1)(ii)(B)",
                "title": "Risk Management",
                "description": (
                    "Implement security measures sufficient to reduce risks and "
                    "vulnerabilities to a reasonable and appropriate level."
                ),
                "checks": {
                    "aws": ["config_rules_active", "ssm_patch_compliance"],
                    "azure": ["azure_policy_compliance_rate", "azure_update_management"],
                    "gcp": ["gcp_os_patch_management", "gcp_scc_findings_resolved"],
                },
            },
            {
                "id": "164.308(a)(1)(ii)(D)",
                "title": "Information System Activity Review",
                "description": (
                    "Implement procedures to regularly review records of "
                    "information system activity, such as audit logs."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudwatch_alarm_actions", "cloudtrail_log_validation"],
                    "azure": ["azure_monitor_log_profile", "azure_monitor_diagnostic_settings"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_logging_sinks_configured", "gcp_logging_metric_filters"],
                },
            },
            {
                "id": "164.308(a)(3)(i)",
                "title": "Workforce Security",
                "description": (
                    "Implement policies and procedures to ensure that all members "
                    "of the workforce have appropriate access to ePHI."
                ),
                "checks": {
                    "aws": ["iam_no_star_policies", "iam_user_no_attached_policies", "iam_users_in_groups"],
                    "azure": ["azure_iam_no_custom_owner_roles", "azure_rbac_least_privilege"],
                    "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_separation_of_duties"],
                },
            },
            {
                "id": "164.308(a)(3)(ii)(A)",
                "title": "Authorization and/or Supervision",
                "description": (
                    "Implement procedures for the authorization and/or supervision "
                    "of workforce members who work with ePHI."
                ),
                "checks": {
                    "aws": ["iam_policies_attached_to_groups", "iam_no_root_access_key"],
                    "azure": ["azure_ad_pim_enabled", "azure_iam_no_custom_owner_roles"],
                    "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_no_sa_admin_privilege"],
                },
            },
            {
                "id": "164.308(a)(3)(ii)(B)",
                "title": "Workforce Clearance Procedure",
                "description": (
                    "Implement procedures to determine that access to ePHI is "
                    "appropriate based on role."
                ),
                "checks": {
                    "aws": ["iam_access_analyzer_enabled", "iam_credential_report_audit"],
                    "azure": ["azure_ad_access_reviews", "azure_rbac_least_privilege"],
                    "gcp": ["gcp_iam_recommender_enabled", "gcp_iam_no_public_access"],
                },
            },
            {
                "id": "164.308(a)(3)(ii)(C)",
                "title": "Termination Procedures",
                "description": (
                    "Implement procedures for terminating access to ePHI when "
                    "an employee leaves the organization."
                ),
                "checks": {
                    "aws": ["iam_user_unused_credentials", "iam_access_key_rotation"],
                    "azure": ["azure_ad_stale_accounts", "azure_ad_guest_review"],
                    "gcp": ["gcp_iam_unused_sa_keys", "gcp_iam_user_sa_key_rotation"],
                },
            },
            {
                "id": "164.308(a)(4)(i)",
                "title": "Information Access Management",
                "description": (
                    "Implement policies and procedures for authorizing access to "
                    "ePHI consistent with the applicable requirements."
                ),
                "checks": {
                    "aws": ["s3_bucket_policy_restrictive", "iam_no_star_policies"],
                    "azure": ["azure_storage_no_public_access", "azure_rbac_least_privilege"],
                    "gcp": ["gcp_storage_no_public_access", "gcp_iam_no_public_access"],
                },
            },
            {
                "id": "164.308(a)(4)(ii)(B)",
                "title": "Access Authorization",
                "description": (
                    "Implement policies and procedures for granting access to ePHI, "
                    "for example, through workstation access or software programs."
                ),
                "checks": {
                    "aws": ["iam_policies_attached_to_groups", "iam_no_inline_policies"],
                    "azure": ["azure_ad_conditional_access", "azure_ad_pim_enabled"],
                    "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_workload_identity"],
                },
            },
            {
                "id": "164.308(a)(4)(ii)(C)",
                "title": "Access Establishment and Modification",
                "description": (
                    "Implement policies and procedures for changes to access "
                    "rights based on job function changes."
                ),
                "checks": {
                    "aws": ["iam_access_analyzer_enabled", "cloudtrail_iam_changes_alarm"],
                    "azure": ["azure_ad_access_reviews", "azure_monitor_iam_changes"],
                    "gcp": ["gcp_iam_recommender_enabled", "gcp_logging_iam_changes"],
                },
            },
            {
                "id": "164.308(a)(5)(i)",
                "title": "Security Awareness and Training",
                "description": (
                    "Implement a security awareness and training program for "
                    "all workforce members."
                ),
                "checks": {
                    "aws": ["securityhub_enabled"],
                    "azure": ["azure_defender_enabled"],
                    "gcp": ["gcp_scc_enabled"],
                },
            },
            {
                "id": "164.308(a)(5)(ii)(B)",
                "title": "Protection from Malicious Software",
                "description": (
                    "Procedures for guarding against, detecting, and reporting "
                    "malicious software."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "guardduty_malware_protection"],
                    "azure": ["azure_defender_enabled", "azure_endpoint_protection_installed"],
                    "gcp": ["gcp_scc_enabled", "gcp_compute_shielded_vm"],
                },
            },
            {
                "id": "164.308(a)(5)(ii)(C)",
                "title": "Log-in Monitoring",
                "description": (
                    "Procedures for monitoring log-in attempts and reporting "
                    "discrepancies."
                ),
                "checks": {
                    "aws": ["cloudtrail_console_signin_alarm", "guardduty_enabled"],
                    "azure": ["azure_ad_sign_in_risk_policy", "azure_monitor_log_profile"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_logging_admin_activity"],
                },
            },
            {
                "id": "164.308(a)(5)(ii)(D)",
                "title": "Password Management",
                "description": (
                    "Procedures for creating, changing, and safeguarding passwords."
                ),
                "checks": {
                    "aws": ["iam_password_policy_strong", "iam_mfa_enabled_for_console"],
                    "azure": ["azure_ad_password_policy", "azure_ad_mfa_enabled"],
                    "gcp": ["gcp_iam_2fa_enforced", "gcp_org_policy_constraints"],
                },
            },
            {
                "id": "164.308(a)(6)(i)",
                "title": "Security Incident Procedures",
                "description": (
                    "Implement policies and procedures to address security incidents."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "securityhub_enabled", "sns_topics_configured"],
                    "azure": ["azure_sentinel_automation_rules", "azure_action_groups_configured"],
                    "gcp": ["gcp_scc_notifications_configured", "gcp_logging_alert_policies"],
                },
            },
            {
                "id": "164.308(a)(6)(ii)",
                "title": "Response and Reporting",
                "description": (
                    "Identify and respond to suspected or known security incidents; "
                    "mitigate harmful effects; document incidents and outcomes."
                ),
                "checks": {
                    "aws": ["cloudwatch_alarm_actions", "sns_topics_configured"],
                    "azure": ["azure_alert_notifications_enabled", "azure_critical_operation_alerts"],
                    "gcp": ["gcp_logging_metric_filters", "gcp_scc_enabled"],
                },
            },
            {
                "id": "164.308(a)(7)(i)",
                "title": "Contingency Plan",
                "description": (
                    "Establish and implement policies and procedures for responding "
                    "to an emergency or other occurrence that damages systems with ePHI."
                ),
                "checks": {
                    "aws": ["backup_plan_exists", "rds_automated_backups", "s3_versioning_enabled"],
                    "azure": ["azure_backup_vault_exists", "azure_recovery_services_configured"],
                    "gcp": ["gcp_sql_automated_backups", "gcp_storage_versioning"],
                },
            },
            {
                "id": "164.308(a)(7)(ii)(A)",
                "title": "Data Backup Plan",
                "description": (
                    "Establish procedures to create and maintain retrievable "
                    "exact copies of ePHI."
                ),
                "checks": {
                    "aws": ["backup_plan_exists", "rds_automated_backups", "dynamodb_pitr_enabled"],
                    "azure": ["azure_backup_vault_exists", "azure_sql_long_term_retention"],
                    "gcp": ["gcp_sql_automated_backups", "gcp_storage_versioning", "gcp_gke_backup_enabled"],
                },
            },
            {
                "id": "164.308(a)(7)(ii)(B)",
                "title": "Disaster Recovery Plan",
                "description": (
                    "Establish procedures to restore any loss of ePHI data."
                ),
                "checks": {
                    "aws": ["backup_plan_exists", "rds_multi_az", "s3_cross_region_replication"],
                    "azure": ["azure_recovery_services_configured", "azure_sql_geo_replication"],
                    "gcp": ["gcp_sql_ha_configured", "gcp_storage_multi_region"],
                },
            },
            {
                "id": "164.308(a)(8)",
                "title": "Evaluation",
                "description": (
                    "Perform periodic technical and non-technical evaluation "
                    "of security measures."
                ),
                "checks": {
                    "aws": ["securityhub_enabled", "config_rules_active", "inspector_enabled"],
                    "azure": ["azure_defender_enabled", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_scc_enabled", "gcp_scc_findings_resolved"],
                },
            },
            # ── Technical Safeguards (§164.312) ─────────────────────────────
            {
                "id": "164.312(a)(1)",
                "title": "Access Control",
                "description": (
                    "Implement technical policies and procedures for systems "
                    "with ePHI to allow access only to authorized persons."
                ),
                "checks": {
                    "aws": ["iam_no_star_policies", "iam_no_root_access_key", "s3_bucket_public_access_blocked"],
                    "azure": ["azure_rbac_least_privilege", "azure_storage_no_public_access"],
                    "gcp": ["gcp_iam_no_public_access", "gcp_storage_no_public_access"],
                },
            },
            {
                "id": "164.312(a)(2)(i)",
                "title": "Unique User Identification",
                "description": (
                    "Assign a unique name and/or number for identifying and "
                    "tracking user identity."
                ),
                "checks": {
                    "aws": ["iam_no_root_access_key", "iam_users_in_groups", "iam_no_shared_credentials"],
                    "azure": ["azure_ad_individual_accounts", "azure_ad_no_guest_admin"],
                    "gcp": ["gcp_iam_no_sa_admin_privilege", "gcp_iam_workload_identity"],
                },
            },
            {
                "id": "164.312(a)(2)(ii)",
                "title": "Emergency Access Procedure",
                "description": (
                    "Establish procedures for obtaining necessary ePHI during "
                    "an emergency."
                ),
                "checks": {
                    "aws": ["iam_break_glass_account", "backup_plan_exists"],
                    "azure": ["azure_ad_emergency_access_accounts", "azure_recovery_services_configured"],
                    "gcp": ["gcp_org_emergency_access", "gcp_sql_automated_backups"],
                },
            },
            {
                "id": "164.312(a)(2)(iii)",
                "title": "Automatic Logoff",
                "description": (
                    "Implement electronic procedures that terminate sessions "
                    "after a predetermined period of inactivity."
                ),
                "checks": {
                    "aws": ["iam_session_policy", "sso_session_timeout"],
                    "azure": ["azure_ad_conditional_access", "azure_ad_session_lifetime"],
                    "gcp": ["gcp_org_session_controls", "gcp_iam_session_length"],
                },
            },
            {
                "id": "164.312(a)(2)(iv)",
                "title": "Encryption and Decryption",
                "description": (
                    "Implement mechanism to encrypt and decrypt ePHI."
                ),
                "checks": {
                    "aws": ["s3_default_encryption", "rds_encryption_at_rest", "ebs_encryption_enabled"],
                    "azure": ["azure_storage_encryption_cmk", "azure_sql_tde_enabled", "azure_disk_encryption"],
                    "gcp": ["gcp_storage_cmek", "gcp_sql_encryption_cmek", "gcp_compute_disk_cmek"],
                },
            },
            {
                "id": "164.312(b)",
                "title": "Audit Controls",
                "description": (
                    "Implement hardware, software, and/or procedural mechanisms "
                    "to record and examine activity in systems with ePHI."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation", "vpc_flow_logs_enabled"],
                    "azure": ["azure_monitor_log_profile", "azure_nsg_flow_logs_enabled"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_vpc_flow_logs_enabled"],
                },
            },
            {
                "id": "164.312(c)(1)",
                "title": "Integrity",
                "description": (
                    "Implement policies and procedures to protect ePHI from "
                    "improper alteration or destruction."
                ),
                "checks": {
                    "aws": ["s3_versioning_enabled", "s3_object_lock_enabled", "cloudtrail_log_validation"],
                    "azure": ["azure_storage_soft_delete", "azure_storage_immutability_policy"],
                    "gcp": ["gcp_storage_versioning", "gcp_storage_retention_policy"],
                },
            },
            {
                "id": "164.312(c)(2)",
                "title": "Mechanism to Authenticate Electronic PHI",
                "description": (
                    "Implement electronic mechanisms to corroborate that ePHI "
                    "has not been altered or destroyed."
                ),
                "checks": {
                    "aws": ["cloudtrail_log_validation", "s3_object_lock_enabled"],
                    "azure": ["azure_storage_immutability_policy"],
                    "gcp": ["gcp_storage_retention_policy", "gcp_logging_log_bucket_locked"],
                },
            },
            {
                "id": "164.312(d)",
                "title": "Person or Entity Authentication",
                "description": (
                    "Implement procedures to verify that a person or entity "
                    "seeking access to ePHI is who they claim to be."
                ),
                "checks": {
                    "aws": ["iam_mfa_enabled_for_console", "iam_root_mfa_enabled"],
                    "azure": ["azure_ad_mfa_enabled", "azure_ad_conditional_access"],
                    "gcp": ["gcp_iam_2fa_enforced", "gcp_org_policy_constraints"],
                },
            },
            {
                "id": "164.312(e)(1)",
                "title": "Transmission Security",
                "description": (
                    "Implement technical security measures to guard against "
                    "unauthorized access to ePHI transmitted over networks."
                ),
                "checks": {
                    "aws": ["elb_tls_listener", "s3_ssl_requests_only", "rds_ssl_enforced"],
                    "azure": ["azure_storage_https_only", "azure_sql_tls_enforced", "azure_appservice_https_only"],
                    "gcp": ["gcp_sql_ssl_enforced", "gcp_lb_ssl_policy", "gcp_storage_https_only"],
                },
            },
            {
                "id": "164.312(e)(2)(i)",
                "title": "Integrity Controls for Transmission",
                "description": (
                    "Implement security measures to ensure that electronically "
                    "transmitted ePHI is not improperly modified."
                ),
                "checks": {
                    "aws": ["elb_tls_listener", "cloudfront_tls_minimum_version"],
                    "azure": ["azure_appservice_tls_minimum", "azure_frontdoor_tls_minimum"],
                    "gcp": ["gcp_lb_ssl_policy", "gcp_compute_ssl_minimum_version"],
                },
            },
            {
                "id": "164.312(e)(2)(ii)",
                "title": "Encryption for Transmission",
                "description": (
                    "Implement mechanism to encrypt ePHI whenever deemed "
                    "appropriate during transmission."
                ),
                "checks": {
                    "aws": ["elb_tls_listener", "s3_ssl_requests_only", "vpc_vpn_encryption"],
                    "azure": ["azure_storage_https_only", "azure_vpn_gateway_encryption"],
                    "gcp": ["gcp_sql_ssl_enforced", "gcp_vpn_tunnel_encryption"],
                },
            },
            # ── Physical Safeguards (§164.310) ──────────────────────────────
            {
                "id": "164.310(a)(1)",
                "title": "Facility Access Controls",
                "description": (
                    "Implement policies and procedures to limit physical access "
                    "to electronic information systems."
                ),
                "checks": {
                    "aws": ["vpc_default_security_group_closed", "ec2_no_public_ip"],
                    "azure": ["azure_nsg_no_unrestricted_access", "azure_vm_no_public_ip"],
                    "gcp": ["gcp_compute_no_default_sa", "gcp_compute_no_public_ip"],
                },
            },
            {
                "id": "164.310(a)(2)(ii)",
                "title": "Facility Security Plan",
                "description": (
                    "Implement policies and procedures to safeguard the facility "
                    "and equipment from unauthorized access, tampering, and theft."
                ),
                "checks": {
                    "aws": ["vpc_security_groups_restrictive", "ec2_imdsv2_required"],
                    "azure": ["azure_nsg_no_unrestricted_access", "azure_vm_managed_disks"],
                    "gcp": ["gcp_compute_firewall_no_open_ports", "gcp_compute_shielded_vm"],
                },
            },
            {
                "id": "164.310(a)(2)(iv)",
                "title": "Maintenance Records",
                "description": (
                    "Implement policies and procedures to document repairs and "
                    "modifications to physical components of a facility."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "cloudtrail_multiregion"],
                    "azure": ["azure_monitor_activity_log", "azure_monitor_diagnostic_settings"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_asset_inventory_enabled"],
                },
            },
            {
                "id": "164.310(b)",
                "title": "Workstation Use",
                "description": (
                    "Implement policies and procedures that specify the proper "
                    "functions to be performed and physical attributes of "
                    "workstations with access to ePHI."
                ),
                "checks": {
                    "aws": ["ec2_imdsv2_required", "ssm_managed_instances"],
                    "azure": ["azure_vm_endpoint_protection", "azure_vm_auto_updates"],
                    "gcp": ["gcp_compute_shielded_vm", "gcp_compute_os_login"],
                },
            },
            {
                "id": "164.310(c)",
                "title": "Workstation Security",
                "description": (
                    "Implement physical safeguards for all workstations that "
                    "access ePHI to restrict access to authorized users."
                ),
                "checks": {
                    "aws": ["ec2_no_public_ip", "ssm_managed_instances"],
                    "azure": ["azure_vm_no_public_ip", "azure_jit_vm_access"],
                    "gcp": ["gcp_compute_no_public_ip", "gcp_compute_os_login"],
                },
            },
            {
                "id": "164.310(d)(1)",
                "title": "Device and Media Controls",
                "description": (
                    "Implement policies and procedures for the receipt and "
                    "removal of hardware and media with ePHI."
                ),
                "checks": {
                    "aws": ["ebs_encryption_enabled", "s3_default_encryption"],
                    "azure": ["azure_disk_encryption", "azure_storage_encryption_cmk"],
                    "gcp": ["gcp_compute_disk_cmek", "gcp_storage_cmek"],
                },
            },
            {
                "id": "164.310(d)(2)(i)",
                "title": "Disposal",
                "description": (
                    "Implement policies and procedures for final disposal of "
                    "ePHI and hardware or media on which it is stored."
                ),
                "checks": {
                    "aws": ["s3_lifecycle_policy", "ebs_snapshot_encryption"],
                    "azure": ["azure_storage_lifecycle_management", "azure_disk_encryption"],
                    "gcp": ["gcp_storage_lifecycle_policy", "gcp_compute_disk_cmek"],
                },
            },
            {
                "id": "164.310(d)(2)(iii)",
                "title": "Accountability",
                "description": (
                    "Maintain a record of movements of hardware and media "
                    "and the person responsible."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "config_recorder_enabled"],
                    "azure": ["azure_monitor_activity_log", "azure_resource_locks"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_asset_inventory_enabled"],
                },
            },
            {
                "id": "164.310(d)(2)(iv)",
                "title": "Data Backup and Storage",
                "description": (
                    "Create a retrievable, exact copy of ePHI before moving "
                    "equipment."
                ),
                "checks": {
                    "aws": ["backup_plan_exists", "ebs_snapshot_exists"],
                    "azure": ["azure_backup_vault_exists", "azure_snapshot_exists"],
                    "gcp": ["gcp_compute_snapshot_exists", "gcp_sql_automated_backups"],
                },
            },
            # ── Breach Notification Rule (§164.400-414) ─────────────────────
            {
                "id": "164.404(a)",
                "title": "Notification to Individuals",
                "description": (
                    "Covered entity must notify affected individuals following "
                    "discovery of a breach of unsecured ePHI."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "macie_enabled", "sns_topics_configured"],
                    "azure": ["azure_sentinel_automation_rules", "azure_alert_notifications_enabled"],
                    "gcp": ["gcp_scc_notifications_configured", "gcp_dlp_enabled"],
                },
            },
            {
                "id": "164.408",
                "title": "Notification to the Secretary",
                "description": (
                    "Covered entity must notify the Secretary of HHS following "
                    "discovery of a breach of unsecured ePHI."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "securityhub_enabled"],
                    "azure": ["azure_monitor_log_profile", "azure_defender_enabled"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_scc_enabled"],
                },
            },
            # ── Organizational Requirements (§164.314) ──────────────────────
            {
                "id": "164.314(a)(1)",
                "title": "Business Associate Contracts",
                "description": (
                    "A covered entity may permit a business associate to create, "
                    "receive, maintain, or transmit ePHI only if it obtains "
                    "satisfactory assurances."
                ),
                "checks": {
                    "aws": ["iam_cross_account_access_audit", "ram_shared_resources"],
                    "azure": ["azure_ad_external_collaboration", "azure_lighthouse_delegations"],
                    "gcp": ["gcp_iam_cross_project_permissions", "gcp_org_external_sharing"],
                },
            },
            {
                "id": "164.314(b)(1)",
                "title": "Requirements for Group Health Plans",
                "description": (
                    "Group health plan must ensure adequate separation between "
                    "the plan and the sponsor."
                ),
                "checks": {
                    "aws": ["organizations_scp_enabled", "iam_no_star_policies"],
                    "azure": ["azure_management_groups_configured", "azure_rbac_least_privilege"],
                    "gcp": ["gcp_org_policy_constraints", "gcp_resource_hierarchy"],
                },
            },
            # ── Policies & Procedures (§164.316) ───────────────────────────
            {
                "id": "164.316(a)",
                "title": "Policies and Procedures",
                "description": (
                    "Implement reasonable and appropriate policies and procedures "
                    "to comply with the Security Rule."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "config_rules_active"],
                    "azure": ["azure_policy_assignments_exist", "azure_policy_security_initiative"],
                    "gcp": ["gcp_org_policy_constraints", "gcp_scc_enabled"],
                },
            },
            {
                "id": "164.316(b)(1)",
                "title": "Documentation",
                "description": (
                    "Maintain written policies and procedures and written records "
                    "of required actions, activities, or assessments."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "config_recorder_enabled", "cloudtrail_s3_logging"],
                    "azure": ["azure_monitor_log_profile", "azure_storage_logging_enabled"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_logging_log_bucket_retention"],
                },
            },
            {
                "id": "164.316(b)(2)(i)",
                "title": "Time Limit on Documentation Retention",
                "description": (
                    "Retain documentation for 6 years from the date of its "
                    "creation or the date when it last was in effect."
                ),
                "checks": {
                    "aws": ["cloudtrail_s3_retention", "s3_lifecycle_policy", "cloudwatch_log_retention"],
                    "azure": ["azure_storage_lifecycle_management", "azure_log_analytics_retention"],
                    "gcp": ["gcp_logging_log_bucket_retention", "gcp_storage_lifecycle_policy"],
                },
            },
            {
                "id": "164.316(b)(2)(ii)",
                "title": "Availability of Documentation",
                "description": (
                    "Make documentation available to those persons responsible "
                    "for implementing the procedures."
                ),
                "checks": {
                    "aws": ["s3_versioning_enabled", "backup_plan_exists"],
                    "azure": ["azure_storage_geo_redundant", "azure_backup_vault_exists"],
                    "gcp": ["gcp_storage_multi_region", "gcp_storage_versioning"],
                },
            },
        ],
    },
}
