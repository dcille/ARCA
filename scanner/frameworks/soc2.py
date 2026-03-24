"""SOC 2 -- Service Organization Control 2 (Type II).

Compliance framework mapping AICPA Trust Service Criteria to cloud security
checks across AWS, Azure, GCP, OCI, and Alibaba Cloud.
"""

FRAMEWORK = {
    "SOC2": {
        "name": "SOC 2 Type II — AICPA Trust Service Criteria",
        "description": (
            "American Institute of Certified Public Accountants (AICPA) "
            "framework evaluating a service organization's controls relevant "
            "to security, availability, processing integrity, confidentiality, "
            "and privacy (Trust Service Criteria)."
        ),
        "category": "industry",
        "controls": [
            # ── CC1: Control Environment ────────────────────────────────────
            {
                "id": "CC1.1",
                "title": "COSO Principle 1: Integrity and Ethical Values",
                "description": (
                    "The entity demonstrates a commitment to integrity and "
                    "ethical values."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "organizations_scp_enabled"],
                    "azure": ["azure_policy_assignments_exist", "azure_policy_security_initiative"],
                    "gcp": ["gcp_org_policy_constraints", "gcp_resource_hierarchy"],
                },
            },
            {
                "id": "CC1.2",
                "title": "COSO Principle 2: Board Independence and Oversight",
                "description": (
                    "The board of directors demonstrates independence from "
                    "management and exercises oversight."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "securityhub_enabled"],
                    "azure": ["azure_defender_enabled", "azure_monitor_log_profile"],
                    "gcp": ["gcp_scc_enabled", "gcp_logging_audit_logs_enabled"],
                },
            },
            {
                "id": "CC1.3",
                "title": "COSO Principle 3: Management Establishes Structure and Authority",
                "description": (
                    "Management establishes structures, reporting lines, and "
                    "appropriate authorities and responsibilities."
                ),
                "checks": {
                    "aws": ["iam_policies_attached_to_groups", "organizations_scp_enabled"],
                    "azure": ["azure_management_groups_configured", "azure_rbac_least_privilege"],
                    "gcp": ["gcp_resource_hierarchy", "gcp_iam_separation_of_duties"],
                },
            },
            {
                "id": "CC1.4",
                "title": "COSO Principle 4: Commitment to Competence",
                "description": (
                    "The entity demonstrates a commitment to attract, develop, "
                    "and retain competent individuals."
                ),
                "checks": {
                    "aws": ["securityhub_enabled"],
                    "azure": ["azure_defender_enabled"],
                    "gcp": ["gcp_scc_enabled"],
                },
            },
            {
                "id": "CC1.5",
                "title": "COSO Principle 5: Accountability for Internal Control",
                "description": (
                    "The entity holds individuals accountable for their internal "
                    "control responsibilities."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "iam_access_analyzer_enabled"],
                    "azure": ["azure_monitor_activity_log", "azure_ad_access_reviews"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_iam_recommender_enabled"],
                },
            },
            # ── CC2: Communication and Information ──────────────────────────
            {
                "id": "CC2.1",
                "title": "COSO Principle 13: Quality Information",
                "description": (
                    "The entity obtains or generates and uses relevant, quality "
                    "information to support the functioning of internal control."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "config_recorder_enabled", "cloudwatch_alarm_actions"],
                    "azure": ["azure_monitor_diagnostic_settings", "azure_monitor_log_profile"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_logging_sinks_configured"],
                },
            },
            {
                "id": "CC2.2",
                "title": "COSO Principle 14: Internal Communication",
                "description": (
                    "The entity internally communicates information necessary "
                    "to support the functioning of internal control."
                ),
                "checks": {
                    "aws": ["sns_topics_configured", "cloudwatch_alarm_actions"],
                    "azure": ["azure_action_groups_configured", "azure_alert_notifications_enabled"],
                    "gcp": ["gcp_scc_notifications_configured", "gcp_logging_alert_policies"],
                },
            },
            {
                "id": "CC2.3",
                "title": "COSO Principle 15: External Communication",
                "description": (
                    "The entity communicates with external parties regarding "
                    "matters affecting the functioning of internal control."
                ),
                "checks": {
                    "aws": ["sns_topics_configured", "ses_identity_verified"],
                    "azure": ["azure_security_contact_configured", "azure_alert_notifications_enabled"],
                    "gcp": ["gcp_scc_notifications_configured", "gcp_essential_contacts_configured"],
                },
            },
            # ── CC3: Risk Assessment ────────────────────────────────────────
            {
                "id": "CC3.1",
                "title": "COSO Principle 6: Specifies Suitable Objectives",
                "description": (
                    "The entity specifies objectives with sufficient clarity "
                    "to enable identification and assessment of risks."
                ),
                "checks": {
                    "aws": ["config_rules_active", "securityhub_enabled"],
                    "azure": ["azure_policy_compliance_rate", "azure_defender_enabled"],
                    "gcp": ["gcp_scc_enabled", "gcp_org_policy_constraints"],
                },
            },
            {
                "id": "CC3.2",
                "title": "COSO Principle 7: Identifies and Analyzes Risk",
                "description": (
                    "The entity identifies risks to the achievement of its "
                    "objectives and analyzes risks as a basis for determining "
                    "how risks should be managed."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "inspector_enabled", "securityhub_enabled"],
                    "azure": ["azure_defender_enabled", "azure_defender_vulnerability_assessment"],
                    "gcp": ["gcp_scc_enabled", "gcp_web_security_scanner"],
                },
            },
            {
                "id": "CC3.3",
                "title": "COSO Principle 8: Considers Potential for Fraud",
                "description": (
                    "The entity considers the potential for fraud in assessing "
                    "risks to the achievement of objectives."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "macie_enabled", "cloudtrail_console_signin_alarm"],
                    "azure": ["azure_ad_sign_in_risk_policy", "azure_sentinel_automation_rules"],
                    "gcp": ["gcp_scc_enabled", "gcp_logging_admin_activity"],
                },
            },
            {
                "id": "CC3.4",
                "title": "COSO Principle 9: Identifies and Assesses Changes",
                "description": (
                    "The entity identifies and assesses changes that could "
                    "significantly impact the system of internal control."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "cloudtrail_iam_changes_alarm"],
                    "azure": ["azure_monitor_iam_changes", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_logging_iam_changes", "gcp_asset_inventory_enabled"],
                },
            },
            # ── CC4: Monitoring Activities ──────────────────────────────────
            {
                "id": "CC4.1",
                "title": "COSO Principle 16: Selects and Develops Monitoring Activities",
                "description": (
                    "The entity selects, develops, and performs monitoring "
                    "activities to ascertain controls are present and functioning."
                ),
                "checks": {
                    "aws": ["securityhub_enabled", "config_rules_active", "guardduty_enabled"],
                    "azure": ["azure_defender_enabled", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_scc_enabled", "gcp_scc_findings_resolved"],
                },
            },
            {
                "id": "CC4.2",
                "title": "COSO Principle 17: Evaluates and Communicates Deficiencies",
                "description": (
                    "The entity evaluates and communicates internal control "
                    "deficiencies in a timely manner."
                ),
                "checks": {
                    "aws": ["securityhub_enabled", "cloudwatch_alarm_actions", "sns_topics_configured"],
                    "azure": ["azure_alert_notifications_enabled", "azure_action_groups_configured"],
                    "gcp": ["gcp_scc_notifications_configured", "gcp_logging_alert_policies"],
                },
            },
            # ── CC5: Control Activities ─────────────────────────────────────
            {
                "id": "CC5.1",
                "title": "COSO Principle 10: Selects and Develops Control Activities",
                "description": (
                    "The entity selects and develops control activities that "
                    "contribute to the mitigation of risks."
                ),
                "checks": {
                    "aws": ["config_rules_active", "iam_no_star_policies", "guardduty_enabled"],
                    "azure": ["azure_policy_assignments_exist", "azure_rbac_least_privilege"],
                    "gcp": ["gcp_org_policy_constraints", "gcp_iam_no_primitive_roles"],
                },
            },
            {
                "id": "CC5.2",
                "title": "COSO Principle 11: Technology General Controls",
                "description": (
                    "The entity selects and develops general control activities "
                    "over technology to support the achievement of objectives."
                ),
                "checks": {
                    "aws": ["vpc_default_security_group_closed", "ec2_imdsv2_required"],
                    "azure": ["azure_nsg_no_unrestricted_access", "azure_vm_managed_disks"],
                    "gcp": ["gcp_compute_firewall_no_open_ports", "gcp_compute_shielded_vm"],
                },
            },
            {
                "id": "CC5.3",
                "title": "COSO Principle 12: Deploys Through Policies and Procedures",
                "description": (
                    "The entity deploys control activities through policies "
                    "and procedures that put directives into action."
                ),
                "checks": {
                    "aws": ["organizations_scp_enabled", "config_rules_active"],
                    "azure": ["azure_policy_assignments_exist", "azure_management_groups_configured"],
                    "gcp": ["gcp_org_policy_constraints", "gcp_resource_hierarchy"],
                },
            },
            # ── CC6: Logical and Physical Access Controls ───────────────────
            {
                "id": "CC6.1",
                "title": "Logical Access Security Software and Infrastructure",
                "description": (
                    "The entity implements logical access security software, "
                    "infrastructure, and architectures over protected information "
                    "assets to protect them from security events."
                ),
                "checks": {
                    "aws": ["iam_no_star_policies", "iam_no_root_access_key", "vpc_default_security_group_closed"],
                    "azure": ["azure_rbac_least_privilege", "azure_nsg_no_unrestricted_access"],
                    "gcp": ["gcp_iam_no_public_access", "gcp_compute_firewall_no_open_ports"],
                },
            },
            {
                "id": "CC6.2",
                "title": "User Registration and Authorization",
                "description": (
                    "Prior to granting access, the entity registers and "
                    "authorizes new internal and external users whose access "
                    "is administered by the entity."
                ),
                "checks": {
                    "aws": ["iam_users_in_groups", "iam_policies_attached_to_groups"],
                    "azure": ["azure_ad_pim_enabled", "azure_ad_access_reviews"],
                    "gcp": ["gcp_iam_separation_of_duties", "gcp_iam_recommender_enabled"],
                },
            },
            {
                "id": "CC6.3",
                "title": "Role-Based Access and Least Privilege",
                "description": (
                    "The entity authorizes, modifies, or removes access to "
                    "data and other protected assets based on roles and "
                    "the principle of least privilege."
                ),
                "checks": {
                    "aws": ["iam_no_star_policies", "iam_user_no_attached_policies", "iam_access_analyzer_enabled"],
                    "azure": ["azure_rbac_least_privilege", "azure_iam_no_custom_owner_roles"],
                    "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_no_public_access"],
                },
            },
            {
                "id": "CC6.6",
                "title": "Security Measures Against Threats Outside System Boundaries",
                "description": (
                    "The entity implements logical access security measures "
                    "to protect against threats from sources outside its "
                    "system boundaries."
                ),
                "checks": {
                    "aws": ["waf_web_acl_configured", "guardduty_enabled", "vpc_security_groups_restrictive"],
                    "azure": ["azure_waf_enabled", "azure_firewall_configured", "azure_ddos_protection"],
                    "gcp": ["gcp_cloud_armor_enabled", "gcp_compute_firewall_no_open_ports"],
                },
            },
            {
                "id": "CC6.7",
                "title": "Restricts Transmission and Movement of Data",
                "description": (
                    "The entity restricts the transmission, movement, and "
                    "removal of information to authorized internal and external "
                    "users and processes."
                ),
                "checks": {
                    "aws": ["s3_bucket_public_access_blocked", "s3_ssl_requests_only", "elb_tls_listener"],
                    "azure": ["azure_storage_https_only", "azure_storage_no_public_access"],
                    "gcp": ["gcp_storage_no_public_access", "gcp_sql_ssl_enforced"],
                },
            },
            {
                "id": "CC6.8",
                "title": "Prevents or Detects Unauthorized or Malicious Software",
                "description": (
                    "The entity implements controls to prevent or detect and "
                    "act upon the introduction of unauthorized or malicious "
                    "software."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "guardduty_malware_protection"],
                    "azure": ["azure_endpoint_protection_installed", "azure_defender_enabled"],
                    "gcp": ["gcp_scc_enabled", "gcp_compute_shielded_vm"],
                },
            },
            # ── CC7: System Operations ──────────────────────────────────────
            {
                "id": "CC7.1",
                "title": "Detection and Monitoring of Security Events",
                "description": (
                    "To meet its objectives, the entity uses detection and "
                    "monitoring procedures to identify changes to configurations "
                    "that result in new vulnerabilities."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "config_recorder_enabled", "inspector_enabled"],
                    "azure": ["azure_defender_enabled", "azure_monitor_diagnostic_settings"],
                    "gcp": ["gcp_scc_enabled", "gcp_logging_audit_logs_enabled"],
                },
            },
            {
                "id": "CC7.2",
                "title": "Monitors for Anomalies and Security Events",
                "description": (
                    "The entity monitors system components for anomalies that "
                    "are indicative of malicious acts, natural disasters, and "
                    "errors."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "cloudwatch_alarm_actions", "cloudtrail_console_signin_alarm"],
                    "azure": ["azure_sentinel_automation_rules", "azure_defender_enabled"],
                    "gcp": ["gcp_scc_enabled", "gcp_logging_metric_filters"],
                },
            },
            {
                "id": "CC7.3",
                "title": "Evaluates Security Events",
                "description": (
                    "The entity evaluates identified security events to "
                    "determine whether they could or have resulted in a "
                    "failure to meet its objectives."
                ),
                "checks": {
                    "aws": ["securityhub_enabled", "guardduty_enabled"],
                    "azure": ["azure_defender_enabled", "azure_sentinel_automation_rules"],
                    "gcp": ["gcp_scc_enabled", "gcp_scc_findings_resolved"],
                },
            },
            {
                "id": "CC7.4",
                "title": "Responds to Security Incidents",
                "description": (
                    "The entity responds to identified security incidents by "
                    "executing a defined incident-response program."
                ),
                "checks": {
                    "aws": ["guardduty_enabled", "sns_topics_configured", "cloudwatch_alarm_actions"],
                    "azure": ["azure_sentinel_automation_rules", "azure_action_groups_configured"],
                    "gcp": ["gcp_scc_notifications_configured", "gcp_logging_alert_policies"],
                },
            },
            {
                "id": "CC7.5",
                "title": "Identifies and Recovers from Security Incidents",
                "description": (
                    "The entity identifies, develops, and implements activities "
                    "to recover from identified security incidents."
                ),
                "checks": {
                    "aws": ["backup_plan_exists", "rds_automated_backups", "s3_versioning_enabled"],
                    "azure": ["azure_backup_vault_exists", "azure_recovery_services_configured"],
                    "gcp": ["gcp_sql_automated_backups", "gcp_storage_versioning"],
                },
            },
            # ── CC8: Change Management ──────────────────────────────────────
            {
                "id": "CC8.1",
                "title": "Changes to Infrastructure and Software Authorized and Managed",
                "description": (
                    "The entity authorizes, designs, develops, configures, "
                    "documents, tests, approves, and implements changes to "
                    "infrastructure and software."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "cloudtrail_iam_changes_alarm"],
                    "azure": ["azure_monitor_iam_changes", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_logging_iam_changes", "gcp_asset_inventory_enabled"],
                },
            },
            # ── CC9: Risk Mitigation ────────────────────────────────────────
            {
                "id": "CC9.1",
                "title": "Identifies and Manages Risk from Vendors",
                "description": (
                    "The entity identifies, selects, and develops risk "
                    "mitigation activities for risks arising from potential "
                    "business disruptions."
                ),
                "checks": {
                    "aws": ["backup_plan_exists", "rds_multi_az", "s3_cross_region_replication"],
                    "azure": ["azure_recovery_services_configured", "azure_sql_geo_replication"],
                    "gcp": ["gcp_sql_ha_configured", "gcp_storage_multi_region"],
                },
            },
            {
                "id": "CC9.2",
                "title": "Vendor and Business Partner Risk Management",
                "description": (
                    "The entity assesses and manages risks associated with "
                    "vendors and business partners."
                ),
                "checks": {
                    "aws": ["iam_cross_account_access_audit", "ram_shared_resources"],
                    "azure": ["azure_ad_external_collaboration", "azure_lighthouse_delegations"],
                    "gcp": ["gcp_iam_cross_project_permissions", "gcp_org_external_sharing"],
                },
            },
            # ── A: Availability ─────────────────────────────────────────────
            {
                "id": "A1.1",
                "title": "Capacity Management and Demand Forecasting",
                "description": (
                    "The entity maintains, monitors, and evaluates current "
                    "processing capacity and use of system components to "
                    "manage capacity demand."
                ),
                "checks": {
                    "aws": ["cloudwatch_alarm_actions", "autoscaling_configured"],
                    "azure": ["azure_monitor_diagnostic_settings", "azure_autoscale_configured"],
                    "gcp": ["gcp_compute_autoscaler_configured", "gcp_monitoring_alert_policies"],
                },
            },
            {
                "id": "A1.2",
                "title": "Recovery and Continuity Planning",
                "description": (
                    "The entity authorizes, designs, develops, implements, "
                    "operates, approves, maintains, and monitors environmental "
                    "protections, software, data backup processes, and recovery "
                    "infrastructure."
                ),
                "checks": {
                    "aws": ["backup_plan_exists", "rds_automated_backups", "rds_multi_az"],
                    "azure": ["azure_backup_vault_exists", "azure_sql_geo_replication"],
                    "gcp": ["gcp_sql_automated_backups", "gcp_sql_ha_configured"],
                },
            },
            {
                "id": "A1.3",
                "title": "Recovery Testing",
                "description": (
                    "The entity tests recovery plan procedures to ensure they "
                    "meet the entity's objectives."
                ),
                "checks": {
                    "aws": ["backup_plan_exists", "rds_automated_backups"],
                    "azure": ["azure_recovery_services_configured", "azure_backup_vault_exists"],
                    "gcp": ["gcp_sql_automated_backups", "gcp_gke_backup_enabled"],
                },
            },
            # ── C: Confidentiality ──────────────────────────────────────────
            {
                "id": "C1.1",
                "title": "Identification of Confidential Information",
                "description": (
                    "The entity identifies and maintains confidential "
                    "information to meet its objectives."
                ),
                "checks": {
                    "aws": ["macie_enabled", "config_recorder_enabled"],
                    "azure": ["azure_purview_enabled", "azure_information_protection"],
                    "gcp": ["gcp_dlp_enabled", "gcp_asset_inventory_enabled"],
                },
            },
            {
                "id": "C1.2",
                "title": "Disposal of Confidential Information",
                "description": (
                    "The entity disposes of confidential information to meet "
                    "its objectives related to confidentiality."
                ),
                "checks": {
                    "aws": ["s3_lifecycle_policy", "ebs_snapshot_lifecycle"],
                    "azure": ["azure_storage_lifecycle_management", "azure_storage_soft_delete"],
                    "gcp": ["gcp_storage_lifecycle_policy", "gcp_compute_snapshot_policy"],
                },
            },
            # ── PI: Processing Integrity ────────────────────────────────────
            {
                "id": "PI1.1",
                "title": "Quality Assurance for System Processing",
                "description": (
                    "The entity implements policies and procedures over system "
                    "processing to achieve completeness, accuracy, timeliness, "
                    "and authorization."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "cloudtrail_log_validation"],
                    "azure": ["azure_monitor_diagnostic_settings", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_scc_enabled"],
                },
            },
            {
                "id": "PI1.2",
                "title": "System Input Controls",
                "description": (
                    "The entity implements policies and procedures to ensure "
                    "that system inputs are complete, accurate, and timely."
                ),
                "checks": {
                    "aws": ["waf_web_acl_configured", "api_gateway_authorization"],
                    "azure": ["azure_waf_enabled", "azure_api_management_policies"],
                    "gcp": ["gcp_cloud_armor_enabled", "gcp_api_gateway_configured"],
                },
            },
            # ── P: Privacy ──────────────────────────────────────────────────
            {
                "id": "P1.1",
                "title": "Privacy Notice and Consent",
                "description": (
                    "The entity provides notice to data subjects about its "
                    "privacy practices to meet its objectives."
                ),
                "checks": {
                    "aws": ["cloudtrail_multiregion", "config_recorder_enabled"],
                    "azure": ["azure_monitor_diagnostic_settings"],
                    "gcp": ["gcp_logging_audit_logs_enabled"],
                },
            },
            {
                "id": "P3.1",
                "title": "Collection Limited to Identified Purpose",
                "description": (
                    "Personal information is collected consistent with "
                    "the entity's objectives."
                ),
                "checks": {
                    "aws": ["macie_enabled", "s3_bucket_public_access_blocked"],
                    "azure": ["azure_purview_enabled", "azure_storage_no_public_access"],
                    "gcp": ["gcp_dlp_enabled", "gcp_storage_no_public_access"],
                },
            },
            {
                "id": "P4.1",
                "title": "Use of Personal Information Limited",
                "description": (
                    "The entity limits the use of personal information to "
                    "the purposes identified in the entity's objectives."
                ),
                "checks": {
                    "aws": ["iam_no_star_policies", "macie_enabled"],
                    "azure": ["azure_rbac_least_privilege", "azure_purview_enabled"],
                    "gcp": ["gcp_iam_no_public_access", "gcp_dlp_enabled"],
                },
            },
            {
                "id": "P6.1",
                "title": "Disclosure of Personal Information",
                "description": (
                    "The entity discloses personal information to third parties "
                    "only for the purposes identified and with the implicit or "
                    "explicit consent of the data subject."
                ),
                "checks": {
                    "aws": ["s3_bucket_public_access_blocked", "iam_cross_account_access_audit"],
                    "azure": ["azure_storage_no_public_access", "azure_ad_external_collaboration"],
                    "gcp": ["gcp_storage_no_public_access", "gcp_org_external_sharing"],
                },
            },
            {
                "id": "P8.1",
                "title": "Data Quality and Accuracy",
                "description": (
                    "The entity collects and maintains accurate, up-to-date, "
                    "complete, and relevant personal information."
                ),
                "checks": {
                    "aws": ["config_recorder_enabled", "cloudtrail_multiregion"],
                    "azure": ["azure_monitor_diagnostic_settings", "azure_policy_compliance_rate"],
                    "gcp": ["gcp_logging_audit_logs_enabled", "gcp_asset_inventory_enabled"],
                },
            },
        ],
    },
}
