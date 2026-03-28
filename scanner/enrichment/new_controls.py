"""New controls for compliance framework enrichment.

Adds controls that cover regulatory requirements not yet represented
in the base framework definitions, bringing total coverage from 237
to ~300 controls across all five frameworks.
"""

# Structure: { framework_key: [ { "id": ..., "title": ..., ... }, ... ] }
NEW_CONTROLS: dict[str, list[dict]] = {
    # =========================================================================
    # ENS - 13 new controls
    # =========================================================================
    "ENS": [
        {
            "id": "op.pl.5",
            "title": "Componentes certificados",
            "description": (
                "Use of certified security components and products that have"
                " been evaluated against recognized standards."
            ),
            "checks": {
                "aws": ["config_recorder_enabled", "config_rules_active", "securityhub_enabled"],
                "azure": ["azure_policy_assignments_exist", "azure_policy_compliance_rate"],
                "gcp": ["gcp_org_policy_constraints", "gcp_scc_enabled"],
            },
        },
        {
            "id": "op.ext.1",
            "title": "Contratación y acuerdos de nivel de servicio",
            "description": (
                "Establish and enforce contractual agreements and service level"
                " agreements with third-party providers."
            ),
            "checks": {
                "aws": ["config_recorder_enabled", "cloudtrail_multiregion"],
                "azure": ["azure_monitor_diagnostic_settings", "azure_policy_assignments_exist"],
                "gcp": ["gcp_logging_audit_logs_enabled", "gcp_org_policy_constraints"],
            },
        },
        {
            "id": "op.ext.2",
            "title": "Gestión diaria",
            "description": (
                "Day-to-day operations management including monitoring,"
                " incident handling, and change control for external services."
            ),
            "checks": {
                "aws": ["cloudwatch_alarm_actions", "guardduty_enabled", "securityhub_enabled"],
                "azure": ["azure_monitor_diagnostic_settings", "azure_defender_enabled"],
                "gcp": ["gcp_logging_audit_logs_enabled", "gcp_scc_enabled"],
            },
        },
        {
            "id": "op.ext.3",
            "title": "Protección de la cadena de suministro",
            "description": (
                "Protect the supply chain by assessing and managing risks"
                " introduced by suppliers and third-party components."
            ),
            "checks": {
                "aws": ["inspector_enabled", "config_rules_active", "guardduty_enabled"],
                "azure": ["azure_defender_vulnerability_assessment", "azure_policy_compliance_rate"],
                "gcp": ["gcp_web_security_scanner", "gcp_scc_enabled"],
            },
        },
        {
            "id": "op.ext.4",
            "title": "Interconexión de sistemas",
            "description": (
                "Control and secure interconnections between internal systems"
                " and external networks."
            ),
            "checks": {
                "aws": ["vpc_flow_logs_enabled", "vpc_security_groups_restrictive", "ec2_no_unrestricted_ssh"],
                "azure": ["azure_nsg_no_unrestricted_access", "azure_firewall_configured"],
                "gcp": ["gcp_compute_firewall_no_open_ports", "gcp_vpc_flow_logs_enabled"],
            },
        },
        {
            "id": "op.nub.1",
            "title": "Protección de servicios en la nube",
            "description": (
                "Apply security controls for the protection of cloud-hosted"
                " services including data residency and access management."
            ),
            "checks": {
                "aws": ["s3_default_encryption", "s3_bucket_public_access_blocked", "iam_no_star_policies"],
                "azure": ["azure_storage_encryption_cmk", "azure_storage_no_public_access"],
                "gcp": ["gcp_storage_cmek", "gcp_storage_no_public_access"],
            },
        },
        {
            "id": "op.nub.2",
            "title": "Auditoría de servicios en la nube",
            "description": (
                "Audit and verify the security posture of cloud services,"
                " ensuring compliance with organizational policies."
            ),
            "checks": {
                "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation", "securityhub_enabled"],
                "azure": ["azure_monitor_diagnostic_settings", "azure_defender_enabled"],
                "gcp": ["gcp_logging_audit_logs_enabled", "gcp_scc_enabled"],
            },
        },
        {
            "id": "mp.eq.1",
            "title": "Puesto de trabajo despejado",
            "description": (
                "Enforce clean desk policies and endpoint security measures"
                " to protect workstations from unauthorized access."
            ),
            "checks": {
                "aws": ["iam_mfa_enabled_for_console", "iam_user_unused_credentials"],
                "azure": ["azure_ad_conditional_access", "azure_rbac_least_privilege"],
                "gcp": ["gcp_iam_2fa_enforced", "gcp_iam_no_primitive_roles"],
            },
        },
        {
            "id": "mp.eq.2",
            "title": "Bloqueo de puesto de trabajo",
            "description": (
                "Automatic workstation lockout after periods of inactivity"
                " to prevent unauthorized access."
            ),
            "checks": {
                "aws": ["iam_mfa_enabled_for_console", "iam_password_policy_strong"],
                "azure": ["azure_ad_conditional_access", "azure_ad_pim_enabled"],
                "gcp": ["gcp_iam_2fa_enforced", "gcp_iam_no_primitive_roles"],
            },
        },
        {
            "id": "mp.eq.3",
            "title": "Protección de dispositivos portátiles",
            "description": (
                "Security controls for mobile and portable devices including"
                " encryption, remote wipe, and access restrictions."
            ),
            "checks": {
                "aws": ["ebs_encryption_enabled", "s3_default_encryption", "iam_mfa_enabled_for_console"],
                "azure": ["azure_ad_conditional_access", "azure_storage_encryption_cmk"],
                "gcp": ["gcp_iam_2fa_enforced", "gcp_storage_cmek"],
            },
        },
        {
            "id": "mp.sw.1",
            "title": "Desarrollo",
            "description": (
                "Secure software development practices including code review,"
                " static analysis, and secure coding guidelines."
            ),
            "checks": {
                "aws": ["inspector_enabled", "config_rules_active"],
                "azure": ["azure_defender_vulnerability_assessment", "azure_policy_assignments_exist"],
                "gcp": ["gcp_web_security_scanner", "gcp_org_policy_constraints"],
            },
        },
        {
            "id": "mp.sw.2",
            "title": "Aceptación y puesta en servicio",
            "description": (
                "Formal acceptance testing and controlled deployment of"
                " software before it enters production."
            ),
            "checks": {
                "aws": ["config_recorder_enabled", "config_rules_active", "ssm_patch_compliance"],
                "azure": ["azure_policy_assignments_exist", "azure_policy_compliance_rate"],
                "gcp": ["gcp_org_policy_constraints", "gcp_scc_enabled"],
            },
        },
        {
            "id": "mp.per.1",
            "title": "Caracterización del puesto de trabajo",
            "description": (
                "Define role-based access profiles ensuring that personnel"
                " have only the permissions needed for their functions."
            ),
            "checks": {
                "aws": ["iam_no_star_policies", "iam_access_analyzer_enabled", "iam_user_unused_credentials"],
                "azure": ["azure_rbac_least_privilege", "azure_ad_pim_enabled"],
                "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_2fa_enforced"],
            },
        },
    ],
    # =========================================================================
    # GDPR - 12 new controls
    # =========================================================================
    "GDPR": [
        {
            "id": "Art.6",
            "title": "Lawfulness of processing",
            "description": (
                "Ensure all personal data processing has a legitimate legal"
                " basis as defined in the regulation."
            ),
            "checks": {
                "aws": ["cloudtrail_multiregion", "config_recorder_enabled", "macie_enabled"],
                "azure": ["azure_monitor_diagnostic_settings", "azure_purview_enabled"],
                "gcp": ["gcp_logging_audit_logs_enabled", "gcp_dlp_enabled"],
            },
        },
        {
            "id": "Art.7",
            "title": "Conditions for consent",
            "description": (
                "Manage and demonstrate valid, informed, and freely given"
                " consent for personal data processing."
            ),
            "checks": {
                "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation"],
                "azure": ["azure_monitor_diagnostic_settings", "azure_purview_enabled"],
                "gcp": ["gcp_logging_audit_logs_enabled", "gcp_dlp_enabled"],
            },
        },
        {
            "id": "Art.9",
            "title": "Processing of special categories",
            "description": (
                "Apply additional safeguards when processing special categories"
                " of personal data such as health, biometric, or ethnic data."
            ),
            "checks": {
                "aws": ["macie_enabled", "s3_default_encryption", "kms_key_rotation_enabled"],
                "azure": ["azure_purview_enabled", "azure_storage_encryption_cmk"],
                "gcp": ["gcp_dlp_enabled", "gcp_storage_cmek"],
            },
        },
        {
            "id": "Art.13",
            "title": "Information to be provided at collection",
            "description": (
                "Provide data subjects with transparent information at the"
                " point of data collection, including purpose and retention."
            ),
            "checks": {
                "aws": ["cloudtrail_multiregion", "macie_enabled"],
                "azure": ["azure_purview_enabled", "azure_monitor_diagnostic_settings"],
                "gcp": ["gcp_dlp_enabled", "gcp_logging_audit_logs_enabled"],
            },
        },
        {
            "id": "Art.16",
            "title": "Right to rectification",
            "description": (
                "Provide the ability for data subjects to correct inaccurate"
                " personal data without undue delay."
            ),
            "checks": {
                "aws": ["macie_enabled", "config_recorder_enabled"],
                "azure": ["azure_purview_enabled", "azure_policy_assignments_exist"],
                "gcp": ["gcp_dlp_enabled", "gcp_org_policy_constraints"],
            },
        },
        {
            "id": "Art.18",
            "title": "Right to restriction of processing",
            "description": (
                "Allow data subjects to restrict the processing of their"
                " personal data under certain conditions."
            ),
            "checks": {
                "aws": ["macie_enabled", "iam_no_star_policies", "cloudtrail_multiregion"],
                "azure": ["azure_purview_enabled", "azure_rbac_least_privilege"],
                "gcp": ["gcp_dlp_enabled", "gcp_iam_no_primitive_roles"],
            },
        },
        {
            "id": "Art.21",
            "title": "Right to object",
            "description": (
                "Provide mechanisms for data subjects to object to the"
                " processing of their personal data."
            ),
            "checks": {
                "aws": ["cloudtrail_multiregion", "macie_enabled"],
                "azure": ["azure_monitor_diagnostic_settings", "azure_purview_enabled"],
                "gcp": ["gcp_logging_audit_logs_enabled", "gcp_dlp_enabled"],
            },
        },
        {
            "id": "Art.22",
            "title": "Automated individual decision-making",
            "description": (
                "Control automated processing, including profiling, that"
                " produces legal or similarly significant effects on individuals."
            ),
            "checks": {
                "aws": ["cloudtrail_multiregion", "config_rules_active", "macie_enabled"],
                "azure": ["azure_monitor_diagnostic_settings", "azure_policy_compliance_rate"],
                "gcp": ["gcp_logging_audit_logs_enabled", "gcp_org_policy_constraints"],
            },
        },
        {
            "id": "Art.27",
            "title": "Representatives of controllers not established in the Union",
            "description": (
                "Designate a representative in the EU when the controller or"
                " processor is not established within the Union."
            ),
            "checks": {
                "aws": ["config_recorder_enabled", "cloudtrail_multiregion"],
                "azure": ["azure_policy_assignments_exist", "azure_monitor_diagnostic_settings"],
                "gcp": ["gcp_org_policy_constraints", "gcp_logging_audit_logs_enabled"],
            },
        },
        {
            "id": "Art.36",
            "title": "Prior consultation",
            "description": (
                "Consult the supervisory authority prior to processing where"
                " a data protection impact assessment indicates high risk."
            ),
            "checks": {
                "aws": ["securityhub_enabled", "guardduty_enabled", "inspector_enabled"],
                "azure": ["azure_defender_enabled", "azure_defender_vulnerability_assessment"],
                "gcp": ["gcp_scc_enabled", "gcp_web_security_scanner"],
            },
        },
        {
            "id": "Art.37",
            "title": "Designation of the DPO",
            "description": (
                "Designate a Data Protection Officer to oversee compliance"
                " and serve as a point of contact for supervisory authorities."
            ),
            "checks": {
                "aws": ["iam_access_analyzer_enabled", "cloudtrail_multiregion"],
                "azure": ["azure_ad_pim_enabled", "azure_monitor_diagnostic_settings"],
                "gcp": ["gcp_iam_no_primitive_roles", "gcp_logging_audit_logs_enabled"],
            },
        },
        {
            "id": "Art.47",
            "title": "Binding corporate rules",
            "description": (
                "Establish binding corporate rules to govern international"
                " transfers of personal data within a corporate group."
            ),
            "checks": {
                "aws": ["s3_default_encryption", "kms_key_rotation_enabled", "config_rules_active"],
                "azure": ["azure_storage_encryption_cmk", "azure_policy_compliance_rate"],
                "gcp": ["gcp_storage_cmek", "gcp_org_policy_constraints"],
            },
        },
    ],
    # =========================================================================
    # HIPAA - 13 new controls
    # =========================================================================
    "HIPAA": [
        {
            "id": "164.308(a)(2)",
            "title": "Assigned Security Responsibility",
            "description": (
                "Identify a security official responsible for developing and"
                " implementing security policies and procedures."
            ),
            "checks": {
                "aws": ["iam_access_analyzer_enabled", "securityhub_enabled"],
                "azure": ["azure_ad_pim_enabled", "azure_defender_enabled"],
                "gcp": ["gcp_iam_no_primitive_roles", "gcp_scc_enabled"],
            },
        },
        {
            "id": "164.308(a)(4)(ii)(A)",
            "title": "Isolating Healthcare Clearinghouse Functions",
            "description": (
                "Implement network segmentation to isolate healthcare"
                " clearinghouse functions from other operations."
            ),
            "checks": {
                "aws": ["vpc_default_security_group_closed", "vpc_security_groups_restrictive", "vpc_flow_logs_enabled"],
                "azure": ["azure_nsg_no_unrestricted_access", "azure_firewall_configured"],
                "gcp": ["gcp_compute_firewall_no_open_ports", "gcp_vpc_flow_logs_enabled"],
            },
        },
        {
            "id": "164.308(a)(5)(ii)(A)",
            "title": "Security Reminders",
            "description": (
                "Provide periodic security reminders and awareness updates"
                " to the workforce."
            ),
            "checks": {
                "aws": ["securityhub_enabled", "guardduty_enabled", "cloudwatch_alarm_actions"],
                "azure": ["azure_defender_enabled", "azure_monitor_diagnostic_settings"],
                "gcp": ["gcp_scc_enabled", "gcp_logging_audit_logs_enabled"],
            },
        },
        {
            "id": "164.308(a)(7)(ii)(C)",
            "title": "Emergency Mode Operation Plan",
            "description": (
                "Establish procedures to enable continuation of critical"
                " business processes during an emergency."
            ),
            "checks": {
                "aws": ["backup_plan_exists", "rds_multi_az", "rds_automated_backups"],
                "azure": ["azure_backup_vault_exists", "azure_recovery_services_configured"],
                "gcp": ["gcp_sql_automated_backups", "gcp_sql_ha_configured"],
            },
        },
        {
            "id": "164.308(a)(7)(ii)(D)",
            "title": "Testing and Revision Procedures",
            "description": (
                "Implement procedures for periodic testing and revision of"
                " contingency and disaster recovery plans."
            ),
            "checks": {
                "aws": ["backup_plan_exists", "config_rules_active", "rds_automated_backups"],
                "azure": ["azure_recovery_services_configured", "azure_policy_compliance_rate"],
                "gcp": ["gcp_sql_automated_backups", "gcp_org_policy_constraints"],
            },
        },
        {
            "id": "164.308(a)(7)(ii)(E)",
            "title": "Applications and Data Criticality Analysis",
            "description": (
                "Assess the relative criticality of applications and data"
                " to support contingency planning priorities."
            ),
            "checks": {
                "aws": ["config_recorder_enabled", "securityhub_enabled", "macie_enabled"],
                "azure": ["azure_defender_enabled", "azure_purview_enabled"],
                "gcp": ["gcp_scc_enabled", "gcp_dlp_enabled"],
            },
        },
        {
            "id": "164.310(a)(2)(i)",
            "title": "Contingency Operations",
            "description": (
                "Establish procedures for physical access to facilities"
                " during emergency operations and disaster recovery."
            ),
            "checks": {
                "aws": ["backup_plan_exists", "rds_multi_az"],
                "azure": ["azure_backup_vault_exists", "azure_recovery_services_configured"],
                "gcp": ["gcp_sql_automated_backups", "gcp_sql_ha_configured"],
            },
        },
        {
            "id": "164.310(a)(2)(iii)",
            "title": "Access Control and Validation",
            "description": (
                "Implement procedures to validate physical access based"
                " on role or function, including visitor control."
            ),
            "checks": {
                "aws": ["iam_no_star_policies", "iam_access_analyzer_enabled", "iam_mfa_enabled_for_console"],
                "azure": ["azure_rbac_least_privilege", "azure_ad_conditional_access"],
                "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_2fa_enforced"],
            },
        },
        {
            "id": "164.310(d)(2)(ii)",
            "title": "Removal of Media",
            "description": (
                "Implement policies and procedures for the secure removal"
                " and sanitization of electronic media containing ePHI."
            ),
            "checks": {
                "aws": ["s3_default_encryption", "ebs_encryption_enabled", "kms_key_rotation_enabled"],
                "azure": ["azure_storage_encryption_cmk", "azure_storage_no_public_access"],
                "gcp": ["gcp_storage_cmek", "gcp_storage_no_public_access"],
            },
        },
        {
            "id": "164.312(a)(2)(iii)-net",
            "title": "Automatic Logoff (Network)",
            "description": (
                "Implement network-level automatic session termination after"
                " a predetermined period of inactivity."
            ),
            "checks": {
                "aws": ["vpc_flow_logs_enabled", "cloudwatch_alarm_actions", "iam_password_policy_strong"],
                "azure": ["azure_ad_conditional_access", "azure_monitor_diagnostic_settings"],
                "gcp": ["gcp_vpc_flow_logs_enabled", "gcp_iam_2fa_enforced"],
            },
        },
        {
            "id": "164.404(b)",
            "title": "Timeliness of Notification",
            "description": (
                "Notify affected individuals of a breach without unreasonable"
                " delay and no later than 60 days after discovery."
            ),
            "checks": {
                "aws": ["securityhub_enabled", "guardduty_enabled", "cloudwatch_alarm_actions"],
                "azure": ["azure_defender_enabled", "azure_monitor_diagnostic_settings"],
                "gcp": ["gcp_scc_enabled", "gcp_logging_audit_logs_enabled"],
            },
        },
        {
            "id": "164.406",
            "title": "Notification to the Media",
            "description": (
                "Notify prominent media outlets in the affected jurisdiction"
                " when a breach affects more than 500 residents."
            ),
            "checks": {
                "aws": ["securityhub_enabled", "cloudwatch_alarm_actions"],
                "azure": ["azure_defender_enabled", "azure_monitor_diagnostic_settings"],
                "gcp": ["gcp_scc_enabled", "gcp_logging_audit_logs_enabled"],
            },
        },
        {
            "id": "164.410",
            "title": "Notification by a Business Associate",
            "description": (
                "Require business associates to notify the covered entity"
                " of any breach of unsecured protected health information."
            ),
            "checks": {
                "aws": ["cloudtrail_multiregion", "guardduty_enabled", "securityhub_enabled"],
                "azure": ["azure_defender_enabled", "azure_monitor_diagnostic_settings"],
                "gcp": ["gcp_scc_enabled", "gcp_logging_audit_logs_enabled"],
            },
        },
    ],
    # =========================================================================
    # PCI-DSS v4.0 - 13 new controls
    # =========================================================================
    "PCI-DSS-v4.0": [
        {
            "id": "1.4.2",
            "title": "Network traffic between trusted and untrusted controlled",
            "description": (
                "Implement DMZ controls to manage traffic between trusted"
                " and untrusted network zones."
            ),
            "checks": {
                "aws": ["vpc_security_groups_restrictive", "vpc_flow_logs_enabled", "ec2_no_unrestricted_ssh"],
                "azure": ["azure_firewall_configured", "azure_nsg_no_unrestricted_access"],
                "gcp": ["gcp_compute_firewall_no_open_ports", "gcp_vpc_flow_logs_enabled"],
            },
        },
        {
            "id": "2.2.3",
            "title": "Primary functions requiring different security levels separated",
            "description": (
                "Separate primary functions that require different security"
                " levels onto distinct system components."
            ),
            "checks": {
                "aws": ["vpc_default_security_group_closed", "vpc_security_groups_restrictive"],
                "azure": ["azure_nsg_no_unrestricted_access", "azure_firewall_configured"],
                "gcp": ["gcp_compute_firewall_no_open_ports", "gcp_vpc_flow_logs_enabled"],
            },
        },
        {
            "id": "2.2.4",
            "title": "Only necessary services and protocols enabled",
            "description": (
                "Harden system components by enabling only necessary services,"
                " protocols, daemons, and functions."
            ),
            "checks": {
                "aws": ["vpc_default_security_group_closed", "ec2_no_unrestricted_ssh", "ssm_patch_compliance"],
                "azure": ["azure_nsg_no_unrestricted_access", "azure_policy_compliance_rate"],
                "gcp": ["gcp_compute_firewall_no_open_ports", "gcp_org_policy_constraints"],
            },
        },
        {
            "id": "3.2.1",
            "title": "Account data storage is kept to minimum",
            "description": (
                "Minimize account data storage with data retention and"
                " disposal policies."
            ),
            "checks": {
                "aws": ["macie_enabled", "s3_bucket_public_access_blocked", "s3_default_encryption"],
                "azure": ["azure_purview_enabled", "azure_storage_no_public_access"],
                "gcp": ["gcp_dlp_enabled", "gcp_storage_no_public_access"],
            },
        },
        {
            "id": "3.3.1",
            "title": "SAD not retained after authorization",
            "description": (
                "Sensitive authentication data is not stored after"
                " authorization, even if encrypted."
            ),
            "checks": {
                "aws": ["macie_enabled", "s3_default_encryption", "kms_key_rotation_enabled"],
                "azure": ["azure_purview_enabled", "azure_storage_encryption_cmk"],
                "gcp": ["gcp_dlp_enabled", "gcp_storage_cmek"],
            },
        },
        {
            "id": "5.2.2",
            "title": "Anti-malware solution detects all known types",
            "description": (
                "Deploy anti-malware solutions capable of detecting all"
                " known types of malware."
            ),
            "checks": {
                "aws": ["guardduty_enabled", "inspector_enabled", "securityhub_enabled"],
                "azure": ["azure_defender_enabled", "azure_defender_vulnerability_assessment"],
                "gcp": ["gcp_scc_enabled", "gcp_web_security_scanner"],
            },
        },
        {
            "id": "5.4.1",
            "title": "Mechanisms in place to detect phishing",
            "description": (
                "Implement mechanisms to detect and protect personnel"
                " against phishing attacks."
            ),
            "checks": {
                "aws": ["guardduty_enabled", "securityhub_enabled", "waf_web_acl_configured"],
                "azure": ["azure_defender_enabled", "azure_ad_conditional_access"],
                "gcp": ["gcp_scc_enabled", "gcp_iam_2fa_enforced"],
            },
        },
        {
            "id": "6.2.2",
            "title": "Custom software developed securely",
            "description": (
                "Ensure bespoke and custom software is developed securely"
                " following industry best practices."
            ),
            "checks": {
                "aws": ["inspector_enabled", "config_rules_active"],
                "azure": ["azure_defender_vulnerability_assessment", "azure_policy_assignments_exist"],
                "gcp": ["gcp_web_security_scanner", "gcp_org_policy_constraints"],
            },
        },
        {
            "id": "6.4.3",
            "title": "Payment page scripts managed",
            "description": (
                "Manage and authorize all payment page scripts to ensure"
                " integrity and prevent skimming attacks."
            ),
            "checks": {
                "aws": ["waf_web_acl_configured", "cloudtrail_multiregion"],
                "azure": ["azure_defender_enabled", "azure_monitor_diagnostic_settings"],
                "gcp": ["gcp_scc_enabled", "gcp_web_security_scanner"],
            },
        },
        {
            "id": "8.2.2",
            "title": "Group and shared accounts not used",
            "description": (
                "Prohibit the use of group, shared, or generic accounts"
                " and credentials for system access."
            ),
            "checks": {
                "aws": ["iam_no_star_policies", "iam_user_unused_credentials", "iam_access_analyzer_enabled"],
                "azure": ["azure_ad_pim_enabled", "azure_rbac_least_privilege"],
                "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_2fa_enforced"],
            },
        },
        {
            "id": "8.3.9",
            "title": "Passwords/passphrases changed at least every 90 days",
            "description": (
                "Enforce password rotation policies requiring changes at"
                " least every 90 days where MFA is not implemented."
            ),
            "checks": {
                "aws": ["iam_password_policy_strong", "iam_access_key_rotation", "iam_mfa_enabled_for_console"],
                "azure": ["azure_ad_conditional_access", "azure_ad_pim_enabled"],
                "gcp": ["gcp_iam_2fa_enforced", "gcp_iam_no_primitive_roles"],
            },
        },
        {
            "id": "10.4.2",
            "title": "Failures of critical security controls detected and reported",
            "description": (
                "Detect and alert on failures of critical security control"
                " systems including logging, IDS, and monitoring."
            ),
            "checks": {
                "aws": ["cloudwatch_alarm_actions", "securityhub_enabled", "guardduty_enabled"],
                "azure": ["azure_monitor_diagnostic_settings", "azure_defender_enabled"],
                "gcp": ["gcp_logging_audit_logs_enabled", "gcp_scc_enabled"],
            },
        },
        {
            "id": "12.6.2",
            "title": "Security awareness program reviewed annually",
            "description": (
                "Review the security awareness program at least annually"
                " and update based on emerging threats."
            ),
            "checks": {
                "aws": ["config_rules_active", "securityhub_enabled"],
                "azure": ["azure_policy_compliance_rate", "azure_defender_enabled"],
                "gcp": ["gcp_org_policy_constraints", "gcp_scc_enabled"],
            },
        },
    ],
    # =========================================================================
    # SOC2 - 12 new controls
    # =========================================================================
    "SOC2": [
        {
            "id": "CC6.4",
            "title": "Access to physical assets restricted",
            "description": (
                "Restrict physical access to facilities and assets to"
                " authorized personnel only."
            ),
            "checks": {
                "aws": ["iam_mfa_enabled_for_console", "iam_no_star_policies", "iam_access_analyzer_enabled"],
                "azure": ["azure_rbac_least_privilege", "azure_ad_conditional_access"],
                "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_2fa_enforced"],
            },
        },
        {
            "id": "CC6.5",
            "title": "Assets disposed of securely",
            "description": (
                "Dispose of physical and logical assets securely when they"
                " are no longer needed."
            ),
            "checks": {
                "aws": ["s3_default_encryption", "ebs_encryption_enabled", "kms_key_rotation_enabled"],
                "azure": ["azure_storage_encryption_cmk", "azure_storage_no_public_access"],
                "gcp": ["gcp_storage_cmek", "gcp_storage_no_public_access"],
            },
        },
        {
            "id": "CC9.3",
            "title": "Risk from business disruption managed",
            "description": (
                "Identify, assess, and manage risks from potential business"
                " disruptions to maintain service continuity."
            ),
            "checks": {
                "aws": ["backup_plan_exists", "rds_multi_az", "rds_automated_backups"],
                "azure": ["azure_backup_vault_exists", "azure_recovery_services_configured"],
                "gcp": ["gcp_sql_automated_backups", "gcp_sql_ha_configured"],
            },
        },
        {
            "id": "A1.4",
            "title": "Environmental protections verified",
            "description": (
                "Verify that environmental protections, including power,"
                " cooling, and fire suppression, are operating effectively."
            ),
            "checks": {
                "aws": ["config_recorder_enabled", "cloudwatch_alarm_actions", "securityhub_enabled"],
                "azure": ["azure_monitor_diagnostic_settings", "azure_defender_enabled"],
                "gcp": ["gcp_logging_audit_logs_enabled", "gcp_scc_enabled"],
            },
        },
        {
            "id": "PI1.3",
            "title": "Processing accuracy validated",
            "description": (
                "Validate the accuracy of data processing to ensure outputs"
                " match expected results."
            ),
            "checks": {
                "aws": ["config_rules_active", "cloudtrail_multiregion", "cloudtrail_log_validation"],
                "azure": ["azure_policy_compliance_rate", "azure_monitor_diagnostic_settings"],
                "gcp": ["gcp_org_policy_constraints", "gcp_logging_audit_logs_enabled"],
            },
        },
        {
            "id": "PI1.4",
            "title": "Processing outputs complete and accurate",
            "description": (
                "Verify that processing outputs are complete, accurate, and"
                " timely in accordance with specifications."
            ),
            "checks": {
                "aws": ["config_rules_active", "cloudwatch_alarm_actions"],
                "azure": ["azure_policy_compliance_rate", "azure_monitor_diagnostic_settings"],
                "gcp": ["gcp_org_policy_constraints", "gcp_logging_audit_logs_enabled"],
            },
        },
        {
            "id": "PI1.5",
            "title": "Inputs stored and maintained accurately",
            "description": (
                "Ensure that processing inputs are stored and maintained"
                " with integrity and accuracy."
            ),
            "checks": {
                "aws": ["s3_default_encryption", "s3_bucket_public_access_blocked", "rds_encryption_at_rest"],
                "azure": ["azure_storage_encryption_cmk", "azure_storage_no_public_access"],
                "gcp": ["gcp_storage_cmek", "gcp_storage_no_public_access"],
            },
        },
        {
            "id": "P1.2",
            "title": "Privacy notice communicated",
            "description": (
                "Communicate privacy notices to data subjects describing"
                " the purpose, use, and retention of personal information."
            ),
            "checks": {
                "aws": ["cloudtrail_multiregion", "macie_enabled"],
                "azure": ["azure_purview_enabled", "azure_monitor_diagnostic_settings"],
                "gcp": ["gcp_dlp_enabled", "gcp_logging_audit_logs_enabled"],
            },
        },
        {
            "id": "P2.1",
            "title": "Consent obtained for data collection",
            "description": (
                "Obtain informed consent from data subjects before collecting"
                " their personal information."
            ),
            "checks": {
                "aws": ["cloudtrail_multiregion", "cloudtrail_log_validation", "macie_enabled"],
                "azure": ["azure_monitor_diagnostic_settings", "azure_purview_enabled"],
                "gcp": ["gcp_logging_audit_logs_enabled", "gcp_dlp_enabled"],
            },
        },
        {
            "id": "P5.1",
            "title": "Personal information use limited",
            "description": (
                "Limit the use of personal information to the purposes"
                " identified in the privacy notice."
            ),
            "checks": {
                "aws": ["macie_enabled", "iam_no_star_policies", "s3_bucket_public_access_blocked"],
                "azure": ["azure_purview_enabled", "azure_rbac_least_privilege"],
                "gcp": ["gcp_dlp_enabled", "gcp_iam_no_primitive_roles"],
            },
        },
        {
            "id": "P5.2",
            "title": "Personal information retained per policy",
            "description": (
                "Retain personal information only for the period stated in"
                " the retention policy and securely dispose of it afterward."
            ),
            "checks": {
                "aws": ["macie_enabled", "s3_default_encryption", "config_rules_active"],
                "azure": ["azure_purview_enabled", "azure_storage_encryption_cmk"],
                "gcp": ["gcp_dlp_enabled", "gcp_storage_cmek"],
            },
        },
        {
            "id": "P7.1",
            "title": "Disclosure to third parties controlled",
            "description": (
                "Control and document the disclosure of personal information"
                " to third parties with appropriate agreements."
            ),
            "checks": {
                "aws": ["macie_enabled", "cloudtrail_multiregion", "s3_bucket_public_access_blocked"],
                "azure": ["azure_purview_enabled", "azure_storage_no_public_access"],
                "gcp": ["gcp_dlp_enabled", "gcp_storage_no_public_access"],
            },
        },
    ],
}


def apply_new_controls(frameworks: dict) -> int:
    """Append new controls to loaded frameworks. Returns count added."""
    added = 0
    for fw_key, controls in NEW_CONTROLS.items():
        if fw_key not in frameworks:
            continue
        existing_ids = {c["id"] for c in frameworks[fw_key].get("controls", [])}
        for ctrl in controls:
            if ctrl["id"] not in existing_ids:
                frameworks[fw_key]["controls"].append(ctrl)
                added += 1
    return added
