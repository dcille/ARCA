"""SaaS provider check_id mappings for compliance frameworks.

Maps SaaS-specific scanner check_ids to existing framework controls,
enriching ENS, GDPR, HIPAA, PCI-DSS, and SOC2 with M365, Google Workspace,
Snowflake, GitHub, Cloudflare, ServiceNow, Salesforce, and OpenStack coverage.
"""

# Structure: { framework_key: { control_id: { provider: [check_ids] } } }
SAAS_MAPPINGS: dict[str, dict[str, dict[str, list[str]]]] = {
    # ── ENS ────────────────────────────────────────────────────────────
    "ENS": {
        # org — Organizational controls
        "org.1": {
            "m365": ["m365_security_defaults_enabled"],
            "google_workspace": ["gws_cis_admin_audit_log_enabled"],
        },
        "org.3": {
            "m365": ["m365_audit_log_enabled"],
            "google_workspace": ["gws_cis_admin_audit_log_enabled"],
            "servicenow": ["servicenow_admin_audit_logging"],
        },
        "org.4": {
            "m365": ["m365_privileged_accounts_limited", "m365_ca_policies_configured"],
            "google_workspace": ["gws_admin_count_appropriate"],
            "salesforce": ["salesforce_admin_count_limited"],
        },
        # op.acc — Access controls
        "op.acc.1": {
            "m365": ["m365_admin_mfa_enforced", "m365_emergency_access_accounts"],
            "google_workspace": ["gws_admin_mfa_enforced"],
            "snowflake": ["snowflake_admin_count_appropriate"],
            "servicenow": ["servicenow_high_priv_roles_limited"],
            "salesforce": ["salesforce_admin_count_limited"],
        },
        "op.acc.2": {
            "m365": ["m365_ca_policies_configured", "m365_privileged_accounts_limited"],
            "google_workspace": ["gws_cis_custom_admin_roles_reviewed"],
            "snowflake": ["snowflake_system_defined_roles_minimal"],
            "github": ["github_org_base_permissions_none"],
        },
        "op.acc.3": {
            "m365": ["m365_privileged_accounts_limited"],
            "snowflake": ["snowflake_role_hierarchy_reviewed"],
            "servicenow": ["servicenow_role_separation"],
        },
        "op.acc.4": {
            "m365": ["m365_guest_expiration_configured"],
            "snowflake": ["snowflake_user_not_inactive", "snowflake_user_password_rotation"],
            "github": ["github_ac_inactive_members_removed"],
            "salesforce": ["salesforce_user_not_stale"],
        },
        "op.acc.5": {
            "m365": ["m365_user_mfa_registered", "m365_user_phishing_resistant_mfa"],
            "google_workspace": ["gws_user_2fa_enrolled", "gws_security_keys_admins"],
            "snowflake": ["snowflake_user_mfa_enabled"],
            "salesforce": ["salesforce_user_mfa_enabled"],
        },
        "op.acc.6": {
            "m365": ["m365_ca_require_mfa", "m365_ca_block_legacy_auth"],
            "google_workspace": ["gws_admin_2fa_enforced", "gws_less_secure_apps_disabled"],
            "servicenow": ["servicenow_users_mfa_enabled"],
        },
        "op.acc.7": {
            "m365": ["m365_ca_require_compliant_device"],
            "google_workspace": ["gws_cis_screen_lock_enforced"],
        },
        "op.acc.8": {
            "cloudflare": ["cloudflare_zt_access_app_configured"],
            "google_workspace": ["gws_sso_configured"],
            "servicenow": ["servicenow_sso_configured"],
        },
        # op.exp — Operations
        "op.exp.1": {
            "github": ["github_org_audit_log_streaming"],
            "servicenow": ["servicenow_cmdb_integrity"],
        },
        "op.exp.4": {
            "github": ["github_repo_dependabot_security_updates",
                        "github_repo_dependabot_version_updates"],
        },
        "op.exp.5": {
            "github": ["github_repo_branch_protection", "github_repo_require_reviews"],
            "servicenow": ["servicenow_change_management"],
        },
        "op.exp.6": {
            "m365": ["m365_defender_auto_investigation", "m365_safe_attachments_enabled"],
            "google_workspace": ["gws_cis_safe_browsing_gmail"],
            "github": ["github_repo_code_scanning", "github_repo_secret_scanning"],
            "cloudflare": ["cloudflare_waf_managed_rules"],
        },
        "op.exp.7": {
            "m365": ["m365_defender_alert_policies"],
            "google_workspace": ["gws_cis_alert_center_active"],
            "servicenow": ["servicenow_incident_management"],
        },
        "op.exp.8": {
            "m365": ["m365_audit_log_enabled", "m365_purview_audit_premium"],
            "google_workspace": ["gws_cis_admin_audit_log_enabled",
                                  "gws_cis_login_activity_monitored"],
            "snowflake": ["snowflake_audit_logging_enabled", "snowflake_query_audit_enabled"],
            "github": ["github_org_audit_log_streaming"],
            "salesforce": ["salesforce_setup_audit_trail"],
        },
        "op.exp.10": {
            "snowflake": ["snowflake_query_history_retention"],
        },
        # op.mon — Monitoring
        "op.mon.1": {
            "m365": ["m365_defender_auto_investigation"],
            "cloudflare": ["cloudflare_waf_managed_rules", "cloudflare_bot_management"],
            "github": ["github_repo_vulnerability_alerts"],
        },
        "op.mon.2": {
            "m365": ["m365_defender_alert_policies"],
            "google_workspace": ["gws_cis_alert_center_active"],
        },
        # mp.info — Information protection
        "mp.info.1": {
            "m365": ["m365_dlp_policies_configured", "m365_sensitivity_labels_enabled"],
            "snowflake": ["snowflake_column_masking_policies",
                           "snowflake_data_classification_enabled"],
            "salesforce": ["salesforce_field_level_security"],
        },
        "mp.info.3": {
            "m365": ["m365_aip_encryption_enabled"],
            "snowflake": ["snowflake_stages_encrypted"],
            "servicenow": ["servicenow_encryption_at_rest", "servicenow_field_encryption"],
            "salesforce": ["salesforce_encryption_at_rest"],
            "openstack": ["openstack_storage_volume_encrypted"],
        },
        "mp.info.7": {
            "snowflake": ["snowflake_failover_configured",
                           "snowflake_data_retention_configured"],
            "openstack": ["openstack_storage_backup_policies"],
        },
        # mp.s — Service protection
        "mp.s.1": {
            "m365": ["m365_anti_phishing_policy", "m365_safe_links_enabled",
                      "m365_dkim_configured", "m365_dmarc_configured"],
            "google_workspace": ["gws_email_dmarc_configured", "gws_email_spf_configured",
                                  "gws_email_dkim_configured",
                                  "gws_email_phishing_protection"],
        },
        "mp.s.2": {
            "cloudflare": ["cloudflare_waf_managed_rules", "cloudflare_waf_owasp_rules",
                            "cloudflare_tls_full_strict"],
        },
        "mp.s.3": {
            "cloudflare": ["cloudflare_waf_rate_limiting", "cloudflare_waf_ddos_challenge_ttl"],
        },
        # mp.com — Communications
        "mp.com.1": {
            "cloudflare": ["cloudflare_waf_firewall_rules", "cloudflare_waf_ip_access_rules"],
            "snowflake": ["snowflake_network_policy_set"],
            "openstack": ["openstack_net_sg_restrictive"],
        },
        "mp.com.2": {
            "cloudflare": ["cloudflare_tls_full_strict", "cloudflare_tls_min_version"],
            "servicenow": ["servicenow_tls_enforced"],
            "salesforce": ["salesforce_tls_enforced"],
            "openstack": ["openstack_api_tls_v12_minimum"],
        },
    },

    # ── HIPAA ──────────────────────────────────────────────────────────
    "HIPAA": {
        "164.308(a)(1)(i)": {
            "m365": ["m365_security_defaults_enabled", "m365_defender_alert_policies"],
            "google_workspace": ["gws_cis_alert_center_active"],
            "servicenow": ["servicenow_incident_management"],
        },
        "164.308(a)(1)(ii)(D)": {
            "m365": ["m365_audit_log_enabled", "m365_purview_audit_premium"],
            "google_workspace": ["gws_cis_admin_audit_log_enabled"],
            "snowflake": ["snowflake_audit_logging_enabled"],
            "salesforce": ["salesforce_setup_audit_trail"],
        },
        "164.308(a)(3)(i)": {
            "m365": ["m365_privileged_accounts_limited", "m365_ca_policies_configured"],
            "snowflake": ["snowflake_system_defined_roles_minimal"],
            "github": ["github_org_base_permissions_none"],
        },
        "164.308(a)(3)(ii)(A)": {
            "m365": ["m365_privileged_accounts_limited"],
            "salesforce": ["salesforce_no_modify_all_data", "salesforce_no_view_all_data"],
        },
        "164.308(a)(4)(i)": {
            "m365": ["m365_ca_policies_configured"],
            "snowflake": ["snowflake_role_hierarchy_reviewed"],
        },
        "164.308(a)(5)(i)": {
            "m365": ["m365_anti_phishing_policy", "m365_safe_links_enabled"],
            "google_workspace": ["gws_email_phishing_protection"],
        },
        "164.308(a)(5)(ii)(D)": {
            "m365": ["m365_ca_block_legacy_auth", "m365_legacy_auth_blocked"],
            "google_workspace": ["gws_less_secure_apps_disabled"],
            "snowflake": ["snowflake_user_password_rotation"],
        },
        "164.308(a)(6)(i)": {
            "m365": ["m365_defender_alert_policies"],
            "google_workspace": ["gws_cis_alert_center_active"],
            "servicenow": ["servicenow_incident_management"],
        },
        "164.308(a)(7)(i)": {
            "snowflake": ["snowflake_failover_configured"],
            "openstack": ["openstack_storage_backup_policies"],
        },
        "164.312(a)(1)": {
            "m365": ["m365_user_mfa_registered", "m365_ca_require_mfa"],
            "google_workspace": ["gws_user_2fa_enrolled"],
            "snowflake": ["snowflake_user_mfa_enabled"],
            "servicenow": ["servicenow_users_mfa_enabled"],
            "salesforce": ["salesforce_user_mfa_enabled"],
        },
        "164.312(a)(2)(i)": {
            "m365": ["m365_ca_policies_configured"],
            "snowflake": ["snowflake_row_access_policies"],
        },
        "164.312(a)(2)(ii)": {
            "m365": ["m365_cis_idle_session_timeout"],
            "snowflake": ["snowflake_account_session_timeout"],
            "servicenow": ["servicenow_session_timeout"],
            "salesforce": ["salesforce_session_timeout"],
        },
        "164.312(a)(2)(iv)": {
            "m365": ["m365_aip_encryption_enabled"],
            "snowflake": ["snowflake_stages_encrypted"],
            "servicenow": ["servicenow_encryption_at_rest"],
            "salesforce": ["salesforce_encryption_at_rest"],
        },
        "164.312(b)": {
            "m365": ["m365_audit_log_enabled", "m365_cis_mailbox_audit_enabled"],
            "google_workspace": ["gws_cis_admin_audit_log_enabled"],
            "snowflake": ["snowflake_audit_logging_enabled", "snowflake_query_audit_enabled"],
            "github": ["github_org_audit_log_streaming"],
            "salesforce": ["salesforce_setup_audit_trail",
                            "salesforce_event_monitoring"],
        },
        "164.312(c)(1)": {
            "m365": ["m365_sensitivity_labels_enabled"],
            "snowflake": ["snowflake_column_masking_policies"],
        },
        "164.312(d)": {
            "m365": ["m365_user_phishing_resistant_mfa"],
            "google_workspace": ["gws_security_keys_admins"],
            "servicenow": ["servicenow_sso_configured"],
            "salesforce": ["salesforce_sso_enabled"],
        },
        "164.312(e)(1)": {
            "cloudflare": ["cloudflare_tls_full_strict", "cloudflare_tls_min_version"],
            "servicenow": ["servicenow_tls_enforced"],
            "salesforce": ["salesforce_tls_enforced"],
        },
        "164.312(e)(2)(i)": {
            "cloudflare": ["cloudflare_tls_full_strict"],
            "openstack": ["openstack_api_tls_v12_minimum"],
        },
        "164.404(a)": {
            "m365": ["m365_defender_alert_policies"],
            "servicenow": ["servicenow_incident_management"],
        },
    },

    # ── PCI-DSS-v4.0 ──────────────────────────────────────────────────
    "PCI-DSS-v4.0": {
        "1.2.1": {
            "cloudflare": ["cloudflare_waf_firewall_rules"],
            "snowflake": ["snowflake_network_policy_set"],
            "openstack": ["openstack_net_sg_restrictive", "openstack_net_port_security"],
        },
        "1.3.1": {
            "cloudflare": ["cloudflare_waf_ip_access_rules"],
            "openstack": ["openstack_network_sg_no_ssh_open"],
        },
        "1.4.1": {
            "cloudflare": ["cloudflare_tls_full_strict"],
        },
        "2.2.1": {
            "servicenow": ["servicenow_instance_hardening"],
            "openstack": ["openstack_compute_default_sg_restrictive"],
        },
        "3.4.1": {
            "m365": ["m365_aip_encryption_enabled"],
            "snowflake": ["snowflake_stages_encrypted", "snowflake_column_masking_policies"],
            "servicenow": ["servicenow_encryption_at_rest"],
            "salesforce": ["salesforce_encryption_at_rest"],
        },
        "3.5.1": {
            "snowflake": ["snowflake_key_pair_rotation"],
        },
        "4.2.1": {
            "cloudflare": ["cloudflare_tls_full_strict", "cloudflare_tls_min_version",
                            "cloudflare_tls_tls_1_3_enabled"],
            "servicenow": ["servicenow_tls_enforced"],
            "salesforce": ["salesforce_tls_enforced"],
            "openstack": ["openstack_api_tls_v12_minimum"],
        },
        "5.2.1": {
            "m365": ["m365_defender_auto_investigation", "m365_safe_attachments_enabled"],
            "github": ["github_repo_code_scanning"],
            "cloudflare": ["cloudflare_waf_managed_rules"],
        },
        "5.3.1": {
            "m365": ["m365_zero_hour_purge_enabled"],
            "google_workspace": ["gws_cis_safe_browsing_gmail"],
        },
        "6.2.1": {
            "github": ["github_repo_branch_protection", "github_repo_require_reviews",
                        "github_repo_require_status_checks"],
        },
        "6.3.1": {
            "github": ["github_repo_dependabot_security_updates",
                        "github_repo_vulnerability_alerts"],
        },
        "6.4.1": {
            "cloudflare": ["cloudflare_waf_managed_rules", "cloudflare_waf_owasp_rules"],
        },
        "7.2.1": {
            "m365": ["m365_ca_policies_configured", "m365_privileged_accounts_limited"],
            "snowflake": ["snowflake_system_defined_roles_minimal"],
            "github": ["github_org_base_permissions_none"],
            "salesforce": ["salesforce_profile_permissions_reviewed"],
        },
        "7.2.2": {
            "snowflake": ["snowflake_role_hierarchy_reviewed"],
            "servicenow": ["servicenow_role_separation"],
        },
        "8.2.1": {
            "m365": ["m365_admin_mfa_enforced", "m365_user_mfa_registered"],
            "google_workspace": ["gws_user_2fa_enrolled"],
            "snowflake": ["snowflake_user_mfa_enabled"],
            "servicenow": ["servicenow_users_mfa_enabled"],
            "salesforce": ["salesforce_user_mfa_enabled"],
        },
        "8.3.1": {
            "m365": ["m365_ca_require_mfa", "m365_user_phishing_resistant_mfa"],
            "google_workspace": ["gws_admin_2fa_enforced"],
        },
        "8.3.6": {
            "snowflake": ["snowflake_account_password_policy",
                           "snowflake_account_password_min_length"],
            "servicenow": ["servicenow_password_complexity"],
            "salesforce": ["salesforce_password_complexity"],
        },
        "8.6.1": {
            "snowflake": ["snowflake_service_account_rsa"],
            "github": ["github_ac_deploy_keys_audit"],
        },
        "10.2.1": {
            "m365": ["m365_audit_log_enabled"],
            "google_workspace": ["gws_cis_admin_audit_log_enabled"],
            "snowflake": ["snowflake_audit_logging_enabled"],
            "github": ["github_org_audit_log_streaming"],
            "salesforce": ["salesforce_setup_audit_trail"],
        },
        "10.2.2": {
            "m365": ["m365_purview_audit_premium"],
            "snowflake": ["snowflake_query_audit_enabled"],
        },
        "10.7.1": {
            "m365": ["m365_defender_alert_policies"],
            "google_workspace": ["gws_cis_alert_center_active"],
        },
        "11.4.1": {
            "m365": ["m365_defender_auto_investigation"],
            "github": ["github_repo_code_scanning", "github_repo_secret_scanning"],
            "cloudflare": ["cloudflare_waf_managed_rules"],
        },
        "11.6.1": {
            "cloudflare": ["cloudflare_waf_managed_rules"],
        },
        "12.10.1": {
            "m365": ["m365_defender_alert_policies"],
            "servicenow": ["servicenow_incident_management"],
        },
    },

    # ── SOC2 ───────────────────────────────────────────────────────────
    "SOC2": {
        "CC1.1": {
            "m365": ["m365_security_defaults_enabled"],
            "google_workspace": ["gws_cis_admin_audit_log_enabled"],
        },
        "CC1.3": {
            "m365": ["m365_privileged_accounts_limited"],
            "github": ["github_org_base_permissions_none"],
        },
        "CC2.1": {
            "m365": ["m365_audit_log_enabled"],
            "google_workspace": ["gws_cis_admin_audit_log_enabled"],
            "servicenow": ["servicenow_admin_audit_logging"],
        },
        "CC3.1": {
            "m365": ["m365_defender_alert_policies"],
            "google_workspace": ["gws_cis_alert_center_active"],
        },
        "CC3.2": {
            "github": ["github_repo_vulnerability_alerts",
                        "github_repo_dependabot_security_updates"],
        },
        "CC5.2": {
            "m365": ["m365_ca_policies_configured"],
            "snowflake": ["snowflake_system_defined_roles_minimal"],
            "github": ["github_org_base_permissions_none"],
        },
        "CC5.3": {
            "github": ["github_repo_branch_protection", "github_repo_require_reviews"],
            "servicenow": ["servicenow_change_management",
                            "servicenow_change_risk_assessment"],
        },
        "CC6.1": {
            "m365": ["m365_user_mfa_registered", "m365_ca_require_mfa",
                      "m365_ca_block_legacy_auth"],
            "google_workspace": ["gws_user_2fa_enrolled", "gws_admin_2fa_enforced"],
            "snowflake": ["snowflake_user_mfa_enabled",
                           "snowflake_account_password_policy"],
            "servicenow": ["servicenow_users_mfa_enabled"],
            "salesforce": ["salesforce_user_mfa_enabled", "salesforce_sso_enabled"],
        },
        "CC6.2": {
            "m365": ["m365_guest_expiration_configured", "m365_guest_access_restricted"],
            "snowflake": ["snowflake_user_not_inactive", "snowflake_user_password_rotation"],
            "github": ["github_ac_inactive_members_removed"],
            "salesforce": ["salesforce_user_not_stale"],
        },
        "CC6.3": {
            "m365": ["m365_privileged_accounts_limited"],
            "snowflake": ["snowflake_role_hierarchy_reviewed"],
            "servicenow": ["servicenow_role_separation"],
        },
        "CC6.6": {
            "cloudflare": ["cloudflare_waf_firewall_rules", "cloudflare_tls_full_strict"],
            "snowflake": ["snowflake_network_policy_set",
                           "snowflake_private_link_configured"],
            "openstack": ["openstack_net_sg_restrictive"],
        },
        "CC6.7": {
            "m365": ["m365_aip_encryption_enabled"],
            "snowflake": ["snowflake_stages_encrypted"],
            "servicenow": ["servicenow_encryption_at_rest"],
            "salesforce": ["salesforce_encryption_at_rest"],
            "openstack": ["openstack_storage_volume_encrypted"],
        },
        "CC6.8": {
            "m365": ["m365_defender_auto_investigation", "m365_safe_attachments_enabled"],
            "cloudflare": ["cloudflare_waf_managed_rules"],
            "github": ["github_repo_code_scanning"],
        },
        "CC7.1": {
            "m365": ["m365_defender_auto_investigation", "m365_defender_alert_policies"],
            "google_workspace": ["gws_cis_alert_center_active"],
            "github": ["github_repo_vulnerability_alerts"],
            "cloudflare": ["cloudflare_bot_management"],
        },
        "CC7.2": {
            "m365": ["m365_audit_log_enabled", "m365_purview_audit_premium"],
            "google_workspace": ["gws_cis_login_activity_monitored"],
            "snowflake": ["snowflake_audit_logging_enabled"],
            "salesforce": ["salesforce_event_monitoring"],
        },
        "CC7.3": {
            "m365": ["m365_defender_alert_policies"],
            "servicenow": ["servicenow_incident_management"],
        },
        "CC7.4": {
            "servicenow": ["servicenow_incident_management"],
        },
        "CC8.1": {
            "github": ["github_repo_branch_protection", "github_repo_require_reviews",
                        "github_repo_require_status_checks"],
            "servicenow": ["servicenow_change_management"],
        },
        "A1.1": {
            "snowflake": ["snowflake_failover_configured"],
            "openstack": ["openstack_storage_backup_policies"],
        },
        "A1.2": {
            "snowflake": ["snowflake_data_retention_configured"],
        },
        "C1.1": {
            "m365": ["m365_aip_encryption_enabled", "m365_sensitivity_labels_enabled"],
            "snowflake": ["snowflake_stages_encrypted", "snowflake_column_masking_policies"],
            "salesforce": ["salesforce_encryption_at_rest"],
        },
        "C1.2": {
            "cloudflare": ["cloudflare_tls_full_strict", "cloudflare_tls_min_version"],
            "servicenow": ["servicenow_tls_enforced"],
        },
        "P1.1": {
            "m365": ["m365_dlp_policies_configured", "m365_sensitivity_labels_enabled"],
            "snowflake": ["snowflake_data_classification_enabled"],
            "salesforce": ["salesforce_field_level_security"],
        },
        "P3.1": {
            "m365": ["m365_dlp_policies_configured"],
            "snowflake": ["snowflake_column_masking_policies",
                           "snowflake_row_access_policies"],
        },
    },

    # ── GDPR (supplement existing minimal SaaS mappings) ───────────────
    "GDPR": {
        "Art.5(1)(a)": {
            "m365": ["m365_audit_log_enabled"],
            "google_workspace": ["gws_cis_admin_audit_log_enabled"],
            "salesforce": ["salesforce_setup_audit_trail"],
        },
        "Art.5(1)(b)": {
            "m365": ["m365_ca_policies_configured"],
            "snowflake": ["snowflake_row_access_policies"],
            "salesforce": ["salesforce_profile_permissions_reviewed"],
        },
        "Art.5(1)(c)": {
            "m365": ["m365_dlp_policies_configured"],
            "snowflake": ["snowflake_column_masking_policies",
                           "snowflake_data_classification_enabled"],
            "salesforce": ["salesforce_field_level_security"],
        },
        "Art.5(1)(f)": {
            "m365": ["m365_aip_encryption_enabled", "m365_user_mfa_registered"],
            "google_workspace": ["gws_user_2fa_enrolled"],
            "servicenow": ["servicenow_encryption_at_rest", "servicenow_users_mfa_enabled"],
        },
        "Art.25(1)": {
            "m365": ["m365_sensitivity_labels_enabled", "m365_dlp_policies_configured"],
            "snowflake": ["snowflake_column_masking_policies"],
        },
        "Art.30": {
            "m365": ["m365_audit_log_enabled", "m365_purview_audit_premium"],
            "google_workspace": ["gws_cis_admin_audit_log_enabled"],
            "snowflake": ["snowflake_audit_logging_enabled"],
        },
        "Art.32(1)(a)": {
            "servicenow": ["servicenow_encryption_at_rest"],
            "salesforce": ["salesforce_encryption_at_rest"],
            "openstack": ["openstack_storage_volume_encrypted"],
        },
        "Art.32(1)(b)": {
            "m365": ["m365_ca_require_mfa"],
            "google_workspace": ["gws_admin_2fa_enforced"],
            "servicenow": ["servicenow_users_mfa_enabled"],
        },
        "Art.33(1)": {
            "m365": ["m365_defender_alert_policies"],
            "google_workspace": ["gws_cis_alert_center_active"],
            "servicenow": ["servicenow_incident_management"],
        },
        "Art.35": {
            "google_workspace": ["gws_cis_security_investigation_tool"],
            "github": ["github_repo_vulnerability_alerts"],
        },
    },
}


def apply_saas_enrichment(frameworks: dict) -> int:
    """Merge SaaS mappings into loaded frameworks. Returns count of enriched controls."""
    enriched = 0
    for fw_key, control_mappings in SAAS_MAPPINGS.items():
        if fw_key not in frameworks:
            continue
        controls = frameworks[fw_key].get("controls", [])
        ctrl_index = {c["id"]: c for c in controls}

        for ctrl_id, provider_checks in control_mappings.items():
            ctrl = ctrl_index.get(ctrl_id)
            if ctrl is None:
                continue
            checks = ctrl.setdefault("checks", {})
            modified = False
            for provider, check_ids in provider_checks.items():
                existing = set(checks.get(provider, []))
                new_ids = [cid for cid in check_ids if cid not in existing]
                if new_ids:
                    checks.setdefault(provider, []).extend(new_ids)
                    modified = True
            if modified:
                enriched += 1

    return enriched
