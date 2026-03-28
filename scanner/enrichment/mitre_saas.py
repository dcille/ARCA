"""MITRE ATT&CK mappings for SaaS provider scanner checks.

Extends the core CHECK_TO_MITRE in attack_mapping.py with mappings
for M365, Google Workspace, Snowflake, GitHub, Cloudflare, ServiceNow,
Salesforce, and OpenStack scanner checks.
"""

# Maps scanner check_id -> list of MITRE ATT&CK technique IDs
SAAS_CHECK_TO_MITRE: dict[str, list[str]] = {
    # ── M365 ─────────────────────────────────────────────────────────────
    "m365_admin_mfa_enforced": ["T1078", "T1110", "T1078.004"],
    "m365_ca_block_legacy_auth": ["T1078", "T1110", "T1556"],
    "m365_ca_require_mfa": ["T1078", "T1110", "T1078.004"],
    "m365_dlp_policies_configured": ["T1567", "T1530", "T1537"],
    "m365_safe_attachments_enabled": ["T1566", "T1204"],
    "m365_safe_links_enabled": ["T1566", "T1204"],
    "m365_dkim_configured": ["T1566", "T1586"],
    "m365_dmarc_configured": ["T1566", "T1586"],
    "m365_audit_log_enabled": ["T1562", "T1070"],
    "m365_defender_auto_investigation": ["T1566", "T1190"],
    "m365_zero_hour_purge_enabled": ["T1566", "T1114"],
    "m365_anti_phishing_policy": ["T1566", "T1528"],
    "m365_external_sharing_restricted": ["T1530", "T1537", "T1567"],
    "m365_sensitivity_labels_enabled": ["T1530", "T1567"],
    "m365_oauth_app_restrictions": ["T1528", "T1199", "T1098"],
    "m365_guest_access_restricted": ["T1078", "T1199"],
    "m365_privileged_accounts_limited": ["T1078", "T1098", "T1136"],
    "m365_security_defaults_enabled": ["T1078", "T1110", "T1556"],
    "m365_legacy_auth_blocked": ["T1078", "T1110", "T1556"],
    "m365_teams_external_access_restricted": ["T1199", "T1567", "T1530"],

    # ── Google Workspace ─────────────────────────────────────────────────
    "gws_admin_mfa_enforced": ["T1078", "T1110", "T1078.004"],
    "gws_admin_2fa_enforced": ["T1078", "T1110", "T1078.004"],
    "gws_less_secure_apps_disabled": ["T1078", "T1110", "T1556"],
    "gws_email_dmarc_configured": ["T1566", "T1586"],
    "gws_email_spf_configured": ["T1566", "T1586"],
    "gws_email_dkim_configured": ["T1566", "T1586"],
    "gws_drive_external_sharing_restricted": ["T1530", "T1537", "T1567"],
    "gws_cis_auto_forwarding_disabled": ["T1114", "T1567", "T1537"],
    "gws_cis_alert_center_active": ["T1562", "T1070"],
    "gws_password_policy_strength": ["T1110", "T1078"],
    "gws_sso_configured": ["T1556", "T1199", "T1078"],
    "gws_cis_marketplace_apps_restricted": ["T1528", "T1199", "T1098"],
    "gws_cis_chrome_management_enabled": ["T1190", "T1204"],
    "gws_cis_device_encryption_required": ["T1530", "T1485"],
    "gws_admin_audit_logging_enabled": ["T1562", "T1070"],
    "gws_dlp_policies_configured": ["T1567", "T1530", "T1537"],
    "gws_session_timeout_configured": ["T1539", "T1528"],
    "gws_oauth_app_whitelist_enabled": ["T1528", "T1199"],
    "gws_security_sandbox_enabled": ["T1566", "T1204"],
    "gws_context_aware_access_enabled": ["T1078", "T1199"],

    # ── Snowflake ────────────────────────────────────────────────────────
    "snowflake_user_mfa_enabled": ["T1078", "T1110", "T1078.004"],
    "snowflake_network_policy_set": ["T1190", "T1595"],
    "snowflake_audit_logging_enabled": ["T1562", "T1070"],
    "snowflake_column_masking_policies": ["T1530", "T1567"],
    "snowflake_row_access_policies": ["T1530", "T1078"],
    "snowflake_account_password_policy": ["T1110", "T1078"],
    "snowflake_stages_encrypted": ["T1530", "T1537"],
    "snowflake_private_link_configured": ["T1190", "T1557"],
    "snowflake_account_session_timeout": ["T1539", "T1528"],
    "snowflake_service_account_rsa": ["T1078", "T1552", "T1528"],
    "snowflake_data_retention_set": ["T1485", "T1070"],
    "snowflake_ip_whitelist_configured": ["T1190", "T1595"],
    "snowflake_query_tag_required": ["T1562", "T1070"],
    "snowflake_admin_accounts_limited": ["T1078", "T1098", "T1136"],
    "snowflake_external_functions_restricted": ["T1199", "T1059"],

    # ── GitHub ───────────────────────────────────────────────────────────
    "github_org_2fa_required": ["T1078", "T1110", "T1078.004"],
    "github_org_saml_enforced": ["T1556", "T1078", "T1199"],
    "github_repo_branch_protection": ["T1195", "T1098"],
    "github_repo_secret_scanning": ["T1552", "T1528"],
    "github_repo_code_scanning": ["T1190", "T1195"],
    "github_actions_restricted": ["T1059", "T1195", "T1199"],
    "github_org_audit_log_streaming": ["T1562", "T1070"],
    "github_repo_dependabot_security_updates": ["T1195", "T1190"],
    "github_ac_webhook_secrets_configured": ["T1528", "T1199"],
    "github_repo_signed_commits": ["T1195", "T1098"],
    "github_org_ip_allow_list": ["T1190", "T1595"],
    "github_org_member_privileges_restricted": ["T1078", "T1098", "T1136"],
    "github_repo_deploy_key_readonly": ["T1528", "T1552"],
    "github_org_sso_enforced": ["T1556", "T1078"],
    "github_actions_secrets_encrypted": ["T1552", "T1528"],
    "github_repo_vulnerability_alerts": ["T1190", "T1195"],

    # ── Cloudflare ───────────────────────────────────────────────────────
    "cloudflare_tls_full_strict": ["T1557", "T1190"],
    "cloudflare_tls_min_version": ["T1557", "T1190"],
    "cloudflare_dns_dnssec_enabled": ["T1557", "T1584"],
    "cloudflare_waf_managed_rules": ["T1190", "T1595"],
    "cloudflare_waf_rate_limiting": ["T1498", "T1110", "T1595"],
    "cloudflare_ac_2fa_enabled": ["T1078", "T1110"],
    "cloudflare_zt_access_app_configured": ["T1078", "T1199", "T1190"],
    "cloudflare_zt_dlp_configured": ["T1567", "T1530", "T1537"],
    "cloudflare_bot_management": ["T1595", "T1498", "T1110"],
    "cloudflare_page_shield_enabled": ["T1190", "T1059"],
    "cloudflare_api_shield_configured": ["T1190", "T1528"],
    "cloudflare_audit_logs_enabled": ["T1562", "T1070"],
    "cloudflare_access_service_tokens_rotated": ["T1528", "T1078"],
    "cloudflare_ssl_recommendation_enabled": ["T1557", "T1190"],
    "cloudflare_ip_access_rules_configured": ["T1190", "T1595"],

    # ── ServiceNow ───────────────────────────────────────────────────────
    "servicenow_users_mfa_enabled": ["T1078", "T1110", "T1078.004"],
    "servicenow_sso_configured": ["T1556", "T1078", "T1199"],
    "servicenow_encryption_at_rest": ["T1530", "T1485"],
    "servicenow_session_timeout": ["T1539", "T1528"],
    "servicenow_admin_audit_logging": ["T1562", "T1070"],
    "servicenow_change_management": ["T1098", "T1562"],
    "servicenow_acl_rules_configured": ["T1078", "T1530"],
    "servicenow_tls_enforced": ["T1557", "T1190"],
    "servicenow_ip_address_restrictions": ["T1190", "T1595"],
    "servicenow_password_policy_strong": ["T1110", "T1078"],
    "servicenow_privileged_access_limited": ["T1078", "T1098", "T1136"],
    "servicenow_data_classification_enabled": ["T1530", "T1567"],
    "servicenow_instance_hardening": ["T1190", "T1595"],
    "servicenow_api_key_rotation": ["T1528", "T1552"],
    "servicenow_integration_user_restricted": ["T1199", "T1078"],

    # ── Salesforce ───────────────────────────────────────────────────────
    "salesforce_user_mfa_enabled": ["T1078", "T1110", "T1078.004"],
    "salesforce_sso_enabled": ["T1556", "T1078", "T1199"],
    "salesforce_encryption_at_rest": ["T1530", "T1485"],
    "salesforce_session_timeout": ["T1539", "T1528"],
    "salesforce_setup_audit_trail": ["T1562", "T1070"],
    "salesforce_field_level_security": ["T1530", "T1078"],
    "salesforce_ip_ranges_restricted": ["T1190", "T1595"],
    "salesforce_tls_enforced": ["T1557", "T1190"],
    "salesforce_transaction_security_active": ["T1567", "T1530", "T1537"],
    "salesforce_login_forensics_enabled": ["T1562", "T1070", "T1078"],
    "salesforce_connected_app_policies": ["T1528", "T1199"],
    "salesforce_api_access_restricted": ["T1190", "T1528"],
    "salesforce_password_policy_strong": ["T1110", "T1078"],
    "salesforce_sharing_rules_reviewed": ["T1530", "T1537"],
    "salesforce_named_credentials_used": ["T1552", "T1528"],
    "salesforce_event_monitoring_enabled": ["T1562", "T1070"],

    # ── OpenStack ────────────────────────────────────────────────────────
    "openstack_identity_admin_mfa": ["T1078", "T1110", "T1078.004"],
    "openstack_identity_token_expiration": ["T1539", "T1528"],
    "openstack_storage_volume_encrypted": ["T1530", "T1485"],
    "openstack_network_sg_no_ssh_open": ["T1190", "T1595"],
    "openstack_api_tls_v12_minimum": ["T1557", "T1190"],
    "openstack_identity_rbac_policies": ["T1078", "T1098"],
    "openstack_api_audit_logging": ["T1562", "T1070"],
    "openstack_keystone_password_policy": ["T1110", "T1078"],
    "openstack_barbican_secrets_managed": ["T1552", "T1528"],
    "openstack_neutron_port_security": ["T1190", "T1557"],
    "openstack_nova_metadata_restricted": ["T1552", "T1078"],
    "openstack_cinder_backup_enabled": ["T1485", "T1486"],
    "openstack_swift_acl_restricted": ["T1530", "T1537"],
    "openstack_admin_project_isolated": ["T1078", "T1098", "T1136"],
    "openstack_service_endpoints_internal": ["T1190", "T1595"],
}


def get_merged_mitre_map() -> dict[str, list[str]]:
    """Return merged CHECK_TO_MITRE + SAAS_CHECK_TO_MITRE."""
    from scanner.mitre.attack_mapping import CHECK_TO_MITRE

    merged = dict(CHECK_TO_MITRE)
    merged.update(SAAS_CHECK_TO_MITRE)
    return merged
