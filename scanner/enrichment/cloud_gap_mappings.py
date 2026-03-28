"""OCI and Alibaba Cloud check_id mappings for compliance frameworks.

Fills the cloud provider gap: ENS, HIPAA, PCI-DSS, and SOC2 currently
only have AWS/Azure/GCP checks. This module adds OCI and Alibaba mappings.
"""

# Structure: { framework_key: { control_id: { provider: [check_ids] } } }
CLOUD_GAP_MAPPINGS: dict[str, dict[str, dict[str, list[str]]]] = {
    # ── ENS ────────────────────────────────────────────────────────────
    "ENS": {
        "org.1": {
            "oci": ["oci_cloud_guard_enabled"],
            "alibaba": ["ali_security_center_enabled"],
        },
        "org.3": {
            "oci": ["oci_logging_audit_retention"],
            "alibaba": ["alibaba_logging_actiontrail_enabled"],
        },
        "org.4": {
            "oci": ["oci_iam_policy_no_wildcard"],
            "alibaba": ["alibaba_iam_ram_no_wildcard_policy"],
        },
        "op.pl.1": {
            "oci": ["oci_cloud_guard_enabled", "oci_events_rule_configured"],
            "alibaba": ["ali_security_center_enabled", "ali_sas_advanced_edition"],
        },
        "op.acc.1": {
            "oci": ["oci_iam_user_mfa_enabled"],
            "alibaba": ["alibaba_iam_ram_user_mfa_enabled"],
        },
        "op.acc.2": {
            "oci": ["oci_iam_policy_no_wildcard"],
            "alibaba": ["alibaba_iam_ram_no_wildcard_policy"],
        },
        "op.acc.3": {
            "oci": ["oci_iam_policy_no_wildcard"],
        },
        "op.acc.4": {
            "oci": ["oci_iam_api_key_rotation", "oci_iam_auth_token_rotation"],
        },
        "op.acc.5": {
            "oci": ["oci_iam_user_mfa_enabled", "oci_iam_admin_mfa_enabled"],
            "alibaba": ["alibaba_iam_ram_root_mfa_enabled", "alibaba_iam_ram_user_mfa_enabled"],
        },
        "op.acc.6": {
            "oci": ["oci_iam_admin_mfa_enabled"],
            "alibaba": ["alibaba_iam_ram_root_mfa_enabled"],
        },
        "op.exp.1": {
            "oci": ["oci_logging_log_groups_exist"],
            "alibaba": ["alibaba_logging_sls_audit_enabled"],
        },
        "op.exp.3": {
            "oci": ["oci_cloud_guard_enabled"],
        },
        "op.exp.6": {
            "oci": ["oci_cloud_guard_enabled"],
            "alibaba": ["ali_security_center_enabled"],
        },
        "op.exp.7": {
            "oci": ["oci_events_rule_configured", "oci_notifications_topic_configured"],
            "alibaba": ["ali_security_center_enabled"],
        },
        "op.exp.8": {
            "oci": ["oci_logging_audit_retention", "oci_logging_log_groups_exist"],
            "alibaba": ["alibaba_logging_actiontrail_enabled"],
        },
        "op.exp.10": {
            "oci": ["oci_logging_audit_retention"],
            "alibaba": ["alibaba_logging_actiontrail_enabled"],
        },
        "op.mon.1": {
            "oci": ["oci_cloud_guard_enabled", "oci_events_rule_configured"],
            "alibaba": ["ali_security_center_enabled", "ali_sas_advanced_edition"],
        },
        "op.mon.2": {
            "oci": ["oci_cloud_guard_enabled"],
            "alibaba": ["ali_security_center_enabled"],
        },
        "op.mon.3": {
            "oci": ["oci_logging_audit_retention"],
            "alibaba": ["alibaba_logging_actiontrail_enabled"],
        },
        "mp.info.1": {
            "oci": ["oci_objectstorage_bucket_cmk_encryption"],
            "alibaba": ["alibaba_storage_oss_encryption_enabled"],
        },
        "mp.info.3": {
            "oci": ["oci_objectstorage_bucket_cmk_encryption", "oci_vault_key_rotation",
                     "oci_filestorage_cmk_encryption"],
            "alibaba": ["alibaba_storage_oss_encryption_enabled",
                         "alibaba_kms_key_rotation_enabled"],
        },
        "mp.info.4": {
            "oci": ["oci_vault_key_rotation"],
            "alibaba": ["alibaba_kms_key_rotation_enabled"],
        },
        "mp.info.7": {
            "oci": ["oci_db_autonomous_private_endpoint"],
            "alibaba": ["alibaba_database_rds_backup_enabled"],
        },
        "mp.s.2": {
            "alibaba": ["ali_waf_enabled", "ali_waf_domains_configured"],
        },
        "mp.s.3": {
            "alibaba": ["ali_waf_enabled"],
        },
        "mp.com.2": {
            "oci": ["oci_compute_boot_volume_transit_encryption"],
            "alibaba": ["alibaba_apigateway_https_enforcement"],
        },
        "mp.com.3": {
            "oci": ["oci_compute_boot_volume_transit_encryption"],
        },
        "mp.si.2": {
            "oci": ["oci_storage_volume_cmk_encryption", "oci_objectstorage_bucket_cmk_encryption"],
            "alibaba": ["alibaba_storage_oss_encryption_enabled"],
        },
    },

    # ── HIPAA ──────────────────────────────────────────────────────────
    "HIPAA": {
        "164.308(a)(1)(i)": {
            "oci": ["oci_cloud_guard_enabled", "oci_events_rule_configured"],
            "alibaba": ["ali_security_center_enabled"],
        },
        "164.308(a)(1)(ii)(A)": {
            "oci": ["oci_cloud_guard_enabled"],
            "alibaba": ["ali_security_center_enabled", "ali_sas_advanced_edition"],
        },
        "164.308(a)(1)(ii)(D)": {
            "oci": ["oci_logging_audit_retention", "oci_logging_log_groups_exist"],
            "alibaba": ["alibaba_logging_actiontrail_enabled"],
        },
        "164.308(a)(3)(i)": {
            "oci": ["oci_iam_policy_no_wildcard"],
            "alibaba": ["alibaba_iam_ram_no_wildcard_policy"],
        },
        "164.308(a)(3)(ii)(A)": {
            "oci": ["oci_iam_policy_no_wildcard"],
        },
        "164.308(a)(4)(i)": {
            "oci": ["oci_iam_policy_no_wildcard"],
            "alibaba": ["alibaba_iam_ram_no_wildcard_policy"],
        },
        "164.308(a)(5)(i)": {
            "oci": ["oci_iam_user_mfa_enabled"],
            "alibaba": ["alibaba_iam_ram_user_mfa_enabled"],
        },
        "164.308(a)(5)(ii)(D)": {
            "oci": ["oci_iam_api_key_rotation", "oci_iam_secret_key_rotation"],
        },
        "164.308(a)(6)(i)": {
            "oci": ["oci_events_rule_configured", "oci_notifications_topic_configured"],
            "alibaba": ["ali_security_center_enabled"],
        },
        "164.308(a)(6)(ii)": {
            "oci": ["oci_notifications_security_topic_exists"],
        },
        "164.308(a)(7)(i)": {
            "oci": ["oci_db_autonomous_private_endpoint"],
            "alibaba": ["alibaba_database_rds_backup_enabled"],
        },
        "164.308(a)(7)(ii)(A)": {
            "alibaba": ["alibaba_database_rds_backup_enabled"],
        },
        "164.312(a)(1)": {
            "oci": ["oci_iam_user_mfa_enabled", "oci_iam_admin_mfa_enabled"],
            "alibaba": ["alibaba_iam_ram_root_mfa_enabled", "alibaba_iam_ram_user_mfa_enabled"],
        },
        "164.312(a)(2)(i)": {
            "oci": ["oci_iam_policy_no_wildcard"],
            "alibaba": ["alibaba_iam_ram_no_wildcard_policy"],
        },
        "164.312(a)(2)(iv)": {
            "oci": ["oci_objectstorage_bucket_cmk_encryption", "oci_vault_key_rotation"],
            "alibaba": ["alibaba_storage_oss_encryption_enabled",
                         "alibaba_kms_key_rotation_enabled"],
        },
        "164.312(b)": {
            "oci": ["oci_logging_audit_retention", "oci_logging_log_groups_exist"],
            "alibaba": ["alibaba_logging_actiontrail_enabled",
                         "alibaba_logging_sls_audit_enabled"],
        },
        "164.312(c)(1)": {
            "oci": ["oci_objectstorage_bucket_cmk_encryption"],
            "alibaba": ["alibaba_storage_oss_encryption_enabled"],
        },
        "164.312(d)": {
            "oci": ["oci_iam_admin_mfa_enabled", "oci_iam_user_mfa_enabled"],
            "alibaba": ["alibaba_iam_ram_root_mfa_enabled"],
        },
        "164.312(e)(1)": {
            "oci": ["oci_network_vcn_flow_logs"],
        },
        "164.312(e)(2)(i)": {
            "oci": ["oci_compute_boot_volume_transit_encryption"],
            "alibaba": ["alibaba_apigateway_https_enforcement"],
        },
        "164.312(e)(2)(ii)": {
            "oci": ["oci_objectstorage_bucket_cmk_encryption",
                     "oci_filestorage_cmk_encryption"],
            "alibaba": ["alibaba_storage_oss_encryption_enabled",
                         "alibaba_database_rds_encryption_enabled"],
        },
        "164.310(a)(1)": {
            "oci": ["oci_compute_secure_boot"],
        },
        "164.310(d)(1)": {
            "oci": ["oci_storage_volume_cmk_encryption"],
            "alibaba": ["alibaba_storage_oss_encryption_enabled"],
        },
        "164.316(b)(1)": {
            "oci": ["oci_logging_audit_retention"],
            "alibaba": ["alibaba_logging_actiontrail_enabled"],
        },
    },

    # ── PCI-DSS-v4.0 ──────────────────────────────────────────────────
    "PCI-DSS-v4.0": {
        "1.2.1": {
            "oci": ["oci_network_vcn_flow_logs"],
        },
        "1.3.1": {
            "oci": ["oci_network_vcn_flow_logs"],
        },
        "3.4.1": {
            "oci": ["oci_objectstorage_bucket_cmk_encryption",
                     "oci_storage_volume_cmk_encryption"],
            "alibaba": ["alibaba_storage_oss_encryption_enabled",
                         "alibaba_database_rds_encryption_enabled"],
        },
        "3.5.1": {
            "oci": ["oci_vault_key_rotation"],
            "alibaba": ["alibaba_kms_key_rotation_enabled",
                         "alibaba_kms_key_deletion_protection"],
        },
        "3.6.1": {
            "oci": ["oci_vault_key_rotation"],
            "alibaba": ["alibaba_kms_key_rotation_enabled"],
        },
        "4.2.1": {
            "oci": ["oci_compute_boot_volume_transit_encryption"],
            "alibaba": ["alibaba_apigateway_https_enforcement"],
        },
        "5.2.1": {
            "oci": ["oci_cloud_guard_enabled"],
            "alibaba": ["ali_security_center_enabled"],
        },
        "6.4.1": {
            "alibaba": ["ali_waf_enabled", "ali_waf_domains_configured"],
        },
        "7.2.1": {
            "oci": ["oci_iam_policy_no_wildcard"],
            "alibaba": ["alibaba_iam_ram_no_wildcard_policy"],
        },
        "7.2.2": {
            "oci": ["oci_iam_policy_no_wildcard"],
        },
        "8.2.1": {
            "oci": ["oci_iam_user_mfa_enabled"],
            "alibaba": ["alibaba_iam_ram_user_mfa_enabled"],
        },
        "8.3.1": {
            "oci": ["oci_iam_user_mfa_enabled", "oci_iam_admin_mfa_enabled"],
            "alibaba": ["alibaba_iam_ram_root_mfa_enabled",
                         "alibaba_iam_ram_user_mfa_enabled"],
        },
        "8.3.6": {
            "oci": ["oci_iam_api_key_rotation", "oci_iam_auth_token_rotation"],
        },
        "8.6.1": {
            "oci": ["oci_iam_api_key_rotation", "oci_iam_secret_key_rotation"],
        },
        "10.2.1": {
            "oci": ["oci_logging_audit_retention", "oci_logging_log_groups_exist"],
            "alibaba": ["alibaba_logging_actiontrail_enabled"],
        },
        "10.2.2": {
            "oci": ["oci_logging_log_groups_exist"],
            "alibaba": ["alibaba_logging_sls_audit_enabled"],
        },
        "10.3.1": {
            "oci": ["oci_logging_audit_retention"],
            "alibaba": ["alibaba_logging_actiontrail_enabled"],
        },
        "10.5.1": {
            "oci": ["oci_logging_audit_retention"],
        },
        "10.7.1": {
            "oci": ["oci_events_rule_configured", "oci_notifications_topic_configured"],
            "alibaba": ["ali_security_center_enabled"],
        },
        "11.4.1": {
            "oci": ["oci_cloud_guard_enabled"],
            "alibaba": ["ali_security_center_enabled", "ali_sas_advanced_edition"],
        },
        "11.5.1": {
            "oci": ["oci_cloud_guard_enabled"],
        },
        "12.10.1": {
            "oci": ["oci_notifications_security_topic_exists",
                     "oci_events_rule_configured"],
            "alibaba": ["ali_security_center_enabled"],
        },
    },

    # ── SOC2 ───────────────────────────────────────────────────────────
    "SOC2": {
        "CC1.1": {
            "oci": ["oci_cloud_guard_enabled"],
        },
        "CC1.2": {
            "oci": ["oci_logging_audit_retention"],
            "alibaba": ["alibaba_logging_actiontrail_enabled"],
        },
        "CC3.1": {
            "oci": ["oci_cloud_guard_enabled"],
            "alibaba": ["ali_security_center_enabled"],
        },
        "CC3.2": {
            "oci": ["oci_cloud_guard_enabled", "oci_events_rule_configured"],
            "alibaba": ["ali_security_center_enabled", "ali_sas_advanced_edition"],
        },
        "CC5.2": {
            "oci": ["oci_iam_policy_no_wildcard"],
            "alibaba": ["alibaba_iam_ram_no_wildcard_policy"],
        },
        "CC6.1": {
            "oci": ["oci_iam_user_mfa_enabled", "oci_iam_admin_mfa_enabled",
                     "oci_iam_policy_no_wildcard"],
            "alibaba": ["alibaba_iam_ram_root_mfa_enabled",
                         "alibaba_iam_ram_user_mfa_enabled"],
        },
        "CC6.2": {
            "oci": ["oci_iam_api_key_rotation", "oci_iam_auth_token_rotation"],
        },
        "CC6.3": {
            "oci": ["oci_iam_policy_no_wildcard"],
            "alibaba": ["alibaba_iam_ram_no_wildcard_policy"],
        },
        "CC6.6": {
            "oci": ["oci_network_vcn_flow_logs"],
            "alibaba": ["alibaba_apigateway_https_enforcement"],
        },
        "CC6.7": {
            "oci": ["oci_objectstorage_bucket_cmk_encryption",
                     "oci_compute_boot_volume_transit_encryption"],
            "alibaba": ["alibaba_storage_oss_encryption_enabled",
                         "alibaba_kms_key_rotation_enabled"],
        },
        "CC6.8": {
            "oci": ["oci_cloud_guard_enabled"],
            "alibaba": ["ali_security_center_enabled"],
        },
        "CC7.1": {
            "oci": ["oci_cloud_guard_enabled", "oci_events_rule_configured"],
            "alibaba": ["ali_security_center_enabled"],
        },
        "CC7.2": {
            "oci": ["oci_logging_audit_retention", "oci_logging_log_groups_exist"],
            "alibaba": ["alibaba_logging_actiontrail_enabled",
                         "alibaba_logging_sls_audit_enabled"],
        },
        "CC7.3": {
            "oci": ["oci_notifications_topic_configured",
                     "oci_notifications_security_topic_exists"],
            "alibaba": ["ali_security_center_enabled"],
        },
        "CC7.4": {
            "oci": ["oci_events_rule_configured"],
        },
        "CC8.1": {
            "oci": ["oci_compute_secure_boot"],
        },
        "CC9.1": {
            "oci": ["oci_cloud_guard_enabled"],
            "alibaba": ["ali_waf_enabled"],
        },
        "A1.1": {
            "alibaba": ["alibaba_database_rds_backup_enabled"],
        },
        "A1.2": {
            "oci": ["oci_db_autonomous_private_endpoint"],
            "alibaba": ["alibaba_database_rds_backup_enabled"],
        },
        "C1.1": {
            "oci": ["oci_objectstorage_bucket_cmk_encryption",
                     "oci_filestorage_cmk_encryption", "oci_vault_key_rotation"],
            "alibaba": ["alibaba_storage_oss_encryption_enabled",
                         "alibaba_kms_key_rotation_enabled"],
        },
        "C1.2": {
            "oci": ["oci_compute_boot_volume_transit_encryption"],
            "alibaba": ["alibaba_apigateway_https_enforcement"],
        },
        "P1.1": {
            "oci": ["oci_objectstorage_bucket_cmk_encryption"],
            "alibaba": ["alibaba_storage_oss_encryption_enabled"],
        },
    },
}


def apply_cloud_gap_enrichment(frameworks: dict) -> int:
    """Merge OCI/Alibaba mappings into loaded frameworks. Returns count of enriched controls."""
    enriched = 0
    for fw_key, control_mappings in CLOUD_GAP_MAPPINGS.items():
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
