"""Ransomware Readiness Evaluator.

Orchestrates the evaluation of existing CSPM findings against the RR framework.
Consumes findings from the CSPM database and produces CheckEvaluations
that feed into the scoring engine.
"""

from __future__ import annotations

from scanner.ransomware_readiness.framework import (
    Domain, Severity, RRRule,
    get_all_rules, build_check_id_to_rules_map,
)
from scanner.ransomware_readiness.scoring import CheckEvaluation


# Maps rule check_ids to actual scanner check_ids where names differ.
# Format: rule_check_id -> list of scanner_check_ids that satisfy the rule.
CHECK_ID_ALIASES: dict[str, list[str]] = {
    # ── AWS IAM ──
    "iam_access_keys_rotated_90_days": ["iam_access_key_rotation"],
    "iam_no_active_access_keys_root": ["iam_no_root_access_key"],
    "iam_policy_no_admin_access": ["iam_no_star_policies"],
    "iam_password_policy_min_length_14": ["iam_password_policy_strong"],
    "iam_password_policy_symbol": ["iam_password_policy_strong"],
    "iam_password_policy_uppercase": ["iam_password_policy_strong"],
    "iam_password_policy_lowercase": ["iam_password_policy_strong"],
    "iam_password_policy_number": ["iam_password_policy_strong"],
    "iam_unused_credentials_disabled": ["iam_user_unused_credentials_45days"],
    "iam_credential_report_no_anomalies": ["iam_user_unused_credentials_45days"],
    "iam_no_inline_policies": ["iam_user_no_inline_policies", "iam_group_no_inline_policies"],
    "iam_user_no_direct_policies": ["iam_user_no_attached_policies"],
    "iam_support_role_configured": ["iam_support_role_created"],
    "iam_role_no_admin_policy": ["iam_no_star_policies"],
    # ── AWS EC2 / Network ──
    "ec2_sg_no_public_ssh": ["ec2_sg_open_port_22"],
    "ec2_sg_no_public_rdp": ["ec2_sg_open_port_3389"],
    "ec2_sg_no_public_smb": ["ec2_sg_open_port_445"],
    "ec2_sg_no_allow_all_ingress": ["ec2_sg_no_wide_open_ports"],
    "ec2_sg_no_allow_all_egress": ["ec2_sg_no_wide_open_ports"],
    "ec2_ebs_encryption_enabled": ["ec2_ebs_volume_encrypted"],
    "ec2_instance_backup_enabled": ["backup_plan_exists"],
    # ── AWS RDS ──
    "rds_encryption_at_rest": ["rds_encryption_enabled"],
    "rds_automated_backups_enabled": ["rds_backup_enabled"],
    "rds_backup_retention_adequate": ["rds_backup_enabled"],
    "rds_no_public_access": ["rds_public_access_disabled"],
    "rds_snapshot_encrypted": ["rds_encryption_enabled"],
    # ── AWS S3 ──
    "s3_bucket_no_public_access": ["s3_bucket_public_access_blocked"],
    "s3_account_level_public_access_block": ["s3_bucket_public_access_blocked"],
    "s3_bucket_object_lock_enabled": ["s3_bucket_object_lock"],
    # ── AWS Secrets / KMS ──
    "secretsmanager_secrets_rotated": ["secretsmanager_rotation_enabled"],
    # ── AWS ELB ──
    "elb_https_listener": ["cloudfront_https_only"],
    "elb_tls_12_minimum": ["cloudfront_https_only"],
    # ── AWS Backup ──
    "backup_monitoring_alerts": ["backup_plan_exists"],
    "backup_vault_deletion_protection": ["backup_vault_encrypted"],
    # ── Azure (with azure_ prefix in scanner) ──
    "iam_mfa_enabled_all_users": ["azure_iam_mfa_enabled_all_users"],
    "iam_global_admin_mfa": ["azure_entra_global_admin_count", "azure_iam_mfa_enabled_all_users"],
    "iam_no_owner_role_all_resources": ["azure_iam_owner_count", "azure_iam_no_custom_owner_roles"],
    "iam_custom_role_least_privilege": ["azure_iam_no_custom_owner_roles"],
    "iam_service_principal_least_privilege": ["azure_iam_sp_high_privilege"],
    "iam_conditional_access_session_controls": ["azure_pim_jit_access"],
    "iam_cross_tenant_access_restricted": ["azure_entra_guest_access_restricted"],
    "iam_azure_policy_assignments": ["azure_policy_assignments_exist"],
    "iam_federation_hardened": ["azure_entra_admin_center_restricted"],
    "iam_conditional_access_policies_enabled": ["azure_pim_jit_access"],
    "iam_pim_enabled_for_admins": ["azure_pim_jit_access"],
    "iam_unused_role_assignments": ["azure_iam_guest_users_reviewed"],
    "iam_inactive_users_disabled": ["azure_iam_guest_users_reviewed"],
    "iam_emergency_access_accounts": ["azure_entra_global_admin_count"],
    "iam_password_policy_configured": ["azure_entra_custom_banned_passwords"],
    "iam_group_based_assignment": ["azure_iam_managed_identity_usage"],
    "iam_customer_lockbox_enabled": ["azure_security_contact_configured"],
    "iam_security_contact_email": ["azure_security_contact_configured"],
    "network_nsg_no_public_ssh": ["azure_nsg_unrestricted_port_22"],
    "network_nsg_no_public_rdp": ["azure_nsg_unrestricted_port_3389"],
    "network_nsg_deny_by_default": ["azure_nsg_default_deny_inbound"],
    "network_nsg_flow_logs_enabled": ["azure_nsg_flow_logs_enabled"],
    "network_environment_segmentation": ["azure_subnet_has_nsg"],
    "network_nsg_restricted_egress": ["azure_nsg_http_restricted"],
    "network_public_ip_inventory": ["azure_public_ip_review"],
    "network_unused_nsgs": ["azure_nsg_flow_logs_enabled"],
    "network_peering_controlled": ["azure_network_watcher_enabled"],
    "network_custom_vnet_used": ["azure_network_watcher_enabled"],
    "storage_encryption_enabled": ["azure_storage_infrastructure_encryption", "azure_storage_cmk_encryption"],
    "storage_https_only": ["azure_storage_https_only"],
    "storage_cmk_encryption": ["azure_storage_cmk_encryption"],
    "storage_no_public_access": ["azure_storage_no_public_access"],
    "storage_no_anonymous_access": ["azure_storage_no_public_access"],
    "storage_immutable_blob_storage": ["azure_storage_no_public_access"],
    "storage_soft_delete_enabled": ["azure_storage_soft_delete_blobs"],
    "storage_container_soft_delete": ["azure_storage_soft_delete_files"],
    "storage_blob_versioning_enabled": ["azure_storage_soft_delete_blobs"],
    "storage_lifecycle_management": ["azure_storage_key_rotation"],
    "storage_private_endpoint": ["azure_private_endpoints_used"],
    "vm_disk_encryption": ["azure_vm_disk_encryption"],
    "vm_disk_cmk": ["azure_vm_disk_encryption"],
    "vm_disk_encryption_default": ["azure_vm_disk_encryption"],
    "vm_snapshot_encrypted": ["azure_vm_disk_encryption"],
    "vm_snapshot_policy_configured": ["azure_vm_disk_encryption"],
    "vm_backup_enabled": ["azure_backup_vault_exists"],
    "keyvault_soft_delete_enabled": ["azure_keyvault_soft_delete"],
    "keyvault_purge_protection_enabled": ["azure_keyvault_purge_protection"],
    "keyvault_key_rotation_enabled": ["azure_keyvault_key_expiration"],
    "keyvault_access_policy_restrictive": ["azure_keyvault_rbac_authorization"],
    "keyvault_rbac_enabled": ["azure_keyvault_rbac_authorization"],
    "keyvault_secrets_expiration": ["azure_keyvault_secret_expiration"],
    "keyvault_certificate_not_expiring": ["azure_keyvault_certificate_validity"],
    "sql_tde_enabled": ["azure_sql_tde_enabled"],
    "sql_database_encryption": ["azure_sql_tde_enabled"],
    "sql_automated_backups_enabled": ["azure_sql_auditing_enabled"],
    "sql_pitr_enabled": ["azure_sql_auditing_enabled"],
    "sql_private_endpoint": ["azure_sql_public_access_disabled"],
    "app_service_https_only": ["azure_appservice_https_only"],
    "app_gateway_tls_policy": ["azure_appgw_tls_12"],
    "waf_application_gateway_enabled": ["azure_appgw_waf_enabled"],
    "dns_security_configured": ["azure_ddos_protection_enabled"],
    "apim_auth_configured": ["azure_appgw_waf_enabled"],
    "backup_soft_delete_enabled": ["azure_backup_vault_exists"],
    "backup_geo_redundant_enabled": ["azure_backup_vault_redundancy"],
    "backup_retention_minimum_30d": ["azure_backup_vault_exists"],
    "backup_encryption_enabled": ["azure_backup_vault_exists"],
    "backup_separate_subscription": ["azure_backup_vault_redundancy"],
    "backup_rbac_configured": ["azure_backup_vault_exists"],
    "backup_monitoring_alerts": ["azure_backup_vault_exists"],
    "cosmos_db_backup_configured": ["azure_sql_auditing_enabled"],
    "function_app_backup_configured": ["azure_appservice_managed_identity"],
    "purview_dlp_configured": ["azure_security_contact_configured"],
    "aks_backup_configured": ["azure_aks_rbac_enabled"],
    # ── GCP ──
    "gcp_iam_mfa_enabled": ["gcp_iam_corp_login_required"],
    "gcp_iam_super_admin_mfa": ["gcp_iam_corp_login_required"],
    "gcp_iam_service_account_key_rotation": ["gcp_iam_sa_key_rotation"],
    "gcp_iam_no_owner_role": ["gcp_iam_no_primitive_roles"],
    "gcp_iam_service_account_no_admin": ["gcp_iam_no_sa_admin_key"],
    "gcp_iam_service_account_no_keys": ["gcp_iam_no_user_managed_sa_keys"],
    "gcp_iam_unused_service_accounts": ["gcp_iam_no_user_managed_sa_keys"],
    "gcp_iam_api_key_restricted": ["gcp_iam_api_keys_restricted"],
    "gcp_iam_api_key_rotated": ["gcp_iam_api_keys_rotated"],
    "gcp_iam_workload_identity_federation": ["gcp_gke_workload_identity"],
    "gcp_iam_recommender_applied": ["gcp_iam_no_primitive_roles"],
    "gcp_iam_no_permanent_owner": ["gcp_iam_no_primitive_roles"],
    "gcp_iam_organization_policy_enforced": ["gcp_iam_no_primitive_roles"],
    "gcp_iam_access_context_manager": ["gcp_iam_no_public_access"],
    "gcp_iam_password_policy_enforced": ["gcp_iam_corp_login_required"],
    "gcp_iam_workforce_identity": ["gcp_iam_corp_login_required"],
    "gcp_iam_cross_project_access": ["gcp_iam_no_public_access"],
    "gcp_iam_break_glass_account": ["gcp_iam_separation_of_duties"],
    "gcp_iam_access_transparency": ["gcp_iam_essential_contacts"],
    "gcp_storage_bucket_encryption": ["gcp_storage_cmek_encryption"],
    "gcp_storage_cmek_enabled": ["gcp_storage_cmek_encryption"],
    "gcp_sql_encryption_enabled": ["gcp_sql_cmek_encryption"],
    "gcp_sql_cmek_enabled": ["gcp_sql_cmek_encryption"],
    "gcp_kms_key_rotation_enabled": ["gcp_kms_key_rotation"],
    "gcp_kms_key_destroy_protection": ["gcp_kms_hsm_protection"],
    "gcp_kms_key_access_restricted": ["gcp_kms_no_public_access"],
    "gcp_storage_versioning_enabled": ["gcp_storage_versioning"],
    "gcp_storage_soft_delete_enabled": ["gcp_storage_retention_policy"],
    "gcp_storage_lifecycle_configured": ["gcp_storage_retention_policy"],
    "gcp_storage_bucket_lock": ["gcp_storage_retention_policy"],
    "gcp_sql_ssl_enforced": ["gcp_sql_ssl_required"],
    "gcp_sql_automated_backups_enabled": ["gcp_sql_backup_enabled"],
    "gcp_network_no_public_ssh": ["gcp_firewall_open_22"],
    "gcp_network_no_public_rdp": ["gcp_firewall_open_3389"],
    "gcp_network_deny_by_default": ["gcp_firewall_no_default_allow"],
    "gcp_network_restricted_egress": ["gcp_firewall_no_default_allow"],
    "gcp_network_environment_segmentation": ["gcp_network_no_default_network"],
    "gcp_network_unused_firewall_rules": ["gcp_firewall_no_default_allow"],
    "gcp_network_peering_controlled": ["gcp_network_no_legacy_network"],
    "gcp_cloud_armor_enabled": ["gcp_gke_master_auth_networks"],
    "gcp_network_ssl_policy": ["gcp_network_ssl_policy"],
    "gcp_api_gateway_auth_configured": ["gcp_function_ingress_restricted"],
    "gcp_dns_security_configured": ["gcp_dns_dnssec_enabled", "gcp_network_dns_sec"],
    "gcp_compute_snapshot_encrypted": ["gcp_compute_disk_encryption_cmek"],
    "gcp_compute_snapshot_schedule": ["gcp_compute_disk_encryption_cmek"],
    "gcp_compute_public_ip_inventory": ["gcp_compute_no_external_ip"],
    "gcp_compute_instance_backup": ["gcp_compute_disk_encryption_cmek"],
    "gcp_certificate_not_expiring": ["gcp_network_ssl_policy"],
    "gcp_secret_manager_configured": ["gcp_secret_rotation"],
    "gcp_dlp_configured": ["gcp_bigquery_classification"],
    "gcp_bigquery_classification": ["gcp_bigquery_classification"],
    "gcp_backup_encryption_enabled": ["gcp_sql_backup_enabled"],
    "gcp_backup_retention_minimum_30d": ["gcp_sql_backup_enabled"],
    "gcp_backup_multi_region": ["gcp_sql_backup_enabled"],
    "gcp_backup_deletion_protection": ["gcp_storage_retention_policy"],
    "gcp_backup_separate_project": ["gcp_sql_backup_enabled"],
    "gcp_backup_access_restricted": ["gcp_storage_retention_policy"],
    "gcp_backup_monitoring_alerts": ["gcp_logging_audit_logs_enabled"],
    "gcp_gke_backup_configured": ["gcp_gke_cluster_logging"],
    "gcp_firestore_backup_configured": ["gcp_sql_backup_enabled"],
    "gcp_cloud_function_versioned": ["gcp_function_runtime_supported"],
    # ── D5: Hardening additional aliases ──
    "inspector_enabled": ["guardduty_enabled"],
    "ecr_image_scanning_enabled": ["ecr_image_scanning"],
    "defender_for_servers_enabled": ["azure_defender_auto_provisioning"],
    "acr_vulnerability_scanning": ["azure_acr_vulnerability_scan"],
    "gcp_security_command_center_enabled": ["gcp_logging_audit_logs_enabled"],
    "gcp_artifact_registry_scanning": ["gcp_gke_binary_auth"],
    "defender_for_cloud_enabled": ["azure_defender_auto_provisioning"],
    "ec2_ami_hardened": ["ec2_imdsv2_required"],
    "vm_image_hardened": ["azure_vm_trusted_launch"],
    "gcp_compute_image_hardened": ["gcp_compute_shielded_vm"],
    "lambda_function_no_admin_role": ["lambda_runtime_supported"],
    "function_app_runtime_updated": ["azure_appservice_managed_identity"],
    "gcp_cloud_function_runtime_updated": ["gcp_function_runtime_supported"],
    "apigateway_throttling_enabled": ["apigateway_rest_api_logging"],
    "apim_rate_limiting_configured": ["azure_appgw_waf_enabled"],
    "gcp_api_gateway_quota_configured": ["gcp_function_ingress_restricted"],
    "config_enabled": ["config_recorder_enabled"],
    "cloudformation_drift_detection": ["config_recorder_enabled"],
    "policy_compliance_monitoring": ["azure_policy_compliance_rate"],
    "gcp_config_monitoring_enabled": ["gcp_logging_cloud_asset_inventory"],
    "security_center_default_policy": ["azure_policy_security_initiative"],
    "gcp_compute_default_service_account_no_admin": ["gcp_compute_no_full_api_access"],
    "ec2_no_eol_os": ["ec2_imdsv2_required"],
    "rds_engine_not_eol": ["rds_auto_minor_upgrade"],
    "vm_no_eol_os": ["azure_vm_auto_updates"],
    "app_service_runtime_not_eol": ["azure_appservice_tls_12"],
    "gcp_compute_no_eol_os": ["gcp_compute_shielded_vm"],
    "gcp_sql_engine_not_eol": ["gcp_sql_backup_enabled"],
    "ec2_nitro_enclave_capable": ["ec2_imdsv2_required"],
    "vm_trusted_launch_enabled": ["azure_vm_trusted_launch"],
    "gcp_compute_no_serial_port": ["gcp_compute_serial_port_disabled"],
    "gcp_compute_no_project_wide_ssh": ["gcp_compute_block_project_ssh"],
    # ── D6: Logging additional aliases ──
    "cloudtrail_log_validation_enabled": ["cloudtrail_log_validation"],
    "cloudtrail_s3_bucket_immutable": ["cloudtrail_s3_bucket_logging"],
    "logging_immutable_storage": ["azure_storage_soft_delete_blobs"],
    "gcp_logging_bucket_locked": ["gcp_logging_bucket_retention"],
    "cloudwatch_alarm_root_usage": ["cloudtrail_enabled"],
    "cloudwatch_alarm_iam_changes": ["cloudtrail_enabled"],
    "cloudwatch_alarm_cloudtrail_changes": ["cloudtrail_enabled"],
    "monitor_alert_security_events": ["azure_security_alert_notifications"],
    "cloudwatch_log_group_retention_365d": ["cloudwatch_log_group_retention"],
    "cloudtrail_s3_lifecycle_retention": ["cloudtrail_s3_bucket_logging"],
    "log_analytics_retention_365d": ["azure_monitor_log_retention_365"],
    "gcp_logging_retention_365d": ["gcp_logging_bucket_retention"],
    "cloudtrail_organization_trail": ["cloudtrail_multiregion"],
    "cloudwatch_cross_account_logging": ["cloudtrail_integrated_cloudwatch"],
    "logging_centralized_workspace": ["azure_monitor_diagnostic_settings"],
    "gcp_logging_organization_sink": ["gcp_logging_sinks_configured"],
    "logging_activity_log_enabled": ["azure_monitor_log_profile"],
    "route53_query_logging_enabled": ["cloudtrail_enabled"],
    "dns_query_logging_enabled": ["azure_monitor_diagnostic_settings"],
    "gcp_dns_logging_enabled": ["gcp_logging_dns_logging"],
    "storage_logging_enabled": ["azure_storage_soft_delete_blobs"],
    "gcp_storage_access_logging": ["gcp_storage_logging_enabled"],
    "monitor_alert_diagnostic_setting_changes": ["azure_security_alert_notifications"],
    "cloudtrail_s3_bucket_deletion_alert": ["cloudtrail_s3_bucket_logging"],
    # ── AWS ec2_sg_restricted_egress (D4) ──
    "ec2_sg_restricted_egress": ["ec2_sg_no_wide_open_ports"],
    "ec2_public_ip_inventory": ["ec2_instance_no_public_ip"],
    "ec2_unused_eips": ["ec2_instance_no_public_ip"],
    "ec2_unused_security_groups": ["ec2_default_sg_no_traffic"],
    "vpc_peering_route_tables_restrictive": ["vpc_default_sg_restricts_all"],
    "vpc_default_not_used": ["vpc_default_sg_restricts_all"],
    "vpc_endpoint_s3": ["s3_bucket_public_access_blocked"],
    "vpc_endpoint_dynamodb": ["dynamodb_table_encrypted_kms"],
    "waf_web_acl_associated": ["waf_web_acl_exists"],
    "route53_resolver_dnssec": ["cloudtrail_enabled"],
    "route53_dns_firewall": ["cloudtrail_enabled"],
    "elb_access_logs_enabled": ["cloudtrail_enabled"],
    "apigateway_auth_configured": ["apigateway_rest_api_logging"],
}


def evaluate_findings_against_rules(
    findings: list[dict],
    provider: str,
    account_id: str,
    governance_data: dict | None = None,
) -> list[CheckEvaluation]:
    """Evaluate a list of CSPM findings against all RR rules for a provider.

    Args:
        findings: List of finding dicts from the DB (check_id, status, severity, resource_id, ...).
        provider: Cloud provider type (aws, azure, gcp).
        account_id: The cloud account / subscription / project ID.
        governance_data: Optional dict with manual governance inputs for D7 rules.

    Returns:
        List of CheckEvaluation results, one per applicable RR rule.
    """
    # Index findings by check_id, including normalized variants and aliases.
    # Scanner check_ids may have provider prefixes (e.g. "azure_iam_mfa_enabled")
    # while rules may reference them without prefix (e.g. "iam_mfa_enabled") or vice-versa.
    findings_by_check: dict[str, list[dict]] = {}
    provider_prefixes = ("aws_", "azure_", "gcp_")
    for f in findings:
        cid = f.get("check_id", "")
        findings_by_check.setdefault(cid, []).append(f)
        # Also index under normalized key (without provider prefix)
        for prefix in provider_prefixes:
            if cid.startswith(prefix):
                stripped = cid[len(prefix):]
                findings_by_check.setdefault(stripped, []).append(f)
                break
        else:
            # No prefix found — also index with provider prefix
            prefixed = f"{provider}_{cid}"
            findings_by_check.setdefault(prefixed, []).append(f)

    # Build reverse alias index: for each rule check_id that maps to scanner
    # check_ids, populate findings_by_check so rule lookups find scanner results.
    for rule_cid, scanner_cids in CHECK_ID_ALIASES.items():
        if rule_cid in findings_by_check:
            continue  # already has direct findings, skip alias
        for scanner_cid in scanner_cids:
            if scanner_cid in findings_by_check:
                findings_by_check.setdefault(rule_cid, []).extend(
                    findings_by_check[scanner_cid]
                )

    all_rules = get_all_rules()
    evaluations: list[CheckEvaluation] = []

    for rule in all_rules:
        # Skip rules not applicable to this provider
        if provider not in rule.cloud_providers:
            continue

        # Handle manual / governance rules
        if rule.is_manual:
            ev = _evaluate_manual_rule(rule, governance_data, account_id, provider)
            evaluations.append(ev)
            continue

        # Handle composite rules
        if rule.is_composite:
            ev = _evaluate_composite_rule(rule, findings_by_check, provider, account_id)
            evaluations.append(ev)
            continue

        # Standard rule: map check_ids to findings
        ev = _evaluate_standard_rule(rule, findings_by_check, provider, account_id)
        evaluations.append(ev)

    return evaluations


def _evaluate_standard_rule(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """Evaluate a standard rule by aggregating its mapped CSPM check results."""
    check_ids = rule.check_ids.get(provider, [])
    if not check_ids:
        # Rule defined for provider but no check_ids mapped -> warning
        return CheckEvaluation(
            rule_id=rule.rule_id,
            domain=rule.domain,
            severity=rule.severity,
            status="warning",
            account_id=account_id,
            provider=provider,
            evidence={
                "summary": f"No hay checks CSPM mapeados para esta regla en {provider.upper()}. "
                           "No se puede evaluar automáticamente.",
                "check_type": "automated",
                "checks_evaluated": [],
                "expected": "Checks CSPM disponibles para evaluación automática",
                "actual": "Sin checks mapeados para este proveedor",
            },
        )

    total_resources = 0
    passed_resources = 0
    failed_resources = 0
    all_evidence: list[dict] = []

    for cid in check_ids:
        matched_findings = findings_by_check.get(cid, [])
        for f in matched_findings:
            total_resources += 1
            status = f.get("status", "").upper()
            if status == "PASS":
                passed_resources += 1
            elif status == "FAIL":
                failed_resources += 1
                all_evidence.append({
                    "check_id": cid,
                    "resource_id": f.get("resource_id"),
                    "resource_name": f.get("resource_name"),
                    "status_extended": f.get("status_extended"),
                })

    if total_resources == 0:
        # No findings found for mapped checks -> could mean checks weren't run
        return CheckEvaluation(
            rule_id=rule.rule_id,
            domain=rule.domain,
            severity=rule.severity,
            status="warning",
            account_id=account_id,
            provider=provider,
            evidence={
                "summary": f"No se encontraron resultados para los checks: {', '.join(check_ids)}. "
                           "Los checks pueden no haberse ejecutado en el último scan.",
                "check_type": "automated",
                "checks_evaluated": check_ids,
                "expected": "Resultados de los checks CSPM disponibles",
                "actual": "No se encontraron findings para estos checks",
            },
        )

    # Rule passes only if ALL resources pass
    if failed_resources == 0:
        status = "pass"
    else:
        status = "fail"

    if status == "pass":
        summary = (f"Todos los {total_resources} recursos evaluados cumplen con este control. "
                   f"Checks ejecutados: {', '.join(check_ids)}.")
    else:
        summary = (f"{failed_resources} de {total_resources} recursos no cumplen con este control. "
                   f"Checks ejecutados: {', '.join(check_ids)}.")

    return CheckEvaluation(
        rule_id=rule.rule_id,
        domain=rule.domain,
        severity=rule.severity,
        status=status,
        resource_count=total_resources,
        passed_resources=passed_resources,
        failed_resources=failed_resources,
        account_id=account_id,
        provider=provider,
        evidence={
            "summary": summary,
            "check_type": "automated",
            "checks_evaluated": check_ids,
            "expected": "Todos los recursos deben pasar los checks",
            "actual": f"{passed_resources} passed, {failed_resources} failed de {total_resources} total",
            "total": total_resources,
            "passed": passed_resources,
            "failed": failed_resources,
            "failed_details": all_evidence[:20],  # cap evidence for storage
        },
    )


def _evaluate_composite_rule(
    rule: RRRule,
    findings_by_check: dict[str, list[dict]],
    provider: str,
    account_id: str,
) -> CheckEvaluation:
    """Evaluate composite rules that require cross-check analysis.

    Composite rules aggregate results from multiple checks and may apply
    custom logic (e.g. CIS compliance percentage, cross-region backup existence).
    For now, we use a standard aggregation — specific composite logic
    can be added per rule_id in composite_rules.py.
    """
    from scanner.ransomware_readiness.composite_rules import COMPOSITE_EVALUATORS

    evaluator_fn = COMPOSITE_EVALUATORS.get(rule.rule_id)
    if evaluator_fn:
        return evaluator_fn(rule, findings_by_check, provider, account_id)

    # Default: fall back to standard aggregation
    return _evaluate_standard_rule(rule, findings_by_check, provider, account_id)


def _evaluate_manual_rule(
    rule: RRRule,
    governance_data: dict | None,
    account_id: str,
    provider: str,
) -> CheckEvaluation:
    """Evaluate manual / governance rules from operator-provided data."""
    if not governance_data:
        return CheckEvaluation(
            rule_id=rule.rule_id,
            domain=rule.domain,
            severity=rule.severity,
            status="warning",
            account_id=account_id,
            provider=provider,
            evidence={
                "summary": "Datos de gobernanza no proporcionados. Complete el cuestionario de Governance Inputs para evaluar este control.",
                "check_type": "manual",
                "expected": "Respuesta del operador en el cuestionario de gobernanza",
                "actual": "Pendiente de completar",
            },
        )

    # Map rule_ids to governance data fields
    field_map = {
        "RR-GOV-001": "ransomware_response_plan",
        "RR-GOV-002": "last_tabletop_exercise_date",
        "RR-GOV-003": "security_training_completion",
        "RR-GOV-004": "ir_roles_defined",
        "RR-GOV-005": "communication_plan_exists",
        "RR-BKP-015": "rto_rpo_documented",
        "RR-BKP-016": "backup_restore_tested",
        "RR-BKP-017": "dr_plan_documented",
        "RR-HDN-015": "iac_scanning_integrated",
        "RR-LOG-009": "siem_integration_configured",
    }

    field_name = field_map.get(rule.rule_id, rule.rule_id.lower())
    value = governance_data.get(field_name)

    if value is None:
        return CheckEvaluation(
            rule_id=rule.rule_id,
            domain=rule.domain,
            severity=rule.severity,
            status="warning",
            account_id=account_id,
            provider=provider,
            evidence={
                "summary": f"El campo '{field_name}' no ha sido completado en los datos de gobernanza.",
                "check_type": "manual",
                "expected": f"Valor para '{field_name}' en el cuestionario de gobernanza",
                "actual": "Campo no completado",
            },
        )

    # Human-readable field labels
    FIELD_LABELS = {
        "ransomware_response_plan": "Plan de respuesta a ransomware",
        "last_tabletop_exercise_date": "Fecha último tabletop exercise",
        "security_training_completion": "Porcentaje de completion del security training",
        "ir_roles_defined": "Roles y responsabilidades de IR definidos",
        "communication_plan_exists": "Plan de comunicación existente",
        "rto_rpo_documented": "RTO/RPO documentados",
        "backup_restore_tested": "Pruebas de restauración realizadas",
        "dr_plan_documented": "Plan de disaster recovery documentado",
        "iac_scanning_integrated": "IaC scanning integrado en pipeline",
        "siem_integration_configured": "Integración SIEM configurada",
    }
    field_label = FIELD_LABELS.get(field_name, field_name)

    # Boolean fields
    if isinstance(value, bool):
        return CheckEvaluation(
            rule_id=rule.rule_id,
            domain=rule.domain,
            severity=rule.severity,
            status="pass" if value else "fail",
            account_id=account_id,
            provider=provider,
            evidence={
                "summary": f"{field_label}: {'Sí' if value else 'No'}",
                "check_type": "manual",
                "expected": f"{field_label} debe estar confirmado (Sí)",
                "actual": "Sí" if value else "No",
            },
        )

    # Date fields (e.g. last tabletop exercise — must be within 6 months)
    if field_name == "last_tabletop_exercise_date":
        from datetime import datetime, timedelta
        try:
            exercise_date = datetime.fromisoformat(str(value))
            six_months_ago = datetime.utcnow() - timedelta(days=180)
            is_recent = exercise_date >= six_months_ago
            return CheckEvaluation(
                rule_id=rule.rule_id,
                domain=rule.domain,
                severity=rule.severity,
                status="pass" if is_recent else "fail",
                account_id=account_id,
                provider=provider,
                evidence={
                    "summary": f"{field_label}: {str(value)[:10]} — {'dentro de los últimos 6 meses' if is_recent else 'hace más de 6 meses'}",
                    "check_type": "manual",
                    "expected": "Último ejercicio realizado dentro de los últimos 6 meses",
                    "actual": f"Fecha registrada: {str(value)[:10]}",
                },
            )
        except (ValueError, TypeError):
            pass

    # Percentage fields (e.g. training completion — must be ≥90%)
    if field_name == "security_training_completion":
        try:
            pct = float(value)
            return CheckEvaluation(
                rule_id=rule.rule_id,
                domain=rule.domain,
                severity=rule.severity,
                status="pass" if pct >= 90.0 else "fail",
                account_id=account_id,
                provider=provider,
                evidence={
                    "summary": f"{field_label}: {pct}% — {'cumple' if pct >= 90.0 else 'no cumple'} el umbral mínimo",
                    "check_type": "manual",
                    "expected": "Porcentaje de completion ≥ 90%",
                    "actual": f"{pct}%",
                },
            )
        except (ValueError, TypeError):
            pass

    # Default: truthy check
    return CheckEvaluation(
        rule_id=rule.rule_id,
        domain=rule.domain,
        severity=rule.severity,
        status="pass" if value else "fail",
        account_id=account_id,
        provider=provider,
        evidence={
            "summary": f"{field_label}: {str(value)}",
            "check_type": "manual",
            "expected": f"{field_label} debe tener un valor válido",
            "actual": str(value),
        },
    )


def evaluate_all_accounts(
    accounts: list[dict],
    governance_data: dict | None = None,
) -> list[CheckEvaluation]:
    """Evaluate RR rules across multiple cloud accounts.

    Args:
        accounts: List of dicts with keys: account_id, provider, name, findings (list of finding dicts)
        governance_data: Optional governance inputs

    Returns:
        Combined list of CheckEvaluations for all accounts
    """
    all_evaluations: list[CheckEvaluation] = []

    for account in accounts:
        evals = evaluate_findings_against_rules(
            findings=account.get("findings", []),
            provider=account["provider"],
            account_id=account["account_id"],
            governance_data=governance_data,
        )
        all_evaluations.extend(evals)

    return all_evaluations
