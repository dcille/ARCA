#!/usr/bin/env python3
"""
Build the complete CCM-4.1 framework with all 207 controls for ARCA.
Parses the reference ccm-v41-data.js for control metadata and maps ARCA check IDs.
"""
import re, json, sys

# ============================================================
# 1. Parse all 207 controls from the JS reference file
# ============================================================
with open("/tmp/ccm-v41-data.js") as f:
    js = f.read()

# Extract domain names
domain_names = {}
for m in re.finditer(r'\{\s*id:\s*"([^"]+)",\s*name:\s*"([^"]+)"', js):
    domain_names[m.group(1)] = m.group(2)

# Extract all controls
controls_raw = []
for m in re.finditer(
    r'\{\s*id:\s*"([^"]+)",\s*title:\s*"([^"]+)",\s*spec:\s*"((?:[^"\\]|\\.)*)"',
    js
):
    ctrl_id = m.group(1)
    title = m.group(2)
    spec = m.group(3).replace('\\"', '"').replace('\\n', ' ')
    domain_prefix = ctrl_id.rsplit('-', 1)[0]
    controls_raw.append({
        "id": ctrl_id,
        "title": title,
        "description": spec,
        "domain_id": domain_prefix,
        "domain": domain_names.get(domain_prefix, domain_prefix),
    })

print(f"Parsed {len(controls_raw)} controls from JS reference")

# ============================================================
# 2. Map ARCA check IDs to CCM controls
# Based on the ccm_engine.py mappings + our ARCA check inventory
# ============================================================

# Mapping from ccm_engine function names to ARCA check IDs
ENGINE_TO_ARCA = {
    # AWS
    "aws_check_mfa_root": "iam_root_mfa_enabled",
    "aws_check_mfa_users": "iam_user_mfa_enabled",
    "aws_check_password_policy": "iam_password_policy_strong",
    "aws_check_root_keys": "iam_no_root_access_key",
    "aws_check_root_usage": "iam_no_root_access_key",
    "aws_check_admin_users": "iam_no_star_policies",
    "aws_check_unused_creds": "iam_user_unused_credentials_45days",
    "aws_check_inactive_users": "iam_user_unused_credentials_45days",
    "aws_check_key_rotation": "iam_access_key_rotation",
    "aws_check_access_key_age": "iam_access_key_rotation",
    "aws_check_credential_report": "iam_user_unused_credentials_45days",
    "aws_check_ebs_encryption": "ec2_ebs_volume_encrypted",
    "aws_check_s3_encryption": "s3_bucket_encryption_enabled",
    "aws_check_s3_versioning": "s3_bucket_versioning_enabled",
    "aws_check_rds_encryption": "rds_encryption_enabled",
    "aws_check_rds_multi_az": "rds_multi_az_enabled",
    "aws_check_kms_key_spec": "kms_key_rotation_enabled",
    "aws_check_kms_rotation": "kms_key_rotation_enabled",
    "aws_check_kms_inventory": "kms_key_rotation_enabled",
    "aws_check_sg_open_ports": "ec2_sg_no_wide_open_ports",
    "aws_check_nacl_open": "vpc_no_unrestricted_nacl",
    "aws_check_ssm_compliance": "ssm_managed_instances",
    "aws_check_imdsv2": "ec2_imdsv2_required",
    "aws_check_vpc_flow_logs": "vpc_flow_logs_enabled",
    "aws_check_default_vpc": "vpc_default_sg_restricts_all",
    "aws_check_waf": "waf_web_acl_exists",
    "aws_check_shield": "waf_web_acl_exists",
    "aws_check_cloudtrail": "cloudtrail_enabled",
    "aws_check_guardduty": "guardduty_enabled",
    "aws_check_securityhub": "guardduty_enabled",
    "aws_check_ct_log_validation": "cloudtrail_log_validation",
    "aws_check_cw_log_retention": "cloudwatch_log_group_retention",
    "aws_check_config_rules": "config_recorder_enabled",
    "aws_check_config_conformance": "config_recorder_enabled",
    "aws_check_tls_config": "cloudfront_https_only",
    "aws_check_backup_plans": "backup_plan_exists",
    "aws_check_inspector": "ecr_image_scanning",
    "aws_check_codepipeline": "lambda_runtime_supported",
    "aws_check_codeguru": "ecr_image_scanning",
    "aws_check_eventbridge": "guardduty_enabled",
    # Azure
    "azure_check_storage_encryption": "azure_storage_cmk_encryption",
    "azure_check_disk_encryption": "azure_vm_disk_encryption",
    "azure_check_sql_tde": "azure_sql_tde_enabled",
    "azure_check_keyvault_key_type": "azure_keyvault_key_expiration",
    "azure_check_keyvault_rotation": "azure_keyvault_key_expiration",
    "azure_check_nsg_open": "azure_nsg_default_deny_inbound",
    "azure_check_nsg_flow_logs": "azure_nsg_flow_logs_enabled",
    "azure_check_vm_extensions": "azure_vm_antimalware_extension",
    "azure_check_conditional_access": "azure_iam_mfa_enabled_all_users",
    "azure_check_mfa_enforcement": "azure_iam_mfa_enabled_all_users",
    "azure_check_user_list": "azure_iam_guest_users_reviewed",
    "azure_check_owner_assignments": "azure_iam_owner_count",
    "azure_check_stale_accounts": "azure_iam_guest_users_reviewed",
    "azure_check_pim": "azure_pim_jit_access",
    "azure_check_sp_secrets": "azure_keyvault_secret_expiration",
    "azure_check_tls_version": "azure_storage_tls_12",
    "azure_check_activity_log": "azure_monitor_diagnostic_settings",
    "azure_check_defender_pricing": "azure_defender_auto_provisioning",
    "azure_check_log_immutability": "azure_monitor_log_retention_365",
    "azure_check_log_retention": "azure_monitor_log_retention_365",
    "azure_check_policy_compliance": "azure_policy_compliance_rate",
    "azure_check_policy_state": "azure_policy_compliance_rate",
    "azure_check_recovery_vault": "azure_backup_vault_exists",
    "azure_check_geo_replication": "azure_backup_vault_redundancy",
    "azure_check_ddos_protection": "azure_public_ip_ddos_protection",
    "azure_check_defender_vuln": "azure_defender_auto_provisioning",
    "azure_check_devops_security": "azure_policy_security_initiative",
    # GCP
    "gcp_check_disk_encryption": "gcp_compute_disk_encryption_cmek",
    "gcp_check_csek_usage": "gcp_storage_cmek_encryption",
    "gcp_check_fw_rules": "gcp_firewall_no_default_allow",
    "gcp_check_vpc_flow_logs": "gcp_logging_vpc_flow_logs",
    "gcp_check_audit_logs": "gcp_logging_audit_logs_enabled",
    "gcp_check_scc": "gcp_logging_metric_filters",
    "gcp_check_org_policies": "gcp_iam_no_primitive_roles",
    "gcp_check_snapshot_schedules": "gcp_sql_backup_enabled",
    "gcp_check_2fa_org": "gcp_iam_corp_login_required",
    "gcp_check_sa_inventory": "gcp_iam_no_user_managed_sa_keys",
    "gcp_check_editor_bindings": "gcp_iam_no_primitive_roles",
    "gcp_check_sa_key_age": "gcp_iam_sa_key_rotation",
    # OCI
    "oci_check_boot_volume_encryption": "oci_storage_boot_volume_cmk_encryption",
    "oci_check_bucket_encryption": "oci_objectstorage_bucket_cmk_encryption",
    "oci_check_seclist_open": "oci_network_nsg_no_unrestricted_ingress",
    "oci_check_mfa_users": "oci_iam_user_mfa_enabled",
    "oci_check_admin_users": "oci_iam_admin_mfa_enabled",
    "oci_check_api_key_age": "oci_iam_api_key_rotation",
    "oci_check_audit_enabled": "oci_logging_audit_retention",
    "oci_check_cloud_guard": "oci_cloud_guard_enabled",
}

# Build the check mappings per CCM control using the engine data
# Parse engine for control->check mappings
with open("/tmp/ccm_engine.py") as f:
    engine_content = f.read()

# Extract mappings: control_id -> {provider: [fn_names]}
engine_checks = {}
# Multi-line pattern for controls with checks
ctrl_blocks = re.findall(
    r'"([A-Z&]+\-\d+)":\s*\{[^}]*"checks":\s*\{([^}]+)\}',
    engine_content
)
for ctrl_id, checks_body in ctrl_blocks:
    engine_checks[ctrl_id] = {}
    for pm in re.finditer(r'"(\w+)":\s*\[([^\]]+)\]', checks_body):
        provider = pm.group(1)
        fns = re.findall(r'"fn":\s*"([^"]+)"', pm.group(2))
        engine_checks[ctrl_id][provider] = fns

# Now also add broader ARCA-specific check mappings beyond what the engine had
# These are additional mappings based on domain relevance
EXTRA_ARCA_CHECKS = {
    # A&A: Audit & Assurance - map to audit/logging checks
    "A&A-01": {"aws": ["cloudtrail_enabled", "config_recorder_enabled"], "gcp": ["gcp_logging_audit_logs_enabled"], "azure": ["azure_monitor_diagnostic_settings"]},
    "A&A-02": {"aws": ["guardduty_enabled"], "azure": ["azure_policy_compliance_rate"]},
    "A&A-06": {"aws": ["config_recorder_enabled"], "azure": ["azure_policy_compliance_rate"]},

    # AIS: Application & Interface Security
    "AIS-01": {"aws": ["waf_web_acl_exists", "apigateway_rest_api_logging"], "azure": ["azure_appgw_waf_enabled"]},
    "AIS-02": {"aws": ["lambda_runtime_supported"], "kubernetes": ["k8s_admission_pod_security"]},
    "AIS-04": {"aws": ["ecr_image_scanning", "ecr_lifecycle_policy"], "gcp": ["gcp_gke_binary_auth"]},
    "AIS-07": {"aws": ["ecr_image_scanning", "lambda_runtime_supported"]},
    "AIS-08": {"aws": ["apigateway_rest_api_logging", "apigateway_waf_enabled"]},

    # BCR: Business Continuity
    "BCR-01": {"aws": ["backup_plan_exists", "rds_backup_enabled"], "gcp": ["gcp_sql_backup_enabled"], "azure": ["azure_backup_vault_exists"]},
    "BCR-03": {"aws": ["rds_multi_az_enabled", "backup_plan_exists"], "azure": ["azure_backup_vault_redundancy"]},
    "BCR-04": {"aws": ["backup_plan_exists", "dynamodb_pitr_enabled"], "gcp": ["gcp_sql_pitr_enabled"]},
    "BCR-11": {"aws": ["rds_multi_az_enabled"], "azure": ["azure_backup_vault_redundancy"]},

    # CCC: Change Control
    "CCC-01": {"aws": ["config_recorder_enabled"], "gcp": ["gcp_logging_audit_logs_enabled"], "servicenow": ["servicenow_change_management"]},
    "CCC-03": {"aws": ["config_recorder_enabled"], "azure": ["azure_policy_assignments_exist"]},
    "CCC-06": {"aws": ["config_recorder_enabled"], "azure": ["azure_policy_security_initiative"]},

    # CEK: Cryptography, Encryption & Key Management
    "CEK-01": {"aws": ["kms_key_rotation_enabled"], "gcp": ["gcp_kms_key_rotation"], "azure": ["azure_keyvault_key_expiration"]},
    "CEK-02": {"aws": ["kms_key_rotation_enabled"]},
    "CEK-08": {"aws": ["kms_key_rotation_enabled"], "gcp": ["gcp_kms_hsm_protection"]},
    "CEK-09": {"aws": ["cloudtrail_encrypted"], "azure": ["azure_keyvault_rbac_authorization"]},
    "CEK-10": {"aws": ["kms_key_rotation_enabled"], "gcp": ["gcp_kms_key_rotation"]},
    "CEK-11": {"aws": ["kms_key_rotation_enabled"]},
    "CEK-12": {"aws": ["kms_key_rotation_enabled", "iam_access_key_rotation"], "gcp": ["gcp_kms_key_rotation", "gcp_iam_sa_key_rotation"], "alibaba": ["ali_kms_key_rotation"]},
    "CEK-13": {"aws": ["kms_key_rotation_enabled"]},
    "CEK-14": {"aws": ["kms_key_rotation_enabled"]},
    "CEK-21": {"aws": ["kms_key_rotation_enabled"]},

    # DCS: Datacenter Security - mostly physical, limited cloud checks
    "DCS-06": {"aws": ["config_recorder_enabled"]},
    "DCS-07": {"aws": ["config_recorder_enabled"], "servicenow": ["servicenow_cmdb_integrity"]},

    # DSP: Data Security & Privacy
    "DSP-01": {"aws": ["macie_enabled", "s3_bucket_public_access_blocked"], "m365": ["m365_dlp_policies_configured"]},
    "DSP-03": {"aws": ["config_recorder_enabled", "macie_enabled"], "servicenow": ["servicenow_data_classification"]},
    "DSP-04": {"aws": ["macie_enabled"], "m365": ["m365_sensitivity_labels_enabled"], "snowflake": ["snowflake_column_masking_policies"]},
    "DSP-05": {"aws": ["vpc_flow_logs_enabled"], "gcp": ["gcp_logging_vpc_flow_logs"]},
    "DSP-07": {"aws": ["s3_bucket_encryption_enabled", "ec2_ebs_default_encryption"], "gcp": ["gcp_storage_cmek_encryption"]},
    "DSP-10": {"aws": ["s3_bucket_ssl_required", "cloudfront_https_only"], "gcp": ["gcp_sql_ssl_required"]},
    "DSP-16": {"aws": ["s3_bucket_object_lock", "cloudwatch_log_group_retention"], "gcp": ["gcp_storage_retention_policy"], "snowflake": ["snowflake_data_retention_configured"]},
    "DSP-19": {"aws": ["config_recorder_enabled"]},

    # GRC: Governance, Risk & Compliance
    "GRC-01": {"aws": ["config_recorder_enabled", "guardduty_enabled"], "azure": ["azure_policy_assignments_exist"]},
    "GRC-02": {"aws": ["guardduty_enabled", "config_recorder_enabled"]},
    "GRC-05": {"aws": ["guardduty_enabled", "config_recorder_enabled"], "azure": ["azure_policy_security_initiative"]},

    # HRS: Human Resources - mostly policy, limited checks
    "HRS-11": {},  # manual

    # I&S: Infrastructure & Virtualization Security (supplement engine)
    "I&S-01": {"aws": ["vpc_flow_logs_enabled", "ec2_default_sg_no_traffic"], "kubernetes": ["k8s_namespace_network_policy"]},
    "I&S-02": {"kubernetes": ["k8s_namespace_resource_quotas", "k8s_namespace_limit_ranges"]},
    "I&S-05": {"aws": ["ec2_instance_no_public_ip"], "gcp": ["gcp_compute_no_external_ip"]},
    "I&S-08": {"aws": ["vpc_flow_logs_enabled"], "gcp": ["gcp_logging_vpc_flow_logs"]},

    # IAM: Identity & Access Management (supplement engine)
    "IAM-04": {"aws": ["iam_no_star_policies"], "gcp": ["gcp_iam_separation_of_duties"], "kubernetes": ["k8s_rbac_no_wildcard_cluster_admin"]},
    "IAM-06": {"aws": ["iam_user_no_inline_policies", "iam_group_no_inline_policies"]},
    "IAM-08": {"aws": ["iam_user_unused_credentials_45days"], "alibaba": ["ali_ram_unused_users"], "snowflake": ["snowflake_user_not_inactive"]},
    "IAM-11": {"azure": ["azure_pim_jit_access"]},
    "IAM-13": {"aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled"], "alibaba": ["ali_ram_mfa_enabled"], "m365": ["m365_admin_mfa_enforced", "m365_user_phishing_resistant_mfa"], "salesforce": ["salesforce_user_mfa_enabled"], "snowflake": ["snowflake_user_mfa_enabled"], "servicenow": ["servicenow_users_mfa_enabled"]},
    "IAM-14": {"aws": ["iam_access_key_rotation", "iam_password_policy_strong"], "alibaba": ["ali_ram_password_policy"], "snowflake": ["snowflake_account_password_policy"]},
    "IAM-15": {"kubernetes": ["k8s_rbac_no_wildcard_verbs", "k8s_rbac_limit_secrets_access"]},

    # LOG: Logging & Monitoring (supplement engine)
    "LOG-02": {"aws": ["cloudtrail_encrypted", "cloudtrail_log_validation"], "gcp": ["gcp_logging_bucket_retention"]},
    "LOG-04": {"aws": ["cloudtrail_s3_bucket_logging"]},
    "LOG-06": {},  # NTP - manual
    "LOG-07": {"aws": ["cloudtrail_multiregion", "config_recorder_enabled"], "alibaba": ["ali_actiontrail_multi_region"]},
    "LOG-09": {"aws": ["cloudtrail_enabled", "cloudwatch_log_group_encrypted"]},
    "LOG-10": {"aws": ["cloudtrail_encrypted", "s3_bucket_encryption_enabled"]},
    "LOG-11": {"aws": ["kms_key_rotation_enabled"]},
    "LOG-12": {"aws": ["cloudtrail_enabled", "s3_bucket_logging_enabled"], "gcp": ["gcp_storage_logging_enabled"], "alibaba": ["ali_oss_logging_enabled"], "salesforce": ["salesforce_setup_audit_trail"]},
    "LOG-13": {"aws": ["cloudtrail_enabled"], "gcp": ["gcp_logging_audit_logs_enabled"], "servicenow": ["servicenow_admin_audit_logging"]},

    # SEF: Security Incident Management
    "SEF-01": {"aws": ["guardduty_enabled"], "servicenow": ["servicenow_incident_management"]},
    "SEF-03": {"aws": ["guardduty_enabled", "iam_support_role_created"]},
    "SEF-06": {"aws": ["guardduty_enabled"], "m365": ["m365_defender_sensor_active"]},
    "SEF-07": {"aws": ["guardduty_enabled"], "servicenow": ["servicenow_incident_management"]},

    # STA: Supply Chain - mostly policy
    "STA-08": {"aws": ["config_recorder_enabled"], "servicenow": ["servicenow_cmdb_integrity"]},

    # TVM: Threat & Vulnerability Management (supplement engine)
    "TVM-01": {"aws": ["guardduty_enabled", "ecr_image_scanning"], "m365": ["m365_defender_low_risk"]},
    "TVM-03": {"aws": ["ecr_image_scanning", "guardduty_enabled"], "gcp": ["gcp_gke_binary_auth"]},
    "TVM-04": {"aws": ["guardduty_enabled"]},
    "TVM-05": {"aws": ["guardduty_enabled", "lambda_runtime_supported"], "m365": ["m365_safe_attachments_enabled", "m365_safe_links_enabled"]},
    "TVM-06": {"aws": ["lambda_runtime_supported", "ecr_image_scanning"]},
    "TVM-08": {"aws": ["rds_auto_minor_upgrade", "lambda_runtime_supported"]},
    "TVM-10": {"aws": ["guardduty_enabled"], "m365": ["m365_defender_sensor_active"]},

    # UEM: Universal Endpoint Management
    "UEM-01": {"m365": ["m365_ca_require_compliant_device"]},
    "UEM-05": {"aws": ["ssm_managed_instances"]},
    "UEM-08": {"aws": ["ec2_ebs_volume_encrypted", "ec2_ebs_default_encryption"]},
    "UEM-09": {"azure": ["azure_vm_antimalware_extension"], "m365": ["m365_safe_attachments_enabled"]},
    "UEM-11": {"m365": ["m365_dlp_policies_configured"]},
}

# ============================================================
# 3. Build final control list merging engine + extra checks
# ============================================================
def get_arca_checks(ctrl_id):
    """Get ARCA check IDs for a control, merging engine and extra mappings."""
    checks = {}

    # From engine (translated to ARCA IDs)
    if ctrl_id in engine_checks:
        for provider, fn_list in engine_checks[ctrl_id].items():
            prov_key = provider
            if prov_key == "oracle":
                prov_key = "oci"
            arca_ids = []
            for fn in fn_list:
                arca_id = ENGINE_TO_ARCA.get(fn)
                if arca_id and arca_id not in arca_ids:
                    arca_ids.append(arca_id)
            if arca_ids:
                checks[prov_key] = list(set(checks.get(prov_key, []) + arca_ids))

    # From extra mappings
    if ctrl_id in EXTRA_ARCA_CHECKS:
        for provider, check_ids in EXTRA_ARCA_CHECKS[ctrl_id].items():
            existing = checks.get(provider, [])
            for cid in check_ids:
                if cid not in existing:
                    existing.append(cid)
            if existing:
                checks[provider] = existing

    return checks

# ============================================================
# 4. Generate Python code for the CCM-4.1 framework
# ============================================================
lines = []
lines.append('    # ═══════════════════════════════════════════════════════════════════')
lines.append('    # CSA Cloud Controls Matrix (CCM) v4.1 — 207 controls, 17 domains')
lines.append('    # ═══════════════════════════════════════════════════════════════════')
lines.append('    "CCM-4.1": {')
lines.append('        "name": "CSA Cloud Controls Matrix v4.1",')
lines.append('        "description": "Cloud Security Alliance Cloud Controls Matrix v4.1 — 207 security controls across 17 domains for cloud computing, aligned with ISO 27001/27002, NIST SP 800-53, PCI-DSS, and AICPA TSC.",')
lines.append('        "category": "industry",')
lines.append('        "controls": [')

current_domain = None
for ctrl in controls_raw:
    checks = get_arca_checks(ctrl["id"])

    # Add domain separator comment
    if ctrl["domain_id"] != current_domain:
        current_domain = ctrl["domain_id"]
        lines.append(f'            # ─── {current_domain}: {ctrl["domain"]} ───')

    # Escape description for Python string
    desc = ctrl["description"].replace('"', '\\"').replace("'", "\\'")
    # Truncate very long descriptions
    if len(desc) > 200:
        desc = desc[:197] + "..."

    lines.append('            {')
    lines.append(f'                "id": "{ctrl["id"]}",')
    lines.append(f'                "domain": "{ctrl["domain"]}",')
    lines.append(f'                "title": "{ctrl["title"]}",')
    lines.append(f'                "description": "{desc}",')

    if checks:
        checks_parts = []
        for prov in sorted(checks.keys()):
            check_list = ', '.join(f'"{c}"' for c in sorted(checks[prov]))
            checks_parts.append(f'"{prov}": [{check_list}]')
        checks_str = ', '.join(checks_parts)
        lines.append(f'                "checks": {{{checks_str}}},')
    else:
        lines.append('                "checks": {},')

    lines.append('            },')

lines.append('        ],')
lines.append('    },')

output = '\n'.join(lines)

# Count stats
total_with_checks = sum(1 for c in controls_raw if get_arca_checks(c["id"]))
all_check_ids = set()
for c in controls_raw:
    for prov_checks in get_arca_checks(c["id"]).values():
        all_check_ids.update(prov_checks)

print(f"Total controls: {len(controls_raw)}")
print(f"Controls with automated checks: {total_with_checks}")
print(f"Unique check IDs referenced: {len(all_check_ids)}")
print(f"Generated {len(lines)} lines of Python code")

# Write to temp file
with open("/tmp/ccm41_framework.py", "w") as f:
    f.write(output)

print("\nSaved to /tmp/ccm41_framework.py")
