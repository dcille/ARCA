#!/usr/bin/env python3
"""Add missing Azure check mappings to CCM-4.1 controls in frameworks.py."""
import re

FRAMEWORKS_FILE = "scanner/compliance/frameworks.py"

# Mapping: CCM control ID → list of Azure check_ids to ADD
# Based on CSA CCM v4.1 domain semantics and Azure check purposes
AZURE_MAPPINGS = {
    # A&A - Audit & Assurance
    "A&A-01": ["azure_monitor_log_profile", "azure_monitor_log_retention_365"],
    "A&A-03": ["azure_sql_auditing_enabled"],
    "A&A-05": ["azure_monitor_log_retention_365"],

    # AIS - Application & Interface Security
    "AIS-01": ["azure_appservice_https_only", "azure_appservice_tls_12"],
    "AIS-02": ["azure_appservice_client_certs", "azure_appservice_managed_identity"],
    "AIS-04": ["azure_appservice_remote_debugging_off", "azure_appservice_ftp_disabled"],
    "AIS-07": ["azure_appservice_http_logging"],

    # BCR - Business Continuity Management & Operational Resilience
    "BCR-02": ["azure_backup_vault_redundancy", "azure_storage_soft_delete_blobs"],
    "BCR-04": ["azure_storage_soft_delete_blobs"],
    "BCR-08": ["azure_resource_locks_configured"],

    # CCC - Change Control & Configuration Management
    "CCC-01": ["azure_policy_compliance_rate"],
    "CCC-02": ["azure_policy_assignments_exist", "azure_policy_security_initiative"],
    "CCC-04": ["azure_aks_azure_policy_addon"],
    "CCC-05": ["azure_resource_locks_configured"],

    # CEK - Cryptography, Encryption & Key Management
    "CEK-01": ["azure_keyvault_secret_expiration"],
    "CEK-02": ["azure_keyvault_soft_delete", "azure_keyvault_purge_protection"],
    "CEK-03": ["azure_storage_cmk_encryption", "azure_vm_disk_encryption", "azure_sql_tde_enabled", "azure_disk_unattached_encrypted"],
    "CEK-04": ["azure_keyvault_network_acls"],
    "CEK-05": ["azure_storage_https_only", "azure_sql_tls_12", "azure_storage_tls_12"],
    "CEK-06": ["azure_storage_infrastructure_encryption"],
    "CEK-07": ["azure_keyvault_key_expiration", "azure_keyvault_secret_expiration"],
    "CEK-08": ["azure_keyvault_purge_protection"],

    # DSP - Data Security & Privacy Lifecycle Management
    "DSP-01": ["azure_storage_no_public_access", "azure_sql_public_access_disabled"],
    "DSP-04": ["azure_storage_cmk_encryption", "azure_sql_tde_enabled"],
    "DSP-05": ["azure_storage_network_default_deny"],
    "DSP-10": ["azure_storage_no_public_access"],
    "DSP-17": ["azure_vm_disk_encryption", "azure_disk_unattached_encrypted"],

    # GRC - Governance, Risk Management & Compliance
    "GRC-02": ["azure_policy_assignments_exist"],
    "GRC-03": ["azure_policy_compliance_rate"],

    # HRS - Human Resources Security (no direct Azure checks)

    # IAM - Identity & Access Management
    "IAM-01": ["azure_iam_mfa_enabled_all_users"],
    "IAM-02": ["azure_iam_mfa_enabled_all_users", "azure_iam_managed_identity_usage"],
    "IAM-04": ["azure_iam_no_custom_owner_roles", "azure_iam_owner_count"],
    "IAM-05": ["azure_iam_contributor_count", "azure_iam_sp_high_privilege"],
    "IAM-06": ["azure_classic_admins_removed"],
    "IAM-07": ["azure_iam_guest_users_reviewed"],
    "IAM-09": ["azure_sql_ad_admin_configured"],
    "IAM-10": ["azure_keyvault_rbac_authorization"],
    "IAM-13": ["azure_iam_mfa_enabled_all_users"],

    # IPY - Interoperability & Portability
    "IPY-01": ["azure_vm_managed_disks"],

    # IVS - Infrastructure & Virtualization Security
    "IVS-01": ["azure_nsg_default_deny_inbound", "azure_subnet_has_nsg"],
    "IVS-02": ["azure_nsg_flow_logs_enabled", "azure_network_watcher_enabled"],
    "IVS-03": ["azure_vm_no_public_ip", "azure_private_endpoints_used"],
    "IVS-04": ["azure_public_ip_ddos_protection"],
    "IVS-05": ["azure_aks_network_policy", "azure_aks_authorized_ip_ranges"],
    "IVS-06": ["azure_vm_trusted_launch"],
    "IVS-09": ["azure_aks_aad_integration", "azure_aks_rbac_enabled"],

    # LOG - Logging and Monitoring
    "LOG-01": ["azure_monitor_diagnostic_settings", "azure_monitor_log_profile"],
    "LOG-02": ["azure_nsg_flow_logs_enabled"],
    "LOG-03": ["azure_monitor_log_retention_365"],
    "LOG-04": ["azure_security_alert_notifications"],
    "LOG-05": ["azure_appservice_http_logging"],
    "LOG-07": ["azure_sql_auditing_enabled"],
    "LOG-09": ["azure_monitor_diagnostic_settings"],
    "LOG-13": ["azure_security_alert_notifications", "azure_security_contact_configured"],

    # SEF - Security Incident Management
    "SEF-01": ["azure_security_alert_notifications", "azure_security_contact_configured"],
    "SEF-02": ["azure_defender_auto_provisioning"],
    "SEF-03": ["azure_security_contact_configured"],
    "SEF-05": ["azure_security_alert_notifications"],

    # STA - Supply Chain Management
    "STA-07": ["azure_sql_vulnerability_assessment"],
    "STA-14": ["azure_sql_atp_enabled"],

    # TVM - Threat & Vulnerability Management
    "TVM-01": ["azure_sql_vulnerability_assessment", "azure_sql_atp_enabled"],
    "TVM-02": ["azure_defender_auto_provisioning"],
    "TVM-04": ["azure_appgw_waf_enabled"],
    "TVM-07": ["azure_sql_atp_enabled"],
    "TVM-09": ["azure_vm_antimalware_extension"],

    # UEM - Universal Endpoint Management
    "UEM-01": ["azure_vm_managed_disks"],
    "UEM-03": ["azure_vm_trusted_launch"],
    "UEM-06": ["azure_aks_rbac_enabled"],
    "UEM-08": ["azure_storage_shared_key_disabled"],

    # DCS - Datacenter Security
    "DCS-06": ["azure_postgresql_public_access"],
}

with open(FRAMEWORKS_FILE, "r") as f:
    content = f.read()

# Find the CCM-4.1 section
ccm_start = content.find('"CCM-4.1"')
if ccm_start == -1:
    print("ERROR: CCM-4.1 not found")
    exit(1)

# For each control in our mapping, find it in the file and add/update azure checks
changes_made = 0
for ctrl_id, new_checks in AZURE_MAPPINGS.items():
    # Find this control's checks block
    # Pattern: "id": "CTRL_ID", ... "checks": { ... }
    ctrl_pattern = f'"id": "{ctrl_id}"'
    ctrl_pos = content.find(ctrl_pattern, ccm_start)
    if ctrl_pos == -1:
        print(f"WARNING: Control {ctrl_id} not found")
        continue

    # Find the "checks": { block after this control
    checks_start = content.find('"checks": {', ctrl_pos)
    if checks_start == -1 or checks_start - ctrl_pos > 2000:
        print(f"WARNING: No checks block for {ctrl_id}")
        continue

    # Find the closing } of the checks dict
    brace_start = content.find('{', checks_start + 10)
    depth = 1
    pos = brace_start + 1
    while depth > 0 and pos < len(content):
        if content[pos] == '{':
            depth += 1
        elif content[pos] == '}':
            depth -= 1
        pos += 1
    checks_end = pos - 1  # position of closing }

    checks_block = content[brace_start:checks_end + 1]

    # Check if azure already exists
    azure_match = re.search(r'"azure":\s*\[(.*?)\]', checks_block, re.DOTALL)
    if azure_match:
        # Azure exists - merge new checks with existing
        existing = re.findall(r'"([^"]+)"', azure_match.group(1))
        merged = list(dict.fromkeys(existing + new_checks))  # preserve order, deduplicate
        new_azure_str = '"azure": [' + ', '.join(f'"{c}"' for c in merged) + ']'
        old_azure_str = azure_match.group(0)
        content = content[:brace_start + azure_match.start()] + new_azure_str + content[brace_start + azure_match.end():]
        if set(merged) != set(existing):
            changes_made += 1
    else:
        # No azure key - add it
        # Find the last provider entry before closing }
        # Insert before the closing }
        insert_pos = checks_end
        # Check if there's content (other providers)
        inner = checks_block[1:-1].strip()
        azure_entry = '"azure": [' + ', '.join(f'"{c}"' for c in new_checks) + ']'
        if inner:
            # Add after last entry with comma
            content = content[:insert_pos] + ', ' + azure_entry + content[insert_pos:]
        else:
            content = content[:insert_pos] + azure_entry + content[insert_pos:]
        changes_made += 1

with open(FRAMEWORKS_FILE, "w") as f:
    f.write(content)

print(f"Done! Made {changes_made} changes to CCM-4.1 Azure mappings")

# Verify
import importlib.util
spec = importlib.util.spec_from_file_location("frameworks", FRAMEWORKS_FILE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

ccm = mod.FRAMEWORKS.get("CCM-4.1", {})
controls = ccm.get("controls", [])
azure_count = 0
azure_checks = set()
for ctrl in controls:
    checks = ctrl.get("checks", {})
    if "azure" in checks:
        azure_count += 1
        azure_checks.update(checks["azure"])

print(f"Controls with Azure mappings: {azure_count}")
print(f"Unique Azure check_ids: {len(azure_checks)}")
