"""CIS OCI v3.1 Section 4: Logging and Monitoring -- 18 controls.

Coverage:
  4.1  Default tags used on resources                       automated
  4.2  Notification topic and subscription exist            automated
  4.3  Notification for Identity Provider changes           automated
  4.4  Notification for IdP group mapping changes           automated
  4.5  Notification for IAM group changes                   automated
  4.6  Notification for IAM policy changes                  automated
  4.7  Notification for user changes                        automated
  4.8  Notification for VCN changes                         automated
  4.9  Notification for route table changes                 automated
  4.10 Notification for security list changes               automated
  4.11 Notification for NSG changes                         automated
  4.12 Notification for network gateway changes             automated
  4.13 VCN flow logging enabled for all subnets             automated
  4.14 Cloud Guard enabled in root compartment              automated
  4.15 Notification for Cloud Guard problems                automated
  4.16 CMK rotated at least annually                        automated
  4.17 Write-level Object Storage logging enabled           automated
  4.18 Notification for Local OCI User Authentication       automated
"""

import logging
from datetime import datetime, timezone

from .base import OCIClientCache, EvalConfig, make_result

logger = logging.getLogger(__name__)
FW = ["CIS-OCI-3.1"]


# ═══════════════════════════════════════════════════════════════
# 4.1 -- Default tags used on resources
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_1(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    tag_defaults = c.identity.list_tag_defaults(cfg.tenancy_id).data
    if tag_defaults:
        return [make_result(
            cis_id="4.1", check_id="oci_cis_4_1",
            title="Ensure default tags are used on resources",
            service="logging_monitoring", severity="critical", status="PASS",
            resource_id=cfg.tenancy_id,
            status_extended=f"{len(tag_defaults)} default tag rule(s) configured",
            remediation="Define default tags in tag namespaces for resource tracking.",
            compliance_frameworks=FW,
        )]
    return [make_result(
        cis_id="4.1", check_id="oci_cis_4_1",
        title="Ensure default tags are used on resources",
        service="logging_monitoring", severity="critical", status="FAIL",
        resource_id=cfg.tenancy_id,
        status_extended="No default tag rules found",
        remediation="Create tag defaults via Identity > Tag Namespaces > Tag Defaults.",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 4.2 -- Notification topic and subscription exist
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_2(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    total_topics = 0
    for cid in c.list_compartments():
        try:
            topics = c.notifications.list_topics(cid).data
            total_topics += len(topics)
        except Exception:
            pass
    status = "PASS" if total_topics > 0 else "FAIL"
    return [make_result(
        cis_id="4.2", check_id="oci_cis_4_2",
        title="Create at least one notification topic and subscription to receive monitoring alerts",
        service="logging_monitoring", severity="high", status=status,
        resource_id=cfg.tenancy_id,
        status_extended=f"{total_topics} notification topic(s) found",
        remediation="Create a notification topic and subscribe security admins.",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 4.3-4.12, 4.18 -- Event rule notifications
# These controls check that an Events Service rule exists that
# matches specific resource-type + action pairs and routes to
# a notification topic.
# ═══════════════════════════════════════════════════════════════

_EVENT_RULE_CONTROLS = {
    "4.3": {
        "title": "Ensure a notification is configured for Identity Provider changes",
        "condition_key": "com.oraclecloud.identitycontrolplane",
        "actions": ["createidentityprovider", "updateidentityprovider", "deleteidentityprovider"],
    },
    "4.4": {
        "title": "Ensure a notification is configured for IdP group mapping changes",
        "condition_key": "com.oraclecloud.identitycontrolplane",
        "actions": ["createidpgroupmapping", "updateidpgroupmapping", "deleteidpgroupmapping"],
    },
    "4.5": {
        "title": "Ensure a notification is configured for IAM group changes",
        "condition_key": "com.oraclecloud.identitycontrolplane",
        "actions": ["creategroup", "updategroup", "deletegroup"],
    },
    "4.6": {
        "title": "Ensure a notification is configured for IAM policy changes",
        "condition_key": "com.oraclecloud.identitycontrolplane",
        "actions": ["createpolicy", "updatepolicy", "deletepolicy"],
    },
    "4.7": {
        "title": "Ensure a notification is configured for user changes",
        "condition_key": "com.oraclecloud.identitycontrolplane",
        "actions": ["createuser", "updateuser", "deleteuser"],
    },
    "4.8": {
        "title": "Ensure a notification is configured for VCN changes",
        "condition_key": "com.oraclecloud.virtualnetwork",
        "actions": ["createvcn", "updatevcn", "deletevcn"],
    },
    "4.9": {
        "title": "Ensure a notification is configured for changes to route tables",
        "condition_key": "com.oraclecloud.virtualnetwork",
        "actions": ["createroutetable", "updateroutetable", "deleteroutetable"],
    },
    "4.10": {
        "title": "Ensure a notification is configured for security list changes",
        "condition_key": "com.oraclecloud.virtualnetwork",
        "actions": ["createsecuritylist", "updatesecuritylist", "deletesecuritylist"],
    },
    "4.11": {
        "title": "Ensure a notification is configured for network security group changes",
        "condition_key": "com.oraclecloud.virtualnetwork",
        "actions": ["createnetworksecuritygroup", "updatenetworksecuritygroup", "deletenetworksecuritygroup"],
    },
    "4.12": {
        "title": "Ensure a notification is configured for changes to network gateways",
        "condition_key": "com.oraclecloud.virtualnetwork",
        "actions": ["createinternetgateway", "updateinternetgateway", "deleteinternetgateway",
                     "createdrg", "updatedrg", "deletedrg",
                     "createservicegateway", "updateservicegateway", "deleteservicegateway",
                     "createlocalpeering", "updatelocalpeering", "deletelocalpeering",
                     "createnatgateway", "updatenatgateway", "deletenatgateway"],
    },
    "4.18": {
        "title": "Ensure a notification is configured for Local OCI User Authentication",
        "condition_key": "com.oraclecloud.identitycontrolplane",
        "actions": ["createorupdateauthenticationpolicy"],
    },
}


def _evaluate_event_rule(cis_id: str, c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    """Check if an Events Service rule exists for the given control's actions."""
    ctrl = _EVENT_RULE_CONTROLS[cis_id]
    title = ctrl["title"]
    condition_key = ctrl["condition_key"]
    required_actions = set(a.lower() for a in ctrl["actions"])

    found = False
    for cid in c.list_compartments():
        try:
            rules = c.events.list_rules(cid).data
            for rule in rules:
                if not rule.is_enabled:
                    continue
                condition = getattr(rule, "condition", "") or ""
                cond_lower = condition.lower()
                if condition_key.lower() in cond_lower:
                    if any(action in cond_lower for action in required_actions):
                        found = True
                        break
        except Exception:
            pass
        if found:
            break

    return [make_result(
        cis_id=cis_id, check_id=f"oci_cis_{cis_id.replace('.', '_')}",
        title=title,
        service="logging_monitoring", severity="critical",
        status="PASS" if found else "FAIL",
        resource_id=cfg.tenancy_id,
        status_extended=(
            f"Event rule found for {condition_key} actions"
            if found else
            f"No event rule found for {condition_key} actions: {', '.join(ctrl['actions'][:3])}..."
        ),
        remediation=f"Create an Events Service rule matching {condition_key} actions and route to a notification topic.",
        compliance_frameworks=FW,
    )]


def evaluate_cis_4_3(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return _evaluate_event_rule("4.3", c, cfg)

def evaluate_cis_4_4(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return _evaluate_event_rule("4.4", c, cfg)

def evaluate_cis_4_5(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return _evaluate_event_rule("4.5", c, cfg)

def evaluate_cis_4_6(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return _evaluate_event_rule("4.6", c, cfg)

def evaluate_cis_4_7(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return _evaluate_event_rule("4.7", c, cfg)

def evaluate_cis_4_8(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return _evaluate_event_rule("4.8", c, cfg)

def evaluate_cis_4_9(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return _evaluate_event_rule("4.9", c, cfg)

def evaluate_cis_4_10(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return _evaluate_event_rule("4.10", c, cfg)

def evaluate_cis_4_11(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return _evaluate_event_rule("4.11", c, cfg)

def evaluate_cis_4_12(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return _evaluate_event_rule("4.12", c, cfg)

def evaluate_cis_4_18(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return _evaluate_event_rule("4.18", c, cfg)


# ═══════════════════════════════════════════════════════════════
# 4.13 -- VCN flow logging enabled for all subnets
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_13(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    # Collect all enabled flow log subnet OCIDs
    flow_log_subnets: set[str] = set()
    for cid in c.list_compartments():
        try:
            log_groups = c.logging.list_log_groups(cid).data
            for lg in log_groups:
                logs = c.logging.list_logs(lg.id).data
                for log_entry in logs:
                    log_cfg = getattr(log_entry, "configuration", None)
                    if log_cfg:
                        source = getattr(log_cfg, "source", None)
                        if source and getattr(source, "service", "") == "flowlogs":
                            resource = getattr(source, "resource", "")
                            if resource:
                                flow_log_subnets.add(resource)
        except Exception:
            pass

    # Check all subnets
    for cid in c.list_compartments():
        try:
            vcns = c.virtual_network.list_vcns(cid).data
            for vcn in vcns:
                subnets = c.virtual_network.list_subnets(cid, vcn_id=vcn.id).data
                for subnet in subnets:
                    has_flow = subnet.id in flow_log_subnets
                    results.append(make_result(
                        cis_id="4.13", check_id="oci_cis_4_13",
                        title="Ensure VCN flow logging is enabled for all subnets",
                        service="logging_monitoring", severity="high",
                        status="PASS" if has_flow else "FAIL",
                        resource_id=subnet.id,
                        resource_name=subnet.display_name or vcn.display_name,
                        status_extended=f"Subnet '{subnet.display_name}': flow logging {'enabled' if has_flow else 'not enabled'}",
                        remediation="Enable VCN flow logs via the OCI Logging service for each subnet.",
                        compliance_frameworks=FW,
                    ))
        except Exception as e:
            logger.warning("CIS 4.13 compartment %s: %s", cid, e)

    return results or [make_result(
        cis_id="4.13", check_id="oci_cis_4_13",
        title="Ensure VCN flow logging is enabled for all subnets",
        service="logging_monitoring", severity="high", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No subnets found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 4.14 -- Cloud Guard enabled in root compartment
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_14(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    try:
        cg_config = c.cloud_guard.get_configuration(cfg.tenancy_id).data
        is_enabled = cg_config.status == "ENABLED"
    except Exception:
        is_enabled = False

    return [make_result(
        cis_id="4.14", check_id="oci_cis_4_14",
        title="Ensure Cloud Guard is enabled in the root compartment of the tenancy",
        service="logging_monitoring", severity="critical",
        status="PASS" if is_enabled else "FAIL",
        resource_id=cfg.tenancy_id, resource_name="Cloud Guard",
        status_extended=f"Cloud Guard is {'enabled' if is_enabled else 'not enabled'}",
        remediation="Enable Cloud Guard in the OCI console for threat detection.",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 4.15 -- Notification for Cloud Guard problems detected
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_15(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    found = False
    for cid in c.list_compartments():
        try:
            rules = c.events.list_rules(cid).data
            for rule in rules:
                if not rule.is_enabled:
                    continue
                condition = (getattr(rule, "condition", "") or "").lower()
                if "com.oraclecloud.cloudguard" in condition and "problemdetected" in condition:
                    found = True
                    break
        except Exception:
            pass
        if found:
            break

    return [make_result(
        cis_id="4.15", check_id="oci_cis_4_15",
        title="Ensure a notification is configured for Oracle Cloud Guard problems detected",
        service="logging_monitoring", severity="critical",
        status="PASS" if found else "FAIL",
        resource_id=cfg.tenancy_id,
        status_extended=(
            "Event rule for Cloud Guard problemDetected found"
            if found else "No event rule for Cloud Guard problemDetected found"
        ),
        remediation="Create an Events Service rule for Cloud Guard problemDetected and route to notification topic.",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 4.16 -- CMK rotated at least annually
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_16(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in c.list_compartments():
        try:
            vaults = c.kms_vault.list_vaults(cid).data
            for vault in vaults:
                if vault.lifecycle_state != "ACTIVE":
                    continue
                kms_mgmt = c.kms_management(vault.management_endpoint)
                keys = kms_mgmt.list_keys(cid).data
                for key in keys:
                    if key.lifecycle_state != "ENABLED":
                        continue
                    # Check key version age
                    key_detail = kms_mgmt.get_key(key.id).data
                    current_version = getattr(key_detail, "current_key_version", None)
                    if current_version:
                        version_detail = kms_mgmt.get_key_version(key.id, current_version).data
                        version_age = (datetime.now(timezone.utc) - version_detail.time_created).days
                        status = "FAIL" if version_age > 365 else "PASS"
                        ext = f"Key '{key.display_name}' current version is {version_age} days old"
                    else:
                        status = "FAIL"
                        ext = f"Key '{key.display_name}' version age could not be determined"
                    results.append(make_result(
                        cis_id="4.16", check_id="oci_cis_4_16",
                        title="Ensure customer created Customer Managed Key (CMK) is rotated at least annually",
                        service="logging_monitoring", severity="high", status=status,
                        resource_id=key.id, resource_name=key.display_name,
                        status_extended=ext,
                        remediation="Rotate master encryption keys at least annually via OCI Vault.",
                        compliance_frameworks=FW,
                    ))
        except Exception as e:
            logger.warning("CIS 4.16 compartment %s: %s", cid, e)

    return results or [make_result(
        cis_id="4.16", check_id="oci_cis_4_16",
        title="Ensure customer created Customer Managed Key (CMK) is rotated at least annually",
        service="logging_monitoring", severity="high", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No vaults or CMKs found",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 4.17 -- Write-level Object Storage logging enabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_4_17(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    # Collect buckets with write-level logging
    logged_buckets: set[str] = set()
    for cid in c.list_compartments():
        try:
            log_groups = c.logging.list_log_groups(cid).data
            for lg in log_groups:
                logs = c.logging.list_logs(lg.id).data
                for log_entry in logs:
                    log_cfg = getattr(log_entry, "configuration", None)
                    if log_cfg:
                        source = getattr(log_cfg, "source", None)
                        if (source
                            and getattr(source, "service", "") == "objectstorage"
                            and getattr(source, "category", "") in ("write", "all")):
                            resource = getattr(source, "resource", "")
                            if resource:
                                logged_buckets.add(resource)
        except Exception:
            pass

    # Check all buckets
    try:
        namespace = c.object_storage.get_namespace().data
    except Exception:
        return [make_result(
            cis_id="4.17", check_id="oci_cis_4_17",
            title="Ensure write level Object Storage logging is enabled for all buckets",
            service="logging_monitoring", severity="high", status="ERROR",
            resource_id=cfg.tenancy_id,
            status_extended="Could not retrieve Object Storage namespace",
            compliance_frameworks=FW,
        )]

    for cid in c.list_compartments():
        try:
            buckets = c.object_storage.list_buckets(namespace, cid).data
            for bucket_summary in buckets:
                has_logging = bucket_summary.name in logged_buckets
                results.append(make_result(
                    cis_id="4.17", check_id="oci_cis_4_17",
                    title="Ensure write level Object Storage logging is enabled for all buckets",
                    service="logging_monitoring", severity="high",
                    status="PASS" if has_logging else "FAIL",
                    resource_id=bucket_summary.name, resource_name=bucket_summary.name,
                    status_extended=f"Bucket '{bucket_summary.name}': write logging {'enabled' if has_logging else 'not enabled'}",
                    remediation="Enable write-level logging via OCI Logging service for each bucket.",
                    compliance_frameworks=FW,
                ))
        except Exception as e:
            logger.warning("CIS 4.17 compartment %s: %s", cid, e)

    return results or [make_result(
        cis_id="4.17", check_id="oci_cis_4_17",
        title="Ensure write level Object Storage logging is enabled for all buckets",
        service="logging_monitoring", severity="high", status="N/A",
        resource_id=cfg.tenancy_id, status_extended="No buckets found",
        compliance_frameworks=FW,
    )]
