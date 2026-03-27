"""CIS OCI v3.1 Section 4 — Logging and Monitoring (18 controls).

All Automated. 4.3–4.12 and 4.18 check event rules for specific resource changes.
"""
from __future__ import annotations
from .base import (OCIClientCache, EvalConfig, make_result, logger)


# ── Helper: collect all active event rules ──

def _collect_event_rules(clients: OCIClientCache, cfg: EvalConfig) -> list:
    """Gather all active event rules across compartments."""
    all_rules = []
    for cid in cfg.compartment_ids[:20]:  # limit for perf
        try:
            rules = clients.events.list_rules(cid).data
            all_rules.extend([r for r in rules if r.lifecycle_state == "ACTIVE"])
        except Exception:
            pass
    return all_rules


def _check_event_rule(rules, event_types, cis_id, title, cfg):
    """Check if any rule covers the given event types."""
    covered = False
    for rule in rules:
        cond = (getattr(rule, 'condition', '') or '').lower()
        if any(et.lower() in cond for et in event_types):
            covered = True
            break
    return [make_result(cis_id, title,
        cfg.tenancy_id, f"Event Rule - {title}", covered,
        f"Event rule for {title}: {'configured' if covered else 'NOT found'}",
        severity="medium", service="Logging",
        remediation=f"Create an Event Rule for {title} and route to a notification topic")]


# ── 4.1 Default tags on resources (Automated) ──

def evaluate_4_1(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        tag_defaults = clients.identity.list_tag_defaults(cfg.tenancy_id).data
        has_defaults = len(tag_defaults) > 0
        results.append(make_result("4.1",
            "Ensure default tags are used on resources",
            cfg.tenancy_id, "Tag Defaults", has_defaults,
            f"{len(tag_defaults)} default tag(s) configured",
            severity="low", service="Logging",
            remediation="Create tag defaults in the root compartment"))
    except Exception as e:
        logger.warning(f"Tag defaults check: {e}")
    return results


# ── 4.2 Notification topic + subscription (Automated) ──

def evaluate_4_2(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    total_topics = 0
    for cid in cfg.compartment_ids[:10]:
        try:
            topics = clients.ons.list_topics(cid).data
            total_topics += len(topics)
        except Exception:
            pass
    results.append(make_result("4.2",
        "At least one notification topic and subscription to receive monitoring alerts",
        cfg.tenancy_id, "Notifications", total_topics > 0,
        f"{total_topics} notification topic(s) found",
        severity="high", service="Logging",
        remediation="Create a notification topic and add subscriptions for security alerts"))
    return results


# ── 4.3–4.12 Event rule checks (Automated) ──

_EVENT_CHECKS = {
    "4.3": ("Identity Provider changes", [
        "com.oraclecloud.identitycontrolplane.createidentityprovider",
        "com.oraclecloud.identitycontrolplane.deleteidentityprovider",
        "com.oraclecloud.identitycontrolplane.updateidentityprovider"]),
    "4.4": ("IdP group mapping changes", [
        "com.oraclecloud.identitycontrolplane.createidpgroupmapping",
        "com.oraclecloud.identitycontrolplane.deleteidpgroupmapping",
        "com.oraclecloud.identitycontrolplane.updateidpgroupmapping"]),
    "4.5": ("IAM group changes", [
        "com.oraclecloud.identitycontrolplane.creategroup",
        "com.oraclecloud.identitycontrolplane.deletegroup",
        "com.oraclecloud.identitycontrolplane.updategroup",
        "com.oraclecloud.identitycontrolplane.addusertogroupmembership",
        "com.oraclecloud.identitycontrolplane.removeuserfromgroupmembership"]),
    "4.6": ("IAM policy changes", [
        "com.oraclecloud.identitycontrolplane.createpolicy",
        "com.oraclecloud.identitycontrolplane.deletepolicy",
        "com.oraclecloud.identitycontrolplane.updatepolicy"]),
    "4.7": ("user changes", [
        "com.oraclecloud.identitycontrolplane.createuser",
        "com.oraclecloud.identitycontrolplane.deleteuser",
        "com.oraclecloud.identitycontrolplane.updateuser",
        "com.oraclecloud.identitycontrolplane.updateusercapabilities",
        "com.oraclecloud.identitycontrolplane.updateuserstate"]),
    "4.8": ("VCN changes", [
        "com.oraclecloud.virtualnetwork.createvcn",
        "com.oraclecloud.virtualnetwork.deletevcn",
        "com.oraclecloud.virtualnetwork.updatevcn"]),
    "4.9": ("route table changes", [
        "com.oraclecloud.virtualnetwork.createroutetable",
        "com.oraclecloud.virtualnetwork.deleteroutetable",
        "com.oraclecloud.virtualnetwork.updateroutetable",
        "com.oraclecloud.virtualnetwork.changeroutetablecompartment"]),
    "4.10": ("security list changes", [
        "com.oraclecloud.virtualnetwork.createsecuritylist",
        "com.oraclecloud.virtualnetwork.deletesecuritylist",
        "com.oraclecloud.virtualnetwork.updatesecuritylist",
        "com.oraclecloud.virtualnetwork.changesecuritylistcompartment"]),
    "4.11": ("network security group changes", [
        "com.oraclecloud.virtualnetwork.createnetworksecuritygroup",
        "com.oraclecloud.virtualnetwork.deletenetworksecuritygroup",
        "com.oraclecloud.virtualnetwork.updatenetworksecuritygroup",
        "com.oraclecloud.virtualnetwork.updatenetworksecuritygroupsecurityrules"]),
    "4.12": ("network gateway changes", [
        "com.oraclecloud.virtualnetwork.createinternetgateway",
        "com.oraclecloud.virtualnetwork.deleteinternetgateway",
        "com.oraclecloud.virtualnetwork.updateinternetgateway",
        "com.oraclecloud.virtualnetwork.createnatgateway",
        "com.oraclecloud.virtualnetwork.deletenatgateway",
        "com.oraclecloud.virtualnetwork.updatenatgateway",
        "com.oraclecloud.virtualnetwork.createlocalpeeringgateway",
        "com.oraclecloud.virtualnetwork.deletelocalpeeringgateway"]),
}

def _make_event_evaluator(cis_id, title, event_types):
    def evaluator(clients, cfg, _rules_cache=[]):
        if not _rules_cache:
            _rules_cache.extend(_collect_event_rules(clients, cfg))
        return _check_event_rule(_rules_cache, event_types, cis_id,
            f"Notification configured for {title}", cfg)
    evaluator.__name__ = f"evaluate_{cis_id.replace('.', '_')}"
    return evaluator


# ── 4.13 VCN flow logging enabled for all subnets (Automated) ──

def evaluate_4_13(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for cid in cfg.compartment_ids:
        try:
            vcns = clients.vcn.list_vcns(cid).data
            for vcn in vcns:
                subnets = clients.vcn.list_subnets(cid, vcn_id=vcn.id).data
                for subnet in subnets:
                    # Check if flow logs are enabled via logging service
                    flow_enabled = False
                    try:
                        logs = clients.logging_mgmt.list_logs(
                            log_group_id=None,  # search all
                            log_type="SERVICE",
                            source_service="flowlogs",
                            source_resource=subnet.id,
                        ).data
                        flow_enabled = len(logs) > 0
                    except Exception:
                        # Fallback: can't determine, mark as needing check
                        pass
                    results.append(make_result("4.13",
                        "VCN flow logging is enabled for all subnets",
                        subnet.id, subnet.display_name or vcn.display_name, flow_enabled,
                        severity="medium", service="Logging",
                        remediation="Enable VCN flow logs via the OCI Logging service for each subnet"))
        except Exception as e:
            logger.warning(f"VCN flow logs check compartment {cid}: {e}")
    return results


# ── 4.14 Cloud Guard enabled in root compartment (Automated) ──

def evaluate_4_14(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    try:
        cg_cfg = clients.cloud_guard.get_configuration(cfg.tenancy_id).data
        enabled = cg_cfg.status == "ENABLED"
        return [make_result("4.14",
            "Cloud Guard is enabled in the root compartment of the tenancy",
            cfg.tenancy_id, "Cloud Guard", enabled,
            f"Cloud Guard status: {cg_cfg.status}",
            severity="critical", service="Logging",
            remediation="Enable Cloud Guard in the OCI console for threat detection")]
    except Exception as e:
        return [make_result("4.14",
            "Cloud Guard is enabled in the root compartment of the tenancy",
            cfg.tenancy_id, "Cloud Guard", False,
            f"Could not verify Cloud Guard status: {e}",
            severity="critical", service="Logging",
            remediation="Enable Cloud Guard in the OCI console")]


# ── 4.15 Notification for Cloud Guard problems (Automated) ──

def evaluate_4_15(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    rules = _collect_event_rules(clients, cfg)
    cg_events = ["com.oraclecloud.cloudguard.problemdetected"]
    return _check_event_rule(rules, cg_events, "4.15",
        "Notification configured for Oracle Cloud Guard problems detected", cfg)


# ── 4.16 CMK rotated at least annually (Automated) ──

def evaluate_4_16(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    from .base import days_since
    results = []
    for cid in cfg.compartment_ids:
        try:
            vaults = clients.kms_vault.list_vaults(cid).data
            for vault in vaults:
                if vault.lifecycle_state != "ACTIVE":
                    continue
                kms_mgmt = clients.kms_management(vault.management_endpoint)
                keys = kms_mgmt.list_keys(cid).data
                for key in keys:
                    if key.lifecycle_state != "ENABLED":
                        continue
                    # Get key versions to find last rotation
                    try:
                        versions = kms_mgmt.list_key_versions(key.id).data
                        if versions:
                            latest = max(versions, key=lambda v: v.time_created)
                            age = days_since(latest.time_created)
                            results.append(make_result("4.16",
                                "Customer created CMK is rotated at least annually",
                                key.id, key.display_name, age <= 365,
                                f"Key '{key.display_name}' last rotated {age} days ago",
                                severity="high", service="Logging",
                                remediation="Rotate master encryption keys at least annually"))
                    except Exception:
                        results.append(make_result("4.16",
                            "Customer created CMK is rotated at least annually",
                            key.id, key.display_name, False,
                            "Could not verify key rotation status",
                            severity="high", service="Logging"))
        except Exception as e:
            logger.warning(f"CMK rotation check compartment {cid}: {e}")
    return results


# ── 4.17 Write level Object Storage logging enabled (Automated) ──

def evaluate_4_17(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        namespace = clients.object_storage.get_namespace().data
        for cid in cfg.compartment_ids:
            try:
                buckets = clients.object_storage.list_buckets(namespace, cid).data
                for bs in buckets:
                    bucket = clients.object_storage.get_bucket(namespace, bs.name).data
                    events_enabled = getattr(bucket, 'object_events_enabled', False)
                    results.append(make_result("4.17",
                        "Write level Object Storage logging is enabled for all buckets",
                        bucket.name, bucket.name, events_enabled,
                        f"Bucket '{bucket.name}' object events: {'enabled' if events_enabled else 'disabled'}",
                        severity="medium", service="Logging",
                        remediation="Enable object event emission for audit logging on all buckets"))
            except Exception as e:
                logger.warning(f"Bucket logging check compartment {cid}: {e}")
    except Exception as e:
        logger.warning(f"Object Storage namespace check: {e}")
    return results


# ── 4.18 Notification for Local OCI User Authentication (Automated) ──

def evaluate_4_18(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    rules = _collect_event_rules(clients, cfg)
    auth_events = [
        "com.oraclecloud.identitycontrolplane.interactivelogin",
        "com.oraclecloud.identitycontrolplane.createapikey",
        "com.oraclecloud.identitycontrolplane.createauthtoken",
    ]
    return _check_event_rule(rules, auth_events, "4.18",
        "Notification configured for Local OCI User Authentication", cfg)


# ── Build SECTION_4_EVALUATORS ──

SECTION_4_EVALUATORS = {
    "4.1": evaluate_4_1,
    "4.2": evaluate_4_2,
    "4.13": evaluate_4_13,
    "4.14": evaluate_4_14,
    "4.15": evaluate_4_15,
    "4.16": evaluate_4_16,
    "4.17": evaluate_4_17,
    "4.18": evaluate_4_18,
}

# Add event rule evaluators (4.3–4.12)
for _cis_id, (_title, _events) in _EVENT_CHECKS.items():
    SECTION_4_EVALUATORS[_cis_id] = _make_event_evaluator(_cis_id, _title, _events)
