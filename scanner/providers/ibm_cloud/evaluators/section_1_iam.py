"""CIS IBM Cloud v2.0.0 Section 1: Identity and Access Management — 20 controls.

Automated (3): 1.16, 1.17, 1.18
Manual (17): 1.1–1.15, 1.19, 1.20
"""

import logging
from .base import IBMCloudClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-IBM-Cloud-2.0"]


# ── 1.1 — Monitor account owner logins (MANUAL) ──
def evaluate_cis_1_1(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.1", "ibm_cis_1_1",
        "Monitor account owner for frequent, unexpected, or unauthorized logins",
        "iam", "medium", cfg.account_id,
        "Requires reviewing IBM Cloud Logs / Activity Tracker for login events.")]


# ── 1.2 — API keys unused for 180 days (MANUAL) ──
def evaluate_cis_1_2(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.2", "ibm_cis_1_2",
        "Ensure API keys unused for 180 days are detected and optionally disabled",
        "iam", "medium", cfg.account_id,
        "Requires reviewing the Inactive Identities report in IAM console.")]


# ── 1.3 — API keys rotated every 90 days (MANUAL) ──
def evaluate_cis_1_3(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.3", "ibm_cis_1_3",
        "Ensure API keys are rotated every 90 days",
        "iam", "high", cfg.account_id,
        "Requires checking API key creation dates and rotation schedule via IAM console.")]


# ── 1.4 — Restrict API key / service ID creation (MANUAL) ──
def evaluate_cis_1_4(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.4", "ibm_cis_1_4",
        "Restrict user API key creation and service ID creation in the account via IAM roles",
        "iam", "medium", cfg.account_id,
        "Requires verifying IAM settings restrict API key and service ID creation.")]


# ── 1.5 — No owner account API key (MANUAL) ──
def evaluate_cis_1_5(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.5", "ibm_cis_1_5",
        "Ensure no owner account API key exists",
        "iam", "medium", cfg.account_id,
        "Requires reviewing API keys in IAM to confirm no account owner API keys exist.")]


# ── 1.6 — MFA enabled for all users (MANUAL) ──
def evaluate_cis_1_6(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.6", "ibm_cis_1_6",
        "Ensure multi-factor authentication (MFA) is enabled for all users in account",
        "iam", "high", cfg.account_id,
        "Requires checking IAM settings > Authentication to verify MFA is enabled for all users.")]


# ── 1.7 — MFA enabled for account owner and admins (MANUAL) ──
def evaluate_cis_1_7(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.7", "ibm_cis_1_7",
        "Ensure MFA is enabled for the account owner and all administrative users",
        "iam", "high", cfg.account_id,
        "Requires verifying MFA configuration for administrative users via IAM console.")]


# ── 1.8 — MFA enabled at account level (MANUAL) ──
def evaluate_cis_1_8(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.8", "ibm_cis_1_8",
        "Ensure multi-factor authentication (MFA) is enabled at the account level",
        "iam", "high", cfg.account_id,
        "Requires checking IAM Settings > Authentication for account-level MFA setting.")]


# ── 1.9 — Contact email is valid (MANUAL) ──
def evaluate_cis_1_9(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.9", "ibm_cis_1_9",
        "Ensure contact email is valid",
        "iam", "medium", cfg.account_id,
        "Requires verifying account contact email via Account Settings in console.")]


# ── 1.10 — Contact phone number is valid (MANUAL) ──
def evaluate_cis_1_10(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.10", "ibm_cis_1_10",
        "Ensure contact phone number is valid",
        "iam", "medium", cfg.account_id,
        "Requires verifying account contact phone number via Account Settings in console.")]


# ── 1.11 — Use Trusted Profiles over ServiceIDs (MANUAL) ──
def evaluate_cis_1_11(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.11", "ibm_cis_1_11",
        "Ensure Trusted Profiles are used in place of ServiceIDs wherever feasible",
        "iam", "medium", cfg.account_id,
        "Requires reviewing usage of Trusted Profiles vs Service IDs in IAM.")]


# ── 1.12 — Context-Based Restrictions (MANUAL) ──
def evaluate_cis_1_12(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.12", "ibm_cis_1_12",
        "Ensure Context-Based Restrictions are implemented",
        "iam", "medium", cfg.account_id,
        "Requires verifying Context-Based Restriction rules are configured for critical resources.")]


# ── 1.13 — External identity interaction limitations (MANUAL) ──
def evaluate_cis_1_13(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.13", "ibm_cis_1_13",
        "Ensure limitations on External Identity Interactions are Enabled",
        "iam", "medium", cfg.account_id,
        "Requires checking IAM Settings for external identity interaction limitations.")]


# ── 1.14 — IAM policies assigned to groups/profiles (MANUAL) ──
def evaluate_cis_1_14(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.14", "ibm_cis_1_14",
        "Ensure IAM policies are assigned only to access groups or Trusted Profiles",
        "iam", "medium", cfg.account_id,
        "Requires reviewing IAM user policies to ensure they are assigned via access groups.")]


# ── 1.15 — Support access group (MANUAL) ──
def evaluate_cis_1_15(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.15", "ibm_cis_1_15",
        "Ensure a support access group has been created to manage incidents with IBM Support",
        "iam", "medium", cfg.account_id,
        "Requires verifying a support access group exists with appropriate permissions.")]


# ── 1.16 — Minimal admin users (AUTOMATED) ──
def evaluate_cis_1_16(c: IBMCloudClientCache, cfg: EvalConfig):
    """Check that a minimal number of users have administrative privileges."""
    results = []
    try:
        # List all access groups
        groups = c.iam_get("/v2/groups", account_id=cfg.account_id)
        admin_groups = []
        for group in groups.get("groups", []):
            group_id = group.get("id", "")
            # Check policies for each group
            policies_resp = c.iam_get(
                "/v1/policies",
                account_id=cfg.account_id,
                access_group_id=group_id,
                type="access",
            )
            for policy in policies_resp.get("policies", []):
                roles = [r.get("display_name", "") for r in policy.get("roles", [])]
                if "Administrator" in roles:
                    admin_groups.append(group.get("name", group_id))
                    break

        # List users in admin groups and count
        admin_user_count = 0
        for group in groups.get("groups", []):
            group_id = group.get("id", "")
            if group.get("name", group_id) in admin_groups:
                members = c.iam_get(f"/v2/groups/{group_id}/members", account_id=cfg.account_id)
                admin_user_count += len(members.get("members", []))

        ok = admin_user_count <= 5
        results.append(make_result(
            cis_id="1.16", check_id="ibm_cis_1_16",
            title="Ensure Minimal Number of Users are Granted Administrative Privileges",
            service="iam", severity="critical",
            status="PASS" if ok else "FAIL",
            resource_id=cfg.account_id,
            status_extended=f"Found {admin_user_count} users with administrative privileges via access groups (threshold: 5)",
            remediation="Review and reduce the number of users with Administrator role. Use access groups with least privilege.",
            compliance_frameworks=FW,
        ))
    except Exception as e:
        logger.warning("1.16 evaluation failed: %s", e)
        results.append(make_result(
            cis_id="1.16", check_id="ibm_cis_1_16",
            title="Ensure Minimal Number of Users are Granted Administrative Privileges",
            service="iam", severity="critical", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to evaluate admin users: {e}",
            compliance_frameworks=FW,
        ))
    return results


# ── 1.17 — Minimal admin service IDs (AUTOMATED) ──
def evaluate_cis_1_17(c: IBMCloudClientCache, cfg: EvalConfig):
    """Check that a minimal number of Service IDs have administrative privileges."""
    results = []
    try:
        # List service IDs in the account
        svc_ids = c.iam_get("/v1/serviceids", account_id=cfg.account_id)
        admin_svc_ids = []
        for svc in svc_ids.get("serviceids", []):
            iam_id = svc.get("iam_id", "")
            policies_resp = c.iam_get(
                "/v1/policies",
                account_id=cfg.account_id,
                iam_id=iam_id,
                type="access",
            )
            for policy in policies_resp.get("policies", []):
                roles = [r.get("display_name", "") for r in policy.get("roles", [])]
                if "Administrator" in roles:
                    admin_svc_ids.append(svc.get("name", iam_id))
                    break

        ok = len(admin_svc_ids) <= 3
        results.append(make_result(
            cis_id="1.17", check_id="ibm_cis_1_17",
            title="Ensure Minimal Number of Service IDs are Granted Administrative Privileges",
            service="iam", severity="critical",
            status="PASS" if ok else "FAIL",
            resource_id=cfg.account_id,
            status_extended=f"Found {len(admin_svc_ids)} service IDs with administrative privileges (threshold: 3): {', '.join(admin_svc_ids[:10])}",
            remediation="Remove Administrator role from unnecessary Service IDs. Use access groups with least privilege.",
            compliance_frameworks=FW,
        ))
    except Exception as e:
        logger.warning("1.17 evaluation failed: %s", e)
        results.append(make_result(
            cis_id="1.17", check_id="ibm_cis_1_17",
            title="Ensure Minimal Number of Service IDs are Granted Administrative Privileges",
            service="iam", severity="critical", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to evaluate admin service IDs: {e}",
            compliance_frameworks=FW,
        ))
    return results


# ── 1.18 — No public access to cloud services (AUTOMATED) ──
def evaluate_cis_1_18(c: IBMCloudClientCache, cfg: EvalConfig):
    """Check that IAM does not allow public access to cloud services."""
    results = []
    try:
        settings = c.iam_get("/v2/account_settings", account_id=cfg.account_id)
        # Check if public access is disabled
        public_access_enabled = settings.get("public_access_enabled", True)

        if not public_access_enabled:
            results.append(make_result(
                cis_id="1.18", check_id="ibm_cis_1_18",
                title="Ensure IAM Does Not Allow Public Access to Cloud Services",
                service="iam", severity="critical",
                status="PASS", resource_id=cfg.account_id,
                status_extended="Public access group is disabled in IAM settings.",
                remediation="No action required.",
                compliance_frameworks=FW,
            ))
        else:
            # Public access enabled — check if any policies exist in Public Access group
            groups = c.iam_get("/v2/groups", account_id=cfg.account_id)
            public_group = next(
                (g for g in groups.get("groups", []) if g.get("name") == "Public Access"),
                None,
            )
            if public_group:
                policies_resp = c.iam_get(
                    "/v1/policies",
                    account_id=cfg.account_id,
                    access_group_id=public_group["id"],
                    type="access",
                )
                policy_count = len(policies_resp.get("policies", []))
                if policy_count > 0:
                    results.append(make_result(
                        cis_id="1.18", check_id="ibm_cis_1_18",
                        title="Ensure IAM Does Not Allow Public Access to Cloud Services",
                        service="iam", severity="critical",
                        status="FAIL", resource_id=cfg.account_id,
                        status_extended=f"Public access group is enabled and has {policy_count} access policies.",
                        remediation="Disable the Public Access group in IAM Settings or remove all access policies from it.",
                        compliance_frameworks=FW,
                    ))
                else:
                    results.append(make_result(
                        cis_id="1.18", check_id="ibm_cis_1_18",
                        title="Ensure IAM Does Not Allow Public Access to Cloud Services",
                        service="iam", severity="critical",
                        status="PASS", resource_id=cfg.account_id,
                        status_extended="Public access group is enabled but has no access policies.",
                        remediation="Consider disabling the Public Access group if not needed.",
                        compliance_frameworks=FW,
                    ))
            else:
                results.append(make_result(
                    cis_id="1.18", check_id="ibm_cis_1_18",
                    title="Ensure IAM Does Not Allow Public Access to Cloud Services",
                    service="iam", severity="critical",
                    status="PASS", resource_id=cfg.account_id,
                    status_extended="Public Access group not found (public access enabled but no group exists).",
                    compliance_frameworks=FW,
                ))
    except Exception as e:
        logger.warning("1.18 evaluation failed: %s", e)
        results.append(make_result(
            cis_id="1.18", check_id="ibm_cis_1_18",
            title="Ensure IAM Does Not Allow Public Access to Cloud Services",
            service="iam", severity="critical", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to evaluate public access settings: {e}",
            compliance_frameworks=FW,
        ))
    return results


# ── 1.19 — Inactive user accounts suspended (MANUAL) ──
def evaluate_cis_1_19(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.19", "ibm_cis_1_19",
        "Ensure Inactive User Accounts are Suspended",
        "iam", "medium", cfg.account_id,
        "Requires reviewing the Inactive Identities report and suspending dormant accounts.")]


# ── 1.20 — Audit logging for IAM (MANUAL) ──
def evaluate_cis_1_20(c: IBMCloudClientCache, cfg: EvalConfig):
    return [make_manual_result("1.20", "ibm_cis_1_20",
        "Enable audit logging for IBM Cloud Identity and Access Management",
        "iam", "high", cfg.account_id,
        "Requires verifying Activity Tracker / IBM Cloud Logs is configured for IAM events.")]
