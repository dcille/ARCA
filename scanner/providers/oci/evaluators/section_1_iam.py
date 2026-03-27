"""CIS OCI v3.1 Section 1: Identity and Access Management -- 17 controls.

Coverage:
  1.1  Service level admins created                        MANUAL
  1.2  Permissions only to tenancy Administrators group    automated
  1.3  IAM admins cannot update Administrators group       automated
  1.4  Password policy min length >= 14                    automated
  1.5  Password expires within 365 days                    MANUAL
  1.6  Password reuse prevention                           MANUAL
  1.7  MFA enabled for all console users                   automated
  1.8  User API keys rotate within 90 days                 automated
  1.9  Customer secret keys rotate within 90 days          automated
  1.10 Auth tokens rotate within 90 days                   automated
  1.11 IAM Database Passwords rotate within 90 days        MANUAL
  1.12 No API keys for tenancy administrator users         automated
  1.13 All local users have valid email                    MANUAL
  1.14 Instance Principal authentication used              MANUAL
  1.15 Storage admins cannot delete managed resources      MANUAL
  1.16 Credentials unused 45+ days disabled                automated
  1.17 Only one active API key per user                    automated
"""

import logging
from datetime import datetime, timezone

from .base import OCIClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-OCI-3.1"]


# ═══════════════════════════════════════════════════════════════
# 1.1 -- Service level admins created (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_1(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.1", "oci_cis_1_1",
        "Ensure service level admins are created to manage resources of particular service",
        "iam", "medium", cfg.tenancy_id,
        "Requires verifying that distinct service-level admin groups and policies exist. "
        "Check via OCI Console or: oci iam group list / oci iam policy list.")]


# ═══════════════════════════════════════════════════════════════
# 1.2 -- Permissions only to tenancy Administrators group
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_2(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    policies = c.identity.list_policies(cfg.tenancy_id).data
    violating = []
    for policy in policies:
        for stmt in (policy.statements or []):
            lower = stmt.lower()
            if "manage all-resources in tenancy" in lower and "administrators" not in lower:
                violating.append((policy, stmt))
    if violating:
        for policy, stmt in violating:
            results.append(make_result(
                cis_id="1.2", check_id="oci_cis_1_2",
                title="Ensure permissions on all resources are given only to the tenancy administrator group",
                service="iam", severity="medium", status="FAIL",
                resource_id=policy.id, resource_name=policy.name,
                status_extended=f"Policy '{policy.name}' grants 'manage all-resources in tenancy' to non-Administrators group",
                remediation="Remove 'manage all-resources in tenancy' from non-Administrators groups.",
                compliance_frameworks=FW,
            ))
    else:
        results.append(make_result(
            cis_id="1.2", check_id="oci_cis_1_2",
            title="Ensure permissions on all resources are given only to the tenancy administrator group",
            service="iam", severity="medium", status="PASS",
            resource_id=cfg.tenancy_id,
            status_extended="Only Administrators group has 'manage all-resources in tenancy' permission",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 1.3 -- IAM admins cannot update Administrators group
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_3(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    policies = c.identity.list_policies(cfg.tenancy_id).data
    violating = []
    for policy in policies:
        for stmt in (policy.statements or []):
            lower = stmt.lower()
            if ("use users in tenancy" in lower or "use groups in tenancy" in lower
                    or "manage users in tenancy" in lower or "manage groups in tenancy" in lower):
                if "administrators" not in lower or "!=" not in lower:
                    violating.append((policy, stmt))
    if violating:
        for policy, stmt in violating:
            results.append(make_result(
                cis_id="1.3", check_id="oci_cis_1_3",
                title="Ensure IAM administrators cannot update tenancy Administrators group",
                service="iam", severity="medium", status="FAIL",
                resource_id=policy.id, resource_name=policy.name,
                status_extended=f"Policy '{policy.name}' may allow non-admin group to manage Administrators group",
                remediation="Add condition 'where target.group.name != Administrators' to user/group management policies.",
                compliance_frameworks=FW,
            ))
    else:
        results.append(make_result(
            cis_id="1.3", check_id="oci_cis_1_3",
            title="Ensure IAM administrators cannot update tenancy Administrators group",
            service="iam", severity="medium", status="PASS",
            resource_id=cfg.tenancy_id,
            status_extended="All user/group management policies properly exclude Administrators group",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 1.4 -- Password policy min length >= 14
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_4(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    auth_policy = c.identity.get_authentication_policy(cfg.tenancy_id).data
    pw = auth_policy.password_policy
    min_len = getattr(pw, "minimum_password_length", 0) or 0
    status = "PASS" if min_len >= 14 else "FAIL"
    return [make_result(
        cis_id="1.4", check_id="oci_cis_1_4",
        title="Ensure IAM password policy requires minimum length of 14 or greater",
        service="iam", severity="high", status=status,
        resource_id=cfg.tenancy_id, resource_name="Authentication Policy",
        status_extended=f"Minimum password length is {min_len}",
        remediation="Set IAM password policy minimum length to 14 or greater.",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 1.5 -- Password expires within 365 days (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_5(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.5", "oci_cis_1_5",
        "Ensure IAM password policy expires passwords within 365 days",
        "iam", "high", cfg.tenancy_id,
        "Password expiry settings require OCI Console verification under Identity > Authentication Settings.")]


# ═══════════════════════════════════════════════════════════════
# 1.6 -- Password reuse prevention (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_6(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.6", "oci_cis_1_6",
        "Ensure IAM password policy prevents password reuse",
        "iam", "high", cfg.tenancy_id,
        "Password reuse prevention requires OCI Console verification under Identity > Authentication Settings.")]


# ═══════════════════════════════════════════════════════════════
# 1.7 -- MFA enabled for all console users
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_7(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    users = c.identity.list_users(cfg.tenancy_id).data
    console_users = [u for u in users if getattr(u, "can_use_console_password", None)]
    if not console_users:
        return [make_result(
            cis_id="1.7", check_id="oci_cis_1_7",
            title="Ensure MFA is enabled for all users with a console password",
            service="iam", severity="high", status="N/A",
            resource_id=cfg.tenancy_id,
            status_extended="No console users found",
            compliance_frameworks=FW,
        )]
    for user in users:
        mfa = getattr(user, "is_mfa_activated", None)
        if mfa is None:
            continue
        status = "PASS" if mfa else "FAIL"
        results.append(make_result(
            cis_id="1.7", check_id="oci_cis_1_7",
            title="Ensure MFA is enabled for all users with a console password",
            service="iam", severity="high", status=status,
            resource_id=user.id, resource_name=user.name,
            status_extended=f"User {user.name}: MFA {'enabled' if mfa else 'not enabled'}",
            remediation="Enable MFA for all IAM local users via Console or API.",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 1.8 -- API keys rotate within 90 days
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_8(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    users = c.identity.list_users(cfg.tenancy_id).data
    for user in users:
        api_keys = c.identity.list_api_keys(user.id).data
        for key in api_keys:
            if key.lifecycle_state != "ACTIVE":
                continue
            age = (datetime.now(timezone.utc) - key.time_created).days
            status = "FAIL" if age > 90 else "PASS"
            results.append(make_result(
                cis_id="1.8", check_id="oci_cis_1_8",
                title="Ensure user API keys rotate within 90 days",
                service="iam", severity="high", status=status,
                resource_id=key.key_id, resource_name=user.name,
                status_extended=f"API key for {user.name} is {age} days old",
                remediation="Rotate API keys every 90 days or less.",
                compliance_frameworks=FW,
            ))
    if not results:
        results.append(make_result(
            cis_id="1.8", check_id="oci_cis_1_8",
            title="Ensure user API keys rotate within 90 days",
            service="iam", severity="high", status="N/A",
            resource_id=cfg.tenancy_id,
            status_extended="No active API keys found",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 1.9 -- Customer secret keys rotate within 90 days
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_9(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    users = c.identity.list_users(cfg.tenancy_id).data
    for user in users:
        secret_keys = c.identity.list_customer_secret_keys(user.id).data
        for sk in secret_keys:
            if getattr(sk, "lifecycle_state", "ACTIVE") != "ACTIVE":
                continue
            age = (datetime.now(timezone.utc) - sk.time_created).days
            status = "FAIL" if age > 90 else "PASS"
            results.append(make_result(
                cis_id="1.9", check_id="oci_cis_1_9",
                title="Ensure user customer secret keys rotate every 90 days",
                service="iam", severity="high", status=status,
                resource_id=sk.id, resource_name=user.name,
                status_extended=f"Secret key for {user.name} is {age} days old",
                remediation="Rotate customer secret keys every 90 days.",
                compliance_frameworks=FW,
            ))
    if not results:
        results.append(make_result(
            cis_id="1.9", check_id="oci_cis_1_9",
            title="Ensure user customer secret keys rotate every 90 days",
            service="iam", severity="high", status="N/A",
            resource_id=cfg.tenancy_id,
            status_extended="No customer secret keys found",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 1.10 -- Auth tokens rotate within 90 days
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_10(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    users = c.identity.list_users(cfg.tenancy_id).data
    for user in users:
        tokens = c.identity.list_auth_tokens(user.id).data
        for token in tokens:
            if getattr(token, "lifecycle_state", "ACTIVE") != "ACTIVE":
                continue
            age = (datetime.now(timezone.utc) - token.time_created).days
            status = "FAIL" if age > 90 else "PASS"
            results.append(make_result(
                cis_id="1.10", check_id="oci_cis_1_10",
                title="Ensure user auth tokens rotate within 90 days or less",
                service="iam", severity="high", status=status,
                resource_id=token.id, resource_name=user.name,
                status_extended=f"Auth token for {user.name} is {age} days old",
                remediation="Rotate auth tokens every 90 days or less.",
                compliance_frameworks=FW,
            ))
    if not results:
        results.append(make_result(
            cis_id="1.10", check_id="oci_cis_1_10",
            title="Ensure user auth tokens rotate within 90 days or less",
            service="iam", severity="high", status="N/A",
            resource_id=cfg.tenancy_id,
            status_extended="No auth tokens found",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 1.11 -- IAM Database Passwords rotate within 90 days (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_11(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.11", "oci_cis_1_11",
        "Ensure user IAM Database Passwords rotate within 90 days",
        "iam", "high", cfg.tenancy_id,
        "IAM Database passwords are not queryable via API. Verify rotation in OCI Console.")]


# ═══════════════════════════════════════════════════════════════
# 1.12 -- No API keys for tenancy administrator users
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_12(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    groups = c.identity.list_groups(cfg.tenancy_id).data
    admin_group = next((g for g in groups if g.name == "Administrators"), None)
    if not admin_group:
        return [make_result(
            cis_id="1.12", check_id="oci_cis_1_12",
            title="Ensure API keys are not created for tenancy administrator users",
            service="iam", severity="medium", status="N/A",
            resource_id=cfg.tenancy_id,
            status_extended="No Administrators group found",
            compliance_frameworks=FW,
        )]
    members = c.identity.list_user_group_memberships(cfg.tenancy_id, group_id=admin_group.id).data
    for member in members:
        user = c.identity.get_user(member.user_id).data
        api_keys = c.identity.list_api_keys(user.id).data
        active_keys = [k for k in api_keys if k.lifecycle_state == "ACTIVE"]
        status = "FAIL" if active_keys else "PASS"
        results.append(make_result(
            cis_id="1.12", check_id="oci_cis_1_12",
            title="Ensure API keys are not created for tenancy administrator users",
            service="iam", severity="medium", status=status,
            resource_id=user.id, resource_name=user.name,
            status_extended=(
                f"Admin user {user.name} has {len(active_keys)} active API key(s)"
                if active_keys else f"Admin user {user.name} has no API keys"
            ),
            remediation="Remove API keys from tenancy administrator users; use service-level admins instead.",
            compliance_frameworks=FW,
        ))
    return results or [make_result(
        cis_id="1.12", check_id="oci_cis_1_12",
        title="Ensure API keys are not created for tenancy administrator users",
        service="iam", severity="medium", status="PASS",
        resource_id=cfg.tenancy_id,
        status_extended="No members in Administrators group",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 1.13 -- All local users have valid email (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_13(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.13", "oci_cis_1_13",
        "Ensure all OCI IAM local user accounts have a valid and current email address",
        "iam", "medium", cfg.tenancy_id,
        "Email validity requires manual verification in OCI Console > Identity > Users.")]


# ═══════════════════════════════════════════════════════════════
# 1.14 -- Instance Principal authentication used (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_14(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.14", "oci_cis_1_14",
        "Ensure Instance Principal authentication is used for OCI instances, OCI Cloud Databases and OCI Functions to access OCI resources",
        "iam", "medium", cfg.tenancy_id,
        "Requires verifying dynamic groups and matching rules for instances, databases, and functions.")]


# ═══════════════════════════════════════════════════════════════
# 1.15 -- Storage admins cannot delete managed resources (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_15(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.15", "oci_cis_1_15",
        "Ensure storage service-level admins cannot delete resources they manage",
        "iam", "high", cfg.tenancy_id,
        "Requires verifying IAM policies use 'where request.permission != *DELETE' for storage admin groups.")]


# ═══════════════════════════════════════════════════════════════
# 1.16 -- Credentials unused 45+ days disabled
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_16(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    users = c.identity.list_users(cfg.tenancy_id).data
    for user in users:
        if user.lifecycle_state != "ACTIVE":
            continue
        last_login = getattr(user, "last_successful_login_time", None)
        if last_login:
            inactive_days = (datetime.now(timezone.utc) - last_login).days
            status = "FAIL" if inactive_days > 45 else "PASS"
            results.append(make_result(
                cis_id="1.16", check_id="oci_cis_1_16",
                title="Ensure OCI IAM credentials unused for 45 days or more are disabled",
                service="iam", severity="medium", status=status,
                resource_id=user.id, resource_name=user.name,
                status_extended=f"User {user.name} last login {inactive_days} days ago",
                remediation="Disable or remove user accounts inactive for more than 45 days.",
                compliance_frameworks=FW,
            ))
        else:
            # Never logged in -- check creation date
            age = (datetime.now(timezone.utc) - user.time_created).days
            if age > 45:
                results.append(make_result(
                    cis_id="1.16", check_id="oci_cis_1_16",
                    title="Ensure OCI IAM credentials unused for 45 days or more are disabled",
                    service="iam", severity="medium", status="FAIL",
                    resource_id=user.id, resource_name=user.name,
                    status_extended=f"User {user.name} created {age} days ago and never logged in",
                    remediation="Disable or remove user accounts inactive for more than 45 days.",
                    compliance_frameworks=FW,
                ))
    if not results:
        results.append(make_result(
            cis_id="1.16", check_id="oci_cis_1_16",
            title="Ensure OCI IAM credentials unused for 45 days or more are disabled",
            service="iam", severity="medium", status="N/A",
            resource_id=cfg.tenancy_id,
            status_extended="No active users found",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 1.17 -- Only one active API key per user
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_17(c: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    users = c.identity.list_users(cfg.tenancy_id).data
    for user in users:
        api_keys = c.identity.list_api_keys(user.id).data
        active_keys = [k for k in api_keys if k.lifecycle_state == "ACTIVE"]
        status = "FAIL" if len(active_keys) > 1 else "PASS"
        results.append(make_result(
            cis_id="1.17", check_id="oci_cis_1_17",
            title="Ensure there is only one active API Key for any single OCI IAM user",
            service="iam", severity="medium", status=status,
            resource_id=user.id, resource_name=user.name,
            status_extended=f"User {user.name} has {len(active_keys)} active API key(s)",
            remediation="Remove extra API keys so each user has at most one active key.",
            compliance_frameworks=FW,
        ))
    return results or [make_result(
        cis_id="1.17", check_id="oci_cis_1_17",
        title="Ensure there is only one active API Key for any single OCI IAM user",
        service="iam", severity="medium", status="N/A",
        resource_id=cfg.tenancy_id,
        status_extended="No users found",
        compliance_frameworks=FW,
    )]
