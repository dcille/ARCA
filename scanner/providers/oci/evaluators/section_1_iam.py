"""CIS OCI v3.1 Section 1 — Identity and Access Management (17 controls).

Automated: 1.2, 1.3, 1.4, 1.7, 1.8, 1.9, 1.10, 1.12, 1.16, 1.17
Manual:    1.1, 1.5, 1.6, 1.11, 1.13, 1.14, 1.15
"""
from __future__ import annotations
from .base import (OCIClientCache, EvalConfig, make_result, make_manual_result,
                   days_since, logger)


# ── 1.1 Service-level admins created (Manual) ──

def evaluate_1_1(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.1",
        "Ensure service level admins are created to manage resources of particular service",
        service="IAM", severity="medium")]


# ── 1.2 Permissions only to tenancy admin group (Automated) ──

def evaluate_1_2(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    policies = clients.identity.list_policies(cfg.tenancy_id).data
    for p in policies:
        for stmt in (p.statements or []):
            s = stmt.lower()
            if "manage all-resources" in s and "tenancy" in s:
                # Check it's granted only to Administrators
                if "administrators" not in s:
                    results.append(make_result("1.2",
                        "Permissions on all resources given only to tenancy administrator group",
                        p.id, p.name, False,
                        f"Policy '{p.name}' grants 'manage all-resources' to non-Administrators group",
                        severity="critical", service="IAM",
                        remediation="Restrict 'manage all-resources in tenancy' to Administrators group only"))
    if not results:
        results.append(make_result("1.2",
            "Permissions on all resources given only to tenancy administrator group",
            cfg.tenancy_id, "IAM Policies", True,
            "No non-admin 'manage all-resources' statements found",
            severity="critical", service="IAM"))
    return results


# ── 1.3 IAM admins cannot update tenancy Administrators group (Automated) ──

def evaluate_1_3(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    policies = clients.identity.list_policies(cfg.tenancy_id).data
    violation = False
    for p in policies:
        for stmt in (p.statements or []):
            s = stmt.lower()
            if ("manage" in s or "use" in s) and "groups" in s and "administrators" not in s:
                if "where" not in s or "target.group.name" not in s:
                    violation = True
                    results.append(make_result("1.3",
                        "IAM administrators cannot update tenancy Administrators group",
                        p.id, p.name, False,
                        f"Policy '{p.name}' may allow non-admins to modify the Administrators group",
                        severity="critical", service="IAM",
                        remediation="Add condition: where target.group.name != 'Administrators'"))
    if not violation:
        results.append(make_result("1.3",
            "IAM administrators cannot update tenancy Administrators group",
            cfg.tenancy_id, "IAM Policies", True, severity="critical", service="IAM"))
    return results


# ── 1.4 Password policy min length >= 14 (Automated) ──

def evaluate_1_4(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    auth_policy = clients.identity.get_authentication_policy(cfg.tenancy_id).data
    pp = auth_policy.password_policy
    min_len = getattr(pp, 'minimum_password_length', 0) or 0
    return [make_result("1.4",
        "IAM password policy requires minimum length of 14 or greater",
        cfg.tenancy_id, "Authentication Policy", min_len >= 14,
        f"Minimum password length: {min_len}",
        severity="medium", service="IAM",
        remediation="Set minimum password length to 14 or greater")]


# ── 1.5 Password expires within 365 days (Manual) ──

def evaluate_1_5(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.5",
        "Ensure IAM password policy expires passwords within 365 days",
        service="IAM", severity="medium")]


# ── 1.6 Password reuse prevention (Manual) ──

def evaluate_1_6(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.6",
        "Ensure IAM password policy prevents password reuse",
        service="IAM", severity="medium")]


# ── 1.7 MFA enabled for all console users (Automated) ──

def evaluate_1_7(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    users = clients.identity.list_users(cfg.tenancy_id).data
    for u in users:
        if u.lifecycle_state != "ACTIVE":
            continue
        mfa = getattr(u, 'is_mfa_activated', False) or False
        results.append(make_result("1.7",
            "MFA is enabled for all users with a console password",
            u.id, u.name, mfa,
            f"User {u.name}: MFA {'enabled' if mfa else 'NOT enabled'}",
            severity="critical", service="IAM",
            remediation="Enable MFA for all local IAM users"))
    return results


# ── 1.8 API keys rotate within 90 days (Automated) ──

def evaluate_1_8(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    users = clients.identity.list_users(cfg.tenancy_id).data
    for u in users:
        if u.lifecycle_state != "ACTIVE":
            continue
        api_keys = clients.identity.list_api_keys(u.id).data
        for k in api_keys:
            age = days_since(k.time_created)
            results.append(make_result("1.8",
                "User API keys rotate within 90 days",
                k.key_id, u.name, age <= 90,
                f"API key for {u.name} is {age} days old",
                severity="high", service="IAM",
                remediation="Rotate API keys every 90 days or less"))
    return results


# ── 1.9 Customer secret keys rotate every 90 days (Automated) ──

def evaluate_1_9(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    users = clients.identity.list_users(cfg.tenancy_id).data
    for u in users:
        if u.lifecycle_state != "ACTIVE":
            continue
        skeys = clients.identity.list_customer_secret_keys(u.id).data
        for sk in skeys:
            age = days_since(sk.time_created)
            results.append(make_result("1.9",
                "User customer secret keys rotate every 90 days",
                sk.id, u.name, age <= 90,
                f"Secret key for {u.name} is {age} days old",
                severity="high", service="IAM",
                remediation="Rotate customer secret keys every 90 days"))
    return results


# ── 1.10 Auth tokens rotate within 90 days (Automated) ──

def evaluate_1_10(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    users = clients.identity.list_users(cfg.tenancy_id).data
    for u in users:
        if u.lifecycle_state != "ACTIVE":
            continue
        tokens = clients.identity.list_auth_tokens(u.id).data
        for t in tokens:
            age = days_since(t.time_created)
            results.append(make_result("1.10",
                "User auth tokens rotate within 90 days or less",
                t.id, u.name, age <= 90,
                f"Auth token for {u.name} is {age} days old",
                severity="high", service="IAM",
                remediation="Rotate auth tokens every 90 days or less"))
    return results


# ── 1.11 IAM Database Passwords rotate within 90 days (Manual) ──

def evaluate_1_11(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.11",
        "Ensure user IAM Database Passwords rotate within 90 days",
        service="IAM", severity="high")]


# ── 1.12 API keys not created for tenancy admin users (Automated) ──

def evaluate_1_12(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    groups = clients.identity.list_groups(cfg.tenancy_id).data
    admin_group = next((g for g in groups if g.name == "Administrators"), None)
    if not admin_group:
        return [make_result("1.12",
            "API keys are not created for tenancy administrator users",
            cfg.tenancy_id, "Administrators", True,
            "No Administrators group found", severity="critical", service="IAM")]

    members = clients.identity.list_user_group_memberships(
        cfg.tenancy_id, group_id=admin_group.id).data
    for m in members:
        user = clients.identity.get_user(m.user_id).data
        api_keys = clients.identity.list_api_keys(user.id).data
        active = [k for k in api_keys if k.lifecycle_state == "ACTIVE"]
        results.append(make_result("1.12",
            "API keys are not created for tenancy administrator users",
            user.id, user.name, len(active) == 0,
            f"Admin user {user.name} has {len(active)} active API key(s)",
            severity="critical", service="IAM",
            remediation="Remove API keys from tenancy administrator users"))
    return results


# ── 1.13 All local users have valid email (Manual) ──

def evaluate_1_13(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.13",
        "Ensure all OCI IAM local user accounts have a valid and current email address",
        service="IAM", severity="medium")]


# ── 1.14 Instance Principal authentication (Manual) ──

def evaluate_1_14(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.14",
        "Ensure Instance Principal authentication is used for OCI instances, databases and functions",
        service="IAM", severity="medium")]


# ── 1.15 Storage admins cannot delete managed resources (Manual) ──

def evaluate_1_15(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.15",
        "Ensure storage service-level admins cannot delete resources they manage",
        service="IAM", severity="medium")]


# ── 1.16 Credentials unused 45+ days are disabled (Automated) ──

def evaluate_1_16(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    users = clients.identity.list_users(cfg.tenancy_id).data
    for u in users:
        if u.lifecycle_state != "ACTIVE":
            continue
        last_login = getattr(u, 'last_successful_login_time', None)
        inactive = days_since(last_login)
        if last_login is not None:
            results.append(make_result("1.16",
                "OCI IAM credentials unused for 45 days or more are disabled",
                u.id, u.name, inactive <= 45,
                f"User {u.name} last login {inactive} days ago",
                severity="high", service="IAM",
                remediation="Disable or remove user accounts inactive for 45+ days"))
    return results


# ── 1.17 Only one active API key per user (Automated) ──

def evaluate_1_17(clients: OCIClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    users = clients.identity.list_users(cfg.tenancy_id).data
    for u in users:
        if u.lifecycle_state != "ACTIVE":
            continue
        api_keys = clients.identity.list_api_keys(u.id).data
        active = [k for k in api_keys if k.lifecycle_state == "ACTIVE"]
        results.append(make_result("1.17",
            "There is only one active API Key for any single OCI IAM user",
            u.id, u.name, len(active) <= 1,
            f"User {u.name} has {len(active)} active API key(s)",
            severity="medium", service="IAM",
            remediation="Remove extra API keys so each user has at most one active key"))
    return results


SECTION_1_EVALUATORS = {
    "1.1": evaluate_1_1, "1.2": evaluate_1_2, "1.3": evaluate_1_3,
    "1.4": evaluate_1_4, "1.5": evaluate_1_5, "1.6": evaluate_1_6,
    "1.7": evaluate_1_7, "1.8": evaluate_1_8, "1.9": evaluate_1_9,
    "1.10": evaluate_1_10, "1.11": evaluate_1_11, "1.12": evaluate_1_12,
    "1.13": evaluate_1_13, "1.14": evaluate_1_14, "1.15": evaluate_1_15,
    "1.16": evaluate_1_16, "1.17": evaluate_1_17,
}
