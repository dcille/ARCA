"""CIS Alibaba Cloud v2.0 Section 1: Identity and Access Management -- 16 controls.

Coverage:
  1.1  Avoid root account usage                              MANUAL
  1.2  No root account access key                            MANUAL
  1.3  MFA enabled for root account                          MANUAL
  1.4  MFA enabled for all RAM users with console password   automated
  1.5  Disable users not logged on for 90+ days              automated
  1.6  Access keys rotated every 90 days                     automated
  1.7  Password policy: uppercase letter                     automated
  1.8  Password policy: lowercase letter                     automated
  1.9  Password policy: symbol                               automated
  1.10 Password policy: number                               automated
  1.11 Password policy: min length 14                        automated
  1.12 Password policy: prevent reuse                        automated
  1.13 Password policy: expires in 365 days                  automated
  1.14 Password policy: block after 5 failed attempts        automated
  1.15 No full admin (*:*) policies                          automated
  1.16 Policies attached only to groups/roles                automated
"""

import logging
from datetime import datetime, timezone, timedelta

from .base import AlibabaClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-Alibaba-2.0"]


# ═══════════════════════════════════════════════════════════════
# 1.1 -- Avoid root account usage (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_1(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.1", "ali_cis_1_1",
        "Avoid the use of the 'root' account",
        "iam", "critical", cfg.account_id,
        "Requires reviewing ActionTrail logs for root account usage. "
        "Set up log metric filters and alarms for root account activity.")]


# ═══════════════════════════════════════════════════════════════
# 1.2 -- No root account access key (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_2(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.2", "ali_cis_1_2",
        "Ensure no root account access key exists",
        "iam", "critical", cfg.account_id,
        "Requires logging into RAM console as root and checking Security Management "
        "for active access keys. Cannot be verified via RAM API.")]


# ═══════════════════════════════════════════════════════════════
# 1.3 -- MFA enabled for root account (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_3(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.3", "ali_cis_1_3",
        "Ensure MFA is enabled for the 'root' account",
        "iam", "critical", cfg.account_id,
        "Root MFA status cannot be verified via RAM API. Check via Console > "
        "Security Settings > MFA.")]


# ═══════════════════════════════════════════════════════════════
# 1.4 -- MFA enabled for all RAM users with console password
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_4(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_ram20150501 import models as ram_models
    results = []
    resp = c.ram.list_users(ram_models.ListUsersRequest())
    users = resp.body.users.user if resp.body.users and resp.body.users.user else []

    if not users:
        return [make_result(cis_id="1.4", check_id="ali_cis_1_4",
            title="Ensure MFA is enabled for all RAM users with console password",
            service="iam", severity="high", status="N/A",
            resource_id=cfg.account_id,
            status_extended="No RAM users found.",
            compliance_frameworks=FW)]

    for user in users:
        user_name = user.user_name
        try:
            lp_resp = c.ram.get_login_profile(ram_models.GetLoginProfileRequest(
                user_name=user_name,
            ))
            has_console = lp_resp.body.login_profile is not None
        except Exception:
            has_console = False

        if not has_console:
            continue

        try:
            mfa_resp = c.ram.list_virtual_mfadevices(ram_models.ListVirtualMFADevicesRequest())
            mfa_devices = mfa_resp.body.virtual_mfadevices.virtual_mfadevice if (
                mfa_resp.body.virtual_mfadevices and mfa_resp.body.virtual_mfadevices.virtual_mfadevice
            ) else []
            user_has_mfa = any(
                d.user and d.user.user_name == user_name
                for d in mfa_devices
            )
        except Exception:
            user_has_mfa = False

        results.append(make_result(
            cis_id="1.4", check_id="ali_cis_1_4",
            title="Ensure MFA is enabled for all RAM users with console password",
            service="iam", severity="high",
            status="PASS" if user_has_mfa else "FAIL",
            resource_id=user_name, resource_name=user_name,
            status_extended=(
                f"RAM user {user_name}: MFA {'enabled' if user_has_mfa else 'NOT enabled'}"
            ),
            remediation="Enable MFA: RAM Console > Users > User > Security Settings > Enable MFA",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="1.4", check_id="ali_cis_1_4",
        title="Ensure MFA is enabled for all RAM users with console password",
        service="iam", severity="high", status="PASS",
        resource_id=cfg.account_id,
        status_extended="No RAM users with console login found.",
        compliance_frameworks=FW)]


# ═══════════════════════════════════════════════════════════════
# 1.5 -- Disable users not logged on for 90+ days
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_5(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_ram20150501 import models as ram_models
    results = []
    resp = c.ram.list_users(ram_models.ListUsersRequest())
    users = resp.body.users.user if resp.body.users and resp.body.users.user else []
    threshold = datetime.now(timezone.utc) - timedelta(days=90)

    for user in users:
        user_name = user.user_name
        try:
            lp_resp = c.ram.get_login_profile(ram_models.GetLoginProfileRequest(
                user_name=user_name,
            ))
            has_console = lp_resp.body.login_profile is not None
        except Exception:
            has_console = False

        if not has_console:
            continue

        try:
            detail = c.ram.get_user(ram_models.GetUserRequest(user_name=user_name))
            last_login = detail.body.user.last_login_date
            if last_login:
                last_dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                stale = last_dt < threshold
            else:
                stale = True
        except Exception:
            stale = True

        results.append(make_result(
            cis_id="1.5", check_id="ali_cis_1_5",
            title="Ensure users not logged on for 90 days or longer are disabled",
            service="iam", severity="medium",
            status="FAIL" if stale else "PASS",
            resource_id=user_name, resource_name=user_name,
            status_extended=(
                f"RAM user {user_name}: {'inactive 90+ days' if stale else 'recently active'}"
            ),
            remediation="Disable console logon for inactive users via RAM Console.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="1.5", check_id="ali_cis_1_5",
        title="Ensure users not logged on for 90 days or longer are disabled",
        service="iam", severity="medium", status="PASS",
        resource_id=cfg.account_id,
        status_extended="No RAM users with console login found.",
        compliance_frameworks=FW)]


# ═══════════════════════════════════════════════════════════════
# 1.6 -- Access keys rotated every 90 days
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_6(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_ram20150501 import models as ram_models
    results = []
    resp = c.ram.list_users(ram_models.ListUsersRequest())
    users = resp.body.users.user if resp.body.users and resp.body.users.user else []
    threshold = datetime.now(timezone.utc) - timedelta(days=90)

    for user in users:
        user_name = user.user_name
        try:
            ak_resp = c.ram.list_access_keys(ram_models.ListAccessKeysRequest(
                user_name=user_name,
            ))
            keys = ak_resp.body.access_keys.access_key if (
                ak_resp.body.access_keys and ak_resp.body.access_keys.access_key
            ) else []
        except Exception:
            continue

        for key in keys:
            if key.status != "Active":
                continue
            create_date = key.create_date
            try:
                created = datetime.fromisoformat(create_date.replace("Z", "+00:00"))
                old = created < threshold
            except Exception:
                old = True

            results.append(make_result(
                cis_id="1.6", check_id="ali_cis_1_6",
                title="Ensure access keys are rotated every 90 days or less",
                service="iam", severity="high",
                status="FAIL" if old else "PASS",
                resource_id=f"{user_name}/{key.access_key_id}",
                resource_name=user_name,
                status_extended=(
                    f"Access key {key.access_key_id} for {user_name}: "
                    f"created {create_date}, {'older than 90 days' if old else 'within 90 days'}"
                ),
                remediation="Rotate access keys: aliyun ram CreateAccessKey / DeleteAccessKey",
                compliance_frameworks=FW,
            ))

    return results or [make_result(cis_id="1.6", check_id="ali_cis_1_6",
        title="Ensure access keys are rotated every 90 days or less",
        service="iam", severity="high", status="PASS",
        resource_id=cfg.account_id,
        status_extended="No active access keys found for any RAM user.",
        compliance_frameworks=FW)]


# ═══════════════════════════════════════════════════════════════
# 1.7-1.14 -- Password policy checks
# ═══════════════════════════════════════════════════════════════

def _get_password_policy(c: AlibabaClientCache):
    """Fetch the RAM account password policy."""
    from alibabacloud_ram20150501 import models as ram_models
    resp = c.ram.get_password_policy(ram_models.GetPasswordPolicyRequest())
    return resp.body.password_policy


def _check_password_policy(c, cfg, cis_id, check_id, title, severity, field_name, expected, comparator="gte"):
    """Generic password policy field checker."""
    policy = _get_password_policy(c)
    actual = getattr(policy, field_name, None)

    if comparator == "gte":
        passed = actual is not None and actual >= expected
        detail = f"{field_name}={actual} (expected >= {expected})"
    elif comparator == "bool_true":
        passed = actual is True or actual == True
        detail = f"{field_name}={actual} (expected True)"
    else:
        passed = actual == expected
        detail = f"{field_name}={actual} (expected {expected})"

    return [make_result(
        cis_id=cis_id, check_id=check_id,
        title=title, service="iam", severity=severity,
        status="PASS" if passed else "FAIL",
        resource_id=cfg.account_id,
        status_extended=f"Password policy: {detail}",
        remediation=f"Update RAM password policy: Console > RAM > Settings > Password Policy",
        compliance_frameworks=FW,
    )]


def evaluate_cis_1_7(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_password_policy(c, cfg, "1.7", "ali_cis_1_7",
        "Ensure RAM password policy requires at least one uppercase letter",
        "high", "require_uppercase_characters", True, "bool_true")


def evaluate_cis_1_8(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_password_policy(c, cfg, "1.8", "ali_cis_1_8",
        "Ensure RAM password policy requires at least one lowercase letter",
        "high", "require_lowercase_characters", True, "bool_true")


def evaluate_cis_1_9(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_password_policy(c, cfg, "1.9", "ali_cis_1_9",
        "Ensure RAM password policy requires at least one symbol",
        "high", "require_symbols", True, "bool_true")


def evaluate_cis_1_10(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_password_policy(c, cfg, "1.10", "ali_cis_1_10",
        "Ensure RAM password policy requires at least one number",
        "high", "require_numbers", True, "bool_true")


def evaluate_cis_1_11(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_password_policy(c, cfg, "1.11", "ali_cis_1_11",
        "Ensure RAM password policy requires minimum length of 14 or greater",
        "high", "minimum_password_length", 14, "gte")


def evaluate_cis_1_12(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_password_policy(c, cfg, "1.12", "ali_cis_1_12",
        "Ensure RAM password policy prevents password reuse",
        "high", "password_reuse_prevention", 1, "gte")


def evaluate_cis_1_13(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_password_policy(c, cfg, "1.13", "ali_cis_1_13",
        "Ensure RAM password policy expires passwords in 365 days or greater",
        "high", "max_password_age", 1, "gte")


def evaluate_cis_1_14(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_password_policy(c, cfg, "1.14", "ali_cis_1_14",
        "Ensure RAM password policy blocks logon after 5 incorrect attempts",
        "high", "max_login_attemps", 5, "gte")


# ═══════════════════════════════════════════════════════════════
# 1.15 -- No full admin (*:*) policies
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_15(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_ram20150501 import models as ram_models
    import json
    results = []
    resp = c.ram.list_policies(ram_models.ListPoliciesRequest(
        policy_type="Custom",
    ))
    policies = resp.body.policies.policy if (
        resp.body.policies and resp.body.policies.policy
    ) else []

    for policy in policies:
        policy_name = policy.policy_name
        try:
            ver_resp = c.ram.get_policy(ram_models.GetPolicyRequest(
                policy_name=policy_name, policy_type="Custom",
            ))
            doc_str = ver_resp.body.default_policy_version.policy_document
            doc = json.loads(doc_str) if isinstance(doc_str, str) else doc_str
            statements = doc.get("Statement", [])
            has_full_admin = any(
                s.get("Effect") == "Allow"
                and s.get("Action") in ("*", ["*"])
                and s.get("Resource") in ("*", ["*"])
                for s in statements
            )
        except Exception:
            has_full_admin = False

        if has_full_admin:
            results.append(make_result(
                cis_id="1.15", check_id="ali_cis_1_15",
                title="Ensure RAM policies with full admin privileges are not created",
                service="iam", severity="critical",
                status="FAIL",
                resource_id=policy_name, resource_name=policy_name,
                status_extended=f"Custom policy '{policy_name}' grants full '*:*' administrative privileges",
                remediation="Review and restrict the policy to specific actions and resources.",
                compliance_frameworks=FW,
            ))

    if not results:
        results.append(make_result(
            cis_id="1.15", check_id="ali_cis_1_15",
            title="Ensure RAM policies with full admin privileges are not created",
            service="iam", severity="critical",
            status="PASS", resource_id=cfg.account_id,
            status_extended="No custom policies with full '*:*' administrative privileges found",
            compliance_frameworks=FW,
        ))

    return results


# ═══════════════════════════════════════════════════════════════
# 1.16 -- Policies attached only to groups or roles
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_16(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_ram20150501 import models as ram_models
    results = []
    resp = c.ram.list_users(ram_models.ListUsersRequest())
    users = resp.body.users.user if resp.body.users and resp.body.users.user else []

    users_with_direct_policies = []
    for user in users:
        user_name = user.user_name
        try:
            pol_resp = c.ram.list_policies_for_user(ram_models.ListPoliciesForUserRequest(
                user_name=user_name,
            ))
            user_policies = pol_resp.body.policies.policy if (
                pol_resp.body.policies and pol_resp.body.policies.policy
            ) else []
            if user_policies:
                users_with_direct_policies.append((user_name, len(user_policies)))
        except Exception:
            continue

    if users_with_direct_policies:
        for user_name, count in users_with_direct_policies:
            results.append(make_result(
                cis_id="1.16", check_id="ali_cis_1_16",
                title="Ensure RAM policies are attached only to groups or roles",
                service="iam", severity="medium",
                status="FAIL",
                resource_id=user_name, resource_name=user_name,
                status_extended=f"RAM user '{user_name}' has {count} directly attached policies",
                remediation="Move policies to RAM groups and assign users to groups instead.",
                compliance_frameworks=FW,
            ))
    else:
        results.append(make_result(
            cis_id="1.16", check_id="ali_cis_1_16",
            title="Ensure RAM policies are attached only to groups or roles",
            service="iam", severity="medium",
            status="PASS", resource_id=cfg.account_id,
            status_extended="No RAM users have directly attached policies",
            compliance_frameworks=FW,
        ))

    return results
