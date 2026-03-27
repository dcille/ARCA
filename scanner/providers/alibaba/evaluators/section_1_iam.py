"""CIS Alibaba v2.0 Section 1 — Identity and Access Management (16 controls).

Manual: 1.1, 1.2, 1.3
Automated: 1.4–1.16 (RAM SDK: password policy, MFA, keys, policies)
"""
from __future__ import annotations
from .base import (AlibabaClientCache, EvalConfig, make_result, make_manual_result,
                   days_since, logger)


def evaluate_1_1(c, cfg): return [make_manual_result("1.1", "Avoid the use of the root account", "IAM", "critical")]
def evaluate_1_2(c, cfg): return [make_manual_result("1.2", "Ensure no root account access key exists", "IAM", "critical")]
def evaluate_1_3(c, cfg): return [make_manual_result("1.3", "Ensure MFA is enabled for the root account", "IAM", "critical")]


def evaluate_1_4(c: AlibabaClientCache, cfg: EvalConfig):
    """MFA enabled for all RAM users with console password."""
    from alibabacloud_ram20150501 import models as m
    results = []
    users = c.ram.list_users(m.ListUsersRequest()).body.users.user or []
    for u in users:
        try:
            mfa = c.ram.get_user_mfainfo(m.GetUserMFAInfoRequest(user_name=u.user_name))
            has_mfa = bool(mfa.body.mfadevice and mfa.body.mfadevice.serial_number)
        except Exception:
            has_mfa = False
        results.append(make_result("1.4", "MFA enabled for all RAM users with console password",
            u.user_name, u.user_name, has_mfa, severity="high", service="IAM",
            remediation="Enable MFA for all RAM users with console access"))
    return results


def evaluate_1_5(c: AlibabaClientCache, cfg: EvalConfig):
    """Users not logged on for 90+ days disabled."""
    from alibabacloud_ram20150501 import models as m
    results = []
    users = c.ram.list_users(m.ListUsersRequest()).body.users.user or []
    for u in users:
        inactive = days_since(u.last_login_date)
        results.append(make_result("1.5", "Users not logged on for 90 days are disabled",
            u.user_name, u.user_name, inactive <= 90,
            f"User {u.user_name} last login {inactive} days ago",
            severity="medium", service="IAM",
            remediation="Disable console logon for users inactive 90+ days"))
    return results


def evaluate_1_6(c: AlibabaClientCache, cfg: EvalConfig):
    """Access keys rotated every 90 days."""
    from alibabacloud_ram20150501 import models as m
    results = []
    users = c.ram.list_users(m.ListUsersRequest()).body.users.user or []
    for u in users:
        try:
            keys = c.ram.list_access_keys(m.ListAccessKeysRequest(user_name=u.user_name))
            for k in keys.body.access_keys.access_key or []:
                if k.status != "Active": continue
                age = days_since(k.create_date)
                results.append(make_result("1.6", "Access keys rotated every 90 days",
                    f"{u.user_name}/{k.access_key_id}", u.user_name, age <= 90,
                    f"Key {k.access_key_id} is {age} days old",
                    severity="high", service="IAM",
                    remediation="Rotate access keys every 90 days"))
        except Exception: pass
    return results


def _eval_password_policy(c, cfg):
    from alibabacloud_ram20150501 import models as m
    return c.ram.get_password_policy(m.GetPasswordPolicyRequest()).body.password_policy

def evaluate_1_7(c, cfg):
    pp = _eval_password_policy(c, cfg)
    v = getattr(pp, 'require_uppercase_characters', False)
    return [make_result("1.7", "RAM password policy requires uppercase", "password-policy", "Password Policy", v, severity="high", service="IAM")]

def evaluate_1_8(c, cfg):
    pp = _eval_password_policy(c, cfg)
    v = getattr(pp, 'require_lowercase_characters', False)
    return [make_result("1.8", "RAM password policy requires lowercase", "password-policy", "Password Policy", v, severity="high", service="IAM")]

def evaluate_1_9(c, cfg):
    pp = _eval_password_policy(c, cfg)
    v = getattr(pp, 'require_symbols', False)
    return [make_result("1.9", "RAM password policy requires symbol", "password-policy", "Password Policy", v, severity="high", service="IAM")]

def evaluate_1_10(c, cfg):
    pp = _eval_password_policy(c, cfg)
    v = getattr(pp, 'require_numbers', False)
    return [make_result("1.10", "RAM password policy requires number", "password-policy", "Password Policy", v, severity="high", service="IAM")]

def evaluate_1_11(c, cfg):
    pp = _eval_password_policy(c, cfg)
    v = (getattr(pp, 'minimum_password_length', 0) or 0) >= 14
    return [make_result("1.11", "RAM password policy min length >= 14", "password-policy", "Password Policy", v, severity="high", service="IAM")]

def evaluate_1_12(c, cfg):
    pp = _eval_password_policy(c, cfg)
    v = (getattr(pp, 'password_reuse_prevention', 0) or 0) >= 5
    return [make_result("1.12", "RAM password policy prevents password reuse", "password-policy", "Password Policy", v, severity="high", service="IAM")]

def evaluate_1_13(c, cfg):
    pp = _eval_password_policy(c, cfg)
    age = getattr(pp, 'max_password_age', 0) or 0
    v = 0 < age <= 365 if age else False
    return [make_result("1.13", "RAM password policy expires passwords in 365 days", "password-policy", "Password Policy", v, severity="high", service="IAM")]

def evaluate_1_14(c, cfg):
    pp = _eval_password_policy(c, cfg)
    v = 0 < (getattr(pp, 'max_login_attemps', 0) or 0) <= 5
    return [make_result("1.14", "RAM password policy blocks after 5 incorrect attempts", "password-policy", "Password Policy", v, severity="high", service="IAM")]


def evaluate_1_15(c: AlibabaClientCache, cfg: EvalConfig):
    """No wildcard *:* admin policies."""
    from alibabacloud_ram20150501 import models as m
    results = []
    pols = c.ram.list_policies(m.ListPoliciesRequest(policy_type="Custom", max_items=200)).body.policies.policy or []
    for pol in pols:
        try:
            detail = c.ram.get_policy(m.GetPolicyRequest(policy_name=pol.policy_name, policy_type="Custom"))
            doc = detail.body.default_policy_version.policy_document or ""
            has_admin = '"Action": "*"' in doc and '"Resource": "*"' in doc and '"Effect": "Allow"' in doc
            if has_admin:
                results.append(make_result("1.15", "No full *:* admin policies",
                    pol.policy_name, pol.policy_name, False,
                    f"Policy '{pol.policy_name}' grants *:* admin privileges",
                    severity="critical", service="IAM",
                    remediation="Edit policy to grant least-privilege permissions"))
        except Exception: pass
    if not results:
        results.append(make_result("1.15", "No full *:* admin policies",
            "custom-policies", "RAM Policies", True, severity="critical", service="IAM"))
    return results


def evaluate_1_16(c: AlibabaClientCache, cfg: EvalConfig):
    """Policies attached only to groups/roles, not users."""
    from alibabacloud_ram20150501 import models as m
    results = []
    users = c.ram.list_users(m.ListUsersRequest()).body.users.user or []
    for u in users:
        try:
            pols = c.ram.list_policies_for_user(m.ListPoliciesForUserRequest(user_name=u.user_name))
            direct = pols.body.policies.policy or []
            if direct:
                results.append(make_result("1.16", "RAM policies attached only to groups/roles",
                    u.user_name, u.user_name, False,
                    f"User '{u.user_name}' has {len(direct)} direct policies",
                    severity="medium", service="IAM",
                    remediation="Detach policies from users, attach to groups/roles"))
        except Exception: pass
    if not results:
        results.append(make_result("1.16", "RAM policies attached only to groups/roles",
            "ram-users", "RAM Users", True, severity="medium", service="IAM"))
    return results


SECTION_1_EVALUATORS = {f"1.{i}": globals()[f"evaluate_1_{i}"] for i in range(1, 17)}
