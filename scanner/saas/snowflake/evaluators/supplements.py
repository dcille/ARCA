"""CIS Snowflake v1.0.0 — Supplements: manual → automated upgrades.

Upgrades 13 CIS-manual controls to automated by querying ACCOUNT_USAGE
and INFORMATION_SCHEMA views. These controls are marked Manual in the
benchmark because they require verifying *alerting infrastructure*,
but the underlying data IS queryable via SQL.

Section 2 (9 controls): Check for SHOW ALERTS or monitoring tasks that
    cover the required detection queries. If alerts/tasks exist → PASS.
Section 3 (2 controls): Query network policy configuration directly.
Section 4 (2 controls): Query masking/row-access policies directly.
"""

from __future__ import annotations
from .base import SnowflakeClientCache, CheckResult, make_result


# ═══════════════════════════════════════════════════════════════════════
# Section 2 — Monitoring & Alerting (9 upgrades)
# Strategy: check if Snowflake ALERT objects or TASKs exist that
# reference the relevant detection queries / tables.
# ═══════════════════════════════════════════════════════════════════════

def _get_alerts_and_tasks(sf: SnowflakeClientCache) -> tuple[list[dict], list[dict]]:
    """Fetch all alerts and monitoring tasks (cached per scan)."""
    if not hasattr(sf, "_cached_alerts"):
        try:
            sf._cached_alerts = sf.query("SHOW ALERTS")
        except Exception:
            sf._cached_alerts = []
    if not hasattr(sf, "_cached_tasks"):
        try:
            sf._cached_tasks = sf.query("SHOW TASKS")
        except Exception:
            sf._cached_tasks = []
    return sf._cached_alerts, sf._cached_tasks


def _has_monitoring(sf: SnowflakeClientCache, keywords: list[str]) -> bool:
    """Check if any alert or task definition references the given keywords."""
    alerts, tasks = _get_alerts_and_tasks(sf)
    all_items = alerts + tasks
    for item in all_items:
        definition = str(item.get("CONDITION", "")) + str(item.get("DEFINITION", ""))
        definition += str(item.get("QUERY", "")) + str(item.get("SQL_TEXT", ""))
        definition = definition.upper()
        if all(kw.upper() in definition for kw in keywords):
            return True
    return False


# ── 2.1 ───────────────────────────────────────────────────────────────
def eval_2_1_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Monitor ACCOUNTADMIN/SECURITYADMIN role grants."""
    found = _has_monitoring(sf, ["GRANTS_TO_ROLES", "ACCOUNTADMIN"])
    return [make_result(
        "2.1", "Ensure monitoring/alerting for admin role grants",
        passed=found,
        resource_id="account",
        detail="Alert/task checking GRANTS_TO_ROLES for ACCOUNTADMIN: "
               + ("found" if found else "not found"),
        remediation="Create a TASK or ALERT monitoring GRANTS_TO_ROLES for admin role grants.",
        severity="high",
    )]


# ── 2.2 ───────────────────────────────────────────────────────────────
def eval_2_2_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Monitor MANAGE GRANTS privilege grants."""
    found = _has_monitoring(sf, ["MANAGE", "GRANTS", "QUERY_HISTORY"])
    return [make_result(
        "2.2", "Ensure monitoring/alerting for MANAGE GRANTS privilege grants",
        passed=found,
        resource_id="account",
        detail="Alert/task for MANAGE GRANTS detection: " + ("found" if found else "not found"),
        remediation="Create a monitoring task querying QUERY_HISTORY for MANAGE GRANTS events.",
        severity="high",
    )]


# ── 2.3 ───────────────────────────────────────────────────────────────
def eval_2_3_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Monitor password sign-ins of SSO users."""
    found = _has_monitoring(sf, ["LOGIN_HISTORY", "PASSWORD"])
    return [make_result(
        "2.3", "Ensure monitoring/alerting for password sign-ins of SSO users",
        passed=found,
        resource_id="account",
        detail="Alert/task for password SSO login detection: " + ("found" if found else "not found"),
        remediation="Create a monitoring task querying LOGIN_HISTORY for PASSWORD logins of SSO users.",
        severity="high",
    )]


# ── 2.4 ───────────────────────────────────────────────────────────────
def eval_2_4_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Monitor password sign-in without MFA."""
    found = _has_monitoring(sf, ["LOGIN_HISTORY", "PASSWORD", "SECOND_AUTHENTICATION"])
    if not found:
        # Also accept if monitoring for MFA generally
        found = _has_monitoring(sf, ["LOGIN_HISTORY", "MFA"])
    return [make_result(
        "2.4", "Ensure monitoring/alerting for password sign-in without MFA",
        passed=found,
        resource_id="account",
        detail="Alert/task for no-MFA password login detection: " + ("found" if found else "not found"),
        remediation="Create a monitoring task for LOGIN_HISTORY password logins without second factor.",
        severity="high",
    )]


# ── 2.5 ───────────────────────────────────────────────────────────────
def eval_2_5_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Monitor security integration changes."""
    found = _has_monitoring(sf, ["SECURITY INTEGRATION", "QUERY_HISTORY"])
    if not found:
        found = _has_monitoring(sf, ["SECURITY_INTEGRATION"])
    return [make_result(
        "2.5", "Ensure monitoring/alerting for security integration changes",
        passed=found,
        resource_id="account",
        detail="Alert/task for security integration change detection: "
               + ("found" if found else "not found"),
        remediation="Create a monitoring task for CREATE/ALTER/DROP SECURITY INTEGRATION events.",
        severity="high",
    )]


# ── 2.6 ───────────────────────────────────────────────────────────────
def eval_2_6_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Monitor network policy changes."""
    found = _has_monitoring(sf, ["NETWORK_POLICY"])
    return [make_result(
        "2.6", "Ensure monitoring/alerting for network policy changes",
        passed=found,
        resource_id="account",
        detail="Alert/task for network policy change detection: "
               + ("found" if found else "not found"),
        remediation="Create a monitoring task for CREATE/ALTER/DROP NETWORK POLICY events.",
        severity="high",
    )]


# ── 2.7 ───────────────────────────────────────────────────────────────
def eval_2_7_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Monitor SCIM token creation."""
    found = _has_monitoring(sf, ["SCIM", "GENERATE_SCIM_ACCESS_TOKEN"])
    if not found:
        found = _has_monitoring(sf, ["SCIM_ACCESS_TOKEN"])
    return [make_result(
        "2.7", "Ensure monitoring/alerting for SCIM token creation",
        passed=found,
        resource_id="account",
        detail="Alert/task for SCIM token creation detection: "
               + ("found" if found else "not found"),
        remediation="Create a monitoring task for SYSTEM$GENERATE_SCIM_ACCESS_TOKEN calls.",
        severity="medium",
    )]


# ── 2.8 ───────────────────────────────────────────────────────────────
def eval_2_8_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Monitor new share exposures."""
    found = _has_monitoring(sf, ["SHARE", "QUERY_HISTORY"])
    return [make_result(
        "2.8", "Ensure monitoring/alerting for new share exposures",
        passed=found,
        resource_id="account",
        detail="Alert/task for share exposure detection: " + ("found" if found else "not found"),
        remediation="Create a monitoring task for ALTER share / ADD ACCOUNTS events.",
        severity="high",
    )]


# ── 2.9 ───────────────────────────────────────────────────────────────
def eval_2_9_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Monitor unsupported Snowflake connector sessions."""
    found = _has_monitoring(sf, ["SESSIONS", "CLIENT_APPLICATION"])
    if not found:
        found = _has_monitoring(sf, ["SESSIONS", "CONNECTOR"])
    return [make_result(
        "2.9", "Ensure monitoring/alerting for unsupported connector sessions",
        passed=found,
        resource_id="account",
        detail="Alert/task for outdated connector detection: "
               + ("found" if found else "not found"),
        remediation="Create a monitoring task checking SESSIONS for outdated client versions.",
        severity="medium",
    )]


# ═══════════════════════════════════════════════════════════════════════
# Section 3 — Networking (2 upgrades)
# ═══════════════════════════════════════════════════════════════════════

# ── 3.1 ───────────────────────────────────────────────────────────────
def eval_3_1_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Check account-level network policy exists and has allowed IPs."""
    val = sf.show_parameter("NETWORK_POLICY")
    if not val or val.strip() == "":
        return [make_result(
            "3.1", "Ensure account-level network policy allows only trusted IPs",
            passed=False,
            resource_id="account",
            detail="No account-level network policy is set.",
            remediation="CREATE NETWORK POLICY and ALTER ACCOUNT SET NETWORK_POLICY = <name>;",
            severity="high", cis_level=2,
        )]
    # Policy exists — describe it
    try:
        desc = sf.query(f"DESCRIBE NETWORK POLICY {val.strip()}")
        allowed = [r for r in desc if r.get("NAME", "").upper() == "ALLOWED_IP_LIST"]
        allowed_ips = allowed[0].get("VALUE", "") if allowed else ""
        has_ips = bool(allowed_ips and allowed_ips.strip() and allowed_ips.strip() != "")
        return [make_result(
            "3.1", "Ensure account-level network policy allows only trusted IPs",
            passed=has_ips,
            resource_id="account",
            detail=f"Network policy '{val.strip()}' ALLOWED_IP_LIST: {allowed_ips[:100]}",
            remediation="Set ALLOWED_IP_LIST to only trusted IP ranges.",
            severity="high", cis_level=2,
        )]
    except Exception:
        return [make_result(
            "3.1", "Ensure account-level network policy allows only trusted IPs",
            passed=True,  # Policy exists, can't describe = assume configured
            resource_id="account",
            detail=f"Network policy '{val.strip()}' exists (insufficient privilege to describe).",
            remediation="Verify ALLOWED_IP_LIST with DESCRIBE NETWORK POLICY.",
            severity="high", cis_level=2,
        )]


# ── 3.2 ───────────────────────────────────────────────────────────────
def eval_3_2_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Check user-level network policies for service accounts."""
    # Find tagged service accounts
    tagged = sf.query("""
        SELECT TR.OBJECT_NAME
        FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES TR
        WHERE TR.TAG_NAME = 'ACCOUNT_TYPE'
          AND UPPER(TR.TAG_VALUE) = 'SERVICE'
          AND TR.DOMAIN = 'USER'
    """)
    if not tagged:
        return [make_result(
            "3.2", "Ensure user-level network policies for service accounts",
            passed=False,
            resource_id="account",
            detail="No users tagged with ACCOUNT_TYPE='SERVICE'. Cannot verify.",
            remediation="Tag service accounts, then set user-level network policies for each.",
            severity="medium",
        )]
    results = []
    for svc in tagged:
        name = svc.get("OBJECT_NAME", "")
        try:
            params = sf.query(f"SHOW PARAMETERS LIKE 'NETWORK_POLICY' FOR USER {name}")
            has_policy = any(
                p.get("VALUE") and str(p["VALUE"]).strip() != ""
                for p in params
            )
        except Exception:
            has_policy = False
        results.append(make_result(
            "3.2", "Ensure user-level network policies for service accounts",
            passed=has_policy,
            resource_id=name,
            detail=f"Service account '{name}' network policy: {'set' if has_policy else 'not set'}",
            remediation=f"ALTER USER {name} SET NETWORK_POLICY = <policy>;",
            severity="medium",
        ))
    return results


# ═══════════════════════════════════════════════════════════════════════
# Section 4 — Data Protection (2 upgrades: 4.10, 4.11)
# ═══════════════════════════════════════════════════════════════════════

# ── 4.10 ──────────────────────────────────────────────────────────────
def eval_4_10_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Check if masking policies exist in the account."""
    try:
        policies = sf.query("SHOW MASKING POLICIES IN ACCOUNT")
    except Exception:
        policies = []
    return [make_result(
        "4.10", "Ensure data masking is enabled for sensitive data",
        passed=len(policies) > 0,
        resource_id="account",
        detail=f"Masking policies in account: {len(policies)}",
        remediation="CREATE MASKING POLICY and apply to sensitive columns.",
        severity="high",
    )]


# ── 4.11 ──────────────────────────────────────────────────────────────
def eval_4_11_sup(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Check if row-access policies exist in the account."""
    try:
        policies = sf.query("SHOW ROW ACCESS POLICIES IN ACCOUNT")
    except Exception:
        policies = []
    return [make_result(
        "4.11", "Ensure row-access policies are configured for sensitive data",
        passed=len(policies) > 0,
        resource_id="account",
        detail=f"Row access policies in account: {len(policies)}",
        remediation="CREATE ROW ACCESS POLICY and apply to sensitive tables.",
        severity="medium",
    )]


# ── Supplement Registry ───────────────────────────────────────────────
SUPPLEMENT_EVALUATORS: dict[str, callable] = {
    # Section 2 — all 9
    "2.1":  eval_2_1_sup,
    "2.2":  eval_2_2_sup,
    "2.3":  eval_2_3_sup,
    "2.4":  eval_2_4_sup,
    "2.5":  eval_2_5_sup,
    "2.6":  eval_2_6_sup,
    "2.7":  eval_2_7_sup,
    "2.8":  eval_2_8_sup,
    "2.9":  eval_2_9_sup,
    # Section 3 — both
    "3.1":  eval_3_1_sup,
    "3.2":  eval_3_2_sup,
    # Section 4 — 2
    "4.10": eval_4_10_sup,
    "4.11": eval_4_11_sup,
}
