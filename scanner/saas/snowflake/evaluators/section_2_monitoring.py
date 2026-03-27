"""CIS Snowflake v1.0.0 — Section 2: Monitoring and Alerting.

9 controls (2.1–2.9). All marked MANUAL in the CIS benchmark because
they require verifying that alerting *infrastructure* exists, not just
that the data is queryable. We provide stubs that supplements.py can
upgrade to semi-automated by checking for SHOW ALERTS / SHOW TASKS.
"""

from __future__ import annotations
from .base import SnowflakeClientCache, CheckResult, make_manual


# ── 2.1  Monitor ACCOUNTADMIN/SECURITYADMIN role grants ───────────────
def eval_2_1(sf: SnowflakeClientCache) -> list[CheckResult]:
    return [make_manual(
        "2.1", "Ensure monitoring/alerting for ACCOUNTADMIN and SECURITYADMIN role grants",
        resource_id="account",
        detail="Verify that a monitoring task or SIEM alert exists for: "
               "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES "
               "WHERE NAME IN ('ACCOUNTADMIN','SECURITYADMIN');",
        remediation="Create a Snowflake TASK that runs the detection query and sends email alerts.",
        severity="high",
    )]


# ── 2.2  Monitor MANAGE GRANTS privilege grants ──────────────────────
def eval_2_2(sf: SnowflakeClientCache) -> list[CheckResult]:
    return [make_manual(
        "2.2", "Ensure monitoring/alerting for MANAGE GRANTS privilege grants",
        resource_id="account",
        detail="Verify alerting on: query_history WHERE query_type='GRANT' "
               "AND query_text ILIKE '%manage%grants%'.",
        remediation="Create a monitoring task for MANAGE GRANTS events.",
        severity="high",
    )]


# ── 2.3  Monitor password sign-ins of SSO users ──────────────────────
def eval_2_3(sf: SnowflakeClientCache) -> list[CheckResult]:
    return [make_manual(
        "2.3", "Ensure monitoring/alerting for password sign-ins of SSO users",
        resource_id="account",
        detail="Verify alerting on: login_history WHERE first_authentication_factor='PASSWORD' "
               "for users who should only use SSO.",
        remediation="Create a monitoring task using LOGIN_HISTORY to detect password logins for SSO users.",
        severity="high",
    )]


# ── 2.4  Monitor password sign-in without MFA ────────────────────────
def eval_2_4(sf: SnowflakeClientCache) -> list[CheckResult]:
    return [make_manual(
        "2.4", "Ensure monitoring/alerting for password sign-in without MFA",
        resource_id="account",
        detail="Verify alerting on: login_history WHERE first_authentication_factor='PASSWORD' "
               "AND second_authentication_factor IS NULL.",
        remediation="Create a monitoring task for password logins without MFA.",
        severity="high",
    )]


# ── 2.5  Monitor security integration changes ────────────────────────
def eval_2_5(sf: SnowflakeClientCache) -> list[CheckResult]:
    return [make_manual(
        "2.5", "Ensure monitoring/alerting for security integration changes",
        resource_id="account",
        detail="Verify alerting on: query_history WHERE query_type IN ('CREATE','ALTER','DROP') "
               "AND query_text ILIKE '%security integration%'.",
        remediation="Create a monitoring task for security integration CREATE/ALTER/DROP events.",
        severity="high",
    )]


# ── 2.6  Monitor network policy changes ──────────────────────────────
def eval_2_6(sf: SnowflakeClientCache) -> list[CheckResult]:
    return [make_manual(
        "2.6", "Ensure monitoring/alerting for network policy changes",
        resource_id="account",
        detail="Verify alerting on: query_history WHERE query_type IN "
               "('CREATE_NETWORK_POLICY','ALTER_NETWORK_POLICY','DROP_NETWORK_POLICY').",
        remediation="Create a monitoring task for network policy modification events.",
        severity="high",
    )]


# ── 2.7  Monitor SCIM token creation ─────────────────────────────────
def eval_2_7(sf: SnowflakeClientCache) -> list[CheckResult]:
    return [make_manual(
        "2.7", "Ensure monitoring/alerting for SCIM token creation",
        resource_id="account",
        detail="Verify alerting on: query_history WHERE query_text ILIKE "
               "'%system$generate_scim_access_token%'.",
        remediation="Create a monitoring task for SCIM access token generation events.",
        severity="medium",
    )]


# ── 2.8  Monitor new share exposures ─────────────────────────────────
def eval_2_8(sf: SnowflakeClientCache) -> list[CheckResult]:
    return [make_manual(
        "2.8", "Ensure monitoring/alerting for new share exposures",
        resource_id="account",
        detail="Verify alerting on: query_history WHERE query_type='ALTER' "
               "AND query_text matches share addition patterns.",
        remediation="Create a monitoring task for data share exposure changes.",
        severity="high",
    )]


# ── 2.9  Monitor unsupported connector versions ──────────────────────
def eval_2_9(sf: SnowflakeClientCache) -> list[CheckResult]:
    return [make_manual(
        "2.9", "Ensure monitoring/alerting for unsupported Snowflake connector sessions",
        resource_id="account",
        detail="Verify alerting on: SESSIONS view for outdated JDBC/ODBC/Python connector versions.",
        remediation="Create a monitoring task checking SESSIONS for outdated client versions.",
        severity="medium",
    )]


# ── Registry ──────────────────────────────────────────────────────────
SECTION_2_EVALUATORS: dict[str, callable] = {
    "2.1": eval_2_1,
    "2.2": eval_2_2,
    "2.3": eval_2_3,
    "2.4": eval_2_4,
    "2.5": eval_2_5,
    "2.6": eval_2_6,
    "2.7": eval_2_7,
    "2.8": eval_2_8,
    "2.9": eval_2_9,
}
