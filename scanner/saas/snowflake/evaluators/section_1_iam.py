"""CIS Snowflake v1.0.0 — Section 1: Identity and Access Management.

17 controls (1.1–1.17). SQL queries taken from the CIS benchmark PDF.
All queries target SNOWFLAKE.ACCOUNT_USAGE (read-only).
"""

from __future__ import annotations
from .base import SnowflakeClientCache, CheckResult, make_result, make_manual


# ── 1.1  SSO configured ────────────────────────────────────────────────
def eval_1_1(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure SSO (SAML2 or External OAuth) is configured."""
    rows = sf.query("""
        SHOW SECURITY INTEGRATIONS
    """)
    # Filter via result_scan pattern from CIS benchmark
    sso = [
        r for r in rows
        if (str(r.get("TYPE", "")).upper().startswith("SAML2")
            or str(r.get("TYPE", "")).upper().startswith("EXTERNAL_OAUTH"))
        and str(r.get("ENABLED", "")).lower() == "true"
    ]
    return [make_result(
        "1.1", "Ensure SSO is configured for your account/organization",
        passed=len(sso) > 0,
        resource_id="account",
        detail=f"Active SSO integrations: {len(sso)}",
        remediation="Configure a SAML2 or External OAuth security integration for SSO.",
        severity="high",
    )]


# ── 1.2  SCIM integration configured ──────────────────────────────────
def eval_1_2(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure SCIM integration is configured for automated provisioning."""
    rows = sf.query("SHOW SECURITY INTEGRATIONS")
    scim = [
        r for r in rows
        if str(r.get("TYPE", "")).upper().startswith("SCIM")
        and str(r.get("ENABLED", "")).lower() == "true"
    ]
    return [make_result(
        "1.2", "Ensure SCIM integration is configured for user provisioning",
        passed=len(scim) > 0,
        resource_id="account",
        detail=f"Active SCIM integrations: {len(scim)}",
        remediation="Configure a SCIM security integration (Okta, Azure AD, etc.).",
        severity="medium",
    )]


# ── 1.3  Password unset for SSO users (MANUAL) ────────────────────────
def eval_1_3(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure Snowflake password is unset for SSO users."""
    return [make_manual(
        "1.3", "Ensure that Snowflake password is unset for SSO users",
        resource_id="account",
        detail="Requires identifying SSO users and verifying HAS_PASSWORD=false for each. "
               "Cannot determine SSO-only status programmatically without IdP cross-reference.",
        remediation="For each SSO user: ALTER USER <user> SET PASSWORD = null;",
        severity="high",
    )]


# ── 1.4  MFA for password-based human users ───────────────────────────
def eval_1_4(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure MFA is turned on for all human users with password-based auth."""
    rows = sf.query("""
        SELECT NAME, EXT_AUTHN_DUO AS MFA_ENABLED, HAS_PASSWORD
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE DELETED_ON IS NULL AND DISABLED = 'false'
    """)
    results = []
    no_mfa = [
        r for r in rows
        if str(r.get("HAS_PASSWORD", "")).lower() == "true"
        and str(r.get("MFA_ENABLED", "")).lower() != "true"
    ]
    results.append(make_result(
        "1.4", "Ensure MFA is enabled for all password-based human users",
        passed=len(no_mfa) == 0,
        resource_id="account",
        detail=f"Password users without MFA: {len(no_mfa)}"
               + (f" ({', '.join(r['NAME'] for r in no_mfa[:10])})" if no_mfa else ""),
        remediation="Enable MFA (Duo) for all password-authenticated human users.",
        severity="critical",
    ))
    return results


# ── 1.5  Minimum password length >= 14 ────────────────────────────────
def eval_1_5(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure minimum password length is set to 14 characters or more."""
    # CIS audit: check password policies + policy references
    policies = sf.query("""
        SELECT ID, NAME, PASSWORD_MIN_LENGTH
        FROM SNOWFLAKE.ACCOUNT_USAGE.PASSWORD_POLICIES
        WHERE DELETED IS NULL
    """)
    if not policies:
        return [make_result(
            "1.5", "Ensure minimum password length >= 14",
            passed=False, resource_id="account",
            detail="No custom password policies found (using Snowflake defaults: 8 chars).",
            remediation="CREATE PASSWORD POLICY with PASSWORD_MIN_LENGTH = 14 and assign to account.",
            severity="high",
        )]
    # Check that AT LEAST ONE policy assigned to account has >= 14
    refs = sf.query("""
        SELECT A.POLICY_NAME, A.REF_ENTITY_DOMAIN
        FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A
        WHERE A.POLICY_KIND = 'PASSWORD_POLICY'
          AND A.REF_ENTITY_DOMAIN = 'ACCOUNT'
    """)
    account_policy_names = {r.get("POLICY_NAME", "").upper() for r in refs}
    compliant = [
        p for p in policies
        if p.get("NAME", "").upper() in account_policy_names
        and int(p.get("PASSWORD_MIN_LENGTH", 0) or 0) >= 14
    ]
    return [make_result(
        "1.5", "Ensure minimum password length >= 14",
        passed=len(compliant) > 0,
        resource_id="account",
        detail=f"Account-level password policies with min_length>=14: {len(compliant)}/{len(policies)}",
        remediation="ALTER PASSWORD POLICY SET PASSWORD_MIN_LENGTH = 14;",
        severity="high",
    )]


# ── 1.6  Service accounts use key pair auth ───────────────────────────
def eval_1_6(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure service accounts use key pair authentication."""
    # CIS uses tagging: tag_references with tag_name='ACCOUNT_TYPE'
    tagged = sf.query("""
        SELECT TR.OBJECT_NAME
        FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES TR
        WHERE TR.TAG_NAME = 'ACCOUNT_TYPE'
          AND UPPER(TR.TAG_VALUE) = 'SERVICE'
          AND TR.DOMAIN = 'USER'
    """)
    if not tagged:
        return [make_manual(
            "1.6", "Ensure service accounts use key pair authentication",
            resource_id="account",
            detail="No users tagged with ACCOUNT_TYPE='SERVICE'. "
                   "Tag service accounts or provide a list for automated evaluation.",
            remediation="Tag service accounts, then verify HAS_RSA_PUBLIC_KEY=true for each.",
            severity="high",
        )]
    svc_names = {r["OBJECT_NAME"] for r in tagged}
    users = sf.query("""
        SELECT NAME, HAS_RSA_PUBLIC_KEY
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE DELETED_ON IS NULL AND DISABLED = 'false'
    """)
    svc_users = [u for u in users if u["NAME"] in svc_names]
    no_key = [u for u in svc_users if str(u.get("HAS_RSA_PUBLIC_KEY", "")).lower() != "true"]
    return [make_result(
        "1.6", "Ensure service accounts use key pair authentication",
        passed=len(no_key) == 0,
        resource_id="account",
        detail=f"Service accounts without RSA key: {len(no_key)}/{len(svc_users)}"
               + (f" ({', '.join(u['NAME'] for u in no_key[:5])})" if no_key else ""),
        remediation="ALTER USER <svc> SET RSA_PUBLIC_KEY='<key>'; then SET PASSWORD = null;",
        severity="high",
    )]


# ── 1.7  Key pair rotation every 180 days ─────────────────────────────
def eval_1_7(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure authentication key pairs are rotated every 180 days."""
    # CIS audit: parse query_history for ALTER/CREATE USER with rsa_public_key
    rows = sf.query("""
        WITH FILTERED_QUERY_HISTORY AS (
            SELECT END_TIME AS SET_TIME,
                   UPPER(REGEXP_SUBSTR(QUERY_TEXT, 'USER\\\\s+"?([\\\\w]+)"?', 1, 1, 'i', 1)) AS USERNAME,
                   QUERY_TEXT
            FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
            WHERE EXECUTION_STATUS = 'SUCCESS'
              AND QUERY_TYPE IN ('ALTER_USER', 'CREATE_USER')
              AND TO_DATE(END_TIME) < DATEADD(day, -180, CURRENT_DATE())
              AND (QUERY_TEXT ILIKE '%rsa_public_key%' OR QUERY_TEXT ILIKE '%rsa_public_key_2%')
        ),
        EXTRACTED_KEYS AS (
            SELECT SET_TIME, USERNAME,
                   CASE
                       WHEN POSITION('rsa_public_key_2' IN LOWER(QUERY_TEXT)) > 0 THEN 'rsa_public_key_2'
                       WHEN POSITION('rsa_public_key' IN LOWER(QUERY_TEXT)) > 0 THEN 'rsa_public_key'
                   END AS RSA_KEY_NAME
            FROM FILTERED_QUERY_HISTORY
        ),
        RECENT_KEYS AS (
            SELECT EK.SET_TIME, EK.USERNAME, EK.RSA_KEY_NAME,
                   ROW_NUMBER() OVER (PARTITION BY EK.USERNAME, EK.RSA_KEY_NAME ORDER BY EK.SET_TIME DESC) AS RNUM
            FROM EXTRACTED_KEYS EK
            INNER JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS AU ON EK.USERNAME = AU.NAME
            WHERE AU.DELETED_ON IS NULL AND AU.DISABLED = 'false'
              AND EK.RSA_KEY_NAME IS NOT NULL
        )
        SELECT SET_TIME, USERNAME, RSA_PUBLIC_KEY
        FROM RECENT_KEYS WHERE RNUM = 1
    """)
    # If query returns results → those keys are >180 days old = FAIL
    stale = [r for r in rows]
    return [make_result(
        "1.7", "Ensure authentication key pairs are rotated every 180 days",
        passed=len(stale) == 0,
        resource_id="account",
        detail=f"Users with RSA keys older than 180 days: {len(stale)}"
               + (f" ({', '.join(r.get('USERNAME','?') for r in stale[:5])})" if stale else ""),
        remediation="Rotate RSA key pairs: ALTER USER <user> SET RSA_PUBLIC_KEY_2='<new_key>';",
        severity="high",
    )]


# ── 1.8  Inactive users disabled (90 days) ────────────────────────────
def eval_1_8(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure users who did not log in for 90 days are disabled."""
    rows = sf.query("""
        SELECT NAME, LAST_SUCCESS_LOGIN
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE DELETED_ON IS NULL AND DISABLED = 'false'
          AND LAST_SUCCESS_LOGIN < DATEADD(day, -90, CURRENT_TIMESTAMP())
    """)
    return [make_result(
        "1.8", "Ensure users inactive for 90+ days are disabled",
        passed=len(rows) == 0,
        resource_id="account",
        detail=f"Active users with no login in 90+ days: {len(rows)}"
               + (f" ({', '.join(r['NAME'] for r in rows[:10])})" if rows else ""),
        remediation="ALTER USER <user> SET DISABLED = TRUE;",
        severity="medium",
    )]


# ── 1.9  Session timeout <= 15 min for ACCOUNTADMIN ───────────────────
def eval_1_9(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure idle session timeout <= 15 min for ACCOUNTADMIN/SECURITYADMIN users."""
    # CIS: check session policies applied to privileged users
    rows = sf.query("""
        WITH PRIV_USERS AS (
            SELECT DISTINCT GRANTEE_NAME
            FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
            WHERE DELETED_ON IS NULL
              AND ROLE IN ('ACCOUNTADMIN','SECURITYADMIN')
        ),
        POLICY_REFS AS (
            SELECT A.REF_ENTITY_NAME, A.POLICY_KIND, B.SESSION_IDLE_TIMEOUT_MINS
            FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A
            LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.SESSION_POLICIES AS B
                ON A.POLICY_ID = B.ID
            WHERE A.POLICY_KIND = 'SESSION_POLICY'
        )
        SELECT P.GRANTEE_NAME,
               PR.SESSION_IDLE_TIMEOUT_MINS
        FROM PRIV_USERS P
        LEFT JOIN POLICY_REFS PR ON P.GRANTEE_NAME = PR.REF_ENTITY_NAME
    """)
    # Also check account-level session policy
    acct_policy = sf.query("""
        SELECT A.POLICY_NAME, B.SESSION_IDLE_TIMEOUT_MINS
        FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.SESSION_POLICIES AS B ON A.POLICY_ID = B.ID
        WHERE A.POLICY_KIND = 'SESSION_POLICY'
          AND A.REF_ENTITY_DOMAIN = 'ACCOUNT'
    """)
    acct_timeout = None
    if acct_policy:
        acct_timeout = acct_policy[0].get("SESSION_IDLE_TIMEOUT_MINS")

    non_compliant = []
    for r in rows:
        user_timeout = r.get("SESSION_IDLE_TIMEOUT_MINS")
        effective = user_timeout if user_timeout is not None else acct_timeout
        if effective is None or int(effective) > 15:
            non_compliant.append(r.get("GRANTEE_NAME", "?"))

    return [make_result(
        "1.9", "Ensure idle session timeout <= 15 min for admin users",
        passed=len(non_compliant) == 0,
        resource_id="account",
        detail=f"Admin users without <=15 min session policy: {len(non_compliant)}"
               + (f" ({', '.join(non_compliant[:5])})" if non_compliant else ""),
        remediation="Create a SESSION POLICY with SESSION_IDLE_TIMEOUT_MINS=15 and apply to admin users.",
        severity="high",
    )]


# ── 1.10  Limit ACCOUNTADMIN/SECURITYADMIN user count ─────────────────
def eval_1_10(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Limit the number of users with ACCOUNTADMIN and SECURITYADMIN."""
    rows = sf.query("""
        SELECT DISTINCT A.GRANTEE_NAME AS NAME, A.ROLE
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS AS A
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS AS B ON A.GRANTEE_NAME = B.NAME
        WHERE A.ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN')
          AND A.DELETED_ON IS NULL
          AND B.DELETED_ON IS NULL AND B.DISABLED = 'false'
    """)
    acct_admins = [r for r in rows if r.get("ROLE") == "ACCOUNTADMIN"]
    sec_admins = [r for r in rows if r.get("ROLE") == "SECURITYADMIN"]
    # CIS: should have 2+ but not excessive (we use <=10 as reasonable)
    passed = 2 <= len(acct_admins) <= 10
    return [make_result(
        "1.10", "Limit the number of users with ACCOUNTADMIN and SECURITYADMIN",
        passed=passed,
        resource_id="account",
        detail=f"ACCOUNTADMIN users: {len(acct_admins)}, SECURITYADMIN users: {len(sec_admins)}",
        remediation="Maintain between 2 and 10 ACCOUNTADMIN users. Revoke unnecessary grants.",
        severity="high",
    )]


# ── 1.11  ACCOUNTADMIN users have email ───────────────────────────────
def eval_1_11(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure all ACCOUNTADMIN users have an email address assigned."""
    rows = sf.query("""
        SELECT DISTINCT A.GRANTEE_NAME AS NAME, B.EMAIL
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS AS A
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS AS B ON A.GRANTEE_NAME = B.NAME
        WHERE A.ROLE = 'ACCOUNTADMIN'
          AND A.DELETED_ON IS NULL
          AND B.DELETED_ON IS NULL
    """)
    no_email = [r for r in rows if not r.get("EMAIL")]
    return [make_result(
        "1.11", "Ensure ACCOUNTADMIN users have an email address assigned",
        passed=len(no_email) == 0,
        resource_id="account",
        detail=f"ACCOUNTADMIN users without email: {len(no_email)}"
               + (f" ({', '.join(r['NAME'] for r in no_email[:5])})" if no_email else ""),
        remediation="ALTER USER <user> SET EMAIL = '<email>';",
        severity="medium",
    )]


# ── 1.12  No admin as default role ────────────────────────────────────
def eval_1_12(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure no users have ACCOUNTADMIN or SECURITYADMIN as default role."""
    rows = sf.query("""
        SELECT NAME, DEFAULT_ROLE
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE DEFAULT_ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN')
          AND DELETED_ON IS NULL AND DISABLED = 'false'
    """)
    return [make_result(
        "1.12", "Ensure no users have ACCOUNTADMIN/SECURITYADMIN as default role",
        passed=len(rows) == 0,
        resource_id="account",
        detail=f"Users with admin default role: {len(rows)}"
               + (f" ({', '.join(r['NAME'] for r in rows[:10])})" if rows else ""),
        remediation="ALTER USER <user> SET DEFAULT_ROLE = '<custom_role>';",
        severity="high",
    )]


# ── 1.13  Admin roles not granted to custom roles ─────────────────────
def eval_1_13(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure ACCOUNTADMIN/SECURITYADMIN is not granted to any custom role."""
    rows = sf.query("""
        SELECT GRANTEE_NAME AS CUSTOM_ROLE,
               PRIVILEGE AS GRANTED_PRIVILEGE,
               NAME AS GRANTED_ROLE
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        WHERE GRANTED_ON = 'ROLE'
          AND NAME IN ('ACCOUNTADMIN','SECURITYADMIN')
          AND DELETED_ON IS NULL
    """)
    # Filter out system roles that legitimately have these
    system_roles = {"ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "ORGADMIN"}
    custom_grants = [r for r in rows if r.get("CUSTOM_ROLE", "").upper() not in system_roles]
    return [make_result(
        "1.13", "Ensure ACCOUNTADMIN/SECURITYADMIN not granted to custom roles",
        passed=len(custom_grants) == 0,
        resource_id="account",
        detail=f"Custom roles with admin role grants: {len(custom_grants)}"
               + (f" ({', '.join(r['CUSTOM_ROLE'] for r in custom_grants[:5])})" if custom_grants else ""),
        remediation="REVOKE ROLE ACCOUNTADMIN FROM ROLE <custom_role>;",
        severity="critical",
    )]


# ── 1.14  Tasks not owned by admin roles ──────────────────────────────
def eval_1_14(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure tasks are not owned by ACCOUNTADMIN or SECURITYADMIN."""
    rows = sf.query("""
        SELECT NAME, GRANTEE_NAME AS ROLE_NAME, PRIVILEGE
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        WHERE GRANTED_ON = 'TASK'
          AND DELETED_ON IS NULL
          AND GRANTED_TO = 'ROLE'
          AND GRANTEE_NAME IN ('ACCOUNTADMIN','SECURITYADMIN')
          AND PRIVILEGE = 'OWNERSHIP'
    """)
    return [make_result(
        "1.14", "Ensure tasks are not owned by ACCOUNTADMIN/SECURITYADMIN",
        passed=len(rows) == 0,
        resource_id="account",
        detail=f"Tasks owned by admin roles: {len(rows)}"
               + (f" ({', '.join(r.get('NAME','?') for r in rows[:5])})" if rows else ""),
        remediation="GRANT OWNERSHIP ON TASK <task> TO ROLE <custom_role>;",
        severity="medium",
    )]


# ── 1.15  Tasks don't run with admin role privileges ──────────────────
def eval_1_15(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure tasks do not run with ACCOUNTADMIN/SECURITYADMIN privileges."""
    rows = sf.query("""
        SELECT NAME, GRANTEE_NAME AS ROLE_NAME, PRIVILEGE
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        WHERE GRANTED_ON = 'TASK'
          AND DELETED_ON IS NULL
          AND GRANTED_TO = 'ROLE'
          AND GRANTEE_NAME IN ('ACCOUNTADMIN','SECURITYADMIN')
          AND PRIVILEGE != 'OWNERSHIP'
    """)
    return [make_result(
        "1.15", "Ensure tasks do not run with ACCOUNTADMIN/SECURITYADMIN privileges",
        passed=len(rows) == 0,
        resource_id="account",
        detail=f"Task grants to admin roles (non-ownership): {len(rows)}",
        remediation="Revoke non-ownership task privileges from admin roles.",
        severity="medium",
    )]


# ── 1.16  Stored procedures not owned by admin roles ──────────────────
def eval_1_16(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure stored procedures are not owned by ACCOUNTADMIN/SECURITYADMIN."""
    rows = sf.query("""
        SELECT PROCEDURE_NAME, PROCEDURE_OWNER
        FROM SNOWFLAKE.ACCOUNT_USAGE.PROCEDURES
        WHERE DELETED IS NULL
          AND PROCEDURE_OWNER IN ('ACCOUNTADMIN','SECURITYADMIN')
    """)
    return [make_result(
        "1.16", "Ensure stored procedures not owned by ACCOUNTADMIN/SECURITYADMIN",
        passed=len(rows) == 0,
        resource_id="account",
        detail=f"Procedures owned by admin roles: {len(rows)}"
               + (f" ({', '.join(r.get('PROCEDURE_NAME','?') for r in rows[:5])})" if rows else ""),
        remediation="GRANT OWNERSHIP ON PROCEDURE <proc> TO ROLE <custom_role>;",
        severity="medium",
    )]


# ── 1.17  Stored procedures don't run with admin privileges ───────────
def eval_1_17(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure stored procedures do not run with admin role privileges."""
    rows = sf.query("""
        SELECT NAME AS PROCEDURE_NAME, GRANTEE_NAME AS ROLE_NAME, PRIVILEGE
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        WHERE GRANTED_ON = 'PROCEDURE'
          AND DELETED_ON IS NULL
          AND GRANTED_TO = 'ROLE'
          AND GRANTEE_NAME IN ('ACCOUNTADMIN','SECURITYADMIN')
    """)
    return [make_result(
        "1.17", "Ensure stored procedures do not run with admin privileges",
        passed=len(rows) == 0,
        resource_id="account",
        detail=f"Procedure grants to admin roles: {len(rows)}",
        remediation="Revoke procedure privileges from admin roles; use custom roles.",
        severity="medium",
    )]


# ── Registry ──────────────────────────────────────────────────────────
SECTION_1_EVALUATORS: dict[str, callable] = {
    "1.1":  eval_1_1,
    "1.2":  eval_1_2,
    "1.3":  eval_1_3,
    "1.4":  eval_1_4,
    "1.5":  eval_1_5,
    "1.6":  eval_1_6,
    "1.7":  eval_1_7,
    "1.8":  eval_1_8,
    "1.9":  eval_1_9,
    "1.10": eval_1_10,
    "1.11": eval_1_11,
    "1.12": eval_1_12,
    "1.13": eval_1_13,
    "1.14": eval_1_14,
    "1.15": eval_1_15,
    "1.16": eval_1_16,
    "1.17": eval_1_17,
}
