"""CIS Snowflake v1.0.0 — Section 3: Networking + Section 4: Data Protection.

Section 3: 2 controls (both CIS-manual, upgradeable via supplements)
Section 4: 11 controls (7 automated, 4 manual — 2 upgradeable)
"""

from __future__ import annotations
from .base import SnowflakeClientCache, CheckResult, make_result, make_manual


# ═══════════════════════════════════════════════════════════════════════
# Section 3: Networking
# ═══════════════════════════════════════════════════════════════════════

# ── 3.1  Account-level network policy configured ─────────────────────
def eval_3_1(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure account-level network policy is configured (CIS: Manual)."""
    return [make_manual(
        "3.1",
        "Ensure account-level network policy only allows trusted IPs",
        resource_id="account",
        detail="Run: SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT; "
               "then DESCRIBE NETWORK POLICY <name>; and verify ALLOWED_IP_LIST.",
        remediation="CREATE NETWORK POLICY <name> ALLOWED_IP_LIST=('x.x.x.x/y'); "
                    "ALTER ACCOUNT SET NETWORK_POLICY = <name>;",
        severity="high",
        cis_level=2,
    )]


# ── 3.2  User-level network policies for service accounts ────────────
def eval_3_2(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure user-level network policies for service accounts (CIS: Manual)."""
    return [make_manual(
        "3.2",
        "Ensure user-level network policies for service accounts",
        resource_id="account",
        detail="For each service account, run: "
               "SHOW PARAMETERS LIKE 'NETWORK_POLICY' FOR USER <svc>; "
               "then DESCRIBE NETWORK POLICY <name>;",
        remediation="ALTER USER <svc> SET NETWORK_POLICY = <policy>;",
        severity="medium",
    )]


# ═══════════════════════════════════════════════════════════════════════
# Section 4: Data Protection
# ═══════════════════════════════════════════════════════════════════════

# ── 4.1  Yearly rekeying enabled ──────────────────────────────────────
def eval_4_1(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure yearly rekeying is enabled for the Snowflake account."""
    val = sf.show_parameter("PERIODIC_DATA_REKEYING")
    enabled = val is not None and val.strip().lower() == "true"
    return [make_result(
        "4.1", "Ensure yearly rekeying is enabled",
        passed=enabled,
        resource_id="account",
        detail=f"PERIODIC_DATA_REKEYING = {val}",
        remediation="ALTER ACCOUNT SET PERIODIC_DATA_REKEYING = TRUE;",
        severity="high",
    )]


# ── 4.2  AES 256-bit encryption for internal stages ──────────────────
def eval_4_2(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure AES key size for internal stages is 256 bits."""
    val = sf.show_parameter("CLIENT_ENCRYPTION_KEY_SIZE")
    key_size = int(val) if val and val.isdigit() else 128
    return [make_result(
        "4.2", "Ensure AES encryption key size for internal stages is 256 bits",
        passed=key_size == 256,
        resource_id="account",
        detail=f"CLIENT_ENCRYPTION_KEY_SIZE = {val}",
        remediation="ALTER ACCOUNT SET CLIENT_ENCRYPTION_KEY_SIZE = 256;",
        severity="high",
    )]


# ── 4.3  DATA_RETENTION_TIME_IN_DAYS >= 90 for critical data (Manual) ─
def eval_4_3(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure DATA_RETENTION_TIME_IN_DAYS >= 90 for critical data."""
    return [make_manual(
        "4.3",
        "Ensure DATA_RETENTION_TIME_IN_DAYS is set to 90 for critical data",
        resource_id="account",
        detail="Identify critical databases/schemas and verify each has "
               "DATA_RETENTION_TIME_IN_DAYS >= 90. "
               "Check: SHOW PARAMETERS LIKE 'DATA_RETENTION_TIME_IN_DAYS' IN DATABASE <db>;",
        remediation="ALTER DATABASE <db> SET DATA_RETENTION_TIME_IN_DAYS = 90;",
        severity="high",
    )]


# ── 4.4  MIN_DATA_RETENTION_TIME_IN_DAYS >= 7 ────────────────────────
def eval_4_4(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure MIN_DATA_RETENTION_TIME_IN_DAYS account parameter >= 7."""
    val = sf.show_parameter("MIN_DATA_RETENTION_TIME_IN_DAYS")
    days = int(val) if val and val.isdigit() else 0
    return [make_result(
        "4.4", "Ensure MIN_DATA_RETENTION_TIME_IN_DAYS >= 7",
        passed=days >= 7,
        resource_id="account",
        detail=f"MIN_DATA_RETENTION_TIME_IN_DAYS = {val}",
        remediation="ALTER ACCOUNT SET MIN_DATA_RETENTION_TIME_IN_DAYS = 7;",
        severity="high",
    )]


# ── 4.5  REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION = true ───────
def eval_4_5(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION is true."""
    enabled = sf.show_parameter_bool("REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION")
    return [make_result(
        "4.5", "Ensure REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION is true",
        passed=enabled,
        resource_id="account",
        detail=f"REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION = {enabled}",
        remediation="ALTER ACCOUNT SET REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION = TRUE;",
        severity="high",
    )]


# ── 4.6  REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION = true ──────
def eval_4_6(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION is true."""
    enabled = sf.show_parameter_bool("REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION")
    return [make_result(
        "4.6", "Ensure REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION is true",
        passed=enabled,
        resource_id="account",
        detail=f"REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION = {enabled}",
        remediation="ALTER ACCOUNT SET REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION = TRUE;",
        severity="high",
    )]


# ── 4.7  All external stages have storage integrations ───────────────
def eval_4_7(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure all external stages have storage integrations."""
    stages = sf.query("SHOW STAGES")
    external = [
        s for s in stages
        if str(s.get("TYPE", "")).upper() == "EXTERNAL"
    ]
    no_integration = [
        s for s in external
        if not s.get("STORAGE_INTEGRATION")
        or str(s.get("STORAGE_INTEGRATION", "")).strip() == ""
    ]
    return [make_result(
        "4.7", "Ensure all external stages have storage integrations",
        passed=len(no_integration) == 0,
        resource_id="account",
        detail=f"External stages without storage integration: {len(no_integration)}/{len(external)}"
               + (f" ({', '.join(s.get('NAME','?') for s in no_integration[:5])})" if no_integration else ""),
        remediation="Recreate external stages with STORAGE_INTEGRATION = <integration_name>;",
        severity="high",
    )]


# ── 4.8  PREVENT_UNLOAD_TO_INLINE_URL = true ─────────────────────────
def eval_4_8(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure PREVENT_UNLOAD_TO_INLINE_URL is true."""
    enabled = sf.show_parameter_bool("PREVENT_UNLOAD_TO_INLINE_URL")
    return [make_result(
        "4.8", "Ensure PREVENT_UNLOAD_TO_INLINE_URL is true",
        passed=enabled,
        resource_id="account",
        detail=f"PREVENT_UNLOAD_TO_INLINE_URL = {enabled}",
        remediation="ALTER ACCOUNT SET PREVENT_UNLOAD_TO_INLINE_URL = TRUE;",
        severity="high",
    )]


# ── 4.9  Tri-Secret Secure enabled (Manual) ──────────────────────────
def eval_4_9(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure Tri-Secret Secure is enabled for the Snowflake account."""
    return [make_manual(
        "4.9",
        "Ensure Tri-Secret Secure is enabled",
        resource_id="account",
        detail="Tri-Secret Secure requires contacting Snowflake Support to enable. "
               "Cannot be verified via SQL. Check with your Snowflake account team.",
        remediation="Contact Snowflake Support to enable Tri-Secret Secure (customer-managed key + Snowflake key).",
        severity="high",
    )]


# ── 4.10  Data masking enabled for sensitive data (Manual) ────────────
def eval_4_10(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure data masking is enabled for sensitive data."""
    return [make_manual(
        "4.10",
        "Ensure data masking is enabled for sensitive data",
        resource_id="account",
        detail="Run: SHOW MASKING POLICIES IN ACCOUNT; "
               "Verify that masking policies exist and are applied to sensitive columns.",
        remediation="CREATE MASKING POLICY and apply to columns containing sensitive data.",
        severity="high",
    )]


# ── 4.11  Row-access policies for sensitive data (Manual) ─────────────
def eval_4_11(sf: SnowflakeClientCache) -> list[CheckResult]:
    """Ensure row-access policies are configured for sensitive data."""
    return [make_manual(
        "4.11",
        "Ensure row-access policies are configured for sensitive data",
        resource_id="account",
        detail="Run: SHOW ROW ACCESS POLICIES IN ACCOUNT; "
               "Verify that row-access policies exist and are applied to sensitive tables.",
        remediation="CREATE ROW ACCESS POLICY and apply to tables with sensitive data.",
        severity="medium",
    )]


# ── Registries ────────────────────────────────────────────────────────
SECTION_3_EVALUATORS: dict[str, callable] = {
    "3.1": eval_3_1,
    "3.2": eval_3_2,
}

SECTION_4_EVALUATORS: dict[str, callable] = {
    "4.1":  eval_4_1,
    "4.2":  eval_4_2,
    "4.3":  eval_4_3,
    "4.4":  eval_4_4,
    "4.5":  eval_4_5,
    "4.6":  eval_4_6,
    "4.7":  eval_4_7,
    "4.8":  eval_4_8,
    "4.9":  eval_4_9,
    "4.10": eval_4_10,
    "4.11": eval_4_11,
}
