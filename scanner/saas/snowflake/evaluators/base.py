"""Snowflake CIS evaluator base — connection cache and helpers.

Authentication: username/password or key-pair via snowflake-connector-python.
All queries target SNOWFLAKE.ACCOUNT_USAGE (read-only).
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CheckResult builder (matches D-ARCA output format)
# ---------------------------------------------------------------------------
@dataclass
class CheckResult:
    cis_id: str
    title: str
    status: str  # PASS | FAIL | MANUAL | ERROR
    resource_id: str = ""
    detail: str = ""
    remediation: str = ""
    severity: str = "medium"
    cis_level: int = 1
    assessment_type: str = "automated"


def make_result(
    cis_id: str,
    title: str,
    passed: bool,
    resource_id: str = "",
    detail: str = "",
    remediation: str = "",
    severity: str = "medium",
    cis_level: int = 1,
) -> CheckResult:
    return CheckResult(
        cis_id=cis_id,
        title=title,
        status="PASS" if passed else "FAIL",
        resource_id=resource_id,
        detail=detail,
        remediation=remediation,
        severity=severity,
        cis_level=cis_level,
    )


def make_manual(
    cis_id: str,
    title: str,
    resource_id: str = "",
    detail: str = "",
    remediation: str = "",
    severity: str = "medium",
    cis_level: int = 1,
) -> CheckResult:
    return CheckResult(
        cis_id=cis_id,
        title=title,
        status="MANUAL",
        resource_id=resource_id,
        detail=detail,
        remediation=remediation,
        severity=severity,
        cis_level=cis_level,
        assessment_type="manual",
    )


# ---------------------------------------------------------------------------
# safe_evaluate — isolates individual control failures
# ---------------------------------------------------------------------------
def safe_evaluate(fn, *args, **kwargs) -> list[CheckResult]:
    try:
        result = fn(*args, **kwargs)
        return result if isinstance(result, list) else [result]
    except Exception as exc:
        logger.error("Evaluator %s failed: %s", getattr(fn, "__name__", fn), exc)
        return []


# ---------------------------------------------------------------------------
# SnowflakeClientCache — lazy Snowflake connection
# ---------------------------------------------------------------------------
class SnowflakeClientCache:
    """Caches a snowflake-connector-python connection and provides helpers."""

    def __init__(
        self,
        account: str,
        username: str,
        password: str | None = None,
        private_key: bytes | None = None,
        warehouse: str | None = None,
        role: str | None = None,
    ):
        self._account = account
        self._username = username
        self._password = password
        self._private_key = private_key
        self._warehouse = warehouse
        self._role = role or "ACCOUNTADMIN"
        self._conn = None

    # -- connection ----------------------------------------------------------
    def _connect(self):
        import snowflake.connector

        params: dict[str, Any] = dict(
            user=self._username,
            account=self._account,
            database="SNOWFLAKE",
            schema="ACCOUNT_USAGE",
        )
        if self._password:
            params["password"] = self._password
        if self._private_key:
            # Deserialize PEM bytes to cryptography private key object
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )
            pem = self._private_key
            if isinstance(pem, str):
                pem = pem.encode("utf-8")
            params["private_key"] = load_pem_private_key(pem, password=None)
        if self._warehouse:
            params["warehouse"] = self._warehouse
        if self._role:
            params["role"] = self._role

        self._conn = snowflake.connector.connect(**params)
        return self._conn

    @property
    def conn(self):
        if self._conn is None:
            self._connect()
        return self._conn

    # -- query helpers -------------------------------------------------------
    def query(self, sql: str) -> list[dict]:
        """Execute SQL, return list of row-dicts with UPPER column names."""
        cur = self.conn.cursor()
        try:
            cur.execute(sql)
            cols = [d[0].upper() for d in cur.description] if cur.description else []
            return [dict(zip(cols, row)) for row in cur.fetchall()]
        finally:
            cur.close()

    def query_scalar(self, sql: str, default=None):
        """Return the single-value result of a scalar query."""
        rows = self.query(sql)
        if rows:
            first_val = next(iter(rows[0].values()), default)
            return first_val
        return default

    def show_parameter(self, name: str) -> str | None:
        """SHOW PARAMETERS LIKE 'name' IN ACCOUNT → value string or None."""
        rows = self.query(f"SHOW PARAMETERS LIKE '{name}' IN ACCOUNT")
        for r in rows:
            val = r.get("VALUE", r.get("value"))
            if val is not None:
                return str(val)
        return None

    def show_parameter_bool(self, name: str) -> bool:
        val = self.show_parameter(name)
        return val is not None and val.strip().lower() == "true"

    def close(self):
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
