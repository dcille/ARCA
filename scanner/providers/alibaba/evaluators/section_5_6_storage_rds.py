"""CIS Alibaba Cloud v2.0 Sections 5-6: Storage (OSS) and RDS -- 18 controls.

Section 5: Storage / OSS (9 controls — 4 automated, 5 manual)
Section 6: Relational Database Services (9 controls — 9 automated)
"""

import logging
from .base import AlibabaClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-Alibaba-2.0"]


# ═══════════════════════════════════════════════════════════════════
# Section 5: Storage (OSS)
# ═══════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────
# 5.1 -- OSS bucket not anonymously/publicly accessible (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_5_1(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    import oss2
    results = []
    try:
        service = c.oss_service()
        buckets = list(oss2.BucketIterator(service))
    except Exception as e:
        return [make_result(cis_id="5.1", check_id="ali_cis_5_1",
            title="Ensure OSS bucket is not anonymously or publicly accessible",
            service="storage", severity="critical", status="ERROR",
            resource_id=cfg.account_id,
            status_extended=f"Failed to list OSS buckets: {e}",
            compliance_frameworks=FW)]

    for b in buckets:
        bucket_name = b.name
        try:
            bucket = c.oss_bucket(bucket_name, endpoint=f"https://{b.extranet_endpoint}")
            acl = bucket.get_bucket_acl()
            acl_grant = acl.acl
            is_public = acl_grant in ("public-read", "public-read-write")
        except Exception as e:
            logger.warning("Failed to check ACL for bucket %s: %s", bucket_name, e)
            continue

        results.append(make_result(
            cis_id="5.1", check_id="ali_cis_5_1",
            title="Ensure OSS bucket is not anonymously or publicly accessible",
            service="storage", severity="critical",
            status="FAIL" if is_public else "PASS",
            resource_id=bucket_name, resource_name=bucket_name,
            region=b.location if hasattr(b, "location") else "",
            status_extended=f"OSS bucket '{bucket_name}': ACL={acl_grant}",
            remediation="Set bucket ACL to private: ossutil set-acl oss://BUCKET private",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="5.1", check_id="ali_cis_5_1",
        title="Ensure OSS bucket is not anonymously or publicly accessible",
        service="storage", severity="critical", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No OSS buckets found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 5.2 -- No publicly accessible objects in buckets (MANUAL)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_5_2(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("5.2", "ali_cis_5_2",
        "Ensure no publicly accessible objects in storage buckets",
        "storage", "critical", cfg.account_id,
        "Requires checking individual object ACLs within each OSS bucket.")]


# ───────────────────────────────────────────────────────────────
# 5.3 -- Logging enabled for OSS buckets (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_5_3(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    import oss2
    results = []
    try:
        service = c.oss_service()
        buckets = list(oss2.BucketIterator(service))
    except Exception:
        return [make_result(cis_id="5.3", check_id="ali_cis_5_3",
            title="Ensure logging is enabled for OSS buckets",
            service="storage", severity="high", status="ERROR",
            resource_id=cfg.account_id,
            status_extended="Failed to list OSS buckets.",
            compliance_frameworks=FW)]

    for b in buckets:
        bucket_name = b.name
        try:
            bucket = c.oss_bucket(bucket_name, endpoint=f"https://{b.extranet_endpoint}")
            logging_info = bucket.get_bucket_logging()
            has_logging = bool(logging_info.target_bucket)
        except Exception:
            has_logging = False

        results.append(make_result(
            cis_id="5.3", check_id="ali_cis_5_3",
            title="Ensure logging is enabled for OSS buckets",
            service="storage", severity="high",
            status="PASS" if has_logging else "FAIL",
            resource_id=bucket_name, resource_name=bucket_name,
            status_extended=f"OSS bucket '{bucket_name}': logging {'enabled' if has_logging else 'disabled'}",
            remediation="Enable bucket logging: ossutil logging --method put oss://BUCKET oss://LOG-BUCKET prefix/",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="5.3", check_id="ali_cis_5_3",
        title="Ensure logging is enabled for OSS buckets",
        service="storage", severity="high", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No OSS buckets found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 5.4 -- Secure transfer required (HTTPS only) (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_5_4(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    import oss2
    results = []
    try:
        service = c.oss_service()
        buckets = list(oss2.BucketIterator(service))
    except Exception:
        return [make_result(cis_id="5.4", check_id="ali_cis_5_4",
            title="Ensure 'Secure transfer required' is set to 'Enabled'",
            service="storage", severity="high", status="ERROR",
            resource_id=cfg.account_id,
            status_extended="Failed to list OSS buckets.",
            compliance_frameworks=FW)]

    for b in buckets:
        bucket_name = b.name
        try:
            bucket = c.oss_bucket(bucket_name, endpoint=f"https://{b.extranet_endpoint}")
            policy_str = bucket.get_bucket_policy()
            import json
            policy = json.loads(policy_str) if isinstance(policy_str, str) else {}
            statements = policy.get("Statement", [])
            https_enforced = any(
                s.get("Effect") == "Deny"
                and s.get("Condition", {}).get("Bool", {}).get("acs:SecureTransport") == "false"
                for s in statements
            )
        except Exception:
            https_enforced = False

        results.append(make_result(
            cis_id="5.4", check_id="ali_cis_5_4",
            title="Ensure 'Secure transfer required' is set to 'Enabled'",
            service="storage", severity="high",
            status="PASS" if https_enforced else "FAIL",
            resource_id=bucket_name, resource_name=bucket_name,
            status_extended=f"OSS bucket '{bucket_name}': HTTPS enforcement {'enabled' if https_enforced else 'not configured'}",
            remediation="Add a bucket policy denying requests where acs:SecureTransport is false.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="5.4", check_id="ali_cis_5_4",
        title="Ensure 'Secure transfer required' is set to 'Enabled'",
        service="storage", severity="high", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No OSS buckets found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 5.5 -- Shared URL signature expires within an hour (MANUAL)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_5_5(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("5.5", "ali_cis_5_5",
        "Ensure shared URL signature expires within an hour",
        "storage", "medium", cfg.account_id,
        "Requires reviewing application code to verify presigned URL expiration policies.")]


# ───────────────────────────────────────────────────────────────
# 5.6 -- URL signature allowed only over HTTPS (MANUAL)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_5_6(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("5.6", "ali_cis_5_6",
        "Ensure URL signature is allowed only over https",
        "storage", "high", cfg.account_id,
        "Requires verifying that all presigned URLs use HTTPS endpoints.")]


# ───────────────────────────────────────────────────────────────
# 5.7 -- Network access rule not publicly accessible (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_5_7(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    import oss2
    results = []
    try:
        service = c.oss_service()
        buckets = list(oss2.BucketIterator(service))
    except Exception:
        return [make_result(cis_id="5.7", check_id="ali_cis_5_7",
            title="Ensure network access rule for storage bucket is not publicly accessible",
            service="storage", severity="critical", status="ERROR",
            resource_id=cfg.account_id,
            status_extended="Failed to list OSS buckets.",
            compliance_frameworks=FW)]

    for b in buckets:
        bucket_name = b.name
        try:
            bucket = c.oss_bucket(bucket_name, endpoint=f"https://{b.extranet_endpoint}")
            acl = bucket.get_bucket_acl()
            acl_grant = acl.acl
            is_public = acl_grant in ("public-read", "public-read-write")
        except Exception:
            is_public = None

        if is_public is None:
            continue

        results.append(make_result(
            cis_id="5.7", check_id="ali_cis_5_7",
            title="Ensure network access rule for storage bucket is not publicly accessible",
            service="storage", severity="critical",
            status="FAIL" if is_public else "PASS",
            resource_id=bucket_name, resource_name=bucket_name,
            status_extended=f"OSS bucket '{bucket_name}': ACL={acl_grant}",
            remediation="Restrict bucket access: set ACL to private and configure bucket policy.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="5.7", check_id="ali_cis_5_7",
        title="Ensure network access rule for storage bucket is not publicly accessible",
        service="storage", severity="critical", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No OSS buckets found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 5.8 -- Server-side encryption with Service Key (MANUAL)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_5_8(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("5.8", "ali_cis_5_8",
        "Ensure server-side encryption is set to 'Encrypt with Service Key'",
        "storage", "high", cfg.account_id,
        "Requires verifying that OSS buckets have server-side encryption configured with SSE-OSS.")]


# ───────────────────────────────────────────────────────────────
# 5.9 -- Server-side encryption with BYOK (MANUAL)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_5_9(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("5.9", "ali_cis_5_9",
        "Ensure server-side encryption is set to 'Encrypt with BYOK'",
        "storage", "high", cfg.account_id,
        "Requires verifying that OSS buckets use SSE-KMS with customer-managed keys (BYOK).")]


# ═══════════════════════════════════════════════════════════════════
# Section 6: Relational Database Services (9 controls — all automated)
# ═══════════════════════════════════════════════════════════════════

def _list_rds_instances(c: AlibabaClientCache, cfg: EvalConfig) -> list:
    """List all RDS instances across configured regions."""
    from alibabacloud_rds20140815 import models as rds_models
    all_instances = []
    for region in cfg.regions:
        try:
            resp = c.rds(region).describe_dbinstances(rds_models.DescribeDBInstancesRequest(
                region_id=region,
            ))
            items = resp.body.items
            instances = items.dbinstance if items and items.dbinstance else []
            for inst in instances:
                inst._region = region
            all_instances.extend(instances)
        except Exception as e:
            logger.warning("Failed to list RDS instances in %s: %s", region, e)
    return all_instances


# ───────────────────────────────────────────────────────────────
# 6.1 -- RDS requires SSL (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_6_1(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_rds20140815 import models as rds_models
    results = []
    instances = _list_rds_instances(c, cfg)

    for inst in instances:
        db_id = inst.dbinstance_id
        region = getattr(inst, "_region", cfg.regions[0])
        try:
            ssl_resp = c.rds(region).describe_dbinstance_sslaction(
                rds_models.DescribeDBInstanceSSLActionRequest(dbinstance_id=db_id))
            ssl_status = getattr(ssl_resp.body, "require_update", None)
            ssl_enabled = getattr(ssl_resp.body, "sslstatus", "") == "Yes"
        except Exception:
            ssl_enabled = False

        results.append(make_result(
            cis_id="6.1", check_id="ali_cis_6_1",
            title="Ensure RDS instance requires all incoming connections to use SSL",
            service="database", severity="high",
            status="PASS" if ssl_enabled else "FAIL",
            resource_id=db_id, resource_name=db_id, region=region,
            status_extended=f"RDS instance '{db_id}': SSL {'enabled' if ssl_enabled else 'not enabled'}",
            remediation="Enable SSL: aliyun rds ModifyDBInstanceSSL --DBInstanceId ID --SSLEnabled 1",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="6.1", check_id="ali_cis_6_1",
        title="Ensure RDS instance requires all incoming connections to use SSL",
        service="database", severity="high", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No RDS instances found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 6.2 -- RDS instances not open to the world (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_6_2(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_rds20140815 import models as rds_models
    results = []
    instances = _list_rds_instances(c, cfg)

    for inst in instances:
        db_id = inst.dbinstance_id
        region = getattr(inst, "_region", cfg.regions[0])
        try:
            sec_resp = c.rds(region).describe_dbinstance_ip_array_list(
                rds_models.DescribeDBInstanceIPArrayListRequest(dbinstance_id=db_id))
            ip_arrays = sec_resp.body.items.dbinstance_iparray if (
                sec_resp.body.items and sec_resp.body.items.dbinstance_iparray
            ) else []
            open_to_world = any(
                "0.0.0.0/0" in (getattr(arr, "security_iplist", "") or "")
                for arr in ip_arrays
            )
        except Exception:
            open_to_world = False

        results.append(make_result(
            cis_id="6.2", check_id="ali_cis_6_2",
            title="Ensure RDS Instances are not open to the world",
            service="database", severity="medium",
            status="FAIL" if open_to_world else "PASS",
            resource_id=db_id, resource_name=db_id, region=region,
            status_extended=f"RDS '{db_id}': {'open to 0.0.0.0/0' if open_to_world else 'restricted IP whitelist'}",
            remediation="Remove 0.0.0.0/0 from IP whitelist: aliyun rds ModifySecurityIps",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="6.2", check_id="ali_cis_6_2",
        title="Ensure RDS Instances are not open to the world",
        service="database", severity="medium", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No RDS instances found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 6.3 -- Auditing is on (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_6_3(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_rds20140815 import models as rds_models
    results = []
    instances = _list_rds_instances(c, cfg)

    for inst in instances:
        db_id = inst.dbinstance_id
        region = getattr(inst, "_region", cfg.regions[0])
        try:
            audit_resp = c.rds(region).describe_sqlcollector_policy(
                rds_models.DescribeSQLCollectorPolicyRequest(dbinstance_id=db_id))
            audit_on = getattr(audit_resp.body, "sqlcollector_status", "") == "Enable"
        except Exception:
            audit_on = False

        results.append(make_result(
            cis_id="6.3", check_id="ali_cis_6_3",
            title="Ensure 'Auditing' is set to 'On' for applicable database instances",
            service="database", severity="high",
            status="PASS" if audit_on else "FAIL",
            resource_id=db_id, resource_name=db_id, region=region,
            status_extended=f"RDS '{db_id}': SQL audit {'enabled' if audit_on else 'disabled'}",
            remediation="Enable SQL audit: aliyun rds ModifySQLCollectorPolicy --DBInstanceId ID --SQLCollectorStatus Enable",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="6.3", check_id="ali_cis_6_3",
        title="Ensure 'Auditing' is set to 'On' for applicable database instances",
        service="database", severity="high", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No RDS instances found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 6.4 -- Audit retention > 6 months (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_6_4(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_rds20140815 import models as rds_models
    results = []
    instances = _list_rds_instances(c, cfg)

    for inst in instances:
        db_id = inst.dbinstance_id
        region = getattr(inst, "_region", cfg.regions[0])
        try:
            audit_resp = c.rds(region).describe_sqlcollector_retention(
                rds_models.DescribeSQLCollectorRetentionRequest(dbinstance_id=db_id))
            retention = getattr(audit_resp.body, "config_value", "0")
            retention_days = int(retention) if retention else 0
            sufficient = retention_days >= 180
        except Exception:
            retention_days = 0
            sufficient = False

        results.append(make_result(
            cis_id="6.4", check_id="ali_cis_6_4",
            title="Ensure 'Auditing' Retention is greater than 6 months",
            service="database", severity="high",
            status="PASS" if sufficient else "FAIL",
            resource_id=db_id, resource_name=db_id, region=region,
            status_extended=f"RDS '{db_id}': audit retention={retention_days} days (required >= 180)",
            remediation="Increase SQL audit retention to at least 180 days.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="6.4", check_id="ali_cis_6_4",
        title="Ensure 'Auditing' Retention is greater than 6 months",
        service="database", severity="high", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No RDS instances found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 6.5 -- TDE enabled (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_6_5(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_rds20140815 import models as rds_models
    results = []
    instances = _list_rds_instances(c, cfg)
    # TDE is applicable to MySQL and SQL Server
    tde_engines = {"mysql", "mssql", "sqlserver"}

    for inst in instances:
        db_id = inst.dbinstance_id
        engine = (getattr(inst, "engine", "") or "").lower()
        region = getattr(inst, "_region", cfg.regions[0])

        if engine not in tde_engines:
            continue

        try:
            tde_resp = c.rds(region).describe_dbinstance_tde(
                rds_models.DescribeDBInstanceTDERequest(dbinstance_id=db_id))
            tde_status = getattr(tde_resp.body, "tdestatus", "") == "Enabled"
        except Exception:
            tde_status = False

        results.append(make_result(
            cis_id="6.5", check_id="ali_cis_6_5",
            title="Ensure TDE is set to 'Enabled' on applicable database instances",
            service="database", severity="high",
            status="PASS" if tde_status else "FAIL",
            resource_id=db_id, resource_name=db_id, region=region,
            status_extended=f"RDS '{db_id}' ({engine}): TDE {'enabled' if tde_status else 'disabled'}",
            remediation="Enable TDE: aliyun rds ModifyDBInstanceTDE --DBInstanceId ID --TDEStatus Enabled",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="6.5", check_id="ali_cis_6_5",
        title="Ensure TDE is set to 'Enabled' on applicable database instances",
        service="database", severity="high", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No applicable RDS instances (MySQL/SQL Server) found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 6.6 -- TDE protector encrypted with BYOK (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_6_6(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_rds20140815 import models as rds_models
    results = []
    instances = _list_rds_instances(c, cfg)
    tde_engines = {"mysql", "mssql", "sqlserver"}

    for inst in instances:
        db_id = inst.dbinstance_id
        engine = (getattr(inst, "engine", "") or "").lower()
        region = getattr(inst, "_region", cfg.regions[0])

        if engine not in tde_engines:
            continue

        try:
            tde_resp = c.rds(region).describe_dbinstance_tde(
                rds_models.DescribeDBInstanceTDERequest(dbinstance_id=db_id))
            tde_status = getattr(tde_resp.body, "tdestatus", "") == "Enabled"
            encryption_key = getattr(tde_resp.body, "tdekey", "") or ""
            uses_byok = tde_status and bool(encryption_key)
        except Exception:
            uses_byok = False

        results.append(make_result(
            cis_id="6.6", check_id="ali_cis_6_6",
            title="Ensure RDS instance TDE protector is encrypted with BYOK",
            service="database", severity="high",
            status="PASS" if uses_byok else "FAIL",
            resource_id=db_id, resource_name=db_id, region=region,
            status_extended=f"RDS '{db_id}': TDE BYOK {'configured' if uses_byok else 'not configured'}",
            remediation="Enable TDE with customer-managed KMS key (BYOK).",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id="6.6", check_id="ali_cis_6_6",
        title="Ensure RDS instance TDE protector is encrypted with BYOK",
        service="database", severity="high", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No applicable RDS instances found.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 6.7 -- PostgreSQL log_connections ON (automated)
# ───────────────────────────────────────────────────────────────

def _check_pg_parameter(c, cfg, cis_id, check_id, title, param_name, expected_value):
    """Check a PostgreSQL RDS parameter."""
    from alibabacloud_rds20140815 import models as rds_models
    results = []
    instances = _list_rds_instances(c, cfg)

    for inst in instances:
        engine = (getattr(inst, "engine", "") or "").lower()
        if engine != "postgresql":
            continue

        db_id = inst.dbinstance_id
        region = getattr(inst, "_region", cfg.regions[0])
        try:
            param_resp = c.rds(region).describe_parameters(
                rds_models.DescribeParametersRequest(dbinstance_id=db_id))
            running_params = param_resp.body.running_parameters
            params = running_params.dbinstance_parameter if (
                running_params and running_params.dbinstance_parameter
            ) else []
            actual = None
            for p in params:
                if p.parameter_name == param_name:
                    actual = p.parameter_value
                    break
            passed = actual is not None and actual.lower() == expected_value.lower()
        except Exception:
            actual = None
            passed = False

        results.append(make_result(
            cis_id=cis_id, check_id=check_id,
            title=title, service="database", severity="medium",
            status="PASS" if passed else "FAIL",
            resource_id=db_id, resource_name=db_id, region=region,
            status_extended=f"RDS PostgreSQL '{db_id}': {param_name}={actual} (expected {expected_value})",
            remediation=f"Set parameter {param_name} to {expected_value} via RDS Console or API.",
            compliance_frameworks=FW,
        ))

    return results or [make_result(cis_id=cis_id, check_id=check_id,
        title=title, service="database", severity="medium", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No PostgreSQL RDS instances found.",
        compliance_frameworks=FW)]


def evaluate_cis_6_7(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_pg_parameter(c, cfg, "6.7", "ali_cis_6_7",
        "Ensure parameter 'log_connections' is set to 'ON' for PostgreSQL Database",
        "log_connections", "on")


# ───────────────────────────────────────────────────────────────
# 6.8 -- PostgreSQL log_disconnections ON (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_6_8(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_pg_parameter(c, cfg, "6.8", "ali_cis_6_8",
        "Ensure parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database",
        "log_disconnections", "on")


# ───────────────────────────────────────────────────────────────
# 6.9 -- PostgreSQL log_duration ON (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_6_9(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_pg_parameter(c, cfg, "6.9", "ali_cis_6_9",
        "Ensure parameter 'log_duration' is set to 'ON' for PostgreSQL Database Server",
        "log_duration", "on")
