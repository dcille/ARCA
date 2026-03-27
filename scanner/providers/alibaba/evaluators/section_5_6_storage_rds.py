"""CIS Alibaba v2.0 Sections 5–6.

Section 5 — Storage/OSS (9 controls): 5.1/5.3/5.4/5.7 automated, rest manual
Section 6 — Relational Database Services (9 controls): all automated
"""
from __future__ import annotations
from .base import (AlibabaClientCache, EvalConfig, make_result, make_manual_result, logger)


# ═════════════════════════════════════════════════════════════════
# Section 5: Storage (OSS)
# ═════════════════════════════════════════════════════════════════

def evaluate_5_1(c: AlibabaClientCache, cfg: EvalConfig):
    """OSS buckets not publicly accessible."""
    import oss2
    results = []
    auth = c.oss_auth()
    service = oss2.Service(auth, f"https://oss-{cfg.regions[0]}.aliyuncs.com")
    for b in oss2.BucketIterator(service):
        bucket = oss2.Bucket(auth, f"https://oss-{b.location}.aliyuncs.com", b.name)
        try:
            acl = bucket.get_bucket_acl()
            public = acl.acl in ("public-read", "public-read-write")
        except Exception: public = False
        results.append(make_result("5.1", "OSS bucket not publicly accessible",
            b.name, b.name, not public, severity="critical", service="OSS",
            remediation="Set bucket ACL to private"))
    return results

def evaluate_5_2(c, cfg): return [make_manual_result("5.2", "No publicly accessible objects in storage buckets", "OSS", "critical")]

def evaluate_5_3(c: AlibabaClientCache, cfg: EvalConfig):
    """OSS bucket logging enabled."""
    import oss2
    results = []
    auth = c.oss_auth()
    service = oss2.Service(auth, f"https://oss-{cfg.regions[0]}.aliyuncs.com")
    for b in oss2.BucketIterator(service):
        bucket = oss2.Bucket(auth, f"https://oss-{b.location}.aliyuncs.com", b.name)
        try:
            log_cfg = bucket.get_bucket_logging()
            enabled = bool(log_cfg.target_bucket)
        except Exception: enabled = False
        results.append(make_result("5.3", "OSS bucket logging enabled",
            b.name, b.name, enabled, severity="high", service="OSS",
            remediation="Enable access logging for the bucket"))
    return results

def evaluate_5_4(c: AlibabaClientCache, cfg: EvalConfig):
    """Secure transfer required (HTTPS)."""
    import oss2
    results = []
    auth = c.oss_auth()
    service = oss2.Service(auth, f"https://oss-{cfg.regions[0]}.aliyuncs.com")
    for b in oss2.BucketIterator(service):
        bucket = oss2.Bucket(auth, f"https://oss-{b.location}.aliyuncs.com", b.name)
        try:
            policy = bucket.get_bucket_policy()
            txt = policy.policy if hasattr(policy, 'policy') else str(policy)
            https = "SecureTransport" in txt
        except Exception: https = False
        results.append(make_result("5.4", "Secure transfer required enabled",
            b.name, b.name, https, severity="high", service="OSS",
            remediation="Add bucket policy denying non-SSL requests"))
    return results

def evaluate_5_5(c, cfg): return [make_manual_result("5.5", "Shared URL signature expires within an hour", "OSS", "medium")]
def evaluate_5_6(c, cfg): return [make_manual_result("5.6", "URL signature allowed only over HTTPS", "OSS", "high")]

def evaluate_5_7(c: AlibabaClientCache, cfg: EvalConfig):
    """Network access rule not publicly accessible."""
    import oss2
    results = []
    auth = c.oss_auth()
    service = oss2.Service(auth, f"https://oss-{cfg.regions[0]}.aliyuncs.com")
    for b in oss2.BucketIterator(service):
        bucket = oss2.Bucket(auth, f"https://oss-{b.location}.aliyuncs.com", b.name)
        try:
            policy = bucket.get_bucket_policy()
            txt = policy.policy if hasattr(policy, 'policy') else str(policy)
            # Check for IP restrictions in policy
            restricted = "IpAddress" in txt or "SourceVpc" in txt
        except Exception: restricted = False
        results.append(make_result("5.7", "OSS network access restricted to specific IPs",
            b.name, b.name, restricted, severity="critical", service="OSS",
            remediation="Add bucket policy restricting access to specific IP/VPC"))
    return results

def evaluate_5_8(c, cfg): return [make_manual_result("5.8", "Server-side encryption set to Encrypt with Service Key", "OSS", "high")]
def evaluate_5_9(c, cfg): return [make_manual_result("5.9", "Server-side encryption set to Encrypt with BYOK", "OSS", "high")]


# ═════════════════════════════════════════════════════════════════
# Section 6: Relational Database Services (all automated)
# ═════════════════════════════════════════════════════════════════

def evaluate_6_1(c: AlibabaClientCache, cfg: EvalConfig):
    """RDS instance requires SSL connections."""
    from alibabacloud_rds20140815 import models as m
    results = []
    for region in cfg.regions:
        client = c.rds(region)
        dbs = client.describe_dbinstances(m.DescribeDBInstancesRequest(region_id=region, page_size=100)).body.items.dbinstance or []
        for db in dbs:
            try:
                ssl = client.describe_dbinstance_ssl(m.DescribeDBInstanceSSLRequest(dbinstance_id=db.dbinstance_id))
                enabled = bool(ssl.body.sslexpire_time)
            except Exception: enabled = False
            results.append(make_result("6.1", "RDS requires SSL connections",
                db.dbinstance_id, db.dbinstance_description or db.dbinstance_id, enabled,
                severity="high", service="RDS",
                remediation="Enable SSL encryption for RDS connections"))
    return results


def evaluate_6_2(c: AlibabaClientCache, cfg: EvalConfig):
    """RDS not open to the world (whitelist)."""
    from alibabacloud_rds20140815 import models as m
    results = []
    for region in cfg.regions:
        client = c.rds(region)
        dbs = client.describe_dbinstances(m.DescribeDBInstancesRequest(region_id=region, page_size=100)).body.items.dbinstance or []
        for db in dbs:
            try:
                ip_resp = client.describe_dbinstance_iparray_list(m.DescribeDBInstanceIPArrayListRequest(dbinstance_id=db.dbinstance_id))
                open_world = any("0.0.0.0/0" in (arr.security_iplist or "") or "0.0.0.0" in (arr.security_iplist or "").split(",")
                    for arr in ip_resp.body.items.dbinstance_iparray or [])
            except Exception: open_world = False
            results.append(make_result("6.2", "RDS instances not open to the world",
                db.dbinstance_id, db.dbinstance_description or db.dbinstance_id, not open_world,
                severity="medium", service="RDS",
                remediation="Remove 0.0.0.0/0 from RDS IP whitelist"))
    return results


def evaluate_6_3(c: AlibabaClientCache, cfg: EvalConfig):
    """SQL auditing enabled."""
    from alibabacloud_rds20140815 import models as m
    results = []
    for region in cfg.regions:
        client = c.rds(region)
        dbs = client.describe_dbinstances(m.DescribeDBInstancesRequest(region_id=region, page_size=100)).body.items.dbinstance or []
        for db in dbs:
            try:
                audit = client.describe_sqlcollector_policy(m.DescribeSQLCollectorPolicyRequest(dbinstance_id=db.dbinstance_id))
                enabled = audit.body.sqlcollector_status == "Enable"
            except Exception: enabled = False
            results.append(make_result("6.3", "Auditing is On for database instances",
                db.dbinstance_id, db.dbinstance_description or db.dbinstance_id, enabled,
                severity="high", service="RDS", remediation="Enable SQL Explorer/Auditing"))
    return results


def evaluate_6_4(c: AlibabaClientCache, cfg: EvalConfig):
    """Auditing retention > 6 months."""
    from alibabacloud_rds20140815 import models as m
    results = []
    for region in cfg.regions:
        client = c.rds(region)
        dbs = client.describe_dbinstances(m.DescribeDBInstancesRequest(region_id=region, page_size=100)).body.items.dbinstance or []
        for db in dbs:
            try:
                audit = client.describe_sqlcollector_retention(m.DescribeSQLCollectorRetentionRequest(dbinstance_id=db.dbinstance_id))
                retention = int(getattr(audit.body, 'config_value', 0) or 0)
                ok = retention >= 180
            except Exception: ok = False
            results.append(make_result("6.4", "Auditing retention > 6 months",
                db.dbinstance_id, db.dbinstance_description or db.dbinstance_id, ok,
                severity="high", service="RDS", remediation="Set SQL audit retention to 6+ months"))
    return results


def evaluate_6_5(c: AlibabaClientCache, cfg: EvalConfig):
    """TDE enabled."""
    from alibabacloud_rds20140815 import models as m
    results = []
    for region in cfg.regions:
        client = c.rds(region)
        dbs = client.describe_dbinstances(m.DescribeDBInstancesRequest(region_id=region, page_size=100)).body.items.dbinstance or []
        for db in dbs:
            try:
                tde = client.describe_dbinstance_tde(m.DescribeDBInstanceTDERequest(dbinstance_id=db.dbinstance_id))
                enabled = tde.body.tdestatus == "Enabled"
            except Exception: enabled = False
            results.append(make_result("6.5", "TDE enabled on database instance",
                db.dbinstance_id, db.dbinstance_description or db.dbinstance_id, enabled,
                severity="high", service="RDS", remediation="Enable Transparent Data Encryption"))
    return results


def evaluate_6_6(c: AlibabaClientCache, cfg: EvalConfig):
    """TDE protector encrypted with BYOK."""
    from alibabacloud_rds20140815 import models as m
    results = []
    for region in cfg.regions:
        client = c.rds(region)
        dbs = client.describe_dbinstances(m.DescribeDBInstancesRequest(region_id=region, page_size=100)).body.items.dbinstance or []
        for db in dbs:
            try:
                tde = client.describe_dbinstance_tde(m.DescribeDBInstanceTDERequest(dbinstance_id=db.dbinstance_id))
                byok = tde.body.tdestatus == "Enabled" and bool(getattr(tde.body, 'tdemethod', None))
            except Exception: byok = False
            results.append(make_result("6.6", "RDS TDE protector encrypted with BYOK",
                db.dbinstance_id, db.dbinstance_description or db.dbinstance_id, byok,
                severity="high", service="RDS", remediation="Enable TDE with customer-managed key"))
    return results


def _eval_pg_param(c, cfg, param_name, cis_id, title):
    from alibabacloud_rds20140815 import models as m
    results = []
    for region in cfg.regions:
        client = c.rds(region)
        dbs = client.describe_dbinstances(m.DescribeDBInstancesRequest(region_id=region, page_size=100)).body.items.dbinstance or []
        for db in dbs:
            if (getattr(db, 'engine', '') or '').lower() != 'postgresql': continue
            try:
                params = client.describe_parameters(m.DescribeParametersRequest(dbinstance_id=db.dbinstance_id))
                val = "off"
                for p in params.body.running_parameters.dbinstance_parameter or []:
                    if p.parameter_name == param_name:
                        val = p.parameter_value; break
                ok = val.lower() == "on"
            except Exception: ok = False
            results.append(make_result(cis_id, title,
                db.dbinstance_id, db.dbinstance_description or db.dbinstance_id, ok,
                severity="medium", service="RDS",
                remediation=f"Set {param_name} to ON in RDS parameters"))
    return results

def evaluate_6_7(c, cfg): return _eval_pg_param(c, cfg, "log_connections", "6.7", "PostgreSQL log_connections is ON")
def evaluate_6_8(c, cfg): return _eval_pg_param(c, cfg, "log_disconnections", "6.8", "PostgreSQL log_disconnections is ON")
def evaluate_6_9(c, cfg): return _eval_pg_param(c, cfg, "log_duration", "6.9", "PostgreSQL log_duration is ON")


SECTION_5_EVALUATORS = {f"5.{i}": globals()[f"evaluate_5_{i}"] for i in range(1, 10)}
SECTION_6_EVALUATORS = {f"6.{i}": globals()[f"evaluate_6_{i}"] for i in range(1, 10)}
