"""CIS GCP v4.0 Sections 5–8: Storage, Cloud SQL, BigQuery, Dataproc — 29 controls.

Coverage:
  5.1   Cloud Storage not publicly accessible        automated
  5.2   Uniform bucket-level access enabled           automated

  6.1.1 MySQL: no admin without password              manual
  6.1.2 MySQL: skip_show_database flag on             automated
  6.1.3 MySQL: local_infile flag off                  automated

  6.2.1 PostgreSQL: log_error_verbosity               automated
  6.2.2 PostgreSQL: log_connections on                 automated
  6.2.3 PostgreSQL: log_disconnections on              automated
  6.2.4 PostgreSQL: log_statement set properly         automated
  6.2.5 PostgreSQL: log_min_messages warning+          automated
  6.2.6 PostgreSQL: log_min_error_statement error+     automated
  6.2.7 PostgreSQL: log_min_duration_statement -1      automated
  6.2.8 PostgreSQL: cloudsql.enable_pgaudit on         automated

  6.3.1 SQL Server: external scripts enabled off       automated
  6.3.2 SQL Server: cross db ownership chaining off    automated
  6.3.3 SQL Server: user connections non-limiting      automated
  6.3.4 SQL Server: user options not configured        automated
  6.3.5 SQL Server: remote access off                  automated
  6.3.6 SQL Server: 3625 trace flag on                 automated
  6.3.7 SQL Server: contained db authentication off    automated

  6.4   Cloud SQL requires SSL                         automated
  6.5   Cloud SQL no 0.0.0.0/0 whitelist               automated
  6.6   Cloud SQL no public IPs                        automated
  6.7   Cloud SQL automated backups                    automated

  7.1   BigQuery datasets not public                   automated
  7.2   BigQuery tables encrypted with CMEK            automated
  7.3   BigQuery default CMEK on datasets              automated
  7.4   BigQuery data classified                       manual

  8.1   Dataproc clusters encrypted with CMEK          automated
"""

import logging

from .base import GCPClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-GCP-4.0"]


# -----------------------------------------------------------------
# Helpers for Cloud SQL
# -----------------------------------------------------------------

def _get_sql_instances(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    """Retrieve all Cloud SQL instances in the project."""
    try:
        resp = c.sqladmin.instances().list(project=cfg.project_id).execute()
        return resp.get("items", [])
    except Exception as e:
        logger.warning("Could not list SQL instances: %s", e)
        return []


def _check_sql_flag(c: GCPClientCache, cfg: EvalConfig, cis_id: str,
                    check_id: str, title: str, db_prefix: str,
                    flag_name: str, expected_value: str,
                    comparison: str = "eq") -> list[dict]:
    """Check a database flag on SQL instances filtered by database version prefix.

    comparison: "eq" (value must match), "neq" (value must NOT match),
                "in" (value must be in expected_value as comma-separated list),
                "exists" (flag must exist, any value).
    """
    results = []
    for inst in _get_sql_instances(c, cfg):
        db_ver = inst.get("databaseVersion", "")
        if not db_ver.upper().startswith(db_prefix.upper()):
            continue
        flags = inst.get("settings", {}).get("databaseFlags", [])
        flag_val = None
        for f in flags:
            if f.get("name") == flag_name:
                flag_val = f.get("value", "")
                break

        if comparison == "eq":
            ok = flag_val is not None and flag_val.lower() == expected_value.lower()
        elif comparison == "neq":
            ok = flag_val is None or flag_val.lower() != expected_value.lower()
        elif comparison == "in":
            acceptable = [v.strip().lower() for v in expected_value.split(",")]
            ok = flag_val is not None and flag_val.lower() in acceptable
        elif comparison == "not_configured":
            ok = flag_val is None
        else:
            ok = flag_val is not None

        name = inst.get("name", "unknown")
        results.append(make_result(
            cis_id=cis_id, check_id=check_id, title=title,
            service="sql", severity="medium",
            status="PASS" if ok else "FAIL",
            resource_id=name, resource_name=name,
            status_extended=f"SQL instance '{name}': {flag_name}={flag_val}",
            remediation=f"Set database flag {flag_name}={expected_value} on instance {name}.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id=cis_id, check_id=check_id, title=title,
            service="sql", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended=f"No {db_prefix} SQL instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# Section 5: Storage (2 controls)
# ═══════════════════════════════════════════════════════════════

# 5.1 — Ensure Cloud Storage bucket is not publicly accessible

def evaluate_cis_5_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        for bucket in c.storage.list_buckets():
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                public = any(
                    "allUsers" in set(b.get("members", []))
                    or "allAuthenticatedUsers" in set(b.get("members", []))
                    for b in policy.bindings
                )
            except Exception:
                public = False
            results.append(make_result(
                cis_id="5.1", check_id="gcp_cis_5_1",
                title="Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible",
                service="storage", severity="critical",
                status="FAIL" if public else "PASS",
                resource_id=f"gs://{bucket.name}",
                resource_name=bucket.name,
                status_extended=f"Bucket '{bucket.name}': publicly accessible={public}",
                remediation="Remove allUsers/allAuthenticatedUsers from bucket IAM policy.",
                compliance_frameworks=FW,
            ))
    except Exception as e:
        logger.warning("Could not list storage buckets: %s", e)

    if not results:
        return [make_result(cis_id="5.1", check_id="gcp_cis_5_1",
            title="Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible",
            service="storage", severity="critical", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No storage buckets found",
            compliance_frameworks=FW)]
    return results


# 5.2 — Ensure uniform bucket-level access is enabled

def evaluate_cis_5_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        for bucket in c.storage.list_buckets():
            uniform = bucket.iam_configuration.uniform_bucket_level_access_enabled
            results.append(make_result(
                cis_id="5.2", check_id="gcp_cis_5_2",
                title="Ensure That Cloud Storage Buckets Have Uniform Bucket-Level Access Enabled",
                service="storage", severity="medium",
                status="PASS" if uniform else "FAIL",
                resource_id=f"gs://{bucket.name}",
                resource_name=bucket.name,
                status_extended=f"Bucket '{bucket.name}': uniform access={uniform}",
                remediation="Enable uniform bucket-level access on the bucket.",
                compliance_frameworks=FW,
            ))
    except Exception as e:
        logger.warning("Could not list storage buckets: %s", e)

    if not results:
        return [make_result(cis_id="5.2", check_id="gcp_cis_5_2",
            title="Ensure That Cloud Storage Buckets Have Uniform Bucket-Level Access Enabled",
            service="storage", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No storage buckets found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# Section 6.1: Cloud SQL — MySQL (3 controls)
# ═══════════════════════════════════════════════════════════════

# 6.1.1 — MySQL: no admin without password (MANUAL)

def evaluate_cis_6_1_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("6.1.1", "gcp_cis_6_1_1",
        "Ensure That a MySQL Database Instance Does Not Allow Anyone To Connect With Administrative Privileges",
        "sql", "critical", cfg.project_id,
        "Requires reviewing MySQL root user password configuration.")]


# 6.1.2 — MySQL: skip_show_database flag on

def evaluate_cis_6_1_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.1.2", "gcp_cis_6_1_2",
        "Ensure 'Skip_show_database' Database Flag for Cloud SQL MySQL Instance Is Set to 'On'",
        "MYSQL", "skip_show_database", "on")


# 6.1.3 — MySQL: local_infile flag off

def evaluate_cis_6_1_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.1.3", "gcp_cis_6_1_3",
        "Ensure That the 'Local_infile' Database Flag for a Cloud SQL MySQL Instance Is Set to 'Off'",
        "MYSQL", "local_infile", "off")


# ═══════════════════════════════════════════════════════════════
# Section 6.2: Cloud SQL — PostgreSQL (8 controls)
# ═══════════════════════════════════════════════════════════════

# 6.2.1 — PostgreSQL: log_error_verbosity DEFAULT or stricter

def evaluate_cis_6_2_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.1", "gcp_cis_6_2_1",
        "Ensure 'Log_error_verbosity' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'DEFAULT' or Stricter",
        "POSTGRES", "log_error_verbosity", "default,verbose", comparison="in")


# 6.2.2 — PostgreSQL: log_connections on

def evaluate_cis_6_2_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.2", "gcp_cis_6_2_2",
        "Ensure That the 'Log_connections' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'On'",
        "POSTGRES", "log_connections", "on")


# 6.2.3 — PostgreSQL: log_disconnections on

def evaluate_cis_6_2_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.3", "gcp_cis_6_2_3",
        "Ensure That the 'Log_disconnections' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'On'",
        "POSTGRES", "log_disconnections", "on")


# 6.2.4 — PostgreSQL: log_statement set appropriately

def evaluate_cis_6_2_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.4", "gcp_cis_6_2_4",
        "Ensure 'Log_statement' Database Flag for Cloud SQL PostgreSQL Instance Is Set Appropriately",
        "POSTGRES", "log_statement", "ddl,mod,all", comparison="in")


# 6.2.5 — PostgreSQL: log_min_messages at minimum WARNING

def evaluate_cis_6_2_5(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.5", "gcp_cis_6_2_5",
        "Ensure That the 'Log_min_messages' Flag for a Cloud SQL PostgreSQL Instance Is Set at Minimum to 'Warning'",
        "POSTGRES", "log_min_messages", "warning,error,log,fatal,panic", comparison="in")


# 6.2.6 — PostgreSQL: log_min_error_statement set to ERROR or stricter

def evaluate_cis_6_2_6(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.6", "gcp_cis_6_2_6",
        "Ensure 'Log_min_error_statement' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'Error' or Stricter",
        "POSTGRES", "log_min_error_statement", "error,log,fatal,panic", comparison="in")


# 6.2.7 — PostgreSQL: log_min_duration_statement set to -1

def evaluate_cis_6_2_7(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.7", "gcp_cis_6_2_7",
        "Ensure That the 'Log_min_duration_statement' Database Flag for Cloud SQL PostgreSQL Instance Is Set to '-1'",
        "POSTGRES", "log_min_duration_statement", "-1")


# 6.2.8 — PostgreSQL: cloudsql.enable_pgaudit on

def evaluate_cis_6_2_8(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.8", "gcp_cis_6_2_8",
        "Ensure That 'cloudsql.enable_pgaudit' Database Flag for Each Cloud SQL PostgreSQL Instance Is Set to 'on'",
        "POSTGRES", "cloudsql.enable_pgaudit", "on")


# ═══════════════════════════════════════════════════════════════
# Section 6.3: Cloud SQL — SQL Server (7 controls)
# ═══════════════════════════════════════════════════════════════

# 6.3.1 — SQL Server: external scripts enabled off

def evaluate_cis_6_3_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.1", "gcp_cis_6_3_1",
        "Ensure 'External Scripts Enabled' Database Flag for Cloud SQL SQL Server Instance Is Set to 'Off'",
        "SQLSERVER", "external scripts enabled", "off")


# 6.3.2 — SQL Server: cross db ownership chaining off

def evaluate_cis_6_3_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.2", "gcp_cis_6_3_2",
        "Ensure 'Cross db Ownership Chaining' Database Flag for Cloud SQL SQL Server Instance Is Set to 'Off'",
        "SQLSERVER", "cross db ownership chaining", "off")


# 6.3.3 — SQL Server: user connections set to non-limiting value

def evaluate_cis_6_3_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _get_sql_instances(c, cfg):
        db_ver = inst.get("databaseVersion", "")
        if not db_ver.upper().startswith("SQLSERVER"):
            continue
        flags = inst.get("settings", {}).get("databaseFlags", [])
        flag_val = None
        for f in flags:
            if f.get("name") == "user connections":
                flag_val = f.get("value", "0")
                break
        # 0 means unlimited (default, good); any positive value is a limit
        ok = flag_val is None or flag_val == "0"
        name = inst.get("name", "unknown")
        results.append(make_result(
            cis_id="6.3.3", check_id="gcp_cis_6_3_3",
            title="Ensure 'User Connections' Database Flag for Cloud SQL SQL Server Instance Is Set to a Non-limiting Value",
            service="sql", severity="medium",
            status="PASS" if ok else "FAIL",
            resource_id=name, resource_name=name,
            status_extended=f"SQL instance '{name}': user connections={flag_val or '0 (default)'}",
            remediation="Set 'user connections' to 0 (unlimited) or remove the flag.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="6.3.3", check_id="gcp_cis_6_3_3",
            title="Ensure 'User Connections' Database Flag for Cloud SQL SQL Server Instance Is Set to a Non-limiting Value",
            service="sql", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No SQL Server instances found",
            compliance_frameworks=FW)]
    return results


# 6.3.4 — SQL Server: user options not configured

def evaluate_cis_6_3_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.4", "gcp_cis_6_3_4",
        "Ensure 'User Options' Database Flag for Cloud SQL SQL Server Instance Is Not Configured",
        "SQLSERVER", "user options", "", comparison="not_configured")


# 6.3.5 — SQL Server: remote access off

def evaluate_cis_6_3_5(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.5", "gcp_cis_6_3_5",
        "Ensure 'Remote Access' Database Flag for Cloud SQL SQL Server Instance Is Set to 'Off'",
        "SQLSERVER", "remote access", "off")


# 6.3.6 — SQL Server: 3625 trace flag on

def evaluate_cis_6_3_6(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.6", "gcp_cis_6_3_6",
        "Ensure '3625 (Trace Flag)' Database Flag for All Cloud SQL SQL Server Instances Is Set to 'On'",
        "SQLSERVER", "3625", "on")


# 6.3.7 — SQL Server: contained database authentication off

def evaluate_cis_6_3_7(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.7", "gcp_cis_6_3_7",
        "Ensure 'Contained Database Authentication' Database Flag for Cloud SQL SQL Server Instance Is Set to 'Off'",
        "SQLSERVER", "contained database authentication", "off")


# ═══════════════════════════════════════════════════════════════
# Section 6.4–6.7: Cloud SQL — General (4 controls)
# ═══════════════════════════════════════════════════════════════

# 6.4 — Ensure Cloud SQL requires SSL

def evaluate_cis_6_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _get_sql_instances(c, cfg):
        ssl = inst.get("settings", {}).get("ipConfiguration", {}).get("requireSsl", False)
        name = inst.get("name", "unknown")
        results.append(make_result(
            cis_id="6.4", check_id="gcp_cis_6_4",
            title="Ensure That the Cloud SQL Database Instance Requires All Incoming Connections To Use SSL",
            service="sql", severity="high",
            status="PASS" if ssl else "FAIL",
            resource_id=name, resource_name=name,
            status_extended=f"SQL instance '{name}': SSL required={ssl}",
            remediation="Enable requireSsl on the SQL instance IP configuration.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="6.4", check_id="gcp_cis_6_4",
            title="Ensure That the Cloud SQL Database Instance Requires All Incoming Connections To Use SSL",
            service="sql", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No SQL instances found",
            compliance_frameworks=FW)]
    return results


# 6.5 — Ensure Cloud SQL does not whitelist 0.0.0.0/0

def evaluate_cis_6_5(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _get_sql_instances(c, cfg):
        nets = inst.get("settings", {}).get("ipConfiguration", {}).get("authorizedNetworks", [])
        public = any(n.get("value") == "0.0.0.0/0" for n in nets)
        name = inst.get("name", "unknown")
        results.append(make_result(
            cis_id="6.5", check_id="gcp_cis_6_5",
            title="Ensure That Cloud SQL Database Instances Do Not Implicitly Whitelist All Public IP Addresses",
            service="sql", severity="critical",
            status="FAIL" if public else "PASS",
            resource_id=name, resource_name=name,
            status_extended=f"SQL instance '{name}': 0.0.0.0/0 whitelisted={public}",
            remediation="Remove 0.0.0.0/0 from authorized networks.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="6.5", check_id="gcp_cis_6_5",
            title="Ensure That Cloud SQL Database Instances Do Not Implicitly Whitelist All Public IP Addresses",
            service="sql", severity="critical", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No SQL instances found",
            compliance_frameworks=FW)]
    return results


# 6.6 — Ensure Cloud SQL does not have public IPs

def evaluate_cis_6_6(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _get_sql_instances(c, cfg):
        pub_ip = inst.get("settings", {}).get("ipConfiguration", {}).get("ipv4Enabled", True)
        name = inst.get("name", "unknown")
        results.append(make_result(
            cis_id="6.6", check_id="gcp_cis_6_6",
            title="Ensure That Cloud SQL Database Instances Do Not Have Public IPs",
            service="sql", severity="high",
            status="FAIL" if pub_ip else "PASS",
            resource_id=name, resource_name=name,
            status_extended=f"SQL instance '{name}': public IP enabled={pub_ip}",
            remediation="Disable public IP; use private IP only.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="6.6", check_id="gcp_cis_6_6",
            title="Ensure That Cloud SQL Database Instances Do Not Have Public IPs",
            service="sql", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No SQL instances found",
            compliance_frameworks=FW)]
    return results


# 6.7 — Ensure Cloud SQL has automated backups

def evaluate_cis_6_7(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    for inst in _get_sql_instances(c, cfg):
        backup = inst.get("settings", {}).get("backupConfiguration", {}).get("enabled", False)
        name = inst.get("name", "unknown")
        results.append(make_result(
            cis_id="6.7", check_id="gcp_cis_6_7",
            title="Ensure That Cloud SQL Database Instances Are Configured With Automated Backups",
            service="sql", severity="medium",
            status="PASS" if backup else "FAIL",
            resource_id=name, resource_name=name,
            status_extended=f"SQL instance '{name}': automated backups={backup}",
            remediation="Enable automated backups on the SQL instance.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="6.7", check_id="gcp_cis_6_7",
            title="Ensure That Cloud SQL Database Instances Are Configured With Automated Backups",
            service="sql", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No SQL instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# Section 7: BigQuery (4 controls)
# ═══════════════════════════════════════════════════════════════

# 7.1 — Ensure BigQuery datasets are not publicly accessible

def evaluate_cis_7_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        for ds_ref in c.bigquery.list_datasets():
            ds = c.bigquery.get_dataset(ds_ref.reference)
            public = any(
                hasattr(e, "entity_id")
                and e.entity_id in ("allUsers", "allAuthenticatedUsers")
                for e in ds.access_entries
            )
            results.append(make_result(
                cis_id="7.1", check_id="gcp_cis_7_1",
                title="Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible",
                service="bigquery", severity="critical",
                status="FAIL" if public else "PASS",
                resource_id=f"{cfg.project_id}.{ds.dataset_id}",
                resource_name=ds.dataset_id,
                status_extended=f"Dataset '{ds.dataset_id}': publicly accessible={public}",
                remediation="Remove allUsers/allAuthenticatedUsers from dataset access.",
                compliance_frameworks=FW,
            ))
    except Exception as e:
        logger.warning("Could not list BigQuery datasets: %s", e)

    if not results:
        return [make_result(cis_id="7.1", check_id="gcp_cis_7_1",
            title="Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible",
            service="bigquery", severity="critical", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No BigQuery datasets found",
            compliance_frameworks=FW)]
    return results


# 7.2 — Ensure BigQuery tables are encrypted with CMEK

def evaluate_cis_7_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        for ds_ref in c.bigquery.list_datasets():
            for tbl_ref in c.bigquery.list_tables(ds_ref.reference):
                tbl = c.bigquery.get_table(tbl_ref)
                cmek = (
                    tbl.encryption_configuration
                    and bool(tbl.encryption_configuration.kms_key_name)
                )
                results.append(make_result(
                    cis_id="7.2", check_id="gcp_cis_7_2",
                    title="Ensure That All BigQuery Tables Are Encrypted With Customer-Managed Encryption Key (CMEK)",
                    service="bigquery", severity="medium",
                    status="PASS" if cmek else "FAIL",
                    resource_id=f"{cfg.project_id}.{ds_ref.dataset_id}.{tbl.table_id}",
                    resource_name=tbl.table_id,
                    status_extended=f"Table '{tbl.table_id}': CMEK={cmek}",
                    remediation="Configure CMEK encryption on BigQuery tables.",
                    compliance_frameworks=FW,
                ))
    except Exception as e:
        logger.warning("Could not list BigQuery tables: %s", e)

    if not results:
        return [make_result(cis_id="7.2", check_id="gcp_cis_7_2",
            title="Ensure That All BigQuery Tables Are Encrypted With Customer-Managed Encryption Key (CMEK)",
            service="bigquery", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No BigQuery tables found",
            compliance_frameworks=FW)]
    return results


# 7.3 — Ensure default CMEK is specified for BigQuery datasets

def evaluate_cis_7_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        for ds_ref in c.bigquery.list_datasets():
            ds = c.bigquery.get_dataset(ds_ref.reference)
            cmek = (
                ds.default_encryption_configuration
                and bool(ds.default_encryption_configuration.kms_key_name)
            )
            results.append(make_result(
                cis_id="7.3", check_id="gcp_cis_7_3",
                title="Ensure That a Default Customer-Managed Encryption Key (CMEK) Is Specified for All BigQuery Data Sets",
                service="bigquery", severity="medium",
                status="PASS" if cmek else "FAIL",
                resource_id=f"{cfg.project_id}.{ds.dataset_id}",
                resource_name=ds.dataset_id,
                status_extended=f"Dataset '{ds.dataset_id}': default CMEK={cmek}",
                remediation="Set default KMS key on the BigQuery dataset.",
                compliance_frameworks=FW,
            ))
    except Exception as e:
        logger.warning("Could not list BigQuery datasets: %s", e)

    if not results:
        return [make_result(cis_id="7.3", check_id="gcp_cis_7_3",
            title="Ensure That a Default Customer-Managed Encryption Key (CMEK) Is Specified for All BigQuery Data Sets",
            service="bigquery", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No BigQuery datasets found",
            compliance_frameworks=FW)]
    return results


# 7.4 — Ensure all data in BigQuery has been classified (MANUAL)

def evaluate_cis_7_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("7.4", "gcp_cis_7_4",
        "Ensure That All Data in BigQuery Has Been Classified",
        "bigquery", "medium", cfg.project_id,
        "Requires DLP/data classification process review.")]


# ═══════════════════════════════════════════════════════════════
# Section 8: Dataproc (1 control)
# ═══════════════════════════════════════════════════════════════

# 8.1 — Ensure Dataproc cluster is encrypted with CMEK

def evaluate_cis_8_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        for region in cfg.regions:
            try:
                resp = c.dataproc.projects().regions().clusters().list(
                    projectId=cfg.project_id, region=region
                ).execute()
                for cluster in resp.get("clusters", []):
                    name = cluster.get("clusterName", "")
                    cmek = bool(
                        cluster.get("config", {})
                        .get("encryptionConfig", {})
                        .get("gcePdKmsKeyName")
                    )
                    results.append(make_result(
                        cis_id="8.1", check_id="gcp_cis_8_1",
                        title="Ensure That Dataproc Cluster Is Encrypted With Customer-Managed Encryption Keys",
                        service="dataproc", severity="medium",
                        region=region,
                        status="PASS" if cmek else "FAIL",
                        resource_id=f"projects/{cfg.project_id}/regions/{region}/clusters/{name}",
                        resource_name=name,
                        status_extended=f"Dataproc cluster '{name}': CMEK={cmek}",
                        remediation="Configure KMS key for Dataproc cluster encryption.",
                        compliance_frameworks=FW,
                    ))
            except Exception:
                pass
    except Exception as e:
        logger.warning("Could not list Dataproc clusters: %s", e)

    if not results:
        return [make_result(cis_id="8.1", check_id="gcp_cis_8_1",
            title="Ensure That Dataproc Cluster Is Encrypted With Customer-Managed Encryption Keys",
            service="dataproc", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No Dataproc clusters found",
            compliance_frameworks=FW)]
    return results
