"""CIS GCP v4.0 Sections 5-8: Storage, Cloud SQL, BigQuery, Dataproc.

Section 5 — Storage (2 controls):
  5.1  Public access prevented on buckets  automated
  5.2  Uniform bucket-level access         automated

Section 6 — Cloud SQL (sub-sections 6.1-6.7):
  6.1.1 MySQL skip-show-database           manual
  6.1.2 MySQL local_infile off             automated
  6.1.3 MySQL database flags               automated
  6.2.1 PostgreSQL log_checkpoints         automated
  6.2.2 PostgreSQL log_connections         automated
  6.2.3 PostgreSQL log_disconnections      automated
  6.2.4 PostgreSQL log_lock_waits          automated
  6.2.5 PostgreSQL log_min_messages        automated
  6.2.6 PostgreSQL log_temp_files          automated
  6.2.7 PostgreSQL log_min_duration_statement  automated
  6.2.8 PostgreSQL log_statement           automated
  6.3.1 SQL Server external scripts        automated
  6.3.2 SQL Server cross db ownership      automated
  6.3.3 SQL Server user connections        automated
  6.3.4 SQL Server user options            automated
  6.3.5 SQL Server remote access           automated
  6.3.6 SQL Server 3625 trace flag         automated
  6.3.7 SQL Server contained database auth automated
  6.4   Cloud SQL public IP disabled       automated
  6.5   Cloud SQL require SSL              automated
  6.6   Cloud SQL automated backups        automated
  6.7   Cloud SQL no public access         automated

Section 7 — BigQuery (4 controls):
  7.1  BigQuery datasets not public        automated
  7.2  BigQuery tables CMEK encrypted      automated
  7.3  BigQuery default CMEK configured    automated
  7.4  BigQuery data classification        manual

Section 8 — Dataproc (1 control):
  8.1  Dataproc CMEK encryption            automated
"""

import logging

from .base import GCPClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-GCP-4.0"]


# ═══════════════════════════════════════════════════════════════
# SECTION 5: STORAGE
# ═══════════════════════════════════════════════════════════════

# 5.1 — Ensure public access prevention on buckets
def evaluate_cis_5_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        buckets = list(c.storage.list_buckets())
    except Exception:
        buckets = []

    for bucket in buckets:
        iam_config = bucket.iam_configuration or {}
        pap = getattr(iam_config, "public_access_prevention", "inherited")
        if hasattr(pap, "name"):
            pap = pap.name
        ok = str(pap).lower() == "enforced"
        results.append(make_result(
            cis_id="5.1", check_id="gcp_cis_5_1",
            title="Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible",
            service="storage", severity="high",
            status="PASS" if ok else "FAIL",
            resource_id=bucket.name, resource_name=bucket.name,
            status_extended=f"Bucket '{bucket.name}': publicAccessPrevention={pap}",
            remediation="Set publicAccessPrevention to 'enforced' on the bucket.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="5.1", check_id="gcp_cis_5_1",
            title="Ensure Storage Buckets Not Publicly Accessible",
            service="storage", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No storage buckets found",
            compliance_frameworks=FW)]
    return results


# 5.2 — Ensure uniform bucket-level access
def evaluate_cis_5_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        buckets = list(c.storage.list_buckets())
    except Exception:
        buckets = []

    for bucket in buckets:
        iam_config = bucket.iam_configuration or {}
        uniform = getattr(iam_config, "uniform_bucket_level_access", None)
        enabled = uniform and getattr(uniform, "enabled", False)
        results.append(make_result(
            cis_id="5.2", check_id="gcp_cis_5_2",
            title="Ensure That Cloud Storage Buckets Have Uniform Bucket-Level Access Enabled",
            service="storage", severity="medium",
            status="PASS" if enabled else "FAIL",
            resource_id=bucket.name, resource_name=bucket.name,
            status_extended=f"Bucket '{bucket.name}': uniformBucketLevelAccess={enabled}",
            remediation="Enable uniform bucket-level access on the bucket.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="5.2", check_id="gcp_cis_5_2",
            title="Ensure Uniform Bucket-Level Access",
            service="storage", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No storage buckets found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# SECTION 6: CLOUD SQL — Helpers
# ═══════════════════════════════════════════════════════════════

def _get_sql_instances(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    try:
        resp = c.sqladmin.instances().list(project=cfg.project_id).execute()
        return resp.get("items", [])
    except Exception:
        return []


def _check_sql_flag(c: GCPClientCache, cfg: EvalConfig, cis_id: str, check_id: str,
                    title: str, flag_name: str, expected_value: str,
                    db_type: str = "", severity: str = "medium") -> list[dict]:
    """Generic check for a Cloud SQL database flag."""
    results = []
    instances = _get_sql_instances(c, cfg)

    for inst in instances:
        inst_type = inst.get("databaseVersion", "")
        if db_type and not inst_type.upper().startswith(db_type.upper()):
            continue

        name = inst.get("name", "")
        settings = inst.get("settings", {})
        flags = {f["name"]: f.get("value", "") for f in settings.get("databaseFlags", [])}

        actual = flags.get(flag_name, "")
        ok = actual.lower() == expected_value.lower()

        results.append(make_result(
            cis_id=cis_id, check_id=check_id, title=title,
            service="sql", severity=severity,
            status="PASS" if ok else "FAIL",
            resource_id=name, resource_name=name,
            status_extended=f"Instance '{name}': {flag_name}={actual or '(not set)'} (expected: {expected_value})",
            remediation=f"Set database flag {flag_name}={expected_value} on instance {name}.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id=cis_id, check_id=check_id, title=title,
            service="sql", severity=severity, status="PASS",
            resource_id=cfg.project_id,
            status_extended=f"No {db_type or 'Cloud SQL'} instances found",
            compliance_frameworks=FW)]
    return results


# --- 6.1 MySQL flags ---

def evaluate_cis_6_1_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("6.1.1", "gcp_cis_6_1_1",
        "Ensure That a MySQL Database Instance Does Not Allow Anyone To Connect With Administrative Privileges",
        "sql", "high", cfg.project_id,
        "Requires manual review of MySQL user grants for super/admin privileges.")]


def evaluate_cis_6_1_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.1.2", "gcp_cis_6_1_2",
        "Ensure 'local_infile' Database Flag for a Cloud SQL MySQL Instance Is Set to 'Off'",
        "local_infile", "off", db_type="MYSQL")


def evaluate_cis_6_1_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.1.3", "gcp_cis_6_1_3",
        "Ensure 'skip_show_database' Database Flag for a Cloud SQL MySQL Instance Is Set to 'On'",
        "skip_show_database", "on", db_type="MYSQL")


# --- 6.2 PostgreSQL flags ---

def evaluate_cis_6_2_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.1", "gcp_cis_6_2_1",
        "Ensure 'log_checkpoints' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'On'",
        "log_checkpoints", "on", db_type="POSTGRES")


def evaluate_cis_6_2_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.2", "gcp_cis_6_2_2",
        "Ensure 'log_connections' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'On'",
        "log_connections", "on", db_type="POSTGRES")


def evaluate_cis_6_2_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.3", "gcp_cis_6_2_3",
        "Ensure 'log_disconnections' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'On'",
        "log_disconnections", "on", db_type="POSTGRES")


def evaluate_cis_6_2_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.4", "gcp_cis_6_2_4",
        "Ensure 'log_lock_waits' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'On'",
        "log_lock_waits", "on", db_type="POSTGRES")


def evaluate_cis_6_2_5(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.5", "gcp_cis_6_2_5",
        "Ensure 'log_min_messages' Database Flag for Cloud SQL PostgreSQL Is Set Appropriately",
        "log_min_messages", "warning", db_type="POSTGRES")


def evaluate_cis_6_2_6(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.6", "gcp_cis_6_2_6",
        "Ensure 'log_temp_files' Database Flag for Cloud SQL PostgreSQL Is Set to '0'",
        "log_temp_files", "0", db_type="POSTGRES")


def evaluate_cis_6_2_7(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.2.7", "gcp_cis_6_2_7",
        "Ensure 'log_min_duration_statement' Database Flag for Cloud SQL PostgreSQL Is Set to '-1'",
        "log_min_duration_statement", "-1", db_type="POSTGRES")


def evaluate_cis_6_2_8(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    instances = _get_sql_instances(c, cfg)
    for inst in instances:
        if not inst.get("databaseVersion", "").upper().startswith("POSTGRES"):
            continue
        name = inst.get("name", "")
        settings = inst.get("settings", {})
        flags = {f["name"]: f.get("value", "") for f in settings.get("databaseFlags", [])}
        val = flags.get("log_statement", "")
        ok = val.lower() in ("ddl", "mod", "all")
        results.append(make_result(
            cis_id="6.2.8", check_id="gcp_cis_6_2_8",
            title="Ensure 'log_statement' Database Flag for Cloud SQL PostgreSQL Is Set Appropriately",
            service="sql", severity="medium",
            status="PASS" if ok else "FAIL",
            resource_id=name, resource_name=name,
            status_extended=f"Instance '{name}': log_statement={val or '(not set)'} (expected: ddl, mod, or all)",
            remediation="Set database flag log_statement=ddl (or mod/all) on the instance.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="6.2.8", check_id="gcp_cis_6_2_8",
            title="Ensure 'log_statement' Set Appropriately",
            service="sql", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No PostgreSQL instances found",
            compliance_frameworks=FW)]
    return results


# --- 6.3 SQL Server flags ---

def evaluate_cis_6_3_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.1", "gcp_cis_6_3_1",
        "Ensure 'external scripts enabled' Database Flag for Cloud SQL Server Is Set to 'Off'",
        "external scripts enabled", "off", db_type="SQLSERVER")


def evaluate_cis_6_3_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.2", "gcp_cis_6_3_2",
        "Ensure 'cross db ownership chaining' Database Flag for Cloud SQL Server Is Set to 'Off'",
        "cross db ownership chaining", "off", db_type="SQLSERVER")


def evaluate_cis_6_3_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.3", "gcp_cis_6_3_3",
        "Ensure 'user connections' Database Flag for Cloud SQL Server Is Set As Appropriate",
        "user connections", "0", db_type="SQLSERVER")


def evaluate_cis_6_3_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.4", "gcp_cis_6_3_4",
        "Ensure 'user options' Database Flag for Cloud SQL Server Is Not Configured",
        "user options", "", db_type="SQLSERVER")


def evaluate_cis_6_3_5(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.5", "gcp_cis_6_3_5",
        "Ensure 'remote access' Database Flag for Cloud SQL Server Is Set to 'Off'",
        "remote access", "off", db_type="SQLSERVER")


def evaluate_cis_6_3_6(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.6", "gcp_cis_6_3_6",
        "Ensure '3625 (trace flag)' Database Flag for Cloud SQL Server Is Set to 'Off'",
        "3625", "off", db_type="SQLSERVER")


def evaluate_cis_6_3_7(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return _check_sql_flag(c, cfg, "6.3.7", "gcp_cis_6_3_7",
        "Ensure 'contained database authentication' Database Flag for Cloud SQL Server Is Set to 'Off'",
        "contained database authentication", "off", db_type="SQLSERVER")


# --- 6.4 — Cloud SQL instances no public IP ---

def evaluate_cis_6_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    instances = _get_sql_instances(c, cfg)
    for inst in instances:
        name = inst.get("name", "")
        ip_addrs = inst.get("ipAddresses", [])
        has_public = any(a.get("type") == "PRIMARY" for a in ip_addrs)
        results.append(make_result(
            cis_id="6.4", check_id="gcp_cis_6_4",
            title="Ensure That Cloud SQL Database Instances Do Not Have Public IPs",
            service="sql", severity="high",
            status="FAIL" if has_public else "PASS",
            resource_id=name, resource_name=name,
            status_extended=(
                f"Instance '{name}' has a public IP address"
                if has_public else f"Instance '{name}' has no public IP"
            ),
            remediation="Configure Cloud SQL to use private IP only.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="6.4", check_id="gcp_cis_6_4",
            title="Ensure Cloud SQL No Public IP",
            service="sql", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No Cloud SQL instances found",
            compliance_frameworks=FW)]
    return results


# --- 6.5 — Cloud SQL require SSL ---

def evaluate_cis_6_5(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    instances = _get_sql_instances(c, cfg)
    for inst in instances:
        name = inst.get("name", "")
        settings = inst.get("settings", {})
        ip_config = settings.get("ipConfiguration", {})
        require_ssl = ip_config.get("requireSsl", False)
        results.append(make_result(
            cis_id="6.5", check_id="gcp_cis_6_5",
            title="Ensure That Cloud SQL Database Instances Require All Incoming Connections To Use SSL",
            service="sql", severity="high",
            status="PASS" if require_ssl else "FAIL",
            resource_id=name, resource_name=name,
            status_extended=f"Instance '{name}': requireSsl={require_ssl}",
            remediation="Enable requireSsl on Cloud SQL instance IP configuration.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="6.5", check_id="gcp_cis_6_5",
            title="Ensure Cloud SQL Requires SSL",
            service="sql", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No Cloud SQL instances found",
            compliance_frameworks=FW)]
    return results


# --- 6.6 — Cloud SQL automated backups ---

def evaluate_cis_6_6(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    instances = _get_sql_instances(c, cfg)
    for inst in instances:
        name = inst.get("name", "")
        settings = inst.get("settings", {})
        backup = settings.get("backupConfiguration", {})
        enabled = backup.get("enabled", False)
        results.append(make_result(
            cis_id="6.6", check_id="gcp_cis_6_6",
            title="Ensure That Cloud SQL Database Instances Are Configured With Automated Backups",
            service="sql", severity="medium",
            status="PASS" if enabled else "FAIL",
            resource_id=name, resource_name=name,
            status_extended=f"Instance '{name}': automated backups={enabled}",
            remediation="Enable automated backups in Cloud SQL instance settings.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="6.6", check_id="gcp_cis_6_6",
            title="Ensure Cloud SQL Automated Backups",
            service="sql", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No Cloud SQL instances found",
            compliance_frameworks=FW)]
    return results


# --- 6.7 — Cloud SQL no authorized_networks 0.0.0.0/0 ---

def evaluate_cis_6_7(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    instances = _get_sql_instances(c, cfg)
    for inst in instances:
        name = inst.get("name", "")
        settings = inst.get("settings", {})
        ip_config = settings.get("ipConfiguration", {})
        networks = ip_config.get("authorizedNetworks", [])
        open_net = any(n.get("value") in ("0.0.0.0/0", "::/0") for n in networks)
        results.append(make_result(
            cis_id="6.7", check_id="gcp_cis_6_7",
            title="Ensure That Cloud SQL Database Instances Do Not Implicitly Whitelist All Public IP Addresses",
            service="sql", severity="high",
            status="FAIL" if open_net else "PASS",
            resource_id=name, resource_name=name,
            status_extended=(
                f"Instance '{name}' has 0.0.0.0/0 in authorized networks"
                if open_net else f"Instance '{name}' does not allow all IPs"
            ),
            remediation="Remove 0.0.0.0/0 from authorized networks; use private IP.",
            compliance_frameworks=FW,
        ))
    if not results:
        return [make_result(cis_id="6.7", check_id="gcp_cis_6_7",
            title="Ensure Cloud SQL No Wildcard Network Access",
            service="sql", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No Cloud SQL instances found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# SECTION 7: BIGQUERY
# ═══════════════════════════════════════════════════════════════

# 7.1 — BigQuery datasets not publicly accessible
def evaluate_cis_7_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        datasets = list(c.bigquery.list_datasets())
    except Exception:
        datasets = []

    for ds_ref in datasets:
        ds = c.bigquery.get_dataset(ds_ref.reference)
        ds_id = ds.full_dataset_id.replace(":", ".")
        public = False
        for entry in ds.access_entries or []:
            if getattr(entry, "entity_id", "") in ("allUsers", "allAuthenticatedUsers"):
                public = True
                break
            if getattr(entry, "special_group", "") in ("allAuthenticatedUsers",):
                public = True
                break
        results.append(make_result(
            cis_id="7.1", check_id="gcp_cis_7_1",
            title="Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible",
            service="bigquery", severity="high",
            status="FAIL" if public else "PASS",
            resource_id=ds_id,
            resource_name=ds.dataset_id,
            status_extended=(
                f"Dataset '{ds.dataset_id}' is publicly accessible"
                if public else f"Dataset '{ds.dataset_id}' is not publicly accessible"
            ),
            remediation="Remove allUsers/allAuthenticatedUsers from dataset access.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="7.1", check_id="gcp_cis_7_1",
            title="Ensure BigQuery Datasets Not Public",
            service="bigquery", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No BigQuery datasets found",
            compliance_frameworks=FW)]
    return results


# 7.2 — BigQuery tables CMEK encrypted
def evaluate_cis_7_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        datasets = list(c.bigquery.list_datasets())
    except Exception:
        datasets = []

    for ds_ref in datasets:
        ds = c.bigquery.get_dataset(ds_ref.reference)
        tables = list(c.bigquery.list_tables(ds.reference))
        for tbl_ref in tables:
            tbl = c.bigquery.get_table(tbl_ref.reference)
            cmek = getattr(tbl, "encryption_configuration", None)
            has_cmek = cmek and getattr(cmek, "kms_key_name", None)
            results.append(make_result(
                cis_id="7.2", check_id="gcp_cis_7_2",
                title="Ensure That All BigQuery Tables Are Encrypted With CMEK",
                service="bigquery", severity="medium",
                status="PASS" if has_cmek else "FAIL",
                resource_id=f"{ds.dataset_id}.{tbl.table_id}",
                resource_name=tbl.table_id,
                status_extended=(
                    f"Table '{tbl.table_id}' is CMEK encrypted"
                    if has_cmek else f"Table '{tbl.table_id}' uses default encryption"
                ),
                remediation="Encrypt BigQuery table with CMEK.",
                compliance_frameworks=FW,
            ))

    if not results:
        return [make_result(cis_id="7.2", check_id="gcp_cis_7_2",
            title="Ensure BigQuery Tables CMEK Encrypted",
            service="bigquery", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No BigQuery tables found",
            compliance_frameworks=FW)]
    return results


# 7.3 — BigQuery default CMEK configured for datasets
def evaluate_cis_7_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        datasets = list(c.bigquery.list_datasets())
    except Exception:
        datasets = []

    for ds_ref in datasets:
        ds = c.bigquery.get_dataset(ds_ref.reference)
        cmek = getattr(ds, "default_encryption_configuration", None)
        has_cmek = cmek and getattr(cmek, "kms_key_name", None)
        results.append(make_result(
            cis_id="7.3", check_id="gcp_cis_7_3",
            title="Ensure That a Default Customer-Managed Encryption Key (CMEK) Is Specified for All BigQuery Data Sets",
            service="bigquery", severity="medium",
            status="PASS" if has_cmek else "FAIL",
            resource_id=ds.dataset_id, resource_name=ds.dataset_id,
            status_extended=(
                f"Dataset '{ds.dataset_id}' has default CMEK configured"
                if has_cmek else f"Dataset '{ds.dataset_id}' uses default encryption"
            ),
            remediation="Set a default CMEK on the BigQuery dataset.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="7.3", check_id="gcp_cis_7_3",
            title="Ensure BigQuery Default CMEK",
            service="bigquery", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No BigQuery datasets found",
            compliance_frameworks=FW)]
    return results


# 7.4 — BigQuery data classification (MANUAL)
def evaluate_cis_7_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("7.4", "gcp_cis_7_4",
        "Ensure That BigQuery Data Is Classified and DLP Applied",
        "bigquery", "medium", cfg.project_id,
        "Requires verifying DLP policies and data classification labels on BigQuery datasets.")]


# ═══════════════════════════════════════════════════════════════
# SECTION 8: DATAPROC
# ═══════════════════════════════════════════════════════════════

# 8.1 — Dataproc clusters encrypted with CMEK
def evaluate_cis_8_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        resp = c.dataproc.projects().regions().clusters().list(
            projectId=cfg.project_id, region="-"
        ).execute()
        clusters = resp.get("clusters", [])
    except Exception:
        clusters = []

    for cluster in clusters:
        name = cluster.get("clusterName", "")
        config = cluster.get("config", {})
        enc_config = config.get("encryptionConfig", {})
        cmek = enc_config.get("gcePdKmsKeyName", "")
        ok = bool(cmek)
        results.append(make_result(
            cis_id="8.1", check_id="gcp_cis_8_1",
            title="Ensure That Dataproc Cluster Is Encrypted Using CMEK",
            service="dataproc", severity="medium",
            status="PASS" if ok else "FAIL",
            resource_id=name, resource_name=name,
            status_extended=(
                f"Dataproc cluster '{name}' is CMEK encrypted"
                if ok else f"Dataproc cluster '{name}' uses default encryption"
            ),
            remediation="Re-create Dataproc cluster with CMEK encryption configured.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="8.1", check_id="gcp_cis_8_1",
            title="Ensure Dataproc CMEK Encryption",
            service="dataproc", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No Dataproc clusters found",
            compliance_frameworks=FW)]
    return results
