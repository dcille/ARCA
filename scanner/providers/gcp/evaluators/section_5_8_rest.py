"""CIS GCP v4.0 Sections 5-8: Storage, Cloud SQL, BigQuery, Dataproc — 14 controls."""
import logging
from .base import GCPClientCache, EvalConfig, make_result, make_manual_result
logger = logging.getLogger(__name__)
FW = ["CIS-GCP-4.0"]

# ══════════════════ Section 5: Storage (2 controls) ══════════════════

def evaluate_cis_5_1(c, cfg):
    results = []
    try:
        for bucket in c.storage_client.list_buckets():
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                public = any("allUsers" in set(b.get("members",[])) or "allAuthenticatedUsers" in set(b.get("members",[])) for b in policy.bindings)
            except Exception:
                public = False
            results.append(make_result(cis_id="5.1",check_id="gcp_cis_5_1",title="Ensure Cloud Storage bucket is not publicly accessible",service="storage",severity="critical",status="FAIL" if public else "PASS",resource_id=f"gs://{bucket.name}",resource_name=bucket.name,status_extended=f"Bucket {bucket.name}: public = {public}",remediation="Remove allUsers/allAuthenticatedUsers from bucket IAM.",compliance_frameworks=FW))
    except Exception: pass
    return results

def evaluate_cis_5_2(c, cfg):
    results = []
    try:
        for bucket in c.storage_client.list_buckets():
            uniform = bucket.iam_configuration.uniform_bucket_level_access_enabled
            results.append(make_result(cis_id="5.2",check_id="gcp_cis_5_2",title="Ensure Cloud Storage buckets have uniform bucket-level access",service="storage",severity="medium",status="PASS" if uniform else "FAIL",resource_id=f"gs://{bucket.name}",resource_name=bucket.name,status_extended=f"Bucket {bucket.name}: uniform access = {uniform}",remediation="Enable uniform bucket-level access.",compliance_frameworks=FW))
    except Exception: pass
    return results

# ══════════════════ Section 6: Cloud SQL (7 controls) ══════════════════

def _get_sql_instances(c, cfg):
    try:
        svc = c.api_service("sqladmin","v1beta4")
        return svc.instances().list(project=cfg.project_id).execute().get("items",[])
    except Exception:
        return []

def evaluate_cis_6_1(c, cfg):
    return [make_manual_result("6.1","gcp_cis_6_1","MySQL: Ensure instance does not allow anyone to connect","sql","high",cfg.project_id,"Requires reviewing MySQL-specific database flags and user grants.")]

def evaluate_cis_6_2(c, cfg):
    results = []
    for inst in _get_sql_instances(c, cfg):
        if not inst.get("databaseVersion","").startswith("POSTGRES"): continue
        flags = inst.get("settings",{}).get("databaseFlags",[])
        verbose = any(f["name"]=="log_error_verbosity" and f["value"].upper()=="DEFAULT" for f in flags)
        results.append(make_result(cis_id="6.2",check_id="gcp_cis_6_2",title="PostgreSQL: Ensure log_error_verbosity is set properly",service="sql",severity="medium",status="PASS" if verbose else "FAIL",resource_id=inst["name"],status_extended=f"SQL {inst['name']}: log_error_verbosity check",remediation="Set log_error_verbosity database flag to DEFAULT or VERBOSE.",compliance_frameworks=FW))
    return results

def evaluate_cis_6_3(c, cfg):
    results = []
    for inst in _get_sql_instances(c, cfg):
        if not inst.get("databaseVersion","").startswith("SQLSERVER"): continue
        flags = inst.get("settings",{}).get("databaseFlags",[])
        ext_scripts = any(f["name"]=="external scripts enabled" and f["value"]=="off" for f in flags)
        results.append(make_result(cis_id="6.3",check_id="gcp_cis_6_3",title="SQL Server: Ensure external scripts enabled flag is off",service="sql",severity="medium",status="PASS" if ext_scripts else "FAIL",resource_id=inst["name"],status_extended=f"SQL {inst['name']}: external scripts check",remediation="Set 'external scripts enabled' flag to off.",compliance_frameworks=FW))
    return results

def evaluate_cis_6_4(c, cfg):
    results = []
    for inst in _get_sql_instances(c, cfg):
        ssl = inst.get("settings",{}).get("ipConfiguration",{}).get("requireSsl",False)
        results.append(make_result(cis_id="6.4",check_id="gcp_cis_6_4",title="Ensure Cloud SQL requires all incoming connections to use SSL",service="sql",severity="high",status="PASS" if ssl else "FAIL",resource_id=inst["name"],status_extended=f"SQL {inst['name']}: SSL required = {ssl}",remediation="Enable requireSsl on the SQL instance.",compliance_frameworks=FW))
    return results

def evaluate_cis_6_5(c, cfg):
    results = []
    for inst in _get_sql_instances(c, cfg):
        nets = inst.get("settings",{}).get("ipConfiguration",{}).get("authorizedNetworks",[])
        public = any(n.get("value")=="0.0.0.0/0" for n in nets)
        results.append(make_result(cis_id="6.5",check_id="gcp_cis_6_5",title="Ensure Cloud SQL does not whitelist 0.0.0.0/0",service="sql",severity="critical",status="FAIL" if public else "PASS",resource_id=inst["name"],status_extended=f"SQL {inst['name']}: 0.0.0.0/0 whitelisted = {public}",remediation="Remove 0.0.0.0/0 from authorized networks.",compliance_frameworks=FW))
    return results

def evaluate_cis_6_6(c, cfg):
    results = []
    for inst in _get_sql_instances(c, cfg):
        pub_ip = inst.get("settings",{}).get("ipConfiguration",{}).get("ipv4Enabled",True)
        results.append(make_result(cis_id="6.6",check_id="gcp_cis_6_6",title="Ensure Cloud SQL does not have public IPs",service="sql",severity="high",status="FAIL" if pub_ip else "PASS",resource_id=inst["name"],status_extended=f"SQL {inst['name']}: public IP = {pub_ip}",remediation="Disable public IP; use private IP only.",compliance_frameworks=FW))
    return results

def evaluate_cis_6_7(c, cfg):
    results = []
    for inst in _get_sql_instances(c, cfg):
        backup = inst.get("settings",{}).get("backupConfiguration",{}).get("enabled",False)
        results.append(make_result(cis_id="6.7",check_id="gcp_cis_6_7",title="Ensure Cloud SQL has automated backups configured",service="sql",severity="medium",status="PASS" if backup else "FAIL",resource_id=inst["name"],status_extended=f"SQL {inst['name']}: automated backups = {backup}",remediation="Enable automated backups.",compliance_frameworks=FW))
    return results

# ══════════════════ Section 7: BigQuery (4 controls) ══════════════════

def evaluate_cis_7_1(c, cfg):
    results = []
    try:
        for ds_ref in c.bigquery_client.list_datasets():
            ds = c.bigquery_client.get_dataset(ds_ref.reference)
            public = any(hasattr(e,'entity_id') and e.entity_id in ("allUsers","allAuthenticatedUsers") for e in ds.access_entries)
            results.append(make_result(cis_id="7.1",check_id="gcp_cis_7_1",title="Ensure BigQuery datasets are not publicly accessible",service="bigquery",severity="critical",status="FAIL" if public else "PASS",resource_id=f"{cfg.project_id}.{ds.dataset_id}",resource_name=ds.dataset_id,status_extended=f"Dataset {ds.dataset_id}: public = {public}",remediation="Remove allUsers/allAuthenticatedUsers from dataset access.",compliance_frameworks=FW))
    except Exception: pass
    return results

def evaluate_cis_7_2(c, cfg):
    results = []
    try:
        for ds_ref in c.bigquery_client.list_datasets():
            for tbl_ref in c.bigquery_client.list_tables(ds_ref.reference):
                tbl = c.bigquery_client.get_table(tbl_ref)
                cmek = tbl.encryption_configuration and bool(tbl.encryption_configuration.kms_key_name)
                results.append(make_result(cis_id="7.2",check_id="gcp_cis_7_2",title="Ensure BigQuery tables are encrypted with CMEK",service="bigquery",severity="medium",status="PASS" if cmek else "FAIL",resource_id=f"{cfg.project_id}.{ds_ref.dataset_id}.{tbl.table_id}",resource_name=tbl.table_id,status_extended=f"Table {tbl.table_id}: CMEK = {cmek}",remediation="Configure CMEK on BigQuery tables.",compliance_frameworks=FW))
    except Exception: pass
    return results

def evaluate_cis_7_3(c, cfg):
    results = []
    try:
        for ds_ref in c.bigquery_client.list_datasets():
            ds = c.bigquery_client.get_dataset(ds_ref.reference)
            cmek = ds.default_encryption_configuration and bool(ds.default_encryption_configuration.kms_key_name)
            results.append(make_result(cis_id="7.3",check_id="gcp_cis_7_3",title="Ensure default CMEK is specified for BigQuery datasets",service="bigquery",severity="medium",status="PASS" if cmek else "FAIL",resource_id=f"{cfg.project_id}.{ds.dataset_id}",resource_name=ds.dataset_id,status_extended=f"Dataset {ds.dataset_id}: default CMEK = {cmek}",remediation="Set default KMS key on dataset.",compliance_frameworks=FW))
    except Exception: pass
    return results

def evaluate_cis_7_4(c, cfg):
    return [make_manual_result("7.4","gcp_cis_7_4","Ensure all data in BigQuery has been classified","bigquery","medium",cfg.project_id,"Requires DLP/data classification process review.")]

# ══════════════════ Section 8: Dataproc (1 control) ══════════════════

def evaluate_cis_8_1(c, cfg):
    results = []
    try:
        svc = c.api_service("dataproc","v1")
        for region in cfg.regions:
            try:
                resp = svc.projects().regions().clusters().list(projectId=cfg.project_id,region=region).execute()
                for cluster in resp.get("clusters",[]):
                    name = cluster.get("clusterName","")
                    cmek = bool(cluster.get("config",{}).get("encryptionConfig",{}).get("gcePdKmsKeyName"))
                    results.append(make_result(cis_id="8.1",check_id="gcp_cis_8_1",title="Ensure Dataproc cluster is encrypted with CMEK",service="dataproc",severity="medium",region=region,status="PASS" if cmek else "FAIL",resource_id=f"projects/{cfg.project_id}/regions/{region}/clusters/{name}",resource_name=name,status_extended=f"Dataproc {name}: CMEK = {cmek}",remediation="Configure KMS key for Dataproc cluster.",compliance_frameworks=FW))
            except Exception: pass
    except Exception: pass
    return results
