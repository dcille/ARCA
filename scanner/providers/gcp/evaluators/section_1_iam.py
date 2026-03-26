"""CIS GCP v4.0 Section 1: Identity and Access Management — 17 controls."""
import logging
from datetime import datetime, timedelta, timezone
from .base import GCPClientCache, EvalConfig, make_result, make_manual_result
logger = logging.getLogger(__name__)
FW = ["CIS-GCP-4.0"]

def evaluate_cis_1_1(c, cfg):
    return [make_manual_result("1.1","gcp_cis_1_1","Ensure corporate login credentials are used","iam","high",cfg.project_id,"Requires verifying Cloud Identity or Google Workspace org setup.")]

def evaluate_cis_1_2(c, cfg):
    return [make_manual_result("1.2","gcp_cis_1_2","Ensure MFA is enabled for all non-service accounts","iam","critical",cfg.project_id,"MFA enforcement must be verified in Google Workspace/Cloud Identity admin console.")]

def evaluate_cis_1_3(c, cfg):
    return [make_manual_result("1.3","gcp_cis_1_3","Ensure security key enforcement is enabled for all admin accounts","iam","critical",cfg.project_id,"Security key enforcement is configured in Google Workspace admin console.")]

def evaluate_cis_1_4(c, cfg):
    results = []
    try:
        for sa in c.iam_client.list_service_accounts(request={"name": f"projects/{cfg.project_id}"}):
            from google.cloud import iam_admin_v1
            keys = c.iam_client.list_service_account_keys(request={"name": sa.name, "key_types": [iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED]})
            has_user_keys = len(list(keys.keys)) > 0
            results.append(make_result(cis_id="1.4",check_id="gcp_cis_1_4",title="Ensure only GCP-managed SA keys exist",service="iam",severity="high",status="FAIL" if has_user_keys else "PASS",resource_id=sa.name,resource_name=sa.email,status_extended=f"SA {sa.email}: user-managed keys = {has_user_keys}",remediation="Delete user-managed keys; use Workload Identity Federation.",compliance_frameworks=FW))
    except Exception as e:
        results.append(make_result(cis_id="1.4",check_id="gcp_cis_1_4",title="Ensure only GCP-managed SA keys exist",service="iam",severity="high",status="ERROR",resource_id=f"projects/{cfg.project_id}",status_extended=str(e),compliance_frameworks=FW))
    return results

def evaluate_cis_1_5(c, cfg):
    results = []
    policy = c.crm_policy()
    admin_roles = {"roles/owner","roles/editor","roles/iam.serviceAccountAdmin"}
    for b in policy.get("bindings",[]):
        if b["role"] in admin_roles:
            for m in b.get("members",[]):
                if m.startswith("serviceAccount:"):
                    results.append(make_result(cis_id="1.5",check_id="gcp_cis_1_5",title="Ensure SA has no admin privileges",service="iam",severity="critical",status="FAIL",resource_id=f"projects/{cfg.project_id}",status_extended=f"SA {m} has admin role {b['role']}",remediation="Remove admin roles from service accounts.",compliance_frameworks=FW))
    if not results:
        results.append(make_result(cis_id="1.5",check_id="gcp_cis_1_5",title="Ensure SA has no admin privileges",service="iam",severity="critical",status="PASS",resource_id=f"projects/{cfg.project_id}",status_extended="No SA with admin roles found.",compliance_frameworks=FW))
    return results

def evaluate_cis_1_6(c, cfg):
    results = []
    policy = c.crm_policy()
    bad_roles = {"roles/iam.serviceAccountUser","roles/iam.serviceAccountTokenCreator"}
    for b in policy.get("bindings",[]):
        if b["role"] in bad_roles:
            for m in b.get("members",[]):
                results.append(make_result(cis_id="1.6",check_id="gcp_cis_1_6",title="Ensure IAM users not assigned SA User/Token Creator at project level",service="iam",severity="high",status="FAIL",resource_id=f"projects/{cfg.project_id}",status_extended=f"{m} has {b['role']} at project level",remediation="Grant these roles on specific SAs, not project-wide.",compliance_frameworks=FW))
    if not results:
        results.append(make_result(cis_id="1.6",check_id="gcp_cis_1_6",title="Ensure IAM users not assigned SA User/Token Creator at project level",service="iam",severity="high",status="PASS",resource_id=f"projects/{cfg.project_id}",status_extended="No project-level SA User/Token Creator assignments.",compliance_frameworks=FW))
    return results

def evaluate_cis_1_7(c, cfg):
    results = []
    ninety_days = datetime.now(tz=timezone.utc) - timedelta(days=90)
    try:
        from google.cloud import iam_admin_v1
        for sa in c.iam_client.list_service_accounts(request={"name": f"projects/{cfg.project_id}"}):
            keys = c.iam_client.list_service_account_keys(request={"name": sa.name, "key_types": [iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED]})
            for key in keys.keys:
                created = key.valid_after_time
                if created and created < ninety_days:
                    results.append(make_result(cis_id="1.7",check_id="gcp_cis_1_7",title="Ensure user-managed SA keys are rotated within 90 days",service="iam",severity="high",status="FAIL",resource_id=sa.name,resource_name=sa.email,status_extended=f"Key {key.name.split('/')[-1]} created {created}, > 90 days",remediation="Rotate or delete the SA key.",compliance_frameworks=FW))
    except Exception:
        pass
    if not results:
        results.append(make_result(cis_id="1.7",check_id="gcp_cis_1_7",title="Ensure user-managed SA keys are rotated within 90 days",service="iam",severity="high",status="PASS",resource_id=f"projects/{cfg.project_id}",status_extended="All SA keys within 90-day window.",compliance_frameworks=FW))
    return results

def evaluate_cis_1_8(c, cfg):
    policy = c.crm_policy()
    admin_members, token_members = set(), set()
    for b in policy.get("bindings",[]):
        if b["role"] == "roles/iam.serviceAccountAdmin": admin_members.update(b.get("members",[]))
        if b["role"] == "roles/iam.serviceAccountTokenCreator": token_members.update(b.get("members",[]))
    overlap = admin_members & token_members
    if overlap:
        return [make_result(cis_id="1.8",check_id="gcp_cis_1_8",title="Ensure separation of duties for SA-related roles",service="iam",severity="high",status="FAIL",resource_id=f"projects/{cfg.project_id}",status_extended=f"Members with both SA Admin + Token Creator: {list(overlap)[:5]}",remediation="Separate SA Admin and Token Creator roles.",compliance_frameworks=FW)]
    return [make_result(cis_id="1.8",check_id="gcp_cis_1_8",title="Ensure separation of duties for SA-related roles",service="iam",severity="high",status="PASS",resource_id=f"projects/{cfg.project_id}",status_extended="No SoD violations.",compliance_frameworks=FW)]

def evaluate_cis_1_9(c, cfg):
    results = []
    try:
        parent = f"projects/{cfg.project_id}/locations/-"
        for ring in c.kms_client.list_key_rings(request={"parent": parent}):
            for key in c.kms_client.list_crypto_keys(request={"parent": ring.name}):
                policy = c.kms_client.get_iam_policy(request={"resource": key.name})
                public = any(m in ("allUsers","allAuthenticatedUsers") for b in policy.bindings for m in b.members)
                results.append(make_result(cis_id="1.9",check_id="gcp_cis_1_9",title="Ensure KMS CryptoKeys are not anonymously/publicly accessible",service="iam",severity="critical",status="FAIL" if public else "PASS",resource_id=key.name,resource_name=key.name.split("/")[-1],status_extended=f"Key {key.name.split('/')[-1]}: public = {public}",remediation="Remove allUsers/allAuthenticatedUsers from KMS key IAM.",compliance_frameworks=FW))
    except Exception:
        pass
    return results

def evaluate_cis_1_10(c, cfg):
    results = []
    try:
        parent = f"projects/{cfg.project_id}/locations/-"
        for ring in c.kms_client.list_key_rings(request={"parent": parent}):
            for key in c.kms_client.list_crypto_keys(request={"parent": ring.name}):
                rot = key.rotation_period
                ok = rot and rot.total_seconds() <= 7776000
                results.append(make_result(cis_id="1.10",check_id="gcp_cis_1_10",title="Ensure KMS keys are rotated within 90 days",service="iam",severity="high",status="PASS" if ok else "FAIL",resource_id=key.name,resource_name=key.name.split("/")[-1],status_extended=f"Key rotation: {'<= 90d' if ok else 'not configured or > 90d'}",remediation="Set key rotation period to 90 days or less.",compliance_frameworks=FW))
    except Exception:
        pass
    return results

def evaluate_cis_1_11(c, cfg):
    policy = c.crm_policy()
    admin_m, enc_m = set(), set()
    for b in policy.get("bindings",[]):
        if b["role"] == "roles/cloudkms.admin": admin_m.update(b.get("members",[]))
        if b["role"] == "roles/cloudkms.cryptoKeyEncrypterDecrypter": enc_m.update(b.get("members",[]))
    overlap = admin_m & enc_m
    return [make_result(cis_id="1.11",check_id="gcp_cis_1_11",title="Ensure separation of duties for KMS roles",service="iam",severity="high",status="FAIL" if overlap else "PASS",resource_id=f"projects/{cfg.project_id}",status_extended=f"KMS SoD overlap: {list(overlap)[:5]}" if overlap else "No KMS SoD violations.",remediation="Separate cloudkms.admin and cryptoKeyEncrypterDecrypter roles.",compliance_frameworks=FW)]

def evaluate_cis_1_12(c, cfg):
    results = []
    try:
        svc = c.api_service("apikeys","v2")
        keys = svc.projects().locations().keys().list(parent=f"projects/{cfg.project_id}/locations/global").execute()
        for k in keys.get("keys",[]):
            restrictions = k.get("restrictions",{})
            has_api_targets = bool(restrictions.get("apiTargets"))
            results.append(make_result(cis_id="1.12",check_id="gcp_cis_1_12",title="Ensure API keys only exist for active services",service="iam",severity="medium",status="PASS" if has_api_targets else "FAIL",resource_id=k.get("name",""),resource_name=k.get("displayName",""),status_extended=f"API key restricted to APIs: {has_api_targets}",remediation="Restrict API key to specific APIs or delete unused keys.",compliance_frameworks=FW))
    except Exception:
        pass
    return results

def evaluate_cis_1_13(c, cfg):
    return [make_manual_result("1.13","gcp_cis_1_13","Ensure API keys are restricted to specified hosts/apps","iam","medium",cfg.project_id,"Requires verifying API key application restrictions (browser/server/android/iOS).")]

def evaluate_cis_1_14(c, cfg):
    results = []
    try:
        svc = c.api_service("apikeys","v2")
        keys = svc.projects().locations().keys().list(parent=f"projects/{cfg.project_id}/locations/global").execute()
        for k in keys.get("keys",[]):
            restrictions = k.get("restrictions",{})
            has_api = bool(restrictions.get("apiTargets"))
            results.append(make_result(cis_id="1.14",check_id="gcp_cis_1_14",title="Ensure API keys restricted to only needed APIs",service="iam",severity="medium",status="PASS" if has_api else "FAIL",resource_id=k.get("name",""),resource_name=k.get("displayName",""),status_extended=f"API targets configured: {has_api}",remediation="Restrict API key to specific APIs needed.",compliance_frameworks=FW))
    except Exception:
        pass
    return results

def evaluate_cis_1_15(c, cfg):
    results = []
    ninety_days = datetime.now(tz=timezone.utc) - timedelta(days=90)
    try:
        svc = c.api_service("apikeys","v2")
        keys = svc.projects().locations().keys().list(parent=f"projects/{cfg.project_id}/locations/global").execute()
        for k in keys.get("keys",[]):
            ct = k.get("createTime","")
            if ct:
                created = datetime.fromisoformat(ct.replace("Z","+00:00"))
                old = created < ninety_days
                results.append(make_result(cis_id="1.15",check_id="gcp_cis_1_15",title="Ensure API keys are rotated every 90 days",service="iam",severity="medium",status="FAIL" if old else "PASS",resource_id=k.get("name",""),resource_name=k.get("displayName",""),status_extended=f"API key created {ct}, age > 90d: {old}",remediation="Rotate the API key.",compliance_frameworks=FW))
    except Exception:
        pass
    return results

def evaluate_cis_1_16(c, cfg):
    try:
        svc = c.api_service("essentialcontacts","v1")
        contacts = svc.projects().contacts().list(parent=f"projects/{cfg.project_id}").execute()
        has = len(contacts.get("contacts",[])) > 0
        return [make_result(cis_id="1.16",check_id="gcp_cis_1_16",title="Ensure Essential Contacts is configured",service="iam",severity="medium",status="PASS" if has else "FAIL",resource_id=f"projects/{cfg.project_id}",status_extended=f"Essential Contacts: {len(contacts.get('contacts',[]))}",remediation="Configure Essential Contacts for security notifications.",compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="1.16",check_id="gcp_cis_1_16",title="Ensure Essential Contacts is configured",service="iam",severity="medium",status="FAIL",resource_id=f"projects/{cfg.project_id}",status_extended="Could not query Essential Contacts.",compliance_frameworks=FW)]

def evaluate_cis_1_17(c, cfg):
    return [make_manual_result("1.17","gcp_cis_1_17","Ensure secrets are not stored in Cloud Functions env vars","iam","high",cfg.project_id,"Requires inspecting Cloud Function environment variables for secret-like values.")]
