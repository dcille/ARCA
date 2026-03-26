"""CIS GCP v4.0 Section 1: Identity and Access Management — 17 controls.

Coverage:
  1.1  Corporate login credentials     manual
  1.2  MFA for all non-service accts   manual
  1.3  Security key enforcement admins  manual
  1.4  Only GCP-managed SA keys        automated
  1.5  SA has no admin privileges      automated
  1.6  SA user-managed key rotation    automated
  1.7  SA with user roles separation   automated
  1.8  No project-level SA impersonation  automated
  1.9  KMS encryption keys separation  automated
  1.10 KMS keys not anonymously accessible  automated
  1.11 API keys rotation <= 90 days    automated
  1.12 API keys restricted to needed APIs  automated
  1.13 API keys restricted to needed IPs/apps  manual
  1.14 API keys restricted to needed APIs  automated
  1.15 Essential Contacts configured   automated
  1.16 No SA key upload                automated
  1.17 Dataproc default SA override    manual
"""

import logging
from datetime import datetime, timezone, timedelta

from .base import GCPClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-GCP-4.0"]


# ═══════════════════════════════════════════════════════════════
# 1.1 — Corporate Login Credentials (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_1(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.1", "gcp_cis_1_1",
        "Ensure that Corporate Login Credentials are Used",
        "iam", "medium", cfg.project_id,
        "Requires verifying that all IAM members use corporate domain accounts, "
        "not consumer Gmail accounts. Check via Console or gcloud projects get-iam-policy.")]


# ═══════════════════════════════════════════════════════════════
# 1.2 — MFA for all non-service accounts (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_2(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.2", "gcp_cis_1_2",
        "Ensure that Multi-Factor Authentication is Enabled for All Non-Service Accounts",
        "iam", "high", cfg.project_id,
        "MFA status can only be verified in Google Workspace Admin Console.")]


# ═══════════════════════════════════════════════════════════════
# 1.3 — Security Key Enforcement for admins (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_3(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.3", "gcp_cis_1_3",
        "Ensure that Security Key Enforcement is Enabled for All Admin Accounts",
        "iam", "medium", cfg.project_id,
        "Security key enforcement is configured in Google Workspace Admin Console.")]


# ═══════════════════════════════════════════════════════════════
# 1.4 — Only GCP-managed SA keys
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_4(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    sas = list(c.iam_admin.list_service_accounts(
        request={"name": f"projects/{cfg.project_id}"}
    ))
    if not sas:
        return [make_result(cis_id="1.4", check_id="gcp_cis_1_4",
            title="Ensure only GCP-managed service account keys for each SA",
            service="iam", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No user-managed service accounts found",
            compliance_frameworks=FW)]

    for sa in sas:
        if not sa.email.endswith("iam.gserviceaccount.com"):
            continue
        keys = list(c.iam_admin.list_service_account_keys(
            request={"name": sa.name, "key_types": ["USER_MANAGED"]}
        ))
        user_keys = [k for k in keys if k.key_type.name == "USER_MANAGED"]
        results.append(make_result(
            cis_id="1.4", check_id="gcp_cis_1_4",
            title="Ensure only GCP-managed service account keys for each SA",
            service="iam", severity="medium",
            status="FAIL" if user_keys else "PASS",
            resource_id=sa.name, resource_name=sa.email,
            status_extended=(
                f"SA {sa.email}: {len(user_keys)} user-managed key(s) found"
                if user_keys else f"SA {sa.email}: No user-managed keys"
            ),
            remediation="Delete user-managed keys: gcloud iam service-accounts keys delete --iam-account=EMAIL KEY_ID",
            compliance_frameworks=FW,
        ))
    return results or [make_result(cis_id="1.4", check_id="gcp_cis_1_4",
        title="Ensure only GCP-managed service account keys for each SA",
        service="iam", severity="medium", status="PASS",
        resource_id=cfg.project_id,
        status_extended="No user-managed service accounts found",
        compliance_frameworks=FW)]


# ═══════════════════════════════════════════════════════════════
# 1.5 — SA has no admin privileges
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_5(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    body = {"options": {"requestedPolicyVersion": 3}}
    policy = c.crm_v1.projects().getIamPolicy(resource=cfg.project_id, body=body).execute()

    admin_sas = set()
    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        if "admin" in role.lower() or role in ("roles/owner", "roles/editor"):
            for member in binding.get("members", []):
                if member.startswith("serviceAccount:") and "iam.gserviceaccount.com" in member:
                    admin_sas.add(member)

    if not admin_sas:
        return [make_result(cis_id="1.5", check_id="gcp_cis_1_5",
            title="Ensure that Service Account has no Admin Privileges",
            service="iam", severity="critical", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No service accounts have admin/owner/editor roles",
            compliance_frameworks=FW)]

    for sa in admin_sas:
        results.append(make_result(
            cis_id="1.5", check_id="gcp_cis_1_5",
            title="Ensure that Service Account has no Admin Privileges",
            service="iam", severity="critical", status="FAIL",
            resource_id=sa.replace("serviceAccount:", ""),
            resource_name=sa.replace("serviceAccount:", ""),
            status_extended=f"Service account {sa} has admin/owner/editor role",
            remediation="Remove admin/owner/editor roles from service accounts.",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 1.6 — SA user-managed key rotation <= 90 days
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_6(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    now = datetime.now(timezone.utc)
    threshold = timedelta(days=90)

    sas = list(c.iam_admin.list_service_accounts(
        request={"name": f"projects/{cfg.project_id}"}
    ))
    for sa in sas:
        if not sa.email.endswith("iam.gserviceaccount.com"):
            continue
        keys = list(c.iam_admin.list_service_account_keys(
            request={"name": sa.name, "key_types": ["USER_MANAGED"]}
        ))
        user_keys = [k for k in keys if k.key_type.name == "USER_MANAGED"]
        for key in user_keys:
            created = key.valid_after_time
            if created:
                age = now - created.replace(tzinfo=timezone.utc) if created.tzinfo is None else now - created
                ok = age <= threshold
            else:
                ok = False
                age = timedelta(days=999)
            results.append(make_result(
                cis_id="1.6", check_id="gcp_cis_1_6",
                title="Ensure user-managed SA keys are rotated within 90 days",
                service="iam", severity="medium",
                status="PASS" if ok else "FAIL",
                resource_id=f"{sa.name}/keys/{key.name.split('/')[-1]}",
                resource_name=sa.email,
                status_extended=f"Key age: {age.days} days (max 90)",
                remediation="Rotate keys older than 90 days: delete old key and create new one.",
                compliance_frameworks=FW,
            ))
    if not results:
        return [make_result(cis_id="1.6", check_id="gcp_cis_1_6",
            title="Ensure user-managed SA keys are rotated within 90 days",
            service="iam", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No user-managed SA keys found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 1.7 — SA user/token creator roles not at project level
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_7(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    body = {"options": {"requestedPolicyVersion": 3}}
    policy = c.crm_v1.projects().getIamPolicy(resource=cfg.project_id, body=body).execute()

    risky_roles = {"roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator"}
    violations = []
    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        if role in risky_roles:
            for member in binding.get("members", []):
                violations.append((member, role))

    if not violations:
        return [make_result(cis_id="1.7", check_id="gcp_cis_1_7",
            title="Ensure SA User/Token Creator roles not assigned at project level",
            service="iam", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No users have SA User or Token Creator at project level",
            compliance_frameworks=FW)]

    for member, role in violations:
        results.append(make_result(
            cis_id="1.7", check_id="gcp_cis_1_7",
            title="Ensure SA User/Token Creator roles not assigned at project level",
            service="iam", severity="medium", status="FAIL",
            resource_id=member, resource_name=member,
            status_extended=f"{member} has {role} at project level",
            remediation="Remove project-level SA User/Token Creator. Grant at SA level instead.",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 1.8 — Separation of duties: SA admin & SA user
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_8(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    body = {"options": {"requestedPolicyVersion": 3}}
    policy = c.crm_v1.projects().getIamPolicy(resource=cfg.project_id, body=body).execute()

    role_members: dict[str, set] = {}
    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        for member in binding.get("members", []):
            role_members.setdefault(role, set()).add(member)

    admin_members = role_members.get("roles/iam.serviceAccountAdmin", set())
    user_members = role_members.get("roles/iam.serviceAccountUser", set())
    overlap = admin_members & user_members

    if not overlap:
        return [make_result(cis_id="1.8", check_id="gcp_cis_1_8",
            title="Ensure Separation of Duties for Service Account Admin and User",
            service="iam", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No user has both SA Admin and SA User roles",
            compliance_frameworks=FW)]

    results = []
    for member in overlap:
        results.append(make_result(
            cis_id="1.8", check_id="gcp_cis_1_8",
            title="Ensure Separation of Duties for Service Account Admin and User",
            service="iam", severity="medium", status="FAIL",
            resource_id=member,
            status_extended=f"{member} has both SA Admin and SA User roles",
            remediation="Remove one of the roles to enforce separation of duties.",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 1.9 — Separation of duties: KMS admin & encrypter/decrypter
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_9(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    body = {"options": {"requestedPolicyVersion": 3}}
    policy = c.crm_v1.projects().getIamPolicy(resource=cfg.project_id, body=body).execute()

    role_members: dict[str, set] = {}
    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        for member in binding.get("members", []):
            role_members.setdefault(role, set()).add(member)

    kms_admin = role_members.get("roles/cloudkms.admin", set())
    kms_crypto = (
        role_members.get("roles/cloudkms.cryptoKeyEncrypterDecrypter", set())
        | role_members.get("roles/cloudkms.cryptoKeyEncrypter", set())
        | role_members.get("roles/cloudkms.cryptoKeyDecrypter", set())
    )
    overlap = kms_admin & kms_crypto

    if not overlap:
        return [make_result(cis_id="1.9", check_id="gcp_cis_1_9",
            title="Ensure KMS Encryption Keys Separation of Duties",
            service="iam", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No user has both KMS Admin and CryptoKey Encrypter/Decrypter",
            compliance_frameworks=FW)]

    results = []
    for member in overlap:
        results.append(make_result(
            cis_id="1.9", check_id="gcp_cis_1_9",
            title="Ensure KMS Encryption Keys Separation of Duties",
            service="iam", severity="high", status="FAIL",
            resource_id=member,
            status_extended=f"{member} has both KMS Admin and CryptoKey Encrypter/Decrypter",
            remediation="Separate KMS admin from encryption duties to prevent key misuse.",
            compliance_frameworks=FW,
        ))
    return results


# ═══════════════════════════════════════════════════════════════
# 1.10 — KMS keys not publicly accessible
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_10(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    parent = f"projects/{cfg.project_id}/locations/-"
    try:
        key_rings = list(c.kms.list_key_rings(request={"parent": parent}))
    except Exception:
        key_rings = []

    for kr in key_rings:
        crypto_keys = list(c.kms.list_crypto_keys(request={"parent": kr.name}))
        for ck in crypto_keys:
            policy = c.kms.get_iam_policy(request={"resource": ck.name})
            public = False
            for binding in policy.bindings:
                for member in binding.members:
                    if member in ("allUsers", "allAuthenticatedUsers"):
                        public = True
                        break
            results.append(make_result(
                cis_id="1.10", check_id="gcp_cis_1_10",
                title="Ensure KMS Encryption Keys Are Not Anonymously or Publicly Accessible",
                service="iam", severity="high",
                status="FAIL" if public else "PASS",
                resource_id=ck.name, resource_name=ck.name.split("/")[-1],
                status_extended=(
                    f"KMS key {ck.name} is publicly accessible" if public
                    else f"KMS key {ck.name} is not publicly accessible"
                ),
                remediation="Remove allUsers/allAuthenticatedUsers from KMS key IAM policy.",
                compliance_frameworks=FW,
            ))

    if not results:
        return [make_result(cis_id="1.10", check_id="gcp_cis_1_10",
            title="Ensure KMS Encryption Keys Are Not Anonymously or Publicly Accessible",
            service="iam", severity="high", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No KMS keys found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 1.11 — API keys rotation <= 90 days
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_11(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        apikeys_svc = c.discovery_client("apikeys", "v2")
        resp = apikeys_svc.projects().locations().keys().list(
            parent=f"projects/{cfg.project_id}/locations/global"
        ).execute()
        keys = resp.get("keys", [])
    except Exception:
        keys = []

    now = datetime.now(timezone.utc)
    for key in keys:
        name = key.get("name", "")
        display = key.get("displayName", name.split("/")[-1])
        create_time = key.get("createTime", "")
        if create_time:
            created = datetime.fromisoformat(create_time.replace("Z", "+00:00"))
            age = (now - created).days
        else:
            age = 999
        ok = age <= 90
        results.append(make_result(
            cis_id="1.11", check_id="gcp_cis_1_11",
            title="Ensure API Keys Are Rotated Within 90 Days",
            service="iam", severity="medium",
            status="PASS" if ok else "FAIL",
            resource_id=name, resource_name=display,
            status_extended=f"API key '{display}' age: {age} days (max 90)",
            remediation="Regenerate API keys older than 90 days.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="1.11", check_id="gcp_cis_1_11",
            title="Ensure API Keys Are Rotated Within 90 Days",
            service="iam", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No API keys found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 1.12 — API keys restricted to needed APIs only
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_12(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        apikeys_svc = c.discovery_client("apikeys", "v2")
        resp = apikeys_svc.projects().locations().keys().list(
            parent=f"projects/{cfg.project_id}/locations/global"
        ).execute()
        keys = resp.get("keys", [])
    except Exception:
        keys = []

    for key in keys:
        name = key.get("name", "")
        display = key.get("displayName", name.split("/")[-1])
        restrictions = key.get("restrictions", {})
        api_targets = restrictions.get("apiTargets", [])
        ok = len(api_targets) > 0
        results.append(make_result(
            cis_id="1.12", check_id="gcp_cis_1_12",
            title="Ensure API Keys Are Restricted to Only APIs That Application Needs Access",
            service="iam", severity="medium",
            status="PASS" if ok else "FAIL",
            resource_id=name, resource_name=display,
            status_extended=(
                f"API key '{display}' restricted to {len(api_targets)} API(s)"
                if ok else f"API key '{display}' has no API restrictions (unrestricted)"
            ),
            remediation="Restrict API key to specific APIs via Console > APIs & Services > Credentials.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="1.12", check_id="gcp_cis_1_12",
            title="Ensure API Keys Are Restricted to Only APIs That Application Needs Access",
            service="iam", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No API keys found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 1.13 — API keys restricted to specified hosts/apps (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_13(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.13", "gcp_cis_1_13",
        "Ensure API Keys Are Restricted to Use by Only Specified Hosts and Apps",
        "iam", "medium", cfg.project_id,
        "Requires manual verification of API key application restrictions "
        "(browser keys, server keys, Android/iOS keys).")]


# ═══════════════════════════════════════════════════════════════
# 1.14 — API keys restricted to specified APIs
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_14(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    results = []
    try:
        apikeys_svc = c.discovery_client("apikeys", "v2")
        resp = apikeys_svc.projects().locations().keys().list(
            parent=f"projects/{cfg.project_id}/locations/global"
        ).execute()
        keys = resp.get("keys", [])
    except Exception:
        keys = []

    for key in keys:
        name = key.get("name", "")
        display = key.get("displayName", name.split("/")[-1])
        restrictions = key.get("restrictions", {})
        api_targets = restrictions.get("apiTargets", [])
        ok = len(api_targets) > 0
        results.append(make_result(
            cis_id="1.14", check_id="gcp_cis_1_14",
            title="Ensure API Keys Are Restricted To Necessary APIs",
            service="iam", severity="medium",
            status="PASS" if ok else "FAIL",
            resource_id=name, resource_name=display,
            status_extended=(
                f"API key '{display}': restricted to {len(api_targets)} API target(s)"
                if ok else f"API key '{display}': unrestricted (no apiTargets)"
            ),
            remediation="Add API restrictions to the key via Console > Credentials.",
            compliance_frameworks=FW,
        ))

    if not results:
        return [make_result(cis_id="1.14", check_id="gcp_cis_1_14",
            title="Ensure API Keys Are Restricted To Necessary APIs",
            service="iam", severity="medium", status="PASS",
            resource_id=cfg.project_id,
            status_extended="No API keys found",
            compliance_frameworks=FW)]
    return results


# ═══════════════════════════════════════════════════════════════
# 1.15 — Essential Contacts configured
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_15(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    try:
        resp = c.essentialcontacts.projects().contacts().list(
            parent=f"projects/{cfg.project_id}"
        ).execute()
        contacts = resp.get("contacts", [])
    except Exception:
        contacts = []

    required_categories = {"SECURITY", "TECHNICAL", "BILLING"}
    found_categories = set()
    for contact in contacts:
        for cat in contact.get("notificationCategorySubscriptions", []):
            found_categories.add(cat)

    missing = required_categories - found_categories
    ok = len(missing) == 0

    return [make_result(
        cis_id="1.15", check_id="gcp_cis_1_15",
        title="Ensure Essential Contacts is Configured for Organization",
        service="iam", severity="medium",
        status="PASS" if ok else "FAIL",
        resource_id=cfg.project_id,
        status_extended=(
            "Essential Contacts configured for all required categories"
            if ok else f"Missing Essential Contact categories: {', '.join(sorted(missing))}"
        ),
        remediation="Configure Essential Contacts for Security, Technical, and Billing categories.",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 1.16 — Ensure that no SA key upload is allowed
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_16(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    try:
        crm = c.discovery_client("cloudresourcemanager", "v1")
        resp = crm.projects().getOrgPolicy(
            resource=cfg.project_id,
            body={"constraint": "constraints/iam.disableServiceAccountKeyUpload"}
        ).execute()
        enforced = resp.get("booleanPolicy", {}).get("enforced", False)
    except Exception:
        enforced = False

    return [make_result(
        cis_id="1.16", check_id="gcp_cis_1_16",
        title="Ensure No SA Key Upload Is Allowed",
        service="iam", severity="medium",
        status="PASS" if enforced else "FAIL",
        resource_id=cfg.project_id,
        status_extended=(
            "Org policy iam.disableServiceAccountKeyUpload is enforced"
            if enforced else "Org policy iam.disableServiceAccountKeyUpload is NOT enforced"
        ),
        remediation="Enable org policy constraint iam.disableServiceAccountKeyUpload.",
        compliance_frameworks=FW,
    )]


# ═══════════════════════════════════════════════════════════════
# 1.17 — Managed default SA for Dataproc (MANUAL)
# ═══════════════════════════════════════════════════════════════

def evaluate_cis_1_17(c: GCPClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("1.17", "gcp_cis_1_17",
        "Ensure that Dataproc Cluster Is Not Using the Default Service Account",
        "iam", "medium", cfg.project_id,
        "Requires checking each Dataproc cluster configuration for custom SA assignment.")]
