"""CIS AWS v6.0 Section 2: Identity and Access Management — 21 controls."""

import csv
import io
import json
import logging
import urllib.parse
from datetime import datetime, timezone

from .base import AWSClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-AWS-6.0"]


# 2.1 — Contact details (MANUAL)
def evaluate_cis_2_1(c, cfg):
    return [make_manual_result("2.1", "aws_cis_2_1", "Maintain current contact details",
        "iam", "high", cfg.account_id,
        "Contact details can only be verified via AWS Console > Account Settings.")]

# 2.2 — Security contact (MANUAL)
def evaluate_cis_2_2(c, cfg):
    return [make_manual_result("2.2", "aws_cis_2_2", "Ensure security contact information is registered",
        "iam", "high", cfg.account_id,
        "Security contact can only be verified via AWS Console > Account Settings > Alternate Contacts.")]

# 2.3 — No root access keys
def evaluate_cis_2_3(c, cfg):
    summary = c.iam.get_account_summary()["SummaryMap"]
    keys = summary.get("AccountAccessKeysPresent", 0)
    return [make_result(cis_id="2.3", check_id="aws_cis_2_3",
        title="Ensure no root user account access key exists",
        service="iam", severity="critical",
        status="PASS" if keys == 0 else "FAIL",
        resource_id="root",
        status_extended=f"Root account access keys: {keys}",
        remediation="Delete all root account access keys via IAM console.",
        compliance_frameworks=FW)]

# 2.4 — Root MFA
def evaluate_cis_2_4(c, cfg):
    summary = c.iam.get_account_summary()["SummaryMap"]
    mfa = summary.get("AccountMFAEnabled", 0) == 1
    return [make_result(cis_id="2.4", check_id="aws_cis_2_4",
        title="Ensure MFA is enabled for the root user account",
        service="iam", severity="critical",
        status="PASS" if mfa else "FAIL", resource_id="root",
        status_extended=f"Root MFA enabled: {mfa}",
        remediation="Enable MFA for root: IAM > Dashboard > Activate MFA on root.",
        compliance_frameworks=FW)]

# 2.5 — Hardware MFA for root (MANUAL)
def evaluate_cis_2_5(c, cfg):
    return [make_manual_result("2.5", "aws_cis_2_5",
        "Ensure hardware MFA is enabled for the root user account",
        "iam", "critical", cfg.account_id,
        "Requires verifying the MFA device type (hardware vs virtual) via Console.")]

# 2.6 — Eliminate root usage (MANUAL)
def evaluate_cis_2_6(c, cfg):
    return [make_manual_result("2.6", "aws_cis_2_6",
        "Eliminate use of the root user for administrative and daily tasks",
        "iam", "critical", cfg.account_id,
        "Requires reviewing CloudTrail logs for root account activity.")]

# 2.7 — Password min length >= 14
def evaluate_cis_2_7(c, cfg):
    try:
        pol = c.iam.get_account_password_policy()["PasswordPolicy"]
        length = pol.get("MinimumPasswordLength", 0)
        ok = length >= 14
        return [make_result(cis_id="2.7", check_id="aws_cis_2_7",
            title="Ensure IAM password policy requires minimum length of 14 or greater",
            service="iam", severity="high",
            status="PASS" if ok else "FAIL", resource_id="password-policy",
            status_extended=f"MinimumPasswordLength = {length} (requires >= 14)",
            remediation="aws iam update-account-password-policy --minimum-password-length 14",
            compliance_frameworks=FW)]
    except c.iam.exceptions.NoSuchEntityException:
        return [make_result(cis_id="2.7", check_id="aws_cis_2_7",
            title="Ensure IAM password policy requires minimum length of 14 or greater",
            service="iam", severity="high", status="FAIL", resource_id="password-policy",
            status_extended="No custom password policy configured.",
            remediation="Create a password policy: aws iam update-account-password-policy --minimum-password-length 14",
            compliance_frameworks=FW)]

# 2.8 — Password reuse prevention >= 24
def evaluate_cis_2_8(c, cfg):
    try:
        pol = c.iam.get_account_password_policy()["PasswordPolicy"]
        reuse = pol.get("PasswordReusePrevention", 0)
        ok = reuse >= 24
        return [make_result(cis_id="2.8", check_id="aws_cis_2_8",
            title="Ensure IAM password policy prevents password reuse",
            service="iam", severity="high",
            status="PASS" if ok else "FAIL", resource_id="password-policy",
            status_extended=f"PasswordReusePrevention = {reuse} (requires >= 24)",
            remediation="aws iam update-account-password-policy --password-reuse-prevention 24",
            compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="2.8", check_id="aws_cis_2_8",
            title="Ensure IAM password policy prevents password reuse",
            service="iam", severity="high", status="FAIL", resource_id="password-policy",
            status_extended="No password policy or cannot query.",
            compliance_frameworks=FW)]

# 2.9 — MFA for all console users
def evaluate_cis_2_9(c, cfg):
    results = []
    try:
        c.iam.generate_credential_report()
    except Exception:
        pass
    try:
        report = c.iam.get_credential_report()
        reader = csv.DictReader(io.StringIO(report["Content"].decode("utf-8")))
        for row in reader:
            user = row["user"]
            if user == "<root_account>":
                continue
            has_password = row.get("password_enabled", "false") == "true"
            has_mfa = row.get("mfa_active", "false") == "true"
            if has_password:
                results.append(make_result(cis_id="2.9", check_id="aws_cis_2_9",
                    title="Ensure MFA is enabled for all IAM users with console password",
                    service="iam", severity="high",
                    status="PASS" if has_mfa else "FAIL",
                    resource_id=row.get("arn", user), resource_name=user,
                    status_extended=f"User {user}: console password=yes, MFA={has_mfa}",
                    remediation=f"Enable MFA for user {user}.",
                    compliance_frameworks=FW))
    except Exception as e:
        results.append(make_result(cis_id="2.9", check_id="aws_cis_2_9",
            title="Ensure MFA is enabled for all IAM users with console password",
            service="iam", severity="high", status="ERROR", resource_id=cfg.account_id,
            status_extended=f"Could not generate/get credential report: {e}",
            compliance_frameworks=FW))
    return results

# 2.10 — No access keys at initial setup (MANUAL)
def evaluate_cis_2_10(c, cfg):
    return [make_manual_result("2.10", "aws_cis_2_10",
        "Do not create access keys during initial setup for IAM users with a console password",
        "iam", "high", cfg.account_id,
        "Requires reviewing user creation processes and policies.")]

# 2.11 — Unused credentials 45 days
def evaluate_cis_2_11(c, cfg):
    results = []
    try:
        c.iam.generate_credential_report()
    except Exception:
        pass
    try:
        report = c.iam.get_credential_report()
        reader = csv.DictReader(io.StringIO(report["Content"].decode("utf-8")))
        for row in reader:
            user = row["user"]
            if user == "<root_account>":
                continue
            for field in ["password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date"]:
                val = row.get(field, "N/A")
                if val in ("N/A", "no_information", "not_supported", ""):
                    continue
                try:
                    dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                    days = (datetime.now(timezone.utc) - dt).days
                    if days > 45:
                        results.append(make_result(cis_id="2.11", check_id="aws_cis_2_11",
                            title="Ensure credentials unused for 45 days or more are disabled",
                            service="iam", severity="high", status="FAIL",
                            resource_id=row.get("arn", user), resource_name=user,
                            status_extended=f"User {user}: {field} = {days} days ago (> 45)",
                            remediation=f"Disable or remove unused credentials for {user}.",
                            compliance_frameworks=FW))
                except Exception:
                    pass
    except Exception:
        pass
    if not results:
        results.append(make_result(cis_id="2.11", check_id="aws_cis_2_11",
            title="Ensure credentials unused for 45 days or more are disabled",
            service="iam", severity="high", status="PASS", resource_id=cfg.account_id,
            status_extended="No credentials unused for > 45 days found.",
            compliance_frameworks=FW))
    return results

# 2.12 — Single active access key per user
def evaluate_cis_2_12(c, cfg):
    results = []
    for user in c.iam.list_users()["Users"]:
        name = user["UserName"]
        keys = c.iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
        active = [k for k in keys if k["Status"] == "Active"]
        results.append(make_result(cis_id="2.12", check_id="aws_cis_2_12",
            title="Ensure there is only one active access key for any single IAM user",
            service="iam", severity="critical",
            status="PASS" if len(active) <= 1 else "FAIL",
            resource_id=user["Arn"], resource_name=name,
            status_extended=f"User {name}: {len(active)} active access key(s)",
            remediation="Deactivate extra access keys so only one remains active.",
            compliance_frameworks=FW))
    return results

# 2.13 — Access keys rotated every 90 days
def evaluate_cis_2_13(c, cfg):
    results = []
    for user in c.iam.list_users()["Users"]:
        name = user["UserName"]
        keys = c.iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
        for key in keys:
            if key["Status"] != "Active":
                continue
            age = (datetime.now(timezone.utc) - key["CreateDate"]).days
            results.append(make_result(cis_id="2.13", check_id="aws_cis_2_13",
                title="Ensure access keys are rotated every 90 days or less",
                service="iam", severity="high",
                status="PASS" if age <= 90 else "FAIL",
                resource_id=key["AccessKeyId"], resource_name=f"{name}/{key['AccessKeyId']}",
                status_extended=f"Key {key['AccessKeyId']} for {name}: {age} days old",
                remediation="Rotate the access key: create new, update apps, deactivate old.",
                compliance_frameworks=FW))
    return results

# 2.14 — Users receive permissions only through groups
def evaluate_cis_2_14(c, cfg):
    results = []
    for user in c.iam.list_users()["Users"]:
        name = user["UserName"]
        inline = c.iam.list_user_policies(UserName=name)["PolicyNames"]
        attached = c.iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
        ok = not inline and not attached
        results.append(make_result(cis_id="2.14", check_id="aws_cis_2_14",
            title="Ensure IAM users receive permissions only through groups",
            service="iam", severity="high",
            status="PASS" if ok else "FAIL",
            resource_id=user["Arn"], resource_name=name,
            status_extended=f"User {name}: {len(inline)} inline + {len(attached)} attached policies",
            remediation="Remove all direct policies; grant permissions via IAM groups only.",
            compliance_frameworks=FW))
    return results

# 2.15 — No *:* admin policies attached
def evaluate_cis_2_15(c, cfg):
    results = []
    try:
        policies = c.iam.list_policies(Scope="Local", OnlyAttached=True)["Policies"]
        for pol in policies:
            version = c.iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])["PolicyVersion"]
            doc = version["Document"]
            if isinstance(doc, str):
                doc = json.loads(urllib.parse.unquote(doc))
            has_star = False
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    if isinstance(actions, str): actions = [actions]
                    if isinstance(resources, str): resources = [resources]
                    if "*" in actions and "*" in resources:
                        has_star = True
                        break
            results.append(make_result(cis_id="2.15", check_id="aws_cis_2_15",
                title="Ensure IAM policies that allow full *:* administrative privileges are not attached",
                service="iam", severity="critical",
                status="FAIL" if has_star else "PASS",
                resource_id=pol["Arn"], resource_name=pol["PolicyName"],
                status_extended=f"Policy {pol['PolicyName']}: {'grants *:* admin' if has_star else 'no *:* admin'}",
                remediation="Restrict the policy to only required permissions (least privilege).",
                compliance_frameworks=FW))
    except Exception:
        pass
    return results

# 2.16 — Support role created
def evaluate_cis_2_16(c, cfg):
    try:
        entities = c.iam.list_entities_for_policy(PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess")
        has_role = bool(entities.get("PolicyRoles", []))
        return [make_result(cis_id="2.16", check_id="aws_cis_2_16",
            title="Ensure a support role has been created to manage incidents with AWS Support",
            service="iam", severity="high",
            status="PASS" if has_role else "FAIL", resource_id="AWSSupportAccess",
            status_extended=f"AWSSupportAccess attached to roles: {has_role}",
            remediation="Create an IAM role with AWSSupportAccess policy attached.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="2.16", check_id="aws_cis_2_16",
            title="Ensure a support role has been created",
            service="iam", severity="high", status="FAIL", resource_id="AWSSupportAccess",
            status_extended="Could not query AWSSupportAccess policy entities.",
            compliance_frameworks=FW)]

# 2.17 — IAM instance roles for EC2
def evaluate_cis_2_17(c, cfg):
    results = []
    for region in c.regions:
        ec2 = c.client("ec2", region)
        try:
            for res in ec2.describe_instances()["Reservations"]:
                for inst in res["Instances"]:
                    iid = inst["InstanceId"]
                    profile = inst.get("IamInstanceProfile")
                    results.append(make_result(cis_id="2.17", check_id="aws_cis_2_17",
                        title="Ensure IAM instance roles are used for AWS resource access from instances",
                        service="iam", severity="high", region=region,
                        status="PASS" if profile else "FAIL",
                        resource_id=iid,
                        status_extended=f"Instance {iid}: IAM profile = {'yes' if profile else 'NONE'}",
                        remediation="Attach an IAM instance profile/role to the EC2 instance.",
                        compliance_frameworks=FW))
        except Exception:
            pass
    return results

# 2.18 — Expired SSL/TLS certificates removed
def evaluate_cis_2_18(c, cfg):
    results = []
    try:
        certs = c.iam.list_server_certificates()["ServerCertificateMetadataList"]
        now = datetime.now(timezone.utc)
        for cert in certs:
            name = cert["ServerCertificateName"]
            exp = cert["Expiration"]
            expired = exp < now
            results.append(make_result(cis_id="2.18", check_id="aws_cis_2_18",
                title="Ensure all expired SSL/TLS certificates stored in AWS IAM are removed",
                service="iam", severity="high",
                status="FAIL" if expired else "PASS",
                resource_id=cert.get("Arn", name), resource_name=name,
                status_extended=f"Certificate {name}: {'EXPIRED' if expired else 'valid'} (expires {exp.isoformat()})",
                remediation=f"Delete expired certificate: aws iam delete-server-certificate --server-certificate-name {name}",
                compliance_frameworks=FW))
    except Exception:
        pass
    if not results:
        results.append(make_result(cis_id="2.18", check_id="aws_cis_2_18",
            title="Ensure all expired SSL/TLS certificates stored in AWS IAM are removed",
            service="iam", severity="high", status="PASS", resource_id=cfg.account_id,
            status_extended="No IAM server certificates found.", compliance_frameworks=FW))
    return results

# 2.19 — IAM Access Analyzer enabled for all regions
def evaluate_cis_2_19(c, cfg):
    results = []
    for region in c.regions:
        try:
            aa = c.client("accessanalyzer", region)
            analyzers = aa.list_analyzers(type="ACCOUNT")["analyzers"]
            active = [a for a in analyzers if a.get("status") == "ACTIVE"]
            results.append(make_result(cis_id="2.19", check_id="aws_cis_2_19",
                title="Ensure IAM Access Analyzer is enabled for all regions",
                service="iam", severity="high", region=region,
                status="PASS" if active else "FAIL",
                resource_id=f"access-analyzer:{region}",
                status_extended=f"Access Analyzer in {region}: {len(active)} active analyzer(s)",
                remediation=f"Enable Access Analyzer in {region}: aws accessanalyzer create-analyzer --analyzer-name default --type ACCOUNT --region {region}",
                compliance_frameworks=FW))
        except Exception:
            results.append(make_result(cis_id="2.19", check_id="aws_cis_2_19",
                title="Ensure IAM Access Analyzer is enabled for all regions",
                service="iam", severity="high", region=region, status="FAIL",
                resource_id=f"access-analyzer:{region}",
                status_extended=f"Could not query Access Analyzer in {region}.",
                compliance_frameworks=FW))
    return results

# 2.20 — Centralized IAM (MANUAL)
def evaluate_cis_2_20(c, cfg):
    return [make_manual_result("2.20", "aws_cis_2_20",
        "Ensure IAM users are managed centrally via identity federation or AWS Organizations",
        "iam", "high", cfg.account_id,
        "Requires verifying identity federation (SSO/SAML) or AWS Organizations setup.")]

# 2.21 — CloudShell restricted (MANUAL)
def evaluate_cis_2_21(c, cfg):
    try:
        entities = c.iam.list_entities_for_policy(PolicyArn="arn:aws:iam::aws:policy/AWSCloudShellFullAccess")
        roles = entities.get("PolicyRoles", [])
        users = entities.get("PolicyUsers", [])
        groups = entities.get("PolicyGroups", [])
        attached = bool(roles or users or groups)
        return [make_result(cis_id="2.21", check_id="aws_cis_2_21",
            title="Ensure access to AWSCloudShellFullAccess is restricted",
            service="iam", severity="high",
            status="FAIL" if attached else "PASS",
            resource_id="AWSCloudShellFullAccess",
            status_extended=f"AWSCloudShellFullAccess attached to {len(roles)} roles, {len(users)} users, {len(groups)} groups",
            remediation="Detach AWSCloudShellFullAccess and use a restrictive custom policy.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_manual_result("2.21", "aws_cis_2_21",
            "Ensure access to AWSCloudShellFullAccess is restricted",
            "iam", "high", cfg.account_id,
            "Could not query AWSCloudShellFullAccess policy entities.")]
