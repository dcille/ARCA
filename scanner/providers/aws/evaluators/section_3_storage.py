"""CIS AWS v6.0 Section 3: Storage — 9 controls (S3, RDS, EFS)."""

import json
import logging
from .base import AWSClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-AWS-6.0"]


# 3.1.1 — S3 bucket policy denies HTTP
def evaluate_cis_3_1_1(c, cfg):
    results = []
    for bucket in c.s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        try:
            policy_str = c.s3.get_bucket_policy(Bucket=name)["Policy"]
            doc = json.loads(policy_str)
            ssl_required = any(
                stmt.get("Effect") == "Deny" and
                stmt.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport") == "false"
                for stmt in doc.get("Statement", [])
            )
            results.append(make_result(cis_id="3.1.1", check_id="aws_cis_3_1_1",
                title="Ensure S3 Bucket Policy is set to deny HTTP requests",
                service="storage", severity="high",
                status="PASS" if ssl_required else "FAIL",
                resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                status_extended=f"Bucket {name}: SSL-only policy = {ssl_required}",
                remediation="Add bucket policy denying requests where aws:SecureTransport is false.",
                compliance_frameworks=FW))
        except c.s3.exceptions.from_code("NoSuchBucketPolicy"):
            results.append(make_result(cis_id="3.1.1", check_id="aws_cis_3_1_1",
                title="Ensure S3 Bucket Policy is set to deny HTTP requests",
                service="storage", severity="high", status="FAIL",
                resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                status_extended=f"Bucket {name}: no bucket policy exists.",
                remediation="Add a bucket policy denying non-HTTPS requests.",
                compliance_frameworks=FW))
        except Exception:
            results.append(make_result(cis_id="3.1.1", check_id="aws_cis_3_1_1",
                title="Ensure S3 Bucket Policy is set to deny HTTP requests",
                service="storage", severity="high", status="FAIL",
                resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                status_extended=f"Bucket {name}: no bucket policy or could not check.",
                compliance_frameworks=FW))
    return results


# 3.1.2 — MFA Delete on S3 (MANUAL)
def evaluate_cis_3_1_2(c, cfg):
    return [make_manual_result("3.1.2", "aws_cis_3_1_2",
        "Ensure MFA Delete is enabled on S3 buckets",
        "storage", "high", cfg.account_id,
        "MFA Delete requires root credentials to enable. Verify via: aws s3api get-bucket-versioning --bucket <name>")]

# 3.1.3 — S3 data discovered/classified (MANUAL)
def evaluate_cis_3_1_3(c, cfg):
    return [make_manual_result("3.1.3", "aws_cis_3_1_3",
        "Ensure all data in Amazon S3 has been discovered, classified, and secured",
        "storage", "high", cfg.account_id,
        "Requires Amazon Macie or manual data classification process.")]

# 3.1.4 — S3 Block Public Access enabled
def evaluate_cis_3_1_4(c, cfg):
    results = []
    # Account-level check
    try:
        acct_block = c.s3.get_public_access_block()["PublicAccessBlockConfiguration"]  # S3Control
    except Exception:
        acct_block = None

    for bucket in c.s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        try:
            block = c.s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            all_blocked = all([
                block.get("BlockPublicAcls", False),
                block.get("IgnorePublicAcls", False),
                block.get("BlockPublicPolicy", False),
                block.get("RestrictPublicBuckets", False),
            ])
            results.append(make_result(cis_id="3.1.4", check_id="aws_cis_3_1_4",
                title="Ensure S3 is configured with Block Public Access enabled",
                service="storage", severity="critical",
                status="PASS" if all_blocked else "FAIL",
                resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                status_extended=f"Bucket {name}: all public access blocked = {all_blocked}",
                remediation="Enable all 4 Block Public Access settings on the bucket.",
                compliance_frameworks=FW))
        except Exception:
            results.append(make_result(cis_id="3.1.4", check_id="aws_cis_3_1_4",
                title="Ensure S3 is configured with Block Public Access enabled",
                service="storage", severity="critical", status="FAIL",
                resource_id=f"arn:aws:s3:::{name}", resource_name=name,
                status_extended=f"Bucket {name}: no public access block configured.",
                compliance_frameworks=FW))
    return results


# 3.2.1 — RDS encryption at rest
def evaluate_cis_3_2_1(c, cfg):
    results = []
    for region in c.regions:
        rds = c.client("rds", region)
        try:
            for db in rds.describe_db_instances()["DBInstances"]:
                enc = db.get("StorageEncrypted", False)
                results.append(make_result(cis_id="3.2.1", check_id="aws_cis_3_2_1",
                    title="Ensure encryption-at-rest is enabled for RDS instances",
                    service="storage", severity="high", region=region,
                    status="PASS" if enc else "FAIL",
                    resource_id=db.get("DBInstanceArn", db["DBInstanceIdentifier"]),
                    resource_name=db["DBInstanceIdentifier"],
                    status_extended=f"RDS {db['DBInstanceIdentifier']}: encrypted = {enc}",
                    remediation="Enable encryption at rest (requires recreating the instance).",
                    compliance_frameworks=FW))
        except Exception:
            pass
    return results

# 3.2.2 — RDS auto minor version upgrade
def evaluate_cis_3_2_2(c, cfg):
    results = []
    for region in c.regions:
        rds = c.client("rds", region)
        try:
            for db in rds.describe_db_instances()["DBInstances"]:
                auto = db.get("AutoMinorVersionUpgrade", False)
                results.append(make_result(cis_id="3.2.2", check_id="aws_cis_3_2_2",
                    title="Ensure Auto Minor Version Upgrade is enabled for RDS instances",
                    service="storage", severity="high", region=region,
                    status="PASS" if auto else "FAIL",
                    resource_id=db.get("DBInstanceArn", db["DBInstanceIdentifier"]),
                    resource_name=db["DBInstanceIdentifier"],
                    status_extended=f"RDS {db['DBInstanceIdentifier']}: auto minor upgrade = {auto}",
                    remediation="aws rds modify-db-instance --db-instance-identifier <id> --auto-minor-version-upgrade",
                    compliance_frameworks=FW))
        except Exception:
            pass
    return results

# 3.2.3 — RDS not publicly accessible
def evaluate_cis_3_2_3(c, cfg):
    results = []
    for region in c.regions:
        rds = c.client("rds", region)
        try:
            for db in rds.describe_db_instances()["DBInstances"]:
                pub = db.get("PubliclyAccessible", False)
                results.append(make_result(cis_id="3.2.3", check_id="aws_cis_3_2_3",
                    title="Ensure RDS instances are not publicly accessible",
                    service="storage", severity="critical", region=region,
                    status="PASS" if not pub else "FAIL",
                    resource_id=db.get("DBInstanceArn", db["DBInstanceIdentifier"]),
                    resource_name=db["DBInstanceIdentifier"],
                    status_extended=f"RDS {db['DBInstanceIdentifier']}: publicly accessible = {pub}",
                    remediation="aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible",
                    compliance_frameworks=FW))
        except Exception:
            pass
    return results

# 3.2.4 — RDS Multi-AZ (MANUAL)
def evaluate_cis_3_2_4(c, cfg):
    results = []
    for region in c.regions:
        rds = c.client("rds", region)
        try:
            for db in rds.describe_db_instances()["DBInstances"]:
                multi = db.get("MultiAZ", False)
                results.append(make_result(cis_id="3.2.4", check_id="aws_cis_3_2_4",
                    title="Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS",
                    service="storage", severity="high", region=region,
                    status="PASS" if multi else "MANUAL",
                    resource_id=db.get("DBInstanceArn", db["DBInstanceIdentifier"]),
                    resource_name=db["DBInstanceIdentifier"],
                    status_extended=f"RDS {db['DBInstanceIdentifier']}: Multi-AZ = {multi}. CIS classifies as manual — org-dependent.",
                    remediation="Enable Multi-AZ for production databases.",
                    compliance_frameworks=FW))
        except Exception:
            pass
    return results

# 3.3.1 — EFS encryption enabled
def evaluate_cis_3_3_1(c, cfg):
    results = []
    for region in c.regions:
        efs = c.client("efs", region)
        try:
            for fs in efs.describe_file_systems()["FileSystems"]:
                enc = fs.get("Encrypted", False)
                results.append(make_result(cis_id="3.3.1", check_id="aws_cis_3_3_1",
                    title="Ensure encryption is enabled for EFS file systems",
                    service="storage", severity="high", region=region,
                    status="PASS" if enc else "FAIL",
                    resource_id=fs["FileSystemId"],
                    status_extended=f"EFS {fs['FileSystemId']}: encrypted = {enc}",
                    remediation="Create a new encrypted EFS (cannot enable on existing).",
                    compliance_frameworks=FW))
        except Exception:
            pass
    return results
