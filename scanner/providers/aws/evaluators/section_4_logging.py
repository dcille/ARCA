"""CIS AWS v6.0 Section 4: Logging — 9 controls."""

import logging
from .base import AWSClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-AWS-6.0"]


# 4.1 — CloudTrail enabled all regions (MANUAL per CIS)
def evaluate_cis_4_1(c, cfg):
    ct = c.client("cloudtrail")
    try:
        trails = ct.describe_trails()["trailList"]
        multi = any(t.get("IsMultiRegionTrail") for t in trails)
        return [make_result(cis_id="4.1", check_id="aws_cis_4_1",
            title="Ensure CloudTrail is enabled in all regions",
            service="logging", severity="high",
            status="PASS" if multi else "FAIL",
            resource_id="cloudtrail",
            status_extended=f"Multi-region trails: {sum(1 for t in trails if t.get('IsMultiRegionTrail'))} of {len(trails)}",
            remediation="Create a multi-region CloudTrail trail.",
            compliance_frameworks=FW)]
    except Exception:
        return [make_result(cis_id="4.1", check_id="aws_cis_4_1",
            title="Ensure CloudTrail is enabled in all regions",
            service="logging", severity="high", status="FAIL",
            resource_id="cloudtrail", status_extended="No CloudTrail trails found.",
            compliance_frameworks=FW)]

# 4.2 — CloudTrail log validation
def evaluate_cis_4_2(c, cfg):
    results = []
    ct = c.client("cloudtrail")
    try:
        for trail in ct.describe_trails()["trailList"]:
            valid = trail.get("LogFileValidationEnabled", False)
            results.append(make_result(cis_id="4.2", check_id="aws_cis_4_2",
                title="Ensure CloudTrail log file validation is enabled",
                service="logging", severity="high",
                status="PASS" if valid else "FAIL",
                resource_id=trail.get("TrailARN", trail["Name"]), resource_name=trail["Name"],
                status_extended=f"Trail {trail['Name']}: log validation = {valid}",
                remediation="aws cloudtrail update-trail --name <trail> --enable-log-file-validation",
                compliance_frameworks=FW))
    except Exception:
        pass
    return results

# 4.3 — AWS Config enabled in all regions
def evaluate_cis_4_3(c, cfg):
    results = []
    for region in c.regions:
        config = c.client("config", region)
        try:
            recorders = config.describe_configuration_recorders()["ConfigurationRecorders"]
            status = config.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
            recording = any(s.get("recording") for s in status)
            results.append(make_result(cis_id="4.3", check_id="aws_cis_4_3",
                title="Ensure AWS Config is enabled in all regions",
                service="logging", severity="high", region=region,
                status="PASS" if recorders and recording else "FAIL",
                resource_id=f"config:{region}",
                status_extended=f"Config in {region}: recorders={len(recorders)}, recording={recording}",
                remediation=f"Enable AWS Config in {region}.",
                compliance_frameworks=FW))
        except Exception:
            results.append(make_result(cis_id="4.3", check_id="aws_cis_4_3",
                title="Ensure AWS Config is enabled in all regions",
                service="logging", severity="high", region=region, status="FAIL",
                resource_id=f"config:{region}",
                status_extended=f"Config not enabled in {region}.",
                compliance_frameworks=FW))
    return results

# 4.4 — CloudTrail S3 bucket access logging (MANUAL)
def evaluate_cis_4_4(c, cfg):
    results = []
    ct = c.client("cloudtrail")
    try:
        for trail in ct.describe_trails()["trailList"]:
            bucket = trail.get("S3BucketName")
            if not bucket:
                continue
            try:
                log_cfg = c.s3.get_bucket_logging(Bucket=bucket)
                has_log = "LoggingEnabled" in log_cfg
                results.append(make_result(cis_id="4.4", check_id="aws_cis_4_4",
                    title="Ensure server access logging is enabled on the CloudTrail S3 bucket",
                    service="logging", severity="high",
                    status="PASS" if has_log else "FAIL",
                    resource_id=f"arn:aws:s3:::{bucket}", resource_name=bucket,
                    status_extended=f"CloudTrail bucket {bucket}: access logging = {has_log}",
                    remediation="Enable server access logging on the S3 bucket used by CloudTrail.",
                    compliance_frameworks=FW))
            except Exception:
                pass
    except Exception:
        pass
    return results

# 4.5 — CloudTrail encrypted with KMS CMKs
def evaluate_cis_4_5(c, cfg):
    results = []
    ct = c.client("cloudtrail")
    try:
        for trail in ct.describe_trails()["trailList"]:
            kms = trail.get("KmsKeyId")
            results.append(make_result(cis_id="4.5", check_id="aws_cis_4_5",
                title="Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
                service="logging", severity="high",
                status="PASS" if kms else "FAIL",
                resource_id=trail.get("TrailARN", trail["Name"]), resource_name=trail["Name"],
                status_extended=f"Trail {trail['Name']}: KMS encryption = {'yes' if kms else 'no'}",
                remediation="aws cloudtrail update-trail --name <trail> --kms-key-id <key-arn>",
                compliance_frameworks=FW))
    except Exception:
        pass
    return results

# 4.6 — CMK rotation enabled
def evaluate_cis_4_6(c, cfg):
    results = []
    for region in c.regions:
        kms = c.client("kms", region)
        try:
            for key_meta in kms.list_keys()["Keys"]:
                kid = key_meta["KeyId"]
                try:
                    info = kms.describe_key(KeyId=kid)["KeyMetadata"]
                    if info.get("KeyManager") != "CUSTOMER" or info.get("KeyState") != "Enabled":
                        continue
                    if info.get("KeySpec") not in ("SYMMETRIC_DEFAULT",):
                        continue
                    rotation = kms.get_key_rotation_status(KeyId=kid)
                    results.append(make_result(cis_id="4.6", check_id="aws_cis_4_6",
                        title="Ensure rotation for customer-created symmetric CMKs is enabled",
                        service="logging", severity="high", region=region,
                        status="PASS" if rotation.get("KeyRotationEnabled") else "FAIL",
                        resource_id=info.get("Arn", kid),
                        status_extended=f"KMS key {kid}: rotation = {rotation.get('KeyRotationEnabled')}",
                        remediation="aws kms enable-key-rotation --key-id <key-id>",
                        compliance_frameworks=FW))
                except Exception:
                    pass
        except Exception:
            pass
    return results

# 4.7 — VPC flow logging enabled in all VPCs
def evaluate_cis_4_7(c, cfg):
    results = []
    for region in c.regions:
        ec2 = c.client("ec2", region)
        try:
            for vpc in ec2.describe_vpcs()["Vpcs"]:
                vid = vpc["VpcId"]
                flows = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vid]}])["FlowLogs"]
                results.append(make_result(cis_id="4.7", check_id="aws_cis_4_7",
                    title="Ensure VPC flow logging is enabled in all VPCs",
                    service="logging", severity="high", region=region,
                    status="PASS" if flows else "FAIL",
                    resource_id=vid,
                    status_extended=f"VPC {vid}: {len(flows)} flow log(s)",
                    remediation=f"Enable VPC flow logs for {vid}.",
                    compliance_frameworks=FW))
        except Exception:
            pass
    return results

# 4.8 — S3 object-level write events
def evaluate_cis_4_8(c, cfg):
    results = []
    ct = c.client("cloudtrail")
    try:
        for trail in ct.describe_trails()["trailList"]:
            arn = trail.get("TrailARN", trail["Name"])
            has_write = False
            try:
                sel = ct.get_event_selectors(TrailName=arn)
                for adv in sel.get("AdvancedEventSelectors", []):
                    fields = {f["Field"]: f.get("Equals", []) for f in adv.get("FieldSelectors", [])}
                    if "AWS::S3::Object" in fields.get("resources.type", []):
                        ro = fields.get("readOnly", [])
                        if not ro or "false" in ro:
                            has_write = True
                for basic in sel.get("EventSelectors", []):
                    for dr in basic.get("DataResources", []):
                        if dr.get("Type") == "AWS::S3::Object":
                            rw = basic.get("ReadWriteType", "All")
                            if rw in ("WriteOnly", "All"):
                                has_write = True
            except Exception:
                pass
            results.append(make_result(cis_id="4.8", check_id="aws_cis_4_8",
                title="Ensure object-level logging for write events is enabled for S3 buckets",
                service="logging", severity="high",
                status="PASS" if has_write else "FAIL",
                resource_id=arn, resource_name=trail["Name"],
                status_extended=f"Trail {trail['Name']}: S3 write data events = {has_write}",
                remediation="Enable S3 data event logging (write) on the CloudTrail trail.",
                compliance_frameworks=FW))
    except Exception:
        pass
    return results

# 4.9 — S3 object-level read events
def evaluate_cis_4_9(c, cfg):
    results = []
    ct = c.client("cloudtrail")
    try:
        for trail in ct.describe_trails()["trailList"]:
            arn = trail.get("TrailARN", trail["Name"])
            has_read = False
            try:
                sel = ct.get_event_selectors(TrailName=arn)
                for adv in sel.get("AdvancedEventSelectors", []):
                    fields = {f["Field"]: f.get("Equals", []) for f in adv.get("FieldSelectors", [])}
                    if "AWS::S3::Object" in fields.get("resources.type", []):
                        ro = fields.get("readOnly", [])
                        if not ro or "true" in ro:
                            has_read = True
                for basic in sel.get("EventSelectors", []):
                    for dr in basic.get("DataResources", []):
                        if dr.get("Type") == "AWS::S3::Object":
                            rw = basic.get("ReadWriteType", "All")
                            if rw in ("ReadOnly", "All"):
                                has_read = True
            except Exception:
                pass
            results.append(make_result(cis_id="4.9", check_id="aws_cis_4_9",
                title="Ensure object-level logging for read events is enabled for S3 buckets",
                service="logging", severity="high",
                status="PASS" if has_read else "FAIL",
                resource_id=arn, resource_name=trail["Name"],
                status_extended=f"Trail {trail['Name']}: S3 read data events = {has_read}",
                remediation="Enable S3 data event logging (read) on the CloudTrail trail.",
                compliance_frameworks=FW))
    except Exception:
        pass
    return results
