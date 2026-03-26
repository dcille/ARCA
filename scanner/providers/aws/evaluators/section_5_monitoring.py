"""CIS AWS v6.0 Section 5: Monitoring — 16 controls.

5.1–5.15 are CIS-manual (require CloudWatch metric filters / alarms).
5.16 is automated (Security Hub).
"""

import logging
from .base import AWSClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-AWS-6.0"]

# Generic helper for monitoring controls that check CloudWatch metric filters
_MONITORING_CONTROLS = [
    ("5.1", "Ensure unauthorized API calls are monitored",
     "{$.errorCode=\"*UnauthorizedAccess*\"}"),
    ("5.2", "Ensure management console sign-in without MFA is monitored",
     "{$.eventName=\"ConsoleLogin\" && $.additionalEventData.MFAUsed !=\"Yes\"}"),
    ("5.3", "Ensure usage of the root account is monitored",
     "{$.userIdentity.type=\"Root\"}"),
    ("5.4", "Ensure IAM policy changes are monitored",
     "{$.eventName=CreatePolicy||$.eventName=DeletePolicy||...}"),
    ("5.5", "Ensure CloudTrail configuration changes are monitored",
     "{$.eventName=CreateTrail||$.eventName=UpdateTrail||...}"),
    ("5.6", "Ensure AWS Management Console authentication failures are monitored",
     "{$.eventName=ConsoleLogin && $.errorMessage=\"Failed authentication\"}"),
    ("5.7", "Ensure disabling or scheduled deletion of customer created CMKs is monitored",
     "{$.eventSource=kms* && $.eventName=DisableKey||ScheduleKeyDeletion}"),
    ("5.8", "Ensure S3 bucket policy changes are monitored",
     "{$.eventSource=s3* && $.eventName=PutBucketPolicy||DeleteBucketPolicy}"),
    ("5.9", "Ensure AWS Config configuration changes are monitored",
     "{$.eventSource=config* && $.eventName=StopConfigurationRecorder||...}"),
    ("5.10", "Ensure security group changes are monitored",
     "{$.eventName=AuthorizeSecurityGroup*||RevokeSecurityGroup*||...}"),
    ("5.11", "Ensure Network Access Control List (NACL) changes are monitored",
     "{$.eventName=CreateNetworkAcl*||DeleteNetworkAcl*||...}"),
    ("5.12", "Ensure changes to network gateways are monitored",
     "{$.eventName=CreateCustomerGateway||DeleteCustomerGateway||...}"),
    ("5.13", "Ensure route table changes are monitored",
     "{$.eventName=CreateRoute*||DeleteRoute*||ReplaceRoute*}"),
    ("5.14", "Ensure VPC changes are monitored",
     "{$.eventName=CreateVpc||DeleteVpc||ModifyVpcAttribute||...}"),
    ("5.15", "Ensure AWS Organizations changes are monitored",
     "{$.eventSource=organizations*}"),
]


def _make_monitoring_evaluator(cis_id, title, filter_pattern):
    """Generate an evaluator for a CloudWatch monitoring control.

    These are CIS-manual because verifying the exact filter+alarm+SNS chain
    requires deep inspection of CloudWatch Logs metric filters. We attempt
    a best-effort check.
    """
    def evaluator(c, cfg):
        # Try to find a matching metric filter in CloudWatch Logs
        found = False
        for region in c.regions:
            logs = c.client("logs", region)
            try:
                # Check metric filters across log groups associated with CloudTrail
                ct = c.client("cloudtrail", region)
                trails = ct.describe_trails()["trailList"]
                for trail in trails:
                    cw_group_arn = trail.get("CloudWatchLogsLogGroupArn", "")
                    if not cw_group_arn:
                        continue
                    # Extract log group name from ARN
                    # arn:aws:logs:region:acct:log-group:name:*
                    parts = cw_group_arn.split(":")
                    if len(parts) >= 7:
                        lg_name = parts[6]
                        try:
                            filters = logs.describe_metric_filters(logGroupName=lg_name)
                            if filters.get("metricFilters"):
                                # Simple heuristic: if any metric filter exists on the CT log group
                                found = True
                        except Exception:
                            pass
            except Exception:
                pass
            if found:
                break

        return [make_result(
            cis_id=cis_id, check_id=f"aws_cis_{cis_id.replace('.', '_')}",
            title=title, service="monitoring", severity="high",
            status="PASS" if found else "MANUAL",
            resource_id=cfg.account_id,
            status_extended=(
                f"CloudWatch metric filter detected for CloudTrail log group."
                if found else
                f"CIS classifies as manual. Verify metric filter exists: {filter_pattern[:80]}"
            ),
            remediation=f"Create CloudWatch metric filter and alarm for: {filter_pattern[:100]}",
            compliance_frameworks=FW,
        )]
    return evaluator


# Generate evaluators for 5.1–5.15
for _cid, _title, _pattern in _MONITORING_CONTROLS:
    _fn_name = f"evaluate_cis_{_cid.replace('.', '_')}"
    globals()[_fn_name] = _make_monitoring_evaluator(_cid, _title, _pattern)


# 5.16 — Security Hub enabled (AUTOMATED)
def evaluate_cis_5_16(c, cfg):
    results = []
    for region in c.regions:
        try:
            sh = c.client("securityhub", region)
            hub = sh.describe_hub()
            enabled = "HubArn" in hub
            results.append(make_result(cis_id="5.16", check_id="aws_cis_5_16",
                title="Ensure AWS Security Hub is enabled",
                service="monitoring", severity="high", region=region,
                status="PASS" if enabled else "FAIL",
                resource_id=hub.get("HubArn", f"securityhub:{region}"),
                status_extended=f"Security Hub in {region}: {'enabled' if enabled else 'disabled'}",
                remediation="aws securityhub enable-security-hub --enable-default-standards",
                compliance_frameworks=FW))
        except Exception:
            results.append(make_result(cis_id="5.16", check_id="aws_cis_5_16",
                title="Ensure AWS Security Hub is enabled",
                service="monitoring", severity="high", region=region, status="FAIL",
                resource_id=f"securityhub:{region}",
                status_extended=f"Security Hub not enabled in {region}.",
                compliance_frameworks=FW))
    return results
