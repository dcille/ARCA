"""CIS Alibaba Cloud v2.0 Sections 2-4: Logging/Monitoring, Networking, VMs -- 34 controls.

Section 2: Logging and Monitoring (23 controls — 2 automated, 21 manual)
Section 3: Networking (5 controls — 0 automated, 5 manual)
Section 4: Virtual Machines (6 controls — 0 automated, 6 manual)
"""

import logging
from .base import AlibabaClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-Alibaba-2.0"]


# ═══════════════════════════════════════════════════════════════════
# Section 2: Logging and Monitoring
# ═══════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────
# 2.1 -- ActionTrail exports to Log Service (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_2_1(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_actiontrail20200706 import models as at_models
    results = []
    resp = c.actiontrail.describe_trails(at_models.DescribeTrailsRequest())
    trails = resp.body.trail_list if resp.body.trail_list else []

    if not trails:
        return [make_result(cis_id="2.1", check_id="ali_cis_2_1",
            title="Ensure ActionTrail is configured to export all log entries",
            service="logging", severity="medium", status="FAIL",
            resource_id=cfg.account_id,
            status_extended="No ActionTrail trails configured.",
            remediation="Create an ActionTrail trail that delivers to OSS and/or Log Service.",
            compliance_frameworks=FW)]

    has_multi_region = False
    for trail in trails:
        trail_name = getattr(trail, "name", "unknown")
        is_logging = getattr(trail, "status", "") == "Enable"
        sls_project = getattr(trail, "sls_project_arn", "") or ""
        oss_bucket = getattr(trail, "oss_bucket_name", "") or ""
        delivers = bool(sls_project or oss_bucket)

        if is_logging and delivers:
            has_multi_region = True

        results.append(make_result(
            cis_id="2.1", check_id="ali_cis_2_1",
            title="Ensure ActionTrail is configured to export all log entries",
            service="logging", severity="medium",
            status="PASS" if (is_logging and delivers) else "FAIL",
            resource_id=trail_name, resource_name=trail_name,
            status_extended=(
                f"Trail '{trail_name}': logging={'enabled' if is_logging else 'disabled'}, "
                f"SLS={'yes' if sls_project else 'no'}, OSS={'yes' if oss_bucket else 'no'}"
            ),
            remediation="Enable the trail and configure delivery to SLS or OSS.",
            compliance_frameworks=FW,
        ))

    if not has_multi_region:
        results.append(make_result(
            cis_id="2.1", check_id="ali_cis_2_1",
            title="Ensure ActionTrail is configured to export all log entries",
            service="logging", severity="medium", status="FAIL",
            resource_id=cfg.account_id,
            status_extended="No active trail delivers logs to SLS or OSS.",
            remediation="Configure at least one ActionTrail trail with SLS or OSS delivery.",
            compliance_frameworks=FW,
        ))

    return results


# ───────────────────────────────────────────────────────────────
# 2.2 -- OSS bucket for ActionTrail logs not public (automated)
# ───────────────────────────────────────────────────────────────

def evaluate_cis_2_2(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    from alibabacloud_actiontrail20200706 import models as at_models
    import oss2
    results = []
    resp = c.actiontrail.describe_trails(at_models.DescribeTrailsRequest())
    trails = resp.body.trail_list if resp.body.trail_list else []

    oss_buckets_checked = set()
    for trail in trails:
        bucket_name = getattr(trail, "oss_bucket_name", "") or ""
        if not bucket_name or bucket_name in oss_buckets_checked:
            continue
        oss_buckets_checked.add(bucket_name)

        try:
            bucket = c.oss_bucket(bucket_name)
            acl = bucket.get_bucket_acl()
            acl_grant = acl.acl
            is_public = acl_grant in ("public-read", "public-read-write")
        except Exception as e:
            logger.warning("Failed to check OSS bucket ACL for %s: %s", bucket_name, e)
            is_public = None

        if is_public is None:
            results.append(make_result(
                cis_id="2.2", check_id="ali_cis_2_2",
                title="Ensure ActionTrail log OSS bucket is not publicly accessible",
                service="logging", severity="critical", status="ERROR",
                resource_id=bucket_name, resource_name=bucket_name,
                status_extended=f"Could not determine ACL for OSS bucket '{bucket_name}'.",
                compliance_frameworks=FW,
            ))
        else:
            results.append(make_result(
                cis_id="2.2", check_id="ali_cis_2_2",
                title="Ensure ActionTrail log OSS bucket is not publicly accessible",
                service="logging", severity="critical",
                status="FAIL" if is_public else "PASS",
                resource_id=bucket_name, resource_name=bucket_name,
                status_extended=(
                    f"OSS bucket '{bucket_name}': ACL={acl_grant} "
                    f"({'PUBLIC - NOT COMPLIANT' if is_public else 'private'})"
                ),
                remediation="Set bucket ACL to private: oss2.Bucket.put_bucket_acl(oss2.BUCKET_ACL_PRIVATE)",
                compliance_frameworks=FW,
            ))

    return results or [make_result(cis_id="2.2", check_id="ali_cis_2_2",
        title="Ensure ActionTrail log OSS bucket is not publicly accessible",
        service="logging", severity="critical", status="N/A",
        resource_id=cfg.account_id,
        status_extended="No ActionTrail trails deliver to OSS buckets.",
        compliance_frameworks=FW)]


# ───────────────────────────────────────────────────────────────
# 2.3 - 2.23 -- Manual logging/monitoring controls
# ───────────────────────────────────────────────────────────────

def evaluate_cis_2_3(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.3", "ali_cis_2_3",
        "Ensure audit logs for multiple cloud resources are integrated with Log Service",
        "logging", "high", cfg.account_id,
        "Requires verifying that cloud resource audit logs (RDS, SLB, OSS, etc.) are "
        "integrated with Alibaba Cloud Log Service.")]


def evaluate_cis_2_4(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.4", "ali_cis_2_4",
        "Ensure Log Service is enabled for Container Service for Kubernetes",
        "logging", "high", cfg.account_id,
        "Requires verifying that ACK cluster logging is configured in Log Service.")]


def evaluate_cis_2_5(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.5", "ali_cis_2_5",
        "Ensure virtual network flow log service is enabled",
        "logging", "high", cfg.account_id,
        "Requires verifying VPC flow logs are enabled and delivered to Log Service.")]


def evaluate_cis_2_6(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.6", "ali_cis_2_6",
        "Ensure Anti-DDoS access and security log service is enabled",
        "logging", "medium", cfg.account_id,
        "Requires verifying Anti-DDoS log analysis is enabled in Security Center.")]


def evaluate_cis_2_7(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.7", "ali_cis_2_7",
        "Ensure WAF access and security log service is enabled",
        "logging", "high", cfg.account_id,
        "Requires verifying WAF log analysis is enabled and integrated with Log Service.")]


def evaluate_cis_2_8(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.8", "ali_cis_2_8",
        "Ensure Cloud Firewall access and security log analysis is enabled",
        "logging", "high", cfg.account_id,
        "Requires verifying Cloud Firewall log analysis in Log Service.")]


def evaluate_cis_2_9(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.9", "ali_cis_2_9",
        "Ensure Security Center Network, Host and Security log analysis is enabled",
        "logging", "high", cfg.account_id,
        "Requires verifying Security Center log collection in Log Service.")]


def evaluate_cis_2_10(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.10", "ali_cis_2_10",
        "Ensure log monitoring and alerts are set up for RAM Role changes",
        "logging", "medium", cfg.account_id,
        "Requires configuring SLS alerts for RAM role modification events in ActionTrail.")]


def evaluate_cis_2_11(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.11", "ali_cis_2_11",
        "Ensure log monitoring and alerts are set up for Cloud Firewall changes",
        "logging", "high", cfg.account_id,
        "Requires configuring SLS alerts for Cloud Firewall configuration events.")]


def evaluate_cis_2_12(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.12", "ali_cis_2_12",
        "Ensure log monitoring and alerts are set up for VPC network route changes",
        "logging", "medium", cfg.account_id,
        "Requires configuring SLS alerts for VPC route table modification events.")]


def evaluate_cis_2_13(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.13", "ali_cis_2_13",
        "Ensure log monitoring and alerts are set up for VPC changes",
        "logging", "medium", cfg.account_id,
        "Requires configuring SLS alerts for VPC creation/deletion events.")]


def evaluate_cis_2_14(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.14", "ali_cis_2_14",
        "Ensure log monitoring and alerts are set up for OSS permission changes",
        "logging", "medium", cfg.account_id,
        "Requires configuring SLS alerts for OSS bucket ACL/policy modification events.")]


def evaluate_cis_2_15(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.15", "ali_cis_2_15",
        "Ensure log monitoring and alerts are set up for RDS instance config changes",
        "logging", "medium", cfg.account_id,
        "Requires configuring SLS alerts for RDS instance configuration modification events.")]


def evaluate_cis_2_16(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.16", "ali_cis_2_16",
        "Ensure log monitoring and alerts are set up for unauthorized API calls",
        "logging", "medium", cfg.account_id,
        "Requires configuring SLS alerts for API calls returning authorization errors.")]


def evaluate_cis_2_17(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.17", "ali_cis_2_17",
        "Ensure log monitoring and alerts for Console sign-in without MFA",
        "logging", "high", cfg.account_id,
        "Requires configuring SLS alerts for console sign-in events without MFA.")]


def evaluate_cis_2_18(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.18", "ali_cis_2_18",
        "Ensure log monitoring and alerts for usage of 'root' account",
        "logging", "critical", cfg.account_id,
        "Requires configuring SLS alerts for root account activity in ActionTrail.")]


def evaluate_cis_2_19(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.19", "ali_cis_2_19",
        "Ensure log monitoring and alerts for Console authentication failures",
        "logging", "medium", cfg.account_id,
        "Requires configuring SLS alerts for failed console authentication events.")]


def evaluate_cis_2_20(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.20", "ali_cis_2_20",
        "Ensure log monitoring and alerts for disabling or deletion of customer-created CMK",
        "logging", "medium", cfg.account_id,
        "Requires configuring SLS alerts for KMS key disable/delete events.")]


def evaluate_cis_2_21(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.21", "ali_cis_2_21",
        "Ensure log monitoring and alerts for OSS bucket policy changes",
        "logging", "medium", cfg.account_id,
        "Requires configuring SLS alerts for OSS bucket policy modification events.")]


def evaluate_cis_2_22(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.22", "ali_cis_2_22",
        "Ensure log monitoring and alerts for security group changes",
        "logging", "high", cfg.account_id,
        "Requires configuring SLS alerts for security group modification events.")]


def evaluate_cis_2_23(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("2.23", "ali_cis_2_23",
        "Ensure that Logstore data retention period is set 365 days or greater",
        "logging", "high", cfg.account_id,
        "Requires verifying Log Service logstore retention (TTL) settings.")]


# ═══════════════════════════════════════════════════════════════════
# Section 3: Networking (5 controls — all manual)
# ═══════════════════════════════════════════════════════════════════

def evaluate_cis_3_1(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("3.1", "ali_cis_3_1",
        "Ensure legacy networks do not exist",
        "networking", "medium", cfg.account_id,
        "Requires verifying that no classic network resources remain. "
        "All resources should use VPC networking.")]


def evaluate_cis_3_2(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("3.2", "ali_cis_3_2",
        "Ensure that SSH access is restricted from the internet",
        "networking", "critical", cfg.account_id,
        "Requires reviewing security group rules to ensure no rule allows "
        "0.0.0.0/0 or ::/0 ingress on port 22.")]


def evaluate_cis_3_3(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("3.3", "ali_cis_3_3",
        "Ensure VPC flow logging is enabled in all VPCs",
        "networking", "high", cfg.account_id,
        "Requires verifying that flow logs are enabled for all VPCs and delivered to SLS.")]


def evaluate_cis_3_4(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("3.4", "ali_cis_3_4",
        "Ensure routing tables for VPC peering are 'least access'",
        "networking", "medium", cfg.account_id,
        "Requires reviewing VPC peering route table entries for overly permissive routing.")]


def evaluate_cis_3_5(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("3.5", "ali_cis_3_5",
        "Ensure the security groups are configured with fine grained rules",
        "networking", "high", cfg.account_id,
        "Requires reviewing security group rules for overly permissive CIDR ranges and ports.")]


# ═══════════════════════════════════════════════════════════════════
# Section 4: Virtual Machines (6 controls — all manual)
# ═══════════════════════════════════════════════════════════════════

def evaluate_cis_4_1(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("4.1", "ali_cis_4_1",
        "Ensure that 'Unattached disks' are encrypted",
        "compute", "high", cfg.account_id,
        "Requires checking that all unattached ECS cloud disks have encryption enabled.")]


def evaluate_cis_4_2(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("4.2", "ali_cis_4_2",
        "Ensure that 'Virtual Machine's disk' are encrypted",
        "compute", "high", cfg.account_id,
        "Requires verifying that all ECS instance disks (system + data) have encryption enabled.")]


def evaluate_cis_4_3(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("4.3", "ali_cis_4_3",
        "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        "compute", "critical", cfg.account_id,
        "Requires reviewing all security group rules for unrestricted SSH access.")]


def evaluate_cis_4_4(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("4.4", "ali_cis_4_4",
        "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
        "compute", "critical", cfg.account_id,
        "Requires reviewing all security group rules for unrestricted RDP access.")]


def evaluate_cis_4_5(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("4.5", "ali_cis_4_5",
        "Ensure that the latest OS Patches for all Virtual Machines are applied",
        "compute", "medium", cfg.account_id,
        "Requires verifying that ECS instances have the latest OS patches. "
        "Check via Security Center vulnerability scan.")]


def evaluate_cis_4_6(c: AlibabaClientCache, cfg: EvalConfig) -> list[dict]:
    return [make_manual_result("4.6", "ali_cis_4_6",
        "Ensure that endpoint protection for all Virtual Machines is installed",
        "compute", "medium", cfg.account_id,
        "Requires verifying Security Center agent is installed on all ECS instances.")]
