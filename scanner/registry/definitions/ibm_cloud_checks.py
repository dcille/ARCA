"""Check definitions for IBM Cloud.

Auto-generated from ibm_cloud scanner. 8 checks.
"""

from scanner.registry.models import CheckDefinition


def get_checks() -> list[CheckDefinition]:
    """Return all IBM Cloud check definitions."""
    return [
        CheckDefinition(
            check_id="ibm_cloud_activity_tracker_enabled",
            title="CIS 3.1 — Ensure Activity Tracker is provisioned for audit logging",
            description="CIS 3.1 — Ensure Activity Tracker is provisioned for audit logging.",
            severity="high",
            provider="ibm_cloud",
            service="activity_tracker",
            category="Compliance",
            tags=["activity_tracker"],
        ),
        CheckDefinition(
            check_id="ibm_cloud_cos_encryption",
            title="CIS 2.1 — Ensure Cloud Object Storage buckets are encrypted",
            description="CIS 2.1 — Ensure Cloud Object Storage buckets are encrypted.",
            severity="high",
            provider="ibm_cloud",
            service="cos",
            category="Compliance",
            tags=["cos", "encryption"],
        ),
        CheckDefinition(
            check_id="ibm_cloud_iam_api_key_age",
            title="CIS 1.2 — API keys unused for 180 days should be disabled",
            description="CIS 1.2 — API keys unused for 180 days should be disabled.",
            severity="high",
            provider="ibm_cloud",
            service="iam",
            category="Identity",
            tags=["iam"],
        ),
        CheckDefinition(
            check_id="ibm_cloud_iam_mfa_enabled",
            title="CIS 1.6 — Ensure MFA is enabled for all users in account",
            description="CIS 1.6 — Ensure MFA is enabled for all users in account.",
            severity="critical",
            provider="ibm_cloud",
            service="iam",
            category="Identity",
            tags=["iam", "mfa"],
        ),
        CheckDefinition(
            check_id="ibm_cloud_iam_no_owner_api_key",
            title="CIS 1.5 — Ensure no owner account API key exists",
            description="CIS 1.5 — Ensure no owner account API key exists.",
            severity="high",
            provider="ibm_cloud",
            service="iam",
            category="Identity",
            tags=["iam"],
        ),
        CheckDefinition(
            check_id="ibm_cloud_iam_no_public_access",
            title="CIS 1.18 — Ensure IAM does not allow public access to cloud services",
            description="CIS 1.18 — Ensure IAM does not allow public access to cloud services.",
            severity="critical",
            provider="ibm_cloud",
            service="iam",
            category="Identity",
            tags=["iam", "public-access"],
        ),
        CheckDefinition(
            check_id="ibm_cloud_iks_version",
            title="CIS 7.1 — Ensure IKS clusters run a supported Kubernetes version",
            description="CIS 7.1 — Ensure IKS clusters run a supported Kubernetes version.",
            severity="medium",
            provider="ibm_cloud",
            service="kubernetes",
            category="Compliance",
            tags=["kubernetes"],
        ),
        CheckDefinition(
            check_id="ibm_cloud_vpc_sg_unrestricted_ingress",
            title="CIS 6.1 — Ensure no security group allows unrestricted ingress from 0.0.0.0/0",
            description="CIS 6.1 — Ensure no security group allows unrestricted ingress from 0.0.0.0/0.",
            severity="high",
            provider="ibm_cloud",
            service="networking",
            category="Networking",
            tags=["networking", "security-group"],
        ),
    ]
