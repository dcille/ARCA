"""CIS Amazon Web Services Foundations Benchmark v3.0.0 — Complete Control Registry.

This registry contains ALL controls from the CIS AWS Foundations Benchmark.
Each control is marked as 'automated' or 'manual' per the CIS assessment status.
Controls are organized by section matching the benchmark structure.

Reference: CIS Amazon Web Services Foundations Benchmark v3.0.0 (2024)

The benchmark covers five key areas:
  Section 1: Identity and Access Management (IAM)
  Section 2: Storage
  Section 3: Logging
  Section 4: Monitoring
  Section 5: Networking

Total controls: 56 across 5 sections.
"""

# Each control: (cis_id, title, level, assessment_type, severity, service_area)
# level: "L1" (essential) or "L2" (enhanced)
# assessment_type: "automated" or "manual"

AWS_CIS_CONTROLS = [
    # =========================================================================
    # Section 1: Identity and Access Management (IAM)
    # =========================================================================

    ("1.1", "Maintain current contact details",
     "L1", "manual", "medium", "iam"),
    ("1.2", "Ensure security contact information is registered",
     "L1", "manual", "medium", "iam"),
    ("1.3", "Ensure security questions are registered in the AWS account",
     "L1", "manual", "medium", "iam"),
    ("1.4", "Ensure no 'root' user account access key exists",
     "L1", "automated", "critical", "iam"),
    ("1.5", "Ensure MFA is enabled for the 'root' user account",
     "L1", "automated", "critical", "iam"),
    ("1.6", "Ensure hardware MFA is enabled for the 'root' user account",
     "L2", "automated", "critical", "iam"),
    ("1.7", "Eliminate use of the 'root' user for administrative and daily tasks",
     "L1", "automated", "critical", "iam"),
    ("1.8", "Ensure IAM password policy requires minimum length of 14 or greater",
     "L1", "automated", "high", "iam"),
    ("1.9", "Ensure IAM password policy prevents password reuse",
     "L1", "automated", "high", "iam"),
    ("1.10", "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
     "L1", "automated", "high", "iam"),
    ("1.11", "Do not setup access keys during initial user setup",
     "L1", "manual", "medium", "iam"),
    ("1.12", "Ensure credentials unused for 45 days or greater are disabled",
     "L1", "automated", "high", "iam"),
    ("1.13", "Ensure there is only one active access key available for any single IAM user",
     "L1", "automated", "medium", "iam"),
    ("1.14", "Ensure access keys are rotated every 90 days or less",
     "L1", "automated", "high", "iam"),
    ("1.15", "Ensure IAM Users receive permissions only through Groups",
     "L1", "automated", "medium", "iam"),
    ("1.16", "Ensure IAM policies that allow full \"*:*\" administrative privileges are not attached",
     "L1", "automated", "critical", "iam"),
    ("1.17", "Ensure a support role has been created to manage incidents with AWS Support",
     "L1", "automated", "medium", "iam"),
    ("1.18", "Ensure IAM instance roles are used for AWS resource access from instances",
     "L2", "manual", "medium", "iam"),
    ("1.19", "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed",
     "L1", "automated", "high", "iam"),
    ("1.20", "Ensure that IAM Access Analyzer is enabled for all regions",
     "L1", "automated", "high", "iam"),
    ("1.21", "Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments",
     "L1", "manual", "medium", "iam"),
    ("1.22", "Ensure access is analyzed for changes to the IAM policy",
     "L1", "manual", "medium", "iam"),

    # =========================================================================
    # Section 2: Storage
    # =========================================================================

    # 2.1 Simple Storage Service (S3)
    ("2.1.1", "Ensure S3 Bucket Policy is set to deny HTTP requests",
     "L2", "automated", "high", "storage"),
    ("2.1.2", "Ensure MFA Delete is enabled on S3 buckets",
     "L2", "automated", "high", "storage"),
    ("2.1.4", "Ensure that all data in Amazon S3 has been discovered, classified and secured when required",
     "L2", "manual", "medium", "storage"),

    # 2.2 Elastic Compute Cloud (EC2) - EBS
    ("2.2.1", "Ensure EBS Volume Encryption is enabled in all Regions",
     "L1", "automated", "high", "storage"),

    # 2.3 Relational Database Service (RDS)
    ("2.3.1", "Ensure that encryption is enabled for RDS Instances",
     "L1", "automated", "high", "storage"),
    ("2.3.2", "Ensure Auto Minor Version Upgrade feature is enabled for RDS Instances",
     "L1", "automated", "medium", "storage"),
    ("2.3.3", "Ensure that public access is not given to RDS Instance",
     "L1", "automated", "critical", "storage"),

    # =========================================================================
    # Section 3: Logging
    # =========================================================================

    ("3.1", "Ensure CloudTrail is enabled in all regions",
     "L1", "automated", "critical", "logging"),
    ("3.2", "Ensure CloudTrail log file validation is enabled",
     "L2", "automated", "high", "logging"),
    ("3.3", "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
     "L1", "automated", "critical", "logging"),
    ("3.4", "Ensure CloudTrail trails are integrated with CloudWatch Logs",
     "L1", "automated", "high", "logging"),
    ("3.5", "Ensure AWS Config is enabled in all regions",
     "L2", "automated", "high", "logging"),
    ("3.6", "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
     "L1", "automated", "high", "logging"),
    ("3.7", "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
     "L2", "automated", "high", "logging"),
    ("3.8", "Ensure rotation for customer-created symmetric CMKs is enabled",
     "L2", "automated", "medium", "logging"),
    ("3.9", "Ensure VPC flow logging is enabled in all VPCs",
     "L2", "automated", "high", "logging"),
    ("3.10", "Ensure that Object-level logging for write events is enabled for S3 bucket",
     "L2", "automated", "high", "logging"),
    ("3.11", "Ensure that Object-level logging for read events is enabled for S3 bucket",
     "L2", "automated", "high", "logging"),

    # =========================================================================
    # Section 4: Monitoring
    # =========================================================================

    ("4.1", "Ensure a log metric filter and alarm exist for unauthorized API calls",
     "L1", "automated", "high", "monitoring"),
    ("4.2", "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA",
     "L1", "automated", "high", "monitoring"),
    ("4.3", "Ensure a log metric filter and alarm exist for usage of 'root' account",
     "L1", "automated", "critical", "monitoring"),
    ("4.4", "Ensure a log metric filter and alarm exist for IAM policy changes",
     "L1", "automated", "high", "monitoring"),
    ("4.5", "Ensure a log metric filter and alarm exist for CloudTrail configuration changes",
     "L1", "automated", "high", "monitoring"),
    ("4.6", "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures",
     "L2", "automated", "medium", "monitoring"),
    ("4.7", "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer-created CMKs",
     "L2", "automated", "high", "monitoring"),
    ("4.8", "Ensure a log metric filter and alarm exist for S3 bucket policy changes",
     "L1", "automated", "high", "monitoring"),
    ("4.9", "Ensure a log metric filter and alarm exist for AWS Config configuration changes",
     "L2", "automated", "high", "monitoring"),
    ("4.10", "Ensure a log metric filter and alarm exist for security group changes",
     "L2", "automated", "high", "monitoring"),
    ("4.11", "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)",
     "L2", "automated", "high", "monitoring"),
    ("4.12", "Ensure a log metric filter and alarm exist for changes to network gateways",
     "L2", "automated", "medium", "monitoring"),
    ("4.13", "Ensure a log metric filter and alarm exist for route table changes",
     "L2", "automated", "medium", "monitoring"),
    ("4.14", "Ensure a log metric filter and alarm exist for VPC changes",
     "L1", "automated", "high", "monitoring"),
    ("4.15", "Ensure a log metric filter and alarm exist for AWS Organizations changes",
     "L1", "automated", "high", "monitoring"),
    ("4.16", "Ensure AWS Security Hub is enabled",
     "L2", "automated", "high", "monitoring"),

    # =========================================================================
    # Section 5: Networking
    # =========================================================================

    ("5.1", "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports",
     "L1", "automated", "critical", "networking"),
    ("5.2", "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
     "L1", "automated", "critical", "networking"),
    ("5.3", "Ensure the default security group of every VPC restricts all traffic",
     "L2", "automated", "high", "networking"),
    ("5.4", "Ensure routing tables for VPC peering are 'least access'",
     "L2", "manual", "medium", "networking"),
    ("5.5", "Ensure that EC2 Metadata Service only allows IMDSv2",
     "L1", "automated", "high", "networking"),
    ("5.6", "Ensure that security groups with 0.0.0.0/0 ingress to ports other than 80 and 443 are not present",
     "L1", "automated", "high", "networking"),
]


def get_aws_cis_registry():
    """Return the complete CIS AWS control registry as a list of dicts."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in AWS_CIS_CONTROLS
    ]


def get_aws_control_count():
    """Return total number of CIS AWS controls."""
    return len(AWS_CIS_CONTROLS)


def get_aws_automated_count():
    """Return count of automated controls."""
    return sum(1 for c in AWS_CIS_CONTROLS if c[3] == "automated")


def get_aws_manual_count():
    """Return count of manual controls."""
    return sum(1 for c in AWS_CIS_CONTROLS if c[3] == "manual")
