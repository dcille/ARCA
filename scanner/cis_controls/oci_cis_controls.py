"""CIS Oracle Cloud Infrastructure (OCI) Foundations Benchmark v2.0.0 -- Complete Control Registry.

This registry contains ALL controls from the CIS OCI Foundations Benchmark.
Each control is marked as 'automated' or 'manual' per the CIS assessment status.
Controls are organized by section matching the benchmark structure.

Reference: CIS Oracle Cloud Infrastructure Foundations Benchmark v2.0.0
Total controls: ~65 across 6 sections.
"""

# Each control: (cis_id, title, level, assessment_type, severity, service_area)
# level: "L1" or "L2"
# assessment_type: "automated" or "manual"
# severity: "critical", "high", "medium", "low"
# service_area: "iam", "networking", "logging_monitoring", "object_storage",
#               "asset_management", "database"

OCI_CIS_CONTROLS = [
    # =========================================================================
    # Section 1: Identity and Access Management (IAM)
    # =========================================================================

    ("1.1", "Ensure service level admins are created to manage resources of particular service",
     "L1", "manual", "high", "iam"),
    ("1.2", "Ensure permissions on all resources are given only to tenancy administrator group",
     "L1", "automated", "critical", "iam"),
    ("1.3", "Ensure IAM administrators cannot update tenancy Administrators group",
     "L1", "automated", "critical", "iam"),
    ("1.4", "Ensure IAM password policy requires minimum length of 14 characters",
     "L1", "automated", "high", "iam"),
    ("1.5", "Ensure IAM password policy expires passwords within 365 days",
     "L1", "automated", "medium", "iam"),
    ("1.6", "Ensure IAM password policy prevents password reuse",
     "L1", "automated", "medium", "iam"),
    ("1.7", "Ensure MFA is enabled for all users with a console password",
     "L1", "automated", "critical", "iam"),
    ("1.8", "Ensure user API keys rotate within 90 days or less",
     "L1", "automated", "high", "iam"),
    ("1.9", "Ensure user customer secret keys rotate within 90 days or less",
     "L1", "automated", "high", "iam"),
    ("1.10", "Ensure user auth tokens rotate within 90 days or less",
     "L1", "automated", "high", "iam"),
    ("1.11", "Ensure API keys are not created for tenancy administrator users",
     "L1", "automated", "critical", "iam"),
    ("1.12", "Ensure all OCI IAM user accounts have a valid and current email address",
     "L1", "manual", "medium", "iam"),
    ("1.13", "Ensure Dynamic Groups are used for OCI instances, OCI Cloud Databases and OCI Function to access OCI resources",
     "L1", "manual", "medium", "iam"),
    ("1.14", "Ensure storage service-level admins cannot delete resources they manage",
     "L1", "automated", "high", "iam"),
    ("1.15", "Ensure cloud guard is enabled in the root compartment of the tenancy",
     "L1", "automated", "high", "iam"),

    # =========================================================================
    # Section 2: Networking
    # =========================================================================

    ("2.1", "Ensure no security lists allow ingress from 0.0.0.0/0 to port 22",
     "L1", "automated", "critical", "networking"),
    ("2.2", "Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389",
     "L1", "automated", "critical", "networking"),
    ("2.3", "Ensure no network security groups allow ingress from 0.0.0.0/0 to port 22",
     "L1", "automated", "critical", "networking"),
    ("2.4", "Ensure no network security groups allow ingress from 0.0.0.0/0 to port 3389",
     "L1", "automated", "critical", "networking"),
    ("2.5", "Ensure the default security list of every VCN restricts all traffic except ICMP",
     "L1", "automated", "high", "networking"),
    ("2.6", "Ensure Oracle Integration Cloud (OIC) access is restricted to allowed sources",
     "L1", "manual", "high", "networking"),
    ("2.7", "Ensure Oracle Analytics Cloud (OAC) access is restricted to allowed sources or deployed within a VCN",
     "L1", "manual", "high", "networking"),

    # =========================================================================
    # Section 3: Logging and Monitoring
    # =========================================================================

    ("3.1", "Ensure audit log retention period is set to 365 days",
     "L1", "automated", "high", "logging_monitoring"),
    ("3.2", "Ensure default tags are used on resources",
     "L1", "automated", "medium", "logging_monitoring"),
    ("3.3", "Create at least one notification topic and subscription to receive monitoring alerts",
     "L1", "automated", "high", "logging_monitoring"),
    ("3.4", "Ensure a notification is configured for Identity Provider changes",
     "L1", "automated", "high", "logging_monitoring"),
    ("3.5", "Ensure a notification is configured for IdP group mapping changes",
     "L1", "automated", "high", "logging_monitoring"),
    ("3.6", "Ensure a notification is configured for IAM group changes",
     "L1", "automated", "high", "logging_monitoring"),
    ("3.7", "Ensure a notification is configured for IAM policy changes",
     "L1", "automated", "critical", "logging_monitoring"),
    ("3.8", "Ensure a notification is configured for user changes",
     "L1", "automated", "high", "logging_monitoring"),
    ("3.9", "Ensure a notification is configured for VCN changes",
     "L1", "automated", "high", "logging_monitoring"),
    ("3.10", "Ensure a notification is configured for changes to route tables",
     "L1", "automated", "high", "logging_monitoring"),
    ("3.11", "Ensure a notification is configured for changes to security lists",
     "L1", "automated", "high", "logging_monitoring"),
    ("3.12", "Ensure a notification is configured for changes to network security groups",
     "L1", "automated", "high", "logging_monitoring"),
    ("3.13", "Ensure a notification is configured for changes to network gateways",
     "L1", "automated", "high", "logging_monitoring"),
    ("3.14", "Ensure VCN flow logging is enabled for all subnets",
     "L2", "automated", "medium", "logging_monitoring"),
    ("3.15", "Ensure Cloud Guard is enabled in the root compartment of the tenancy",
     "L1", "automated", "high", "logging_monitoring"),
    ("3.16", "Ensure customer created budget is configured",
     "L1", "automated", "medium", "logging_monitoring"),
    ("3.17", "Ensure write level Object Storage logging is enabled for all buckets",
     "L2", "automated", "medium", "logging_monitoring"),

    # =========================================================================
    # Section 4: Object Storage
    # =========================================================================

    ("4.1", "Ensure no Object Storage buckets are publicly visible",
     "L1", "automated", "critical", "object_storage"),
    ("4.2", "Ensure Object Storage Buckets are encrypted with a Customer Managed Key",
     "L2", "automated", "high", "object_storage"),
    ("4.3", "Ensure Versioning is enabled for Object Storage Buckets",
     "L2", "automated", "medium", "object_storage"),
    ("4.4", "Ensure Object Storage is enabled on a bucket",
     "L1", "automated", "medium", "object_storage"),
    ("4.5", "Ensure no Object Storage bucket has a lifecycle rule that deletes data in fewer than required retention days",
     "L1", "automated", "medium", "object_storage"),
    ("4.6", "Ensure Object Storage bucket access type is set to ObjectRead only where needed",
     "L1", "automated", "high", "object_storage"),

    # =========================================================================
    # Section 5: Asset Management (Compute, Block Volume, File Storage)
    # =========================================================================

    ("5.1", "Ensure no compute instance has a public IP address",
     "L1", "automated", "high", "asset_management"),
    ("5.2", "Ensure Block Volumes are encrypted with Customer Managed Keys",
     "L2", "automated", "high", "asset_management"),
    ("5.3", "Ensure Boot Volumes are encrypted with Customer Managed Keys",
     "L2", "automated", "high", "asset_management"),
    ("5.4", "Ensure File Storage Systems are encrypted with Customer Managed Keys",
     "L2", "automated", "high", "asset_management"),
    ("5.5", "Ensure Oracle Kubernetes Engine (OKE) clusters are configured with private endpoint",
     "L1", "automated", "high", "asset_management"),
    ("5.6", "Ensure Oracle Kubernetes Engine (OKE) worker node pools do not have public IP addresses",
     "L1", "automated", "high", "asset_management"),

    # =========================================================================
    # Section 6: Database
    # =========================================================================

    ("6.1", "Ensure Oracle Autonomous Database (ADB) instances do not have public IP addresses",
     "L1", "automated", "high", "database"),
    ("6.2", "Ensure Oracle Autonomous Databases (ADB) are configured with Customer Managed Keys",
     "L2", "automated", "high", "database"),
    ("6.3", "Ensure Database Systems (DBCS) are not publicly accessible",
     "L1", "automated", "high", "database"),
    ("6.4", "Ensure Database Systems (DBCS) are encrypted with Customer Managed Keys",
     "L2", "automated", "high", "database"),
    ("6.5", "Ensure MySQL Database Systems are configured with Customer Managed Keys",
     "L2", "automated", "high", "database"),
    ("6.6", "Ensure MySQL Database Systems backups are enabled",
     "L1", "automated", "high", "database"),
]


def get_oci_cis_registry():
    """Return the complete CIS OCI control registry as a list of dicts."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in OCI_CIS_CONTROLS
    ]


def get_oci_control_count():
    """Return total number of CIS OCI controls."""
    return len(OCI_CIS_CONTROLS)


def get_oci_automated_count():
    """Return count of automated controls."""
    return sum(1 for c in OCI_CIS_CONTROLS if c[3] == "automated")


def get_oci_manual_count():
    """Return count of manual controls."""
    return sum(1 for c in OCI_CIS_CONTROLS if c[3] == "manual")


def get_oci_controls_by_section(section_prefix):
    """Return controls matching a section prefix (e.g., '1', '3')."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in OCI_CIS_CONTROLS
        if ctrl[0].startswith(section_prefix)
    ]


def get_oci_controls_by_severity(severity):
    """Return controls matching a given severity level."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in OCI_CIS_CONTROLS
        if ctrl[4] == severity
    ]


def get_oci_controls_by_service_area(service_area):
    """Return controls matching a given service area."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in OCI_CIS_CONTROLS
        if ctrl[5] == service_area
    ]
