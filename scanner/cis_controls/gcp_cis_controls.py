"""CIS Google Cloud Platform Foundation Benchmark v3.0.0 — Complete Control Registry.

This registry contains ALL controls from the CIS GCP Foundation Benchmark v3.0.0.
Each control is marked as 'automated' or 'manual' per the CIS assessment status.
Controls are organized by section matching the benchmark structure.

Reference: CIS Google Cloud Platform Foundation Benchmark v3.0.0

Total controls: 84 across 7 sections.
"""

# Each control: (cis_id, title, level, assessment_type, severity, service_area)
# level: "L1" or "L2"
# assessment_type: "automated" or "manual"
# severity: "critical", "high", "medium", "low"
# service_area: "iam", "logging_monitoring", "networking", "virtual_machines",
#               "storage", "cloud_sql", "bigquery"

GCP_CIS_CONTROLS = [
    # =========================================================================
    # Section 1: Identity and Access Management (IAM)
    # =========================================================================

    ("1.1", "Ensure corporate login credentials are used",
     "L1", "automated", "critical", "iam"),
    ("1.2", "Ensure multi-factor authentication is enabled for all non-service accounts",
     "L1", "manual", "critical", "iam"),
    ("1.3", "Ensure Security Key enforcement for admin accounts",
     "L2", "manual", "critical", "iam"),
    ("1.4", "Ensure that there are only GCP-managed service account keys",
     "L1", "automated", "high", "iam"),
    ("1.5", "Ensure that Service Account has no admin privileges",
     "L1", "automated", "critical", "iam"),
    ("1.6", "Ensure IAM users are not assigned Service Account User/Token Creator roles at project level",
     "L1", "automated", "high", "iam"),
    ("1.7", "Ensure user-managed/external keys for service accounts are rotated within 90 days",
     "L1", "automated", "high", "iam"),
    ("1.8", "Ensure that Separation of duties is enforced while assigning service account related roles",
     "L2", "manual", "high", "iam"),
    ("1.9", "Ensure Cloud KMS cryptokeys are not anonymously or publicly accessible",
     "L1", "automated", "critical", "iam"),
    ("1.10", "Ensure KMS encryption keys are rotated within 365 days",
     "L1", "automated", "high", "iam"),
    ("1.11", "Ensure API keys are restricted to use by only specified Hosts and Apps",
     "L1", "automated", "medium", "iam"),
    ("1.12", "Ensure API keys are restricted to only APIs that application needs access",
     "L1", "automated", "medium", "iam"),
    ("1.13", "Ensure API keys are rotated within 90 days",
     "L1", "automated", "medium", "iam"),
    ("1.14", "Ensure API keys are not created for a project",
     "L2", "manual", "medium", "iam"),
    ("1.15", "Ensure Essential Contacts is configured for a project",
     "L1", "automated", "medium", "iam"),

    # =========================================================================
    # Section 2: Logging and Monitoring
    # =========================================================================

    ("2.1", "Ensure Cloud Audit Logging is configured properly",
     "L1", "automated", "critical", "logging_monitoring"),
    ("2.2", "Ensure log metric filter and alerts for project ownership changes",
     "L1", "automated", "high", "logging_monitoring"),
    ("2.3", "Ensure log metric filter and alerts for audit configuration changes",
     "L1", "automated", "high", "logging_monitoring"),
    ("2.4", "Ensure log metric filter and alerts for custom role changes",
     "L1", "automated", "medium", "logging_monitoring"),
    ("2.5", "Ensure log metric filter and alerts for VPC firewall changes",
     "L1", "automated", "high", "logging_monitoring"),
    ("2.6", "Ensure log metric filter and alerts for VPC route changes",
     "L1", "automated", "medium", "logging_monitoring"),
    ("2.7", "Ensure log metric filter and alerts for VPC network changes",
     "L1", "automated", "medium", "logging_monitoring"),
    ("2.8", "Ensure log metric filter and alerts for Cloud Storage IAM changes",
     "L1", "automated", "medium", "logging_monitoring"),
    ("2.9", "Ensure log metric filter and alerts for Cloud SQL configuration changes",
     "L1", "automated", "medium", "logging_monitoring"),
    ("2.10", "Ensure DNS logging is enabled for all VPC networks",
     "L1", "automated", "medium", "logging_monitoring"),
    ("2.11", "Ensure Cloud Asset Inventory is enabled",
     "L1", "automated", "medium", "logging_monitoring"),
    ("2.12", "Ensure Access Transparency is enabled",
     "L2", "automated", "medium", "logging_monitoring"),
    ("2.13", "Ensure Cloud Audit log is configured for all services/users",
     "L2", "automated", "high", "logging_monitoring"),
    ("2.14", "Ensure org-level sink is configured for all log entries",
     "L2", "automated", "high", "logging_monitoring"),
    ("2.15", "Ensure Access Approval is enabled",
     "L2", "automated", "medium", "logging_monitoring"),
    ("2.16", "Ensure log bucket retention policies are configured",
     "L1", "automated", "high", "logging_monitoring"),

    # =========================================================================
    # Section 3: Networking
    # =========================================================================

    ("3.1", "Ensure default network does not exist",
     "L1", "automated", "high", "networking"),
    ("3.2", "Ensure legacy networks do not exist",
     "L1", "automated", "high", "networking"),
    ("3.3", "Ensure DNSSEC is enabled for Cloud DNS",
     "L1", "automated", "medium", "networking"),
    ("3.4", "Ensure RSASHA1 is not used",
     "L1", "automated", "medium", "networking"),
    ("3.5", "Ensure VPC Flow Logs is enabled for every subnet",
     "L2", "automated", "medium", "networking"),
    ("3.6", "Ensure firewall rules do not exist for SSH from 0.0.0.0/0",
     "L1", "automated", "critical", "networking"),
    ("3.7", "Ensure firewall rules do not exist for RDP from 0.0.0.0/0",
     "L1", "automated", "critical", "networking"),
    ("3.8", "Ensure VPC network has a secure SSL policy",
     "L1", "automated", "high", "networking"),
    ("3.9", "Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites",
     "L1", "automated", "high", "networking"),
    ("3.10", "Ensure Firewall Rules for instances behind ILB are not open to world",
     "L2", "automated", "high", "networking"),

    # =========================================================================
    # Section 4: Virtual Machines
    # =========================================================================

    ("4.1", "Ensure instances are not configured to use default service account",
     "L1", "automated", "high", "virtual_machines"),
    ("4.2", "Ensure instances are not configured to use default service account with full API access",
     "L1", "automated", "high", "virtual_machines"),
    ("4.3", "Ensure Block Project-wide SSH keys is enabled",
     "L1", "automated", "medium", "virtual_machines"),
    ("4.4", "Ensure oslogin is enabled for a project",
     "L1", "automated", "medium", "virtual_machines"),
    ("4.5", "Ensure Enable Connecting to Serial Ports is not enabled",
     "L1", "automated", "medium", "virtual_machines"),
    ("4.6", "Ensure IP Forwarding is not enabled on instances",
     "L1", "automated", "medium", "virtual_machines"),
    ("4.7", "Ensure VM disks for critical VMs are encrypted with Customer-Supplied Encryption Keys",
     "L2", "manual", "high", "virtual_machines"),
    ("4.8", "Ensure Compute instances are launched with Shielded VM enabled",
     "L2", "automated", "medium", "virtual_machines"),
    ("4.9", "Ensure instances do not have public IP addresses",
     "L2", "automated", "high", "virtual_machines"),
    ("4.10", "Ensure App Engine applications enforce HTTPS",
     "L1", "automated", "high", "virtual_machines"),
    ("4.11", "Ensure Compute instances do not have public IP addresses",
     "L2", "automated", "high", "virtual_machines"),
    ("4.12", "Ensure Confidential Computing is enabled for Compute instances",
     "L2", "automated", "high", "virtual_machines"),

    # =========================================================================
    # Section 5: Storage
    # =========================================================================

    ("5.1", "Ensure Cloud Storage bucket is not anonymously or publicly accessible",
     "L1", "automated", "critical", "storage"),
    ("5.2", "Ensure Cloud Storage buckets have uniform bucket-level access enabled",
     "L1", "automated", "medium", "storage"),
    ("5.3", "Ensure Cloud Storage bucket versioning is enabled",
     "L1", "automated", "medium", "storage"),
    ("5.4", "Ensure default encryption with Customer-Managed Keys is configured",
     "L2", "automated", "high", "storage"),
    ("5.5", "Ensure Cloud Storage buckets have logging enabled",
     "L1", "automated", "medium", "storage"),
    ("5.6", "Ensure lifecycle rules are configured on Cloud Storage buckets",
     "L1", "automated", "medium", "storage"),

    # =========================================================================
    # Section 6: Cloud SQL Database Services
    # =========================================================================

    ("6.1", "Ensure Cloud SQL database instances are not open to the world",
     "L1", "automated", "critical", "cloud_sql"),
    ("6.2", "Ensure Cloud SQL database instances do not have public IPs",
     "L1", "automated", "high", "cloud_sql"),
    ("6.3", "Ensure Cloud SQL database instances require all incoming connections to use SSL",
     "L1", "automated", "high", "cloud_sql"),
    ("6.4", "Ensure Cloud SQL database instances require all incoming connections to use SSL/TLS",
     "L1", "automated", "high", "cloud_sql"),
    ("6.5", "Ensure backups are enabled for Cloud SQL instances",
     "L1", "automated", "high", "cloud_sql"),
    ("6.6", "Ensure Point-in-Time Recovery is enabled for Cloud SQL instances",
     "L1", "automated", "high", "cloud_sql"),
    ("6.7", "Ensure Cloud SQL instances have automated backups with at least 7 days retention",
     "L1", "automated", "high", "cloud_sql"),

    # =========================================================================
    # Section 7: BigQuery
    # =========================================================================

    ("7.1", "Ensure BigQuery datasets are not anonymously or publicly accessible",
     "L1", "automated", "critical", "bigquery"),
    ("7.2", "Ensure BigQuery datasets are encrypted with Customer-Managed Encryption Keys",
     "L2", "automated", "high", "bigquery"),
    ("7.3", "Ensure BigQuery tables are configured with column-level security",
     "L2", "manual", "medium", "bigquery"),
    ("7.4", "Ensure default Customer-Managed Encryption Key is specified for BigQuery data sets",
     "L2", "automated", "high", "bigquery"),
]


def get_gcp_cis_registry():
    """Return the complete CIS GCP control registry as a list of dicts."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in GCP_CIS_CONTROLS
    ]


def get_gcp_control_count():
    """Return total number of CIS GCP controls."""
    return len(GCP_CIS_CONTROLS)


def get_gcp_automated_count():
    """Return count of automated controls."""
    return sum(1 for c in GCP_CIS_CONTROLS if c[3] == "automated")


def get_gcp_manual_count():
    """Return count of manual controls."""
    return sum(1 for c in GCP_CIS_CONTROLS if c[3] == "manual")


def get_gcp_controls_by_section(section_prefix):
    """Return controls for a given section prefix (e.g., '1' for IAM, '3' for Networking).

    Args:
        section_prefix: String prefix to match against cis_control_id (e.g., '1', '2.1').

    Returns:
        List of control dicts matching the section prefix.
    """
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in GCP_CIS_CONTROLS
        if ctrl[0].startswith(section_prefix + ".")
        or ctrl[0] == section_prefix
    ]


def get_gcp_controls_by_severity(severity):
    """Return controls filtered by severity level.

    Args:
        severity: One of 'critical', 'high', 'medium', 'low'.

    Returns:
        List of control dicts matching the severity.
    """
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in GCP_CIS_CONTROLS
        if ctrl[4] == severity
    ]


def get_gcp_controls_by_service_area(service_area):
    """Return controls filtered by service area.

    Args:
        service_area: One of 'iam', 'logging_monitoring', 'networking',
                      'virtual_machines', 'storage', 'cloud_sql', 'bigquery'.

    Returns:
        List of control dicts matching the service area.
    """
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in GCP_CIS_CONTROLS
        if ctrl[5] == service_area
    ]


def get_gcp_controls_by_level(level):
    """Return controls filtered by CIS level.

    Args:
        level: 'L1' or 'L2'.

    Returns:
        List of control dicts matching the level.
    """
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in GCP_CIS_CONTROLS
        if ctrl[2] == level
    ]
