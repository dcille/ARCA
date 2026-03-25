"""CIS IBM Cloud Foundations Benchmark v1.1.0 — Control Registry.

This registry contains controls from the CIS IBM Cloud Foundations Benchmark.
Each control is marked as 'automated' or 'manual' per the CIS assessment status.
Controls are organized by section matching the benchmark structure.

Reference: CIS IBM Cloud Foundations Benchmark v1.1.0

The benchmark covers nine key areas:
  Section 1: Identity and Access Management (IAM)
  Section 2: Storage
  Section 3: Maintenance, Monitoring and Analysis of Audit Logs
  Section 4: IBM Cloud Databases Family
  Section 5: Cloudant
  Section 6: Networking
  Section 7: Containers
  Section 8: Security and Compliance
  Section 9: IBM Power Virtual Server on IBM Cloud (PowerVS)

Total controls: 44 across 9 sections (2 automated, 42 manual).

NOTE: This registry covers the controls provided from the benchmark JSON data.
The full CIS IBM Cloud Foundations Benchmark v1.1.0 may contain additional
sub-controls (particularly under Sections 2, 6, 7, and 8) that can be added
as they become available.
"""

# Each control: (cis_id, title, level, assessment_type, severity, service_area)
# level: "L1" (essential) or "L2" (enhanced)
# assessment_type: "automated" or "manual"

IBM_CLOUD_CIS_CONTROLS = [
    # =========================================================================
    # Section 1: Identity and Access Management (IAM)
    # =========================================================================

    ("1.1", "Monitor account owner for frequent, unexpected, or unauthorized logins",
     "L1", "manual", "high", "identity_and_access_management"),
    ("1.2", "Ensure API keys unused for 180 days are detected and optionally disabled",
     "L1", "manual", "high", "identity_and_access_management"),
    ("1.3", "Ensure API keys are rotated every 90 days",
     "L1", "manual", "high", "identity_and_access_management"),
    ("1.4", "Restrict user API key creation and service ID creation in the account via IAM roles",
     "L1", "manual", "high", "identity_and_access_management"),
    ("1.5", "Ensure no owner account API key exists",
     "L1", "manual", "high", "identity_and_access_management"),
    ("1.6", "Ensure multi-factor authentication (MFA) is enabled for all users in account",
     "L1", "manual", "critical", "identity_and_access_management"),
    ("1.7", "Ensure multi-factor authentication (MFA) is enabled for the account owner and all administrative users",
     "L1", "manual", "critical", "identity_and_access_management"),
    ("1.8", "Ensure multi-factor authentication (MFA) is enabled at the account level",
     "L1", "manual", "critical", "identity_and_access_management"),
    ("1.9", "Ensure contact email is valid",
     "L1", "manual", "low", "identity_and_access_management"),
    ("1.10", "Ensure contact phone number is valid",
     "L1", "manual", "low", "identity_and_access_management"),
    ("1.11", "Ensure Trusted Profiles are used in place of ServiceIDs wherever feasible",
     "L1", "manual", "medium", "identity_and_access_management"),
    ("1.12", "Ensure Context-Based Restrictions are implemented to enforce secure conditional access to critical resources",
     "L1", "manual", "high", "identity_and_access_management"),
    ("1.13", "Ensure limitations on External Identity Interactions are Enabled",
     "L1", "manual", "high", "identity_and_access_management"),
    ("1.14", "Ensure IAM users with the same level of access are members of access groups and IAM policies are assigned only to access groups or Trusted Profiles",
     "L1", "manual", "medium", "identity_and_access_management"),
    ("1.15", "Ensure a support access group has been created to manage incidents with IBM Support",
     "L1", "manual", "medium", "identity_and_access_management"),
    ("1.16", "Ensure Minimal Number of Users are Granted Administrative Privileges",
     "L1", "manual", "high", "identity_and_access_management"),
    ("1.17", "Ensure Minimal Number of Service IDs are Granted Administrative Privileges",
     "L1", "manual", "high", "identity_and_access_management"),
    ("1.18", "Ensure IAM Does Not Allow Public Access to Cloud Services",
     "L1", "manual", "critical", "identity_and_access_management"),
    ("1.19", "Ensure Inactive User Accounts are Suspended",
     "L1", "manual", "medium", "identity_and_access_management"),
    ("1.20", "Enable audit logging for IBM Cloud Identity and Access Management",
     "L1", "manual", "high", "identity_and_access_management"),

    # =========================================================================
    # Section 2: Storage
    # =========================================================================

    # 2.1 Cloud Object Storage
    ("2.1.1.1", "Ensure Cloud Object Storage encryption is done with customer managed keys",
     "L1", "manual", "high", "storage"),

    # 2.2 Block Storage for VPC
    ("2.2.1.1", "Ensure IBM Cloud Block Storage for Virtual Private Cloud is encrypted with BYOK",
     "L1", "manual", "high", "storage"),

    # =========================================================================
    # Section 3: Maintenance, Monitoring and Analysis of Audit Logs
    # =========================================================================

    ("3.1", "Ensure auditing is configured in the IBM Cloud account",
     "L1", "manual", "critical", "logging_and_monitoring"),
    ("3.2", "Ensure data retention for audit events",
     "L2", "manual", "high", "logging_and_monitoring"),
    ("3.3", "Ensure that events are collected and processed to identify anomalies or abnormal events",
     "L1", "manual", "high", "logging_and_monitoring"),
    ("3.4", "Ensure alerts are defined on custom views to notify of unauthorized requests, critical account actions, and high-impact operations",
     "L2", "manual", "high", "logging_and_monitoring"),
    ("3.5", "Ensure the account owner can login only from a list of authorized countries/IP ranges",
     "L1", "manual", "high", "logging_and_monitoring"),
    ("3.6", "Ensure Activity Tracker data is encrypted at rest",
     "L1", "manual", "high", "logging_and_monitoring"),

    # =========================================================================
    # Section 4: IBM Cloud Databases Family
    # =========================================================================

    ("4.1", "Ensure IBM Cloud Databases disk encryption is enabled with customer managed keys",
     "L1", "manual", "high", "database_services"),
    ("4.2", "Ensure network access to IBM Cloud Databases service is set to Private endpoints only",
     "L1", "manual", "high", "database_services"),
    ("4.3", "Ensure incoming connections are limited to allowed sources",
     "L1", "manual", "high", "database_services"),

    # =========================================================================
    # Section 5: Cloudant
    # =========================================================================

    ("5.1", "Ensure IBM Cloudant encryption is enabled with customer managed keys",
     "L2", "manual", "high", "cloudant"),

    # =========================================================================
    # Section 6: Networking
    # =========================================================================

    # 6.1 IBM Cloud Internet Services
    ("6.1.1", "Enable TLS 1.2 at minimum for all inbound traffic on IBM Cloud Internet Services Proxy",
     "L1", "manual", "high", "networking"),

    # 6.2 Virtual Private Cloud (VPC)
    ("6.2.1", "Ensure no VPC access control lists allow ingress from 0.0.0.0/0 to port 22",
     "L1", "manual", "high", "networking"),

    # =========================================================================
    # Section 7: Containers
    # =========================================================================

    # 7.1 Kubernetes Service
    ("7.1.1", "Ensure data in Kubernetes secrets is encrypted using a Key Management Service (KMS) provider",
     "L1", "manual", "high", "containers"),

    # =========================================================================
    # Section 8: Security and Compliance
    # =========================================================================

    # 8.1 Key Protect
    ("8.1.1.1", "Ensure IBM Key Protect has automated rotation for customer managed keys enabled",
     "L1", "automated", "high", "security_and_compliance"),

    # 8.2 Secrets Manager
    ("8.2.1", "Ensure certificates imported into or generated through IBM Cloud Secrets Manager are automatically renewed before expiration",
     "L1", "automated", "high", "security_and_compliance"),

    # =========================================================================
    # Section 9: IBM Power Virtual Server on IBM Cloud (PowerVS)
    # =========================================================================

    ("9.1", "Ensure the Default Network Security Group of Every Workspace Restricts All Traffic",
     "L1", "manual", "high", "powervs"),
    ("9.2", "Ensure no workspace security groups allow ingress from 0.0.0.0/0 to port 3389",
     "L1", "manual", "high", "powervs"),
    ("9.3", "Ensure no workspace network security groups allow ingress from 0.0.0.0/0 to port 22",
     "L1", "manual", "high", "powervs"),
    ("9.4", "Ensure no workspace network security groups allow inbound traffic from the Internet from 0.0.0.0/0 to any infrastructure ports",
     "L1", "manual", "high", "powervs"),
    ("9.5", "Ensure no workspace network security groups allow inbound traffic from the Internet from 0.0.0.0/0 to any administrative ports",
     "L1", "manual", "high", "powervs"),
    ("9.6", "Ensure no workspace network security groups allow inbound traffic from the Internet from 0.0.0.0/0 to any fileshare port",
     "L1", "manual", "high", "powervs"),
    ("9.7", "Ensure no workspace network security groups allow inbound traffic from the Internet allowing access from 0.0.0.0/0 to telnet port (23) or RSH port (514)",
     "L1", "manual", "high", "powervs"),
]


def get_ibm_cloud_cis_registry():
    """Return the complete CIS IBM Cloud control registry as a list of dicts."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in IBM_CLOUD_CIS_CONTROLS
    ]


def get_ibm_cloud_control_count():
    """Return total number of CIS IBM Cloud controls."""
    return len(IBM_CLOUD_CIS_CONTROLS)


def get_ibm_cloud_automated_count():
    """Return count of automated controls."""
    return sum(1 for c in IBM_CLOUD_CIS_CONTROLS if c[3] == "automated")


def get_ibm_cloud_manual_count():
    """Return count of manual controls."""
    return sum(1 for c in IBM_CLOUD_CIS_CONTROLS if c[3] == "manual")
