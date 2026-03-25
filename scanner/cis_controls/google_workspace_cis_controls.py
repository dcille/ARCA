"""CIS Google Workspace Foundations Benchmark v1.3.0 — Complete Control Registry.

This registry contains ALL controls from the CIS Google Workspace Foundations Benchmark.
Each control is marked as 'automated' or 'manual' per the CIS assessment status.

Reference: CIS Google Workspace Foundations Benchmark v1.3.0 (June 2024)
Based on v1.1.0 (44 new recommendations added) and v1.2.0 structure.

The benchmark follows the Google Admin Console navigation:
  Section 1: Directory (Accounts, Authentication, Identity)
  Section 2: (Devices - excluded from scope, covered by CIS Chrome Benchmark)
  Section 3: Apps (Calendar, Gmail, Drive and Docs, Sites, Groups)
  Section 4: Security (Authentication, API controls, Rules)
  Section 5: Reporting & Audit
  Section 6: Alert Center Rules

Total controls: ~77 across Enterprise L1/L2 profiles.
Automation rate: ~90-95% of controls are automatable via Admin SDK APIs.
"""

# Each control: (cis_id, title, level, assessment_type, severity, service_area)
# level: "L1" (essential) or "L2" (enhanced)
# assessment_type: "automated" or "manual"

GW_CIS_CONTROLS = [
    # =========================================================================
    # Section 1: Directory — Accounts & Authentication
    # =========================================================================

    # 1.1 Super Admin Management
    ("1.1.1", "Ensure that there are no more than 3-4 super admin accounts",
     "L1", "automated", "critical", "directory"),
    ("1.1.2", "Ensure there are at least 2 super admin accounts",
     "L1", "automated", "critical", "directory"),
    ("1.1.3", "Ensure super admin accounts are used only for administrative activities",
     "L2", "manual", "critical", "directory"),
    ("1.1.4", "Ensure super admin accounts use hardware security keys",
     "L2", "automated", "critical", "directory"),

    # 1.2 Authentication & MFA
    ("1.2.1", "Ensure 2-Step Verification is enforced for all users",
     "L1", "automated", "critical", "directory"),
    ("1.2.2", "Ensure 2-Step Verification is enforced for all admin users",
     "L1", "automated", "critical", "directory"),
    ("1.2.3", "Ensure Security Key enforcement is enabled for all admin accounts",
     "L1", "automated", "high", "directory"),
    ("1.2.4", "Ensure that new 2-Step Verification enforcement methods are not 'Any'",
     "L1", "automated", "high", "directory"),
    ("1.2.5", "Ensure enforcement grace period is set to 1 week or less",
     "L1", "automated", "medium", "directory"),

    # 1.3 Password Management
    ("1.3.1", "Ensure password policy requires minimum 12 characters",
     "L1", "automated", "high", "directory"),
    ("1.3.2", "Ensure password policy enforces strong passwords",
     "L1", "automated", "high", "directory"),
    ("1.3.3", "Ensure password reset frequency is configured",
     "L2", "automated", "medium", "directory"),
    ("1.3.4", "Ensure password reuse is limited",
     "L2", "automated", "medium", "directory"),

    # 1.4 Advanced Protection Program
    ("1.4.1", "Ensure Advanced Protection Program is enabled for all admin accounts",
     "L2", "automated", "high", "directory"),
    ("1.4.2", "Ensure Advanced Protection Program enrollment is available",
     "L2", "automated", "medium", "directory"),

    # 1.5 Login & Session Management
    ("1.5.1", "Ensure login challenges are enabled for suspicious sign-ins",
     "L1", "automated", "high", "directory"),
    ("1.5.2", "Ensure Google session control is configured to a maximum of 12 hours",
     "L1", "automated", "medium", "directory"),
    ("1.5.3", "Ensure Google Cloud session control is configured",
     "L2", "automated", "medium", "directory"),
    ("1.5.4", "Ensure login IP ranges are configured for admin console access",
     "L2", "automated", "high", "directory"),

    # 1.6 Directory Sharing
    ("1.6.1", "Ensure directory data sharing is restricted externally",
     "L1", "automated", "high", "directory"),
    ("1.6.2", "Ensure contact sharing is restricted to the domain",
     "L1", "automated", "medium", "directory"),

    # 1.7 Account Recovery
    ("1.7.1", "Ensure account recovery options for super admins are configured",
     "L1", "automated", "high", "directory"),
    ("1.7.2", "Ensure account recovery phone and email are not set for admin accounts",
     "L2", "manual", "medium", "directory"),

    # =========================================================================
    # Section 3: Apps
    # =========================================================================

    # 3.1.1 Calendar
    ("3.1.1.1", "Ensure external sharing options for primary calendars is set to 'Only free/busy information'",
     "L1", "automated", "medium", "apps_calendar"),
    ("3.1.1.2", "Ensure external invitations warnings for Google Calendar are enabled",
     "L1", "automated", "medium", "apps_calendar"),
    ("3.1.1.3", "Ensure internal sharing options for primary calendars are configured appropriately",
     "L2", "automated", "low", "apps_calendar"),

    # 3.1.2 Drive and Docs
    ("3.1.2.1.1.1", "Ensure sharing outside of the organization is restricted or disabled",
     "L1", "automated", "high", "apps_drive"),
    ("3.1.2.1.1.2", "Ensure users cannot publish files to the web",
     "L1", "automated", "high", "apps_drive"),
    ("3.1.2.1.1.3", "Ensure document sharing is controlled by domain with allowlists",
     "L2", "automated", "high", "apps_drive"),
    ("3.1.2.1.1.4", "Ensure warn when sharing outside domain is enabled",
     "L1", "automated", "medium", "apps_drive"),
    ("3.1.2.1.1.5", "Ensure link sharing default is set to 'Restricted' or 'Off'",
     "L1", "automated", "high", "apps_drive"),
    ("3.1.2.1.2.1", "Ensure external sharing for shared drives is restricted",
     "L1", "automated", "high", "apps_drive"),
    ("3.1.2.1.2.2", "Ensure shared drive full-access members cannot modify settings",
     "L1", "automated", "medium", "apps_drive"),
    ("3.1.2.1.2.3", "Ensure shared drive file access is restricted to members only",
     "L1", "automated", "high", "apps_drive"),
    ("3.1.2.1.2.4", "Ensure viewers and commenters cannot download, print, or copy files",
     "L2", "automated", "medium", "apps_drive"),
    ("3.1.2.2", "Ensure DLP policies for Google Drive are configured",
     "L1", "automated", "high", "apps_drive"),
    ("3.1.2.3", "Ensure IRM (Information Rights Management) is configured for shared drives",
     "L2", "automated", "medium", "apps_drive"),
    ("3.1.2.4", "Ensure Google Drive add-ons are restricted",
     "L2", "automated", "medium", "apps_drive"),
    ("3.1.2.5", "Ensure Drive SDK access is restricted",
     "L2", "automated", "medium", "apps_drive"),

    # 3.1.3 Gmail
    ("3.1.3.1.1", "Ensure mailbox delegation is disabled or restricted",
     "L1", "automated", "high", "apps_gmail"),
    ("3.1.3.1.2", "Ensure Gmail offline access is restricted",
     "L2", "automated", "medium", "apps_gmail"),
    ("3.1.3.2.1", "Ensure SPF records are published for all domains",
     "L1", "automated", "high", "apps_gmail"),
    ("3.1.3.2.2", "Ensure SPF record uses strict fail (-all) policy",
     "L1", "automated", "high", "apps_gmail"),
    ("3.1.3.2.3", "Ensure DKIM is enabled for all domains",
     "L1", "automated", "high", "apps_gmail"),
    ("3.1.3.2.4", "Ensure DMARC records are published for all domains",
     "L1", "automated", "high", "apps_gmail"),
    ("3.1.3.2.5", "Ensure DMARC policy is set to 'reject' or 'quarantine'",
     "L1", "automated", "high", "apps_gmail"),
    ("3.1.3.3.1", "Ensure protection against encrypted attachments from untrusted senders is enabled",
     "L1", "automated", "high", "apps_gmail"),
    ("3.1.3.3.2", "Ensure protection against attachments with scripts is enabled",
     "L1", "automated", "high", "apps_gmail"),
    ("3.1.3.3.3", "Ensure protection against anomalous attachment types is enabled",
     "L1", "automated", "high", "apps_gmail"),
    ("3.1.3.3.4", "Ensure email allowlist entries are reviewed and minimal",
     "L1", "automated", "medium", "apps_gmail"),
    ("3.1.3.3.5", "Ensure spoofing and authentication protection is enabled",
     "L1", "automated", "high", "apps_gmail"),
    ("3.1.3.3.6", "Ensure quarantine admin notifications are enabled",
     "L1", "automated", "medium", "apps_gmail"),
    ("3.1.3.4.1", "Ensure comprehensive mail storage is enabled",
     "L2", "automated", "medium", "apps_gmail"),
    ("3.1.3.4.2", "Ensure content compliance rules are configured",
     "L2", "automated", "medium", "apps_gmail"),
    ("3.1.3.4.3", "Ensure objectionable content rules are configured",
     "L2", "automated", "medium", "apps_gmail"),
    ("3.1.3.5.1", "Ensure POP and IMAP access is disabled for all users",
     "L2", "automated", "high", "apps_gmail"),
    ("3.1.3.5.2", "Ensure automatic email forwarding is disabled",
     "L1", "automated", "high", "apps_gmail"),
    ("3.1.3.5.3", "Ensure per-user outbound gateways are disabled",
     "L1", "automated", "medium", "apps_gmail"),
    ("3.1.3.5.4", "Ensure email allowlists are not used",
     "L1", "automated", "high", "apps_gmail"),

    # 3.1.4 Sites
    ("3.1.4.1", "Ensure sites creation is restricted",
     "L2", "automated", "medium", "apps_sites"),
    ("3.1.4.2", "Ensure sites sharing is restricted",
     "L1", "automated", "medium", "apps_sites"),

    # 3.1.5 Groups for Business
    ("3.1.5.1", "Ensure groups for business sharing settings are configured",
     "L1", "automated", "medium", "apps_groups"),
    ("3.1.5.2", "Ensure creating groups outside the organization is restricted",
     "L1", "automated", "medium", "apps_groups"),
    ("3.1.6.1", "Ensure group creation is restricted to admins",
     "L2", "automated", "medium", "apps_groups"),
    ("3.1.6.2", "Ensure access to groups by external members is restricted",
     "L1", "automated", "high", "apps_groups"),

    # =========================================================================
    # Section 4: Security
    # =========================================================================

    # 4.1 Authentication
    ("4.1.1", "Ensure less secure app access is disabled",
     "L1", "automated", "high", "security"),
    ("4.1.2", "Ensure Single Sign-On (SSO) is configured if applicable",
     "L1", "automated", "high", "security"),
    ("4.1.3", "Ensure third-party OAuth app access is restricted",
     "L1", "automated", "high", "security"),

    # 4.2 API Access
    ("4.2.1", "Ensure API access is restricted for third-party applications",
     "L1", "automated", "high", "security"),
    ("4.2.2", "Ensure domain-wide delegation is reviewed and limited",
     "L2", "manual", "critical", "security"),
    ("4.2.3", "Ensure installed marketplace apps are reviewed regularly",
     "L2", "manual", "medium", "security"),

    # =========================================================================
    # Section 5: Reporting & Audit
    # =========================================================================
    ("5.1.1", "Ensure admin audit logging is enabled and reviewed",
     "L1", "automated", "high", "reporting"),
    ("5.1.2", "Ensure login audit logging is enabled and reviewed",
     "L1", "automated", "high", "reporting"),
    ("5.1.3", "Ensure application usage activity report is reviewed regularly",
     "L1", "manual", "medium", "reporting"),
    ("5.1.4", "Ensure Drive audit logging is enabled",
     "L1", "automated", "medium", "reporting"),
    ("5.1.5", "Ensure accounts audit report is reviewed for anomalies",
     "L1", "manual", "medium", "reporting"),

    # =========================================================================
    # Section 6: Alert Center Rules
    # =========================================================================
    ("6.1", "Ensure alert for super admin password change is configured",
     "L1", "automated", "high", "alert_rules"),
    ("6.2", "Ensure alert for government-backed attack warnings is configured",
     "L1", "automated", "high", "alert_rules"),
    ("6.3", "Ensure alert for suspicious user activity is configured",
     "L1", "automated", "high", "alert_rules"),
    ("6.4", "Ensure alert for admin privilege changes is configured",
     "L1", "automated", "high", "alert_rules"),
    ("6.5", "Ensure alert for suspicious programmatic login is configured",
     "L1", "automated", "high", "alert_rules"),
    ("6.6", "Ensure alert for suspicious login from less secure app is configured",
     "L1", "automated", "high", "alert_rules"),
    ("6.7", "Ensure alert for leaked password detection is configured",
     "L1", "automated", "high", "alert_rules"),
    ("6.8", "Ensure alert for potential employee spoofing is configured",
     "L1", "automated", "medium", "alert_rules"),
    ("6.9", "Ensure alert for email auto-forwarding is configured",
     "L1", "automated", "high", "alert_rules"),
    ("6.10", "Ensure alert for user-reported phishing is configured",
     "L1", "automated", "medium", "alert_rules"),
    ("6.11", "Ensure alert for DLP rule violation is configured",
     "L1", "automated", "high", "alert_rules"),
    ("6.12", "Ensure alert for mobile device compromised is configured",
     "L2", "automated", "high", "alert_rules"),
]


def get_gw_cis_registry():
    """Return the complete CIS Google Workspace control registry as a list of dicts."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in GW_CIS_CONTROLS
    ]


def get_gw_control_count():
    """Return total number of CIS GW controls."""
    return len(GW_CIS_CONTROLS)


def get_gw_automated_count():
    """Return count of automated controls."""
    return sum(1 for c in GW_CIS_CONTROLS if c[3] == "automated")


def get_gw_manual_count():
    """Return count of manual controls."""
    return sum(1 for c in GW_CIS_CONTROLS if c[3] == "manual")
