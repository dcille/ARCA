"""CIS Microsoft 365 Foundations Benchmark v3.1.0 / v4.0.0 — Complete Control Registry.

This registry contains ALL controls from the CIS Microsoft 365 Foundations Benchmark.
Each control is marked as 'automated' or 'manual' per the CIS assessment status.
Controls are organized by section matching the benchmark structure.

Reference: CIS Microsoft 365 Foundations Benchmark v3.1.0 (04-29-2024)
Updated with v4.0.0 additions (10-31-2024)

Total controls: ~129 across E3/E5 L1/L2 profiles.
"""

# Each control: (cis_id, title, level, profile, assessment_type, severity, service_area)
# level: "L1" or "L2"
# profile: "E3" (available in E3+), "E5" (requires E5)
# assessment_type: "automated" or "manual"

M365_CIS_CONTROLS = [
    # =========================================================================
    # Section 1: Microsoft 365 Admin Center
    # =========================================================================

    # 1.1 Users
    ("1.1.1", "Ensure Administrative accounts are separate and cloud-only",
     "L1", "E3", "manual", "critical", "admin_center"),
    ("1.1.2", "Ensure two emergency access accounts have been defined",
     "L1", "E3", "manual", "critical", "admin_center"),
    ("1.1.3", "Ensure that between two and four global admins are designated",
     "L1", "E3", "automated", "critical", "admin_center"),
    ("1.1.4", "Ensure Guest Users are reviewed at least biweekly",
     "L1", "E3", "manual", "medium", "admin_center"),

    # v4.0.0 addition
    ("1.1.5", "Ensure administrative accounts use licenses with a reduced application footprint",
     "L1", "E3", "manual", "high", "admin_center"),

    # 1.2 Teams & Groups
    ("1.2.1", "Ensure that only organizationally managed/approved public groups exist",
     "L2", "E3", "automated", "medium", "admin_center"),
    ("1.2.2", "Ensure sign-in to shared mailboxes is blocked",
     "L1", "E3", "automated", "high", "admin_center"),

    # 1.3 Settings
    ("1.3.1", "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)'",
     "L1", "E3", "automated", "medium", "admin_center"),
    ("1.3.2", "Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices",
     "L1", "E3", "manual", "high", "admin_center"),
    ("1.3.3", "Ensure 'External sharing' of calendars is not available",
     "L2", "E3", "automated", "medium", "admin_center"),
    ("1.3.4", "Ensure 'User owned apps and services' is restricted",
     "L1", "E3", "manual", "medium", "admin_center"),
    ("1.3.5", "Ensure internal phishing protection for Forms is enabled",
     "L1", "E3", "manual", "medium", "admin_center"),
    ("1.3.6", "Ensure the customer lockbox feature is enabled",
     "L2", "E5", "automated", "medium", "admin_center"),
    ("1.3.7", "Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'",
     "L2", "E3", "manual", "medium", "admin_center"),
    ("1.3.8", "Ensure that Sways cannot be shared with people outside of your organization",
     "L2", "E3", "manual", "low", "admin_center"),

    # =========================================================================
    # Section 2: Microsoft 365 Defender
    # =========================================================================

    # 2.1 Email & Collaboration
    ("2.1.1", "Ensure Safe Links for Office Applications is Enabled",
     "L2", "E5", "automated", "high", "defender"),
    ("2.1.2", "Ensure the Common Attachment Types Filter is enabled",
     "L1", "E3", "automated", "high", "defender"),
    ("2.1.3", "Ensure notifications for internal users sending malware is Enabled",
     "L1", "E3", "automated", "medium", "defender"),
    ("2.1.4", "Ensure Safe Attachments policy is enabled",
     "L2", "E5", "automated", "high", "defender"),
    ("2.1.5", "Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled",
     "L2", "E5", "automated", "high", "defender"),
    ("2.1.6", "Ensure Exchange Online Spam Policies are set to notify administrators",
     "L1", "E3", "automated", "medium", "defender"),
    ("2.1.7", "Ensure that an anti-phishing policy has been created",
     "L2", "E5", "automated", "high", "defender"),
    ("2.1.8", "Ensure that SPF records are published for all Exchange Domains",
     "L1", "E3", "manual", "high", "defender"),
    ("2.1.9", "Ensure DKIM is enabled for all Exchange Online Domains",
     "L1", "E3", "automated", "high", "defender"),
    ("2.1.10", "Ensure DMARC Records for all Exchange Online domains are published",
     "L1", "E3", "manual", "high", "defender"),
    ("2.1.11", "Ensure comprehensive attachment filtering is applied",
     "L2", "E3", "automated", "medium", "defender"),
    ("2.1.12", "Ensure the connection filter IP allow list is not used",
     "L1", "E3", "automated", "medium", "defender"),
    ("2.1.13", "Ensure the connection filter safe list is off",
     "L1", "E3", "automated", "medium", "defender"),
    ("2.1.14", "Ensure inbound anti-spam policies do not contain allowed domains",
     "L1", "E3", "automated", "medium", "defender"),

    # 2.3 Reports
    ("2.3.1", "Ensure the Account Provisioning Activity report is reviewed at least weekly",
     "L1", "E3", "manual", "medium", "defender"),
    ("2.3.2", "Ensure non-global administrator role group assignments are reviewed at least weekly",
     "L1", "E3", "manual", "medium", "defender"),

    # 2.4 Cloud Apps
    ("2.4.1", "Ensure Priority account protection is enabled and configured",
     "L1", "E5", "automated", "high", "defender"),
    ("2.4.2", "Ensure Priority accounts have 'Strict protection' presets applied",
     "L1", "E5", "automated", "high", "defender"),
    ("2.4.3", "Ensure Microsoft Defender for Cloud Apps is enabled and configured",
     "L2", "E5", "automated", "high", "defender"),
    ("2.4.4", "Ensure Zero-hour auto purge for Microsoft Teams is on",
     "L1", "E5", "automated", "high", "defender"),

    # =========================================================================
    # Section 3: Microsoft Purview (Data Management)
    # =========================================================================

    # 3.1 Audit
    ("3.1.1", "Ensure Microsoft 365 audit log search is Enabled",
     "L1", "E3", "automated", "critical", "purview"),
    ("3.1.2", "Ensure user role group changes are reviewed at least weekly",
     "L1", "E3", "manual", "medium", "purview"),

    # 3.2 Data Loss Prevention
    ("3.2.1", "Ensure DLP policies are enabled",
     "L1", "E3", "automated", "high", "purview"),
    ("3.2.2", "Ensure DLP policies are enabled for Microsoft Teams",
     "L1", "E5", "manual", "high", "purview"),

    # 3.3 Information Protection
    ("3.3.1", "Ensure SharePoint Online Information Protection policies are set up and used",
     "L1", "E3", "automated", "high", "purview"),

    # =========================================================================
    # Section 5: Microsoft Entra Admin Center (Azure AD)
    # =========================================================================

    # 5.1.1 Identity / Overview
    ("5.1.1.1", "Ensure Security Defaults is disabled on Azure Active Directory",
     "L1", "E3", "manual", "high", "entra_identity"),

    # 5.1.2 Users / Settings
    ("5.1.2.1", "Ensure 'Per-user MFA' is disabled",
     "L1", "E3", "manual", "high", "entra_identity"),
    ("5.1.2.2", "Ensure third party integrated applications are not allowed",
     "L2", "E3", "automated", "medium", "entra_identity"),
    ("5.1.2.3", "Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'",
     "L1", "E3", "automated", "medium", "entra_identity"),
    ("5.1.2.4", "Ensure 'Restrict access to the Azure AD administration portal' is set to 'Yes'",
     "L1", "E3", "manual", "medium", "entra_identity"),
    ("5.1.2.5", "Ensure the option to remain signed in is hidden",
     "L2", "E3", "manual", "low", "entra_identity"),
    ("5.1.2.6", "Ensure 'LinkedIn account connections' is disabled",
     "L2", "E3", "manual", "low", "entra_identity"),

    # 5.1.3 Groups
    ("5.1.3.1", "Ensure a dynamic group for guest users is created",
     "L1", "E3", "automated", "medium", "entra_identity"),

    # 5.1.5 Enterprise Applications
    ("5.1.5.1", "Ensure user consent to apps accessing company data on their behalf is not allowed",
     "L2", "E3", "automated", "high", "entra_identity"),
    ("5.1.5.2", "Ensure the admin consent workflow is enabled",
     "L1", "E3", "automated", "medium", "entra_identity"),
    ("5.1.5.3", "Ensure the Application Usage report is reviewed at least weekly",
     "L1", "E3", "manual", "medium", "entra_identity"),

    # 5.1.6 External Identities
    ("5.1.6.1", "Ensure that collaboration invitations are sent to allowed domains only",
     "L2", "E3", "automated", "medium", "entra_identity"),
    ("5.1.6.2", "Ensure that guest user access is restricted",
     "L1", "E3", "automated", "medium", "entra_identity"),
    ("5.1.6.3", "Ensure guest user invitations are limited to the Guest Inviter role",
     "L2", "E3", "automated", "medium", "entra_identity"),

    # 5.1.8 Hybrid
    ("5.1.8.1", "Ensure that password hash sync is enabled for hybrid deployments",
     "L1", "E3", "automated", "high", "entra_identity"),

    # 5.2.2 Conditional Access
    ("5.2.2.1", "Ensure multifactor authentication is enabled for all users in administrative roles",
     "L1", "E3", "automated", "critical", "entra_protection"),
    ("5.2.2.2", "Ensure multifactor authentication is enabled for all users",
     "L1", "E3", "automated", "critical", "entra_protection"),
    ("5.2.2.3", "Enable Conditional Access policies to block legacy authentication",
     "L1", "E3", "automated", "high", "entra_protection"),
    ("5.2.2.4", "Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users",
     "L1", "E3", "automated", "high", "entra_protection"),
    ("5.2.2.5", "Ensure 'Phishing-resistant MFA strength' is required for Administrators",
     "L2", "E3", "automated", "high", "entra_protection"),
    ("5.2.2.6", "Enable Identity Protection user risk policies",
     "L1", "E5", "automated", "high", "entra_protection"),
    ("5.2.2.7", "Enable Identity Protection sign-in risk policies",
     "L1", "E5", "automated", "high", "entra_protection"),
    ("5.2.2.8", "Ensure admin center access is limited to administrative roles",
     "L2", "E3", "automated", "high", "entra_protection"),
    ("5.2.2.9", "Ensure 'sign-in risk' is blocked for medium and high risk",
     "L2", "E5", "automated", "high", "entra_protection"),
    ("5.2.2.10", "Ensure a managed device is required for authentication",
     "L1", "E3", "automated", "high", "entra_protection"),
    ("5.2.2.11", "Ensure a managed device is required for MFA registration",
     "L1", "E3", "automated", "high", "entra_protection"),

    # 5.2.3 Authentication Methods
    ("5.2.3.1", "Ensure Microsoft Authenticator is configured to protect against MFA fatigue",
     "L1", "E3", "automated", "high", "entra_protection"),
    ("5.2.3.2", "Ensure custom banned passwords lists are used",
     "L1", "E3", "automated", "high", "entra_protection"),
    ("5.2.3.3", "Ensure password protection is enabled for on-prem Active Directory",
     "L1", "E3", "automated", "medium", "entra_protection"),
    ("5.2.3.4", "Ensure all member users are 'MFA capable'",
     "L1", "E3", "automated", "high", "entra_protection"),
    ("5.2.3.5", "Ensure weak authentication methods are disabled",
     "L1", "E3", "automated", "high", "entra_protection"),

    # 5.2.4 Password Reset
    ("5.2.4.1", "Ensure 'Self service password reset enabled' is set to 'All'",
     "L1", "E3", "automated", "medium", "entra_protection"),
    ("5.2.4.2", "Ensure the self-service password reset activity report is reviewed at least weekly",
     "L1", "E3", "manual", "medium", "entra_protection"),

    # 5.3 Privileged Identity Management
    ("5.3.1", "Ensure 'Privileged Identity Management' is used to manage roles",
     "L2", "E5", "automated", "critical", "entra_governance"),
    ("5.3.2", "Ensure 'Access reviews' for Guest Users are configured",
     "L1", "E5", "automated", "high", "entra_governance"),
    ("5.3.3", "Ensure 'Access reviews' for privileged roles are configured",
     "L1", "E5", "automated", "high", "entra_governance"),
    ("5.3.4", "Ensure approval is required for Global Administrator role activation",
     "L1", "E5", "automated", "critical", "entra_governance"),

    # =========================================================================
    # Section 6: Exchange Online
    # =========================================================================

    # 6.1 Audit
    ("6.1.1", "Ensure 'AuditDisabled' organizationally is set to 'False'",
     "L1", "E3", "automated", "high", "exchange_online"),
    ("6.1.2", "Ensure mailbox auditing for E3 users is Enabled",
     "L1", "E3", "automated", "high", "exchange_online"),
    ("6.1.3", "Ensure mailbox auditing for E5 users is Enabled",
     "L1", "E5", "automated", "high", "exchange_online"),
    ("6.1.4", "Ensure 'AuditBypassEnabled' is not enabled on mailboxes",
     "L1", "E3", "automated", "high", "exchange_online"),

    # 6.2 Mail Flow
    ("6.2.1", "Ensure all forms of mail forwarding are blocked and/or disabled",
     "L1", "E3", "automated", "high", "exchange_online"),
    ("6.2.2", "Ensure mail transport rules do not whitelist specific domains",
     "L1", "E3", "automated", "high", "exchange_online"),
    ("6.2.3", "Ensure email from external senders is identified",
     "L1", "E3", "automated", "medium", "exchange_online"),

    # 6.3 Add-ins
    ("6.3.1", "Ensure users installing Outlook add-ins is not allowed",
     "L2", "E3", "automated", "medium", "exchange_online"),

    # 6.4 Review
    ("6.4.1", "Ensure mail forwarding rules are reviewed at least weekly",
     "L1", "E3", "manual", "high", "exchange_online"),

    # 6.5 Authentication
    ("6.5.1", "Ensure modern authentication for Exchange Online is enabled",
     "L1", "E3", "automated", "high", "exchange_online"),
    ("6.5.2", "Ensure MailTips are enabled for end users",
     "L1", "E3", "automated", "low", "exchange_online"),
    ("6.5.3", "Ensure additional storage providers are restricted in Outlook on the web",
     "L2", "E3", "automated", "medium", "exchange_online"),
    ("6.5.4", "Ensure SMTP AUTH is disabled",
     "L1", "E3", "automated", "high", "exchange_online"),

    # =========================================================================
    # Section 7: SharePoint & OneDrive
    # =========================================================================

    # 7.2 Sharing
    ("7.2.1", "Ensure modern authentication for SharePoint applications is required",
     "L1", "E3", "automated", "high", "sharepoint_onedrive"),
    ("7.2.2", "Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled",
     "L1", "E3", "automated", "medium", "sharepoint_onedrive"),
    ("7.2.3", "Ensure external content sharing is restricted",
     "L1", "E3", "automated", "high", "sharepoint_onedrive"),
    ("7.2.4", "Ensure OneDrive content sharing is restricted",
     "L2", "E3", "automated", "high", "sharepoint_onedrive"),
    ("7.2.5", "Ensure that SharePoint guest users cannot share items they don't own",
     "L2", "E3", "automated", "medium", "sharepoint_onedrive"),
    ("7.2.6", "Ensure SharePoint external sharing is managed through domain whitelist/blacklists",
     "L2", "E3", "automated", "medium", "sharepoint_onedrive"),
    ("7.2.7", "Ensure link sharing is restricted in SharePoint and OneDrive",
     "L1", "E3", "automated", "high", "sharepoint_onedrive"),
    ("7.2.8", "Ensure external sharing is restricted by security group",
     "L2", "E3", "manual", "medium", "sharepoint_onedrive"),
    ("7.2.9", "Ensure guest access to a site or OneDrive will expire automatically",
     "L1", "E3", "automated", "medium", "sharepoint_onedrive"),
    ("7.2.10", "Ensure reauthentication with verification code is restricted",
     "L1", "E3", "automated", "medium", "sharepoint_onedrive"),
    ("7.2.11", "Ensure the SharePoint default sharing link permission is set to 'View'",
     "L1", "E3", "automated", "high", "sharepoint_onedrive"),

    # 7.3 Access Control
    ("7.3.1", "Ensure Office 365 SharePoint infected files are disallowed for download",
     "L2", "E5", "automated", "high", "sharepoint_onedrive"),
    ("7.3.2", "Ensure OneDrive sync is restricted for unmanaged devices",
     "L2", "E3", "automated", "high", "sharepoint_onedrive"),

    # =========================================================================
    # Section 8: Microsoft Teams
    # =========================================================================

    # 8.1 File Sharing
    ("8.1.1", "Ensure external file sharing in Teams is enabled for only approved cloud storage services",
     "L2", "E3", "automated", "medium", "teams"),
    ("8.1.2", "Ensure users can't send emails to a channel email address",
     "L2", "E3", "automated", "low", "teams"),

    # 8.2 External Access
    ("8.2.1", "Ensure external domains are restricted in the Teams admin center",
     "L2", "E3", "automated", "high", "teams"),
    ("8.2.2", "Ensure communication with unmanaged Teams users is disabled",
     "L1", "E3", "automated", "medium", "teams"),
    ("8.2.3", "Ensure external Teams users cannot initiate conversations",
     "L1", "E3", "automated", "medium", "teams"),
    ("8.2.4", "Ensure communication with Skype users is disabled",
     "L1", "E3", "automated", "low", "teams"),

    # 8.5 Meeting Policies
    ("8.5.1", "Ensure anonymous users can't join a meeting",
     "L2", "E3", "automated", "high", "teams"),
    ("8.5.2", "Ensure anonymous users and dial-in callers can't start a meeting",
     "L1", "E3", "automated", "high", "teams"),
    ("8.5.3", "Ensure only people in my org can bypass the lobby",
     "L1", "E3", "automated", "medium", "teams"),
    ("8.5.4", "Ensure users dialing in can't bypass the lobby",
     "L1", "E3", "automated", "medium", "teams"),
    ("8.5.5", "Ensure meeting chat does not allow anonymous users",
     "L2", "E3", "automated", "medium", "teams"),
    ("8.5.6", "Ensure only organizers and co-organizers can present",
     "L2", "E3", "automated", "medium", "teams"),
    ("8.5.7", "Ensure external participants can't give or request control",
     "L1", "E3", "automated", "medium", "teams"),
    ("8.5.8", "Ensure external meeting chat is off",
     "L2", "E3", "automated", "medium", "teams"),
    ("8.5.9", "Ensure meeting recording is off by default",
     "L2", "E3", "automated", "medium", "teams"),

    # 8.6 Messaging
    ("8.6.1", "Ensure users can report security concerns in Teams",
     "L1", "E3", "automated", "medium", "teams"),

    # =========================================================================
    # Section 9: Microsoft Fabric (Power BI)
    # =========================================================================

    # 9.1 Tenant Settings
    ("9.1.1", "Ensure guests can't access Microsoft Fabric",
     "L2", "E3", "automated", "medium", "fabric"),
    ("9.1.2", "Ensure external user invitations are restricted",
     "L2", "E3", "automated", "medium", "fabric"),
    ("9.1.3", "Ensure R and Python visuals can only be viewed",
     "L1", "E3", "automated", "medium", "fabric"),
    ("9.1.4", "Ensure Azure ActiveDirectory guest access is restricted in Fabric",
     "L1", "E3", "automated", "medium", "fabric"),
    ("9.1.5", "Ensure 'Interact with and share R and Python visuals' is 'Disabled'",
     "L2", "E3", "automated", "medium", "fabric"),
    ("9.1.6", "Ensure Allow DirectQuery connections to Power BI semantic models is restricted",
     "L1", "E3", "automated", "medium", "fabric"),
    ("9.1.7", "Ensure users can only share to internal recipients",
     "L1", "E3", "automated", "medium", "fabric"),
    ("9.1.8", "Ensure Publish to web is restricted",
     "L1", "E3", "automated", "high", "fabric"),
    ("9.1.9", "Ensure export to Excel is restricted",
     "L2", "E3", "automated", "low", "fabric"),
    ("9.1.10", "Ensure access to APIs by Service Principals is restricted",
     "L1", "E3", "automated", "high", "fabric"),
    ("9.1.11", "Ensure Service Principals cannot create and use profiles",
     "L1", "E3", "automated", "medium", "fabric"),
]


def get_m365_cis_registry():
    """Return the complete CIS M365 control registry as a list of dicts."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "cis_profile": ctrl[3],
            "assessment_type": ctrl[4],
            "severity": ctrl[5],
            "service_area": ctrl[6],
        }
        for ctrl in M365_CIS_CONTROLS
    ]


def get_m365_control_count():
    """Return total number of CIS M365 controls."""
    return len(M365_CIS_CONTROLS)


def get_m365_automated_count():
    """Return count of automated controls."""
    return sum(1 for c in M365_CIS_CONTROLS if c[4] == "automated")


def get_m365_manual_count():
    """Return count of manual controls."""
    return sum(1 for c in M365_CIS_CONTROLS if c[4] == "manual")
