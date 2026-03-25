"""CIS Microsoft Azure Foundations Benchmark v3.0.0 — Complete Control Registry.

This registry contains ALL controls from the CIS Microsoft Azure Foundations Benchmark.
Each control is marked as 'automated' or 'manual' per the CIS assessment status.
Controls are organized by section matching the benchmark structure.

Reference: CIS Microsoft Azure Foundations Benchmark v3.0.0 (2024-03-28)

Total controls: ~160 across 10 sections.
"""

# Each control: (cis_id, title, level, assessment_type, severity, service_area)
# level: "L1" or "L2"
# assessment_type: "automated" or "manual"
# severity: "critical", "high", "medium", "low"
# service_area: "identity_and_access_management", "microsoft_defender",
#               "storage_accounts", "database_services", "logging_and_monitoring",
#               "networking", "virtual_machines", "key_vault", "app_service",
#               "miscellaneous"

AZURE_CIS_CONTROLS = [
    # =========================================================================
    # Section 1: Identity and Access Management (~28 controls)
    # =========================================================================

    ("1.1", "Ensure Security Defaults is enabled on Azure Active Directory",
     "L1", "automated", "critical", "identity_and_access_management"),

    # 1.2 Conditional Access
    ("1.2.1", "Ensure Trusted Locations Are Defined",
     "L1", "manual", "high", "identity_and_access_management"),
    ("1.2.2", "Ensure Multi-Factor Authentication is Required for Administrative Roles",
     "L1", "automated", "critical", "identity_and_access_management"),
    ("1.2.3", "Ensure Multi-Factor Authentication is Required for All Users",
     "L1", "automated", "critical", "identity_and_access_management"),
    ("1.2.4", "Ensure Sign-In Frequency is Enabled and Browser Sessions Are Not Persistent for Administrative Users",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.2.5", "Ensure Legacy Authentication is Blocked via Conditional Access Policy",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.2.6", "Ensure Risk-Based Conditional Access Policies are Configured for Sign-In Risk",
     "L2", "automated", "high", "identity_and_access_management"),
    ("1.2.7", "Ensure Risk-Based Conditional Access Policies are Configured for User Risk",
     "L2", "automated", "high", "identity_and_access_management"),

    # 1.3–1.20 IAM controls
    ("1.3", "Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.4", "Ensure Guest Users Are Reviewed on a Regular Basis",
     "L1", "manual", "medium", "identity_and_access_management"),
    ("1.5", "Ensure That 'Number of methods required to reset' is set to '2'",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.6", "Ensure that account 'Lockout Threshold' is less than or equal to '10'",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.7", "Ensure that account 'Lockout duration in seconds' is greater than or equal to '60'",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.8", "Ensure that a Custom Bad Password List is set to 'Enforce' for your Organization",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.9", "Ensure that 'Number of days before users are asked to re-confirm their authentication information' is not set to '0'",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.10", "Ensure that 'Notify users on password resets?' is set to 'Yes'",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.11", "Ensure That 'Notify all admins when other admins reset their password?' is set to 'Yes'",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.12", "Ensure that 'Users can consent to apps accessing company data on their behalf' is set to 'Do not allow user consent'",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.13", "Ensure that 'Users can add gallery apps to My Apps' is set to 'No'",
     "L2", "automated", "low", "identity_and_access_management"),
    ("1.14", "Ensure That 'Users Can Register Applications' Is Set to 'No'",
     "L2", "automated", "medium", "identity_and_access_management"),
    ("1.15", "Ensure That 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects'",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.16", "Ensure that 'Guest invite restrictions' is set to 'Only users assigned to specific admin roles can invite guest users'",
     "L2", "automated", "medium", "identity_and_access_management"),
    ("1.17", "Ensure That 'Restrict access to Microsoft Entra admin center' is Set to 'Yes'",
     "L1", "automated", "medium", "identity_and_access_management"),

    ("1.18", "Ensure that 'Restrict user ability to access groups features in the Access Pane' is Set to 'Yes'",
     "L2", "automated", "low", "identity_and_access_management"),
    ("1.19", "Ensure that 'Users can create security groups in Azure portals, API or PowerShell' is set to 'No'",
     "L2", "automated", "medium", "identity_and_access_management"),
    ("1.20", "Ensure that 'Owners can manage group membership requests in the Access Panel' is set to 'No'",
     "L2", "automated", "low", "identity_and_access_management"),
    ("1.21", "Ensure that 'User consent for applications' is set to 'Do not allow user consent'",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.22", "Ensure that 'User consent for applications' is configured to allow consent only for applications from verified publishers",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.23", "Ensure the admin consent workflow is enabled",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.24", "Ensure custom banned passwords lists are used",
     "L1", "automated", "high", "identity_and_access_management"),
    ("1.25", "Ensure password protection is enabled for on-prem Active Directory",
     "L1", "automated", "medium", "identity_and_access_management"),
    ("1.26", "Ensure That 'Privileged Identity Management' Is Used to Manage Roles",
     "L2", "manual", "critical", "identity_and_access_management"),
    ("1.27", "Ensure fewer than 5 users have Global Administrator assignment",
     "L1", "automated", "critical", "identity_and_access_management"),
    ("1.28", "Ensure Multi-factor Authentication is Required to access Microsoft Admin Portals",
     "L1", "automated", "critical", "identity_and_access_management"),

    # =========================================================================
    # Section 2: Microsoft Defender (~20 controls)
    # =========================================================================

    # 2.1 Microsoft Defender for Cloud
    ("2.1.1", "Ensure That Microsoft Defender for Servers Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.2", "Ensure That Microsoft Defender for App Service Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.3", "Ensure That Microsoft Defender for Azure SQL Database Servers Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.4", "Ensure That Microsoft Defender for SQL Servers on Machines Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.5", "Ensure That Microsoft Defender for Open-Source Relational Databases Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.6", "Ensure That Microsoft Defender for Azure Cosmos DB Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.7", "Ensure That Microsoft Defender for Storage Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.8", "Ensure That Microsoft Defender for Containers Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.9", "Ensure That Microsoft Defender for Key Vault Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.10", "Ensure That Microsoft Defender for DNS Is Set to 'On'",
     "L2", "automated", "medium", "microsoft_defender"),
    ("2.1.11", "Ensure That Microsoft Defender for Resource Manager Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.12", "Ensure that Microsoft Defender Recommendation for 'Apply system updates' status is 'Completed'",
     "L1", "manual", "high", "microsoft_defender"),
    ("2.1.13", "Ensure that Microsoft Cloud Security Benchmark policies are not set to 'Disabled'",
     "L1", "automated", "high", "microsoft_defender"),
    ("2.1.14", "Ensure That 'All users with the following roles' is set to 'Owner'",
     "L1", "automated", "high", "microsoft_defender"),
    ("2.1.15", "Ensure 'Additional email addresses' is Configured with a Security Contact Email",
     "L1", "automated", "high", "microsoft_defender"),
    ("2.1.16", "Ensure That 'Notify about alerts with the following severity' is Set to 'High'",
     "L1", "automated", "high", "microsoft_defender"),
    ("2.1.17", "Ensure That Microsoft Defender for Databases Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.18", "Ensure That Microsoft Defender for Azure DevOps Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.19", "Ensure That Microsoft Defender for APIs Is Set to 'On'",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.20", "Ensure That Microsoft Defender External Attack Surface Monitoring (EASM) Is Enabled",
     "L2", "manual", "medium", "microsoft_defender"),
    ("2.1.21", "Ensure That Microsoft Defender for Cloud Apps Integration With Microsoft Defender for Cloud Is Selected",
     "L2", "automated", "high", "microsoft_defender"),
    ("2.1.22", "Ensure That Microsoft Defender for Endpoint Integration With Microsoft Defender for Cloud Is Selected",
     "L2", "automated", "high", "microsoft_defender"),

    # =========================================================================
    # Section 3: Storage Accounts (~15 controls)
    # =========================================================================

    ("3.1", "Ensure that 'Secure transfer required' is set to 'Enabled'",
     "L1", "automated", "high", "storage_accounts"),
    ("3.2", "Ensure that 'Enable Infrastructure Encryption' for Each Storage Account in Azure Storage is Set to 'enabled'",
     "L2", "automated", "medium", "storage_accounts"),
    ("3.3", "Ensure that 'Enable key rotation reminders' is enabled for each Storage Account",
     "L1", "manual", "medium", "storage_accounts"),
    ("3.4", "Ensure that Storage Account Access Keys are Periodically Regenerated",
     "L1", "manual", "medium", "storage_accounts"),
    ("3.5", "Ensure that Shared Access Signature Tokens Expire Within an Hour",
     "L1", "manual", "medium", "storage_accounts"),
    ("3.6", "Ensure that 'Public access level' is disabled for storage accounts with blob containers",
     "L1", "automated", "high", "storage_accounts"),
    ("3.7", "Ensure Default Network Access Rule for Storage Accounts is Set to Deny",
     "L1", "automated", "high", "storage_accounts"),
    ("3.8", "Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled for Storage Account Access",
     "L2", "automated", "medium", "storage_accounts"),
    ("3.9", "Ensure Private Endpoints are Used to Access Storage Accounts",
     "L2", "automated", "medium", "storage_accounts"),
    ("3.10", "Ensure Soft Delete is Enabled for Azure Containers and Blob Storage",
     "L1", "automated", "medium", "storage_accounts"),
    ("3.11", "Ensure Storage for Critical Data are Encrypted with Customer Managed Keys (CMK)",
     "L2", "automated", "high", "storage_accounts"),
    ("3.12", "Ensure Storage Logging is Enabled for Blob Service for 'Read', 'Write', and 'Delete' requests",
     "L2", "automated", "medium", "storage_accounts"),
    ("3.13", "Ensure Storage Logging is Enabled for Table Service for 'Read', 'Write', and 'Delete' Requests",
     "L2", "automated", "medium", "storage_accounts"),
    ("3.14", "Ensure Storage Logging is Enabled for Queue Service for 'Read', 'Write', and 'Delete' Requests",
     "L2", "automated", "medium", "storage_accounts"),
    ("3.15", "Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'",
     "L1", "automated", "high", "storage_accounts"),

    # =========================================================================
    # Section 4: Database Services (~20 controls)
    # =========================================================================

    ("4.1.1", "Ensure That 'Auditing' is Set to 'On'",
     "L1", "automated", "high", "database_services"),
    ("4.1.2", "Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)",
     "L1", "automated", "high", "database_services"),
    ("4.1.3", "Ensure SQL Server's Transparent Data Encryption (TDE) Protector is Encrypted with Customer-Managed Key",
     "L2", "automated", "high", "database_services"),
    ("4.1.4", "Ensure that Azure Active Directory Admin is Configured for SQL Servers",
     "L1", "automated", "high", "database_services"),
    ("4.1.5", "Ensure That 'Data encryption' is Set to 'On' on a SQL Database",
     "L1", "automated", "high", "database_services"),
    ("4.1.6", "Ensure That 'Auditing' Retention is 'greater than 90 days' for SQL Servers",
     "L1", "automated", "medium", "database_services"),

    # 4.2 PostgreSQL
    ("4.2.1", "Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server",
     "L1", "automated", "high", "database_services"),
    ("4.2.2", "Ensure Server Parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server",
     "L1", "automated", "medium", "database_services"),
    ("4.2.3", "Ensure Server Parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server",
     "L1", "automated", "medium", "database_services"),
    ("4.2.4", "Ensure Server Parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server",
     "L1", "automated", "medium", "database_services"),
    ("4.2.5", "Ensure Server Parameter 'connection_throttle.enable' is set to 'ON' for PostgreSQL Flexible Server",
     "L1", "automated", "medium", "database_services"),
    ("4.2.6", "Ensure Server Parameter 'logfiles.retention_days' is greater than 3 days for PostgreSQL Flexible Server",
     "L1", "automated", "medium", "database_services"),
    ("4.2.7", "Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled",
     "L1", "automated", "high", "database_services"),
    ("4.2.8", "Ensure Private Endpoints are Used for PostgreSQL Flexible Server",
     "L2", "automated", "medium", "database_services"),

    # 4.3 MySQL
    ("4.3.1", "Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server",
     "L1", "automated", "high", "database_services"),
    ("4.3.2", "Ensure Server Parameter 'audit_log_enabled' is set to 'ON' for MySQL Flexible Server",
     "L1", "automated", "medium", "database_services"),
    ("4.3.3", "Ensure Server Parameter 'audit_log_events' has 'CONNECTION' set for MySQL Flexible Server",
     "L1", "automated", "medium", "database_services"),
    ("4.3.4", "Ensure 'TLS version' is set to 'TLSV1.2' (or higher) for MySQL Flexible Server",
     "L1", "automated", "high", "database_services"),

    # 4.4 Cosmos DB
    ("4.4.1", "Ensure That Azure Cosmos DB Accounts Have Customer-Managed Keys to Encrypt Data at Rest",
     "L2", "automated", "high", "database_services"),
    ("4.4.2", "Ensure Cosmos DB Account Access Is Restricted by Firewall",
     "L1", "automated", "high", "database_services"),
    ("4.4.3", "Use Microsoft Entra Client Authentication and Azure RBAC where possible",
     "L1", "manual", "high", "database_services"),

    # =========================================================================
    # Section 5: Logging and Monitoring (~15 controls)
    # =========================================================================

    # 5.1 Configuring Diagnostic Settings
    ("5.1.1", "Ensure That a 'Diagnostic Setting' Exists",
     "L1", "automated", "high", "logging_and_monitoring"),
    ("5.1.2", "Ensure Diagnostic Setting Captures Appropriate Categories",
     "L1", "automated", "high", "logging_and_monitoring"),
    ("5.1.3", "Ensure the Storage Account Containing the Container with Activity Logs is Encrypted with Customer Managed Key (CMK)",
     "L2", "automated", "medium", "logging_and_monitoring"),
    ("5.1.4", "Ensure that logging for Azure Key Vault is 'Enabled'",
     "L1", "automated", "high", "logging_and_monitoring"),
    ("5.1.5", "Ensure that Network Security Group Flow logs are captured and sent to Log Analytics",
     "L2", "automated", "medium", "logging_and_monitoring"),
    ("5.1.6", "Ensure that logging for Azure AppService 'HTTP Logs' is enabled",
     "L1", "automated", "medium", "logging_and_monitoring"),

    # 5.2 Monitoring using Activity Log Alerts
    ("5.2.1", "Ensure that Activity Log Alert exists for Create Policy Assignment",
     "L1", "automated", "medium", "logging_and_monitoring"),
    ("5.2.2", "Ensure that Activity Log Alert exists for Delete Policy Assignment",
     "L1", "automated", "medium", "logging_and_monitoring"),
    ("5.2.3", "Ensure that Activity Log Alert exists for Create or Update Network Security Group",
     "L1", "automated", "medium", "logging_and_monitoring"),
    ("5.2.4", "Ensure that Activity Log Alert exists for Delete Network Security Group",
     "L1", "automated", "medium", "logging_and_monitoring"),
    ("5.2.5", "Ensure that Activity Log Alert exists for Create or Update Security Solution",
     "L1", "automated", "medium", "logging_and_monitoring"),
    ("5.2.6", "Ensure that Activity Log Alert exists for Delete Security Solution",
     "L1", "automated", "medium", "logging_and_monitoring"),
    ("5.2.7", "Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule",
     "L1", "automated", "medium", "logging_and_monitoring"),
    ("5.2.8", "Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule",
     "L1", "automated", "medium", "logging_and_monitoring"),

    # 5.3 Configuring Application Insights
    ("5.3.1", "Ensure Application Insights are Configured",
     "L2", "automated", "medium", "logging_and_monitoring"),

    # 5.4 Ensure Azure Monitor
    ("5.4.1", "Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it",
     "L1", "manual", "medium", "logging_and_monitoring"),

    # =========================================================================
    # Section 6: Networking (~12 controls)
    # =========================================================================

    ("6.1", "Ensure that RDP access from the Internet is evaluated and restricted",
     "L1", "automated", "high", "networking"),
    ("6.2", "Ensure that SSH access from the Internet is evaluated and restricted",
     "L1", "automated", "high", "networking"),
    ("6.3", "Ensure that UDP access from the Internet is evaluated and restricted",
     "L1", "automated", "high", "networking"),
    ("6.4", "Ensure that HTTP(S) access from the Internet is evaluated and restricted",
     "L1", "automated", "medium", "networking"),
    ("6.5", "Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'",
     "L2", "automated", "medium", "networking"),
    ("6.6", "Ensure that Network Watcher is 'Enabled'",
     "L1", "automated", "high", "networking"),
    ("6.7", "Ensure that Public IP addresses are Evaluated on a Periodic Basis",
     "L1", "manual", "medium", "networking"),
    ("6.8", "Ensure that 'Enable Infrastructure Encryption' for Azure Service Bus Namespaces Is Set to 'True'",
     "L2", "automated", "medium", "networking"),
    ("6.9", "Ensure Virtual Network DNS Servers are Configured Properly",
     "L1", "manual", "medium", "networking"),
    ("6.10", "Ensure that All Network Interfaces Do Not Use Public IPs Unless Necessary",
     "L2", "automated", "medium", "networking"),
    ("6.11", "Ensure that Private Endpoints are Used for Azure Key Vault",
     "L2", "automated", "medium", "networking"),
    ("6.12", "Ensure that All Azure Resources within a Subscription Are Connected to a Virtual Network",
     "L2", "manual", "medium", "networking"),

    # =========================================================================
    # Section 7: Virtual Machines (~12 controls)
    # =========================================================================

    ("7.1", "Ensure an Azure Bastion Host Exists",
     "L2", "automated", "medium", "virtual_machines"),
    ("7.2", "Ensure Virtual Machines are Utilizing Managed Disks",
     "L1", "automated", "high", "virtual_machines"),
    ("7.3", "Ensure that 'OS and Data' disks are encrypted with Customer Managed Key (CMK)",
     "L2", "automated", "high", "virtual_machines"),
    ("7.4", "Ensure that 'Unattached disks' are encrypted with 'Customer Managed Key' (CMK)",
     "L2", "automated", "high", "virtual_machines"),
    ("7.5", "Ensure that Only Approved Extensions Are Installed",
     "L1", "manual", "medium", "virtual_machines"),
    ("7.6", "Ensure that Endpoint Protection for all Virtual Machines is installed",
     "L1", "automated", "high", "virtual_machines"),
    ("7.7", "Ensure that VHDs are Encrypted",
     "L2", "manual", "high", "virtual_machines"),
    ("7.8", "Ensure Only MFA Enabled Identities can Access Privileged Virtual Machine",
     "L2", "manual", "high", "virtual_machines"),
    ("7.9", "Ensure that Virtual Machines are backed up using Azure Backup",
     "L2", "automated", "medium", "virtual_machines"),
    ("7.10", "Ensure that Trusted Launch is enabled on Virtual Machines",
     "L1", "automated", "medium", "virtual_machines"),
    ("7.11", "Ensure that Auto-Update is Enabled for Azure Virtual Machines",
     "L1", "automated", "medium", "virtual_machines"),
    ("7.12", "Ensure that 'Disk Network Access' is NOT Set to 'Enable public access from all networks'",
     "L1", "automated", "high", "virtual_machines"),

    # =========================================================================
    # Section 8: Key Vault (~10 controls)
    # =========================================================================

    ("8.1", "Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults",
     "L1", "automated", "high", "key_vault"),
    ("8.2", "Ensure that the Expiration Date is set for all Keys in Non-RBAC Key Vaults",
     "L1", "automated", "high", "key_vault"),
    ("8.3", "Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults",
     "L1", "automated", "high", "key_vault"),
    ("8.4", "Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults",
     "L1", "automated", "high", "key_vault"),
    ("8.5", "Ensure that the Key Vault is Recoverable",
     "L1", "automated", "high", "key_vault"),
    ("8.6", "Enable Role Based Access Control for Azure Key Vault",
     "L2", "automated", "medium", "key_vault"),
    ("8.7", "Ensure that Private Endpoints are Used for Azure Key Vault",
     "L2", "automated", "medium", "key_vault"),
    ("8.8", "Ensure Automatic Key Rotation is Enabled Within Azure Key Vault for the Supported Services",
     "L2", "automated", "medium", "key_vault"),
    ("8.9", "Ensure that Azure Key Vault Managed HSM auto-rotation is Enabled for Key Stored in Azure Key Vault Managed HSM",
     "L2", "automated", "medium", "key_vault"),
    ("8.10", "Ensure that the Key Vault Firewall is Enabled",
     "L1", "automated", "high", "key_vault"),

    # =========================================================================
    # Section 9: App Service (~15 controls)
    # =========================================================================

    ("9.1", "Ensure App Service Authentication is set up for apps in Azure App Service",
     "L2", "automated", "medium", "app_service"),
    ("9.2", "Ensure Web App Redirects All HTTP traffic to HTTPS in Azure App Service",
     "L1", "automated", "high", "app_service"),
    ("9.3", "Ensure Web App is Using the Latest Version of TLS Encryption",
     "L1", "automated", "high", "app_service"),
    ("9.4", "Ensure the Web App has 'Client Certificates (Incoming client certificates)' set to 'On'",
     "L2", "automated", "medium", "app_service"),
    ("9.5", "Ensure that Register with Azure Active Directory is enabled on App Service",
     "L1", "automated", "medium", "app_service"),
    ("9.6", "Ensure That 'PHP version' is the Latest, If Used to Run the Web App",
     "L1", "automated", "medium", "app_service"),
    ("9.7", "Ensure That 'Python version' is the Latest Stable Version, If Used to Run the Web App",
     "L1", "automated", "medium", "app_service"),
    ("9.8", "Ensure That 'Java version' is the Latest, If Used to Run the Web App",
     "L1", "automated", "medium", "app_service"),
    ("9.9", "Ensure That 'HTTP Version' is the Latest, If Used to Run the Web App",
     "L1", "automated", "medium", "app_service"),
    ("9.10", "Ensure FTP deployments are Disabled",
     "L1", "automated", "high", "app_service"),
    ("9.11", "Ensure Azure Key Vaults are Used to Store Secrets",
     "L2", "manual", "high", "app_service"),
    ("9.12", "Ensure that 'Basic Authentication' is disabled for App Service Deployment",
     "L1", "automated", "high", "app_service"),
    ("9.13", "Ensure that 'Basic Authentication' is disabled for Function App Deployment",
     "L1", "automated", "high", "app_service"),
    ("9.14", "Ensure App Service is Configured to Use a Managed Identity",
     "L1", "automated", "medium", "app_service"),
    ("9.15", "Ensure that Remote Debugging is not enabled for App Services",
     "L1", "automated", "high", "app_service"),

    # =========================================================================
    # Section 10: Miscellaneous (~10 controls)
    # =========================================================================

    ("10.1", "Ensure that Resource Locks are set for Mission-Critical Azure Resources",
     "L2", "manual", "medium", "miscellaneous"),
    ("10.2", "Ensure that All Resources have a Tag Defining the Owner",
     "L2", "manual", "low", "miscellaneous"),
    ("10.3", "Ensure that All Resources have a Tag Defining the Environment",
     "L2", "manual", "low", "miscellaneous"),
    ("10.4", "Ensure that All Resources have a Tag Defining Creation Date",
     "L2", "manual", "low", "miscellaneous"),
    ("10.5", "Ensure that All Resources have a Tag Defining the Cost Center",
     "L2", "manual", "low", "miscellaneous"),
    ("10.6", "Ensure that Azure Subscriptions have a Security Contact assigned",
     "L1", "automated", "high", "miscellaneous"),
    ("10.7", "Ensure that 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering Microsoft Entra tenant' is set to 'Permit no one'",
     "L1", "automated", "high", "miscellaneous"),
    ("10.8", "Ensure that Azure Advisor Recommendations are reviewed and resolved at a regular cadence",
     "L1", "manual", "medium", "miscellaneous"),
    ("10.9", "Ensure Azure DevOps PATs are Not Stored in Plaintext",
     "L1", "manual", "high", "miscellaneous"),
    ("10.10", "Ensure that Management Certificates Are Not Used",
     "L1", "automated", "high", "miscellaneous"),
]


def get_azure_cis_registry():
    """Return the complete CIS Azure control registry as a list of dicts."""
    return [
        {
            "cis_control_id": ctrl[0],
            "title": ctrl[1],
            "cis_level": ctrl[2],
            "assessment_type": ctrl[3],
            "severity": ctrl[4],
            "service_area": ctrl[5],
        }
        for ctrl in AZURE_CIS_CONTROLS
    ]


def get_azure_control_count():
    """Return total number of CIS Azure controls."""
    return len(AZURE_CIS_CONTROLS)


def get_azure_automated_count():
    """Return count of automated controls."""
    return sum(1 for c in AZURE_CIS_CONTROLS if c[3] == "automated")


def get_azure_manual_count():
    """Return count of manual controls."""
    return sum(1 for c in AZURE_CIS_CONTROLS if c[3] == "manual")


def get_azure_controls_by_section(section_prefix):
    """Return controls for a given section (e.g., '1' for IAM, '2' for Defender).

    Args:
        section_prefix: String prefix to match CIS IDs (e.g., "1", "2.1", "4.2").

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
        for ctrl in AZURE_CIS_CONTROLS
        if ctrl[0].startswith(section_prefix + ".") or ctrl[0] == section_prefix
    ]


def get_azure_controls_by_service_area(service_area):
    """Return controls for a given service area.

    Args:
        service_area: One of 'identity_and_access_management', 'microsoft_defender',
                      'storage_accounts', 'database_services', 'logging_and_monitoring',
                      'networking', 'virtual_machines', 'key_vault', 'app_service',
                      'miscellaneous'.

    Returns:
        List of control dicts for the specified service area.
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
        for ctrl in AZURE_CIS_CONTROLS
        if ctrl[5] == service_area
    ]


def get_azure_controls_by_severity(severity):
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
        for ctrl in AZURE_CIS_CONTROLS
        if ctrl[4] == severity
    ]


def get_azure_controls_by_level(level):
    """Return controls filtered by CIS level.

    Args:
        level: "L1" or "L2".

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
        for ctrl in AZURE_CIS_CONTROLS
        if ctrl[2] == level
    ]
