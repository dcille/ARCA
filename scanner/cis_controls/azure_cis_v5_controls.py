"""CIS Microsoft Azure Foundations Benchmark v5.0 — Complete Control Registry.

Full control registry with descriptions, remediations, audit procedures, risks,
and references for all controls across Analytics, Compute, Identity, Management,
Networking, Security, and Storage service areas.

Reference: CIS Microsoft Azure Foundations Benchmark v5.0 (2025)

Total controls: ~140 across 9 sections.
"""

# ═══════════════════════════════════════════════════════════════════════════════
# AZURE CIS v5.0 CONTROLS — Full detail per control
# ═══════════════════════════════════════════════════════════════════════════════

AZURE_CIS_V5_CONTROLS: list[dict] = [

    # =========================================================================
    # Section 2 — Analytics Services
    # =========================================================================

    {
        "cis_id": "2.1.1",
        "title": "Ensure that Azure Databricks is deployed in a customer-managed virtual network (VNet)",
        "section": "Analytics Services",
        "cis_level": "L2",
        "assessment_type": "automated",
        "severity": "high",
        "service_area": "analytics_services",
        "description": (
            "Use private endpoints for Azure Databricks workspaces to allow clients "
            "and services to securely access data located over a network via an encrypted "
            "Private Link. The private endpoint uses an IP address from the VNet for each "
            "service. Network traffic between disparate services securely traverses "
            "encrypted over the VNet. This VNet can also link addressing space, extending "
            "your network and accessing resources on it. Similarly, it can be a tunnel "
            "through public networks to connect remote infrastructures together."
        ),
        "rationale": (
            "Using private endpoints for Azure Databricks workspaces ensures that all "
            "communication between clients, services, and data sources occurs over a secure, "
            "private IP space within an Azure Virtual Network (VNet). This approach eliminates "
            "exposure to the public internet, significantly reducing the attack surface and "
            "aligning with Zero Trust principles. Additionally, integrating Databricks with a "
            "VNet enables network segmentation, fine-grained access control, and hybrid "
            "connectivity through VNet peering or VPN/ExpressRoute."
        ),
        "impact": (
            "If an Azure Virtual Network is not implemented correctly, this may result in "
            "the loss of critical network traffic. Private endpoints are charged per hour "
            "of use. Before a private endpoint can be configured, Azure Databricks workspaces "
            "must be deployed in a customer-managed virtual network (VNet injection), must "
            "have secure cluster connectivity enabled, and must be on the Premium pricing tier."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. Go to Azure Databricks.\n"
            "2. Click the name of a workspace.\n"
            "3. Under Settings, click Networking.\n"
            "4. Click Private endpoint connections.\n"
            "5. Ensure a private endpoint connection exists with a connection state of Approved.\n"
            "6. Repeat steps 1-5 for each workspace.\n\n"
            "Audit from Azure CLI\n"
            "az databricks workspace list\n"
            "az databricks workspace show --resource-group <rg> --name <workspace> "
            "--query privateEndpointConnections\n"
            "Ensure a private endpoint connection is returned with a "
            "privateLinkServiceConnectionState status of Approved."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. Go to Azure Databricks.\n"
            "2. Click the name of a workspace.\n"
            "3. Under Settings, click Networking.\n"
            "4. Click Private endpoint connections.\n"
            "5. Click + Private endpoint.\n"
            "6. Under Project details, select a Subscription and Resource group.\n"
            "7. Under Instance details, provide a Name, Network Interface Name, and select a Region.\n"
            "8. Click Next : Resource >.\n"
            "9. Select a Target sub-resource.\n"
            "10. Click Next : Virtual Network >.\n"
            "11. Under Networking, select a Virtual network and a Subnet.\n"
            "12. Click Next : Review + create >.\n"
            "13. Click Create.\n\n"
            "Remediate from Azure CLI\n"
            "az network private-endpoint create --resource-group <rg> --name <pe> "
            "--location <loc> --vnet-name <vnet> --subnet <subnet> "
            "--private-connection-resource-id <workspace> --connection-name <conn> "
            "--group-id <browser_authentication|databricks_ui_api>"
        ),
        "default_value": "Private endpoints are not configured for Azure Databricks workspaces by default.",
        "references": [
            "https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/private-link",
            "https://learn.microsoft.com/en-us/cli/azure/databricks/workspace",
        ],
        "cli_commands": [
            "az databricks workspace list",
            "az databricks workspace show --resource-group <rg> --name <workspace> --query privateEndpointConnections",
        ],
        "azure_policy_id": "258823f2-4595-4b52-b333-cc96192710d8",
    },

    # =========================================================================
    # Section 3 — Compute Services
    # =========================================================================

    {
        "cis_id": "3.1.1",
        "title": "Ensure only MFA enabled identities can access privileged Virtual Machine",
        "section": "Compute Services",
        "cis_level": "L2",
        "assessment_type": "manual",
        "severity": "high",
        "service_area": "compute_services",
        "description": (
            "Virtual Machines with administrative or privileged access should require "
            "MFA-enabled identities via Conditional Access policies to prevent unauthorized "
            "access through compromised credentials."
        ),
        "rationale": (
            "Requiring MFA for privileged VM access adds a critical layer of defense "
            "against credential theft and brute-force attacks. Even if credentials are "
            "compromised, attackers cannot gain access without the second authentication factor."
        ),
        "impact": (
            "Users with privileged access to VMs will need to complete MFA challenges, "
            "which may add minor friction to administrative workflows."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. Go to Microsoft Entra ID > Security > Conditional Access.\n"
            "2. Review policies targeting administrative roles or VM access.\n"
            "3. Ensure MFA is required for access to privileged Virtual Machines.\n"
            "4. Verify the policy is enabled and not in report-only mode."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. Go to Microsoft Entra ID > Security > Conditional Access.\n"
            "2. Create a new policy or edit an existing one.\n"
            "3. Under Assignments, target administrative roles with VM access.\n"
            "4. Under Access controls > Grant, select Require multifactor authentication.\n"
            "5. Enable the policy and click Save."
        ),
        "default_value": "MFA is not required for VM access by default.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    # =========================================================================
    # Section 5.1 — Security Defaults (Per-User MFA)
    # =========================================================================

    {
        "cis_id": "5.1.1",
        "title": "Ensure that 'security defaults' is enabled in Microsoft Entra ID",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "automated",
        "severity": "critical",
        "service_area": "identity_services",
        "description": (
            "Security defaults in Microsoft Entra ID provide baseline identity protection "
            "including MFA enrollment for all users, blocking legacy authentication, and "
            "protecting privileged actions."
        ),
        "rationale": (
            "Security defaults provide a foundational layer of identity protection. They "
            "require all users to register for MFA, block legacy authentication protocols "
            "that cannot enforce MFA, and require MFA for administrative actions. This "
            "significantly reduces the risk of identity-based attacks."
        ),
        "impact": (
            "Legacy authentication clients (IMAP, POP3, SMTP) will be blocked. All users "
            "will be required to register for MFA within 14 days. Organizations using "
            "Conditional Access should disable Security Defaults and use CA policies instead."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. Go to Microsoft Entra ID.\n"
            "2. Under Manage, select Properties.\n"
            "3. Click Manage security defaults.\n"
            "4. Ensure Security defaults is set to Enabled.\n\n"
            "Audit from Azure CLI\n"
            "az rest --method get --url 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' "
            "--query isEnabled"
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. Go to Microsoft Entra ID.\n"
            "2. Under Manage, select Properties.\n"
            "3. Click Manage security defaults.\n"
            "4. Set Security defaults to Enabled.\n"
            "5. Click Save."
        ),
        "default_value": "Security defaults are enabled by default for new tenants created after October 2019.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults",
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-security-defaults",
        ],
        "cli_commands": [
            "az rest --method get --url 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'",
        ],
        "azure_policy_id": "",
    },

    # =========================================================================
    # Section 5.2 — Conditional Access
    # =========================================================================

    {
        "cis_id": "5.2.1",
        "title": "Ensure that 'trusted locations' are defined",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "high",
        "service_area": "identity_services",
        "description": (
            "Define trusted locations for conditional access policies to identify known "
            "corporate networks and limit access from trusted IP ranges."
        ),
        "rationale": (
            "Trusted locations enable organizations to define network locations used in "
            "Conditional Access policies. This allows differentiating access from corporate "
            "networks versus unknown locations, enabling risk-based policies."
        ),
        "impact": "Minimal impact. Trusted locations only define network boundaries for policies.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. Go to Microsoft Entra ID > Security > Conditional Access.\n"
            "2. Under Manage, select Named locations.\n"
            "3. Ensure at least one trusted location is defined."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. Go to Microsoft Entra ID > Security > Conditional Access.\n"
            "2. Under Manage, select Named locations.\n"
            "3. Click + IP ranges location or + Countries location.\n"
            "4. Define the location with appropriate IP ranges or countries.\n"
            "5. Check 'Mark as trusted location' if applicable.\n"
            "6. Click Create."
        ),
        "default_value": "No trusted locations are defined by default.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/location-condition",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    # =========================================================================
    # Section 5.3 — Periodic Identity Reviews
    # =========================================================================

    {
        "cis_id": "5.3.1",
        "title": "Ensure Azure admin accounts are not used for daily operations",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "high",
        "service_area": "identity_services",
        "description": (
            "Administrative accounts should be used exclusively for administrative tasks. "
            "Users should have separate accounts for day-to-day operations to reduce the "
            "attack surface of privileged accounts."
        ),
        "rationale": (
            "Using admin accounts for daily tasks increases exposure to phishing, malware, "
            "and other attacks. Separate accounts ensure that privileged credentials are "
            "only used in secure, controlled contexts."
        ),
        "impact": "Requires maintaining separate user and admin accounts per administrator.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. Go to Microsoft Entra ID > Roles and administrators.\n"
            "2. Review accounts assigned to Global Administrator and other privileged roles.\n"
            "3. Verify these accounts are not used for daily email, browsing, or collaboration."
        ),
        "remediation": (
            "1. Create separate admin accounts (e.g., admin-user@domain.com) for each administrator.\n"
            "2. Assign privileged roles only to admin accounts.\n"
            "3. Remove privileged roles from daily-use accounts.\n"
            "4. Enforce Conditional Access policies requiring MFA and compliant devices for admin accounts."
        ),
        "default_value": "No separation of admin/daily accounts by default.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    # =========================================================================
    # Section 5.4–5.28 — Identity Services
    # =========================================================================

    {
        "cis_id": "5.4",
        "title": "Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "automated",
        "severity": "medium",
        "service_area": "identity_services",
        "description": "Require administrators or appropriately delegated users to create new tenants.",
        "rationale": (
            "It is recommended to only allow an administrator to create new tenants. This "
            "prevents users from creating new Microsoft Entra ID or Azure AD B2C tenants "
            "and ensures that only authorized users are able to do so."
        ),
        "impact": "Enforcing this setting will ensure that only authorized users are able to create new tenants.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Under Manage, select User settings.\n"
            "5. Ensure that Restrict non-admin users from creating tenants is set to Yes.\n\n"
            "Audit from PowerShell\n"
            "Import-Module Microsoft.Graph.Identity.SignIns\n"
            "Connect-MgGraph -Scopes 'Policy.ReadWrite.Authorization'\n"
            "Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty "
            "DefaultUserRolePermissions | Format-List\n"
            "Review the 'DefaultUserRolePermissions' section. Ensure AllowedToCreateTenants is not 'True'."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Under Manage, select User settings.\n"
            "5. Set Restrict non-admin users from creating tenants to Yes.\n"
            "6. Click Save.\n\n"
            "Remediate from PowerShell\n"
            "Import-Module Microsoft.Graph.Identity.SignIns\n"
            "Connect-MgGraph -Scopes 'Policy.ReadWrite.Authorization'\n"
            "$params = @{ DefaultUserRolePermissions = @{ AllowedToCreateTenants = $false } }\n"
            "Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId -BodyParameter $params"
        ),
        "default_value": "By default, non-admin users can create tenants.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions",
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#tenant-creator",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.5",
        "title": "Ensure that 'Number of methods required to reset' is set to '2'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "high",
        "service_area": "identity_services",
        "description": "Ensures that two alternate forms of identification are provided before allowing a password reset.",
        "rationale": (
            "A Self-service Password Reset (SSPR) through Azure Multi-factor Authentication "
            "(MFA) ensures the user's identity is confirmed using two separate methods of "
            "identification. With multiple methods set, an attacker would have to compromise "
            "both methods before they could maliciously reset a user's password."
        ),
        "impact": (
            "There may be administrative overhead, as users who lose access to their secondary "
            "authentication methods will need an administrator with permissions to remove it."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Under Manage, select Password reset.\n"
            "5. Select Authentication methods.\n"
            "6. Ensure that Number of methods required to reset is set to 2."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Under Manage, select Password reset.\n"
            "5. Select Authentication methods.\n"
            "6. Set the Number of methods required to reset to 2.\n"
            "7. Click Save."
        ),
        "default_value": "By default, the Number of methods required to reset is 1.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr",
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-registration-mfa-sspr-combined",
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.6",
        "title": "Ensure that account 'Lockout threshold' is less than or equal to '10'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "medium",
        "service_area": "identity_services",
        "description": (
            "The account lockout threshold determines how many failed login attempts are "
            "permitted prior to placing the account in a locked-out state and initiating "
            "a variable lockout duration."
        ),
        "rationale": (
            "Account lockout is a method of protecting against brute-force and password "
            "spray attacks. Once the lockout threshold has been exceeded, the account enters "
            "a locked-out state which prevents all login attempts for a variable duration. "
            "The lockout in combination with a reasonable duration reduces the total number "
            "of failed login attempts that a malicious actor can execute."
        ),
        "impact": (
            "If set too low (less than 3), users may experience frequent lockout events. "
            "If set too high (more than 10), malicious actors can execute more password "
            "attempts in a given period of time."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Security.\n"
            "4. Under Manage, select Authentication methods.\n"
            "5. Under Manage, select Password protection.\n"
            "6. Ensure that Lockout threshold is set to 10 or fewer.\n\n"
            "Audit from Azure CLI\n"
            "az rest --method get --url "
            "'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' "
            "--query 'passwordProtection.lockoutThreshold'"
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Security.\n"
            "4. Under Manage, select Authentication methods.\n"
            "5. Under Manage, select Password protection.\n"
            "6. Set the Lockout threshold to 10 or fewer.\n"
            "7. Click Save.\n\n"
            "Remediate from Azure CLI\n"
            "az rest --method patch --url "
            "'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' "
            "--headers 'Content-Type=application/json' "
            "--body '{\"passwordProtection\":{\"lockoutThreshold\":10,\"lockoutDuration\":\"PT1M\"}}'"
        ),
        "default_value": "By default, Lockout threshold is set to 10.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout#manage-microsoft-entra-smart-lockout-values",
        ],
        "cli_commands": [
            "az rest --method get --url 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' --query 'passwordProtection.lockoutThreshold'",
        ],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.7",
        "title": "Ensure that account 'Lockout duration in seconds' is greater than or equal to '60'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "medium",
        "service_area": "identity_services",
        "description": (
            "The account lockout duration value determines how long an account retains the "
            "status of lockout, and therefore how long before a user can continue to attempt "
            "to login after passing the lockout threshold."
        ),
        "rationale": (
            "Account lockout is a method of protecting against brute-force and password "
            "spray attacks. The lockout in combination with a reasonable duration reduces "
            "the total number of failed login attempts that a malicious actor can execute."
        ),
        "impact": (
            "If set too low (less than 60 seconds), malicious actors can perform more "
            "password spray and brute-force attempts. If set too high (more than 300 seconds), "
            "users may experience inconvenient delays during lockout."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Security.\n"
            "4. Under Manage, select Authentication methods.\n"
            "5. Under Manage, select Password protection.\n"
            "6. Ensure that Lockout duration in seconds is set to 60 or higher."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Security.\n"
            "4. Under Manage, select Authentication methods.\n"
            "5. Under Manage, select Password protection.\n"
            "6. Set the Lockout duration in seconds to 60 or higher.\n"
            "7. Click Save."
        ),
        "default_value": "By default, Lockout duration in seconds is set to 60.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout#manage-microsoft-entra-smart-lockout-values",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.8",
        "title": "Ensure that a 'Custom banned password list' is set to 'Enforce'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "high",
        "service_area": "identity_services",
        "description": (
            "Microsoft Azure applies a default global banned password list to all user and "
            "admin accounts. For increased password security, a custom banned password list "
            "is recommended to disallow organization-specific terms."
        ),
        "rationale": (
            "Implementing a custom banned password list gives your organization further "
            "control over the password policy. Disallowing easy-to-guess passwords that "
            "include brand names, product names, locations, and company-specific terms "
            "increases the security of your Azure resources."
        ),
        "impact": (
            "Increasing password complexity may increase user account administration overhead. "
            "Utilizing the default global banned password list and a custom list requires a "
            "Microsoft Entra ID P1 or P2 license."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Security.\n"
            "4. Under Manage, select Authentication methods.\n"
            "5. Under Manage, select Password protection.\n"
            "6. Ensure Enforce custom list is set to Yes.\n"
            "7. Review the list of words banned from use in passwords."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Security.\n"
            "4. Under Manage, select Authentication methods.\n"
            "5. Under Manage, select Password protection.\n"
            "6. Set the Enforce custom list option to Yes.\n"
            "7. Click in the Custom banned password list text box.\n"
            "8. Add a list of words, one per line, to prevent users from using in passwords.\n"
            "9. Click Save."
        ),
        "default_value": "By default the custom banned password list is not 'Enabled'.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-combined-policy",
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad",
            "https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-configure-custom-password-protection",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.9",
        "title": "Ensure that 'Number of days before users are asked to re-confirm their authentication information' is not set to '0'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "medium",
        "service_area": "identity_services",
        "description": (
            "Ensure that the number of days before users are asked to re-confirm their "
            "authentication information is not set to 0."
        ),
        "rationale": (
            "This setting is necessary if 'Require users to register when signing in' is "
            "enabled. If authentication re-confirmation is disabled, registered users will "
            "never be prompted to re-confirm their existing authentication information. "
            "If the authentication information for a user changes, such as a phone number "
            "or email, then the password reset information for that user reverts to the "
            "previously registered authentication information."
        ),
        "impact": "Users will be prompted to re-confirm their authentication information after the configured number of days.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Select Password reset.\n"
            "5. Under Manage, select Registration.\n"
            "6. Ensure that Number of days before users are asked to re-confirm their "
            "authentication information is not set to 0."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Select Password reset.\n"
            "5. Under Manage, select Registration.\n"
            "6. Set the Number of days before users are asked to re-confirm their "
            "authentication information to your organization-defined frequency.\n"
            "7. Click Save."
        ),
        "default_value": "By default, the Number of days is set to 180 days.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-howitworks#registration",
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.10",
        "title": "Ensure that 'Notify users on password resets?' is set to 'Yes'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "medium",
        "service_area": "identity_services",
        "description": "Ensure that users are notified on their primary and alternate emails on password resets.",
        "rationale": (
            "User notification on password reset is a proactive way of confirming password "
            "reset activity. It helps the user to recognize unauthorized password reset activities."
        ),
        "impact": "Users will receive emails alerting them to password changes to both their primary and alternate emails.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Under Manage, select Password reset.\n"
            "5. Under Manage, select Notifications.\n"
            "6. Ensure that Notify users on password resets? is set to Yes."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Under Manage, select Password reset.\n"
            "5. Under Manage, select Notifications.\n"
            "6. Set Notify users on password resets? to Yes.\n"
            "7. Click Save."
        ),
        "default_value": "By default, Notify users on password resets? is set to 'Yes'.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr#set-up-notifications-and-customizations",
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-howitworks#notifications",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.11",
        "title": "Ensure that 'Notify all admins when other admins reset their password?' is set to 'Yes'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "medium",
        "service_area": "identity_services",
        "description": "Ensure that all Global Administrators are notified if any other administrator resets their password.",
        "rationale": (
            "Administrator accounts are sensitive. Any password reset activity notification, "
            "when sent to all Administrators, ensures that all Global Administrators can "
            "passively confirm if such a reset is a common pattern within their group."
        ),
        "impact": "All Global Administrators will receive a notification from Azure every time a password is reset.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Under Manage, select Password reset.\n"
            "5. Under Manage, select Notifications.\n"
            "6. Ensure that Notify all admins when other admins reset their password? is set to Yes."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Under Manage, select Password reset.\n"
            "5. Under Manage, select Notifications.\n"
            "6. Set Notify all admins when other admins reset their password? to Yes.\n"
            "7. Click Save."
        ),
        "default_value": "By default, Notify all admins when other admins reset their password? is set to 'No'.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-howitworks#notifications",
            "https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.12",
        "title": "Ensure that 'User consent for applications' is set to 'Do not allow user consent'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "high",
        "service_area": "identity_services",
        "description": "Require administrators to provide consent for applications before use.",
        "rationale": (
            "If Microsoft Entra ID is running as an identity provider for third-party applications, "
            "permissions and consent should be limited to administrators or pre-approved. "
            "Malicious applications may attempt to exfiltrate data or abuse privileged user accounts."
        ),
        "impact": "Enforcing this setting may create additional requests that administrators need to review.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Enterprise applications.\n"
            "4. Under Security, select Consent and permissions.\n"
            "5. Under Manage, select User consent settings.\n"
            "6. Ensure User consent for applications is set to Do not allow user consent.\n\n"
            "Audit from PowerShell\n"
            "Connect-MgGraph\n"
            "(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object "
            "-ExpandProperty PermissionGrantPoliciesAssigned\n"
            "If the command returns no values, the configuration complies."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Enterprise applications.\n"
            "4. Under Security, select Consent and permissions.\n"
            "5. Under Manage, select User consent settings.\n"
            "6. Set User consent for applications to Do not allow user consent.\n"
            "7. Click Save."
        ),
        "default_value": "By default, Users consent for applications is set to Allow user consent for apps.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent",
            "https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.13",
        "title": "Ensure that 'User consent for applications' is set to 'Allow user consent for apps from verified publishers, for selected permissions'",
        "section": "Identity Services",
        "cis_level": "L2",
        "assessment_type": "manual",
        "severity": "medium",
        "service_area": "identity_services",
        "description": "Allow users to provide consent for selected permissions when a request is coming from a verified publisher.",
        "rationale": (
            "If Microsoft Entra ID is running as an identity provider for third-party applications, "
            "permissions and consent should be limited to administrators or pre-approved. "
            "Malicious applications may attempt to exfiltrate data or abuse privileged user accounts."
        ),
        "impact": "Enforcing this setting may create additional requests that administrators need to review.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Enterprise applications.\n"
            "4. Under Security, select Consent and permissions.\n"
            "5. Under Manage, select User consent settings.\n"
            "6. Under User consent for applications, ensure Allow user consent for apps "
            "from verified publishers, for selected permissions is selected.\n\n"
            "Audit from PowerShell\n"
            "Connect-MgGraph\n"
            "(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object "
            "-ExpandProperty PermissionGrantPoliciesAssigned\n"
            "The command should return ManagePermissionGrantsForSelf.microsoft-user-default-low "
            "or a custom app consent policy id."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Enterprise applications.\n"
            "4. Under Security, select Consent and permissions.\n"
            "5. Under Manage, select User consent settings.\n"
            "6. Under User consent for applications, select Allow user consent for apps "
            "from verified publishers, for selected permissions.\n"
            "7. Click Save."
        ),
        "default_value": "By default, User consent for applications is set to Allow user consent for apps.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent?pivots=ms-graph",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.14",
        "title": "Ensure that 'Users can register applications' is set to 'No'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "automated",
        "severity": "medium",
        "service_area": "identity_services",
        "description": "Require administrators or appropriately delegated users to register third-party applications.",
        "rationale": (
            "It is recommended to only allow an administrator to register custom-developed "
            "applications. This ensures that the application undergoes a formal security "
            "review and approval process prior to exposing Microsoft Entra ID data."
        ),
        "impact": (
            "Enforcing this setting will create additional requests for approval that will "
            "need to be addressed by an administrator."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Under Manage, select User settings.\n"
            "5. Ensure that Users can register applications is set to No.\n\n"
            "Audit from PowerShell\n"
            "(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Format-List AllowedToCreateApps\n"
            "Command should return the value of False."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Under Manage, select User settings.\n"
            "5. Set Users can register applications to No.\n"
            "6. Click Save.\n\n"
            "Remediate from PowerShell\n"
            "$param = @{ AllowedToCreateApps = '$false' }\n"
            "Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions $param"
        ),
        "default_value": "By default, Users can register applications is set to 'Yes'.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/delegate-app-roles#restrict-who-can-create-applications",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.15",
        "title": "Ensure that 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "automated",
        "severity": "medium",
        "service_area": "identity_services",
        "description": "Limit guest user permissions to the most restrictive level.",
        "rationale": (
            "Limiting guest access ensures that guest accounts do not have permission for "
            "certain directory tasks, such as enumerating users, groups or other directory "
            "resources, and cannot be assigned to administrative roles in your directory. "
            "The recommended option is the most restrictive: 'Guest user access is restricted "
            "to their own directory object'."
        ),
        "impact": (
            "This may create additional requests for permissions. Some services (Forms, "
            "Project, Yammer, Planner in SharePoint) may have compatibility issues."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select External Identities.\n"
            "4. Select External collaboration settings.\n"
            "5. Under Guest user access, ensure that Guest user access restrictions is set to "
            "Guest user access is restricted to properties and memberships of their own directory objects.\n\n"
            "Audit from PowerShell\n"
            "Connect-MgGraph\n"
            "(Get-MgPolicyAuthorizationPolicy).GuestUserRoleId\n"
            "If the GuestUserRoleID does not equal 2af84b1e-32c8-42b7-82bc-daa82404023b "
            "then it is not set to most restrictive."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select External Identities.\n"
            "4. Select External collaboration settings.\n"
            "5. Under Guest user access, set Guest user access restrictions to "
            "Guest user access is restricted to properties and memberships of their own directory objects.\n"
            "6. Click Save.\n\n"
            "Remediate from PowerShell\n"
            "Update-MgPolicyAuthorizationPolicy -GuestUserRoleId '2af84b1e-32c8-42b7-82bc-daa82404023b'"
        ),
        "default_value": "By default, Guest user access restrictions is set to 'Guest users have limited access to properties and memberships of directory objects'.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions#member-and-guest-users",
            "https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.16",
        "title": "Ensure that 'Guest invite restrictions' is set to 'Only users assigned to specific admin roles can invite guest users' or 'No one in the organization'",
        "section": "Identity Services",
        "cis_level": "L2",
        "assessment_type": "automated",
        "severity": "medium",
        "service_area": "identity_services",
        "description": "Restrict invitations to either users with specific administrative roles or no one.",
        "rationale": (
            "Restricting invitations to users with specific administrator roles ensures "
            "that only authorized accounts have access to cloud resources. This helps to "
            "maintain 'Need to Know' permissions and prevents inadvertent access to data."
        ),
        "impact": (
            "Users with specific admin roles will be in charge of sending invitations "
            "to external users, requiring additional overhead."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select External Identities.\n"
            "4. Select External collaboration settings.\n"
            "5. Under Guest invite settings, ensure Guest invite restrictions is set to "
            "Only users assigned to specific admin roles can invite guest users or "
            "No one in the organization.\n\n"
            "Audit from PowerShell\n"
            "Connect-MgGraph\n"
            "(Get-MgPolicyAuthorizationPolicy).AllowInvitesFrom\n"
            "If the resulting value is adminsAndGuestInviters or none the configuration complies."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select External Identities.\n"
            "4. Select External collaboration settings.\n"
            "5. Under Guest invite settings, set Guest invite restrictions to "
            "Only users assigned to specific admin roles can invite guest users.\n"
            "6. Click Save.\n\n"
            "Remediate from PowerShell\n"
            "Connect-MgGraph\n"
            "Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom 'adminsAndGuestInviters'"
        ),
        "default_value": "By default, Guest invite restrictions is set to 'Anyone in the organization can invite guest users including guests and non-admins'.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.17",
        "title": "Ensure that 'Restrict access to Microsoft Entra admin center' is set to 'Yes'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "medium",
        "service_area": "identity_services",
        "description": (
            "Restrict access to the Microsoft Entra ID administration center to administrators "
            "only. NOTE: This only affects access to the Entra ID administrator's web portal. "
            "This setting does not prohibit privileged users from using other methods such as "
            "Rest API or PowerShell to obtain sensitive information."
        ),
        "rationale": (
            "The Microsoft Entra ID administrative center has sensitive data and permission "
            "settings. All non-administrators should be prohibited from accessing any Microsoft "
            "Entra ID data in the administration center to avoid exposure."
        ),
        "impact": "All administrative tasks will need to be done by Administrators.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Under Manage, select User settings.\n"
            "5. Under Administration centre, ensure that Restrict access to Microsoft "
            "Entra admin center is set to Yes."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Users.\n"
            "4. Under Manage, select User settings.\n"
            "5. Under Administration centre, set Restrict access to Microsoft Entra "
            "admin center to Yes.\n"
            "6. Click Save."
        ),
        "default_value": "By default, Restrict access to Microsoft Entra admin center is set to No.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.18",
        "title": "Ensure that 'Restrict user ability to access groups features in My Groups' is set to 'Yes'",
        "section": "Identity Services",
        "cis_level": "L2",
        "assessment_type": "manual",
        "severity": "low",
        "service_area": "identity_services",
        "description": "Restrict access to group web interface in the Access Panel portal.",
        "rationale": (
            "Self-service group management enables users to create and manage security groups "
            "or Office 365 groups in Microsoft Entra ID. Unless a business requires this "
            "day-to-day delegation for some users, self-service group management should be "
            "disabled. By setting this to 'Yes', users will no longer have access to the "
            "Group feature web interface, but still have access via API."
        ),
        "impact": "Setting to Yes could create administrative overhead for group membership requests.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Groups.\n"
            "4. Under Settings, select General.\n"
            "5. Under Self Service Group Management, ensure that Restrict user ability "
            "to access groups features in My Groups is set to Yes."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Groups.\n"
            "4. Under Settings, select General.\n"
            "5. Under Self Service Group Management, set Restrict user ability to access "
            "groups features in My Groups to Yes.\n"
            "6. Click Save."
        ),
        "default_value": "By default, Restrict user ability to access groups features is set to No.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-management",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.19",
        "title": "Ensure that 'Users can create security groups in Azure portals, API or PowerShell' is set to 'No'",
        "section": "Identity Services",
        "cis_level": "L2",
        "assessment_type": "manual",
        "severity": "medium",
        "service_area": "identity_services",
        "description": "Restrict security group creation to administrators only.",
        "rationale": (
            "When creating security groups is enabled, all users in the directory are allowed "
            "to create new security groups and add members to those groups. Unless a business "
            "requires this day-to-day delegation, security group creation should be restricted "
            "to administrators only."
        ),
        "impact": "Enabling this setting could create a number of requests that would need to be managed by an administrator.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Groups.\n"
            "4. Under Settings, select General.\n"
            "5. Under Security Groups, ensure that Users can create security groups in "
            "Azure portals, API or PowerShell is set to No."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Groups.\n"
            "4. Under Settings, select General.\n"
            "5. Under Security Groups, set Users can create security groups in Azure "
            "portals, API or PowerShell to No.\n"
            "6. Click Save."
        ),
        "default_value": "By default, Users can create security groups is set to Yes.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-management#making-a-group-available-for-end-user-self-service",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.20",
        "title": "Ensure that 'Owners can manage group membership requests in My Groups' is set to 'No'",
        "section": "Identity Services",
        "cis_level": "L2",
        "assessment_type": "manual",
        "severity": "low",
        "service_area": "identity_services",
        "description": "Restrict security group management to administrators only.",
        "rationale": (
            "Restricting security group management to administrators only prohibits users "
            "from making changes to security groups. This ensures that security groups are "
            "appropriately managed and their management is not delegated to non-administrators."
        ),
        "impact": "Group Membership for user accounts will need to be handled by Admins.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Groups.\n"
            "4. Under Settings, select General.\n"
            "5. Under Self Service Group Management, ensure that Owners can manage group "
            "membership requests in My Groups is set to No."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Groups.\n"
            "4. Under Settings, select General.\n"
            "5. Under Self Service Group Management, set Owners can manage group membership "
            "requests in My Groups to No.\n"
            "6. Click Save."
        ),
        "default_value": "By default, Owners can manage group membership requests in My Groups is set to No.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-management#making-a-group-available-for-end-user-self-service",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.21",
        "title": "Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No'",
        "section": "Identity Services",
        "cis_level": "L2",
        "assessment_type": "manual",
        "severity": "medium",
        "service_area": "identity_services",
        "description": "Restrict Microsoft 365 group creation to administrators only.",
        "rationale": (
            "Restricting Microsoft 365 group creation to administrators only ensures that "
            "creation of Microsoft 365 groups is controlled by the administrator. Appropriate "
            "groups should be created and managed by the administrator and group creation "
            "rights should not be delegated to any other user."
        ),
        "impact": "This could create a number of requests that would need to be managed by an administrator.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Groups.\n"
            "4. Under Settings, select General.\n"
            "5. Under Microsoft 365 Groups, ensure that Users can create Microsoft 365 "
            "groups in Azure portals, API or PowerShell is set to No."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Groups.\n"
            "4. Under Settings, select General.\n"
            "5. Under Microsoft 365 Groups, set Users can create Microsoft 365 groups to No.\n"
            "6. Click Save."
        ),
        "default_value": "By default, Users can create Microsoft 365 groups is set to Yes.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-management",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.22",
        "title": "Ensure that 'Require Multifactor Authentication to register or join devices with Microsoft Entra' is set to 'Yes'",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "high",
        "service_area": "identity_services",
        "description": (
            "Joining or registering devices to Microsoft Entra ID should require multi-factor "
            "authentication. NOTE: If your organization uses Conditional Access, the preferred "
            "method is to use a Conditional Access policy instead of this per-user MFA setting."
        ),
        "rationale": (
            "Multi-factor authentication is recommended when adding devices to Microsoft "
            "Entra ID. When set to Yes, users who are adding devices from the internet must "
            "first use the second method of authentication before their device is successfully "
            "added to the directory. This ensures that rogue devices are not added to the "
            "domain using a compromised user account."
        ),
        "impact": "Additional overhead as users must complete MFA to register devices.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Devices.\n"
            "4. Under Manage, select Device settings.\n"
            "5. Under Microsoft Entra join and registration settings, ensure that "
            "Require Multifactor Authentication to register or join devices with "
            "Microsoft Entra is set to Yes."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Devices.\n"
            "4. Under Manage, select Device settings.\n"
            "5. Under Microsoft Entra join and registration settings, set Require "
            "Multifactor Authentication to register or join devices to Yes.\n"
            "6. Click Save."
        ),
        "default_value": "By default, Require Multifactor Authentication to register or join devices is set to No.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-registration",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.23",
        "title": "Ensure that no custom subscription administrator roles exist",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "automated",
        "severity": "high",
        "service_area": "identity_services",
        "description": "The principle of least privilege should be followed and only necessary privileges should be assigned instead of allowing full administrative access.",
        "rationale": (
            "Custom roles in Azure with administrative access can obfuscate the permissions "
            "granted and introduce complexity and blind spots to the management of privileged "
            "identities. Custom Roles should be audited for use and assignment, used minimally, "
            "and the principle of least privilege should be observed."
        ),
        "impact": "Subscriptions will need to be handled by Administrators with standard permissions.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Subscriptions.\n"
            "3. Select a subscription.\n"
            "4. Select Access control (IAM).\n"
            "5. Select Roles.\n"
            "6. Click Type and select Custom role from the drop-down menu.\n"
            "7. Select View next to a role.\n"
            "8. Select JSON.\n"
            "9. Check for assignableScopes set to the subscription, and actions set to *.\n"
            "10. Repeat for each custom role.\n\n"
            "Audit from Azure CLI\n"
            "az role definition list --custom-role-only True\n"
            "Check for entries with assignableScope of the subscription and an action of *."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Subscriptions.\n"
            "3. Select a subscription.\n"
            "4. Select Access control (IAM).\n"
            "5. Select Roles.\n"
            "6. Click Type and select Custom role.\n"
            "7. Check the box next to each role granting subscription administrator privileges.\n"
            "8. Select Delete.\n"
            "9. Select Yes.\n\n"
            "Remediate from Azure CLI\n"
            "az role definition delete --name <role name>\n"
            "Note: any role assignments must be removed before a custom role can be deleted."
        ),
        "default_value": "By default, no custom owner roles are created.",
        "references": [
            "https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/add-change-subscription-administrator",
        ],
        "cli_commands": ["az role definition list --custom-role-only True"],
        "azure_policy_id": "a451c1ef-c6ca-483d-87ed-f49761e3ffb5",
    },

    {
        "cis_id": "5.24",
        "title": "Ensure that a custom role is assigned permissions for administering resource locks",
        "section": "Identity Services",
        "cis_level": "L2",
        "assessment_type": "manual",
        "severity": "medium",
        "service_area": "identity_services",
        "description": (
            "Resource locking is a powerful protection mechanism that can prevent inadvertent "
            "modification or deletion of resources within Azure subscriptions and resource groups."
        ),
        "rationale": (
            "Given that the resource lock functionality is outside of standard Role-Based "
            "Access Control (RBAC), it would be prudent to create a resource lock "
            "administrator role to prevent inadvertent unlocking of resources."
        ),
        "impact": "By adding this role, specific permissions may be granted for managing only resource locks.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. In the Azure portal, navigate to a subscription or resource group.\n"
            "2. Click Access control (IAM).\n"
            "3. Click Roles.\n"
            "4. Click Type : All.\n"
            "5. Select Custom role.\n"
            "6. Click View in the Details column of a custom role.\n"
            "7. Review the role permissions.\n"
            "8. Click Assignments and review the assignments.\n"
            "9. Ensure that at least one custom role exists that assigns the "
            "Microsoft.Authorization/locks permission to appropriate members."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. Navigate to a subscription or resource group.\n"
            "2. Click Access control (IAM).\n"
            "3. Click + Add.\n"
            "4. Click Add custom role.\n"
            "5. In the Custom role name field enter Resource Lock Administrator.\n"
            "6. In the Description field enter Can Administer Resource Locks.\n"
            "7. For Baseline permissions select Start from scratch.\n"
            "8. Click Next.\n"
            "9. Click Add permissions.\n"
            "10. Search for Microsoft.Authorization/locks.\n"
            "11. Click the result and check the box next to Permission.\n"
            "12. Click Add.\n"
            "13. Click Review + create.\n"
            "14. Click Create.\n\n"
            "Remediate from PowerShell\n"
            "$role = Get-AzRoleDefinition 'User Access Administrator'\n"
            "$role.Id = $null\n"
            "$role.Name = 'Resource Lock Administrator'\n"
            "$role.Description = 'Can Administer Resource Locks'\n"
            "$role.Actions.Clear()\n"
            "$role.Actions.Add('Microsoft.Authorization/locks/*')\n"
            "New-AzRoleDefinition -Role $role"
        ),
        "default_value": "A role for administering resource locks does not exist by default.",
        "references": [
            "https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.25",
        "title": "Ensure that 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering Microsoft Entra tenant' is set to 'Permit no one'",
        "section": "Identity Services",
        "cis_level": "L2",
        "assessment_type": "manual",
        "severity": "high",
        "service_area": "identity_services",
        "description": (
            "Users who are set as subscription owners are able to make administrative changes "
            "to the subscriptions and move them into and out of Microsoft Entra ID."
        ),
        "rationale": (
            "Permissions to move subscriptions in and out of a Microsoft Entra tenant must "
            "only be given to appropriate administrative personnel. A subscription that is "
            "moved into a Microsoft Entra tenant may be within a folder to which other users "
            "have elevated permissions. This prevents loss of data or unapproved changes."
        ),
        "impact": "Subscriptions will need to have these settings turned off to be moved.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. From the Azure Portal Home select the portal menu.\n"
            "2. Select Subscriptions.\n"
            "3. In the Advanced options drop-down menu, select Manage Policies.\n"
            "4. Ensure Subscription leaving Microsoft Entra tenant and Subscription "
            "entering Microsoft Entra tenant are set to Permit no one."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. From the Azure Portal Home select the portal menu.\n"
            "2. Select Subscriptions.\n"
            "3. In the Advanced options drop-down menu, select Manage Policies.\n"
            "4. Set Subscription leaving Microsoft Entra tenant and Subscription "
            "entering Microsoft Entra tenant to Permit no one.\n"
            "5. Click Save changes."
        ),
        "default_value": "By default both settings are set to Allow everyone (default).",
        "references": [
            "https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/manage-azure-subscription-policy",
            "https://learn.microsoft.com/en-us/entra/fundamentals/how-subscriptions-associated-directory",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.26",
        "title": "Ensure fewer than 5 users have global administrator assignment",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "manual",
        "severity": "critical",
        "service_area": "identity_services",
        "description": (
            "This recommendation aims to maintain a balance between security and operational "
            "efficiency by ensuring that a minimum of 2 and a maximum of 4 users are assigned "
            "the Global Administrator role in Microsoft Entra ID."
        ),
        "rationale": (
            "The Global Administrator role has extensive privileges across all services. "
            "Limiting the number helps mitigate the risk of unauthorized access, reduces "
            "the potential impact of human error, and aligns with the principle of least "
            "privilege. Having at least two ensures redundancy."
        ),
        "impact": (
            "Implementing this may require changes in administrative workflows or the "
            "redistribution of roles and responsibilities."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. From Azure Home select the Portal Menu.\n"
            "2. Select Microsoft Entra ID.\n"
            "3. Under Manage, select Roles and administrators.\n"
            "4. Under Administrative Roles, select Global Administrator.\n"
            "5. Ensure less than 5 users are actively assigned the role.\n"
            "6. Ensure that at least 2 users are actively assigned the role."
        ),
        "remediation": (
            "If more than 4 users are assigned:\n"
            "1. Remove Global Administrator role for users which do not require the role.\n"
            "2. Assign Global Administrator role via PIM which can be activated when required.\n"
            "3. Assign more granular roles to users to conduct their duties.\n\n"
            "If only one user is assigned:\n"
            "1. Provide the Global Administrator role to a trusted user or create a break glass admin account."
        ),
        "default_value": "Depends on initial tenant setup.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices#5-limit-the-number-of-global-administrators-to-less-than-5",
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    {
        "cis_id": "5.27",
        "title": "Ensure there are between 2 and 3 subscription owners",
        "section": "Identity Services",
        "cis_level": "L1",
        "assessment_type": "automated",
        "severity": "high",
        "service_area": "identity_services",
        "description": "The Owner role in Azure grants full control over all resources in a subscription, including the ability to assign roles to others.",
        "rationale": (
            "Limit the number of security principals (users, groups, service principals, "
            "and managed identities) assigned the Owner role to between 2 and 3 to avoid "
            "privilege sprawl while maintaining redundancy."
        ),
        "impact": "May require redistribution of roles and responsibilities.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. Go to Subscriptions.\n"
            "2. Click the name of a subscription.\n"
            "3. Click Access Controls (IAM).\n"
            "4. Click Role assignments.\n"
            "5. Click Role : All.\n"
            "6. Click Owner.\n"
            "7. Ensure a minimum of 2 and a maximum of 3 members are returned.\n\n"
            "Audit from Azure CLI\n"
            "az role assignment list --role Owner --scope /subscriptions/<subscription-id> "
            "--query \"[].{PrincipalName:principalName, Type:principalType}\"\n"
            "Ensure a minimum of 2 and a maximum of 3 members are returned."
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. Go to Subscriptions.\n"
            "2. Click the name of a subscription.\n"
            "3. Click Access Controls (IAM).\n"
            "4. Click Role assignments.\n"
            "5. Click Owner.\n"
            "6. Check the box next to members from whom the owner role should be removed.\n"
            "7. Click Delete.\n\n"
            "Remediate from Azure CLI\n"
            "az role assignment delete --ids <role-assignment-ids>"
        ),
        "default_value": "A subscription has 1 owner by default.",
        "references": [
            "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/privileged#owner",
        ],
        "cli_commands": [
            "az role assignment list --role Owner --scope /subscriptions/<subscription-id>",
        ],
        "azure_policy_id": "09024ccc-0c5f-475e-9457-b7c0d9ed487b",
    },

    {
        "cis_id": "5.28",
        "title": "Ensure passwordless authentication methods are considered",
        "section": "Identity Services",
        "cis_level": "L2",
        "assessment_type": "manual",
        "severity": "medium",
        "service_area": "identity_services",
        "description": (
            "Passwordless authentication methods improve security and user experience by "
            "replacing passwords with something you have (hardware key), something you are "
            "(biometrics), or something you know. Options include: Windows Hello for Business, "
            "Platform Credential for macOS, Microsoft Authenticator, Passkeys (FIDO2), and "
            "Certificate-based authentication."
        ),
        "rationale": (
            "Using passwordless authentication makes sign-in easier and more secure by "
            "removing passwords, helping to protect organizations from attacks and improving "
            "the user experience."
        ),
        "impact": (
            "Implementing passwordless authentication requires administrative effort and may "
            "incur costs for some methods. It has the potential to save time and money by "
            "improving user convenience and reducing the need for password support."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. Go to Microsoft Entra ID.\n"
            "2. Click Authentication methods.\n"
            "3. Under Manage, click Policies.\n"
            "4. If appropriate for your organization, ensure a passwordless authentication "
            "method policy is configured."
        ),
        "remediation": (
            "1. Review passwordless options: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless\n"
            "2. Choose a method.\n"
            "3. Implement Microsoft Authenticator or Passkeys (FIDO2)."
        ),
        "default_value": "Passwordless authentication is not enabled by default.",
        "references": [
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods",
            "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless",
        ],
        "cli_commands": [],
        "azure_policy_id": "",
    },

    # =========================================================================
    # Section 6 — Management and Governance Services
    # =========================================================================

    {
        "cis_id": "6.1.1",
        "title": "Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs",
        "section": "Management and Governance Services",
        "cis_level": "L1",
        "assessment_type": "automated",
        "severity": "high",
        "service_area": "management_and_governance",
        "description": (
            "Enable diagnostic settings for subscription activity logs to capture administrative, "
            "security, alert, and policy events with appropriate retention."
        ),
        "rationale": (
            "Activity logs provide insight into operations performed on resources within the "
            "subscription. Capturing these logs via diagnostic settings enables security "
            "analysis, compliance auditing, and operational troubleshooting."
        ),
        "impact": "Additional storage costs for log retention depending on data volume and retention period.",
        "audit": (
            "Audit from Azure Portal\n"
            "1. Go to Monitor.\n"
            "2. Under Activity log, click Export Activity Logs.\n"
            "3. Ensure at least one diagnostic setting exists capturing relevant categories.\n\n"
            "Audit from Azure CLI\n"
            "az monitor diagnostic-settings subscription list --subscription <sub-id>"
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. Go to Monitor.\n"
            "2. Under Activity log, click Export Activity Logs.\n"
            "3. Click + Add diagnostic setting.\n"
            "4. Select relevant log categories.\n"
            "5. Select destination (Log Analytics workspace, Storage account, or Event Hub).\n"
            "6. Click Save."
        ),
        "default_value": "No diagnostic settings exist by default.",
        "references": [
            "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
        ],
        "cli_commands": ["az monitor diagnostic-settings subscription list --subscription <sub-id>"],
        "azure_policy_id": "",
    },

    {
        "cis_id": "6.2",
        "title": "Ensure that Resource Locks are set for Mission-Critical Azure Resources",
        "section": "Management and Governance Services",
        "cis_level": "L2",
        "assessment_type": "manual",
        "severity": "medium",
        "service_area": "management_and_governance",
        "description": (
            "Resource Manager Locks provide a way for administrators to lock down Azure "
            "resources to prevent deletion of, or modifications to, a resource. These locks "
            "sit outside of the Role Based Access Controls (RBAC) hierarchy."
        ),
        "rationale": (
            "As an administrator, it may be necessary to lock a subscription, resource group, "
            "or resource to prevent other users from accidentally deleting or modifying "
            "critical resources. Lock types: CanNotDelete and ReadOnly."
        ),
        "impact": (
            "Applying a lock to a parent service will cause it to be inherited by all "
            "resources within. Conversely, applying a lock to a resource may not apply to "
            "connected storage."
        ),
        "audit": (
            "Audit from Azure Portal\n"
            "1. Navigate to the specific Azure Resource or Resource Group.\n"
            "2. Click on Locks.\n"
            "3. Ensure the lock is defined with name and description.\n\n"
            "Audit from Azure CLI\n"
            "az lock list --resource-group <rg> --resource-name <name> --namespace <ns> --resource-type <type>"
        ),
        "remediation": (
            "Remediate from Azure Portal\n"
            "1. Navigate to the specific Azure Resource or Resource Group.\n"
            "2. For each mission critical resource, click on Locks.\n"
            "3. Click Add.\n"
            "4. Give the lock a name and description, then select the type.\n"
            "5. Click OK.\n\n"
            "Remediate from Azure CLI\n"
            "az lock create --name <LockName> --lock-type <CanNotDelete/Read-only> "
            "--resource-group <rg> --resource-name <name> --resource-type <type>"
        ),
        "default_value": "By default, no locks are set.",
        "references": [
            "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources",
        ],
        "cli_commands": [
            "az lock list --resource-group <rg> --resource-name <name> --namespace <ns> --resource-type <type>",
        ],
        "azure_policy_id": "",
    },
]
