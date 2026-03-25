"""CIS Microsoft 365 Foundations Benchmark v4.0.0 — Complete Control Registry.

Auto-generated from the unified CIS controls library.
Contains ALL 140 controls (129 automated, 11 manual).
Each control includes full metadata, audit procedures, detection commands,
remediation guidance, and DSPM/Ransomware Readiness mapping.

Reference: CIS Microsoft 365 Foundations Benchmark v4.0.0 (2025)
Source: CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf

Total controls: 140 (129 automated, 11 manual)
"""

import json as _json


# Control registry — 140 controls
M365_CIS_CONTROLS: list[dict] = _json.loads(r"""
[
  {
    "cis_id": "1.1.1",
    "title": "Ensure Administrative accounts are cloud-only",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "admin_center",
    "domain": "Microsoft 365 admin center",
    "subdomain": "Users",
    "m365_profile": "E3",
    "description": "Administrative accounts are special privileged accounts that could have varying levels\nof access to data, users, and settings. Regular user accounts should never be utilized\nfor administrative tasks and care should be taken, in the case of a hybrid environment,\nto keep administrative accounts separate from on-prem accounts. Administrative\naccounts should not have applications assigned so that they have no access to\npotentially vulnerable services (EX. email, Teams, SharePoint, etc.) and only access to\nperform tasks as needed for administrative purposes.\nEnsure administrative accounts are not On-premises sync enabled.",
    "rationale": "In a hybrid environment, having separate accounts will help ensure that in the event of a\nbreach in the cloud, that the breach does not affect the on-prem environment and vice\nversa.",
    "impact": "Administrative users will need to utilize login/logout functionality to switch accounts\nwhen performing administrative tasks, which means they will not benefit from SSO. This\nwill require a migration process from the 'daily driver' account to a dedicated admin\naccount.\nOnce the new admin account is created, permission sets should be migrated from the\n'daily driver' account to the new admin account. This includes both M365 and Azure\nRBAC roles. Failure to migrate Azure RBAC roles could prevent an admin from seeing\ntheir subscriptions/resources while using their admin account.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Identity > Users and select All users.\n3. To the right of the search box click the Add filter button.\n4. Add the On-premises sync enabled filter with the value set to Yes and click\nApply.\n5. Verify that no user accounts in administrative roles are present in the filtered list.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"RoleManagement.Read.Directory\",\"User.Read.All\"\n2. Run the following PowerShell script:\n$DirectoryRoles = Get-MgDirectoryRole\n# Get privileged role IDs\n$PrivilegedRoles = $DirectoryRoles | Where-Object {\n$_.DisplayName -like \"*Administrator*\" -or $_.DisplayName -eq \"Global\nReader\"\n}\n# Get the members of these various roles\n$RoleMembers = $PrivilegedRoles | ForEach-Object { Get-MgDirectoryRoleMember\n-DirectoryRoleId $_.Id } |\nSelect-Object Id -Unique\n# Retrieve details about the members in these roles\n$PrivilegedUsers = $RoleMembers | ForEach-Object {\nGet-MgUser -UserId $_.Id -Property UserPrincipalName, DisplayName, Id,\nOnPremisesSyncEnabled\n}\n$PrivilegedUsers | Where-Object { $_.OnPremisesSyncEnabled -eq $true } |\nft DisplayName,UserPrincipalName,OnPremisesSyncEnabled\n3. The script will output any hybrid users that are also members of privileged roles.\nIf nothing returns, then no users with that criteria exist.",
    "expected_response": "3. The script will output any hybrid users that are also members of privileged roles.\nIf nothing returns, then no users with that criteria exist.",
    "remediation": "Remediation will require first identifying the privileged accounts that are synced from on-\npremises and then creating a new cloud-only account for that user. Once a replacement\naccount is established, the hybrid account should have its role reduced to that of a non-\nprivileged user or removed depending on the need.",
    "default_value": "N/A",
    "detection_commands": [
      "$DirectoryRoles = Get-MgDirectoryRole",
      "$PrivilegedRoles = $DirectoryRoles | Where-Object { $_.DisplayName -like \"*Administrator*\" -or $_.DisplayName -eq \"Global",
      "$RoleMembers = $PrivilegedRoles | ForEach-Object { Get-MgDirectoryRoleMember",
      "Select-Object Id -Unique",
      "$PrivilegedUsers = $RoleMembers | ForEach-Object { Get-MgUser -UserId $_.Id -Property UserPrincipalName, DisplayName, Id,",
      "$PrivilegedUsers | Where-Object { $_.OnPremisesSyncEnabled -eq $true } |"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/add-",
      "users?view=o365-worldwide",
      "2. https://learn.microsoft.com/en-us/microsoft-365/enterprise/protect-your-global-",
      "administrator-accounts?view=o365-worldwide",
      "3. https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-",
      "practices#9-use-cloud-native-accounts-for-microsoft-entra-roles",
      "4. https://learn.microsoft.com/en-us/entra/fundamentals/whatis",
      "5. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/permissions-reference"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 21,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.1.2",
    "title": "Ensure two emergency access accounts have been defined",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "admin_center",
    "domain": "Microsoft 365 admin center",
    "subdomain": "Maintain Inventory of Administrative Accounts",
    "m365_profile": "E3",
    "description": "Emergency access or \"break glass\" accounts are limited for emergency scenarios\nwhere normal administrative accounts are unavailable. They are not assigned to a\nspecific user and will have a combination of physical and technical controls to prevent\nthem from being accessed outside a true emergency. These emergencies could be due\nto several things, including:\n• Technical failures of a cellular provider or Microsoft related service such as MFA.\n• The last remaining Global Administrator account is inaccessible.\nEnsure two Emergency Access accounts have been defined.\nNote: Microsoft provides several recommendations for these accounts and how to\nconfigure them. For more information on this, please refer to the references section.\nThe CIS Benchmark outlines the more critical things to consider.",
    "rationale": "In various situations, an organization may require the use of a break glass account to\ngain emergency access. In the event of losing access to administrative functions, an\norganization may experience a significant loss in its ability to provide support, lose\ninsight into its security posture, and potentially suffer financial losses.",
    "impact": "Failure to properly implement emergency access accounts can weaken the security\nposture. Microsoft recommends excluding at least one of the two emergency access\naccounts from all conditional access rules, necessitating passwords with sufficient\nentropy and length to protect against random guesses. For a secure passwordless\nsolution, FIDO2 security keys may be used instead of passwords.",
    "audit": "To audit using the UI:\nStep 1 - Ensure a policy and procedure is in place at the organization:\n• In order for accounts to be effectively used in a break-glass situation the proper\npolicies and procedures must be authorized and distributed by senior\nmanagement.\n• FIDO2 Security Keys should be locked in a secure separate fireproof location.\n• Passwords should be at least 16 characters, randomly generated and MAY be\nseparated in multiple pieces to be joined on emergency.\nStep 2 - Ensure two emergency access accounts are defined:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com\n2. Expand Users > Active Users\n3. Inspect the designated emergency access accounts and ensure the following:\no The accounts are named correctly, and do NOT identify with a particular\nperson.\no The accounts use the default .onmicrosoft.com domain and not the\norganization's.\no The accounts are cloud-only.\no The accounts are unlicensed.\no The accounts are assigned the Global Administrator directory role.\nStep 3 - Ensure at least one account is excluded from all conditional access\nrules:\n1. Navigate Microsoft Entra admin center https://entra.microsoft.com/\n2. Expand Protection > Conditional Access.\n3. Inspect the conditional access rules.\n4. Ensure one of the emergency access accounts is excluded from all rules.\nWarning: As of 10/15/2024 MFA is required for all users including Break Glass\nAccounts. It is recommended to update these accounts to use passkey\n(FIDO2) or configure certificate-based authentication for MFA. Both methods satisfy the\nMFA requirement.",
    "expected_response": "Step 1 - Ensure a policy and procedure is in place at the organization:\npolicies and procedures must be authorized and distributed by senior\n• FIDO2 Security Keys should be locked in a secure separate fireproof location.\n• Passwords should be at least 16 characters, randomly generated and MAY be\nStep 2 - Ensure two emergency access accounts are defined:\n3. Inspect the designated emergency access accounts and ensure the following:\nStep 3 - Ensure at least one account is excluded from all conditional access\n4. Ensure one of the emergency access accounts is excluded from all rules.",
    "remediation": "To remediate using the UI:\nStep 1 - Create two emergency access accounts:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com\n2. Expand Users > Active Users\n3. Click Add user and create a new user with this criteria:\no Name the account in a way that does NOT identify it with a particular\nperson.\no Assign the account to the default .onmicrosoft.com domain and not the\norganization's.\no The password must be at least 16 characters and generated randomly.\no Do not assign a license.\no Assign the user the Global Administrator role.\n4. Repeat the above steps for the second account.\nStep 2 - Exclude at least one account from conditional access policies:\n1. Navigate Microsoft Entra admin center https://entra.microsoft.com/\n2. Expand Protection > Conditional Access.\n3. Inspect the conditional access policies.\n4. For each rule add an exclusion for at least one of the emergency access\naccounts.\n5. Users > Exclude > Users and groups and select one emergency access\naccount.\nStep 3 - Ensure the necessary procedures and policies are in place:\n• In order for accounts to be effectively used in a break glass situation the proper\npolicies and procedures must be authorized and distributed by senior\nmanagement.\n• FIDO2 Security Keys should be locked in a secure separate fireproof location.\n• Passwords should be at least 16 characters, randomly generated and MAY be\nseparated in multiple pieces to be joined on emergency.\nWarning: As of 10/15/2024 MFA is required for all users including Break Glass\nAccounts. It is recommended to update these accounts to use passkey\n(FIDO2) or configure certificate-based authentication for MFA. Both methods satisfy the\nMFA requirement.\nAdditional suggestions for emergency account management:\n• Create access reviews for these users.\n• Exclude users from conditional access rules.\n• Add the account to a restricted management administrative unit.\nWarning: If CA (conditional access) exclusion is managed by a group, this group should\nbe added to PIM for groups (licensing required) or be created as a role-assignable\ngroup. If it is a regular security group, then users with the Group Administrators role are\nable to bypass CA entirely.",
    "default_value": "Not defined.",
    "additional_information": "Microsoft has additional instructions regarding using Azure Monitor to capture events in\nthe Log Analytics workspace, and then generate alerts for Emergency Access accounts.\nThis requires an Azure subscription but should be strongly considered as a method of\nmonitoring activity on these accounts:\nhttps://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-\nemergency-access#monitor-sign-in-and-audit-logs",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/security-planning#stage-1-critical-items-to-do-right-now",
      "2. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/security-emergency-access",
      "3. https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-",
      "units-restricted-management",
      "4. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-",
      "mandatory-multifactor-authentication#accounts"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 24,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "1.1.3",
    "title": "Ensure that between two and four global admins are designated",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "admin_center",
    "domain": "Microsoft 365 admin center",
    "subdomain": "Establish and Maintain an Inventory of Accounts",
    "m365_profile": "E3",
    "description": "Between two and four global administrators should be designated in the tenant. Ideally,\nthese accounts will not have licenses assigned to them which supports additional\ncontrols found in this benchmark.",
    "rationale": "If there is only one global administrator, they could perform malicious activities without\nbeing detected by another admin. Designating multiple global administrators eliminates\nthis risk and ensures redundancy if the sole remaining global administrator leaves the\norganization.\nHowever, to minimize the attack surface, there should be no more than four global\nadmins set for any tenant. A large number of global admins increases the likelihood of a\nsuccessful account breach by an external attacker.",
    "impact": "The potential impact associated with ensuring compliance with this requirement is\ndependent upon the current number of global administrators configured in the tenant. If\nthere is only one global administrator in a tenant, an additional global administrator will\nneed to be identified and configured. If there are more than four global administrators, a\nreview of role requirements for current global administrators will be required to identify\nwhich of the users require global administrator access.",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft 365 admin center https://admin.microsoft.com\n2. Select Roles > Role assignments.\n3. Select the Global Administrator role from the list and click on Assigned.\n4. Review the list of Global Administrators.\no If there are groups present, then inspect each group and its members.\no Take note of the total number of Global Administrators in and outside of\ngroups.\n5. Ensure the number of Global Administrators is between two and four.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\nDirectory.Read.All\n2. Run the following PowerShell script:\n# Determine Id of GA role using the immutable RoleTemplateId value.\n$GlobalAdminRole = Get-MgDirectoryRole -Filter \"RoleTemplateId eq '62e90394-\n69f5-4237-9190-012177145e10'\"\n$RoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRole.Id\n$GlobalAdmins = [System.Collections.Generic.List[Object]]::new()\nforeach ($object in $RoleMembers) {\n$Type = $object.AdditionalProperties.'@odata.type'\n# Check for and process role assigned groups\nif ($Type -eq '#microsoft.graph.group') {\n$GroupId = $object.Id\n$GroupMembers = (Get-MgGroupMember -GroupId\n$GroupId).AdditionalProperties\nforeach ($member in $GroupMembers) {\nif ($member.'@odata.type' -eq '#microsoft.graph.user') {\n$GlobalAdmins.Add([PSCustomObject][Ordered]@{\nDisplayName       = $member.displayName\nUserPrincipalName = $member.userPrincipalName\n})\n}\n}\n} elseif ($Type -eq '#microsoft.graph.user') {\n$DisplayName = $object.AdditionalProperties.displayName\n$UPN = $object.AdditionalProperties.userPrincipalName\n$GlobalAdmins.Add([PSCustomObject][Ordered]@{\nDisplayName       = $DisplayName\nUserPrincipalName = $UPN\n})\n}\n}\n$GlobalAdmins = $GlobalAdmins | select DisplayName,UserPrincipalName -Unique\nWrite-Host \"*** There are\" $GlobalAdmins.Count \"Global Administrators in the\norganization.\"\n3. Review the output and ensure there are between 2 and 4 Global Administrators.\nNote: When tallying the number of Global Administrators, the above does not account\nfor Partner relationships. Those are located under Settings > Partner\nRelationships and should be reviewed on a reoccurring basis.",
    "expected_response": "5. Ensure the number of Global Administrators is between two and four.\n3. Review the output and ensure there are between 2 and 4 Global Administrators.\nRelationships and should be reviewed on a reoccurring basis.",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft 365 admin center https://admin.microsoft.com\n2. Select Users > Active Users.\n3. In the Search field enter the name of the user to be made a Global Administrator.\n4. To create a new Global Admin:\n1. Select the user's name.\n2. A window will appear to the right.\n3. Select Manage roles.\n4. Select Admin center access.\n5. Check Global Administrator.\n6. Click Save changes.\n5. To remove Global Admins:\n1. Select User.\n2. Under Roles select Manage roles\n3. De-Select the appropriate role.\n4. Click Save changes.",
    "detection_commands": [
      "$GlobalAdminRole = Get-MgDirectoryRole -Filter \"RoleTemplateId eq '62e90394-",
      "$RoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRole.Id $GlobalAdmins = [System.Collections.Generic.List[Object]]::new()",
      "$Type = $object.AdditionalProperties.'@odata.type'",
      "$GroupId = $object.Id $GroupMembers = (Get-MgGroupMember -GroupId $GroupId).AdditionalProperties",
      "$GlobalAdmins.Add([PSCustomObject][Ordered]@{",
      "$DisplayName = $object.AdditionalProperties.displayName $UPN = $object.AdditionalProperties.userPrincipalName $GlobalAdmins.Add([PSCustomObject][Ordered]@{",
      "$GlobalAdmins = $GlobalAdmins | select DisplayName,UserPrincipalName -Unique"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-",
      "us/powershell/module/microsoft.graph.identity.directorymanagement/get-",
      "mgdirectoryrole?view=graph-powershell-1.0",
      "2. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/permissions-reference#all-roles",
      "3. https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-",
      "practices#5-limit-the-number-of-global-administrators-to-less-than-5"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 28,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.1.4",
    "title": "Ensure administrative accounts use licenses with a reduced application footprint",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "admin_center",
    "domain": "Microsoft 365 admin center",
    "subdomain": "Maintain Inventory of Administrative Accounts",
    "m365_profile": "E3",
    "description": "Administrative accounts are special privileged accounts that could have varying levels\nof access to data, users, and settings. A license can enable an account to gain access\nto a variety of different applications, depending on the license assigned.\nThe recommended state is to not license a privileged account or use licenses without\nassociated applications such as Microsoft Entra ID P1 or Microsoft Entra ID\nP2.",
    "rationale": "Ensuring administrative accounts do not use licenses with applications assigned to\nthem will reduce the attack surface of high privileged identities in the organization's\nenvironment. Granting access to a mailbox or other collaborative tools increases the\nlikelihood that privileged users might interact with these applications, raising the risk of\nexposure to social engineering attacks or malicious content. These activities should be\nrestricted to an unprivileged 'daily driver' account.\nNote: In order to participate in Microsoft 365 security services such as Identity\nProtection, PIM and Conditional Access an administrative account will need a license\nattached to it. Ensure that the license used does not include any applications with\npotentially vulnerable services by using either Microsoft Entra ID P1 or Microsoft\nEntra ID P2 for the cloud-only account with administrator roles.",
    "impact": "Administrative users will be required to switch accounts and use manual login/logout\nprocedures when performing privileged tasks. This change also means they will not\nbenefit from Single Sign-On (SSO), potentially impacting workflow efficiency and user\nexperience.\nNote: Alerts will be sent to TenantAdmins, including Global Administrators, by default.\nTo ensure proper receipt, configure alerts to be sent to security or operations staff with\nvalid email addresses or a security operations center. Otherwise, after adoption of this\nrecommendation, alerts sent to TenantAdmins may go unreceived due to the lack of an\napplication-based license assigned to the Global Administrator accounts.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Users select Active users.\n3. Sort by the Licenses column.\n4. For each user account in an administrative role verify the account is assigned a\nlicense that is not associated with applications i.e. (Microsoft Entra ID P1,\nMicrosoft Entra ID P2).\no If an organization uses PIM to elevate a daily driver account to privileged\nlevels, this control and licensing requirement can be considered satisfied.\nNote: The final step assumes PIM is properly configured to best practices. Accounts\neligible for the Global Administrator role should require approval to activate. Using the\nPIM blade to permanently assign accounts to privileged roles would not satisfy this audit\nprocedure.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"RoleManagement.Read.Directory\",\"User.Read.All\"\n2. Run the following PowerShell script:\n$DirectoryRoles = Get-MgDirectoryRole\n# Get privileged role IDs\n$PrivilegedRoles = $DirectoryRoles | Where-Object {\n$_.DisplayName -like \"*Administrator*\" -or $_.DisplayName -eq \"Global\nReader\"\n}\n# Get the members of these various roles\n$RoleMembers = $PrivilegedRoles | ForEach-Object { Get-MgDirectoryRoleMember\n-DirectoryRoleId $_.Id } |\nSelect-Object Id -Unique\n# Retrieve details about the members in these roles\n$PrivilegedUsers = $RoleMembers | ForEach-Object {\nGet-MgUser -UserId $_.Id -Property UserPrincipalName, DisplayName, Id\n}\n$Report = [System.Collections.Generic.List[Object]]::new()\nforeach ($Admin in $PrivilegedUsers) {\n$License = $null\n$License = (Get-MgUserLicenseDetail -UserId $Admin.id).SkuPartNumber -\njoin \", \"\n$Object = [pscustomobject][ordered]@{\nDisplayName           = $Admin.DisplayName\nUserPrincipalName     = $Admin.UserPrincipalName\nLicense               = $License\n}\n$Report.Add($Object)\n}\n$Report\n3. The output will display users assigned privileged roles alongside their assigned\nlicenses. Additional manual assessment is required to determine if the licensing\nis appropriate for the user.",
    "expected_response": "eligible for the Global Administrator role should require approval to activate. Using the\n3. The output will display users assigned privileged roles alongside their assigned",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Users select Active users\n3. Click Add a user.\n4. Fill out the appropriate fields for Name, user, etc.\n5. When prompted to assign licenses select as needed Microsoft Entra ID P1\nor Microsoft Entra ID P2, then click Next.\n6. Under the Option settings screen you may choose from several types of\nprivileged roles. Choose Admin center access followed by the appropriate role\nthen click Next.\n7. Select Finish adding.\nNote: Utilizing PIM to best practices will satisfy this control. CIS and Microsoft\nrecommend an organization keep zero permanently active assignments for roles other\nthan emergency access accounts.",
    "default_value": "N/A",
    "detection_commands": [
      "$DirectoryRoles = Get-MgDirectoryRole",
      "$PrivilegedRoles = $DirectoryRoles | Where-Object { $_.DisplayName -like \"*Administrator*\" -or $_.DisplayName -eq \"Global",
      "$RoleMembers = $PrivilegedRoles | ForEach-Object { Get-MgDirectoryRoleMember",
      "Select-Object Id -Unique",
      "$PrivilegedUsers = $RoleMembers | ForEach-Object { Get-MgUser -UserId $_.Id -Property UserPrincipalName, DisplayName, Id",
      "$Report = [System.Collections.Generic.List[Object]]::new()",
      "$License = $null $License = (Get-MgUserLicenseDetail -UserId $Admin.id).SkuPartNumber -",
      "$Object = [pscustomobject][ordered]@{",
      "$Report.Add($Object)",
      "$Report"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/enterprise/protect-your-global-",
      "administrator-accounts?view=o365-worldwide",
      "2. https://learn.microsoft.com/en-us/entra/fundamentals/whatis#what-are-the-",
      "microsoft-entra-id-licenses",
      "3. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/permissions-reference",
      "4. https://learn.microsoft.com/en-us/microsoft-365/business-premium/m365bp-",
      "protect-admin-accounts?view=o365-worldwide",
      "5. https://learn.microsoft.com/en-us/microsoft-365/enterprise/subscriptions-licenses-",
      "accounts-and-tenants-for-microsoft-cloud-offerings?view=o365-",
      "worldwide#licenses",
      "6. https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-",
      "management/pim-deployment-plan#principle-of-least-privilege"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 31,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.2.1",
    "title": "Ensure that only organizationally managed/approved public groups exist",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "admin_center",
    "domain": "Microsoft 365 admin center",
    "subdomain": "Teams & groups",
    "m365_profile": "E3",
    "description": "Microsoft 365 Groups is the foundational membership service that drives all teamwork\nacross Microsoft 365. With Microsoft 365 Groups, you can give a group of people\naccess to a collection of shared resources. When a new group is created in the\nAdministration panel, the default privacy value of the group is \"Public\". (In this case,\n‘public’ means accessible to the identities within the organization without requiring group\nowner authorization to join.)\nEnsure that Microsoft 365 Groups are set to Private in the Administration panel.\nNote: Although there are several different group types, this recommendation concerns\nMicrosoft 365 Groups specifically.",
    "rationale": "If group privacy is not controlled, any user may access sensitive information, depending\non the group they try to access.\nWhen the privacy value of a group is set to \"Public,\" users may access data related to\nthis group (e.g. SharePoint) via three methods:\n1. The Azure Portal: Users can add themselves to the public group via the Azure\nPortal; however, administrators are notified when users access the Portal.\n2. Access Requests: Users can request to join the group via the Groups application\nin the Access Panel. This provides the user with immediate access to the group,\neven though they are required to send a message to the group owner when\nrequesting to join.\n3. SharePoint URL: Users can directly access a group via its SharePoint URL,\nwhich is usually guessable and can be found in the Groups application within the\nAccess Panel.",
    "impact": "If the recommendation is applied, group owners could receive more access requests\nthan usual, especially regarding groups originally meant to be public.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Teams & groups select Active teams & groups.\n3. On the Active teams and groups page, check that no groups have the status\n'Public' in the privacy column.\nTo audit using PowerShell:\n1. Connect to the Microsoft Graph service using Connect-MgGraph -Scopes\n\"Group.Read.All\".\n2. Run the following Microsoft Graph PowerShell command:\nGet-MgGroup -All | where {$_.Visibility -eq \"Public\"} | select\nDisplayName,Visibility\n3. Ensure Visibility is Private for each group.",
    "expected_response": "3. Ensure Visibility is Private for each group.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Teams & groups select Active teams & groups..\n3. On the Active teams and groups page, select the group's name that is public.\n4. On the popup groups name page, Select Settings.\n5. Under Privacy, select Private.",
    "default_value": "Public when created from the Administration portal; private otherwise.",
    "detection_commands": [
      "Get-MgGroup -All | where {$_.Visibility -eq \"Public\"} | select"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-",
      "management",
      "2. https://learn.microsoft.com/en-us/microsoft-365/admin/create-groups/compare-",
      "groups?view=o365-worldwide"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 37,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.2.2",
    "title": "Ensure sign-in to shared mailboxes is blocked",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "admin_center",
    "domain": "Microsoft 365 admin center",
    "subdomain": "Maintain an Inventory Sensitive Information",
    "m365_profile": "E3",
    "description": "Shared mailboxes are used when multiple people need access to the same mailbox,\nsuch as a company information or support email address, reception desk, or other\nfunction that might be shared by multiple people.\nUsers with permissions to the group mailbox can send as or send on behalf of the\nmailbox email address if the administrator has given that user permissions to do that.\nThis is particularly useful for help and support mailboxes because users can send\nemails from \"Contoso Support\" or \"Building A Reception Desk.\"\nShared mailboxes are created with a corresponding user account using a system\ngenerated password that is unknown at the time of creation.\nThe recommended state is Sign in blocked for Shared mailboxes.",
    "rationale": "The intent of the shared mailbox is the only allow delegated access from other\nmailboxes. An admin could reset the password, or an attacker could potentially gain\naccess to the shared mailbox allowing the direct sign-in to the shared mailbox and\nsubsequently the sending of email from a sender that does not have a unique identity.\nTo prevent this, block sign-in for the account that is associated with the shared mailbox.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com/\n2. Click to expand Teams & groups and select Shared mailboxes.\n3. Take note of all shared mailboxes.\n4. Click to expand Users and select Active users.\n5. Select a shared mailbox account to open its properties pane, and review.\n6. Ensure the text under the name reads Sign-in blocked.\n7. Repeat for any additional shared mailboxes.\nNote: If sign-in is not blocked there will be an option to Block sign-in. This means the\nshared mailbox is out of compliance with this recommendation.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline\n2. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"User.Read.All\"\n3. Run the following PowerShell commands:\n$MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize\nUnlimited\n$MBX | ForEach-Object { Get-MgUser -UserId $_.ExternalDirectoryObjectId `\n-Property DisplayName, UserPrincipalName, AccountEnabled } |\nFormat-Table DisplayName, UserPrincipalName, AccountEnabled\n4. Ensure AccountEnabled is set to False for all Shared Mailboxes.",
    "expected_response": "6. Ensure the text under the name reads Sign-in blocked.\n4. Ensure AccountEnabled is set to False for all Shared Mailboxes.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com/\n2. Click to expand Teams & groups and select Shared mailboxes.\n3. Take note of all shared mailboxes.\n4. Click to expand Users and select Active users.\n5. Select a shared mailbox account to open it's properties pane and then select\nBlock sign-in.\n6. Check the box for Block this user from signing in.\n7. Repeat for any additional shared mailboxes.\nTo remediate using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"User.ReadWrite.All\"\n2. Connect to Exchange Online using Connect-ExchangeOnline.\n3. To disable sign-in for a single account:\n$MBX = Get-EXOMailbox -Identity TestUser@example.com\nUpdate-MgUser -UserId $MBX.ExternalDirectoryObjectId -AccountEnabled:$false\n3. The following will block sign-in to all Shared Mailboxes.\n$MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox\n$MBX | ForEach-Object { Update-MgUser -UserId $_.ExternalDirectoryObjectId -\nAccountEnabled:$false }",
    "default_value": "AccountEnabled: True",
    "detection_commands": [
      "$MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize",
      "$MBX | ForEach-Object { Get-MgUser -UserId $_.ExternalDirectoryObjectId `"
    ],
    "remediation_commands": [
      "$MBX = Get-EXOMailbox -Identity TestUser@example.com Update-MgUser -UserId $MBX.ExternalDirectoryObjectId -AccountEnabled:$false",
      "$MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox $MBX | ForEach-Object { Update-MgUser -UserId $_.ExternalDirectoryObjectId -"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/admin/email/about-shared-",
      "mailboxes?view=o365-worldwide",
      "2. https://learn.microsoft.com/en-us/microsoft-365/admin/email/create-a-shared-",
      "mailbox?view=o365-worldwide#block-sign-in-for-the-shared-mailbox-account",
      "3. https://learn.microsoft.com/en-us/microsoft-365/enterprise/block-user-accounts-",
      "with-microsoft-365-powershell?view=o365-worldwide#block-individual-user-",
      "accounts"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 40,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "1.3.1",
    "title": "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "admin_center",
    "domain": "Microsoft 365 admin center",
    "subdomain": "Settings",
    "m365_profile": "E3",
    "description": "Microsoft cloud-only accounts have a pre-defined password policy that cannot be\nchanged. The only items that can change are the number of days until a password\nexpires and whether or not passwords expire at all.",
    "rationale": "Organizations such as NIST and Microsoft have updated their password policy\nrecommendations to not arbitrarily require users to change their passwords after a\nspecific amount of time, unless there is evidence that the password is compromised, or\nthe user forgot it. They suggest this even for single factor (Password Only) use cases,\nwith a reasoning that forcing arbitrary password changes on users actually make the\npasswords less secure. Other recommendations within this Benchmark suggest the use\nof MFA authentication for at least critical accounts (at minimum), which makes\npassword expiration even less useful as well as password protection for Entra ID.",
    "impact": "When setting passwords not to expire it is important to have other controls in place to\nsupplement this setting. See below for related recommendations and user guidance.\n• Ban common passwords.\n• Educate users to not reuse organization passwords anywhere else.\n• Enforce Multi-Factor Authentication registration for all users.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings select Org Settings.\n3. Click on Security & privacy.\n4. Select Password expiration policy ensure that Set passwords to never\nexpire (recommended) has been checked.\nTo audit using PowerShell:\n1. Connect to the Microsoft Graph service using Connect-MgGraph -Scopes\n\"Domain.Read.All\".\n2. Run the following Microsoft Online PowerShell command:\nGet-MgDomain | ft id,PasswordValidityPeriodInDays\n3. Verify the value returned for valid domains is 2147483647",
    "expected_response": "4. Select Password expiration policy ensure that Set passwords to never",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings select Org Settings.\n3. Click on Security & privacy.\n4. Check the Set passwords to never expire (recommended) box.\n5. Click Save.\nTo remediate using PowerShell:\n1. Connect to the Microsoft Graph service using Connect-MgGraph -Scopes\n\"Domain.ReadWrite.All\".\n2. Run the following Microsoft Graph PowerShell command:\nUpdate-MgDomain -DomainId <Domain> -PasswordValidityPeriodInDays 2147483647",
    "default_value": "If the property is not set, a default value of 90 days will be used",
    "detection_commands": [
      "Get-MgDomain | ft id,PasswordValidityPeriodInDays"
    ],
    "remediation_commands": [
      "Update-MgDomain -DomainId <Domain> -PasswordValidityPeriodInDays 2147483647"
    ],
    "references": [
      "1. https://pages.nist.gov/800-63-3/sp800-63b.html",
      "2. https://www.cisecurity.org/white-papers/cis-password-policy-guide/",
      "3. https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-",
      "recommendations?view=o365-worldwide"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 44,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "1.3.2",
    "title": "Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "admin_center",
    "domain": "Microsoft 365 admin center",
    "subdomain": "Use Unique Passwords",
    "m365_profile": "E3",
    "description": "Idle session timeout allows the configuration of a setting which will timeout inactive\nusers after a pre-determined amount of time. When a user reaches the set idle timeout\nsession, they'll get a notification that they're about to be signed out. They must choose\nto stay signed in or they'll be automatically signed out of all Microsoft 365 web apps.\nCombined with a Conditional Access rule this will only impact unmanaged devices.\nA managed device is considered a device managed by Intune MDM or joined to a\ndomain (Entra ID or Hybrid joined).\nThe following Microsoft 365 web apps are supported.\n• Outlook Web App\n• OneDrive\n• SharePoint\n• Microsoft Fabric\n• Microsoft365.com and other start pages\n• Microsoft 365 web apps (Word, Excel, PowerPoint)\n• Microsoft 365 Admin Center\n• M365 Defender Portal\n• Microsoft Purview Compliance Portal\nThe recommended setting is 3 hours (or less) for unmanaged devices.\nNote: Idle session timeout doesn't affect Microsoft 365 desktop and mobile apps.",
    "rationale": "Ending idle sessions through an automatic process can help protect sensitive company\ndata and will add another layer of security for end users who work on unmanaged\ndevices that can potentially be accessed by the public. Unauthorized individuals onsite\nor remotely can take advantage of systems left unattended over time. Automatic timing\nout of sessions makes this more difficult.",
    "impact": "If step 2 in the Audit/Remediation procedure is left out, then there is no issue with this\nfrom a security standpoint. However, it will require users on trusted devices to sign in\nmore frequently which could result in credential prompt fatigue.\nUsers don’t get signed out in these cases:\n• If they get single sign-on (SSO) into the web app from the device joined account.\n• If they selected Stay signed in at the time of sign-in. For more info on hiding this\noption for your organization, see Add branding to your organization's sign-in\npage.\n• If they're on a managed device, that is compliant or joined to a domain and using\na supported browser, like Microsoft Edge, or Google Chrome with the Microsoft\nSingle Sign On extension.\nNote: Idle session timeout also affects the Azure Portal idle timeout if this is not\nexplicitly set to a different timeout. The Azure Portal idle timeout applies to all kind of\ndevices, not just unmanaged. See : change the directory timeout setting admin",
    "audit": "Step 1 - Ensure Idle session timeout is configured:\nTo audit using the UI:\n1. Navigate to the Microsoft 365 admin center https://admin.microsoft.com/.\n2. Click to expand Settings Select Org settings.\n3. Click Security & Privacy tab.\n4. Select Idle session timeout.\n5. Verify Turn on to set the period of inactivity for users to be\nsigned off of Microsoft 365 web apps is set to 3 hours (or less).\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.All\":\n2. Run the following script:\n$TimeoutPolicy = Get-MgPolicyActivityBasedTimeoutPolicy\n$BenchmarkTimeSpan = [TimeSpan]::Parse('03:00:00') # 3 hours\nif ($TimeoutPolicy) {\n$PolicyDefinition = $TimeoutPolicy.Definition | ConvertFrom-Json\n$Timeout =\n$PolicyDefinition.ActivityBasedTimeoutPolicy.ApplicationPolicies[0].WebSessio\nnIdleTimeout\n$TimeSpan = [TimeSpan]::Parse($Timeout)\n$TimeoutReadable = \"{0} days, {1} hours, {2} minutes\" `\n-f $TimeSpan.Days, $TimeSpan.Hours, $TimeSpan.Minutes\nif ($TimeSpan -le $BenchmarkTimeSpan) {\nWrite-Host \"** PASS ** Timeout is set to $TimeoutReadable.\"\n} else {\nWrite-Host \"** FAIL ** Timeout is too long. It is set to\n$TimeoutReadable.\"\n}\n} else {\nWrite-Host \"** FAIL **: Idle session timeout is not configured.\"\n}\n3. Verify the policy exists and is 3 hours or less.\nStep 2 - Ensure the Conditional Access policy is in place:\nTo audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/\n2. Expand Protect > Conditional Access.\n3. Inspect existing conditional access rules for one that meets the below conditions:\no Users is set to All users.\no Cloud apps or actions > Select apps is set to Office 365.\no Conditions > Client apps is Browser and nothing else.\no Session is set to Use app enforced restrictions.\no Enable Policy is set to On\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.All\":\n2. Run the following script:\n$Caps = Get-MgIdentityConditionalAccessPolicy -All |\nWhere-Object {\n$_.SessionControls.ApplicationEnforcedRestrictions.IsEnabled }\n$CapReport = [System.Collections.Generic.List[Object]]::new()\n# Filter to policies with \"Use app enforced restrictions\" enabled\n# Loop through policies and generate a per policy report.\nforeach ($policy in $Caps) {\n$Name = $policy.DisplayName\n$Users = $policy.Conditions.Users.IncludeUsers\n$Targets = $policy.Conditions.Applications.IncludeApplications\n$ClientApps = $policy.Conditions.ClientAppTypes\n$Restrictions =\n$policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled\n$State = $policy.State\n$CountPass = $Targets.count -eq 1 -and $ClientApps.count -eq 1\n$Pass = $Targets -eq 'Office365' -and $ClientApps -eq 'browser' -and\n$Restrictions -and $CountPass -and $State -eq 'enabled'\n$obj = [PSCustomObject]@{\nDisplayName             = $Name\nAuditState              = if ($Pass) { \"PASS\" } else { \"FAIL\" }\nIncludeUsers            = $Users\nIncludeApplications     = $Targets\nClientAppTypes          = $ClientApps\nAppEnforcedRestrictions = $Restrictions\nState                   = $State\n}\n$CapReport.Add($obj)\n}\nif ($Caps) {\n$CapReport\n} else {\nWrite-Host \"** FAIL **: There are no qualifying conditional access\npolicies.\"\n}\n3. The script will output qualifying Conditional Access Policies. If one policy passes,\nthen the recommendation passes. A passing policy will have the following\nproperties:\nDisplayName             : (CIS) Idle timeout for unmanaged\nAuditState              : PASS\nIncludeUsers            : {All}   # IncludeUsers not currently scored\nIncludeApplications     : {Office365}\nClientAppTypes          : {browser}\nAppEnforcedRestrictions : True\nState                   : enabled\nNote: Both steps 1 and 2 must pass audit checks in order for the recommendation to\npass as a whole.",
    "expected_response": "Step 1 - Ensure Idle session timeout is configured:\nsigned off of Microsoft 365 web apps is set to 3 hours (or less).\nWrite-Host \"** PASS ** Timeout is set to $TimeoutReadable.\"\nWrite-Host \"** FAIL ** Timeout is too long. It is set to\nStep 2 - Ensure the Conditional Access policy is in place:\no Users is set to All users.\no Cloud apps or actions > Select apps is set to Office 365.\no Session is set to Use app enforced restrictions.\no Enable Policy is set to On\n3. The script will output qualifying Conditional Access Policies. If one policy passes,\nNote: Both steps 1 and 2 must pass audit checks in order for the recommendation to",
    "remediation": "Step 1 - Configure Idle session timeout:\nTo remediate using the UI:\n1. Navigate to the Microsoft 365 admin center https://admin.microsoft.com/.\n2. Click to expand Settings Select Org settings.\n3. Click Security & Privacy tab.\n4. Select Idle session timeout.\n5. Check the box Turn on to set the period of inactivity for users to\nbe signed off of Microsoft 365 web apps\n6. Set a maximum value of 3 hours.\n7. Click save.\nStep 2 - Ensure the Conditional Access policy is in place:\nTo remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/\n2. Expand Protect > Conditional Access.\n3. Click New policy and give the policy a name.\no Select Users > All users.\no Select Cloud apps or actions > Select apps and select Office 365\no Select Conditions > Client apps > Yes check only Browser unchecking\nall other boxes.\no Select Sessions and check Use app enforced restrictions.\n4. Set Enable policy to On and click Create.\nNote: To ensure that idle timeouts affect only unmanaged devices, both steps 1 and 2\nmust be completed. Otherwise managed devices will also be impacted by the timeout\npolicy.",
    "default_value": "Not configured. (Idle sessions will not timeout.)",
    "additional_information": "According to Microsoft idle session timeout isn't supported when third party cookies are\ndisabled in the browser. Users won't see any sign-out prompts.",
    "detection_commands": [
      "$TimeoutPolicy = Get-MgPolicyActivityBasedTimeoutPolicy $BenchmarkTimeSpan = [TimeSpan]::Parse('03:00:00') # 3 hours",
      "$PolicyDefinition = $TimeoutPolicy.Definition | ConvertFrom-Json $Timeout = $PolicyDefinition.ActivityBasedTimeoutPolicy.ApplicationPolicies[0].WebSessio",
      "$TimeSpan = [TimeSpan]::Parse($Timeout) $TimeoutReadable = \"{0} days, {1} hours, {2} minutes\" `",
      "$TimeoutReadable.\"",
      "$Caps = Get-MgIdentityConditionalAccessPolicy -All |",
      "$_.SessionControls.ApplicationEnforcedRestrictions.IsEnabled } $CapReport = [System.Collections.Generic.List[Object]]::new()",
      "$Name = $policy.DisplayName $Users = $policy.Conditions.Users.IncludeUsers $Targets = $policy.Conditions.Applications.IncludeApplications $ClientApps = $policy.Conditions.ClientAppTypes $Restrictions = $policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled $State = $policy.State $CountPass = $Targets.count -eq 1 -and $ClientApps.count -eq 1 $Pass = $Targets -eq 'Office365' -and $ClientApps -eq 'browser' -and $Restrictions -and $CountPass -and $State -eq 'enabled' $obj = [PSCustomObject]@{",
      "$CapReport.Add($obj)",
      "$CapReport"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/admin/manage/idle-session-",
      "timeout-web-apps?view=o365-worldwide"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 47,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "1.3.3",
    "title": "Ensure 'External sharing' of calendars is not available",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "m365_profile": "E3",
    "description": "External calendar sharing allows an administrator to enable the ability for users to share\ncalendars with anyone outside of the organization. Outside users will be sent a URL that\ncan be used to view the calendar.",
    "rationale": "Attackers often spend time learning about organizations before launching an attack.\nPublicly available calendars can help attackers understand organizational relationships\nand determine when specific users may be more vulnerable to an attack, such as when\nthey are traveling.",
    "impact": "This functionality is not widely used. As a result, it is unlikely that implementation of this\nsetting will cause an impact to most users. Users that do utilize this functionality are\nlikely to experience a minor inconvenience when scheduling meetings or synchronizing\ncalendars with people outside the tenant.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings select Org settings.\n3. In the Services section click Calendar.\n4. Verify Let your users share their calendars with people outside of\nyour organization who have Office 365 or Exchange is unchecked.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following Exchange Online PowerShell command:\nGet-SharingPolicy -Identity \"Default Sharing Policy\" | ft Name,Enabled\n3. Verify Enabled is set to False",
    "expected_response": "3. Verify Enabled is set to False",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings select Org settings.\n3. In the Services section click Calendar.\n4. Uncheck Let your users share their calendars with people outside\nof your organization who have Office 365 or Exchange.\n5. Click Save.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following Exchange Online PowerShell command:\nSet-SharingPolicy -Identity \"Default Sharing Policy\" -Enabled $False",
    "default_value": "Enabled (True)",
    "additional_information": "The following script can be used to audit any mailboxes that might be sharing\ncalendars prior to disabling the feature globally:\n$mailboxes = Get-Mailbox -ResultSize Unlimited\nforeach ($mailbox in $mailboxes) {\n# Get the name of the default calendar folder (depends on the mailbox's\nlanguage)\n$calendarFolder = [string](Get-ExoMailboxFolderStatistics\n$mailbox.PrimarySmtpAddress -FolderScope Calendar| Where-Object {\n$_.FolderType -eq 'Calendar' }).Name\n# Get users calendar folder settings for their default Calendar folder\n# calendar has the format identity:\\<calendar folder name>\n$calendar = Get-MailboxCalendarFolder -Identity\n\"$($mailbox.PrimarySmtpAddress):\\$calendarFolder\"\nif ($calendar.PublishEnabled) {\nWrite-Host -ForegroundColor Yellow \"Calendar publishing is enabled\nfor $($mailbox.PrimarySmtpAddress) on $($calendar.PublishedCalendarUrl)\"\n}\n}",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/admin/manage/share-calendars-",
      "with-external-users?view=o365-worldwide"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 54,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.3.4",
    "title": "Ensure 'User owned apps and services' is restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Protect Information through Access Control Lists",
    "m365_profile": "E3",
    "description": "By default, users can install add-ins in their Microsoft Word, Excel, and PowerPoint\napplications, allowing data access within the application.\nDo not allow users to install add-ins in Word, Excel, or PowerPoint.",
    "rationale": "Attackers commonly use vulnerable and custom-built add-ins to access data in user\napplications.\nWhile allowing users to install add-ins by themselves does allow them to easily acquire\nuseful add-ins that integrate with Microsoft applications, it can represent a risk if not\nused and monitored carefully.\nDisable future user's ability to install add-ins in Microsoft Word, Excel, or PowerPoint\nhelps reduce your threat-surface and mitigate this risk.",
    "impact": "Implementation of this change will impact both end users and administrators. End users\nwill not be able to install add-ins that they may want to install.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings > Org settings.\n3. In Services select User owned apps and services.\n4. Verify Let users access the Office Store and Let users start trials\non behalf of your organization are not checked.\nTo Audit using PowerShell:\n1. Connect to the Microsoft Graph service using Connect-MgGraph -Scopes\n\"OrgSettings-AppsAndServices.Read.All\".\n2. Run the following Microsoft Graph PowerShell command:\n$Uri = \"https://graph.microsoft.com/beta/admin/appsAndServices/settings\"\nInvoke-MgGraphRequest -Uri $Uri\n3. Ensure both isOfficeStoreEnabled and isAppAndServicesTrialEnabled\nare False.",
    "expected_response": "3. Ensure both isOfficeStoreEnabled and isAppAndServicesTrialEnabled",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings > Org settings.\n3. In Services select User owned apps and services.\n4. Uncheck Let users access the Office Store and Let users start\ntrials on behalf of your organization.\n5. Click Save.\nTo remediate using PowerShell\n1. Connect to the Microsoft Graph service using Connect-MgGraph -Scopes\n\"OrgSettings-AppsAndServices.ReadWrite.All\".\n2. Run the following Microsoft Graph PowerShell commands:\n$uri = \"https://graph.microsoft.com/beta/admin/appsAndServices\"\n$body = @{\n\"Settings\" = @{\n\"isAppAndServicesTrialEnabled\" = $false\n\"isOfficeStoreEnabled\"         = $false\n}\n} | ConvertTo-Json\nInvoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body",
    "default_value": "Let users access the Office Store is Checked\nLet users start trials on behalf of your organization is Checked",
    "detection_commands": [
      "$Uri = \"https://graph.microsoft.com/beta/admin/appsAndServices/settings\" Invoke-MgGraphRequest -Uri $Uri"
    ],
    "remediation_commands": [
      "$uri = \"https://graph.microsoft.com/beta/admin/appsAndServices\" $body = @{ \"Settings\" = @{ \"isAppAndServicesTrialEnabled\" = $false \"isOfficeStoreEnabled\" = $false",
      "Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/admin/manage/manage-addins-",
      "in-the-admin-center?view=o365-worldwide#manage-add-in-downloads-by-",
      "turning-onoff-the-office-store-across-all-apps-except-outlook"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 57,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "1.3.5",
    "title": "Ensure internal phishing protection for Forms is enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Establish Secure Configurations",
    "m365_profile": "E3",
    "description": "Microsoft Forms can be used for phishing attacks by asking personal or sensitive\ninformation and collecting the results. Microsoft 365 has built-in protection that will\nproactively scan for phishing attempt in forms such personal information request.",
    "rationale": "Enabling internal phishing protection for Microsoft Forms will prevent attackers using\nforms for phishing attacks by asking personal or other sensitive information and URLs.",
    "impact": "If potential phishing was detected, the form will be temporarily blocked and cannot be\ndistributed, and response collection will not happen until it is unblocked by the\nadministrator or keywords were removed by the creator.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings then select Org settings.\n3. Under Services select Microsoft Forms.\n4. Ensure the checkbox labeled Add internal phishing protection is checked\nunder Phishing protection.\nTo Audit using PowerShell:\n1. Connect to the Microsoft Graph service using Connect-MgGraph -Scopes\n\"OrgSettings-Forms.Read.All\".\n2. Run the following Microsoft Graph PowerShell commands:\n$uri = 'https://graph.microsoft.com/beta/admin/forms/settings'\nInvoke-MgGraphRequest -Uri $uri | select isInOrgFormsPhishingScanEnabled\n3. Ensure isInOrgFormsPhishingScanEnabled is 'True'.",
    "expected_response": "4. Ensure the checkbox labeled Add internal phishing protection is checked\n3. Ensure isInOrgFormsPhishingScanEnabled is 'True'.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings then select Org settings.\n3. Under Services select Microsoft Forms.\n4. Click the checkbox labeled Add internal phishing protection under\nPhishing protection.\n5. Click Save.\nTo remediate using PowerShell\n1. Connect to the Microsoft Graph service using Connect-MgGraph -Scopes\n\"OrgSettings-AppsAndServices.ReadWrite.All\".\n2. Run the following Microsoft Graph PowerShell commands:\n$uri = 'https://graph.microsoft.com/beta/admin/forms/settings'\n$body = @{ \"isInOrgFormsPhishingScanEnabled\" = $true } | ConvertTo-Json\nInvoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body",
    "default_value": "Internal Phishing Protection is enabled.",
    "detection_commands": [
      "$uri = 'https://graph.microsoft.com/beta/admin/forms/settings' Invoke-MgGraphRequest -Uri $uri | select isInOrgFormsPhishingScanEnabled"
    ],
    "remediation_commands": [
      "$uri = 'https://graph.microsoft.com/beta/admin/forms/settings' $body = @{ \"isInOrgFormsPhishingScanEnabled\" = $true } | ConvertTo-Json Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-US/microsoft-forms/administrator-settings-",
      "microsoft-forms",
      "2. https://learn.microsoft.com/en-US/microsoft-forms/review-unblock-forms-users-",
      "detected-blocked-potential-phishing"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 60,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "1.3.6",
    "title": "Ensure the customer lockbox feature is enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Train Workforce Members to Recognize Social",
    "m365_profile": "E5",
    "description": "Customer Lockbox is a security feature that provides an additional layer of control and\ntransparency to customer data in Microsoft 365. It offers an approval process for\nMicrosoft support personnel to access organization data and creates an audited trail to\nmeet compliance requirements.",
    "rationale": "Enabling this feature protects organizational data against data spillage and exfiltration.",
    "impact": "Administrators will need to grant Microsoft access to the tenant environment prior to a\nMicrosoft engineer accessing the environment for support or troubleshooting.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings then select Org settings.\n3. Select Security & privacy tab.\n4. Click Customer lockbox.\n5. Ensure the box labeled Require approval for all data access requests\nis checked.\nTo audit using SecureScore:\n1. Navigate to the Microsoft 365 SecureScore portal.\nhttps://securescore.microsoft.com\n2. Search for Turn on customer lockbox feature under Improvement\nactions.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-OrganizationConfig | Select-Object CustomerLockBoxEnabled\n3. Verify the value is set to True.",
    "expected_response": "5. Ensure the box labeled Require approval for all data access requests\n3. Verify the value is set to True.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings then select Org settings.\n3. Select Security & privacy tab.\n4. Click Customer lockbox.\n5. Check the box Require approval for all data access requests.\n6. Click Save.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-OrganizationConfig -CustomerLockBoxEnabled $true",
    "default_value": "Require approval for all data access requests - Unchecked\nCustomerLockboxEnabled - False",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/purview/customer-lockbox-requests#turn-",
      "customer-lockbox-requests-on-or-off"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 62,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "1.3.7",
    "title": "Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Train Workforce Members to Recognize Social",
    "m365_profile": "E3",
    "description": "Third-party storage can be enabled for users in Microsoft 365, allowing them to store\nand share documents using services such as Dropbox, alongside OneDrive and team\nsites.\nEnsure Microsoft 365 on the web third-party storage services are restricted.",
    "rationale": "By using external storage services an organization may increase the risk of data\nbreaches and unauthorized access to confidential information. Additionally, third-party\nservices may not adhere to the same security standards as the organization, making it\ndifficult to maintain data privacy and security.",
    "impact": "Impact associated with this change is highly dependent upon current practices in the\ntenant. If users do not use other storage providers, then minimal impact is likely.\nHowever, if users do regularly utilize providers outside of the tenant this will affect their\nability to continue to do so.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com\n2. Go to Settings > Org Settings > Services > Microsoft 365 on the web\n3. Ensure Let users open files stored in third-party storage services\nin Microsoft 365 on the web is not checked.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Application.Read.All\".\n2. Run the following script:\n$SP = Get-MgServicePrincipal -Filter \"appId eq 'c1f33bc0-bdb4-4248-ba9b-\n096807ddb43e'\"\nif ((-not $SP) -or $SP.AccountEnabled) {\nWrite-Host \"Audit Result: ** FAIL **\"\n} else {\nWrite-Host \"Audit Result: ** PASS **\"\n}\n3. To pass AccountEnabled must be False.\nNote: The check will also fail if the Service Principal does not exist as users will still be\nable to open files stored in third-party storage services in Microsoft 365 on the web.",
    "expected_response": "3. Ensure Let users open files stored in third-party storage services\n3. To pass AccountEnabled must be False.\nNote: The check will also fail if the Service Principal does not exist as users will still be",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com\n2. Go to Settings > Org Settings > Services > Microsoft 365 on the web\n3. Uncheck Let users open files stored in third-party storage\nservices in Microsoft 365 on the web\nTo remediate using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Application.ReadWrite.All\"\n2. Run the following script:\n$SP = Get-MgServicePrincipal -Filter \"appId eq 'c1f33bc0-bdb4-4248-ba9b-\n096807ddb43e'\"\n# If the service principal doesn't exist then create it first.\nif (-not $SP) {\n$SP = New-MgServicePrincipal -AppId \"c1f33bc0-bdb4-4248-ba9b-\n096807ddb43e\"\n}\nUpdate-MgServicePrincipal -ServicePrincipalId $SP.Id -AccountEnabled:$false",
    "default_value": "Enabled - Users are able to open files stored in third-party storage services",
    "detection_commands": [
      "$SP = Get-MgServicePrincipal -Filter \"appId eq 'c1f33bc0-bdb4-4248-ba9b-"
    ],
    "remediation_commands": [
      "$SP = Get-MgServicePrincipal -Filter \"appId eq 'c1f33bc0-bdb4-4248-ba9b-",
      "$SP = New-MgServicePrincipal -AppId \"c1f33bc0-bdb4-4248-ba9b-",
      "Update-MgServicePrincipal -ServicePrincipalId $SP.Id -AccountEnabled:$false"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/admin/setup/set-up-file-storage-",
      "and-sharing?view=o365-worldwide#enable-or-disable-third-party-storage-",
      "services"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 64,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "1.3.8",
    "title": "Ensure that Sways cannot be shared with people outside of your organization",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Only Allow Access to Authorized Cloud Storage or",
    "m365_profile": "E3",
    "description": "Sway is a Microsoft 365 app that lets organizations create interactive, web-based\npresentations using images, text, videos and other media. Its design engine simplifies\nthe process, allowing for quick customization. Presentations can then be shared via a\nlink.\nThis setting controls user Sway sharing capability, both within and outside of the\norganization. By default, Sway is enabled for everyone in the organization.",
    "rationale": "Disable external sharing of Sway documents that can contain sensitive information to\nprevent accidental or arbitrary data leaks.",
    "impact": "Interactive reports, presentations, newsletters, and other items created in Sway will not\nbe shared outside the organization by users.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings then select Org settings.\n3. Under Services select Sway.\n4. Confirm that under Sharing the following is not checked\no Option: Let people in your organization share their sways\nwith people outside your organization.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings then select Org settings.\n3. Under Services select Sway\no Uncheck: Let people in your organization share their sways\nwith people outside your organization.\n4. Click Save.",
    "default_value": "Let people in your organization share their sways with people outside\nyour organization - Enabled",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://support.microsoft.com/en-us/office/administrator-settings-for-sway-",
      "d298e79b-b6ab-44c6-9239-aa312f5784d4",
      "2. https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-sway-",
      "service-description"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 67,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.3.9",
    "title": "Ensure shared bookings pages are restricted to select users",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Maintain an Inventory Sensitive Information",
    "m365_profile": "E3",
    "description": "Shared Bookings allows you to invite your team members and create booking pages\nand let your customers book time with you and your team. It contains various settings to\ndefine services, manage staff members, configure schedules and availability, business\nhours and customize how appointments are scheduled. These pages can be\ncustomized to fit the diverse needs of your organization. It is an extension of Person\nBookings.\nThe recommended state is to restrict the OwaMailboxPolicy-Default policy or disable\nat the organization level.",
    "rationale": "Shared Bookings pages can be exploited by threat actors to impersonate legitimate\nusers using convincing internal email addresses. A compromised low-privilege account\ncould be used to mimic high-profile identities (e.g., the CEO) and bypass impersonation\nfilters to initiate fraudulent actions like fund transfers.\nAdditionally, attackers may create authoritative-looking addresses (e.g., admin@,\nhostmaster@) to conduct social engineering attacks on external parties aimed at the\ntransfer of infrastructure control.\nTo reduce this risk, access to Shared Bookings should be limited to users with a clear\nbusiness need and subject to monitoring and governance.",
    "impact": "Disabling Shared Bookings will limit users’ ability to create self-service scheduling\npages, which may reduce convenience for teams that rely on automated meeting\ncoordination. Approved users will need to be added to a separate OWA Policy which will\nincrease administrative overhead.\nNote: Before modifying the default owa policy, ensure that any users who rely on\nShared Bookings are assigned a separate policy that explicitly allows its use. This will\nhelp prevent unintended service disruptions.",
    "audit": "Ensure Shared Bookings is turned off in the OWA Default policy. If booking is disabled\nat the tenant (OrganizationConfig) level this is also a compliant state.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following command:\nGet-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default | fl\nBookingsMailboxCreationEnabled\n3. Ensure BookingsMailboxCreationEnabled is set to False.\nOptionally: If Bookings is disabled at the organization level, this is also considered a\ncompliant state.\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following command:\nGet-OrganizationConfig | fl BookingsEnabled\n3. If BookingsEnabled is set to False, the organization is using a more restrictive\nand compliant configuration. In this case changing the default OWA policy would\nnot be required for compliance.",
    "expected_response": "Ensure Shared Bookings is turned off in the OWA Default policy. If booking is disabled\n3. Ensure BookingsMailboxCreationEnabled is set to False.\nOptionally: If Bookings is disabled at the organization level, this is also considered a\n3. If BookingsEnabled is set to False, the organization is using a more restrictive",
    "remediation": "To remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-OwaMailboxPolicy \"OwaMailboxPolicy-Default\" -\nBookingsMailboxCreationEnabled:$false\nOptionally: For a more restrictive state Bookings can be disabled at the organization\nlevel\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following command:\nSet-OrganizationConfig -BookingsEnabled $false\nNote: Disabling Bookings at the tenant (organization) level will be more impactful to end\nusers and is not required for compliance.",
    "default_value": "BookingsMailboxCreationEnabled : True (OwaMailboxPolicy-Default)\nBookingsEnabled : True",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/bookings/turn-bookings-on-or-",
      "off?view=o365-worldwide",
      "2. https://techcommunity.microsoft.com/blog/office365businessappsblog/enhancing-",
      "security-in-microsoft-bookings-best-practices-for-admins/4382447",
      "3. https://learn.microsoft.com/en-us/microsoft-365/bookings/best-practices-shared-",
      "bookings?view=o365-worldwide&source=recommendations",
      "4. https://www.cyberis.com/article/microsoft-bookings-facilitating-impersonation"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 69,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "2.1.1",
    "title": "Ensure Safe Links for Office Applications is Enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Email & collaboration",
    "m365_profile": "E5",
    "description": "Enabling Safe Links policy for Office applications allows URL's that exist inside of Office\ndocuments and email applications opened by Office, Office Online and Office mobile to\nbe processed against Defender for Office time-of-click verification and rewritten if\nrequired.\nNote: E5 Licensing includes a number of Built-in Protection policies. When auditing\npolicies note which policy you are viewing, and keep in mind CIS recommendations\noften extend the Default or Built-in Policies provided by MS. In order to Pass the highest\npriority policy must match all settings recommended.",
    "rationale": "Safe Links for Office applications extends phishing protection to documents and emails\nthat contain hyperlinks, even after they have been delivered to a user.",
    "impact": "User impact associated with this change is minor - users may experience a very short\ndelay when clicking on URLs in Office documents before being directed to the\nrequested site. Users should be informed of the change as, in the event a link is unsafe\nand blocked, they will receive a message that it has been blocked.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com\n2. Under Email & collaboration select Policies & rules\n3. Select Threat policies then Safe Links\n4. Inspect each policy and attempt to identify one that matches the parameters\noutlined below.\n5. Scroll down the pane and click on Edit Protection settings (Global Readers\nwill look for on or off values)\n6. Ensure the following protection settings are set as outlined:\nEmail\no Checked On: Safe Links checks a list of known, malicious\nlinks when users click links in email. URLs are rewritten by\ndefault\no Checked Apply Safe Links to email messages sent within the\norganization\no Checked Apply real-time URL scanning for suspicious links\nand links that point to files\no Checked Wait for URL scanning to complete before delivering\nthe message\no Unchecked Do not rewrite URLs, do checks via Safe Links API\nonly.\nTeams\no Checked On: Safe Links checks a list of known, malicious\nlinks when users click links in Microsoft Teams. URLs are\nnot rewritten\nOffice 365 Apps\no Checked On: Safe Links checks a list of known, malicious\nlinks when users click links in Microsoft Office apps. URLs\nare not rewritten\nClick protection settings\no Checked Track user clicks\no Unchecked Let users click through the original URL\n7. There is no recommendation for organization branding.\n8. Click close\nTo audit using PowerShell:\n1. Connect using Connect-ExchangeOnline.\n2. Run the following to output properties from all Safe Links policies:\n$params = @(\n'Identity',\n'EnableSafeLinksForEmail',\n'EnableSafeLinksForTeams',\n'EnableSafeLinksForOffice',\n'TrackClicks',\n'AllowClickThrough',\n'ScanUrls',\n'EnableForInternalSenders',\n'DeliverMessageAfterScan',\n'DisableUrlRewrite'\n)\nGet-SafeLinksPolicy | Select-Object -Property $Params\n3. Verify there is at least one policy that matches the properties and values below:\nIdentity                 : <Example CIS SafeLinks Policy>\nEnableSafeLinksForEmail  : True\nEnableSafeLinksForTeams  : True\nEnableSafeLinksForOffice : True\nTrackClicks              : True\nAllowClickThrough        : False\nScanUrls                 : True\nEnableForInternalSenders : True\nDeliverMessageAfterScan  : True\nDisableUrlRewrite        : False",
    "expected_response": "6. Ensure the following protection settings are set as outlined:\n2. Run the following to output properties from all Safe Links policies:",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com\n2. Under Email & collaboration select Policies & rules\n3. Select Threat policies then Safe Links\n4. Click on +Create\n5. Name the policy then click Next\n6. In Domains select all valid domains for the organization and Next\n7. Ensure the following URL & click protection settings are defined:\nEmail\no Checked On: Safe Links checks a list of known, malicious\nlinks when users click links in email. URLs are rewritten by\ndefault\no Checked Apply Safe Links to email messages sent within the\norganization\no Checked Apply real-time URL scanning for suspicious links\nand links that point to files\no Checked Wait for URL scanning to complete before delivering\nthe message\no Unchecked Do not rewrite URLs, do checks via Safe Links API\nonly.\nTeams\no Checked On: Safe Links checks a list of known, malicious\nlinks when users click links in Microsoft Teams. URLs are\nnot rewritten\nOffice 365 Apps\no Checked On: Safe Links checks a list of known, malicious\nlinks when users click links in Microsoft Office apps. URLs\nare not rewritten\nClick protection settings\no Checked Track user clicks\no Unchecked Let users click through the original URL\no There is no recommendation for organization branding.\n8. Click Next twice and finally Submit\nTo remediate using PowerShell:\n1. Connect using Connect-ExchangeOnline.\n2. Run the following PowerShell script to create a policy at highest priority that will\napply to all valid domains on the tenant:\n# Create the Policy\n$params = @{\nName = \"CIS SafeLinks Policy\"\nEnableSafeLinksForEmail = $true\nEnableSafeLinksForTeams = $true\nEnableSafeLinksForOffice = $true\nTrackClicks = $true\nAllowClickThrough = $false\nScanUrls = $true\nEnableForInternalSenders = $true\nDeliverMessageAfterScan = $true\nDisableUrlRewrite = $false\n}\nNew-SafeLinksPolicy @params\n# Create the rule for all users in all valid domains and associate with\nPolicy\nNew-SafeLinksRule -Name \"CIS SafeLinks\" -SafeLinksPolicy \"CIS SafeLinks\nPolicy\" -RecipientDomainIs (Get-AcceptedDomain).Name -Priority 0",
    "detection_commands": [
      "$params = @( 'Identity', 'EnableSafeLinksForEmail', 'EnableSafeLinksForTeams', 'EnableSafeLinksForOffice', 'TrackClicks', 'AllowClickThrough', 'ScanUrls', 'EnableForInternalSenders', 'DeliverMessageAfterScan', 'DisableUrlRewrite'"
    ],
    "remediation_commands": [
      "$params = @{"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-",
      "configure?view=o365-worldwide",
      "2. https://learn.microsoft.com/en-us/powershell/module/exchange/set-",
      "safelinkspolicy?view=exchange-ps",
      "3. https://learn.microsoft.com/en-us/defender-office-365/preset-security-",
      "policies?view=o365-worldwide"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 74,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.2",
    "title": "Ensure the Common Attachment Types Filter is enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Maintain and Enforce Network-Based URL Filters",
    "m365_profile": "E3",
    "description": "The Common Attachment Types Filter lets a user block known and custom malicious\nfile types from being attached to emails.",
    "rationale": "Blocking known malicious file types can help prevent malware-infested files from\ninfecting a host.",
    "impact": "Blocking common malicious file types should not cause an impact in modern computing\nenvironments.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules.\n3. On the Policies & rules page select Threat policies.\n4. Under Policies select Anti-malware and click on the Default (Default)\npolicy.\n5. On the policy page that appears on the righthand pane, under Protection\nsettings, verify that the Enable the common attachments filter has the\nvalue of On.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following Exchange Online PowerShell command:\nGet-MalwareFilterPolicy -Identity Default | Select-Object EnableFileFilter\n3. Verify EnableFileFilter is set to True.\nNote: Audit and Remediation guidance may focus on the Default policy however, if a\nCustom Policy exists in the organization's tenant, then ensure the setting is set as\noutlined in the highest priority policy listed.",
    "expected_response": "3. Verify EnableFileFilter is set to True.\nCustom Policy exists in the organization's tenant, then ensure the setting is set as",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules.\n3. On the Policies & rules page select Threat policies.\n4. Under polices select Anti-malware and click on the Default (Default) policy.\n5. On the Policy page that appears on the right hand pane scroll to the bottom and\nclick on Edit protection settings, check the Enable the common\nattachments filter.\n6. Click Save.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following Exchange Online PowerShell command:\nSet-MalwareFilterPolicy -Identity Default -EnableFileFilter $true\nNote: Audit and Remediation guidance may focus on the Default policy however, if a\nCustom Policy exists in the organization's tenant, then ensure the setting is set as\noutlined in the highest priority policy listed.",
    "default_value": "Always on",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/powershell/module/exchange/get-",
      "malwarefilterpolicy?view=exchange-ps",
      "2. https://learn.microsoft.com/en-us/defender-office-365/anti-malware-policies-",
      "configure?view=o365-worldwide"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 79,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.3",
    "title": "Ensure notifications for internal users sending malware is Enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Utilize Centrally Managed Anti-malware Software",
    "m365_profile": "E3",
    "description": "Exchange Online Protection (EOP) is Microsoft's cloud-based filtering service that\nprotects organizations against spam, malware, and other email threats. EOP is included\nin all Microsoft 365 organizations with Exchange Online mailboxes.\nEOP uses flexible anti-malware policies for malware protection settings. These policies\ncan be set to notify Admins of malicious activity.",
    "rationale": "This setting alerts administrators that an internal user sent a message that contained\nmalware. This may indicate an account or machine compromise that would need to be\ninvestigated.",
    "impact": "Notification of account with potential issues should not have an impact on the user.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand E-mail & Collaboration select Policies & rules.\n3. On the Policies & rules page select Threat policies.\n4. Under Policies select Anti-malware.\n5. Click on the Default (Default) policy.\n6. Ensure the setting Notify an admin about undelivered messages from\ninternal senders is set to On and that there is at least one email address\nunder Administrator email address.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following command:\nGet-MalwareFilterPolicy | fl Identity,\nEnableInternalSenderAdminNotifications, InternalSenderAdminAddress\n3. Ensure EnableInternalSenderAdminNotifications is set to True and a\nInternalSenderAdminAddress address is defined.\nNote: Audit and Remediation guidance may focus on the Default policy however, if a\nCustom Policy exists in the organization's tenant, then ensure the setting is set as\noutlined in the highest priority policy listed.",
    "expected_response": "6. Ensure the setting Notify an admin about undelivered messages from\ninternal senders is set to On and that there is at least one email address\n3. Ensure EnableInternalSenderAdminNotifications is set to True and a\nCustom Policy exists in the organization's tenant, then ensure the setting is set as",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand E-mail & Collaboration select Policies & rules.\n3. On the Policies & rules page select Threat policies.\n4. Under Policies select Anti-malware.\n5. Click on the Default (Default) policy.\n6. Click on Edit protection settings and change the settings for Notify an\nadmin about undelivered messages from internal senders to On and\nenter the email address of the administrator who should be notified under\nAdministrator email address.\n7. Click Save.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following command:\nSet-MalwareFilterPolicy -Identity '{Identity Name}' -\nEnableInternalSenderAdminNotifications $True -InternalSenderAdminAddress\n{admin@domain1.com}\nNote: Audit and Remediation guidance may focus on the Default policy however, if a\nCustom Policy exists in the organization's tenant, then ensure the setting is set as\noutlined in the highest priority policy listed.",
    "default_value": "EnableInternalSenderAdminNotifications : False\nInternalSenderAdminAddress             : $null",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-",
      "about",
      "2. https://learn.microsoft.com/en-us/defender-office-365/anti-malware-policies-",
      "configure"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 82,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.4",
    "title": "Ensure Safe Attachments policy is enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Utilize Centrally Managed Anti-malware Software",
    "m365_profile": "E5",
    "description": "The Safe Attachments policy helps protect users from malware in email attachments by\nscanning attachments for viruses, malware, and other malicious content. When an email\nattachment is received by a user, Safe Attachments will scan the attachment in a secure\nenvironment and provide a verdict on whether the attachment is safe or not.",
    "rationale": "Enabling Safe Attachments policy helps protect against malware threats in email\nattachments by analyzing suspicious attachments in a secure, cloud-based environment\nbefore they are delivered to the user's inbox. This provides an additional layer of\nsecurity and can prevent new or unseen types of malware from infiltrating the\norganization's network.",
    "impact": "Delivery of email with attachments may be delayed while scanning is occurring.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand E-mail & Collaboration select Policies & rules.\n3. On the Policies & rules page select Threat policies.\n4. Under Policies select Safe Attachments.\n5. Inspect the highest priority policy.\n6. Ensure Users and domains and Included recipient domains are in scope\nfor the organization.\n7. Ensure Safe Attachments detection response: is set to Block - Block\ncurrent and future messages and attachments with detected\nmalware.\n8. Ensure the Quarantine Policy is set to AdminOnlyAccessPolicy.\n9. Ensure the policy is not disabled.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-SafeAttachmentPolicy | ft Identity,Enable,Action,QuarantineTag\n3. Inspect the highest priority safe attachments policy and ensure the properties\nand values match the below:\nEnable        : True\nAction        : Block\nQuarantineTag : AdminOnlyAccessPolicy\nNote: To view the priority for a policy the Get-SafeAttachmentRule must be used.\nBuilt-in policies will always have a priority of lowest while presets like strict and\nstandard can be viewed with Get-ATPProtectionPolicyRule. Strict and standard\npresets always operate at a higher priority than custom policies.",
    "expected_response": "6. Ensure Users and domains and Included recipient domains are in scope\n7. Ensure Safe Attachments detection response: is set to Block - Block\n8. Ensure the Quarantine Policy is set to AdminOnlyAccessPolicy.\n9. Ensure the policy is not disabled.\n3. Inspect the highest priority safe attachments policy and ensure the properties\nNote: To view the priority for a policy the Get-SafeAttachmentRule must be used.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand E-mail & Collaboration select Policies & rules.\n3. On the Policies & rules page select Threat policies.\n4. Under Policies select Safe Attachments.\n5. Click + Create.\n6. Create a Policy Name and Description, and then click Next.\n7. Select all valid domains and click Next.\n8. Select Block.\n9. Quarantine policy is AdminOnlyAccessPolicy.\n10. Leave Enable redirect unchecked.\n11. Click Next and finally Submit.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. To change an existing policy modify the example below and run the following\nPowerShell command:\nSet-SafeAttachmentPolicy -Identity 'Example policy' -Action 'Block' -\nQuarantineTag 'AdminOnlyAccessPolicy' -Enable $true\n3. Or, edit and run the below example to create a new safe attachments policy.\nNew-SafeAttachmentPolicy -Name \"CIS 2.1.4\" -Enable $true -Action 'Block' -\nQuarantineTag 'AdminOnlyAccessPolicy'\nNew-SafeAttachmentRule -Name \"CIS 2.1.4 Rule\" -SafeAttachmentPolicy \"CIS\n2.1.4\" -RecipientDomainIs 'exampledomain[.]com'\nNote: Policy targets such as users and domains should include domains, or groups that\nprovide coverage for a majority of users in the organization. Different inclusion and\nexclusion use cases are not covered in the benchmark.",
    "default_value": "Identity      : Built-In Protection Policy\nEnable        : True\nAction        : Block\nQuarantineTag : AdminOnlyAccessPolicy\nPriority      : (lowest)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about",
      "2. https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-policies-",
      "configure"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 85,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.5",
    "title": "Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Utilize Centrally Managed Anti-malware Software",
    "m365_profile": "E5",
    "description": "Safe Attachments for SharePoint, OneDrive, and Microsoft Teams scans these services\nfor malicious files.",
    "rationale": "Safe Attachments for SharePoint, OneDrive, and Microsoft Teams protect organizations\nfrom inadvertently sharing malicious files. When a malicious file is detected that file is\nblocked so that no one can open, copy, move, or share it until further actions are taken\nby the organization's security team.",
    "impact": "Impact associated with Safe Attachments is minimal, and equivalent to impact\nassociated with anti-virus scanners in an environment.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com\n2. Under Email & collaboration select Policies & rules\n3. Select Threat policies then Safe Attachments.\n4. Click on Global settings\n5. Ensure the toggle is Enabled to Turn on Defender for Office 365 for\nSharePoint, OneDrive, and Microsoft Teams.\n6. Ensure the toggle is Enabled to Turn on Safe Documents for Office\nclients.\n7. Ensure the toggle is Deselected/Disabled to Allow people to click\nthrough Protected View even if Safe Documents identified the file\nas malicious.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-AtpPolicyForO365 | fl\nName,EnableATPForSPOTeamsODB,EnableSafeDocs,AllowSafeDocsOpen\nVerify the values for each parameter as below:\nEnableATPForSPOTeamsODB : True\nEnableSafeDocs : True\nAllowSafeDocsOpen : False",
    "expected_response": "5. Ensure the toggle is Enabled to Turn on Defender for Office 365 for\n6. Ensure the toggle is Enabled to Turn on Safe Documents for Office\n7. Ensure the toggle is Deselected/Disabled to Allow people to click",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com\n2. Under Email & collaboration select Policies & rules\n3. Select Threat policies then Safe Attachments.\n4. Click on Global settings\n5. Click to Enable Turn on Defender for Office 365 for SharePoint,\nOneDrive, and Microsoft Teams\n6. Click to Enable Turn on Safe Documents for Office clients\n7. Click to Disable Allow people to click through Protected View even\nif Safe Documents identified the file as malicious.\n8. Click Save\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true -EnableSafeDocs $true -\nAllowSafeDocsOpen $false",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-for-spo-",
      "odfb-teams-about"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 89,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "2.1.6",
    "title": "Ensure Exchange Online Spam Policies are set to notify administrators",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Utilize Centrally Managed Anti-malware Software",
    "m365_profile": "E3",
    "description": "In Microsoft 365 organizations with mailboxes in Exchange Online or standalone\nExchange Online Protection (EOP) organizations without Exchange Online mailboxes,\nemail messages are automatically protected against spam (junk email) by EOP.\nConfigure Exchange Online Spam Policies to copy emails and notify someone when a\nsender in the organization has been blocked for sending spam emails.",
    "rationale": "A blocked account is a good indication that the account in question has been breached,\nand an attacker is using it to send spam emails to other people.",
    "impact": "Notification of users that have been blocked should not cause an impact to the user.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules > Threat\npolicies.\n3. Under Policies select Anti-spam.\n4. Click on the Anti-spam outbound policy (default).\n5. Verify that Send a copy of suspicious outbound messages or message\nthat exceed these limits to these users and groups is set to On,\nensure the email address is correct.\n6. Verify that Notify these users and groups if a sender is blocked due\nto sending outbound spam is set to On, ensure the email address is correct.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-HostedOutboundSpamFilterPolicy | Select-Object Bcc*, Notify*\n3. Verify both BccSuspiciousOutboundMail and NotifyOutboundSpam are set to\nTrue and the email addresses to be notified are correct.\nNote: Audit and Remediation guidance may focus on the Default policy however, if a\nCustom Policy exists in the organization's tenant, then ensure the setting is set as\noutlined in the highest priority policy listed.",
    "expected_response": "that exceed these limits to these users and groups is set to On,\nensure the email address is correct.\nto sending outbound spam is set to On, ensure the email address is correct.\n3. Verify both BccSuspiciousOutboundMail and NotifyOutboundSpam are set to\nCustom Policy exists in the organization's tenant, then ensure the setting is set as",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules> Threat\npolicies.\n3. Under Policies select Anti-spam.\n4. Click on the Anti-spam outbound policy (default).\n5. Select Edit protection settings then under Notifications\n6. Check Send a copy of suspicious outbound messages or message that\nexceed these limits to these users and groups then enter the desired\nemail addresses.\n7. Check Notify these users and groups if a sender is blocked due to\nsending outbound spam then enter the desired email addresses.\n8. Click Save.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\n$BccEmailAddress = @(\"<INSERT-EMAIL>\")\n$NotifyEmailAddress = @(\"<INSERT-EMAIL>\")\nSet-HostedOutboundSpamFilterPolicy -Identity Default -\nBccSuspiciousOutboundAdditionalRecipients $BccEmailAddress -\nBccSuspiciousOutboundMail $true -NotifyOutboundSpam $true -\nNotifyOutboundSpamRecipients $NotifyEmailAddress\nNote: Audit and Remediation guidance may focus on the Default policy however, if a\nCustom Policy exists in the organization's tenant, then ensure the setting is set as\noutlined in the highest priority policy listed.",
    "default_value": "BccSuspiciousOutboundAdditionalRecipients : {}\nBccSuspiciousOutboundMail                 : False\nNotifyOutboundSpamRecipients              : {}\nNotifyOutboundSpam                        : False",
    "detection_commands": [],
    "remediation_commands": [
      "$BccEmailAddress = @(\"<INSERT-EMAIL>\") $NotifyEmailAddress = @(\"<INSERT-EMAIL>\")"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-protection-",
      "about"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 92,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.7",
    "title": "Ensure that an anti-phishing policy has been created",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Sandbox All Email Attachments",
    "m365_profile": "E5",
    "description": "By default, Office 365 includes built-in features that help protect users from phishing\nattacks. Set up anti-phishing polices to increase this protection, for example by refining\nsettings to better detect and prevent impersonation and spoofing attacks. The default\npolicy applies to all users within the organization and is a single view to fine-tune anti-\nphishing protection. Custom policies can be created and configured for specific users,\ngroups or domains within the organization and will take precedence over the default\npolicy for the scoped users.",
    "rationale": "Protects users from phishing attacks (like impersonation and spoofing) and uses safety\ntips to warn users about potentially harmful messages.",
    "impact": "Mailboxes that are used for support systems such as helpdesk and billing systems send\nmail to internal users and are often not suitable candidates for impersonation protection.\nCare should be taken to ensure that these systems are excluded from Impersonation\nProtection.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules\n3. Select Threat policies.\n4. Under Policies select Anti-phishing.\n5. Ensure an AntiPhish policy exists that is On and meets the following criteria:\n6. Under Users, groups, and domains.\no Verify that the included domains and groups includes a majority of the\norganization.\n7. Under Phishing threshold & protection\no Verify Phishing email threshold is at least 3 - More Aggressive.\no Verify User impersonation protection is On and contains a subset of\nusers.\no Verify Domain impersonation protection is On for owned domains.\no Verify Mailbox intelligence and Mailbox intelligence for\nimpersonations and Spoof intelligence are On.\n8. Under Actions review the following:\no Verify If a message is detected as user impersonation is set to\nQuarantine the message.\no Verify If a message is detected as domain impersonation is set to\nQuarantine the message.\no Verify If Mailbox Intelligence detects an impersonated user is\nset to Quarantine the message.\no Verify First contact safety tip is On.\no Verify User impersonation safety tip is On.\no Verify Domain impersonation safety tip is On.\no Verify Unusual characters safety tip is On.\no Verify Honor DMARC record policy when the message is detected\nas spoof is On.\nNote: DefaultFullAccessWithNotificationPolicy is suggested but not required.\nUsers will be notified that impersonation emails are in the Quarantine.\nTo audit using PowerShell:\n1. Connect to Exchange Online service using Connect-ExchangeOnline.\n2. Run the following Exchange Online PowerShell commands:\n$params = @(\n\"name\",\"Enabled\",\"PhishThresholdLevel\",\"EnableTargetedUserProtection\"\n\"EnableOrganizationDomainsProtection\",\"EnableMailboxIntelligence\"\n\"EnableMailboxIntelligenceProtection\",\"EnableSpoofIntelligence\"\n\"TargetedUserProtectionAction\",\"TargetedDomainProtectionAction\"\n\"MailboxIntelligenceProtectionAction\",\"EnableFirstContactSafetyTips\"\n\"EnableSimilarUsersSafetyTips\",\"EnableSimilarDomainsSafetyTips\"\n\"EnableUnusualCharactersSafetyTips\",\"TargetedUsersToProtect\"\n\"HonorDmarcPolicy\"\n)\nGet-AntiPhishPolicy | fl $params\n3. Verify there is a policy created that has matching values for the following\nparameters:\nEnabled                             : True\nPhishThresholdLevel                 : 3\nEnableTargetedUserProtection        : True\nEnableOrganizationDomainsProtection : True\nEnableMailboxIntelligence           : True\nEnableMailboxIntelligenceProtection : True\nEnableSpoofIntelligence             : True\nTargetedUserProtectionAction        : Quarantine\nTargetedDomainProtectionAction      : Quarantine\nMailboxIntelligenceProtectionAction : Quarantine\nEnableFirstContactSafetyTips        : True\nEnableSimilarUsersSafetyTips        : True\nEnableSimilarDomainsSafetyTips      : True\nEnableUnusualCharactersSafetyTips   : True\nTargetedUsersToProtect              : {<contains users>}\nHonorDmarcPolicy                    : True\n4. Verify that TargetedUsersToProtect contains a subset of the organization, up\nto 350 users, for targeted Impersonation Protection.\n5. Use PowerShell to verify the AntiPhishRule is configured and enabled.\nGet-AntiPhishRule |\nft AntiPhishPolicy,Priority,State,SentToMemberOf,RecipientDomainIs\n6. Identity correct rule from the matching AntiPhishPolicy name in step 3. Ensure\nthe rule defines groups or domains that include the majority of the organization\nby inspecting SentToMemberOf or RecipientDomainIs.\nNote: Audit guidance is intended to help identify a qualifying AntiPhish policy+rule that\nmeets the recommended criteria while protecting the majority of the organization. It's\nunderstood some individual user exceptions may exist or exceptions for the entire policy\nif another product stands in as an equivalent control.",
    "expected_response": "5. Ensure an AntiPhish policy exists that is On and meets the following criteria:\no Verify If a message is detected as user impersonation is set to\no Verify If a message is detected as domain impersonation is set to\n5. Use PowerShell to verify the AntiPhishRule is configured and enabled.\n6. Identity correct rule from the matching AntiPhishPolicy name in step 3. Ensure",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules\n3. Select Threat policies.\n4. Under Policies select Anti-phishing and click Create.\n5. Name the policy, continuing and clicking Next as needed:\no Add Groups and/or Domains that contain a majority of the organization.\no Set Phishing email threshold to 3 - More Aggressive\no Check Enable users to protect and add up to 350 users.\no Check Enable domains to protect and check Include domains I\nown.\no Check Enable mailbox intelligence (Recommended).\no Check Enable Intelligence for impersonation protection\n(Recommended).\no Check Enable spoof intelligence (Recommended).\n6. Under Actions configure the following:\no Set If a message is detected as user impersonation to\nQuarantine the message.\no Set If a message is detected as domain impersonation to\nQuarantine the message.\no Set If Mailbox Intelligence detects an impersonated user to\nQuarantine the message.\no Leave Honor DMARC record policy when the message is detected\nas spoof checked.\no Check Show first contact safety tip (Recommended).\no Check Show user impersonation safety tip.\no Check Show domain impersonation safety tip.\no Check Show user impersonation unusual characters safety tip.\n7. Finally click Next and Submit the policy.\nNote: DefaultFullAccessWithNotificationPolicy is suggested but not required.\nUsers will be notified that impersonation emails are in the Quarantine.\nTo remediate using PowerShell:\n1. Connect to Exchange Online service using Connect-ExchangeOnline.\n2. Run the following Exchange Online PowerShell script to create an AntiPhish\npolicy:\n# Create the Policy\n$params = @{\nName = \"CIS AntiPhish Policy\"\nPhishThresholdLevel = 3\nEnableTargetedUserProtection = $true\nEnableOrganizationDomainsProtection = $true\nEnableMailboxIntelligence = $true\nEnableMailboxIntelligenceProtection = $true\nEnableSpoofIntelligence = $true\nTargetedUserProtectionAction = 'Quarantine'\nTargetedDomainProtectionAction = 'Quarantine'\nMailboxIntelligenceProtectionAction = 'Quarantine'\nTargetedUserQuarantineTag = 'DefaultFullAccessWithNotificationPolicy'\nMailboxIntelligenceQuarantineTag =\n'DefaultFullAccessWithNotificationPolicy'\nTargetedDomainQuarantineTag = 'DefaultFullAccessWithNotificationPolicy'\nEnableFirstContactSafetyTips = $true\nEnableSimilarUsersSafetyTips = $true\nEnableSimilarDomainsSafetyTips = $true\nEnableUnusualCharactersSafetyTips = $true\nHonorDmarcPolicy = $true\n}\nNew-AntiPhishPolicy @params\n# Create the rule for all users in all valid domains and associate with\nPolicy\nNew-AntiPhishRule -Name $params.Name -AntiPhishPolicy $params.Name -\nRecipientDomainIs (Get-AcceptedDomain).Name -Priority 0\n3. The new policy can be edited in the UI or via PowerShell.\nNote: Remediation guidance is intended to help create a qualifying AntiPhish policy that\nmeets the recommended criteria while protecting the majority of the organization. It's\nunderstood some individual user exceptions may exist or exceptions for the entire policy\nif another product acts as a similar control.",
    "detection_commands": [
      "$params = @( \"name\",\"Enabled\",\"PhishThresholdLevel\",\"EnableTargetedUserProtection\" \"EnableOrganizationDomainsProtection\",\"EnableMailboxIntelligence\" \"EnableMailboxIntelligenceProtection\",\"EnableSpoofIntelligence\" \"TargetedUserProtectionAction\",\"TargetedDomainProtectionAction\" \"MailboxIntelligenceProtectionAction\",\"EnableFirstContactSafetyTips\" \"EnableSimilarUsersSafetyTips\",\"EnableSimilarDomainsSafetyTips\" \"EnableUnusualCharactersSafetyTips\",\"TargetedUsersToProtect\" \"HonorDmarcPolicy\""
    ],
    "remediation_commands": [
      "$params = @{"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-protection-",
      "about",
      "2. https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-eop-",
      "configure"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 95,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.8",
    "title": "Ensure that SPF records are published for all Exchange Domains",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Deploy and Maintain Email Server Anti-Malware",
    "m365_profile": "E3",
    "description": "For each domain that is configured in Exchange, a corresponding Sender Policy\nFramework (SPF) record should be created.",
    "rationale": "SPF records allow Exchange Online Protection and other mail systems to know where\nmessages from domains are allowed to originate. This information can be used by that\nsystem to determine how to treat the message based on if it is being spoofed or is valid.",
    "impact": "There should be minimal impact of setting up SPF records however, organizations\nshould ensure proper SPF record setup as email could be flagged as spam if SPF is not\nsetup appropriately.",
    "audit": "To audit using PowerShell:\n1. Open a command prompt.\n2. Type the following command in PowerShell:\nResolve-DnsName [domain1.com] txt | fl\n3. Ensure that a value exists and that it includes v=spf1\ninclude:spf.protection.outlook.com. This designates Exchange Online as\na designated sender.\nTo verify the SPF records are published, use the REST API for each domain:\nhttps://graph.microsoft.com/v1.0/domains/[DOMAIN.COM]/serviceConfigurationRec\nords\n1. Ensure that a value exists that includes v=spf1\ninclude:spf.protection.outlook.com. This designates Exchange Online as\na designated sender.\nNote: Resolve-DnsName is not available on older versions of Windows prior to\nWindows 8 and Server 2012.",
    "expected_response": "3. Ensure that a value exists and that it includes v=spf1\n1. Ensure that a value exists that includes v=spf1",
    "remediation": "To remediate using a DNS Provider:\n1. If all email in your domain is sent from and received by Exchange Online, add the\nfollowing TXT record for each Accepted Domain:\nv=spf1 include:spf.protection.outlook.com -all\n2. If there are other systems that send email in the environment, refer to this article\nfor the proper SPF configuration: https://docs.microsoft.com/en-\nus/office365/SecurityCompliance/set-up-spf-in-office-365-to-help-prevent-\nspoofing.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/security/office-365-",
      "security/email-authentication-spf-configure?view=o365-worldwide"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 101,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.9",
    "title": "Ensure that DKIM is enabled for all Exchange Online Domains",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Implement DMARC and Enable Receiver-Side",
    "m365_profile": "E3",
    "description": "DKIM is one of the trio of Authentication methods (SPF, DKIM and DMARC) that help\nprevent attackers from sending messages that look like they come from your domain.\nDKIM lets an organization add a digital signature to outbound email messages in the\nmessage header. When DKIM is configured, the organization authorizes it's domain to\nassociate, or sign, its name to an email message using cryptographic authentication.\nEmail systems that get email from this domain can use a digital signature to help verify\nwhether incoming email is legitimate.\nUse of DKIM in addition to SPF and DMARC to help prevent malicious actors using\nspoofing techniques from sending messages that look like they are coming from your\ndomain.",
    "rationale": "By enabling DKIM with Office 365, messages that are sent from Exchange Online will\nbe cryptographically signed. This will allow the receiving email system to validate that\nthe messages were generated by a server that the organization authorized and not\nbeing spoofed.",
    "impact": "There should be no impact of setting up DKIM however, organizations should ensure\nappropriate setup to ensure continuous mail-flow.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com/\n2. Expand Email & collaboration > Policies & rules > Threat policies.\n3. Under Rules section click Email authentication settings.\n4. Select DKIM\n5. Click on each domain and confirm that Sign messages for this domain with\nDKIM signatures is Enabled and Status reads Signing DKIM signatures\nfor this domain.\n6. A status of Not signing DKIM signatures for this domain is an audit fail.\nNote: For step 5 these can also be audited the overview showing all domains. In this\ncase a passing audit procedure will be Toggle set as Enabled and Status as Valid.\nTo audit using PowerShell:\n1. Connect to Exchange Online service using Connect-ExchangeOnline.\n2. Run the following Exchange Online PowerShell command:\nGet-DkimSigningConfig | Format-Table Name,Enabled,Status\n3. For each domain verify that Enabled is True and Status is Valid.",
    "expected_response": "DKIM signatures is Enabled and Status reads Signing DKIM signatures",
    "remediation": "To remediate using a DNS Provider:\n1. For each accepted domain in Exchange Online, two DNS entries are required.\nHost name:   selector1._domainkey\nPoints to address or value: selector1-\n<domainGUID>._domainkey.<initialDomain>\nTTL:    3600\nHost name:   selector2._domainkey\nPoints to address or value: selector2-\n<domainGUID>._domainkey.<initialDomain>\nTTL:    3600\nFor Office 365, the selectors will always be selector1 or selector2.\ndomainGUID is the same as the domainGUID in the customized MX record for your\ncustom domain that appears before mail.protection.outlook.com. For example, in the\nfollowing MX record for the domain contoso.com, the domainGUID is contoso-com:\ncontoso.com.  3600  IN  MX   5 contoso-com.mail.protection.outlook.com\nThe initial domain is the domain that you used when you signed up for Office 365. Initial\ndomains always end with on.microsoft.com.\n1. After the DNS records are created, enable DKIM signing in Defender.\n2. Navigate to Microsoft 365 Defender https://security.microsoft.com/\n3. Expand Email & collaboration > Policies & rules > Threat policies.\n4. Under Rules section click Email authentication settings.\n5. Select DKIM\n6. Click on each domain and click Enable next to Sign messages for this\ndomain with DKIM signature.\nFinal remediation step using the Exchange Online PowerShell Module:\n1. Connect to Exchange Online service using Connect-ExchangeOnline.\n2. Run the following Exchange Online PowerShell command:\nSet-DkimSigningConfig -Identity < domainName > -Enabled $True",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/security/office-365-",
      "security/email-authentication-dkim-configure?view=o365-worldwide"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 103,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.10",
    "title": "Ensure DMARC Records for all Exchange Online domains are published",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Implement DMARC and Enable Receiver-Side",
    "m365_profile": "E3",
    "description": "DMARC, or Domain-based Message Authentication, Reporting, and Conformance,\nassists recipient mail systems in determining the appropriate action to take when\nmessages from a domain fail to meet SPF or DKIM authentication criteria.",
    "rationale": "DMARC strengthens the trustworthiness of messages sent from an organization's\ndomain to destination email systems. By integrating DMARC with SPF (Sender Policy\nFramework) and DKIM (DomainKeys Identified Mail), organizations can significantly\nenhance their defenses against email spoofing and phishing attempts.\nLeaving a DMARC policy set to p=none can result in failed action when a spear phishing\nemail fails DMARC but passes SPF and DKIM checks. Having DMARC fully configured\nis a critical part in preventing business email compromise.",
    "impact": "There should be no impact of setting up DMARC however, organizations should ensure\nappropriate setup to ensure continuous mail-flow.",
    "audit": "To audit using PowerShell:\n1. Open a command prompt.\n2. For each of the Accepted Domains in Exchange Online run the following in\nPowerShell:\nResolve-DnsName _dmarc.[domain1.com] txt\n3. Ensure that the record exists and has at minimum the following flags defined as\nfollows:\nv=DMARC1; (p=quarantine OR p=reject), pct=100, rua=mailto:<reporting\nemail address> and ruf=mailto:<reporting email address>\nThe below example records would pass as they contain a policy that would either\nquarantine or reject messages failing DMARC, the policy affects 100% of mail\npct=100 as well as containing valid reporting addresses:\nv=DMARC1; p=reject; pct=100; rua=mailto:rua@contoso.com;\nruf=mailto:ruf@contoso.com; fo=1\nv=DMARC1; p=reject; pct=100; fo=1; ri=3600; rua=mailto:rua@contoso.com;\nruf=mailto:ruf@contoso.com\nv=DMARC1; p=quarantine; pct=100; sp=none; fo=1; ri=3600;\nrua=mailto:rua@contoso.com; ruf=ruf@contoso.com;\n4. Ensure the Microsoft MOERA domain is also configured.\nResolve-DnsName _dmarc.[tenant].onmicrosoft.com txt\n5. Ensure the record meets the same criteria listed in step #3.\nNote: Resolve-DnsName is not available on older versions of Windows prior to\nWindows 8 and Server 2012.",
    "expected_response": "3. Ensure that the record exists and has at minimum the following flags defined as\n4. Ensure the Microsoft MOERA domain is also configured.\n5. Ensure the record meets the same criteria listed in step #3.",
    "remediation": "To remediate using a DNS Provider:\n1. For each Exchange Online Accepted Domain, add the following record to DNS:\nRecord:  _dmarc.domain1.com\nType:  TXT\nValue:  v=DMARC1; p=none; rua=mailto:<rua-report@example.com>;\nruf=mailto:<ruf-report@example.com>\n2. This will create a basic DMARC policy that will allow the organization to start\nmonitoring message statistics.\n3. One week is enough time for data generated by the reports to be useful in\nunderstanding email trends and traffic. The final step requires implementing a\npolicy of p=reject OR p=quarantine and pct=100 with the necessary rua and\nruf email addresses defined:\nRecord:  _dmarc.domain1.com\nType:  TXT\nValue:  v=DMARC1; p=reject; pct=100; rua=mailto:<rua-report@example.com>;\nruf=mailto:<ruf-report@example.com>\nAlso remediate the MOREA domain using the UI:\n1. Navigate to the Microsoft 365 admin center https://admin.microsoft.com/\n2. Expand Settings and select Domains.\n3. Select your tenant domain (for example, contoso.onmicrosoft.com).\n4. Select DNS records and click + Add record.\n5. Add a new record with the TXT name of _dmarc with the appropriate values\noutlined above.\nNote: The remediation portion involves a multi-staged approach over a period of time.\nFirst, a baseline of the current state of email will be established with p=none and rua\nand ruf. Once the environment is better understood and reports have been analyzed\nan organization will move to the final state with dmarc record values as outlined in the\naudit section.\nMicrosoft has a list of best practices for implementing DMARC that cover these steps in\ndetail.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/email-authentication-",
      "dmarc-configure?view=o365-worldwide",
      "2. https://learn.microsoft.com/en-us/defender-office-365/step-by-step-guides/how-",
      "to-enable-dmarc-reporting-for-microsoft-online-email-routing-address-moera-and-",
      "parked-domains?view=o365-worldwide",
      "3. https://media.defense.gov/2024/May/02/2003455483/-1/-1/0/CSA-NORTH-",
      "KOREAN-ACTORS-EXPLOIT-WEAK-DMARC.PDF"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 107,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.11",
    "title": "Ensure comprehensive attachment filtering is applied",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Implement DMARC and Enable Receiver-Side",
    "m365_profile": "E3",
    "description": "The Common Attachment Types Filter lets a user block known and custom malicious\nfile types from being attached to emails. The policy provided by Microsoft covers 53\nextensions, and an additional custom list of extensions can be defined.\nThe list of 184 extensions provided in this recommendation is comprehensive but not\nexhaustive.",
    "rationale": "Blocking known malicious file types can help prevent malware-infested files from\ninfecting a host or performing other malicious attacks such as phishing and data\nextraction.\nDefining a comprehensive list of attachments can help protect against additional\nunknown and known threats. Many legacy file formats, binary files and compressed files\nhave been used as delivery mechanisms for malicious software. Organizations can\nprotect themselves from Business E-mail Compromise (BEC) by allow-listing only the\nfile types relevant to their line of business and blocking all others.",
    "impact": "For file types that are business necessary users will need to use other organizationally\napproved methods to transfer blocked extension types between business partners.",
    "audit": "For this control, a Level 2 comprehensive attachment policy is defined as one that\nincludes at least 120 extensions. The 184 extensions included are a known vector for\nmalicious activity. To pass, organizations must demonstrate at least a 90% adoption\nrate of the extension list referenced in the script below, with allowances for justified\nexceptions. Since individual extensions are not assigned specific risk weights,\nexceptions should be based on documented business needs.\nNote: Utilizing the UI for auditing Anti-malware policies can be very time consuming so\nit is recommended to use a script like the one supplied below.\nTo Audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following script:\n$AttachExts = @(\n\"7z\", \"a3x\", \"ace\", \"ade\", \"adp\", \"ani\", \"app\", \"appinstaller\",\n\"applescript\", \"application\", \"appref-ms\", \"appx\", \"appxbundle\", \"arj\",\n\"asd\", \"asx\", \"bas\", \"bat\", \"bgi\", \"bz2\", \"cab\", \"chm\", \"cmd\", \"com\",\n\"cpl\", \"crt\", \"cs\", \"csh\", \"daa\", \"dbf\", \"dcr\", \"deb\",\n\"desktopthemepackfile\", \"dex\", \"diagcab\", \"dif\", \"dir\", \"dll\", \"dmg\",\n\"doc\", \"docm\", \"dot\", \"dotm\", \"elf\", \"eml\", \"exe\", \"fxp\", \"gadget\", \"gz\",\n\"hlp\", \"hta\", \"htc\", \"htm\", \"html\", \"hwpx\", \"ics\", \"img\",\n\"inf\", \"ins\", \"iqy\", \"iso\", \"isp\", \"jar\", \"jnlp\", \"js\", \"jse\", \"kext\",\n\"ksh\", \"lha\", \"lib\", \"library-ms\", \"lnk\", \"lzh\", \"macho\", \"mam\", \"mda\",\n\"mdb\", \"mde\", \"mdt\", \"mdw\", \"mdz\", \"mht\", \"mhtml\", \"mof\", \"msc\", \"msi\",\n\"msix\", \"msp\", \"msrcincident\", \"mst\", \"ocx\", \"odt\", \"ops\", \"oxps\", \"pcd\",\n\"pif\", \"plg\", \"pot\", \"potm\", \"ppa\", \"ppam\", \"ppkg\", \"pps\", \"ppsm\", \"ppt\",\n\"pptm\", \"prf\", \"prg\", \"ps1\", \"ps11\", \"ps11xml\", \"ps1xml\", \"ps2\",\n\"ps2xml\", \"psc1\", \"psc2\", \"pub\", \"py\", \"pyc\", \"pyo\", \"pyw\", \"pyz\",\n\"pyzw\", \"rar\", \"reg\", \"rev\", \"rtf\", \"scf\", \"scpt\", \"scr\", \"sct\",\n\"searchConnector-ms\", \"service\", \"settingcontent-ms\", \"sh\", \"shb\", \"shs\",\n\"shtm\", \"shtml\", \"sldm\", \"slk\", \"so\", \"spl\", \"stm\", \"svg\", \"swf\", \"sys\",\n\"tar\", \"theme\", \"themepack\", \"timer\", \"uif\", \"url\", \"uue\", \"vb\", \"vbe\",\n\"vbs\", \"vhd\", \"vhdx\", \"vxd\", \"wbk\", \"website\", \"wim\", \"wiz\", \"ws\", \"wsc\",\n\"wsf\", \"wsh\", \"xla\", \"xlam\", \"xlc\", \"xll\", \"xlm\", \"xls\", \"xlsb\", \"xlsm\",\n\"xlt\", \"xltm\", \"xlw\", \"xnk\", \"xps\", \"xsl\", \"xz\", \"z\"\n)\n$MalwareFilterPolicies = Get-MalwareFilterPolicy\n$MalwareFilterRules = Get-MalwareFilterRule\n# A policy must have at least 90% of the extensions in the reference list to\npass.\n# This allows for some flexibility with exceptions.\n$PassingValue = .90 # 90%\n$FailThreshold = [int]($AttachExts.count * (1 - $PassingValue))\n# Only evaluate policies that have more than 120 extensions defined\n# so we don't output failures on policies that aren't specific to\n# extension filtering.\n$CompPolicies = $MalwareFilterPolicies | Where-Object { $_.FileTypes.Count -\ngt 120 }\nif (-not $CompPolicies) {\nWrite-Output \"## FAIL ## No comprehensive policies found to evaluate.\"\nreturn\n}\n$ExtensionReport = foreach ($policy in $CompPolicies) {\n$Missing = Compare-Object -ReferenceObject $AttachExts `\n-DifferenceObject $policy.FileTypes `\n-PassThru | Where-Object { $_.SideIndicator -eq '<=' }\n$FoundRule = $MalwareFilterRules |\nWhere-Object { $_.MalwareFilterPolicy -eq $policy.Id }\n# Define passing conditions to determine if this policy passes all\nchecks.\n$Pass = ($Missing.Count -lt $FailThreshold) -and\n($FoundRule.State -eq 'Enabled') -and\n($policy.EnableFileFilter -eq $true)\n[PSCustomObject]@{\nPolicyName        = $policy.Identity\nIsCISCompliant    = $Pass\nEnableFileFilter  = $policy.EnableFileFilter\nState             = $FoundRule.State\nMissingCount      = $Missing.count\nMissingExtensions = $Missing -join \", \"\nExtensionCount    = $policy.FileTypes.count\n}\n}\n# Output results in various formats\n$ExtensionReport | Format-Table -AutoSize\n<# Optional: Export methods\n$ExtensionReport | Out-GridView -Title \"Attachment Filter results\"\n$ExtensionReport | Export-Csv -Path \"2.1.11.csv\" -NoTypeInformation\n$ExtensionReport | ConvertTo-Json | Out-File -FilePath \"2.1.11.json\"\n#>\n3. Review the results, only policies with over 120 extensions defined will be\nevaluated. At the end of the script examples of different output formats are given.\n4. A pass is given for the following conditions:\no A single active policy exists that covers all file extensions listed except\nthose defined as an exception by the organization.\no The policy has a state of Enabled.\no The EnableFileFilter property is set to True.\n5. The report includes a IsCISCompliant property, where True indicates in\ncompliance, allowing for up to 10% of the listed extensions to be missing as\ndocumented exceptions.\nNote: Organizations should evaluate any extensions missing from the report to\ndetermine if they are valid exceptions.\nNote: The audit procedure intentionally does not include the action taken for matched\nextensions, e.g. Reject with NDR or Quarantine the message. These are considered\norganization specific and are not scored. When FileTypeAction is not specified the\naction will default to Reject the message with a non-delivery receipt (NDR).\nThe Quarantine Policy is also considered organization specific.",
    "expected_response": "malicious activity. To pass, organizations must demonstrate at least a 90% adoption\nexceptions should be based on documented business needs.\n# A policy must have at least 90% of the extensions in the reference list to\n# so we don't output failures on policies that aren't specific to\nWrite-Output \"## FAIL ## No comprehensive policies found to evaluate.\"\nreturn\n# Output results in various formats\nevaluated. At the end of the script examples of different output formats are given.\no The EnableFileFilter property is set to True.\nNote: Organizations should evaluate any extensions missing from the report to",
    "remediation": "To Remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following script after editing InternalSenderAdminAddress:\n# Create an attachment policy and associated rule. The rule is\n# intentionally disabled allowing the org to enable it when ready\n$Policy = @{\nName             = \"CIS L2 Attachment Policy\"\nEnableFileFilter = $true\nZapEnabled       = $true\nEnableInternalSenderAdminNotifications = $true\nInternalSenderAdminAddress = 'admin@contoso.com' # Change this.\n}\n$L2Extensions = @(\n\"7z\", \"a3x\", \"ace\", \"ade\", \"adp\", \"ani\", \"app\", \"appinstaller\",\n\"applescript\", \"application\", \"appref-ms\", \"appx\", \"appxbundle\", \"arj\",\n\"asd\", \"asx\", \"bas\", \"bat\", \"bgi\", \"bz2\", \"cab\", \"chm\", \"cmd\", \"com\",\n\"cpl\", \"crt\", \"cs\", \"csh\", \"daa\", \"dbf\", \"dcr\", \"deb\",\n\"desktopthemepackfile\", \"dex\", \"diagcab\", \"dif\", \"dir\", \"dll\", \"dmg\",\n\"doc\", \"docm\", \"dot\", \"dotm\", \"elf\", \"eml\", \"exe\", \"fxp\", \"gadget\", \"gz\",\n\"hlp\", \"hta\", \"htc\", \"htm\", \"html\", \"hwpx\", \"ics\", \"img\",\n\"inf\", \"ins\", \"iqy\", \"iso\", \"isp\", \"jar\", \"jnlp\", \"js\", \"jse\", \"kext\",\n\"ksh\", \"lha\", \"lib\", \"library-ms\", \"lnk\", \"lzh\", \"macho\", \"mam\", \"mda\",\n\"mdb\", \"mde\", \"mdt\", \"mdw\", \"mdz\", \"mht\", \"mhtml\", \"mof\", \"msc\", \"msi\",\n\"msix\", \"msp\", \"msrcincident\", \"mst\", \"ocx\", \"odt\", \"ops\", \"oxps\", \"pcd\",\n\"pif\", \"plg\", \"pot\", \"potm\", \"ppa\", \"ppam\", \"ppkg\", \"pps\", \"ppsm\", \"ppt\",\n\"pptm\", \"prf\", \"prg\", \"ps1\", \"ps11\", \"ps11xml\", \"ps1xml\", \"ps2\",\n\"ps2xml\", \"psc1\", \"psc2\", \"pub\", \"py\", \"pyc\", \"pyo\", \"pyw\", \"pyz\",\n\"pyzw\", \"rar\", \"reg\", \"rev\", \"rtf\", \"scf\", \"scpt\", \"scr\", \"sct\",\n\"searchConnector-ms\", \"service\", \"settingcontent-ms\", \"sh\", \"shb\", \"shs\",\n\"shtm\", \"shtml\", \"sldm\", \"slk\", \"so\", \"spl\", \"stm\", \"svg\", \"swf\", \"sys\",\n\"tar\", \"theme\", \"themepack\", \"timer\", \"uif\", \"url\", \"uue\", \"vb\", \"vbe\",\n\"vbs\", \"vhd\", \"vhdx\", \"vxd\", \"wbk\", \"website\", \"wim\", \"wiz\", \"ws\", \"wsc\",\n\"wsf\", \"wsh\", \"xla\", \"xlam\", \"xlc\", \"xll\", \"xlm\", \"xls\", \"xlsb\", \"xlsm\",\n\"xlt\", \"xltm\", \"xlw\", \"xnk\", \"xps\", \"xsl\", \"xz\", \"z\"\n)\n# Create the policy\nNew-MalwareFilterPolicy @Policy -FileTypes $L2Extensions\n# Create the rule for all accepted domains\n$Rule = @{\nName = $Policy.Name\nEnabled = $false\nMalwareFilterPolicy = $Policy.Name\nRecipientDomainIs = (Get-AcceptedDomain).Name\nPriority = 0\n}\nNew-MalwareFilterRule @Rule\n3. When prepared enable the rule either through the UI or PowerShell.\nNote: Due to the number of extensions the UI method is not covered. The objects can\nhowever be edited in the UI or manually added using the list from the script.\n1. Navigate to Microsoft Defender at https://security.microsoft.com/\n2. Browse to Policies & rules > Threat policies > Anti-malware.",
    "default_value": "The following extensions are blocked by default:\nace, ani, apk, app, appx, arj, bat, cab, cmd, com, deb, dex, dll, docm, elf, exe, hta, img,\niso, jar, jnlp, kext, lha, lib, library, lnk, lzh, macho, msc, msi, msix, msp, mst, pif, ppa,\nppam, reg, rev, scf, scr, sct, sys, uif, vb, vbe, vbs, vxd, wsc, wsf, wsh, xll, xz, z",
    "detection_commands": [
      "$AttachExts = @( \"7z\", \"a3x\", \"ace\", \"ade\", \"adp\", \"ani\", \"app\", \"appinstaller\", \"applescript\", \"application\", \"appref-ms\", \"appx\", \"appxbundle\", \"arj\", \"asd\", \"asx\", \"bas\", \"bat\", \"bgi\", \"bz2\", \"cab\", \"chm\", \"cmd\", \"com\", \"cpl\", \"crt\", \"cs\", \"csh\", \"daa\", \"dbf\", \"dcr\", \"deb\", \"desktopthemepackfile\", \"dex\", \"diagcab\", \"dif\", \"dir\", \"dll\", \"dmg\", \"doc\", \"docm\", \"dot\", \"dotm\", \"elf\", \"eml\", \"exe\", \"fxp\", \"gadget\", \"gz\", \"hlp\", \"hta\", \"htc\", \"htm\", \"html\", \"hwpx\", \"ics\", \"img\", \"inf\", \"ins\", \"iqy\", \"iso\", \"isp\", \"jar\", \"jnlp\", \"js\", \"jse\", \"kext\", \"ksh\", \"lha\", \"lib\", \"library-ms\", \"lnk\", \"lzh\", \"macho\", \"mam\", \"mda\", \"mdb\", \"mde\", \"mdt\", \"mdw\", \"mdz\", \"mht\", \"mhtml\", \"mof\", \"msc\", \"msi\", \"msix\", \"msp\", \"msrcincident\", \"mst\", \"ocx\", \"odt\", \"ops\", \"oxps\", \"pcd\", \"pif\", \"plg\", \"pot\", \"potm\", \"ppa\", \"ppam\", \"ppkg\", \"pps\", \"ppsm\", \"ppt\", \"pptm\", \"prf\", \"prg\", \"ps1\", \"ps11\", \"ps11xml\", \"ps1xml\", \"ps2\", \"ps2xml\", \"psc1\", \"psc2\", \"pub\", \"py\", \"pyc\", \"pyo\", \"pyw\", \"pyz\", \"pyzw\", \"rar\", \"reg\", \"rev\", \"rtf\", \"scf\", \"scpt\", \"scr\", \"sct\", \"searchConnector-ms\", \"service\", \"settingcontent-ms\", \"sh\", \"shb\", \"shs\", \"shtm\", \"shtml\", \"sldm\", \"slk\", \"so\", \"spl\", \"stm\", \"svg\", \"swf\", \"sys\", \"tar\", \"theme\", \"themepack\", \"timer\", \"uif\", \"url\", \"uue\", \"vb\", \"vbe\", \"vbs\", \"vhd\", \"vhdx\", \"vxd\", \"wbk\", \"website\", \"wim\", \"wiz\", \"ws\", \"wsc\", \"wsf\", \"wsh\", \"xla\", \"xlam\", \"xlc\", \"xll\", \"xlm\", \"xls\", \"xlsb\", \"xlsm\", \"xlt\", \"xltm\", \"xlw\", \"xnk\", \"xps\", \"xsl\", \"xz\", \"z\"",
      "$MalwareFilterPolicies = Get-MalwareFilterPolicy $MalwareFilterRules = Get-MalwareFilterRule",
      "$PassingValue = .90 # 90% $FailThreshold = [int]($AttachExts.count * (1 - $PassingValue))",
      "$CompPolicies = $MalwareFilterPolicies | Where-Object { $_.FileTypes.Count -",
      "$ExtensionReport = foreach ($policy in $CompPolicies) { $Missing = Compare-Object -ReferenceObject $AttachExts `",
      "$FoundRule = $MalwareFilterRules |",
      "$Pass = ($Missing.Count -lt $FailThreshold) -and",
      "$ExtensionReport | Format-Table -AutoSize",
      "$ExtensionReport | Out-GridView -Title \"Attachment Filter results\" $ExtensionReport | Export-Csv -Path \"2.1.11.csv\" -NoTypeInformation $ExtensionReport | ConvertTo-Json | Out-File -FilePath \"2.1.11.json\""
    ],
    "remediation_commands": [
      "$Policy = @{",
      "$L2Extensions = @( \"7z\", \"a3x\", \"ace\", \"ade\", \"adp\", \"ani\", \"app\", \"appinstaller\", \"applescript\", \"application\", \"appref-ms\", \"appx\", \"appxbundle\", \"arj\", \"asd\", \"asx\", \"bas\", \"bat\", \"bgi\", \"bz2\", \"cab\", \"chm\", \"cmd\", \"com\", \"cpl\", \"crt\", \"cs\", \"csh\", \"daa\", \"dbf\", \"dcr\", \"deb\", \"desktopthemepackfile\", \"dex\", \"diagcab\", \"dif\", \"dir\", \"dll\", \"dmg\", \"doc\", \"docm\", \"dot\", \"dotm\", \"elf\", \"eml\", \"exe\", \"fxp\", \"gadget\", \"gz\", \"hlp\", \"hta\", \"htc\", \"htm\", \"html\", \"hwpx\", \"ics\", \"img\", \"inf\", \"ins\", \"iqy\", \"iso\", \"isp\", \"jar\", \"jnlp\", \"js\", \"jse\", \"kext\", \"ksh\", \"lha\", \"lib\", \"library-ms\", \"lnk\", \"lzh\", \"macho\", \"mam\", \"mda\", \"mdb\", \"mde\", \"mdt\", \"mdw\", \"mdz\", \"mht\", \"mhtml\", \"mof\", \"msc\", \"msi\", \"msix\", \"msp\", \"msrcincident\", \"mst\", \"ocx\", \"odt\", \"ops\", \"oxps\", \"pcd\", \"pif\", \"plg\", \"pot\", \"potm\", \"ppa\", \"ppam\", \"ppkg\", \"pps\", \"ppsm\", \"ppt\", \"pptm\", \"prf\", \"prg\", \"ps1\", \"ps11\", \"ps11xml\", \"ps1xml\", \"ps2\", \"ps2xml\", \"psc1\", \"psc2\", \"pub\", \"py\", \"pyc\", \"pyo\", \"pyw\", \"pyz\", \"pyzw\", \"rar\", \"reg\", \"rev\", \"rtf\", \"scf\", \"scpt\", \"scr\", \"sct\", \"searchConnector-ms\", \"service\", \"settingcontent-ms\", \"sh\", \"shb\", \"shs\", \"shtm\", \"shtml\", \"sldm\", \"slk\", \"so\", \"spl\", \"stm\", \"svg\", \"swf\", \"sys\", \"tar\", \"theme\", \"themepack\", \"timer\", \"uif\", \"url\", \"uue\", \"vb\", \"vbe\", \"vbs\", \"vhd\", \"vhdx\", \"vxd\", \"wbk\", \"website\", \"wim\", \"wiz\", \"ws\", \"wsc\", \"wsf\", \"wsh\", \"xla\", \"xlam\", \"xlc\", \"xll\", \"xlm\", \"xls\", \"xlsb\", \"xlsm\", \"xlt\", \"xltm\", \"xlw\", \"xnk\", \"xps\", \"xsl\", \"xz\", \"z\"",
      "$Rule = @{"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/powershell/module/exchange/get-",
      "malwarefilterpolicy?view=exchange-ps",
      "2. https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-",
      "malware-policies-configure?view=o365-worldwide",
      "3. https://learn.microsoft.com/en-us/office/compatibility/office-file-format-reference"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 110,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.12",
    "title": "Ensure the connection filter IP allow list is not used",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Utilize Centrally Managed Anti-malware Software",
    "m365_profile": "E3",
    "description": "In Microsoft 365 organizations with Exchange Online mailboxes or standalone\nExchange Online Protection (EOP) organizations without Exchange Online mailboxes,\nconnection filtering and the default connection filter policy identify good or bad source\nemail servers by IP addresses. The key components of the default connection filter\npolicy are IP Allow List, IP Block List and Safe list.\nThe recommended state is IP Allow List empty or undefined.",
    "rationale": "Without additional verification like mail flow rules, email from sources in the IP Allow List\nskips spam filtering and sender authentication (SPF, DKIM, DMARC) checks. This\nmethod creates a high risk of attackers successfully delivering email to the Inbox that\nwould otherwise be filtered. Messages that are determined to be malware or high\nconfidence phishing are filtered.",
    "impact": "This is the default behavior. IP Allow lists may reduce false positives, however, this\nbenefit is outweighed by the importance of a policy which scans all messages\nregardless of the origin. This supports the principle of zero trust.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules > Threat\npolicies.\n3. Under Policies select Anti-spam.\n4. Click on the Connection filter policy (Default).\n5. Ensure IP Allow list contains no entries.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-HostedConnectionFilterPolicy -Identity Default | fl IPAllowList\n3. Ensure IPAllowList is empty or {}",
    "expected_response": "5. Ensure IP Allow list contains no entries.\n3. Ensure IPAllowList is empty or {}",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules> Threat\npolicies.\n3. Under Policies select Anti-spam.\n4. Click on the Connection filter policy (Default).\n5. Click Edit connection filter policy.\n6. Remove any IP entries from Always allow messages from the following\nIP addresses or address range:.\n7. Click Save.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-HostedConnectionFilterPolicy -Identity Default -IPAllowList @{}",
    "default_value": "IPAllowList : {}",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-",
      "configure",
      "2. https://learn.microsoft.com/en-us/defender-office-365/create-safe-sender-lists-in-",
      "office-365#use-the-ip-allow-list",
      "3. https://learn.microsoft.com/en-us/defender-office-365/how-policies-and-",
      "protections-are-combined#user-and-tenant-settings-conflict"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 117,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.13",
    "title": "Ensure the connection filter safe list is off",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Deploy and Maintain Email Server Anti-Malware",
    "m365_profile": "E3",
    "description": "In Microsoft 365 organizations with Exchange Online mailboxes or standalone\nExchange Online Protection (EOP) organizations without Exchange Online mailboxes,\nconnection filtering and the default connection filter policy identify good or bad source\nemail servers by IP addresses. The key components of the default connection filter\npolicy are IP Allow List, IP Block List and Safe list.\nThe safe list is a pre-configured allow list that is dynamically updated by Microsoft.\nThe recommended safe list state is: Off or False",
    "rationale": "Without additional verification like mail flow rules, email from sources in the IP Allow List\nskips spam filtering and sender authentication (SPF, DKIM, DMARC) checks. This\nmethod creates a high risk of attackers successfully delivering email to the Inbox that\nwould otherwise be filtered. Messages that are determined to be malware or high\nconfidence phishing are filtered.\nThe safe list is managed dynamically by Microsoft, and administrators do not have\nvisibility into which sender are included. Incoming messages from email servers on the\nsafe list bypass spam filtering.",
    "impact": "This is the default behavior. IP Allow lists may reduce false positives, however, this\nbenefit is outweighed by the importance of a policy which scans all messages\nregardless of the origin. This supports the principle of zero trust.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules > Threat\npolicies.\n3. Under Policies select Anti-spam.\n4. Click on the Connection filter policy (Default).\n5. Ensure Safe list is Off.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-HostedConnectionFilterPolicy -Identity Default | fl EnableSafeList\n3. Ensure EnableSafeList is False",
    "expected_response": "5. Ensure Safe list is Off.\n3. Ensure EnableSafeList is False",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules> Threat\npolicies.\n3. Under Policies select Anti-spam.\n4. Click on the Connection filter policy (Default).\n5. Click Edit connection filter policy.\n6. Uncheck Turn on safe list.\n7. Click Save.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-HostedConnectionFilterPolicy -Identity Default -EnableSafeList $false",
    "default_value": "EnableSafeList : False",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-",
      "configure",
      "2. https://learn.microsoft.com/en-us/defender-office-365/create-safe-sender-lists-in-",
      "office-365#use-the-ip-allow-list",
      "3. https://learn.microsoft.com/en-us/defender-office-365/how-policies-and-",
      "protections-are-combined#user-and-tenant-settings-conflict"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 120,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.14",
    "title": "Ensure inbound anti-spam policies do not contain allowed domains",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Deploy and Maintain Email Server Anti-Malware",
    "m365_profile": "E3",
    "description": "Anti-spam protection is a feature of Exchange Online that utilizes policies to help to\nreduce the amount of junk email, bulk and phishing emails a mailbox receives. These\npolicies contain lists to allow or block specific senders or domains.\n• The allowed senders list\n• The allowed domains list\n• The blocked senders list\n• The blocked domains list\nThe recommended state is: Do not define any Allowed domains",
    "rationale": "Messages from entries in the allowed senders list or the allowed domains list bypass\nmost email protection (except malware and high confidence phishing) and email\nauthentication checks (SPF, DKIM and DMARC). Entries in the allowed senders list or\nthe allowed domains list create a high risk of attackers successfully delivering email to\nthe Inbox that would otherwise be filtered. The risk is increased even more when\nallowing common domain names as these can be easily spoofed by attackers.\nMicrosoft specifies in its documentation that allowed domains should be used for testing\npurposes only.",
    "impact": "This is the default behavior. Allowed domains may reduce false positives, however, this\nbenefit is outweighed by the importance of having a policy which scans all messages\nregardless of the origin. As an alternative consider sender based lists. This supports the\nprinciple of zero trust.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules > Threat\npolicies.\n3. Under Policies select Anti-spam.\n4. Inspect each inbound anti-spam policy\n5. Ensure that Allowed domains does not contain any domain names.\n6. Repeat as needed for any additional inbound anti-spam policy.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-HostedContentFilterPolicy | ft Identity,AllowedSenderDomains\n3. Ensure AllowedSenderDomains is undefined for each inbound policy.\nNote: Each inbound policy must pass for this recommendation to be considered to be in\na passing state.",
    "expected_response": "5. Ensure that Allowed domains does not contain any domain names.\n3. Ensure AllowedSenderDomains is undefined for each inbound policy.\nNote: Each inbound policy must pass for this recommendation to be considered to be in",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules> Threat\npolicies.\n3. Under Policies select Anti-spam.\n4. Open each out of compliance inbound anti-spam policy by clicking on it.\n5. Click Edit allowed and blocked senders and domains.\n6. Select Allow domains.\n7. Delete each domain from the domains list.\n8. Click Done > Save.\n9. Repeat as needed.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-HostedContentFilterPolicy -Identity <Policy name> -AllowedSenderDomains\n@{}\nOr, run this to remove allowed domains from all inbound anti-spam policies:\n$AllowedDomains = Get-HostedContentFilterPolicy | Where-Object\n{$_.AllowedSenderDomains}\n$AllowedDomains | Set-HostedContentFilterPolicy -AllowedSenderDomains @{}",
    "default_value": "AllowedSenderDomains : {}",
    "detection_commands": [],
    "remediation_commands": [
      "$AllowedDomains = Get-HostedContentFilterPolicy | Where-Object",
      "$AllowedDomains | Set-HostedContentFilterPolicy -AllowedSenderDomains @{}"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/anti-spam-protection-",
      "about#allow-and-block-lists-in-anti-spam-policies"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 123,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.1.15",
    "title": "Ensure outbound anti-spam message limits are in place",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Deploy and Maintain Email Server Anti-Malware",
    "m365_profile": "E3",
    "description": "The default outbound anti-spam policy in Microsoft Defender automatically applies to all\nusers and is designed to detect and limit suspicious email-sending behavior. The policy\nenforces limits based on both volume and spam detection. If a user sends too many\nemails too quickly or if a high percentage of their messages are flagged as spam, their\nability to send email can be temporarily restricted. This helps prevent abuse from\ncompromised accounts or inadvertent spam campaigns.\nWhen these limits are exceeded, Microsoft routes the messages through a high-risk\ndelivery pool to protect its IP reputation and notifies administrators through built-in alert\npolicies.\nThe recommended state is:\n• External: Restrict sending to external recipients (per hour) - 500\n• Internal: Restrict sending to internal recipients (per hour) - 1000\n• Daily: Maximum recipient limit per day - 1000\n• Action: Over limit action - Restrict the user from sending mail",
    "rationale": "Message limit settings help lessen the impact of a Business Email Compromise (BEC)\nby automatically restricting accounts that send unusually high volumes of email. This\ncontainment prevents compromised accounts from launching large-scale attacks and\nhelps ensure the organization’s email remains trusted and deliverable. Without these\nlimits, excessive or suspicious outbound traffic could result in Microsoft blocking the\norganization’s email, disrupting communication and damaging reputation.",
    "impact": "Enforcing message limits may result in legitimate users being temporarily blocked from\nsending email if their bulk messaging activity resembles spam or exceeds volume\nthresholds. This can disrupt business operations, delay communication, and require\nadministrative effort to investigate and restore access. However, these adverse effects\ntypically stem from a lack of planning around mass mailings. To avoid triggering these\nlimits, Microsoft recommends sending bulk email through custom subdomains or third-\nparty bulk email providers.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules > Threat\npolicies.\n3. Under Policies select Anti-spam and click to open Anti-spam outbound\npolicy (Default).\n4. Ensure the following settings are to the recommended level or more restrictive:\no External: Restrict sending to external recipients (per hour) -\no Internal: Restrict sending to internal recipients (per hour) -\no Daily: Maximum recipient limit per day - 1000\no Action: Over limit action - Restrict the user from sending mail\n5. Ensure a monitored mailbox is configured as a recipient under Notify these\nusers and groups if a sender is blocked due to sending outbound\nspam.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following:\n$params = (\n'RecipientLimitExternalPerHour',\n'RecipientLimitInternalPerHour',\n'RecipientLimitPerDay',\n'ActionWhenThresholdReached'\n)\nGet-HostedOutboundSpamFilterPolicy -Identity Default | fl $params\n3. Ensure that each of the following properties is set to the recommended value\nlisted below or to a more restrictive value.\nRecipientLimitExternalPerHour : 500\nRecipientLimitInternalPerHour : 1000\nRecipientLimitPerDay          : 1000\nActionWhenThresholdReached    : BlockUser\n4. Ensure the property NotifyOutboundSpamRecipients contains a monitored\nmailbox.\nNote: Microsoft's Recommended Strict values represent a more restrictive and also\ncompliant configuration. These values 400, 800, and 800 align with the sequence\nabove. For further details on Standard and Strict settings, refer to the references\nsection.",
    "expected_response": "4. Ensure the following settings are to the recommended level or more restrictive:\n5. Ensure a monitored mailbox is configured as a recipient under Notify these\n3. Ensure that each of the following properties is set to the recommended value\n4. Ensure the property NotifyOutboundSpamRecipients contains a monitored",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com.\n2. Click to expand Email & collaboration select Policies & rules> Threat\npolicies.\n3. Under Policies select Anti-spam and click to open Anti-spam outbound\npolicy (Default).\n4. Select Edit protection settings.\n5. Set the following settings to the recommended values, or more restrictive values.\no External: Set an external message limit - 500\no Internal: Set an internal message limit - 1000\no Daily: Set a daily message limit - 1000\no Action: Restriction placed on users who reach the message\nlimit - Restrict the user from sending mail\n6. Ensure Notify these users and groups if a sender is blocked due to\nsending outbound spam contains a monitored mailbox.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Change the example email addresses below and run the following PowerShell\ncommands:\n$params = @{\nRecipientLimitExternalPerHour = 500\nRecipientLimitInternalPerHour = 1000\nRecipientLimitPerDay = 1000\nActionWhenThresholdReached = 'BlockUser'\nNotifyOutboundSpamRecipients =\n@('admin@example.com','security@example.com')\n}\nSet-HostedOutboundSpamFilterPolicy -Identity 'Default' @params",
    "default_value": "RecipientLimitExternalPerHour : 0\nRecipientLimitInternalPerHour : 0\nRecipientLimitPerDay          : 0\nActionWhenThresholdReached    : BlockUserForToday\nThe value of 0 means the service defaults are being used. More information on sending\nlimits is here: https://learn.microsoft.com/en-us/office365/servicedescriptions/exchange-\nonline-service-description/exchange-online-limits#sending-limits-1",
    "detection_commands": [
      "$params = ( 'RecipientLimitExternalPerHour', 'RecipientLimitInternalPerHour', 'RecipientLimitPerDay', 'ActionWhenThresholdReached'"
    ],
    "remediation_commands": [
      "$params = @{"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-protection-",
      "about",
      "2. https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-",
      "eop-and-office365#outbound-spam-policy-settings",
      "3. https://learn.microsoft.com/en-us/office365/servicedescriptions/exchange-online-",
      "service-description/exchange-online-limits#sending-limits-1"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 126,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "2.2.1",
    "title": "Ensure emergency access account activity is monitored",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Cloud apps",
    "m365_profile": "E5",
    "description": "Organizations should monitor sign-in and audit log activity from the emergency\naccounts and trigger notifications to other administrators. When you monitor the activity\nfor emergency access accounts, you can verify these accounts are only used for testing\nor actual emergencies. You can use Azure Monitor, Microsoft Sentinel, Defender for\nCloud Apps or other tools to monitor the sign-in logs and trigger email and SMS alerts to\nyour administrators whenever emergency access accounts sign in.\nThis recommendation uses Defender for Cloud Apps Policies to alert on emergency\naccess account activity.\nThe recommended state is to monitor Activity type Log on on break-glass or\nemergency access accounts.",
    "rationale": "Emergency access accounts should be used in very few scenarios, for example, the last\nGlobal Administrator has left the organization and the account is inaccessible. All\nactivity on an emergency access account should be reviewed at the time of the event to\nensure the sign on is legitimate and authorized.",
    "impact": "There is no real world impact to monitoring these accounts beyond allocating staff. The\nfrequency of emergency account sign on should be so low that any activity raises a red\nflag that is treated with the highest priority.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com\n2. Under the Cloud Apps section select Policies -> Policy management.\n3. Locate a privileged accounts policy that meets the following criteria\no Policy severity is High severity.\no Category is Privileged accounts.\no Act on Single activity is selected.\no Under Activities matching all of the following verify:\no Filter1: Activity type equals Log on\no Filter2: User Name equals <Emergency access account> as Any role\no Ensure all additional emergency access accounts are accounted for.\no Under Alerts, verify alerting is configured.\n4. Repeat this process for any additional emergency access or break-glass\naccounts in the organization. If matching policies do not exist, then the audit\nprocedure is considered a fail.\nNote: Multiple accounts can be monitored by a single policy or by separate policies.\nNote: Emergency access account activity can be monitored in various ways. The audit\nprocedure passes as long as all emergency access account activity is monitored.",
    "expected_response": "o Filter1: Activity type equals Log on\no Filter2: User Name equals <Emergency access account> as Any role\no Ensure all additional emergency access accounts are accounted for.\no Under Alerts, verify alerting is configured.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com\n2. Under the Cloud Apps section select Policies -> Policy management.\n3. Click on All policies and then Create policy -> Activity policy.\n4. Give the policy a name and set the following:\no Policy severity to High severity.\no Category to Privileged accounts.\no Act on Single activity.\no Click Select a filter -> Activity type equals Log on.\no Click Add a filter -> User Name equals <Emergency access account>\nas Any role.\no Ensure all emergency access accounts are added to this policy or\nanother.\no Select an alert method such as Send alert as email.\nNote: Multiple accounts can be monitored by a single policy or by separate policies.",
    "default_value": "A policy to monitor emergency access accounts does not exist by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/security-emergency-access#monitor-sign-in-and-audit-logs",
      "2. https://learn.microsoft.com/en-us/defender-cloud-apps/control-cloud-apps-with-",
      "policies"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 131,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "2.4.1",
    "title": "Ensure Priority account protection is enabled and configured",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "System",
    "m365_profile": "E5",
    "description": "Identify priority accounts to utilize Microsoft 365's advanced custom security features.\nThis is an essential tool to bolster protection for users who are frequently targeted due\nto their critical positions, such as executives, leaders, managers, or others who have\naccess to sensitive, confidential, financial, or high-priority information.\nOnce these accounts are identified, several services and features can be enabled,\nincluding threat policies, enhanced sign-in protection through conditional access\npolicies, and alert policies, enabling faster response times for incident response teams.",
    "rationale": "Enabling priority account protection for users in Microsoft 365 is necessary to enhance\nsecurity for accounts with access to sensitive data and high privileges, such as CEOs,\nCISOs, CFOs, and IT admins. These priority accounts are often targeted by spear\nphishing or whaling attacks and require stronger protection to prevent account\ncompromise.\nTo address this, Microsoft 365 and Microsoft Defender for Office 365 offer several key\nfeatures that provide extra security, including the identification of incidents and alerts\ninvolving priority accounts and the use of built-in custom protections designed\nspecifically for them.",
    "audit": "To audit using the UI:\nAudit with a 3-step process\nStep 1: Verify Priority account protection is enabled:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com/\n2. Select Settings near the bottom of the left most panel.\n3. Select E-mail & collaboration > Priority account protection\n4. Ensure Priority account protection is set to On\nStep 2: Verify that priority accounts are identified and tagged accordingly:\n5. Select User tags\n6. Select the PRIORITY ACCOUNT tag and click Edit\n7. Verify the assigned members match the organization's defined priority accounts\nor groups.\n8. Repeat the previous 2 steps for any additional tags identified, such as Finance or\nHR.\nStep 3: Ensure alerts are configured:\n9. Expand E-mail & Collaboration on the left column.\n10. Select Policies & rules > Alert policy\n11. Ensure at least two alert policies are configured to monitor priority accounts for\nthe activities Detected malware in an email message and Phishing email\ndetected at time of delivery. These alerts should meet the following\ncriteria:\no Severity: High\no Category: Threat management\no Mail Direction: Inbound\no Recipient Tags: Includes Priority account",
    "expected_response": "Step 1: Verify Priority account protection is enabled:\n4. Ensure Priority account protection is set to On\nStep 3: Ensure alerts are configured:\n11. Ensure at least two alert policies are configured to monitor priority accounts for\ndetected at time of delivery. These alerts should meet the following",
    "remediation": "To remediate using the UI:\nRemediate with a 3-step process\nStep 1: Enable Priority account protection in Microsoft 365 Defender:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com/\n2. Click to expand System select Settings.\n3. Select E-mail & Collaboration > Priority account protection\n4. Ensure Priority account protection is set to On\nStep 2: Tag priority accounts:\n5. Select User tags\n6. Select the PRIORITY ACCOUNT tag and click Edit\n7. Select Add members to add users, or groups. Groups are recommended.\n8. Repeat the previous 2 steps for any additional tags needed, such as Finance or\nHR.\n9. Next and Submit.\nStep 3: Configure E-mail alerts for Priority Accounts:\n10. Expand E-mail & Collaboration on the left column.\n11. Select Policies & rules > Alert policy\n12. Select New Alert Policy\n13. Enter a valid policy Name & Description. Set Severity to High and Category to\nThreat management.\n14. Set Activity is to Detected malware in an e-mail message\n15. Mail direction is Inbound\n16. Select Add Condition and User: recipient tags are\n17. In the Selection option field add chosen priority tags such as Priority account.\n18. Select Every time an activity matches the rule.\n19. Next and verify valid recipient(s) are selected.\n20. Next and select Yes, turn it on right away. Click Submit to save the alert.\n21. Repeat steps 12 - 18 to create a 2nd alert for the Activity field Activity is:\nPhishing email detected at time of delivery\nNote: Any additional activity types may be added as needed. Above are the minimum\nrecommended.",
    "default_value": "By default, priority accounts are undefined.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/admin/setup/priority-accounts",
      "2. https://learn.microsoft.com/en-us/defender-office-365/priority-accounts-security-",
      "recommendations"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 136,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.4.2",
    "title": "Ensure Priority accounts have 'Strict protection' presets applied",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Deploy and Maintain Email Server Anti-Malware",
    "m365_profile": "E5",
    "description": "Preset security policies have been established by Microsoft, utilizing observations and\nexperiences within datacenters to strike a balance between the exclusion of malicious\ncontent from users and limiting unwarranted disruptions. These policies can apply to all,\nor select users and encompass recommendations for addressing spam, malware, and\nphishing threats. The policy parameters are pre-determined and non-adjustable.\nStrict protection has the most aggressive protection of the 3 presets.\n• EOP: Anti-spam, Anti-malware and Anti-phishing\n• Defender: Spoof protection, Impersonation protection and Advanced phishing\n• Defender: Safe Links and Safe Attachments\nNOTE: The preset security polices cannot target Priority account TAGS currently,\ngroups should be used instead.",
    "rationale": "Enabling priority account protection for users in Microsoft 365 is necessary to enhance\nsecurity for accounts with access to sensitive data and high privileges, such as CEOs,\nCISOs, CFOs, and IT admins. These priority accounts are often targeted by spear\nphishing or whaling attacks and require stronger protection to prevent account\ncompromise.\nThe implementation of stringent, pre-defined policies may result in instances of false\npositive, however, the benefit of requiring the end-user to preview junk email before\naccessing their inbox outweighs the potential risk of mistakenly perceiving a malicious\nemail as safe due to its placement in the inbox.",
    "impact": "Strict policies are more likely to cause false positives in anti-spam, phishing,\nimpersonation, spoofing and intelligence responses.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com/\n2. Select to expand E-mail & collaboration.\n3. Select Policies & rules > Threat policies.\n4. From here visit each section in turn: Anti-phishing Anti-spam Anti-malware\nSafe Attachments Safe Links\n5. Ensure in each there is a policy named Strict Preset Security Policy\nwhich includes the organization's priority Accounts/Groups.",
    "expected_response": "5. Ensure in each there is a policy named Strict Preset Security Policy",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com/\n2. Select to expand E-mail & collaboration.\n3. Select Policies & rules > Threat policies > Preset security policies.\n4. Click to Manage protection settings for Strict protection preset.\n5. For Apply Exchange Online Protection select at minimum Specific\nrecipients and include the Accounts/Groups identified as Priority Accounts.\n6. For Apply Defender for Office 365 Protection select at minimum\nSpecific recipients and include the Accounts/Groups identified as Priority\nAccounts.\n7. For Impersonation protection click Next and add valid e-mails or priority\naccounts both internal and external that may be subject to impersonation.\n8. For Protected custom domains add the organization's domain name, along\nside other key partners.\n9. Click Next and finally Confirm",
    "default_value": "By default, presets are not applied to any users or groups.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/preset-security-",
      "policies?view=o365-worldwide",
      "2. https://learn.microsoft.com/en-us/defender-office-365/priority-accounts-security-",
      "recommendations",
      "3. https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-",
      "eop-and-office365?view=o365-worldwide#impersonation-settings-in-anti-",
      "phishing-policies-in-microsoft-defender-for-office-365"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 140,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "2.4.3",
    "title": "Ensure Microsoft Defender for Cloud Apps is enabled and configured",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Deploy and Maintain Email Server Anti-Malware",
    "m365_profile": "E5",
    "description": "Microsoft Defender for Cloud Apps is a Cloud Access Security Broker (CASB). It\nprovides visibility into suspicious activity in Microsoft 365, enabling investigation into\npotential security issues and facilitating the implementation of remediation measures if\nnecessary.\nSome risk detection methods provided by Entra Identity Protection also require\nMicrosoft Defender for Cloud Apps:\n• Suspicious manipulation of inbox rules\n• Suspicious inbox forwarding\n• New country detection\n• Impossible travel detection\n• Activity from anonymous IP addresses\n• Mass access to sensitive files",
    "rationale": "Security teams can receive notifications of triggered alerts for atypical or suspicious\nactivities, see how the organization's data in Microsoft 365 is accessed and used,\nsuspend user accounts exhibiting suspicious activity, and require users to log back in to\nMicrosoft 365 apps after an alert has been triggered.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com/\n2. Click to expand System select Settings > Cloud apps.\n3. Scroll to Connected apps and select App connectors.\n4. Ensure that Microsoft 365 and Microsoft Azure both show in the list as\nConnected.\n5. Go to Cloud Discovery > Microsoft Defender for Endpoint and check if\nthe integration is enabled.\n6. Go to Information Protection > Files and verify Enable file monitoring\nis checked.",
    "expected_response": "4. Ensure that Microsoft 365 and Microsoft Azure both show in the list as\nthe integration is enabled.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com/\n2. Click to expand System select Settings > Cloud apps.\n3. Scroll to Information Protection and select Files.\n4. Check Enable file monitoring.\n5. Scroll up to Cloud Discovery and select Microsoft Defender for\nEndpoint.\n6. Check Enforce app access, configure a Notification URL and Save.\nNote: Defender for Endpoint requires a Defender for Endpoint license.\nConfigure App Connectors:\n1. Scroll to Connected apps and select App connectors.\n2. Click on Connect an app and select Microsoft 365.\n3. Check all Azure and Office 365 boxes then click Connect Office 365.\n4. Repeat for the Microsoft Azure application.",
    "default_value": "Disabled",
    "additional_information": "Additional Microsoft 365 Defender features include:\n• The option to use Defender for cloud apps as a reverse proxy, allowing for the\napplication of access or session controls through the definition of a conditional\naccess policy.\n• The purchase and implementation of the \"App Governance\" add-on, which\nprovides more precise control over OAuth app permissions and includes\nadditional built-in policies.\nA list of Defender for Cloud Apps built-in policies for Office 365 can be found at\nhttps://learn.microsoft.com/en-us/defender-cloud-apps/protect-office-365.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-cloud-apps/protect-office-",
      "365#connect-microsoft-365-to-microsoft-defender-for-cloud-apps",
      "2. https://learn.microsoft.com/en-us/defender-cloud-apps/protect-azure#connect-",
      "azure-to-microsoft-defender-for-cloud-apps",
      "3. https://learn.microsoft.com/en-us/defender-cloud-apps/best-practices",
      "4. https://learn.microsoft.com/en-us/defender-cloud-apps/get-started",
      "5. https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-",
      "risks"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 143,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.4.4",
    "title": "Ensure Zero-hour auto purge for Microsoft Teams is on",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "defender",
    "domain": "Microsoft 365 Defender",
    "subdomain": "Activate audit logging",
    "m365_profile": "E5",
    "description": "Zero-hour auto purge (ZAP) is a protection feature that retroactively detects and\nneutralizes malware and high confidence phishing. When ZAP for Teams protection\nblocks a message, the message is blocked for everyone in the chat. The initial block\nhappens right after delivery, but ZAP occurs up to 48 hours after delivery.",
    "rationale": "ZAP is intended to protect users that have received zero-day malware messages or\ncontent that is weaponized after being delivered to users. It does this by continually\nmonitoring spam and malware signatures taking automated retroactive action on\nmessages that have already been delivered.",
    "impact": "As with any anti-malware or anti-phishing product, false positives may occur.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Defender https://security.microsoft.com/\n2. Click to expand System select Settings > Email & collaboration >\nMicrosoft Teams protection.\n3. Ensure Zero-hour auto purge (ZAP) is set to On (Default)\n4. Under Exclude these participants review the list of exclusions and ensure\nthey are justified and within tolerance for the organization.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following cmdlets:\nGet-TeamsProtectionPolicy | fl ZapEnabled\nGet-TeamsProtectionPolicyRule | fl ExceptIf*\n3. Ensure ZapEnabled is True.\n4. Review the list of exclusions and ensure they are justified and within tolerance for\nthe organization. If nothing returns from the 2nd cmdlet then there are no\nexclusions defined.",
    "expected_response": "3. Ensure Zero-hour auto purge (ZAP) is set to On (Default)\n4. Under Exclude these participants review the list of exclusions and ensure\n3. Ensure ZapEnabled is True.\n4. Review the list of exclusions and ensure they are justified and within tolerance for\nthe organization. If nothing returns from the 2nd cmdlet then there are no",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Defender https://security.microsoft.com/\n2. Click to expand System select Settings > Email & collaboration >\nMicrosoft Teams protection.\n3. Set Zero-hour auto purge (ZAP) to On (Default)\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following cmdlet:\nSet-TeamsProtectionPolicy -Identity \"Teams Protection Policy\" -ZapEnabled\n$true",
    "default_value": "On (Default)",
    "detection_commands": [],
    "remediation_commands": [
      "$true"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-",
      "purge?view=o365-worldwide#zero-hour-auto-purge-zap-in-microsoft-teams",
      "2. https://learn.microsoft.com/en-us/defender-office-365/mdo-support-teams-",
      "about?view=o365-worldwide#configure-zap-for-teams-protection-in-defender-for-",
      "office-365-plan-2"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 146,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "3.1.1",
    "title": "Ensure Microsoft 365 audit log search is Enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "purview",
    "domain": "Microsoft Purview",
    "subdomain": "Audit",
    "m365_profile": "E3",
    "description": "When audit log search is enabled in the Microsoft Purview compliance portal, user and\nadmin activity within the organization is recorded in the audit log and retained for 180\ndays by default. However, some organizations may prefer to use a third-party security\ninformation and event management (SIEM) application to access their auditing data. In\nthis scenario, a global admin can choose to turn off audit log search in Microsoft 365.",
    "rationale": "Enabling audit log search in the Microsoft Purview compliance portal can help\norganizations improve their security posture, meet regulatory compliance requirements,\nrespond to security incidents, and gain valuable operational insights.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Purview https://purview.microsoft.com/\n2. Select Solutions and then Audit to open the audit search.\n3. Choose a date and time frame in the past 30 days.\n4. Verify search capabilities (e.g. try searching for Activities as Accessed file and\nresults should be displayed).\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled\n3. Ensure UnifiedAuditLogIngestionEnabled is set to True.\nNote: If the Get-AdminAuditLogConfig cmdlet is executed while connected to both\nSecurity & Compliance PowerShell as well as Exchange Online PowerShell then\nUnifiedAuditLogIngestionEnabled will always display False. This depends on the\norders the module were imported. If Security & Compliance is needed in the same\nsession be sure to connect to it first, and then Exchange PowerShell second.",
    "expected_response": "results should be displayed).\n3. Ensure UnifiedAuditLogIngestionEnabled is set to True.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Purview https://purview.microsoft.com/\n2. Select Solutions and then Audit to open the audit search.\n3. Click blue bar Start recording user and admin activity.\n4. Click Yes on the dialog box to confirm.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true",
    "default_value": "180 days",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/purview/audit-log-enable-disable?view=o365-",
      "worldwide&tabs=microsoft-purview-portal",
      "2. https://learn.microsoft.com/en-us/powershell/module/exchange/set-",
      "adminauditlogconfig?view=exchange-ps",
      "3. https://learn.microsoft.com/en-us/purview/audit-log-enable-disable?view=o365-",
      "worldwide&tabs=microsoft-purview-portal#verify-the-auditing-status-for-your-",
      "organization"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 150,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.2.1",
    "title": "Ensure DLP policies are enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Data loss protection",
    "m365_profile": "E3",
    "description": "Data Loss Prevention (DLP) policies allow Exchange Online and SharePoint Online\ncontent to be scanned for specific types of data like social security numbers, credit card\nnumbers, or passwords.",
    "rationale": "Enabling DLP policies alerts users and administrators that specific types of data should\nnot be exposed, helping to protect the data from accidental exposure.",
    "impact": "Enabling a Teams DLP policy will allow sensitive data in Exchange Online and\nSharePoint Online to be detected or blocked. Always ensure to follow appropriate\nprocedures during testing and implementation of DLP policies based on organizational\nstandards.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Purview https://purview.microsoft.com/\n2. Click Solutions > Data loss prevention and then Policies.\n3. Verify that the organization is using policies applicable to the types data that is in\ntheir interest to protect.\n4. Verify the policies are On.\nNote: The types of policies an organization should implement to protect information are\nspecific to their industry. However, certain types of information, such as credit card\nnumbers, social security numbers, and certain personally identifiable information (PII),\nare universally important to safeguard across all industries.",
    "expected_response": "Note: The types of policies an organization should implement to protect information are",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Purview https://purview.microsoft.com/\n2. Click Solutions > Data loss prevention then Policies.\n3. Click Create policy.\n4. Create a policy that is specific to the types of data the organization wishes to\nprotect.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp?view=o365-",
      "worldwide"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 153,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "3.2.2",
    "title": "Ensure DLP policies are enabled for Microsoft Teams",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enforce Access Control to Data through Automated",
    "m365_profile": "E5",
    "description": "The default Teams Data Loss Prevention (DLP) policy rule in Microsoft 365 is a\npreconfigured rule that is automatically applied to all Teams conversations and\nchannels. The default rule helps prevent accidental sharing of sensitive information by\ndetecting and blocking certain types of content that are deemed sensitive or\ninappropriate by the organization.\nBy default, the rule includes a check for the sensitive info type Credit Card Number\nwhich is pre-defined by Microsoft.",
    "rationale": "Enabling the default Teams DLP policy rule in Microsoft 365 helps protect an\norganization's sensitive information by preventing accidental sharing or leakage Credit\nCard information in Teams conversations and channels.\nDLP rules are not one size fits all, but at a minimum something should be defined. The\norganization should identify sensitive information important to them and seek to\nintercept it using DLP.",
    "impact": "End-users may be prevented from sharing certain types of content, which may require\nthem to adjust their behavior or seek permission from administrators to share specific\ncontent. Administrators may receive requests from end-users for permission to share\ncertain types of content or to modify the policy to better fit the needs of their teams.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Purview compliance portal\nhttps://purview.microsoft.com/\n2. Under Solutions select Data loss prevention then Policies.\n3. Locate the Default policy for Teams.\n4. Verify the Status is On.\n5. Verify Locations include Teams chat and channel messages - All\naccounts.\n6. Verify Policy settings incudes the Default Teams DLP policy rule or one\nspecific to the organization.\nNote: If there is not a default policy for teams inspect existing policies starting with step\n4. DLP rules are specific to the organization and each organization should take steps to\nprotect the data that matters to them. The default teams DLP rule will only alert on\nCredit Card matches.\nTo audit using PowerShell:\n1. Connect to the Security & Compliance PowerShell using Connect-IPPSSession.\n2. Run the following to return policies that include Teams chat and channel\nmessages:\n$DlpPolicy = Get-DlpCompliancePolicy\n$DlpPolicy | Where-Object {$_.Workload -match \"Teams\"} |\nft Name,Mode,TeamsLocation*\n3. If nothing returns, then there are no policies that include Teams and remediation\nis required.\n4. For any returned policy verify Mode is set to Enable.\n5. Verify TeamsLocation includes All.\n6. Verify TeamsLocationException includes only permitted exceptions.\nNote: Some tenants may not have a default policy for teams as Microsoft started\ncreating these by default at a particular point in time. In this case a new policy will have\nto be created that includes a rule to protect data important to the organization such as\ncredit cards and PII.",
    "expected_response": "4. DLP rules are specific to the organization and each organization should take steps to\n2. Run the following to return policies that include Teams chat and channel\n3. If nothing returns, then there are no policies that include Teams and remediation\n4. For any returned policy verify Mode is set to Enable.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Purview compliance portal\nhttps://purview.microsoft.com/\n2. Under Solutions select Data loss prevention then Policies.\n3. Click Policies tab.\n4. Check Default policy for Teams then click Edit policy.\n5. The edit policy window will appear click Next\n6. At the Choose locations to apply the policy page, turn the status toggle\nto On for Teams chat and channel messages location and then click Next.\n7. On Customized advanced DLP rules page, ensure the Default Teams DLP\npolicy rule Status is On and click Next.\n8. On the Policy mode page, select the radial for Turn it on right away and\nclick Next.\n9. Review all the settings for the created policy on the Review your policy and\ncreate it page, and then click submit.\n10. Once the policy has been successfully submitted click Done.\nNote: Some tenants may not have a default policy for teams as Microsoft started\ncreating these by default at a particular point in time. In this case a new policy will have\nto be created that includes a rule to protect data important to the organization such as\ncredit cards and PII.",
    "default_value": "Enabled (On)",
    "detection_commands": [
      "$DlpPolicy = Get-DlpCompliancePolicy $DlpPolicy | Where-Object {$_.Workload -match \"Teams\"} |"
    ],
    "remediation_commands": [
      "create it page, and then click submit."
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/powershell/exchange/connect-to-scc-",
      "powershell?view=exchange-ps",
      "2. https://learn.microsoft.com/en-us/purview/dlp-teams-default-policy",
      "3. https://learn.microsoft.com/en-us/powershell/module/exchange/connect-",
      "ippssession?view=exchange-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 155,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "3.3.1",
    "title": "Ensure Information Protection sensitivity label policies are published",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Information Protection",
    "m365_profile": "E3",
    "description": "Sensitivity labels enable organizations to classify and label content across Microsoft 365\nbased on its sensitivity and business impact. These labels can be applied manually by\nusers or automatically based on the content. When applied, labels can automatically\nencrypt content, provide \"Confidential\" watermarks, restrict access, and offer various\ndata protection features.\nLabels can be scoped to data assets and containers:\n• Files & other data assets in Microsoft 365, Fabric, Azure, AWS and other\nplatforms\n• Email messages sent from all versions of Outlook\n• Meeting calendar events and schedules in Outlook and Teams\n• Teams, Microsoft 365 Groups and SharePoint sites",
    "rationale": "Consistent usage of sensitivity labels can help reduce the risk of data loss or exposure\nand enable more effective incident response if a breach does occur. They can also help\norganizations comply with regulatory requirements and provide visibility and control over\nsensitive information.",
    "impact": "Encryption configurations (control access, DKE, BYOK) in the individual labels may\nimpact users’ ability to access site documents and information. Careful consideration of\nthe individual sensitivity label configurations should be exercised prior to applying an\nauto labeling policy, publishing policy, sensitivity label configuration, or PowerShell\nbased label settings to SharePoint sites.\nAdditionally, when updating or deleting Sensitivity Labels, an assessment of the\npotential impacts should be conducted to avoid unintended consequences. If tenants\nare configured for sharing with guests or external domains and Sensitivity Labels have\nencryption applied, this can affect the ability to share documents via email stored in\nSharePoint. Some recipients may be unable to open the document depending on their\nemail client, which could trigger Purview Advanced Encryptions and OME flows based\non the recipient type and the cloud license from which the email is sent (e.g.,\ngovernment clouds vs. commercial clouds).",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Purview compliance portal\nhttps://purview.microsoft.com/\n2. Select Information protection > Policies > Label publishing policies.\n3. Ensure that a Label policy exists and is published according to the organization's\ninformation protection needs.\nTo audit using PowerShell:\n1. Connect to the Security & Compliance PowerShell using Connect-IPPSSession.\n2. Run the following script:\n$Policies = Get-LabelPolicy -WarningAction Ignore |\nWhere-Object { $_.Type -eq \"PublishedSensitivityLabel\" }\nif ($Policies) {\n$Policies | Format-List -Property Name, *Location*\nWrite-Host \"$($Policies.Count) Sensitivity Label policies found.\"\n} else {\nWrite-Host \"No Sensitivity Label policies found\"\n}\n3. Ensure there is at least one sensitivity label policy published.\n4. Review the locations defined to ensure they're in scope with the organization's\nneeds.\nNote: These policies are specific to the information protection needs of each\norganization. Whether an organization passes the audit is open to interpretation by the\nauditor and depends largely on how effectively it implements information protection\nfeatures to safeguard data.",
    "expected_response": "3. Ensure that a Label policy exists and is published according to the organization's\n3. Ensure there is at least one sensitivity label policy published.\n4. Review the locations defined to ensure they're in scope with the organization's",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Purview compliance portal\nhttps://purview.microsoft.com/\n2. Select Information protection > Sensitivity labels.\n3. Click Create a label to create a label.\n4. Click Publish labels and select any newly created labels to publish according\nto the organization's information protection needs.",
    "default_value": "The \"Global sensitivity label policy\" exists by default.",
    "detection_commands": [
      "$Policies = Get-LabelPolicy -WarningAction Ignore |",
      "$Policies | Format-List -Property Name, *Location*"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/purview/sensitivity-labels",
      "2. https://learn.microsoft.com/en-us/purview/create-sensitivity-labels"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 159,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "4.1",
    "title": "Ensure devices without a compliance policy are marked 'not compliant'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "intune",
    "domain": "Microsoft Intune admin center",
    "m365_profile": "E3",
    "description": "Compliance policies are sets of rules and conditions that are used to evaluate the\nconfiguration of managed devices. These policies can help secure organizational data\nand resources from devices that don't meet those configuration requirements. Managed\ndevices must satisfy the conditions you set in your policies to be considered compliant\nby Intune. When combined with conditional access, this allows more control over how\nnon-compliant devices are treated.\nThe recommended state is Mark devices with no compliance policy assigned\nas as Not compliant",
    "rationale": "Implementing this setting is a first step in adopting compliance policies for devices.\nWhen used in together with Conditional Access policies the attack surface can be\nreduced by forcing an action to be taken for non-compliant devices.\nNote: This section does not focus on which compliance policies to use, only that an\norganization should adopt and enforce them to their needs.",
    "impact": "Any devices without a compliance policy will be marked not compliant. Care should be\ntaken to first deploy any new compliance policies with a Conditional Access (CA) policy\nthat is in the Report-only state. After the environment's device compliance is better\nunderstood it is then appropriate to finally align with Mark devices with no\ncompliance policy assigned as and enable any CA policies that enforce actions\nbased on device compliance.\nIf a mature environment already has an existing device compliance CA policy and a\nlarge number of devices without an assigned compliance policy, this could cause\ndisruption as those devices would then be suddenly considered not compliant.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Intune admin center https://intune.microsoft.com/\n2. Select Devices and then under Manage devices click Compliance\n3. Click Compliance settings.\n4. Ensure Mark devices with no compliance policy assigned as is set to\nNot compliant.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"DeviceManagementConfiguration.Read.All\"\n2. Run the following commands:\n$Uri = 'https://graph.microsoft.com/v1.0/deviceManagement/settings'\nInvoke-MgGraphRequest -Uri $Uri -Method GET\n3. Ensure that secureByDefault is set to True.",
    "expected_response": "4. Ensure Mark devices with no compliance policy assigned as is set to\n3. Ensure that secureByDefault is set to True.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Intune admin center https://intune.microsoft.com/\n2. Select Devices and then under Manage devices click Compliance\n3. Click Compliance settings.\n4. Set Mark devices with no compliance policy assigned as to Not\ncompliant.\nTo remediate using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"DeviceManagementConfiguration.ReadWrite.All\"\n2. Run the following commands:\n$Uri = 'https://graph.microsoft.com/v1.0/deviceManagement'\n$Body = @{\nsettings = @{\nsecureByDefault = $true\n}\n} | ConvertTo-Json\nInvoke-MgGraphRequest -Uri $Uri -Method PATCH -Body $Body",
    "default_value": "UI: \"Compliant\"\nGraph: secureByDefault = $false",
    "detection_commands": [
      "$Uri = 'https://graph.microsoft.com/v1.0/deviceManagement/settings' Invoke-MgGraphRequest -Uri $Uri -Method GET"
    ],
    "remediation_commands": [
      "$Uri = 'https://graph.microsoft.com/v1.0/deviceManagement' $Body = @{",
      "Invoke-MgGraphRequest -Uri $Uri -Method PATCH -Body $Body"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/mem/intune/protect/device-compliance-get-",
      "started"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 163,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "4.2",
    "title": "Ensure device enrollment for personally owned devices is blocked by default",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "intune",
    "domain": "Microsoft Intune admin center",
    "m365_profile": "E3",
    "description": "Device enrollment restrictions let you restrict devices from enrolling in Intune based on\ncertain device attributes such as device limit, device platform, OS Version, manufacturer\nor device ownership (Personally owned devices).\nThe recommended state is to Block personally owned devices from enrollment.",
    "rationale": "Restricting the enrollment of personally owned devices prevents attackers who have\nbypassed other controls from registering a new device to gain an additional foothold,\nfurther hiding or obscuring their activities.\nAn attack path could be:\n1. Account Compromise via Phishing and AiTM\n2. Conditional Access Bypass\n3. Reconnaissance using e.g. ROADrecon, GraphRunner or AADInternals\n4. Lateral Movement, Privilege Escalation or Persistence through a newly\nregistered device enrolled in Intune",
    "impact": "Per platform personally owned device enrollment impacts are listed below. It is\nimportant to test the changes to the defaults prior to moving into production and\nimplementing this control.\nWindows Devices\nThe following enrollment methods are authorized for corporate enrollment for Windows\ndevices, any other enrollment method will be considered \"Personal\" and blocked:\n• The device enrolls through Windows Autopilot.\n• The device enrolls through GPO, or automatic enrollment from Configuration\nManager for co-management.\n• The device enrolls through a bulk provisioning package.\n• The enrolling user is using a device enrollment manager account.\nMacOS\nBy default, Intune classifies macOS devices as personally owned. To be classified as\ncorporate-owned, a Mac must fulfill one of the following conditions:\n• Registered with a serial number.\n• Enrolled via Apple Automated Device Enrollment (ADE).\niOS/IPadOS devices\nBy default, Intune classifies iOS/iPadOS devices as personally owned. To be classified\nas corporate-owned, an iOS/iPadOS device must fulfill one of the following conditions:\n• Registered with a serial number or IMEI.\n• Enrolled by using Automated Device Enrollment (formerly Device Enrollment\nProgram).\nAndroid devices\nBy default, until you manually make changes in the admin center, your Android\nEnterprise work profile device settings and Android device administrator device settings\nare the same.\nIf you block Android Enterprise work profile enrollment on personal devices, only\ncorporate-owned devices can enroll with personally owned work profiles.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Intune admin center https://intune.microsoft.com/\n2. Select Devices and then under Device onboarding click Enrollment\n3. Under Enrollment options select Device platform restriction.\n4. Inspect the policies listed under Device type restrictions\no For the Default priority policy, click All Users.\no Select Properties.\n5. Ensure all platforms are set to Block in the Personally owned column.\n6. If the Platform itself is set to Block for any of the platforms shown this is also a\npassing state for that platform.\nNote: Blocking platforms that are not used in the organization is a more restrictive best\npractice and will also effectively block enrollment of personally owned devices for the\nselected platform, ensuring compliance for this recommendation.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"DeviceManagementConfiguration.Read.All\"\n2. Run the following script:\n$Uri =\n'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurat\nions'\n$Config = (Invoke-MgGraphRequest -Uri $Uri -Method GET).value |\nWhere-Object { $_.id -match 'DefaultPlatformRestrictions' -and $_.priority -\neq 0 }\n$Result = [PSCustomObject]@{\nWindowsPersonalDeviceEnrollmentBlocked        =\n$Config.windowsRestriction.personalDeviceEnrollmentBlocked\niOSPersonalDeviceEnrollmentBlocked            =\n$Config.iosRestriction.personalDeviceEnrollmentBlocked\nAndroidForWorkPersonalDeviceEnrollmentBlocked =\n$Config.androidForWorkRestriction.personalDeviceEnrollmentBlocked\nMacOPersonalDeviceEnrollmentBlocked           =\n$Config.macOSRestriction.personalDeviceEnrollmentBlocked\nAndroidPersonalDeviceEnrollmentBlocked        =\n$Config.androidRestriction.personalDeviceEnrollmentBlocked\n}\n$Result\n3. Inspect the output, ensure each platform displays True next to it's property. A\npassing output will look like the below:\nWindowsPersonalDeviceEnrollmentBlocked        : True\niOSPersonalDeviceEnrollmentBlocked            : True\nAndroidForWorkPersonalDeviceEnrollmentBlocked : True\nMacOPersonalDeviceEnrollmentBlocked           : True\nAndroidPersonalDeviceEnrollmentBlocked        : True\nNote: If platformBlocked is true then that platform is also in compliance as the\nplatform is blocked from enrollment entirely. This is not currently reflected in the audit\nscript but can be queried from the same API call.",
    "expected_response": "5. Ensure all platforms are set to Block in the Personally owned column.\n6. If the Platform itself is set to Block for any of the platforms shown this is also a\n3. Inspect the output, ensure each platform displays True next to it's property. A\npassing output will look like the below:",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Intune admin center https://intune.microsoft.com/\n2. Select Devices and then under Device onboarding click Enrollment\n3. Under Enrollment options select Device platform restriction.\n4. Inspect the policies listed under Device type restrictions\no For the Default priority policy, click All Users.\no Select Properties.\n5. Click Edit to change Platform settings.\n6. In the Personally owned column set each platform to Block.\nNote: Blocking platforms that are not used in the organization is a more restrictive best\npractice and will also effectively block enrollment of personally owned devices for the\nselected platform, ensuring compliance for this recommendation.",
    "default_value": "Allow",
    "detection_commands": [
      "$Uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurat",
      "$Config = (Invoke-MgGraphRequest -Uri $Uri -Method GET).value |",
      "$Result = [PSCustomObject]@{",
      "$Config.windowsRestriction.personalDeviceEnrollmentBlocked",
      "$Config.iosRestriction.personalDeviceEnrollmentBlocked",
      "$Config.androidForWorkRestriction.personalDeviceEnrollmentBlocked",
      "$Config.macOSRestriction.personalDeviceEnrollmentBlocked",
      "$Config.androidRestriction.personalDeviceEnrollmentBlocked",
      "$Result"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/mem/intune/enrollment/enrollment-restrictions-",
      "set",
      "2. https://www.glueckkanja.com/blog/security/2025/01/compliant-device-bypass-en/"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 166,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.1.2.1",
    "title": "Ensure 'Per-user MFA' is disabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "entra",
    "domain": "Microsoft Entra admin center",
    "subdomain": "Entra ID",
    "m365_profile": "E3",
    "description": "Legacy per-user Multi-Factor Authentication (MFA) can be configured to require\nindividual users to provide multiple authentication factors, such as passwords and\nadditional verification codes, to access their accounts. It was introduced in earlier\nversions of Office 365, prior to the more comprehensive implementation of Conditional\nAccess (CA).",
    "rationale": "Both security defaults and conditional access with security defaults turned off are not\ncompatible with per-user multi-factor authentication (MFA), which can lead to\nundesirable user authentication states. The CIS Microsoft 365 Benchmark explicitly\nemploys Conditional Access for MFA as an enhancement over security defaults and as\na replacement for the outdated per-user MFA. To ensure a consistent authentication\nstate disable per-user MFA on all accounts.",
    "impact": "Accounts using per-user MFA will need to be migrated to use CA.\nPrior to disabling per-user MFA the organization must be prepared to implement\nconditional access MFA to avoid security gaps and allow for a smooth transition. This\nwill help ensure relevant accounts are covered by MFA during the change phase from\ndisabling per-user MFA to enabling CA MFA. Section 5.2.2 in this document covers the\ncreation of a CA rule for both administrators and all users in the tenant.\nMicrosoft has documentation on migrating from per-user MFA Convert users from per-\nuser MFA to Conditional Access based MFA",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Users select All users.\n3. Click on Per-user MFA on the top row.\n4. Ensure under the column Multi-factor Auth Status that each account is set\nto Disabled",
    "expected_response": "4. Ensure under the column Multi-factor Auth Status that each account is set",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Users select All users.\n3. Click on Per-user MFA on the top row.\n4. Click the empty box next to Display Name to select all accounts.\n5. On the far right under quick steps click Disable.",
    "default_value": "Disabled",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-",
      "userstates#convert-users-from-per-user-mfa-to-conditional-access",
      "2. https://learn.microsoft.com/en-us/microsoft-365/admin/security-and-",
      "compliance/set-up-multi-factor-authentication?view=o365-worldwide#use-",
      "conditional-access-policies",
      "3. https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-",
      "userstates#convert-per-user-mfa-enabled-and-enforced-users-to-disabled"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 172,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.1.2.2",
    "title": "Ensure third party integrated applications are not allowed",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "entra",
    "domain": "Microsoft Entra admin center",
    "subdomain": "Require MFA for Externally-Exposed Applications",
    "m365_profile": "E3",
    "description": "App registration allows users to register custom-developed applications for use within\nthe directory.",
    "rationale": "Third-party integrated applications connection to services should be disabled unless\nthere is a very clear value and robust security controls are in place. While there are\nlegitimate uses, attackers can grant access from breached accounts to third party\napplications to exfiltrate data from your tenancy without having to maintain the breached\naccount.",
    "impact": "The implementation of this change will impact both end users and administrators. End\nusers will not be able to integrate third-party applications that they may wish to use.\nAdministrators are likely to receive requests from end users to grant them permission to\nthe necessary third-party applications.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Users select Users settings.\n3. Verify Users can register applications is set to No.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.All\"\n2. Run the following command:\n(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | fl\nAllowedToCreateApps\n3. Ensure the returned value is False.",
    "expected_response": "3. Verify Users can register applications is set to No.\n3. Ensure the returned value is False.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Users select Users settings.\n3. Set Users can register applications to No.\n4. Click Save.\nTo remediate using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.ReadWrite.Authorization\"\n2. Run the following commands:\n$param = @{ AllowedToCreateApps = \"$false\" }\nUpdate-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions $param",
    "default_value": "Yes (Users can register applications.)",
    "detection_commands": [],
    "remediation_commands": [
      "$param = @{ AllowedToCreateApps = \"$false\" } Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions $param"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity-platform/how-applications-are-",
      "added"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 174,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.1.2.3",
    "title": "Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "entra",
    "domain": "Microsoft Entra admin center",
    "subdomain": "Only Use Up-to-date And Trusted Third-Party",
    "m365_profile": "E3",
    "description": "Non-privileged users can create tenants in the Microsoft Entra ID and Microsoft Entra\nadministration portal under \"Manage tenant\". The creation of a tenant is recorded in the\nAudit log as category \"DirectoryManagement\" and activity \"Create Company\". By\ndefault, the user who creates a Microsoft Entra tenant is automatically assigned the\nGlobal Administrator role. The newly created tenant doesn't inherit any settings or\nconfigurations.",
    "rationale": "Restricting tenant creation prevents unauthorized or uncontrolled deployment of\nresources and ensures that the organization retains control over its infrastructure. User\ngeneration of shadow IT could lead to multiple, disjointed environments that can make it\ndifficult for IT to manage and secure the organization's data, especially if other users in\nthe organization began using these tenants for business purposes under the\nmisunderstanding that they were secured by the organization's security team.",
    "impact": "Non-admin users will need to contact I.T. if they have a valid reason to create a tenant.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/\n2. Click to expand Entra ID > Users > User settings.\n3. Ensure Restrict non-admin users from creating tenants is set to Yes\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.All\"\n2. Run the following commands:\n(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions |\nSelect-Object AllowedToCreateTenants\n3. Ensure the returned value is False",
    "expected_response": "3. Ensure Restrict non-admin users from creating tenants is set to Yes\n3. Ensure the returned value is False",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/\n2. Click to expand Entra ID > Users > User settings.\n3. Set Restrict non-admin users from creating tenants to Yes then Save.\nTo remediate using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.ReadWrite.Authorization\"\n2. Run the following commands:\n# Create hashtable and update the auth policy\n$params = @{ AllowedToCreateTenants = $false }\nUpdate-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions $params",
    "default_value": "No - Non-administrators can create tenants.\nAllowedToCreateTenants is True",
    "detection_commands": [
      "Select-Object AllowedToCreateTenants"
    ],
    "remediation_commands": [
      "$params = @{ AllowedToCreateTenants = $false } Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions $params"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/fundamentals/users-default-",
      "permissions#restrict-member-users-default-permissions"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 176,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.1.2.4",
    "title": "Ensure access to the Entra admin center is restricted",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "entra",
    "domain": "Microsoft Entra admin center",
    "subdomain": "Only Use Up-to-date And Trusted Third-Party",
    "m365_profile": "E3",
    "description": "Restrict non-privileged users from signing into the Microsoft Entra admin center.\nNote: This recommendation only affects access to the web portal. It does not prevent\nprivileged users from using other methods such as Rest API or PowerShell to obtain\ninformation. Those channels are addressed elsewhere in this document.",
    "rationale": "The Microsoft Entra admin center contains sensitive data and permission settings,\nwhich are still enforced based on the user's role. However, an end user may\ninadvertently change properties or account settings that could result in increased\nadministrative overhead. Additionally, a compromised end user account could be used\nby a malicious attacker as a means to gather additional information and escalate an\nattack.\nNote: Users will still be able to sign into Microsoft Entra admin center but will be unable\nto see directory information.",
    "impact": "In the event there are resources a user owns that need to be changed in the Entra\nAdmin center, then an administrator would need to make those changes.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/\n2. Click to expand Entra ID > Users > User settings.\n3. Verify under the Administration center section that Restrict access to\nMicrosoft Entra admin center is set to Yes.",
    "expected_response": "Microsoft Entra admin center is set to Yes.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/\n2. Click to expand Entra ID > Users > User settings.\n3. Set Restrict access to Microsoft Entra admin center to Yes then Save.",
    "default_value": "No - Non-administrators can access the Microsoft Entra admin center.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/fundamentals/users-default-",
      "permissions#restrict-member-users-default-permissions"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 179,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2"
    ]
  },
  {
    "cis_id": "5.1.2.5",
    "title": "Ensure the option to remain signed in is hidden",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "entra",
    "domain": "Microsoft Entra admin center",
    "subdomain": "Only Use Up-to-date And Trusted Third-Party",
    "m365_profile": "E3",
    "description": "The option for the user to Stay signed in, or the Keep me signed in option, will\nprompt a user after a successful login. When the user selects this option, a persistent\nrefresh token is created. The refresh token lasts for 90 days by default and does not\nprompt for sign-in or multifactor.",
    "rationale": "Allowing users to select this option presents risk, especially if the user signs into their\naccount on a publicly accessible computer/web browser. In this case it would be trivial\nfor an unauthorized person to gain access to any associated cloud data from that\naccount.",
    "impact": "Once this setting is hidden users will no longer be prompted upon sign-in with the\nmessage Stay signed in?. This may mean users will be forced to sign in more\nfrequently. Important: some features of SharePoint Online and Office 2010 have a\ndependency on users remaining signed in. If you hide this option, users may get\nadditional and unexpected sign in prompts.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Users > User settings.\n3. Ensure Show keep user signed in is highlighted No.",
    "expected_response": "3. Ensure Show keep user signed in is highlighted No.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Users > User settings.\n3. Set Show keep user signed in to No.\n4. Click Save.",
    "default_value": "Users may select stay signed in",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/concepts-azure-",
      "multi-factor-authentication-prompts-session-lifetime",
      "2. https://learn.microsoft.com/en-us/entra/fundamentals/how-to-manage-stay-",
      "signed-in-prompt"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 181,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "5.1.2.6",
    "title": "Ensure 'LinkedIn account connections' is disabled",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "m365_profile": "E3",
    "description": "LinkedIn account connections allow users to connect their Microsoft work or school\naccount with LinkedIn. After a user connects their accounts, information and highlights\nfrom LinkedIn are available in some Microsoft apps and services.",
    "rationale": "Disabling LinkedIn integration prevents potential phishing attacks and risk scenarios\nwhere an external party could accidentally disclose sensitive information.",
    "impact": "Users will not be able to sync contacts or use LinkedIn integration.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Users select User settings.\n3. Under LinkedIn account connections ensure No is highlighted.",
    "expected_response": "3. Under LinkedIn account connections ensure No is highlighted.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Users select User settings.\n3. Under LinkedIn account connections select No.\n4. Click Save.",
    "default_value": "LinkedIn integration is enabled by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/users/linkedin-integration",
      "2. https://learn.microsoft.com/en-us/entra/identity/users/linkedin-user-consent"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 183,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.1.3.1",
    "title": "Ensure a dynamic group for guest users is created",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Monitor and Block Unauthorized Network Traffic",
    "m365_profile": "E3",
    "description": "A dynamic group is a dynamic configuration of security group membership for Microsoft\nEntra ID. Administrators can set rules to populate groups that are created in Entra ID\nbased on user attributes (such as userType, department, or country/region). Members\ncan be automatically added to or removed from a security group based on their\nattributes.\nThe recommended state is to create a dynamic group that includes guest accounts.",
    "rationale": "Dynamic groups allow for an automated method to assign group membership.\nGuest user accounts will be automatically added to this group and through this existing\nconditional access rules, access controls and other security measures will ensure that\nnew guest accounts are restricted in the same manner as existing guest accounts.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Groups select All groups.\n3. On the right of the search field click Add filter.\n4. Set Filter to Membership type and Value to Dynamic then apply.\n5. Identify a dynamic group and select it.\n6. Under manage, select Dynamic membership rules and ensure the rule syntax\ncontains (user.userType -eq \"Guest\")\n7. If necessary, inspect other dynamic groups for the value above.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Group.Read.All\"\n2. Run the following commands:\n$groups = Get-MgGroup -All | Where-Object { $_.GroupTypes -contains\n\"DynamicMembership\" }\n$groups | ft DisplayName,GroupTypes,MembershipRule\n3. Look for a dynamic group containing the rule (user.userType -eq \"Guest\")",
    "expected_response": "6. Under manage, select Dynamic membership rules and ensure the rule syntax",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Groups select All groups.\n3. Select New group and assign the following values:\no Group type: Security\no Microsoft Entra roles can be assigned to the group: No\no Membership type: Dynamic User\n4. Select Add dynamic query.\n5. Above the Rule syntax text box, select Edit.\n6. Place the following expression in the box:\n(user.userType -eq \"Guest\")\n7. Select OK and Save\nTo remediate using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Group.ReadWrite.All\"\n2. In the script below edit DisplayName and MailNickname as needed and run:\n$params = @{\nDisplayName                   = \"Dynamic Guest Group\"\nMailNickname                  = \"DynGuestUsers\"\nMailEnabled                   = $false\nSecurityEnabled               = $true\nGroupTypes                    = \"DynamicMembership\"\nMembershipRule                = '(user.userType -eq \"Guest\")'\nMembershipRuleProcessingState = \"On\"\n}\nNew-MgGroup @params",
    "default_value": "Undefined",
    "detection_commands": [
      "$groups = Get-MgGroup -All | Where-Object { $_.GroupTypes -contains \"DynamicMembership\" } $groups | ft DisplayName,GroupTypes,MembershipRule"
    ],
    "remediation_commands": [
      "$params = @{",
      "New-MgGroup @params"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/users/groups-create-rule",
      "2. https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-",
      "membership",
      "3. https://learn.microsoft.com/en-us/entra/external-id/use-dynamic-groups"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 186,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "5.1.3.2",
    "title": "Ensure users cannot create security groups",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Configure Data Access Control Lists",
    "m365_profile": "E3",
    "description": "This setting allows users in the organization to create new security groups and add\nmembers to these groups in the Azure portal, API, or PowerShell. These new groups\nalso show up in the Access Panel for all other users. If the policy setting on the group\nallows it, other users can create requests to join these groups.\nThe recommended state is Users can create security groups in Azure\nportals, API or PowerShell set to No.",
    "rationale": "Allowing end users to create security groups without oversight can lead to uncontrolled\ngroup sprawl, increasing the risk of inappropriate access to sensitive data. The default\nassignment of group ownership to the creator introduces a potential for privilege\nescalation, especially if IT teams overlook how these groups are later used to manage\naccess.\nA more malicious scenario arises when a compromised non-privileged user creates\ndeceptively named security groups such as “Accounting” or “Break-glass”, or uses\nhomograph techniques to mimic legitimate group names. Third-party IT teams may be\nparticularly susceptible, as they might not be familiar with the environment or lack\nconsistent naming conventions. An unsuspecting administrator could then mistakenly\nassign elevated privileges, grant access to sensitive data, or exclude these groups from\nConditional Access policies, inadvertently creating a serious security gap.",
    "impact": "Restrictions may introduce some operational friction, particularly in fast-paced or\ndecentralized environments where teams rely on self-service capabilities for\ncollaboration and access management.\nThis can increase reliance on IT teams for routine tasks, potentially causing delays.\nHowever, these impacts can be minimized through automated approval workflows and\nclear governance processes.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Groups select General.\n3. Ensure Users can create security groups in Azure portals, API or\nPowerShell is set to No.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.All\"\n2. Run the following command:\n(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | fl\n3. Ensure AllowedToCreateSecurityGroups is set to False.",
    "expected_response": "3. Ensure Users can create security groups in Azure portals, API or\nPowerShell is set to No.\n3. Ensure AllowedToCreateSecurityGroups is set to False.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Groups select General.\n3. Set Users can create security groups in Azure portals, API or\nPowerShell to No.\nTo remediate using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.ReadWrite.Authorization\"\n2. Run the following commands:\n$params = @{\ndefaultUserRolePermissions = @{\nAllowedToCreateSecurityGroups = $false\n}\n}\nUpdate-MgPolicyAuthorizationPolicy -BodyParameter $params",
    "default_value": "AllowedToCreateSecurityGroups : True",
    "detection_commands": [],
    "remediation_commands": [
      "$params = @{",
      "Update-MgPolicyAuthorizationPolicy -BodyParameter $params"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-",
      "management?WT.mc_id=Portal-Microsoft_AAD_IAM#group-settings",
      "2. https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-",
      "rest-1.0&tabs=http"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 189,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "5.1.4.1",
    "title": "Ensure the ability to join devices to Entra is restricted",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Configure Data Access Control Lists",
    "m365_profile": "E3",
    "description": "This setting enables you to select the users who can register their devices as Microsoft\nEntra joined devices.\nThe recommended state is Selected or None.\nNote: This setting is applicable only to Microsoft Entra join on Windows 10 or newer.\nThis setting doesn't apply to Microsoft Entra hybrid joined devices, Microsoft Entra\njoined VMs in Azure, or Microsoft Entra joined devices that use Windows Autopilot self-\ndeployment mode because these methods work in a userless context.",
    "rationale": "If a threat actor compromises a standard user account, they can enroll a rogue device\nunder that user's identity. This device may inherit MDM policies and appear compliant,\ngiving attackers persistent access to cloud resources without triggering MFA.\nIn a 2023 blog, Microsoft IR reports that it has detected threat actors registering their\nown devices to the Microsoft Entra tenant, giving them a platform to escalate the\ncyberattack. While simply joining a device to a Microsoft Entra tenant may present\nlimited immediate risk, it could allow a threat actor to establish a foothold in the\nenvironment.",
    "impact": "Restricting the setting requires IT teams to assign enrollment permissions to specific\nstaff, such as helpdesk or provisioning personnel, which may impact user-driven\nAutopilot scenarios and increase administrative overhead for device onboarding and\nsupport.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Devices select Device settings.\n3. Ensure Users may join devices to Microsoft Entra is set to Selected or\nNone.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.DeviceConfiguration\"\n2. Run the following commands:\n$Uri = \"https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy\"\n(Invoke-MgGraphRequest -Method GET -Uri $Uri).azureADJoin.allowedToJoin\n3. Ensure that the key @odata.type is set to either\n#microsoft.graph.enumeratedDeviceRegistrationMembership (Selected)\nor #microsoft.graph.noDeviceRegistrationMembership (None).\nNote: When set to the setting is set to Selected users and groups will also appear in\nthe output of the Graph Request.",
    "expected_response": "3. Ensure Users may join devices to Microsoft Entra is set to Selected or\n3. Ensure that the key @odata.type is set to either\nNote: When set to the setting is set to Selected users and groups will also appear in\nthe output of the Graph Request.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Devices select Device settings.\n3. Set Users may join devices to Microsoft Entra to Selected (and add\nmembers) or None.",
    "default_value": "All",
    "detection_commands": [
      "$Uri = \"https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy\""
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-",
      "identities#configure-device-settings",
      "2. https://www.microsoft.com/en-us/security/blog/2023/12/05/microsoft-incident-",
      "response-lessons-on-preventing-cloud-identity-compromise/#poor-device",
      "3. https://learn.microsoft.com/en-",
      "us/graph/api/resources/deviceregistrationpolicy?view=graph-rest-beta"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 193,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.1.4.2",
    "title": "Ensure the maximum number of devices per user is limited",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This setting defines the maximum number of Microsoft Entra joined or registered\ndevices that a user can have in Microsoft Entra ID. Once this limit is reached, no\nadditional devices can be added until existing ones are removed. Values above 100 are\nautomatically capped at 100.\nThe recommended state is 20 or less.",
    "rationale": "Microsoft incident response teams have observed threat actors enrolling their own\ndevices to establish persistence after a non-privileged user has been compromised.\nHigh device quotas can exacerbate this risk by enabling attackers to register multiple\ndevices that appear legitimate, while also contributing to unmanaged or personal\ndevices cluttering the environment, driving up licensing costs and complicating\ncompliance efforts.\nEnforcing a reasonable device limit per user supports good governance, reduces the\nattack surface, and encourages administrators to reassess and clean up legacy or\nunused device enrollments.",
    "impact": "IT staff who need to enroll more than 20 devices on behalf of the organization must be\nassigned the role of Device Enrollment Manager in the Intune admin center. Device\nEnrollment Managers are non-administrator accounts that can enroll and manage up to\n1,000 devices. It is recommended to use dedicated service accounts for this role rather\nthan assigning it to users' primary or daily-use accounts.\nWarning: Do not delete accounts assigned as a Device enrollment manager if any\ndevices were enrolled using the account. Doing so will lead to issues with these\ndevices.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Devices select Device settings.\n3. Ensure Maximum number of devices per user is set to 20 (Recommended)\nor less.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.DeviceConfiguration\"\n2. Run the following commands:\n$Uri = \"https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy\"\nInvoke-MgGraphRequest -Method GET -Uri $Uri\n3. Ensure the key userDeviceQuota is set to 20 or less.",
    "expected_response": "3. Ensure Maximum number of devices per user is set to 20 (Recommended)\n3. Ensure the key userDeviceQuota is set to 20 or less.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Devices select Device settings.\n3. Set Maximum number of devices per user to 20 (Recommended) or less.",
    "detection_commands": [
      "$Uri = \"https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy\" Invoke-MgGraphRequest -Method GET -Uri $Uri"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-",
      "identities#configure-device-settings",
      "2. https://learn.microsoft.com/en-us/intune/intune-service/enrollment/device-",
      "enrollment-manager-enroll",
      "3. https://learn.microsoft.com/en-",
      "us/graph/api/resources/deviceregistrationpolicy?view=graph-rest-beta"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 196,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.1.4.3",
    "title": "Ensure the GA role is not added as a local administrator during Entra join",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This setting controls whether the Global Administrator role is automatically added to the\nlocal administrators group on a device during the Microsoft Entra join process.\nThe recommended state is No.",
    "rationale": "System administrators may be inclined to use over-privileged accounts for convenience\nwhen managing devices. Enforcing this control helps discourage that behavior by\nrequiring administrative actions to be performed using accounts specifically designated\nfor local administration. This promotes adherence to the principle of least privilege and\nreduces the risk associated with using high-level roles for routine tasks. For example,\nusing a Global Administrator account to authenticate to a compromised endpoint and\ncontinue performing tasks significantly increases the risk of broader organizational\ncompromise.",
    "impact": "Restricting the default behavior and requiring manual assignment to least privilege roles\nintroduces minor administrative overhead. During the Microsoft Entra join process, the\nMicrosoft Entra Joined Device Local Administrator role is automatically added to the\ndevice's local administrators group and should be used instead.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Devices select Device settings.\n3. Ensure Global administrator role is added as local administrator\non the device during Microsoft Entra join (Preview) is set to No.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.DeviceConfiguration\"\n2. Run the following commands:\n$Uri = \"https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy\"\n(Invoke-MgGraphRequest -Method GET -Uri $Uri).azureADJoin.localAdmins\n3. Ensure the key enableGlobalAdmins is set to False.",
    "expected_response": "3. Ensure Global administrator role is added as local administrator\non the device during Microsoft Entra join (Preview) is set to No.\n3. Ensure the key enableGlobalAdmins is set to False.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Devices select Device settings.\n3. Set Global administrator role is added as local administrator on\nthe device during Microsoft Entra join (Preview) to No.",
    "default_value": "Yes",
    "detection_commands": [
      "$Uri = \"https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy\""
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-",
      "identities#configure-device-settings",
      "2. https://learn.microsoft.com/en-",
      "us/graph/api/resources/deviceregistrationpolicy?view=graph-rest-beta",
      "3. https://learn.microsoft.com/en-us/entra/identity/devices/assign-local-admin"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 199,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.1.4.4",
    "title": "Ensure local administrator assignment is limited during Entra join",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This setting determines if the Microsoft Entra user registering their device as Microsoft\nEntra join be added to the local administrators group. This setting applies only once\nduring the actual registration of the device as Microsoft Entra join.\nThe recommended state is Selected or None.",
    "rationale": "To uphold the principle of least privilege, the assignment of local administrator rights\nduring Microsoft Entra join should be centrally managed using appropriate built-in roles\nthrough Intune. This approach minimizes the number of disparate users with elevated\nprivileges, reducing the attack surface and potential for misuse. Centralized\nmanagement also streamlines the deprovisioning process, ensuring that administrative\naccess can be revoked efficiently and consistently across all devices, rather than\nrequiring manual intervention on each individual endpoint.",
    "impact": "Restricting the default behavior and requiring manual assignment to built-in roles\nintroduces minor administrative overhead. During the Microsoft Entra join process, the\nMicrosoft Entra Joined Device Local Administrator role is automatically added to the\ndevice's local administrators group and should be used instead.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Devices select Device settings.\n3. Ensure Registering user is added as local administrator on the\ndevice during Microsoft Entra join (Preview) is set to Selected or\nNone.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.DeviceConfiguration\"\n2. Run the following commands:\n$Uri = \"https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy\"\n(Invoke-MgGraphRequest -Method GET -Uri\n$Uri).azureADJoin.localAdmins.registeringUsers\n3. Ensure the key @odata.type is set to\n#microsoft.graph.enumeratedDeviceRegistrationMembership (Selected)\nor #microsoft.graph.noDeviceRegistrationMembership (None).\nNote: When set to the setting is set to Selected users and groups will also appear in the\noutput of the Graph Request.",
    "expected_response": "3. Ensure Registering user is added as local administrator on the\ndevice during Microsoft Entra join (Preview) is set to Selected or\n3. Ensure the key @odata.type is set to\nNote: When set to the setting is set to Selected users and groups will also appear in the\noutput of the Graph Request.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Devices select Device settings.\n3. Set Registering user is added as local administrator on the device\nduring Microsoft Entra join (Preview) to Selected (and add members)\nor None.",
    "default_value": "All",
    "detection_commands": [
      "$Uri = \"https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy\"",
      "$Uri).azureADJoin.localAdmins.registeringUsers"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-",
      "identities#configure-device-settings",
      "2. https://learn.microsoft.com/en-",
      "us/graph/api/resources/deviceregistrationpolicy?view=graph-rest-beta",
      "3. https://learn.microsoft.com/en-us/entra/identity/devices/assign-local-admin"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 202,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.1.4.5",
    "title": "Ensure Local Administrator Password Solution is enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "Local Administrator Password Solution (LAPS) is the management of local account\npasswords on Windows devices. LAPS provides a solution to securely manage and\nretrieve the built-in local admin password. With cloud version of LAPS, customers can\nenable storing and rotation of local admin passwords for both Microsoft Entra and\nMicrosoft Entra hybrid join devices\nThe recommended state is Yes.",
    "rationale": "Managing local Administrator passwords across multiple systems can be challenging.\nAs a result, many organizations opt to configure the same password on all workstations\nand/or member servers during deployment. However, this practice introduces a\nsignificant security risk: if an attacker compromises one system and obtains the local\nAdministrator password, they can potentially gain administrative access to every other\nsystem using that same password.\nAdditionally, enabling LAPS at the tenant level is a prerequisite for implementing LAPS-\nrelated recommendations outlined in the CIS Microsoft Intune for Windows Workstation\nBenchmarks.\nNote: Enabling LAPS at the tenant level does not automatically enforce password\nrotation for built-in Administrator accounts. To activate LAPS functionality, appropriate\npolicies must be configured in Intune Settings Catalog or under the Endpoint\nsecurity > Account protection blade. The CIS Microsoft 365 Foundations\nBenchmark focuses on hardening at the tenant level, while the CIS Intune Benchmarks\nfocus on endpoint-specific configurations.",
    "impact": "Enabling LAPS requires some additional operational overhead.\nAlthough unlikely if a password is rotated and not retrieved or backed up before the\ndevice becomes unreachable (e.g., due to hardware failure, network isolation, or being\ndecommissioned), administrators may be locked out.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Devices select Device settings.\n3. Ensure Enable Microsoft Entra Local Administrator Password\nSolution (LAPS) is set to Yes.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.DeviceConfiguration\"\n2. Run the following commands:\n$Uri = \"https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy\"\n(Invoke-MgGraphRequest -Method GET -Uri $Uri).localAdminPassword\n3. Ensure the key isEnabled is set to True.",
    "expected_response": "3. Ensure Enable Microsoft Entra Local Administrator Password\nSolution (LAPS) is set to Yes.\n3. Ensure the key isEnabled is set to True.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Devices select Device settings.\n3. Set Enable Microsoft Entra Local Administrator Password Solution\n(LAPS) to Yes.",
    "default_value": "No",
    "detection_commands": [
      "$Uri = \"https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy\""
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-",
      "identities#configure-device-settings",
      "2. https://learn.microsoft.com/en-",
      "us/graph/api/resources/deviceregistrationpolicy?view=graph-rest-beta",
      "3. https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-",
      "admin-passwords"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 205,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.1.4.6",
    "title": "Ensure users are restricted from recovering BitLocker keys",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Use Unique Passwords",
    "m365_profile": "E3",
    "description": "This setting determines if users can self-service recover their BitLocker key(s). 'Yes'\nrestricts non-admin users from being able to see the BitLocker key(s) for their owned\ndevices if there are any. 'No' allows all users to recover their BitLocker key(s).\nThe recommended state is Yes.",
    "rationale": "Restricting user access to the self-service BitLocker recovery key portal helps mitigate\nthe risk of recovery key exposure in the event of a compromised user account. If an\nattacker gains access to both the user’s credentials and the physical device, they could\npotentially retrieve the recovery key and decrypt sensitive data. The recovery key itself\nis also considered sensitive information.",
    "impact": "Restricting this setting will increase administrative overhead and may introduce friction\nbetween end users and the helpdesk, as users will no longer be able to retrieve\nBitLocker recovery keys through the self-service portal. This portal was originally\ndesigned to streamline recovery and reduce support burden. During the CrowdStrike\nFalcon Sensor outage in July 2024, many endpoints entered recovery mode, and delays\nin accessing recovery keys contributed to prolonged downtime. Limiting self-service\naccess could exacerbate such delays in future incidents, especially in large or\ndistributed environments.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Devices select Device settings.\n3. Ensure Restrict users from recovering the BitLocker key(s) for\ntheir owned devices is set to Yes.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.All\"\n2. Run the following:\n(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | fl\n3. Ensure that the property AllowedToReadBitlockerKeysForOwnedDevice is set\nto False.",
    "expected_response": "3. Ensure Restrict users from recovering the BitLocker key(s) for\ntheir owned devices is set to Yes.\n3. Ensure that the property AllowedToReadBitlockerKeysForOwnedDevice is set",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Devices select Device settings.\n3. Set Restrict users from recovering the BitLocker key(s) for their\nowned devices to Yes.\nTo remediate using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.ReadWrite.Authorization\"\n2. Run the following:\n$params = @{\ndefaultUserRolePermissions = @{\nAllowedToReadBitlockerKeysForOwnedDevice = $false\n}\n}\nUpdate-MgPolicyAuthorizationPolicy -BodyParameter $params",
    "default_value": "No",
    "detection_commands": [],
    "remediation_commands": [
      "$params = @{",
      "Update-MgPolicyAuthorizationPolicy -BodyParameter $params"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-",
      "identities#configure-device-settings",
      "2. https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-",
      "rest-1.0",
      "3. https://techcommunity.microsoft.com/blog/intunecustomersuccess/user-self-",
      "service-bitlocker-recovery-key-access-with-intune-company-portal-",
      "websi/4150458",
      "4. https://learn.microsoft.com/en-us/windows/security/operating-system-",
      "security/data-protection/bitlocker/recovery-process#self-recovery"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 208,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.1.5.1",
    "title": "Ensure user consent to apps accessing company data on their behalf is not allowed",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Configure Data Access Control Lists",
    "m365_profile": "E3",
    "description": "Control when end users and group owners are allowed to grant consent to applications,\nand when they will be required to request administrator review and approval. Allowing\nusers to grant apps access to data helps them acquire useful applications and be\nproductive but can represent a risk in some situations if it's not monitored and controlled\ncarefully.",
    "rationale": "Attackers commonly use custom applications to trick users into granting them access to\ncompany data. Restricting user consent mitigates this risk and helps to reduce the\nthreat-surface.",
    "impact": "If user consent is disabled, previous consent grants will still be honored but all future\nconsent operations must be performed by an administrator. Tenant-wide admin consent\ncan be requested by users through an integrated administrator consent request\nworkflow or through organizational support processes.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID and select Enterprise apps.\n3. Under Security select Consent and permissions > User consent\nsettings.\n4. Verify User consent for applications is set to Do not allow user\nconsent.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.All\"\n2. Run the following command:\n(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions |\nSelect-Object -ExpandProperty PermissionGrantPoliciesAssigned\n3. Verify that the returned string does not contain either\nManagePermissionGrantsForSelf.microsoft-user-default-low or\nManagePermissionGrantsForSelf.microsoft-user-default-legacy. If\neither of these strings is present, the audit fails.",
    "expected_response": "4. Verify User consent for applications is set to Do not allow user\neither of these strings is present, the audit fails.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID and select Enterprise apps.\n3. Under Security select Consent and permissions > User consent\nsettings.\n4. Under User consent for applications select Do not allow user\nconsent.\n5. Click the Save option at the top of the window.",
    "default_value": "UI - Allow user consent for apps",
    "detection_commands": [
      "Select-Object -ExpandProperty PermissionGrantPoliciesAssigned"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-",
      "consent?pivots=portal"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 212,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "5.1.5.2",
    "title": "Ensure the admin consent workflow is enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Protect Information through Access Control Lists",
    "m365_profile": "E3",
    "description": "The admin consent workflow gives admins a secure way to grant access to applications\nthat require admin approval. When a user tries to access an application but is unable to\nprovide consent, they can send a request for admin approval. The request is sent via\nemail to admins who have been designated as reviewers. A reviewer takes action on\nthe request, and the user is notified of the action.",
    "rationale": "The admin consent workflow (Preview) gives admins a secure way to grant access to\napplications that require admin approval. When a user tries to access an application but\nis unable to provide consent, they can send a request for admin approval. The request\nis sent via email to admins who have been designated as reviewers. A reviewer acts on\nthe request, and the user is notified of the action.",
    "impact": "To approve requests, a reviewer must be a global administrator, cloud application\nadministrator, or application administrator. The reviewer must already have one of these\nadmin roles assigned; simply designating them as a reviewer doesn't elevate their\nprivileges.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID and select Enterprise apps.\n3. Under Security select Consent and permissions.\n4. Under Manage select Admin consent settings.\n5. Verify that Users can request admin consent to apps they are unable\nto consent to is set to Yes.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.All\"\n2. Run the following command:\nGet-MgPolicyAdminConsentRequestPolicy |\nfl IsEnabled,NotifyReviewers,RemindersEnabled\n3. Ensure IsEnabled is set to True.",
    "expected_response": "to consent to is set to Yes.\n3. Ensure IsEnabled is set to True.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID and select Enterprise apps.\n3. Under Security select Consent and permissions.\n4. Under Manage select Admin consent settings.\n5. Set Users can request admin consent to apps they are unable to\nconsent to to Yes under Admin consent requests.\n6. Under the Reviewers choose the Roles and Groups that will review user\ngenerated app consent requests.\n7. Set Selected users will receive email notifications for requests to\nYes\n8. Select Save at the top of the window.",
    "default_value": "• Users can request admin consent to apps they are unable to\nconsent to: No\n• Selected users to review admin consent requests: None\n• Selected users will receive email notifications for requests: Yes\n• Selected users will receive request expiration reminders: Yes\n• Consent request expires after (days): 30",
    "detection_commands": [
      "Get-MgPolicyAdminConsentRequestPolicy |"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-",
      "consent-workflow"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 215,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.1.6.1",
    "title": "Ensure that collaboration invitations are sent to allowed domains only",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Verify That Acquired Software is Still Supported",
    "m365_profile": "E3",
    "description": "B2B collaboration is a feature within Microsoft Entra External ID that allows for guest\ninvitations to an organization.\nEnsure users can only send invitations to specified domains.\nNote: This list works independently from OneDrive for Business and SharePoint Online\nallow/block lists. To restrict individual file sharing in SharePoint Online, set up an allow\nor blocklist for OneDrive for Business and SharePoint Online. For instance, in\nSharePoint or OneDrive users can still share with external users from prohibited\ndomains by using Anyone links if they haven't been disabled.",
    "rationale": "By specifying allowed domains for collaborations, external user's companies are\nexplicitly identified. Also, this prevents internal users from inviting unknown external\nusers such as personal accounts and granting them access to resources.",
    "impact": "This could make collaboration more difficult if the setting is not quickly updated when a\nnew domain is identified as \"allowed\".",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > External Identities select External\ncollaboration settings.\n3. Under Collaboration restrictions, verify that Allow invitations only to\nthe specified domains (most restrictive) is selected. Then verify\nallowed domains are specified under Target domains.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.All\"\n2. Run the following:\n$Uri = \"https://graph.microsoft.com/beta/legacy/policies\"\n$Response = (Invoke-MgGraphRequest -Uri $Uri).value |\nWhere-Object { $_.type -eq 'B2BManagementPolicy' }\nif ($Response) {\n$Definition = $Response.definition | ConvertFrom-Json\n$DomainsPolicy =\n$Definition.B2BManagementPolicy.InvitationsAllowedAndBlockedDomainsPolicy\n} else {\nWrite-Output \"No policy found.\"\nreturn\n}\n$DomainsPolicy\n3. Ensure the output includes an AllowedDomains property that either contains no\ndomains or lists only organizationally approved domains. If a BlockedDomains\nproperty is present, the configuration is considered non-compliant.\nExample of a compliant output with AllowedDomains defined:\nAllowedDomains\n--------------\n{cisecurity.org, contoso.com, example.com}\nAllowed with no domains allowed (also compliant):\nAllowedDomains\n--------------\n{}",
    "expected_response": "Write-Output \"No policy found.\"\nreturn\n3. Ensure the output includes an AllowedDomains property that either contains no\nproperty is present, the configuration is considered non-compliant.\nExample of a compliant output with AllowedDomains defined:",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > External Identities select External\ncollaboration settings.\n3. Under Collaboration restrictions, select Allow invitations only to the\nspecified domains (most restrictive) is selected. Then specify the\nallowed domains under Target domains.",
    "default_value": "Allow invitations to be sent to any domain (most inclusive)",
    "detection_commands": [
      "$Uri = \"https://graph.microsoft.com/beta/legacy/policies\" $Response = (Invoke-MgGraphRequest -Uri $Uri).value |",
      "$Definition = $Response.definition | ConvertFrom-Json $DomainsPolicy = $Definition.B2BManagementPolicy.InvitationsAllowedAndBlockedDomainsPolicy",
      "$DomainsPolicy"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/external-id/allow-deny-list",
      "2. https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 219,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.1.6.2",
    "title": "Ensure that guest user access is restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Maintain an Inventory Sensitive Information",
    "m365_profile": "E3",
    "description": "Microsoft Entra ID, part of Microsoft Entra, allows you to restrict what external guest\nusers can see in their organization in Microsoft Entra ID. Guest users are set to a limited\npermission level by default in Microsoft Entra ID, while the default for member users is\nthe full set of user permissions.\nThese directory level permissions are enforced across Microsoft Entra services\nincluding Microsoft Graph, PowerShell v2, the Azure portal, and My Apps portal.\nMicrosoft 365 services leveraging Microsoft 365 groups for collaboration scenarios are\nalso affected, specifically Outlook, Microsoft Teams, and SharePoint. They do not\noverride the SharePoint or Microsoft Teams guest settings.\nThe recommended state is at least Guest users have limited access to\nproperties and memberships of directory objects or more restrictive.",
    "rationale": "By limiting guest access to the most restrictive state this helps prevent malicious group\nand user object enumeration in the Microsoft 365 environment. This first step, known as\nreconnaissance in The Cyber Kill Chain, is often conducted by attackers prior to more\nadvanced targeted attacks.",
    "impact": "The default is Guest users have limited access to properties and\nmemberships of directory objects.\nWhen using the 'most restrictive' setting, guests will only be able to access their own\nprofiles and will not be allowed to see other users' profiles, groups, or group\nmemberships.\nThere are some known issues with Yammer that will prevent guests that are signed in\nfrom leaving the group.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > External Identities select External\ncollaboration settings.\n3. Under Guest user access verify that Guest user access restrictions is set\nto one of the following:\no State: Guest users have limited access to properties and\nmemberships of directory objects\no State: Guest user access is restricted to properties and\nmemberships of their own directory objects (most\nrestrictive)\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.All\"\n2. Run the following command:\nGet-MgPolicyAuthorizationPolicy | fl GuestUserRoleId\n3. Ensure the value returned is 10dae51f-b6af-4016-8d66-8c2a99b929b3 or\n2af84b1e-32c8-42b7-82bc-daa82404023b (most restrictive)\nNote: Either setting allows for a passing state.\nNote 2: The value of a0b1b346-4d3e-4e8b-98f8-753987be4970 is equal to Guest\nusers have the same access as members (most inclusive) and should not be\nused.",
    "expected_response": "3. Ensure the value returned is 10dae51f-b6af-4016-8d66-8c2a99b929b3 or\nNote 2: The value of a0b1b346-4d3e-4e8b-98f8-753987be4970 is equal to Guest\nusers have the same access as members (most inclusive) and should not be",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > External Identities select External\ncollaboration settings.\n3. Under Guest user access set Guest user access restrictions to one of\nthe following:\no State: Guest users have limited access to properties and\nmemberships of directory objects\no State: Guest user access is restricted to properties and\nmemberships of their own directory objects (most\nrestrictive)\nTo remediate using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.ReadWrite.Authorization\"\n2. Run the following command to set the guest user access restrictions to default:\n# Guest users have limited access to properties and memberships of directory\nobjects\nUpdate-MgPolicyAuthorizationPolicy -GuestUserRoleId '10dae51f-b6af-4016-8d66-\n8c2a99b929b3'\n3. Or, run the following command to set it to the \"most restrictive\":\n# Guest user access is restricted to properties and memberships of their own\ndirectory objects (most restrictive)\nUpdate-MgPolicyAuthorizationPolicy -GuestUserRoleId '2af84b1e-32c8-42b7-82bc-\ndaa82404023b'\nNote: Either setting allows for a passing state.",
    "default_value": "• UI: Guest users have limited access to properties and memberships\nof directory objects\n• PowerShell: 10dae51f-b6af-4016-8d66-8c2a99b929b3",
    "detection_commands": [
      "Get-MgPolicyAuthorizationPolicy | fl GuestUserRoleId"
    ],
    "remediation_commands": [
      "Update-MgPolicyAuthorizationPolicy -GuestUserRoleId '10dae51f-b6af-4016-8d66-",
      "Update-MgPolicyAuthorizationPolicy -GuestUserRoleId '2af84b1e-32c8-42b7-82bc-"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-",
      "permissions",
      "2. https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 222,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.1.6.3",
    "title": "Ensure guest user invitations are limited to the Guest Inviter role",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Establish an Access Granting Process",
    "m365_profile": "E3",
    "description": "By default, all users in the organization, including B2B collaboration guest users, can\ninvite external users to B2B collaboration. The ability to send invitations can be limited\nby turning it on or off for everyone, or by restricting invitations to certain roles.\nThe recommended state for guest invite restrictions is Only users assigned to\nspecific admin roles can invite guest users.",
    "rationale": "Restricting who can invite guests limits the exposure the organization might face from\nunauthorized accounts.",
    "impact": "This introduces an obstacle to collaboration by restricting who can invite guest users to\nthe organization. Designated Guest Inviters must be assigned, and an approval process\nestablished and clearly communicated to all users.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > External Identities select External\ncollaboration settings.\n3. Under Guest invite settings verify that Guest invite restrictions is set to\nOnly users assigned to specific admin roles can invite guest\nusers or more restrictive.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.All\"\n2. Run the following command:\nGet-MgPolicyAuthorizationPolicy | fl AllowInvitesFrom\n3. Ensure the value returned is adminsAndGuestInviters or more restrictive.",
    "expected_response": "3. Under Guest invite settings verify that Guest invite restrictions is set to\n3. Ensure the value returned is adminsAndGuestInviters or more restrictive.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > External Identities select External\ncollaboration settings.\n3. Under Guest invite settings set Guest invite restrictions to Only users\nassigned to specific admin roles can invite guest users.\nTo remediate using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.ReadWrite.Authorization\"\n2. Run the following command:\nUpdate-MgPolicyAuthorizationPolicy -AllowInvitesFrom 'adminsAndGuestInviters'\nNote: The more restrictive position of the value will also pass audit, it is however not\nrequired.",
    "default_value": "• UI: Anyone in the organization can invite guest users including\nguests and non-admins (most inclusive)\n• PowerShell: everyone",
    "detection_commands": [
      "Get-MgPolicyAuthorizationPolicy | fl AllowInvitesFrom"
    ],
    "remediation_commands": [
      "Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom 'adminsAndGuestInviters'"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-",
      "configure",
      "2. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/permissions-reference#guest-inviter"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 226,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.1.8.1",
    "title": "Ensure that password hash sync is enabled for hybrid deployments",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Maintain an Inventory Sensitive Information",
    "m365_profile": "E3",
    "description": "Password hash synchronization is one of the sign-in methods used to accomplish hybrid\nidentity synchronization. Microsoft Entra Connect synchronizes a hashed version of the\nuser's password hash from an on-premises Active Directory to a cloud-based Entra ID\ninstance.\nNote: The original MD4 hash isn't transmitted to Microsoft Entra ID. Instead, the\nSHA256 hash of the original MD4 hash is transmitted. As a result, if the hash stored in\nMicrosoft Entra ID is obtained, it can't be used in an on-premises pass-the-hash attack.",
    "rationale": "Password hash synchronization helps by reducing the number of passwords your users\nneed to maintain to just one and enables leaked credential detection for your hybrid\naccounts. Leaked credential protection is leveraged through Entra ID Protection and is a\nsubset of that feature which can help identify if an organization's user account\npasswords have appeared on the dark web or public spaces.\nUsing other options for your directory synchronization may be less resilient as Microsoft\ncan still process sign-ins to 365 with Hash Sync even if a network connection to your\non-premises environment is not available. This minimizes downtime and ensures\nbusiness continuity.",
    "impact": "Compliance or regulatory restrictions may exist, depending on the organization's\nbusiness sector, that preclude hashed versions of passwords from being securely\ntransmitted to cloud data centers.",
    "audit": "To audit using the UI:\nOnly Global Admin and Hybrid Identity Administrator roles have access to view the\nactual Password Hash Sync status message. Inadequate role access will result in a\ndefault message stating: \"Unable to retrieve your tenant’s password hash sync\ninformation.\"\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Entra Connect.\n3. Select Connect Sync.\n4. Under Microsoft Entra Connect sync, verify the Password Hash Sync status\nmessage indicates that synchronization is occurring and no errors are present,\nwith one of the following messages:\no Password hash synchronization is enabled\no Password hash synchronization cloud configuration is enabled\no Password hash synchronization heartbeat detected\nTo audit for the on-prem tool:\n1. Log in to the server that hosts the Microsoft Entra Connect tool.\n2. Run Azure AD Connect, and then click Configure and View or export\ncurrent configuration.\n3. Determine whether PASSWORD HASH SYNCHRONIZATION is enabled on your\ntenant.\nTo audit using PowerShell:\n1. Open PowerShell on the on-premises server running Microsoft Entra Connect.\n2. Run the following cmdlet:\nGet-ADSyncAADCompanyFeature\n3. Ensure PasswordHashSync is True.\nNote: Audit and remediation procedures in this recommendation only apply to Microsoft\n365 tenants operating in a hybrid configuration using Entra Connect sync, and do not\napply to federated domains.",
    "expected_response": "o Password hash synchronization is enabled\no Password hash synchronization cloud configuration is enabled\n3. Determine whether PASSWORD HASH SYNCHRONIZATION is enabled on your\n3. Ensure PasswordHashSync is True.",
    "remediation": "To remediate using the on-prem Microsoft Entra Connect tool:\n1. Log in to the on premises server that hosts the Microsoft Entra Connect tool\n2. Double-click the Azure AD Connect icon that was created on the desktop\n3. Click Configure.\n4. On the Additional tasks page, select Customize synchronization\noptions and click Next.\n5. Enter the username and password for your global administrator.\n6. On the Connect your directories screen, click Next.\n7. On the Domain and OU filtering screen, click Next.\n8. On the Optional features screen, check Password hash synchronization\nand click Next.\n9. On the Ready to configure screen click Configure.\n10. Once the configuration completes, click Exit.",
    "default_value": "• Microsoft Entra Connect sync disabled by default\n• Password Hash Sync is Microsoft's recommended setting for new deployments",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-phs",
      "2. https://www.microsoft.com/en-us/download/details.aspx?id=47594",
      "3. https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-",
      "sync-staging-server",
      "4. https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-",
      "password-hash-synchronization"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 231,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.2.2.1",
    "title": "Ensure multifactor authentication is enabled for all users in administrative roles",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "tenants_operating_in_a_hybrid_configuration_using_entra_connect_sync_and_do_not",
    "domain": "tenants operating in a hybrid configuration using Entra Connect sync, and do not",
    "subdomain": "ID Protection",
    "m365_profile": "E3",
    "description": "Multifactor authentication is a process that requires an additional form of identification\nduring the sign-in process, such as a code from a mobile device or a fingerprint scan, to\nenhance security.\nEnsure users in administrator roles have MFA capabilities enabled.",
    "rationale": "Multifactor authentication requires an individual to present a minimum of two separate\nforms of authentication before access is granted. Multifactor authentication provides\nadditional assurance that the individual attempting to gain access is who they claim to\nbe. With multifactor authentication, an attacker would need to compromise at least two\ndifferent authentication mechanisms, increasing the difficulty of compromise and thus\nreducing the risk.",
    "impact": "Implementation of multifactor authentication for all users in administrative roles will\nnecessitate a change to user routine. All users in administrative roles will be required to\nenroll in multifactor authentication using phone, SMS, or an authentication application.\nAfter enrollment, use of multifactor authentication will be required for future access to\nthe environment.",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Ensure that a policy exists with the following criteria and is set to On:\no Under Users verify Directory roles specific to administrators are\nincluded.\no Ensure that only documented user exclusions exist and that they are\nreviewed annually.\no Under Target resources verify All resources (formerly 'All\ncloud apps') is selected with no exclusions.\no Under Grant verify Grant Access is on and either Require\nmultifactor authentication or Require authentication strength\nis checked.\n4. Ensure Enable policy is set to On.\nNote: A list of Directory roles can be found in the Remediation section.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "expected_response": "3. Ensure that a policy exists with the following criteria and is set to On:\no Ensure that only documented user exclusions exist and that they are\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Click New policy.\no Under Users include Select users and groups and check Directory\nroles.\no At a minimum, include the directory roles listed below in this section of the\ndocument.\no Under Target resources include All resources (formerly 'All\ncloud apps') and do not create any exclusions.\no Under Grant select Grant Access and check either Require\nmultifactor authentication or Require authentication\nstrength.\no Click Select at the bottom of the pane.\n4. Under Enable policy set it to Report-only until the organization is ready to\nenable it.\n5. Click Create.\nAt minimum these directory roles should be included for MFA:\n• Application administrator\n• Authentication administrator\n• Billing administrator\n• Cloud application administrator\n• Conditional Access administrator\n• Exchange administrator\n• Global administrator\n• Global reader\n• Helpdesk administrator\n• Password administrator\n• Privileged authentication administrator\n• Privileged role administrator\n• Security administrator\n• SharePoint administrator\n• User administrator\nNote: Report-only is an acceptable first stage when introducing any CA policy. The\ncontrol, however, is not complete until the policy is on.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-",
      "conditional-access-policy-admin-mfa"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 236,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.2.2",
    "title": "Ensure multifactor authentication is enabled for all users",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "tenants_operating_in_a_hybrid_configuration_using_entra_connect_sync_and_do_not",
    "domain": "tenants operating in a hybrid configuration using Entra Connect sync, and do not",
    "subdomain": "Require Multi-factor Authentication",
    "m365_profile": "E3",
    "description": "Enable multifactor authentication for all users in the Microsoft 365 tenant. Users will be\nprompted to authenticate with a second factor upon logging in to Microsoft 365 services.\nThe second factor is most commonly a text message to a registered mobile phone\nnumber where they type in an authorization code, or with a mobile application like\nMicrosoft Authenticator.",
    "rationale": "Multifactor authentication requires an individual to present a minimum of two separate\nforms of authentication before access is granted. Multifactor authentication provides\nadditional assurance that the individual attempting to gain access is who they claim to\nbe. With multifactor authentication, an attacker would need to compromise at least two\ndifferent authentication mechanisms, increasing the difficulty of compromise and thus\nreducing the risk.",
    "impact": "Implementation of multifactor authentication for all users will necessitate a change to\nuser routine. All users will be required to enroll in multifactor authentication using phone,\nSMS, or an authentication application. After enrollment, use of multifactor authentication\nwill be required for future authentication to the environment.\nExternal identities that attempt to access documents that utilize Purview Information\nProtection (Sensitivity Labels) will find their access disrupted. In order to mitigate this\ncreate an exclusion for Microsoft Rights Management Services ID: 00000012-\n0000-0000-c000-000000000000\nNote: Organizations that struggle to enforce MFA globally due to budget constraints\npreventing the provision of company-owned mobile devices to every user, or due to\nregulations, unions, or policies that prevent forcing end users to use their personal\ndevices, have another option. FIDO2 security keys can be used as an alternative. They\nare more secure, phishing-resistant, and affordable for organizations to issue to every\nend user.",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Ensure that a policy exists with the following criteria and is set to On:\no Under Users verify All users is included.\no Ensure that only documented user exclusions exist and that they are\nreviewed annually.\no Under Target resources verify All resources (formerly 'All\ncloud apps') is selected with no exclusions.\no Under Grant verify Grant Access and either Require multifactor\nauthentication or Require authentication strength is checked.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "expected_response": "3. Ensure that a policy exists with the following criteria and is set to On:\no Ensure that only documented user exclusions exist and that they are\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand Protection > Conditional Access select Policies.\n3. Click New policy.\no Under Users include All users.\no Under Target resources include All resources (formerly 'All\ncloud apps') and do not create any exclusions.\no Under Grant select Grant Access and check either Require\nmultifactor authentication or Require authentication\nstrength.\no Click Select at the bottom of the pane.\n4. Under Enable policy set it to Report-only until the organization is ready to\nenable it.\n5. Click Create.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-",
      "conditional-access-policy-all-users-mfa"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 240,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.2.2.3",
    "title": "Enable Conditional Access policies to block legacy authentication",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "tenants_operating_in_a_hybrid_configuration_using_entra_connect_sync_and_do_not",
    "domain": "tenants operating in a hybrid configuration using Entra Connect sync, and do not",
    "subdomain": "Require Multi-factor Authentication",
    "m365_profile": "E3",
    "description": "Entra ID supports the most widely used authentication and authorization protocols\nincluding legacy authentication. This authentication pattern includes basic\nauthentication, a widely used industry-standard method for collecting username and\npassword information.\nThe following messaging protocols support legacy authentication:\n• Authenticated SMTP - Used to send authenticated email messages.\n• Autodiscover - Used by Outlook and EAS clients to find and connect to\nmailboxes in Exchange Online.\n• Exchange ActiveSync (EAS) - Used to connect to mailboxes in Exchange Online.\n• Exchange Online PowerShell - Used to connect to Exchange Online with remote\nPowerShell. If you block Basic authentication for Exchange Online PowerShell,\nyou need to use the Exchange Online PowerShell Module to connect. For\ninstructions, see Connect to Exchange Online PowerShell using multifactor\nauthentication.\n• Exchange Web Services (EWS) - A programming interface that's used by\nOutlook, Outlook for Mac, and third-party apps.\n• IMAP4 - Used by IMAP email clients.\n• MAPI over HTTP (MAPI/HTTP) - Primary mailbox access protocol used by\nOutlook 2010 SP2 and later.\n• Offline Address Book (OAB) - A copy of address list collections that are\ndownloaded and used by Outlook.\n• Outlook Anywhere (RPC over HTTP) - Legacy mailbox access protocol\nsupported by all current Outlook versions.\n• POP3 - Used by POP email clients.\n• Reporting Web Services - Used to retrieve report data in Exchange Online.\n• Universal Outlook - Used by the Mail and Calendar app for Windows 10.\n• Other clients - Other protocols identified as utilizing legacy authentication.",
    "rationale": "Legacy authentication protocols do not support multi-factor authentication. These\nprotocols are often used by attackers because of this deficiency. Blocking legacy\nauthentication makes it harder for attackers to gain access.\nNote: Basic authentication is now disabled in all tenants. Before December 31 2022,\nyou could re-enable the affected protocols if users and apps in your tenant couldn't\nconnect. Now no one (you or Microsoft support) can re-enable Basic authentication in\nyour tenant.",
    "impact": "Enabling this setting will prevent users from connecting with older versions of Office,\nActiveSync or using protocols like IMAP, POP or SMTP and may require upgrades to\nolder versions of Office, and use of mobile mail clients that support modern\nauthentication.\nThis will also cause multifunction devices such as printers from using scan to e-mail\nfunction if they are using a legacy authentication method. Microsoft has mail flow best\npractices in the link below which can be used to configure a MFP to work with modern\nauthentication:\nhttps://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-\nmultifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Ensure that a policy exists with the following criteria and is set to On:\no Under Users verify All users is included.\no Ensure that only documented user exclusions exist and that they are\nreviewed annually.\no Under Target resources verify All resources (formerly 'All\ncloud apps') is selected.\no Ensure that only documented resource exclusions exist and that they are\nreviewed annually.\no Under Conditions select Client apps then verify Exchange\nActiveSync clients and Other clients is checked.\no Under Grant verify Block access is selected.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "expected_response": "3. Ensure that a policy exists with the following criteria and is set to On:\no Ensure that only documented user exclusions exist and that they are\no Ensure that only documented resource exclusions exist and that they are\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Create a new policy by selecting New policy.\no Under Users include All users.\no Under Target resources include All resources (formerly 'All\ncloud apps').\no Under Conditions select Client apps and check the boxes for\nExchange ActiveSync clients and Other clients.\no Under Grant select Block Access.\no Click Select.\n4. Set the policy On and click Create.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "default_value": "Basic authentication is disabled by default as of January 2023.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-",
      "online/disable-basic-authentication-in-exchange-online",
      "2. https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-",
      "up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-",
      "office-365",
      "3. https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-",
      "online/deprecation-of-basic-authentication-exchange-online"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 243,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.2.4",
    "title": "Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "tenants_operating_in_a_hybrid_configuration_using_entra_connect_sync_and_do_not",
    "domain": "tenants operating in a hybrid configuration using Entra Connect sync, and do not",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "m365_profile": "E3",
    "description": "In complex deployments, organizations might have a need to restrict authentication\nsessions. Conditional Access policies allow for the targeting of specific user accounts.\nSome scenarios might include:\n• Resource access from an unmanaged or shared device\n• Access to sensitive information from an external network\n• High-privileged users\n• Business-critical applications\nNote: This CA policy can be added to the previous CA policy in this benchmark \"Ensure\nmultifactor authentication is enabled for all users in administrative roles\"",
    "rationale": "Forcing a time out for MFA will help ensure that sessions are not kept alive for an\nindefinite period of time, ensuring that browser sessions are not persistent will help in\nprevention of drive-by attacks in web browsers, this also prevents creation and saving of\nsession cookies leaving nothing for an attacker to take.",
    "impact": "Users with Administrative roles will be prompted at the frequency set for MFA.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Ensure that a policy exists with the following criteria and is set to On:\no Under Users verify Directory roles specific to administrators are\nincluded.\no Ensure that only documented user exclusions exist and that they are\nreviewed annually.\no Under Target resources verify All resources (formerly 'All\ncloud apps') is selected.\no Ensure that only documented resource exclusions exist and that they are\nreviewed annually.\no Under Session verify Sign-in frequency is checked and set to\nPeriodic reauthentication.\no Verify the timeframe is set to the time determined by the organization.\no Ensure Periodic reauthentication does not exceed 4 hours (or less).\no Verify Persistent browser session is set to Never persistent.\n4. Ensure Enable policy is set to On\nNote: Break-glass accounts should be excluded from all Conditional Access policies.\nNote: A list of directory roles applying to Administrators can be found in the remediation\nsection.",
    "expected_response": "3. Ensure that a policy exists with the following criteria and is set to On:\no Ensure that only documented user exclusions exist and that they are\no Ensure that only documented resource exclusions exist and that they are\no Verify the timeframe is set to the time determined by the organization.\no Ensure Periodic reauthentication does not exceed 4 hours (or less).\no Verify Persistent browser session is set to Never persistent.\n4. Ensure Enable policy is set to On\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Click New policy.\no Under Users include Select users and groups and check Directory\nroles.\no At a minimum, include the directory roles listed below in this section of the\ndocument.\no Under Target resources include All resources (formerly 'All\ncloud apps').\no Under Grant select Grant Access and check Require multifactor\nauthentication.\no Under Session select Sign-in frequency select Periodic\nreauthentication and set it to 4 hours (or less).\no Check Persistent browser session then select Never persistent in\nthe drop-down menu.\n4. Under Enable policy set it to Report-only until the organization is ready to\nenable it.\nAt minimum these directory roles should be included in the policy:\n• Application administrator\n• Authentication administrator\n• Billing administrator\n• Cloud application administrator\n• Conditional Access administrator\n• Exchange administrator\n• Global administrator\n• Global reader\n• Helpdesk administrator\n• Password administrator\n• Privileged authentication administrator\n• Privileged role administrator\n• Security administrator\n• SharePoint administrator\n• User administrator\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "default_value": "The default configuration for user sign-in frequency is a rolling window of 90 days.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-",
      "conditional-access-session-lifetime"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 246,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.2.5",
    "title": "Ensure 'Phishing-resistant MFA strength' is required for Administrators",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Require Multi-factor Authentication",
    "m365_profile": "E3",
    "description": "Authentication strength is a Conditional Access control that allows administrators to\nspecify which combination of authentication methods can be used to access a resource.\nFor example, they can make only phishing-resistant authentication methods available to\naccess a sensitive resource. But to access a non-sensitive resource, they can allow less\nsecure multifactor authentication (MFA) combinations, such as password + SMS.\nMicrosoft has 3 built-in authentication strengths. MFA strength, Passwordless MFA\nstrength, and Phishing-resistant MFA strength. Ensure administrator roles are using a\nCA policy with Phishing-resistant MFA strength.\nAdministrators can then enroll using one of 3 methods:\n• FIDO2 Security Key\n• Windows Hello for Business\n• Certificate-based authentication (Multi-Factor)\nNote: Additional steps to configure methods such as FIDO2 keys are not covered here\nbut can be found in related MS articles in the references section. The Conditional\nAccess policy only ensures 1 of the 3 methods is used.\nWarning: Administrators should be pre-registered for a strong authentication\nmechanism before this Conditional Access Policy is enforced. Additionally, as stated\nelsewhere in the CIS Benchmark a break-glass administrator account should be\nexcluded from this policy to ensure unfettered access in the case of an emergency.",
    "rationale": "Sophisticated attacks targeting MFA are more prevalent as the use of it becomes more\nwidespread. These 3 methods are considered phishing-resistant as they remove\npasswords from the login workflow. It also ensures that public/private key exchange can\nonly happen between the devices and a registered provider which prevents login to fake\nor phishing websites.",
    "impact": "If administrators aren't pre-registered for a strong authentication method prior to a\nconditional access policy being created, then a condition could occur where a user can't\nregister for strong authentication because they don't meet the conditional access policy\nrequirements and therefore are prevented from signing in.\nAdditionally, Internet Explorer based credential prompts in PowerShell do not support\nprompting for a security key. Implementing phishing-resistant MFA with a security key\nmay prevent admins from running their existing sets of PowerShell scripts. Device\nAuthorization Grant Flow can be used as a workaround in some instances.",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Ensure that a policy exists with the following criteria and is set to On:\no Under Users verify Directory roles specific to administrators are\nincluded.\no Ensure that only documented user exclusions exist and that they are\nreviewed annually.\no Directory Roles should include at minimum the roles listed in the\nremediation section.\no Under Target resources verify All resources (formerly 'All\ncloud apps') is selected with no exclusions.\no Under Grant verify Grant Access is selected and Require\nauthentication strength is checked with Phishing-resistant MFA\nset as the value.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "expected_response": "3. Ensure that a policy exists with the following criteria and is set to On:\no Ensure that only documented user exclusions exist and that they are\no Directory Roles should include at minimum the roles listed in the\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Click New policy.\no Under Users include Select users and groups and check Directory\nroles.\no At a minimum, include the directory roles listed below in this section of the\ndocument.\no Under Target resources include All resources (formerly 'All\ncloud apps') and do not create any exclusions.\no Under Grant select Grant Access and check Require authentication\nstrength and set Phishing-resistant MFA in the dropdown box.\no Click Select.\n4. Under Enable policy set it to Report-only until the organization is ready to\nenable it.\n5. Click Create.\nAt minimum these directory roles should be included for the policy:\n• Application administrator\n• Authentication administrator\n• Billing administrator\n• Cloud application administrator\n• Conditional Access administrator\n• Exchange administrator\n• Global administrator\n• Global reader\n• Helpdesk administrator\n• Password administrator\n• Privileged authentication administrator\n• Privileged role administrator\n• Security administrator\n• SharePoint administrator\n• User administrator\nWarning: Ensure administrators are pre-registered with strong authentication before\nenforcing the policy. After which the policy must be set to On.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-",
      "authentication-passwordless#fido2-security-keys",
      "2. https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-enable-",
      "passkey-fido2",
      "3. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-",
      "authentication-strengths",
      "4. https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-",
      "configure-mfa-policy"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 250,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.2.6",
    "title": "Enable Identity Protection user risk policies",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Require MFA for Administrative Access",
    "m365_profile": "E5",
    "description": "Microsoft Entra ID Protection user risk policies detect the probability that a user account\nhas been compromised.\nNote: While Identity Protection also provides two risk policies with limited conditions,\nMicrosoft highly recommends setting up risk-based policies in Conditional Access as\nopposed to the \"legacy method\" for the following benefits:\n• Enhanced diagnostic data\n• Report-only mode integration\n• Graph API support\n• Use more Conditional Access attributes like sign-in frequency in the policy",
    "rationale": "With the user risk policy turned on, Entra ID protection detects the probability that a user\naccount has been compromised. Administrators can configure a user risk conditional\naccess policy to automatically respond to a specific user risk level.",
    "impact": "Upon policy activation, account access will be either blocked or the user will be required\nto use multi-factor authentication (MFA) and change their password. Users without\nregistered MFA will be denied access, necessitating an admin to recover the account.\nTo avoid inconvenience, it is advised to configure the MFA registration policy for all\nusers under the User Risk policy.\nAdditionally, users identified in the Risky Users section will be affected by this policy. To\ngain a better understanding of the impact on the organization's environment, the list of\nRisky Users should be reviewed before enforcing the policy.",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Ensure that a policy exists with the following criteria and is set to On:\no Under Users verify All users is included.\no Ensure that only documented user exclusions exist and that they are\nreviewed annually.\no Under Target resources verify All resources (formerly 'All\ncloud apps') is selected.\no Under Conditions verify User risk is set to High.\no Under Grant verify Grant access is selected and either Require\nmultifactor authentication or Require authentication strength\nare checked. Then verify Require password change is checked.\no Under Session ensure Sign-in frequency is set to Every time.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "expected_response": "3. Ensure that a policy exists with the following criteria and is set to On:\no Ensure that only documented user exclusions exist and that they are\no Under Conditions verify User risk is set to High.\no Under Session ensure Sign-in frequency is set to Every time.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Create a new policy by selecting New policy.\n4. Set the following conditions within the policy:\no Under Users choose All users\no Under Target resources choose All resources (formerly 'All\ncloud apps')\no Under Conditions choose User risk then Yes and select the user risk\nlevel High.\no Under Grant select Grant access then check Require multifactor\nauthentication or Require authentication strength. Finally check\nRequire password change.\no Under Session set Sign-in frequency to Every time.\no Click Select.\n5. Under Enable policy set it to Report-only until the organization is ready to\nenable it.\n6. Click Create or Save.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-",
      "risk-feedback",
      "2. https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-",
      "risks"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 254,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.2.2.7",
    "title": "Enable Identity Protection sign-in risk policies",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Alert on Account Login Behavior Deviation",
    "m365_profile": "E5",
    "description": "Microsoft Entra ID Protection sign-in risk detects risks in real-time and offline. A risky\nsign-in is an indicator for a sign-in attempt that might not have been performed by the\nlegitimate owner of a user account.\nNote: While Identity Protection also provides two risk policies with limited conditions,\nMicrosoft highly recommends setting up risk-based policies in Conditional Access as\nopposed to the \"legacy method\" for the following benefits:\n• Enhanced diagnostic data\n• Report-only mode integration\n• Graph API support\n• Use more Conditional Access attributes like sign-in frequency in the policy",
    "rationale": "Turning on the sign-in risk policy ensures that suspicious sign-ins are challenged for\nmulti-factor authentication.",
    "impact": "When the policy triggers, the user will need MFA to access the account. In the case of a\nuser who hasn't registered MFA on their account, they would be blocked from accessing\ntheir account. It is therefore recommended that the MFA registration policy be\nconfigured for all users who are a part of the Sign-in Risk policy.",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Ensure that a policy exists with the following criteria and is set to On:\no Under Users verify All users is included.\no Ensure that only documented user exclusions exist and that they are\nreviewed annually.\no Under Target resources verify All resources (formerly 'All\ncloud apps') is selected.\no Under Conditions verify Sign-in risk is set to Yes ensuring High and\nMedium are selected.\no Under Grant verify grant Grant access is selected and Require\nmultifactor authentication checked.\no Under Session verify Sign-in Frequency is set to Every time.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "expected_response": "3. Ensure that a policy exists with the following criteria and is set to On:\no Ensure that only documented user exclusions exist and that they are\no Under Conditions verify Sign-in risk is set to Yes ensuring High and\no Under Session verify Sign-in Frequency is set to Every time.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Create a new policy by selecting New policy.\n4. Set the following conditions within the policy.\no Under Users choose All users.\no Under Target resources choose All resources (formerly 'All\ncloud apps').\no Under Conditions choose Sign-in risk then Yes and check the risk\nlevel boxes High and Medium.\no Under Grant click Grant access then select Require multifactor\nauthentication.\no Under Session select Sign-in Frequency and set to Every time.\no Click Select.\n5. Under Enable policy set it to Report-only until the organization is ready to\nenable it.\n6. Click Create.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-",
      "risk-feedback",
      "2. https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-",
      "risks"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 257,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.2.2.8",
    "title": "Ensure 'sign-in risk' is blocked for medium and high risk",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Alert on Account Login Behavior Deviation",
    "m365_profile": "E5",
    "description": "Microsoft Entra ID Protection sign-in risk detects risks in real-time and offline. A risky\nsign-in is an indicator for a sign-in attempt that might not have been performed by the\nlegitimate owner of a user account.\nNote: While Identity Protection also provides two risk policies with limited conditions,\nMicrosoft highly recommends setting up risk-based policies in Conditional Access as\nopposed to the \"legacy method\" for the following benefits:\n• Enhanced diagnostic data\n• Report-only mode integration\n• Graph API support\n• Use more Conditional Access attributes like sign-in frequency in the policy",
    "rationale": "Sign-in risk is determined at the time of sign-in and includes criteria across both real-\ntime and offline detections for risk. Blocking sign-in to accounts that have risk can\nprevent undesired access from potentially compromised devices or unauthorized users.",
    "impact": "Sign-in risk is heavily dependent on detecting risk based on atypical behaviors. Due to\nthis it is important to run this policy in a report-only mode to better understand how the\norganization's environment and user activity may influence sign-in risk before turning\nthe policy on. Once it's understood what actions may trigger a medium or high sign-in\nrisk event I.T. can then work to create an environment to reduce false positives. For\nexample, employees might be required to notify security personnel when they intend to\ntravel with intent to access work resources.\nNote: Break-glass accounts should always be excluded from risk detection.",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Ensure that a policy exists with the following criteria and is set to On:\no Under Users verify All users is included.\no Ensure that only documented user exclusions exist and that they are\nreviewed annually.\no Under Target resources verify All resources (formerly 'All\ncloud apps') is selected with no exclusions.\no Under Conditions verify Sign-in risk values of High and Medium are\nselected.\no Under Grant verify Block access is selected.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "expected_response": "3. Ensure that a policy exists with the following criteria and is set to On:\no Ensure that only documented user exclusions exist and that they are\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Create a new policy by selecting New policy.\n4. Set the following conditions within the policy.\no Under Users include All users.\no Under Target resources include All resources (formerly 'All\ncloud apps') and do not set any exclusions.\no Under Conditions choose Sign-in risk values of High and Medium\nand click Done.\no Under Grant choose Block access and click Select.\n5. Under Enable policy set it to Report-only until the organization is ready to\nenable it.\n6. Click Create.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-",
      "risks#risk-detections-mapped-to-riskeventtype"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 260,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.2.2.9",
    "title": "Ensure a managed device is required for authentication",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Deploy a Network Intrusion Detection Solution",
    "m365_profile": "E3",
    "description": "Conditional Access (CA) can be configured to enforce access based on the device's\ncompliance status or whether it is Entra hybrid joined. Collectively this allows CA to\nclassify devices as managed or unmanaged, providing more granular control over\nauthentication policies.\nWhen using Require device to be marked as compliant, the device must pass\nchecks configured in Compliance policies defined within Intune (Endpoint Manager).\nBefore these checks can be applied, the device must first be enrolled in Intune MDM.\nBy selecting Require Microsoft Entra hybrid joined device this means the\ndevice must first be synchronized from an on-premises Active Directory to qualify for\nauthentication.\nWhen configured to the recommended state below only one condition needs to be met\nfor the user to authenticate from the device. This functions as an \"OR\" operator.\nThe recommended state is:\n• Require device to be marked as compliant\n• Require Microsoft Entra hybrid joined device\n• Require one of the selected controls",
    "rationale": "\"Managed\" devices are considered more secure because they often have additional\nconfiguration hardening enforced through centralized management such as Intune or\nGroup Policy. These devices are also typically equipped with MDR/EDR, managed\npatching and alerting systems. As a result, they provide a safer environment for users to\nauthenticate and operate from.\nThis policy also ensures that attackers must first gain access to a compliant or trusted\ndevice before authentication is permitted, reducing the risk posed by compromised\naccount credentials. When combined with other distinct Conditional Access (CA)\npolicies, such as requiring multi-factor authentication, this adds one additional factor\nbefore authentication is permitted.\nNote: Avoid combining these two settings with other Grant settings in the same policy.\nIn a single policy you can only choose between Require all the selected\ncontrols or Require one of the selected controls, which limits the ability to\nintegrate this recommendation with others in this benchmark. CA policies function as an\n\"AND\" operator across multiple policies. The goal here is to both (Require MFA for all\nusers) AND (Require device to be marked as compliant OR Require Microsoft Entra\nhybrid joined device).",
    "impact": "Unmanaged devices will not be permitted as a valid authenticator. As a result this may\nrequire the organization to mature their device enrollment and management. The\nfollowing devices can be considered managed:\n• Entra hybrid joined from Active Directory\n• Entra joined and enrolled in Intune, with compliance policies\n• Entra registered and enrolled in Intune, with compliances policies\nIf Guest or external users are collaborating with the organization, they must either\nbe excluded or onboarded with a compliant device to authenticate. Failure to adequately\nsurvey the environment and test the Conditional Access (CA) policy in the Report-only\nstate could result in access disruptions for these guest users.",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Ensure that a policy exists with the following criteria and is set to On:\no Under Users verify All users is included.\no Ensure that only documented user exclusions exist and that they are\nreviewed annually.\no Under Target resources verify All resources (formerly 'All\ncloud apps') is selected.\no Ensure that only documented resource exclusions exist and that they are\nreviewed annually.\no Under Grant verify that only Require device to be marked as\ncompliant and Require Microsoft Entra hybrid joined device\nare checked.\no Under Grant verify Require one of the selected controls is\nselected.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "expected_response": "3. Ensure that a policy exists with the following criteria and is set to On:\no Ensure that only documented user exclusions exist and that they are\no Ensure that only documented resource exclusions exist and that they are\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Create a new policy by selecting New policy.\no Under Users include All users.\no Under Target resources include All resources (formerly 'All\ncloud apps').\no Under Grant select Grant access.\no Select only the checkboxes Require device to be marked as\ncompliant and Require Microsoft Entra hybrid joined device.\no Choose Require one of the selected controls and click Select at\nthe bottom.\n4. Under Enable policy set it to Report-only until the organization is ready to\nenable it.\n5. Click Create.\nNote: Guest user accounts, if collaborating with the organization, should be considered\nwhen testing this policy.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-",
      "conditional-access-grant#require-device-to-be-marked-as-compliant",
      "2. https://learn.microsoft.com/en-us/entra/identity/devices/concept-hybrid-join",
      "3. https://learn.microsoft.com/en-us/mem/intune/fundamentals/deployment-guide-",
      "enrollment"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 263,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.2.10",
    "title": "Ensure a managed device is required to register security information",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Require MFA for Externally-Exposed Applications",
    "m365_profile": "E3",
    "description": "Conditional Access (CA) can be configured to enforce access based on the device's\ncompliance status or whether it is Entra hybrid joined. Collectively this allows CA to\nclassify devices as managed or not, providing more granular control over whether or not\na user can register MFA on a device.\nWhen using Require device to be marked as compliant, the device must pass\nchecks configured in Compliance policies defined within Intune (Endpoint Manager).\nBefore these checks can be applied, the device must first be enrolled in Intune MDM.\nBy selecting Require Microsoft Entra hybrid joined device this means the\ndevice must first be synchronized from an on-premises Active Directory to qualify for\nauthentication.\nWhen configured to the recommended state below only one condition needs to be met\nfor the user to register MFA from the device. This functions as an \"OR\" operator.\nThe recommended state is to restrict Register security information to a device\nthat is marked as compliant or Entra hybrid joined.",
    "rationale": "Requiring registration on a managed device significantly reduces the risk of bad actors\nusing stolen credentials to register security information. Accounts that are created but\nnever registered with an MFA method are particularly vulnerable to this type of attack.\nEnforcing this requirement will both reduce the attack surface for fake registrations and\nensure that legitimate users register using trusted devices which typically have\nadditional security measures in place already.",
    "impact": "The organization will be required to have a mature device management process. New\ndevices provided to users will need to be pre-enrolled in Intune, auto-enrolled or be\nEntra hybrid joined. Otherwise, the user will be unable to complete registration,\nrequiring additional resources from I.T. This could be more disruptive in remote worker\nenvironments where the MDM maturity is low.\nIn these cases where the person enrolling in MFA (enrollee) doesn't have physical\naccess to a managed device, a help desk process can be created using a Teams\nmeeting to complete enrollment using: 1) a durable process to verify the enrollee's\nidentity including government identification with a photograph held up to the camera,\ninformation only the enrollee should know, and verification by the enrollee's direct\nmanager in the same meeting; 2) complete enrollment in the same Teams meeting with\nthe enrollee being granted screen and keyboard access to the help desk person's\nInPrivate Edge browser session.",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Ensure that a policy exists with the following criteria and is set to On:\no Under Users verify All users is included.\no Ensure that only documented user exclusions exist and that they are\nreviewed annually.\no Under Target resources verify User actions is selected with\nRegister security information checked.\no Under Grant verify that only Require device to be marked as\ncompliant and Require Microsoft Entra hybrid joined device\nare checked.\no Under Grant verify Require one of the selected controls is\nselected.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "expected_response": "3. Ensure that a policy exists with the following criteria and is set to On:\no Ensure that only documented user exclusions exist and that they are\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Create a new policy by selecting New policy.\no Under Users include All users.\no Under Target resources select User actions and check Register\nsecurity information.\no Under Grant select Grant access.\no Check only Require multifactor authentication and Require\nMicrosoft Entra hybrid joined device.\no Choose Require one of the selected controls and click Select at\nthe bottom.\n4. Under Enable policy set it to Report-only until the organization is ready to\nenable it.\n5. Click Create.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-",
      "conditional-access-grant#require-device-to-be-marked-as-compliant",
      "2. https://learn.microsoft.com/en-us/entra/identity/devices/concept-hybrid-join",
      "3. https://learn.microsoft.com/en-us/mem/intune/fundamentals/deployment-guide-",
      "enrollment",
      "4. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-",
      "conditional-access-cloud-apps#user-actions"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 266,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.2.11",
    "title": "Ensure sign-in frequency for Intune Enrollment is set to 'Every time'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Require MFA for Externally-Exposed Applications",
    "m365_profile": "E3",
    "description": "Sign-in frequency defines the time period before a user is asked to sign in again when\nattempting to access a resource. The Microsoft Entra ID default configuration for user\nsign-in frequency is a rolling window of 90 days.\nThe recommended state is a Sign-in frequency of Every time for Microsoft\nIntune Enrollment\nNote: Microsoft accounts for a five-minute clock skew when 'every time' is selected in a\nconditional access policy, ensuring that users are not prompted more frequently than\nonce every five minutes.",
    "rationale": "Intune Enrollment is considered a sensitive action and should be safeguarded. An\nattack path exists that allows for a bypass of device compliance Conditional Access\nrule. This could allow compromised credentials to be used through a newly registered\ndevice enrolled in Intune, enabling persistence and privilege escalation.\nSetting sign-in frequency to every time limits the timespan an attacker could use fresh\ncredentials to enroll a new device to Intune.",
    "impact": "New users enrolling into Intune through an automated process may need to sign-in\nagain if the enrollment process goes on for too long.",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Ensure that a policy exists with the following criteria and is set to On:\no Under Users verify All users is included.\no Ensure that only documented user exclusions exist and that they are\nreviewed annually.\no Under Target resources verify Resources (formerly cloud apps)\nincludes Microsoft Intune Enrollment.\no Under Grant verify Require multifactor authentication or Require\nauthentication strength is checked.\no Under Session verify Sign-in frequency is set to Every time.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "expected_response": "3. Ensure that a policy exists with the following criteria and is set to On:\no Ensure that only documented user exclusions exist and that they are\no Under Session verify Sign-in frequency is set to Every time.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Create a new policy by selecting New policy.\no Under Users include All users.\no Under Target resources select Resources (formerly cloud apps),\nchoose Select resources and add Microsoft Intune Enrollment to\nthe list.\no Under Grant select Grant access.\no Check either Require multifactor authentication or Require\nauthentication strength.\no Under Session check Sign-in frequency and select Every time.\n4. Under Enable policy set it to Report-only until the organization is ready to\nenable it.\n5. Click Create.\nNote: If the Microsoft Intune Enrollment cloud app isn't available then it must be\ncreated. To add the app for new tenants, a Microsoft Entra administrator must create a\nservice principal object, with app ID d4ebce55-015a-49b5-a083-c84d1797ae8c, in\nPowerShell or Microsoft Graph.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "default_value": "Sign-in frequency defaults to 90 days.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-",
      "session-lifetime#require-reauthentication-every-time",
      "2. https://www.blackhat.com/eu-24/briefings/schedule/#unveiling-the-power-of-",
      "intune-leveraging-intune-for-breaking-into-your-cloud-and-on-premise-42176",
      "3. https://www.glueckkanja.com/blog/security/2025/01/compliant-device-bypass-en/"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 269,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.2.12",
    "title": "Ensure the device code sign-in flow is blocked",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Require MFA for Externally-Exposed Applications",
    "m365_profile": "E3",
    "description": "The Microsoft identity platform supports the device authorization grant, which allows\nusers to sign in to input-constrained devices such as a smart TV, IoT device, or a\nprinter. To enable this flow, the device has the user visit a webpage in a browser on\nanother device to sign in. Once the user signs in, the device is able to get access\ntokens and refresh tokens as needed.\nThe recommended state is to Block access for Device code flow in Conditional\nAccess.",
    "rationale": "Since August 2024, Microsoft has observed threat actors, such as Storm-2372,\nemploying \"device code phishing\" attacks. These attacks deceive users into logging into\nproductivity applications, capturing authentication tokens to gain further access to\ncompromised accounts.\nTo mitigate this specific attack, block authentication code flows and permit only those\nfrom devices within trusted environments, identified by specific IP addresses.",
    "impact": "Some administrative overhead will be required for stricter management of these\ndevices. Since exclusions do not violate compliance, this feature can still be utilized\neffectively within a controlled environment.",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Ensure that a policy exists with the following criteria and is set to On:\no Under Users verify All users is included.\no Ensure that only documented user exclusions exist and that they are\nreviewed annually.\no Under Target resources verify Resources (formerly cloud apps)\nincludes All resources (formerly 'All cloud apps')\no Under Conditions > Authentication flows verify Configure is set to\nYes and Device code flow is checked.\no Under Grant verify Block access is selected.\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "expected_response": "3. Ensure that a policy exists with the following criteria and is set to On:\no Ensure that only documented user exclusions exist and that they are\no Under Conditions > Authentication flows verify Configure is set to\n4. Ensure Enable policy is set to On.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click expand ID Protection > Risk-based Conditional Access.\n3. Create a new policy by selecting New policy.\no Under Users include All users.\no Under Target resources > Resources (formerly cloud apps)\ninclude All resources (formerly 'All cloud apps').\no Under Conditions > Authentication flows set Configure is set to\nYes, select Device code flow and click Save.\no Under Grant select Block access and click Select.\n4. Under Enable policy set it to Report-only until the organization is ready to\nenable it.\n5. Click Create.\nNote: Break-glass accounts should be excluded from all Conditional Access policies.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code",
      "2. https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-",
      "authentication-flows",
      "3. https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-",
      "device-code-phishing-campaign/",
      "4. https://securing365.com/secure-your-device-code-auth-flows-now/",
      "5. https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-",
      "authentication-flows#device-code-flow-policies"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 272,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.3.1",
    "title": "Ensure Microsoft Authenticator is configured to protect against MFA fatigue",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Use Standard Hardening Configuration Templates for",
    "m365_profile": "E3",
    "description": "Microsoft provides supporting settings to enhance the configuration of the Microsoft\nAuthenticator application. These settings provide users with additional information and\ncontext when they receive MFA passwordless and push requests, including the\ngeographic location of the request, the requesting application, and a requirement for\nnumber matching.\nEnsure the following are Enabled.\n• Require number matching for push notifications\n• Show application name in push and passwordless notifications\n• Show geographic location in push and passwordless notifications\nNOTE: On February 27, 2023 Microsoft started enforcing number matching tenant-wide\nfor all users using Microsoft Authenticator.",
    "rationale": "As the use of strong authentication has become more widespread, attackers have\nstarted to exploit the tendency of users to experience \"MFA fatigue.\" This occurs when\nusers are repeatedly asked to provide additional forms of identification, leading them to\neventually approve requests without fully verifying the source. To counteract this,\nnumber matching can be employed to ensure the security of the authentication process.\nWith this method, users are prompted to confirm a number displayed on their original\ndevice and enter it into the device being used for MFA. Additionally, other information\nsuch as geolocation and application details are displayed to enhance the end user's\nawareness. Among these 3 options, number matching provides the strongest net\nsecurity gain.",
    "impact": "Additional interaction will be required by end users using number matching as opposed\nto simply pressing \"Approve\" for login attempts.",
    "audit": "To audit using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click to expand Entra ID > Authentication methods select Policies.\n3. Under Method select Microsoft Authenticator.\n4. Under Enable and Target verify the setting is set to Enable.\n5. In the Include tab ensure All users is selected.\n6. In the Exclude tab ensure only valid groups are present (i.e. Break Glass\naccounts).\n7. Select Configure\n8. Verify the following Microsoft Authenticator settings:\no Require number matching for push notifications Status is set to\nEnabled, Target All users\no Show application name in push and passwordless notifications\nis set to Enabled, Target All users\no Show geographic location in push and passwordless\nnotifications is set to Enabled, Target All users\n9. In each setting select Exclude and verify only groups are present (i.e. Break\nGlass accounts).",
    "expected_response": "4. Under Enable and Target verify the setting is set to Enable.\n5. In the Include tab ensure All users is selected.\n6. In the Exclude tab ensure only valid groups are present (i.e. Break Glass\no Require number matching for push notifications Status is set to\nis set to Enabled, Target All users\nnotifications is set to Enabled, Target All users",
    "remediation": "To remediate using the UI:\n1. Navigate to the Microsoft Entra admin center https://entra.microsoft.com.\n2. Click to expand Entra ID > Authentication methods select Policies.\n3. Select Microsoft Authenticator\n4. Under Enable and Target ensure the setting is set to Enable.\n5. Select Configure\n6. Set the following Microsoft Authenticator settings:\no Require number matching for push notifications Status is set to\nEnabled, Target All users\no Show application name in push and passwordless notifications\nis set to Enabled, Target All users\no Show geographic location in push and passwordless\nnotifications is set to Enabled, Target All users\nNote: Valid groups such as break glass accounts can be excluded per organization\npolicy.",
    "default_value": "Microsoft-managed",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-",
      "authentication-default-enablement",
      "2. https://techcommunity.microsoft.com/t5/microsoft-entra-blog/defend-your-users-",
      "from-mfa-fatigue-attacks/ba-p/2365677",
      "3. https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-",
      "number-match"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 276,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.3.2",
    "title": "Ensure custom banned passwords lists are used",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Use Standard Hardening Configuration Templates for",
    "m365_profile": "E3",
    "description": "With Entra Password Protection, default global banned password lists are automatically\napplied to all users in an Entra ID tenant. To support business and security needs,\ncustom banned password lists can be defined. When users change or reset their\npasswords, these banned password lists are checked to enforce the use of strong\npasswords.\nA custom banned password list should include some of the following examples:\n• Brand names\n• Product names\n• Locations, such as company headquarters\n• Company-specific internal terms\n• Abbreviations that have specific company meaning",
    "rationale": "Creating a new password can be difficult regardless of one's technical background. It is\ncommon to look around one's environment for suggestions when building a password,\nhowever, this may include picking words specific to the organization as inspiration for a\npassword. An adversary may employ what is called a 'mangler' to create permutations\nof these specific words in an attempt to crack passwords or hashes making it easier to\nreach their goal.",
    "impact": "If a custom banned password list includes too many common dictionary words, or short\nwords that are part of compound words, then perfectly secure passwords may be\nblocked. The organization should consider a balance between security and usability\nwhen creating a list.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/\n2. Click to expand Entra ID > Authentication methods.\n3. Select Password protection\n4. Verify Enforce custom list is set to Yes\n5. Verify Custom banned password list contains entries specific to the\norganization or matches a pre-determined list.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Directory.Read.All\"\n2. Run the following commands:\n$PwRuleSettings = '5cf42378-d67d-4f36-ba46-e8b86229381d'\nGet-MgGroupSetting | Where-Object TemplateId -eq $PwRuleSettings |\nSelect-Object -ExpandProperty Values\n3. Ensure EnableBannedPasswordCheck is True and BannedPasswordList is\npopulated with banned passwords.",
    "expected_response": "4. Verify Enforce custom list is set to Yes\n3. Ensure EnableBannedPasswordCheck is True and BannedPasswordList is",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/\n2. Click to expand Entra ID > Authentication methods.\n3. Select Password protection\n4. Set Enforce custom list to Yes\n5. In Custom banned password list create a list using suggestions outlined in\nthis document.\n6. Click Save\nNote: Below is a list of examples that can be used as a starting place. The references\nsection contains more suggestions.\n• Brand names\n• Product names\n• Locations, such as company headquarters\n• Company-specific internal terms\n• Abbreviations that have specific company meaning",
    "detection_commands": [
      "$PwRuleSettings = '5cf42378-d67d-4f36-ba46-e8b86229381d' Get-MgGroupSetting | Where-Object TemplateId -eq $PwRuleSettings | Select-Object -ExpandProperty Values"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-",
      "ban-bad#custom-banned-password-list",
      "2. https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-configure-",
      "custom-password-protection"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 279,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.2.3.3",
    "title": "Ensure password protection is enabled for on-prem Active Directory",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Use Unique Passwords",
    "m365_profile": "E3",
    "description": "Microsoft Entra Password Protection provides a global and custom banned password\nlist. A password change request fails if there's a match in these banned password list.\nTo protect on-premises Active Directory Domain Services (AD DS) environment, install\nand configure Entra Password Protection.\nNote: This recommendation applies to Hybrid deployments only and will have no impact\nunless working with on-premises Active Directory.",
    "rationale": "This feature protects an organization by prohibiting the use of weak or leaked\npasswords. In addition, organizations can create custom banned password lists to\nprevent their users from using easily guessed passwords that are specific to their\nindustry. Deploying this feature to Active Directory will strengthen the passwords that\nare used in the environment.",
    "impact": "The potential impact associated with implementation of this setting is dependent upon\nthe existing password policies in place in the environment. For environments that have\nstrong password policies in place, the impact will be minimal. For organizations that do\nnot have strong password policies in place, implementation of Microsoft Entra Password\nProtection may require users to change passwords and adhere to more stringent\nrequirements than they have been accustomed to.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Authentication methods.\n3. Select Password protection and ensure that Enable password protection\non Windows Server Active Directory is set to Yes and that Mode is set to\nEnforced.\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Directory.Read.All\"\n2. Run the following command:\n(Get-MgGroupSetting | ? { $_.TemplateId -eq '5cf42378-d67d-4f36-ba46-\ne8b86229381d' }).Values\n3. Ensure that EnableBannedPasswordCheckOnPremises is set to True and\nBannedPasswordCheckOnPremisesMode is set to Enforce.",
    "expected_response": "3. Select Password protection and ensure that Enable password protection\non Windows Server Active Directory is set to Yes and that Mode is set to\n3. Ensure that EnableBannedPasswordCheckOnPremises is set to True and\nBannedPasswordCheckOnPremisesMode is set to Enforce.",
    "remediation": "To remediate using the UI:\n• Download and install the Azure AD Password Proxies and DC Agents from\nthe following location:\nhttps://www.microsoft.com/download/details.aspx?id=57071 After installed follow\nthe steps below.\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Protection select Authentication methods.\n3. Select Password protection and set Enable password protection on\nWindows Server Active Directory to Yes and Mode to Enforced.",
    "default_value": "Enable - Yes\nMode - Audit",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-",
      "ban-bad-on-premises-operations"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 282,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.3.4",
    "title": "Ensure all member users are 'MFA capable'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Use Unique Passwords",
    "m365_profile": "E3",
    "description": "Microsoft defines Multifactor authentication capable as being registered and enabled for\na strong authentication method. The method must also be allowed by the authentication\nmethods policy.\nEnsure all member users are MFA capable.",
    "rationale": "Multifactor authentication requires an individual to present a minimum of two separate\nforms of authentication before access is granted.\nUsers who are not MFA Capable have never registered a strong authentication method\nfor multifactor authentication that is within policy and may not be using MFA. This could\nbe a result of having never signed in, exclusion from a Conditional Access (CA) policy\nrequiring MFA, or a CA policy does not exist. Reviewing this list of users will help\nidentify possible lapses in policy or procedure.",
    "impact": "When using the UI audit method guest users will appear in the report and unless the\norganization is applying MFA rules to guests then they will need to be manually filtered.\nAccounts that provide on-premises directory synchronization also appear in these\nreports.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Authentication methods.\n3. Select User registration details.\n4. Set the filter option Multifactor authentication capable to Not Capable.\n5. Review the non-guest users in this list.\n6. Excluding any exceptions users found in this report may require remediation.\nTo audit using PowerShell:\n1. Connect to Graph using Connect-MgGraph -Scopes\n\"UserAuthenticationMethod.Read.All,AuditLog.Read.All\"\n2. Run the following:\nGet-MgReportAuthenticationMethodUserRegistrationDetail `\n-Filter \"IsMfaCapable eq false and UserType eq 'Member'\" |\nft UserPrincipalName,IsMfaCapable,IsAdmin\n3. Ensure IsMfaCapable is set to True.\n4. Excluding any exceptions users found in this report may require remediation.\nNote: The CA rule must be in place for a successful deployment of Multifactor\nAuthentication. This policy is outlined in the conditional access section 5.2.2\nNote 2: Possible exceptions include on-premises synchronization accounts.",
    "expected_response": "3. Ensure IsMfaCapable is set to True.\nNote: The CA rule must be in place for a successful deployment of Multifactor",
    "remediation": "Remediation steps will depend on the status of the personnel in question or\nconfiguration of Conditional Access policies and will not be covered in detail.\nAdministrators should review each user identified on a case-by-case basis using the\nconditions below.\nUser has never signed on:\n• Employment status should be reviewed, and appropriate action taken on the user\naccount's roles, licensing and enablement.\nConditional Access policy applicability:\n• Ensure a CA policy is in place requiring all users to use MFA.\n• Ensure the user is not excluded from the CA MFA policy.\n• Ensure the policy's state is set to On.\n• Use What if to determine applicable CA policies. (Protection > Conditional\nAccess > Policies)\n• Review the user account in Sign-in logs. Under the Activity Details pane\nclick the Conditional Access tab to view applied policies.\nNote: Conditional Access is covered step by step in section 5.2.2",
    "detection_commands": [
      "Get-MgReportAuthenticationMethodUserRegistrationDetail `"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-",
      "us/powershell/module/microsoft.graph.reports/update-",
      "mgreportauthenticationmethoduserregistrationdetail?view=graph-powershell-",
      "1.0#-ismfacapable",
      "2. https://learn.microsoft.com/en-us/entra/identity/monitoring-health/how-to-view-",
      "applied-conditional-access-policies",
      "3. https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool",
      "4. https://learn.microsoft.com/en-us/entra/identity/authentication/howto-",
      "authentication-methods-activity"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 285,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.2.3.5",
    "title": "Ensure weak authentication methods are disabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Require Multi-factor Authentication",
    "m365_profile": "E3",
    "description": "Authentication methods support a wide variety of scenarios for signing in to Microsoft\n365 resources. Some of these methods are inherently more secure than others but\nrequire more investment in time to get users enrolled and operational.\nSMS and Voice Call rely on telephony carrier communication methods to deliver the\nauthenticating factor.\nThe recommended state is to Disable these methods:\n• SMS\n• Voice Call",
    "rationale": "Traditional MFA methods such as SMS codes, email-based OTPs, and push\nnotifications are becoming less effective against today’s attackers. Sophisticated\nphishing campaigns have demonstrated that second factors can be intercepted or\nspoofed. Attackers now exploit social engineering, man-in-the-middle tactics, and user\nfatigue (e.g., MFA bombing) to bypass these mechanisms. These risks are amplified in\ndistributed, cloud-first organizations with hybrid workforces and varied device\necosystems.\nThe SMS and Voice call methods are vulnerable to SIM swapping which could allow an\nattacker to gain access to your Microsoft 365 account.",
    "impact": "There may be increased administrative overhead in adopting more secure\nauthentication methods depending on the maturity of the organization.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Authentication methods.\n3. Select Policies.\n4. Verify that the following methods in the Enabled column are set to No.\no Method: SMS\no Method: Voice call\nTo audit using Powershell:\n1. Connect to Graph using Connect-MgGraph -Scopes \"Policy.Read.All\"\n2. Run the following:\n(Get-MgPolicyAuthenticationMethodPolicy).AuthenticationMethodConfigurations\n3. Ensure Sms and Voice are disabled.",
    "expected_response": "4. Verify that the following methods in the Enabled column are set to No.\n3. Ensure Sms and Voice are disabled.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Authentication methods.\n3. Select Policies.\n4. Inspect each method that is out of compliance and remediate:\no Click on the method to open it.\no Change the Enable toggle to the off position.\no Click Save.\nNote: If the save button remains greyed out after toggling a method off, then first turn it\nback on and then change the position of the Target selection (all users or select\ngroups). Turn the method off again and save. This was observed to be a bug in the UI\nat the time this document was published.\nTo remediate using Powershell:\n1. Connect to Graph using Connect-MgGraph -Scopes\n\"Policy.ReadWrite.AuthenticationMethod\"\n2. Run the following to disable all three authentication methods:\n$params = @(\n@{ Id = \"Sms\"; State = \"disabled\" },\n@{ Id = \"Voice\"; State = \"disabled\" }\n)\nUpdate-MgPolicyAuthenticationMethodPolicy -AuthenticationMethodConfigurations\n$params",
    "default_value": "• SMS : Disabled\n• Voice Call : Disabled",
    "detection_commands": [],
    "remediation_commands": [
      "$params = @(",
      "Update-MgPolicyAuthenticationMethodPolicy -AuthenticationMethodConfigurations $params"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-",
      "authentication-methods-manage",
      "2. https://learn.microsoft.com/en-us/security/zero-trust/sfi/phishing-resistant-",
      "mfa#context-and-problem",
      "3. https://www.microsoft.com/en-us/microsoft-365-life-hacks/privacy-and-",
      "safety/what-is-sim-swapping"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 289,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.3.6",
    "title": "Ensure system-preferred multifactor authentication is enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "resources_some_of_these_methods_are_inherently_more_secure_than_others_but",
    "domain": "resources. Some of these methods are inherently more secure than others but",
    "subdomain": "Require MFA for Externally-Exposed Applications",
    "m365_profile": "E3",
    "description": "System-preferred multifactor authentication (MFA) prompts users to sign in by using the\nmost secure method they registered.\nThe user is prompted to sign-in with the most secure method according to the below\norder. The order of authentication methods is dynamic. It's updated by Microsoft as the\nsecurity landscape changes, and as better authentication methods emerge.\n1. Temporary Access Pass\n2. Passkey (FIDO2)\n3. Microsoft Authenticator notifications\n4. External authentication methods\n5. Time-based one-time password (TOTP)\n6. Telephony\n7. Certificate-based authentication\nThe recommended state is Enabled.",
    "rationale": "Regardless of the authentication method enabled by an administrator or set as\npreferred by the user, the system will dynamically select the most secure option\navailable at the time of authentication. This approach acts as an additional safeguard to\nprevent the use of weaker methods, such as voice calls, SMS, and email OTPs, which\nmay have been inadvertently left enabled due to misconfiguration or lack of\nconfiguration hardening.\nEnforcing the default behavior also ensures the feature is not disabled.",
    "impact": "The Microsoft managed value of system-preferred MFA is Enabled and as such\nenforces the default behavior. No additional impact is expected.\nNote: Due to known issues with certificate-based authentication (CBA) and system-\npreferred MFA, Microsoft moved CBA to the bottom of the list. It is still considered a\nstrong authentication method.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Authentication methods.\n3. Select Settings.\n4. Verify the System-preferred multifactor authentication State is set to\nEnabled and All users are included.\n5. Ensure that only documented exclusions exist and that they are reviewed\nannually\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scopes\n\"Policy.Read.AuthenticationMethod\"\n2. Run the following commands:\n$Uri =\n'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy'\n(Invoke-MgGraphRequest -Method GET -Uri $Uri).systemCredentialPreferences\n3. Ensure that includeTargets is set to all_users and state is set to enabled.",
    "expected_response": "4. Verify the System-preferred multifactor authentication State is set to\n5. Ensure that only documented exclusions exist and that they are reviewed\n3. Ensure that includeTargets is set to all_users and state is set to enabled.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Authentication methods.\n3. Select Settings.\n4. Set the System-preferred multifactor authentication State to Enabled and\ninclude All users.\n5. Any users exclusions should be documented and reviewed annually.",
    "default_value": "Microsoft Managed (Enabled)",
    "detection_commands": [
      "$Uri = 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy'"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-system-",
      "preferred-multifactor-authentication",
      "2. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-system-",
      "preferred-multifactor-authentication#how-does-system-preferred-mfa-determine-",
      "the-most-secure-method"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 292,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.3.7",
    "title": "Ensure the email OTP authentication method is disabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "resources_some_of_these_methods_are_inherently_more_secure_than_others_but",
    "domain": "resources. Some of these methods are inherently more secure than others but",
    "subdomain": "Require MFA for Externally-Exposed Applications",
    "m365_profile": "E3",
    "description": "Authentication methods support a wide variety of scenarios for signing in to Microsoft\n365 resources. Some of these methods are inherently more secure than others but\nrequire more investment in time to get users enrolled and operational.\nThe email one-time passcode feature is a way to authenticate B2B collaboration users\nwhen they can't be authenticated through other means, such as Microsoft Entra ID,\nMicrosoft account (MSA), or social identity providers. When a B2B guest user tries to\nredeem your invitation or sign in to your shared resources, they can request a\ntemporary passcode, which is sent to their email address. Then they enter this\npasscode to continue signing in.\nThe recommended state is to Disable email OTP.",
    "rationale": "Traditional MFA methods such as SMS codes, email-based OTPs, and push\nnotifications are becoming less effective against today’s attackers. Sophisticated\nphishing campaigns have demonstrated that second factors can be intercepted or\nspoofed. Attackers now exploit social engineering, man-in-the-middle tactics, and user\nfatigue (e.g., MFA bombing) to bypass these mechanisms. These risks are amplified in\ndistributed, cloud-first organizations with hybrid workforces and varied device\necosystems.",
    "impact": "Disabling Email OTP will prevent one-time pass codes from being sent to unverified\nguest users accessing Microsoft 365 resources on the tenant such as \"@yahoo.com\".\nThey will be required to use a personal Microsoft account, a managed Microsoft Entra\naccount, be part of a federation or be configured as a guest in the host tenant's\nMicrosoft Entra ID.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Authentication methods.\n3. Select Policies.\n4. Verify that Email OTP is set to No in the Enabled column.\nTo audit using Powershell:\n1. Connect to Graph using Connect-MgGraph -Scopes \"Policy.Read.All\"\n2. Run the following:\n(Get-MgPolicyAuthenticationMethodPolicy).AuthenticationMethodConfigurations\n3. Ensure the id type Email is set to disabled.",
    "expected_response": "4. Verify that Email OTP is set to No in the Enabled column.\n3. Ensure the id type Email is set to disabled.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Authentication methods.\n3. Select Policies.\n4. Click on Email OTP.\n5. Change the Enable toggle to the off position\\\n6. Click Save.\nNote: If the save button remains greyed out after toggling a method off, then first turn it\nback on and then change the position of the Target selection (all users or select\ngroups). Turn the method off again and save. This was observed to be a bug in the UI\nat the time this document was published.\nTo remediate using Powershell:\n1. Connect to Graph using Connect-MgGraph -Scopes\n\"Policy.ReadWrite.AuthenticationMethod\"\n2. Run the following:\n$params = @(\n@{ Id = \"Email\"; State = \"disabled\" }\n)\nUpdate-MgPolicyAuthenticationMethodPolicy -AuthenticationMethodConfigurations\n$params",
    "default_value": "• Email OTP : Enabled",
    "detection_commands": [],
    "remediation_commands": [
      "$params = @(",
      "Update-MgPolicyAuthenticationMethodPolicy -AuthenticationMethodConfigurations $params"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-",
      "authentication-methods-manage",
      "2. https://learn.microsoft.com/en-us/entra/external-id/one-time-passcode",
      "3. https://learn.microsoft.com/en-us/security/zero-trust/sfi/phishing-resistant-",
      "mfa#context-and-problem"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 295,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.2.4.1",
    "title": "Ensure 'Self service password reset enabled' is set to 'All'",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "resources_some_of_these_methods_are_inherently_more_secure_than_others_but",
    "domain": "resources. Some of these methods are inherently more secure than others but",
    "subdomain": "Require MFA for Externally-Exposed Applications",
    "m365_profile": "E3",
    "description": "Enabling self-service password reset allows users to reset their own passwords in Entra\nID. When users sign in to Microsoft 365, they will be prompted to enter additional\ncontact information that will help them reset their password in the future. If combined\nregistration is enabled additional information, outside of multi-factor, will not be needed.\nNote: Effective Oct. 1st, 2022, Microsoft will begin to enable combined registration for\nall users in Entra ID tenants created before August 15th, 2020. Tenants created after\nthis date are enabled with combined registration by default.",
    "rationale": "Enabling Self-Service Password Reset (SSPR) significantly reduces helpdesk\ninteractions, streamlining support operations and improving user experience. Traditional\nmethods involving temporary passwords pose notable security risks—they are often\nweak, predictable, and susceptible to interception. This creates a window of opportunity\nfor threat actors to compromise accounts before users can update their credentials.\nSSPR minimizes credential exposure and strengthens overall identity protection.",
    "impact": "Users will be required to provide additional contact information to enroll in self-service\npassword reset. Additionally, minor user education may be required for users that are\nused to calling a help desk for assistance with password resets.\nNote: This is unavailable if using Entra Connect / Sync in a hybrid environment.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Password reset select Properties.\n3. Ensure Self service password reset enabled is set to All",
    "expected_response": "3. Ensure Self service password reset enabled is set to All",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Entra ID > Password reset select Properties.\n3. Set Self service password reset enabled to All",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/let-users-reset-",
      "passwords?view=o365-worldwide",
      "2. https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr",
      "3. https://learn.microsoft.com/en-us/entra/identity/authentication/howto-registration-",
      "mfa-sspr-combined"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 299,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "5.3.1",
    "title": "Ensure 'Privileged Identity Management' is used to manage roles",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "resources_some_of_these_methods_are_inherently_more_secure_than_others_but",
    "domain": "resources. Some of these methods are inherently more secure than others but",
    "subdomain": "ID Governance",
    "m365_profile": "E5",
    "description": "Microsoft Entra Privileged Identity Management can be used to audit roles, allow just in\ntime activation of roles and allow for periodic role attestation. Organizations should\nremove permanent members from privileged Office 365 roles and instead make them\neligible, through a JIT activation workflow.",
    "rationale": "Organizations want to minimize the number of people who have access to secure\ninformation or resources, because that reduces the chance of a malicious actor getting\nthat access, or an authorized user inadvertently impacting a sensitive resource.\nHowever, users still need to carry out privileged operations in Entra ID. Organizations\ncan give users just-in-time (JIT) privileged access to roles. There is a need for oversight\nfor what those users are doing with their administrator privileges. PIM helps to mitigate\nthe risk of excessive, unnecessary, or misused access rights.",
    "impact": "The implementation of Just in Time privileged access is likely to necessitate changes to\nadministrator routine. Administrators will only be granted access to administrative roles\nwhen required. When administrators request role activation, they will need to document\nthe reason for requiring role access, anticipated time required to have the access, and\nto reauthenticate to enable role access.\nNote: If all global admins become eligible then there will be no global admin to receive\nnotifications, by default. Alerts are sent to TenantAdmins, including Global\nAdministrators, by default. To ensure proper receipt, configure alerts to be sent to\nsecurity or operations staff with valid email addresses or a security operations center.\nOtherwise, after adoption of this recommendation, alerts sent to TenantAdmins may go\nunreceived due to the lack of a licensed permanently active Global Administrator.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Identity Governance select Privileged Identity\nManagement.\n3. Under Manage select Microsoft Entra Roles.\n4. Under Manage select Roles.\n5. Inspect at a minimum the following sensitive roles to ensure the members are\nEligible and not Permanent:\n• Application Administrator\n• Authentication Administrator\n• Azure Information Protection Administrator\n• Billing Administrator\n• Cloud Application Administrator\n• Cloud Device Administrator\n• Compliance Administrator\n• Customer LockBox Access Approver\n• Exchange Administrator\n• Fabric Administrator\n• Global Administrator\n• HelpDesk Administrator\n• Intune Administrator\n• Kaizala Administrator\n• License Administrator\n• Microsoft Entra Joined Device Local Administrator\n• Password Administrator\n• Privileged Authentication Administrator\n• Privileged Role Administrator\n• Security Administrator\n• SharePoint Administrator\n• Skype for Business Administrator\n• Teams Administrator\n• User Administrator",
    "expected_response": "5. Inspect at a minimum the following sensitive roles to ensure the members are",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Identity Governance select Privileged Identity\nManagement.\n3. Under Manage select Microsoft Entra Roles.\n4. Under Manage select Roles.\n5. Inspect at a minimum the following sensitive roles. For each of the members that\nhave an ASSIGNMENT TYPE of Permanent, click on the ... and choose Make\neligible:\n• Application Administrator\n• Authentication Administrator\n• Azure Information Protection Administrator\n• Billing Administrator\n• Cloud Application Administrator\n• Cloud Device Administrator\n• Compliance Administrator\n• Customer LockBox Access Approver\n• Exchange Administrator\n• Fabric Administrator\n• Global Administrator\n• HelpDesk Administrator\n• Intune Administrator\n• Kaizala Administrator\n• License Administrator\n• Microsoft Entra Joined Device Local Administrator\n• Password Administrator\n• Privileged Authentication Administrator\n• Privileged Role Administrator\n• Security Administrator\n• SharePoint Administrator\n• Skype for Business Administrator\n• Teams Administrator\n• User Administrator",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-",
      "management/pim-configure"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 302,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.3.2",
    "title": "Ensure 'Access reviews' for Guest Users are configured",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "resources_some_of_these_methods_are_inherently_more_secure_than_others_but",
    "domain": "resources. Some of these methods are inherently more secure than others but",
    "subdomain": "Maintain Inventory of Administrative Accounts",
    "m365_profile": "E5",
    "description": "Access reviews enable administrators to establish an efficient automated process for\nreviewing group memberships, access to enterprise applications, and role assignments.\nThese reviews can be scheduled to recur regularly, with flexible options for delegating\nthe task of reviewing membership to different members of the organization.\nEnsure Access reviews for Guest Users are configured to be performed no less\nfrequently than monthly.",
    "rationale": "Access to groups and applications for guests can change over time. If a guest user's\naccess to a particular folder goes unnoticed, they may unintentionally gain access to\nsensitive data if a member adds new files or data to the folder or application. Access\nreviews can help reduce the risks associated with outdated assignments by requiring a\nmember of the organization to conduct the reviews. Furthermore, these reviews can\nenable a fail-closed mechanism to remove access to the subject if the reviewer does not\nrespond to the review.",
    "impact": "Access reviews that are ignored may cause guest users to lose access to resources\ntemporarily.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/\n2. Click to expand Identity Governance and select Access reviews\n3. Inspect the access reviews, and ensure an access review is created with the\nfollowing criteria:\no Overview: Scope is set to Guest users only and status is Active\no Reviewers: Ensure appropriate reviewer(s) are designated.\no Settings > General: Mail notifications and Reminders are set to\nEnable\no Reviewers: Require reason on approval is set to Enable\no Scheduling: Frequency is Monthly or more frequent.\no When completed: Auto apply results to resource is set to Enable\no When completed: If reviewers don't respond is set to Remove\naccess\nTo audit using PowerShell:\n1. Connect to Microsoft Graph using Connect-MgGraph -Scope\nAccessReview.Read.All\n2. Run the following script to output a list of Access Reviews that target only Guest\nUsers.\n$Uri =\n'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definition\ns'\n$Response = (Invoke-MgGraphRequest -Uri $Uri -Method Get).Value\n$GuestReviews = $Response |\nWhere-Object { $_.scope.query -match \"userType eq 'Guest'\" -or\n$_.scope.principalscopes.query -match \"userType eq 'Guest'\" }\n$AccessReviewReport = foreach ($review in $GuestReviews) {\n$value = $review.settings\n$RecurrenceType = $value.recurrence.pattern.type\n$RecurrencePass = $RecurrenceType -eq 'absoluteMonthly' -or\n$RecurrenceType -eq 'weekly'\n$IsCISCompliant = $review.status -eq 'InProgress' -and\n$value.mailNotificationsEnabled -eq $true -and\n$value.reminderNotificationsEnabled -eq $true -and\n$value.justificationRequiredOnApproval -eq $true -and\n$RecurrencePass -and\n$value.autoApplyDecisionsEnabled -eq $true -and\n$value.defaultDecision -eq 'Deny'\n[PSCustomObject]@{\nName                            = $review.DisplayName\nStatus                          = $review.Status\nmailNotificationsEnabled        = $value.mailNotificationsEnabled\nReminders                       = $value.reminderNotificationsEnabled\njustificationRequiredOnApproval =\n$value.justificationRequiredOnApproval\nFrequency                       = $RecurrenceType\nautoApplyDecisionsEnabled       = $value.autoApplyDecisionsEnabled\ndefaultDecision                 = $value.defaultDecision\nIsCISCompliant                  = $IsCISCompliant\n}\n}\n$AccessReviewReport\n3. Review the output, if nothing returns then the audit fails.\n4. Only one access review that satisfies all required parameters is necessary to\nachieve compliance. A passing review must meet the below properties with their\ncorresponding values. A Frequency of weekly is also considered a passing\nstate.\nName                            : < Access review name >\nStatus                          : InProgress\nmailNotificationsEnabled        : True\nReminders                       : True\njustificationRequiredOnApproval : True\nFrequency                       : absoluteMonthly\nautoApplyDecisionsEnabled       : True\ndefaultDecision                 : Deny\nIsCISCompliant                  : True",
    "expected_response": "3. Inspect the access reviews, and ensure an access review is created with the\no Overview: Scope is set to Guest users only and status is Active\no Reviewers: Ensure appropriate reviewer(s) are designated.\no Settings > General: Mail notifications and Reminders are set to\no Reviewers: Require reason on approval is set to Enable\no When completed: Auto apply results to resource is set to Enable\no When completed: If reviewers don't respond is set to Remove\n2. Run the following script to output a list of Access Reviews that target only Guest\n3. Review the output, if nothing returns then the audit fails.\nachieve compliance. A passing review must meet the below properties with their",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/\n2. Click to expand Identity Governance and select Access reviews\n3. Click New access review.\n4. Select what to review choose Teams + Groups.\n5. Review Scope set to All Microsoft 365 groups with guest users, do not\nexclude groups.\n6. Scope set to Guest users only then click Next: Reviews.\n7. Select reviewers an appropriate user that is NOT the guest user themselves.\n8. Duration (in days) at most 3.\n9. Review recurrence is Monthly or more frequent.\n10. End is set to Never, then click Next: Settings.\n11. Check Auto apply results to resource.\n12. Set If reviewers don't respond to Remove access.\n13. Check the following: Justification required, E-mail notifications,\nReminders.\n14. Click Next: Review + Create and finally click Create.",
    "default_value": "By default access reviews are not configured.",
    "detection_commands": [
      "$Uri = 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definition",
      "$Response = (Invoke-MgGraphRequest -Uri $Uri -Method Get).Value $GuestReviews = $Response |",
      "$_.scope.principalscopes.query -match \"userType eq 'Guest'\" } $AccessReviewReport = foreach ($review in $GuestReviews) { $value = $review.settings $RecurrenceType = $value.recurrence.pattern.type $RecurrencePass = $RecurrenceType -eq 'absoluteMonthly' -or $RecurrenceType -eq 'weekly' $IsCISCompliant = $review.status -eq 'InProgress' -and $value.mailNotificationsEnabled -eq $true -and $value.reminderNotificationsEnabled -eq $true -and $value.justificationRequiredOnApproval -eq $true -and $RecurrencePass -and $value.autoApplyDecisionsEnabled -eq $true -and $value.defaultDecision -eq 'Deny'",
      "$value.justificationRequiredOnApproval",
      "$AccessReviewReport"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview",
      "2. https://learn.microsoft.com/en-us/entra/id-governance/create-access-review"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 306,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.3.3",
    "title": "Ensure 'Access reviews' for privileged roles are configured",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "resources_some_of_these_methods_are_inherently_more_secure_than_others_but",
    "domain": "resources. Some of these methods are inherently more secure than others but",
    "subdomain": "Disable Dormant Accounts",
    "m365_profile": "E5",
    "description": "Access reviews enable administrators to establish an efficient automated process for\nreviewing group memberships, access to enterprise applications, and role assignments.\nThese reviews can be scheduled to recur regularly, with flexible options for delegating\nthe task of reviewing membership to different members of the organization.\nEnsure Access reviews for high privileged Entra ID roles are done monthly or more\nfrequently. These reviews should include at a minimum the roles listed below:\n• Global Administrator\n• Exchange Administrator\n• SharePoint Administrator\n• Teams Administrator\n• Security Administrator\nNote: An access review is created for each role selected after completing the process.",
    "rationale": "Regular review of critical high privileged roles in Entra ID will help identify role drift, or\npotential malicious activity. This will enable the practice and application of \"separation of\nduties\" where even non-privileged users like security auditors can be assigned to review\nassigned roles in an organization. Furthermore, if configured these reviews can enable\na fail-closed mechanism to remove access to the subject if the reviewer does not\nrespond to the review.",
    "impact": "In order to avoid disruption reviewers who have the authority to revoke roles should be\ntrusted individuals who understand the significance of access reviews. Additionally, the\nprinciple of separation of duties should be applied to ensure that no administrator is\nresponsible for reviewing their own access levels. This will cause additional\nadministrative overhead.\nIf the reviews are configured to automatically revoke highly privileged roles like the\nGlobal Administrator role, then this could result in removing all Global Administrators\nfrom the organization. Care should be taken when configuring this setting especially in\nthe case of break-glass accounts which would be included by association.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/\n2. Click to expand Identity Governance and select Privileged Identity\nManagement\n3. Select Microsoft Entra Roles under Manage\n4. Select Access reviews\n5. Ensure there are access reviews configured for each high privileged roles and\neach meets the criteria laid out below:\no Scope - Everyone\no Status - Active\no Reviewers - Role reviewers should be designated personnel. Preferably\nnot a self-review.\no Mail notifications - Enable\no Reminders - Enable\no Require reason on approval - Enable\no Frequency - Monthly or more frequently.\no Duration (in days) - 14 at most\no Auto apply results to resource - Enable\no If reviewers don't respond - No change\nAny remaining settings are discretionary.",
    "expected_response": "5. Ensure there are access reviews configured for each high privileged roles and\no Reviewers - Role reviewers should be designated personnel. Preferably",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/\n2. Click to expand Identity Governance and select Privileged Identity\nManagement\n3. Select Microsoft Entra Roles under Manage\n4. Select Access reviews and click New access review.\no Provide a name and description.\no Set Frequency to Monthly or more frequently.\no Set Duration (in days) to at most 14.\no Set End to Never.\no Set Users scope to All users and groups.\no In Role select these roles: Global Administrator,Exchange\nAdministrator,SharePoint Administrator,Teams\nAdministrator,Security Administrator\no Set Assignment type to All active and eligible assignments.\no Set Reviewers member(s) responsible for this type of review, other than\nself.\n5. Upon completion settings:\no Set Auto apply results to resource to Enable.\no Set If reviewers don't respond to No change.\n6. Advanced settings:\no Set Show recommendations to Enable\no Set Require reason on approval to Enable\no Set Mail notifications to Enable\no Set Reminders to Enable\n7. Click Start to save the review.\nWarning: Care should be taken when configuring the If reviewers don't respond\nsetting for Global Administrator reviews, if misconfigured break-glass accounts could\nautomatically have roles revoked. Additionally, reviewers should be educated on the\npurpose of break-glass accounts to prevent accidental manual removal of roles.",
    "default_value": "By default access reviews are not configured.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-",
      "management/pim-create-roles-and-resource-roles-review",
      "2. https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 311,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "5.3.4",
    "title": "Ensure approval is required for Global Administrator role activation",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "resources_some_of_these_methods_are_inherently_more_secure_than_others_but",
    "domain": "resources. Some of these methods are inherently more secure than others but",
    "subdomain": "Disable Dormant Accounts",
    "m365_profile": "E5",
    "description": "Microsoft Entra Privileged Identity Management can be used to audit roles, allow just in\ntime activation of roles and allow for periodic role attestation. Requiring approval before\nactivation allows one of the selected approvers to first review and then approve the\nactivation prior to PIM granted the role. The approver doesn't have to be a group\nmember or owner.\nThe recommended state is Require approval to activate for the Global\nAdministrator role.",
    "rationale": "Requiring approval for Global Administrator role activation enhances visibility and\naccountability every time this highly privileged role is used. This process reduces the\nrisk of an attacker elevating a compromised account to the highest privilege level, as\nany activation must first be reviewed and approved by a trusted party.\nNote: This only acts as protection for eligible users that are activating a role. Directly\nassigning a role does require an approval workflow so therefore it is important to\nimplement and use PIM correctly.",
    "impact": "Approvers do not need to be assigned the same role or be members of the same group.\nIt's important to have at least two approvers and an emergency access (break-glass)\naccount to prevent a scenario where no Global Administrators are available. For\nexample, if the last active Global Administrator leaves the organization, and only eligible\nbut inactive Global Administrators remain, a trusted approver without the Global\nAdministrator role or an emergency access account would be essential to avoid delays\nin critical administrative tasks.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Identity Governance select Privileged Identity\nManagement.\n3. Under Manage select Microsoft Entra Roles.\n4. Under Manage select Roles.\n5. Select Global Administrator in the list.\n6. Select Role settings..\n7. Verify Require approval to activate is set to Yes.\n8. Verify there are at least two approvers in the list.",
    "expected_response": "7. Verify Require approval to activate is set to Yes.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Identity Governance select Privileged Identity\nManagement.\n3. Under Manage select Microsoft Entra Roles.\n4. Under Manage select Roles.\n5. Select Global Administrator in the list.\n6. Select Role settings and click Edit.\n7. Check the Require approval to activate box.\n8. Add at least two approvers.\n9. Click Update.",
    "default_value": "Require approval to activate : No.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-",
      "management/pim-configure",
      "2. https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-",
      "management/groups-role-settings#require-approval-to-activate"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 315,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.3.5",
    "title": "Ensure approval is required for Privileged Role Administrator activation",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "resources_some_of_these_methods_are_inherently_more_secure_than_others_but",
    "domain": "resources. Some of these methods are inherently more secure than others but",
    "subdomain": "Maintain Inventory of Administrative Accounts",
    "m365_profile": "E5",
    "description": "Microsoft Entra Privileged Identity Management can be used to audit roles, allow just in\ntime activation of roles and allow for periodic role attestation. Requiring approval before\nactivation allows one of the selected approvers to first review and then approve the\nactivation prior to PIM granted the role. The approver doesn't have to be a group\nmember or owner.\nThe recommended state is Require approval to activate for the Privileged\nRole Administrator role.",
    "rationale": "This role grants the ability to manage assignments for all Microsoft Entra roles including\nthe Global Administrator role. This role does not include any other privileged abilities in\nMicrosoft Entra ID like creating or updating users. However, users assigned to this role\ncan grant themselves or others additional privilege by assigning additional roles.\nRequiring approval for activation enhances visibility and accountability every time this\nhighly privileged role is used. This process reduces the risk of an attacker elevating a\ncompromised account to the highest privilege level, as any activation must first be\nreviewed and approved by a trusted party.\nNote: This only acts as protection for eligible users that are activating a role. Directly\nassigning a role does require an approval workflow so therefore it is important to\nimplement and use PIM correctly.",
    "impact": "Requiring approvers for automatic role assignment can slightly increase administrative\noverhead and add delays to tasks.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Identity Governance select Privileged Identity\nManagement.\n3. Under Manage select Microsoft Entra Roles.\n4. Under Manage select Roles.\n5. Select Privileged Role Administrator in the list.\n6. Select Role settings.\n7. Verify Require approval to activate is set to Yes.\n8. Verify there are at least two approvers in the list.",
    "expected_response": "7. Verify Require approval to activate is set to Yes.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Entra admin center https://entra.microsoft.com/.\n2. Click to expand Identity Governance select Privileged Identity\nManagement.\n3. Under Manage select Microsoft Entra Roles.\n4. Under Manage select Roles.\n5. Select Privileged Role Administrator in the list.\n6. Select Role settings and click Edit.\n7. Check the Require approval to activate box.\n8. Add at least two approvers.\n9. Click Update.",
    "default_value": "Require approval to activate : No.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-",
      "management/pim-configure",
      "2. https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-",
      "management/groups-role-settings#require-approval-to-activate"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 318,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.1",
    "title": "Ensure 'AuditDisabled' organizationally is set to 'False'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "exchange",
    "domain": "Exchange admin center",
    "subdomain": "Audit",
    "m365_profile": "E3",
    "description": "The value False indicates that mailbox auditing on by default is turned on for the\norganization. Mailbox auditing on by default in the organization overrides the mailbox\nauditing settings on individual mailboxes. For example, if mailbox auditing is turned off\nfor a mailbox (the AuditEnabled property on the mailbox is False), the default mailbox\nactions are still audited for the mailbox, because mailbox auditing on by default is turned\non for the organization.\nTurning off mailbox auditing on by default ($true) has the following results:\n• Mailbox auditing is turned off for your organization.\n• From the time you turn off mailbox auditing on by default, no mailbox actions are\naudited, even if mailbox auditing is enabled on a mailbox (the AuditEnabled\nproperty on the mailbox is True).\n• Mailbox auditing isn't turned on for new mailboxes and setting the AuditEnabled\nproperty on a new or existing mailbox to True is ignored.\n• Any mailbox audit bypass association settings (configured by using the Set-\nMailboxAuditBypassAssociation cmdlet) are ignored.\n• Existing mailbox audit records are retained until the audit log age limit for the\nrecord expires.\nThe recommended state for this setting is False at the organization level. This will\nenable auditing and enforce the default.",
    "rationale": "Enforcing the default ensures auditing was not turned off intentionally or accidentally.\nAuditing mailbox actions will allow forensics and IR teams to trace various malicious\nactivities that can generate TTPs caused by inbox access and tampering.\nNote: Without advanced auditing (E5 function) the logs are limited to 90 days.",
    "impact": "None - this is the default behavior as of 2019.",
    "audit": "To audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-OrganizationConfig | Format-List AuditDisabled\n3. Ensure AuditDisabled is set to False.",
    "expected_response": "3. Ensure AuditDisabled is set to False.",
    "remediation": "To remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-OrganizationConfig -AuditDisabled $false",
    "default_value": "False",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/purview/audit-mailboxes?view=o365-worldwide",
      "2. https://learn.microsoft.com/en-us/powershell/module/exchange/set-",
      "organizationconfig?view=exchange-ps#-auditdisabled"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 323,
    "dspm_relevant": true,
    "dspm_categories": [
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.2",
    "title": "Ensure mailbox audit actions are configured",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "exchange",
    "domain": "Exchange admin center",
    "subdomain": "Activate audit logging",
    "m365_profile": "E3",
    "description": "Mailbox audit logging is turned on by default in all organizations. This effort started in\nJanuary 2019, and means that certain actions performed by mailbox owners, delegates,\nand admins are automatically logged. The corresponding mailbox audit records are\navailable for admins to search in the mailbox audit log.\nMailboxes and shared mailboxes have actions assigned to them individually in order to\naudit the data the organization determines valuable at the mailbox level.\nThe recommended state per mailbox is AuditEnabled to True including all default audit\nactions with additional actions outlined below in the audit and remediation sections.\nNote: Audit (Standard) licensing allows for up to 180 days log retention as of October\n2023.",
    "rationale": "Whether it is for regulatory compliance or for tracking unauthorized configuration\nchanges in Microsoft 365, enabling mailbox auditing and ensuring the proper mailbox\nactions are accounted for allows for Microsoft 365 teams to run security operations,\nforensics or general investigations on mailbox activities.\nThe following mailbox types ignore the organizational default and must have\nAuditEnabled set to True at the mailbox level in order to capture relevant audit data.\n• Resource Mailboxes\n• Public Folder Mailboxes\n• DiscoverySearch Mailbox",
    "impact": "Adding additional audit action types and increasing the AuditLogAgeLimit from 90 to\n180 days will have a limited impact on mailbox storage. Mailbox audit log records are\nstored in a subfolder (named Audits) in the Recoverable Items folder in each user's\nmailbox.\n• Mailbox audit records count against the storage quota of the Recoverable Items\nfolder.\n• Mailbox audit records also count against the folder limit for the Recoverable\nItems folder. A maximum of 3 million items (audit records) can be stored in the\nAudits subfolder.\nThe following cmdlet in Exchange Online PowerShell can be run to display the size and\nnumber of items in the Audits subfolder in the Recoverable Items folder:\nGet-MailboxFolderStatistics -Identity <MailboxIdentity> -FolderScope\nRecoverableItems |\nWhere-Object {$_.Name -eq 'Audits'} | Format-List\nFolderPath,FolderSize,ItemsInFolder\nNote: It's unlikely that mailbox auditing on by default impacts the storage quota or the\nfolder limit for the Recoverable Items folder.",
    "audit": "Inspect each UserMailbox and ensure AuditEnabled is True and the following audit\nactions are included in addition to default actions of each sign-in type.\n• Admin actions: Copy, FolderBind and Move.\n• Delegate actions: FolderBind and Move.\n• Owner actions: Create, MailboxLogin and Move.\nNote: The defaults can be found in the Default Value section and the combined total\ncan be found in the scripts of the Audit/Remediation sections.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell script:\n$AdminActions = @(\n\"ApplyRecord\", \"Copy\", \"Create\", \"FolderBind\", \"HardDelete\",\n\"MailItemsAccessed\", \"Move\", \"MoveToDeletedItems\", \"SendAs\",\n\"SendOnBehalf\", \"Send\", \"SoftDelete\", \"Update\",\n\"UpdateCalendarDelegation\",\n\"UpdateFolderPermissions\", \"UpdateInboxRules\"\n)\n$DelegateActions = @(\n\"ApplyRecord\", \"Create\", \"FolderBind\", \"HardDelete\", \"Move\",\n\"MailItemsAccessed\", \"MoveToDeletedItems\", \"SendAs\", \"SendOnBehalf\",\n\"SoftDelete\", \"Update\", \"UpdateFolderPermissions\", \"UpdateInboxRules\"\n)\n$OwnerActions = @(\n\"ApplyRecord\", \"Create\", \"HardDelete\", \"MailboxLogin\", \"Move\",\n\"MailItemsAccessed\", \"MoveToDeletedItems\", \"Send\", \"SoftDelete\",\n\"Update\",\n\"UpdateCalendarDelegation\", \"UpdateFolderPermissions\", \"UpdateInboxRules\"\n)\nfunction VerifyActions {\nparam (\n[array]$ExpectedActions,\n[array]$ActualActions\n)\n$Missing = $ExpectedActions | Where-Object { $_ -notin $ActualActions }\nreturn $Missing\n}\n$Mailboxes = Get-EXOMailbox -PropertySets Audit, Minimum -ResultSize\nUnlimited |\nWhere-Object { $_.RecipientTypeDetails -eq \"UserMailbox\" }\n$Results = foreach ($mailbox in $Mailboxes) {\n$AdminMissing = VerifyActions -ExpectedActions $AdminActions -\nActualActions $mailbox.AuditAdmin\n$DelegateMissing = VerifyActions -ExpectedActions $DelegateActions -\nActualActions $mailbox.AuditDelegate\n$OwnerMissing = VerifyActions -ExpectedActions $OwnerActions -\nActualActions $mailbox.AuditOwner\n$IsCompliant = $AdminMissing.Count -eq 0 -and\n$DelegateMissing.Count -eq 0 -and\n$OwnerMissing.Count -eq 0 -and\n$mailbox.AuditEnabled\n[PSCustomObject]@{\nMailbox         = $mailbox.UserPrincipalName\nAuditEnabled    = $mailbox.AuditEnabled\nAdminMissing    = if ($AdminMissing.Count -gt 0) { $AdminMissing -\njoin \", \" } else { \"None\" }\nDelegateMissing = if ($DelegateMissing.Count -gt 0) {\n$DelegateMissing -join \", \" } else { \"None\" }\nOwnerMissing    = if ($OwnerMissing.Count -gt 0) { $OwnerMissing -\njoin \", \" } else { \"None\" }\nComplianceState = if ($IsCompliant) { \"Compliant\" } else { \"Non-\nCompliant\" }\n}\n}\n# Display results in table format\n$Results | Format-Table -AutoSize\n<# Optional: Export methods\n$Results | Out-GridView -Title \"Mailbox Audit Results\"\n$Results | Export-Csv -Path \"6.1.2.csv\" -NoTypeInformation\n$Results | ConvertTo-Json | Out-File -FilePath \"6.1.2.json\"\n#>\n3. Inspect the results. Mailboxes will be labeled as either Compliant or Non-\ncompliant, accompanied by supporting details that outline the missing actions\nfor each type and the current state of AuditEnabled. Optional methods for\nexporting the data to CSV, JSON, or GridView are also shown at the end of the\nscript.\nNote: Mailboxes with Audit (Premium) licenses, which is included with E5, can retain\naudit logs beyond 180 days.",
    "expected_response": "Inspect each UserMailbox and ensure AuditEnabled is True and the following audit\nreturn $Missing",
    "remediation": "For each UserMailbox ensure AuditEnabled is True and the following audit actions\nare included in addition to default actions of each sign-in type.\n• Admin actions: Copy, FolderBind and Move.\n• Delegate actions: FolderBind and Move.\n• Owner actions: Create, MailboxLogin and Move.\nNote: The defaults can be found in the Default Value section and the combined total\ncan be found in the scripts of the Audit/Remediation sections.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell script to remediate every 'UserMailbox' in the\norganization:\n$AuditAdmin = @(\n\"ApplyRecord\", \"Copy\", \"Create\", \"FolderBind\", \"HardDelete\",\n\"MailItemsAccessed\", \"Move\", \"MoveToDeletedItems\", \"SendAs\",\n\"SendOnBehalf\", \"Send\", \"SoftDelete\", \"Update\",\n\"UpdateCalendarDelegation\",\n\"UpdateFolderPermissions\", \"UpdateInboxRules\"\n)\n$AuditDelegate = @(\n\"ApplyRecord\", \"Create\", \"FolderBind\", \"HardDelete\", \"Move\",\n\"MailItemsAccessed\", \"MoveToDeletedItems\", \"SendAs\", \"SendOnBehalf\",\n\"SoftDelete\", \"Update\", \"UpdateFolderPermissions\", \"UpdateInboxRules\"\n)\n$AuditOwner = @(\n\"ApplyRecord\", \"Create\", \"HardDelete\", \"MailboxLogin\", \"Move\",\n\"MailItemsAccessed\", \"MoveToDeletedItems\", \"Send\", \"SoftDelete\",\n\"Update\",\n\"UpdateCalendarDelegation\", \"UpdateFolderPermissions\", \"UpdateInboxRules\"\n)\n$MBX = Get-EXOMailbox -ResultSize Unlimited | Where-Object {\n$_.RecipientTypeDetails -eq \"UserMailbox\" }\n$MBX | Set-Mailbox -AuditEnabled $true `\n-AuditLogAgeLimit 180 -AuditAdmin $AuditAdmin -AuditDelegate $AuditDelegate `\n-AuditOwner $AuditOwner\n3. The script will apply the prescribed Audit Actions for each sign-in type (Owner,\nDelegate, Admin) and the AuditLogAgeLimit to each UserMailbox in the\norganization.\nNote: Mailboxes with Audit (Premium) licenses, which is included with E5, can retain\naudit logs beyond 180 days.",
    "default_value": "AuditEnabled: True for all mailboxes except below:\n• Resource Mailboxes\n• Public Folder Mailboxes\n• DiscoverySearch Mailbox\nAuditAdmin: ApplyRecord, Create, HardDelete, MailItemsAccessed,\nMoveToDeletedItems, Send, SendAs, SendOnBehalf, SoftDelete, Update,\nUpdateCalendarDelegation, UpdateFolderPermissions, UpdateInboxRules\nAuditDelegate: ApplyRecord, Create, HardDelete, MailItemsAccessed,\nMoveToDeletedItems, SendAs, SendOnBehalf, SoftDelete, Update,\nUpdateFolderPermissions, UpdateInboxRules\nAuditOwner: ApplyRecord, HardDelete, MailItemsAccessed, MoveToDeletedItems,\nSend, SoftDelete, Update, UpdateCalendarDelegation, UpdateFolderPermissions,\nUpdateInboxRules",
    "detection_commands": [
      "$AdminActions = @( \"ApplyRecord\", \"Copy\", \"Create\", \"FolderBind\", \"HardDelete\", \"MailItemsAccessed\", \"Move\", \"MoveToDeletedItems\", \"SendAs\", \"SendOnBehalf\", \"Send\", \"SoftDelete\", \"Update\", \"UpdateCalendarDelegation\", \"UpdateFolderPermissions\", \"UpdateInboxRules\"",
      "$DelegateActions = @( \"ApplyRecord\", \"Create\", \"FolderBind\", \"HardDelete\", \"Move\", \"MailItemsAccessed\", \"MoveToDeletedItems\", \"SendAs\", \"SendOnBehalf\", \"SoftDelete\", \"Update\", \"UpdateFolderPermissions\", \"UpdateInboxRules\"",
      "$OwnerActions = @( \"ApplyRecord\", \"Create\", \"HardDelete\", \"MailboxLogin\", \"Move\", \"MailItemsAccessed\", \"MoveToDeletedItems\", \"Send\", \"SoftDelete\", \"Update\", \"UpdateCalendarDelegation\", \"UpdateFolderPermissions\", \"UpdateInboxRules\"",
      "$Missing = $ExpectedActions | Where-Object { $_ -notin $ActualActions }",
      "$Mailboxes = Get-EXOMailbox -PropertySets Audit, Minimum -ResultSize",
      "$Results = foreach ($mailbox in $Mailboxes) { $AdminMissing = VerifyActions -ExpectedActions $AdminActions -",
      "$DelegateMissing = VerifyActions -ExpectedActions $DelegateActions -",
      "$OwnerMissing = VerifyActions -ExpectedActions $OwnerActions -",
      "$IsCompliant = $AdminMissing.Count -eq 0 -and $DelegateMissing.Count -eq 0 -and $OwnerMissing.Count -eq 0 -and $mailbox.AuditEnabled",
      "$DelegateMissing -join \", \" } else { \"None\" }",
      "$Results | Format-Table -AutoSize",
      "$Results | Out-GridView -Title \"Mailbox Audit Results\" $Results | Export-Csv -Path \"6.1.2.csv\" -NoTypeInformation $Results | ConvertTo-Json | Out-File -FilePath \"6.1.2.json\""
    ],
    "remediation_commands": [
      "$AuditAdmin = @( \"ApplyRecord\", \"Copy\", \"Create\", \"FolderBind\", \"HardDelete\", \"MailItemsAccessed\", \"Move\", \"MoveToDeletedItems\", \"SendAs\", \"SendOnBehalf\", \"Send\", \"SoftDelete\", \"Update\", \"UpdateCalendarDelegation\", \"UpdateFolderPermissions\", \"UpdateInboxRules\"",
      "$AuditDelegate = @( \"ApplyRecord\", \"Create\", \"FolderBind\", \"HardDelete\", \"Move\", \"MailItemsAccessed\", \"MoveToDeletedItems\", \"SendAs\", \"SendOnBehalf\", \"SoftDelete\", \"Update\", \"UpdateFolderPermissions\", \"UpdateInboxRules\"",
      "$AuditOwner = @( \"ApplyRecord\", \"Create\", \"HardDelete\", \"MailboxLogin\", \"Move\", \"MailItemsAccessed\", \"MoveToDeletedItems\", \"Send\", \"SoftDelete\", \"Update\", \"UpdateCalendarDelegation\", \"UpdateFolderPermissions\", \"UpdateInboxRules\"",
      "$MBX = Get-EXOMailbox -ResultSize Unlimited | Where-Object { $_.RecipientTypeDetails -eq \"UserMailbox\" } $MBX | Set-Mailbox -AuditEnabled $true `"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/purview/audit-mailboxes?view=o365-worldwide"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 325,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "retention",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D3",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1.3",
    "title": "Ensure 'AuditBypassEnabled' is not enabled on mailboxes",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "general",
    "domain": "General",
    "subdomain": "Activate audit logging",
    "m365_profile": "E3",
    "description": "When configuring a user or computer account to bypass mailbox audit logging, the\nsystem will not record any access, or actions performed by the said user or computer\naccount on any mailbox. Administratively this was introduced to reduce the volume of\nentries in the mailbox audit logs on trusted user or computer accounts.\nEnsure AuditBypassEnabled is not enabled on accounts without a written exception.",
    "rationale": "If a mailbox audit bypass association is added for an account, the account can access\nany mailbox in the organization to which it has been assigned access permissions,\nwithout generating any mailbox audit logging entries for such access or recording any\nactions taken, such as message deletions.\nEnabling this parameter, whether intentionally or unintentionally, could allow insiders or\nmalicious actors to conceal their activity on specific mailboxes. Ensuring proper logging\nof user actions and mailbox operations in the audit log will enable comprehensive\nincident response and forensics.",
    "impact": "None - this is the default behavior.",
    "audit": "To audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\n$MBXData = Get-MailboxAuditBypassAssociation -ResultSize unlimited\n$Report = $MBXData | ? {$_.AuditBypassEnabled -eq $true} |\nselect Name,AuditBypassEnabled\n$Report\n<# Optional: Export methods\n$Report | Out-GridView -Title \"Mailbox Audit Bypass Association\"\n$Report | Export-Csv -Path \"6.1.3.csv\" -NoTypeInformation\n#>\n3. If nothing is returned, then there are no accounts with Audit Bypass enabled.\nNote: The cmdlet Get-MailboxAuditBypassAssociation may display a WARNING\non system objects that begin with \"Asc-2X1\", this is not part of the Audit procedure and\ncan be ignored.",
    "remediation": "To remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. The following example PowerShell script will disable AuditBypass for all\nmailboxes which currently have it enabled:\n# Get mailboxes with AuditBypassEnabled set to $true\n$MBXAudit = Get-MailboxAuditBypassAssociation -ResultSize unlimited | Where-\nObject { $_.AuditBypassEnabled -eq $true }\nforeach ($mailbox in $MBXAudit) {\n$mailboxName = $mailbox.Name\nSet-MailboxAuditBypassAssociation -Identity $mailboxName -\nAuditBypassEnabled $false\nWrite-Host \"Audit Bypass disabled for mailbox Identity: $mailboxName\" -\nForegroundColor Green\n}",
    "default_value": "AuditBypassEnabled False",
    "detection_commands": [
      "$MBXData = Get-MailboxAuditBypassAssociation -ResultSize unlimited $Report = $MBXData | ? {$_.AuditBypassEnabled -eq $true} | select Name,AuditBypassEnabled $Report",
      "$Report | Out-GridView -Title \"Mailbox Audit Bypass Association\" $Report | Export-Csv -Path \"6.1.3.csv\" -NoTypeInformation"
    ],
    "remediation_commands": [
      "$MBXAudit = Get-MailboxAuditBypassAssociation -ResultSize unlimited | Where-",
      "$mailboxName = $mailbox.Name"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/powershell/module/exchange/get-",
      "mailboxauditbypassassociation?view=exchange-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 332,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.2.1",
    "title": "Ensure all forms of mail forwarding are blocked and/or disabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "general",
    "domain": "General",
    "subdomain": "Mail flow",
    "m365_profile": "E3",
    "description": "Exchange Online offers several methods of managing the flow of email messages.\nThese are Remote domain, Transport Rules, and Anti-spam outbound policies. These\nmethods work together to provide comprehensive coverage for potential automatic\nforwarding channels:\n• Outlook forwarding using inbox rules.\n• Outlook forwarding configured using OOF rule.\n• OWA forwarding setting (ForwardingSmtpAddress).\n• Forwarding set by the admin using EAC (ForwardingAddress).\n• Forwarding using Power Automate / Flow.\nEnsure a Transport rule and Anti-spam outbound policy are used to block mail\nforwarding.\nNOTE: Any exclusions should be implemented based on organizational policy.",
    "rationale": "Attackers often create these rules to exfiltrate data from your tenancy, this could be\naccomplished via access to an end-user account or otherwise. An insider could also use\none of these methods as a secondary channel to exfiltrate sensitive data.",
    "impact": "Care should be taken before implementation to ensure there is no business need for\ncase-by-case auto-forwarding. Disabling auto-forwarding to remote domains will affect\nall users and in an organization. Any exclusions should be implemented based on\norganizational policy.",
    "audit": "Note: Audit is a two step procedure as follows:\nSTEP 1: Transport rules\nTo audit using the UI:\n1. Select Exchange to open the Exchange admin center.\n2. Select Mail Flow then Rules.\n3. Review the rules and verify that none of them are forwards or redirects e-mail to\nexternal domains.\nTo audit using PowerShell:\n1. Connect to Exchange online using Connect-ExchangeOnline.\n2. Run the following PowerShell command to review the Transport Rules that are\nredirecting email:\nGet-TransportRule | Where-Object {$_.RedirectMessageTo -ne $null} | ft\nName,RedirectMessageTo\n3. Verify that none of the addresses listed belong to external domains outside of the\norganization. If nothing returns then there are no transport rules set to redirect\nmessages.\nSTEP 2: Anti-spam outbound policy\nTo audit using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com/\n2. Expand E-mail & collaboration then select Policies & rules.\n3. Select Threat policies > Anti-spam.\n4. Inspect Anti-spam outbound policy (default) and ensure Automatic\nforwarding is set to Off - Forwarding is disabled\n5. Inspect any additional custom outbound policies and ensure Automatic\nforwarding is set to Off - Forwarding is disabled, in accordance with the\norganization's exclusion policies.\nTo audit using PowerShell:\n1. Connect to Exchange online using Connect-ExchangeOnline.\n2. Run the following PowerShell cmdlet:\nGet-HostedOutboundSpamFilterPolicy | ft Name, AutoForwardingMode\n3. In each outbound policy verify AutoForwardingMode is Off.\nNote: According to Microsoft if a recipient is defined in multiple policies of the same\ntype (anti-spam, anti-phishing, etc.), only the policy with the highest priority is applied to\nthe recipient. Any remaining policies of that type are not evaluated for the recipient\n(including the default policy). However, it is our recommendation to audit the default\npolicy as well in the case a higher priority custom policy is removed. This will keep the\norganization's security posture strong.",
    "expected_response": "organization. If nothing returns then there are no transport rules set to redirect\n4. Inspect Anti-spam outbound policy (default) and ensure Automatic\nforwarding is set to Off - Forwarding is disabled\n5. Inspect any additional custom outbound policies and ensure Automatic\nforwarding is set to Off - Forwarding is disabled, in accordance with the",
    "remediation": "Note: Remediation is a two step procedure as follows:\nSTEP 1: Transport rules\nTo remediate using the UI:\n1. Select Exchange to open the Exchange admin center.\n2. Select Mail Flow then Rules.\n3. For each rule that redirects email to external domains, select the rule and click\nthe 'Delete' icon.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nRemove-TransportRule {RuleName}\nSTEP 2: Anti-spam outbound policy\nTo remediate using the UI:\n1. Navigate to Microsoft 365 Defender https://security.microsoft.com/\n2. Expand E-mail & collaboration then select Policies & rules.\n3. Select Threat policies > Anti-spam.\n4. Select Anti-spam outbound policy (default)\n5. Click Edit protection settings\n6. Set Automatic forwarding rules dropdown to Off - Forwarding is\ndisabled and click Save\n7. Repeat steps 4-6 for any additional higher priority, custom policies.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-HostedOutboundSpamFilterPolicy -Identity {policyName} -AutoForwardingMode\nOff\n3. To remove AutoForwarding from all outbound policies you can also run:\nGet-HostedOutboundSpamFilterPolicy | Set-HostedOutboundSpamFilterPolicy -\nAutoForwardingMode Off",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-",
      "rules/mail-flow-rules",
      "2. https://techcommunity.microsoft.com/t5/exchange-team-blog/all-you-need-to-",
      "know-about-automatic-email-forwarding-in/ba-",
      "p/2074888#:~:text=%20%20%20Automatic%20forwarding%20option%20%20,%",
      "3. https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-",
      "external-email-forwarding?view=o365-worldwide"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 336,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.2.2",
    "title": "Ensure mail transport rules do not whitelist specific domains",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "general",
    "domain": "General",
    "subdomain": "Mail flow",
    "m365_profile": "E3",
    "description": "Mail flow rules (transport rules) in Exchange Online are used to identify and take action\non messages that flow through the organization.",
    "rationale": "Whitelisting domains in transport rules bypasses regular malware and phishing\nscanning, which can enable an attacker to launch attacks against your users from a\nsafe haven domain.\nNote: If an organization identifies a business need for an exception, the domain should\nonly be whitelisted if inbound emails from that domain originate from a specific IP\naddress. These exceptions should be documented and regularly reviewed.",
    "impact": "Care should be taken before implementation to ensure there is no business need for\ncase-by-case whitelisting. Removing all whitelisted domains could affect incoming mail\nflow to an organization although modern systems sending legitimate mail should have\nno issue with this.",
    "audit": "To audit using the UI:\n1. Navigate to Exchange admin center https://admin.exchange.microsoft.com..\n2. Click to expand Mail Flow and then select Rules.\n3. Review each rule and ensure that a single rule does not contain both of these\nproperties together:\no Under Apply this rule if: Sender's address domain portion belongs\nto any of these domains: '<domain>'\no Under Do the following: Set the spam confidence level (SCL) to\n'-1'\nNote: Setting the spam confidence level to -1 indicates the message is from a trusted\nsender, so the message bypasses spam filtering. The recommendation fails if any\nexternal domain has a SCL of -1.\nTo audit using PowerShell:\n1. Connect to Exchange online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-TransportRule | Where-Object { $_.setscl -eq -1 -and $_.SenderDomainIs -\nne $null }  | ft Name,SenderDomainIs,SetSCL\n3. Transport rules that fail the audit will be shown. If no output is shown, the\nrecommendation passes. To pass, all rules with SetSCL set to -1 must not\ninclude any domains in the SenderDomainIs property.",
    "expected_response": "3. Review each rule and ensure that a single rule does not contain both of these\n3. Transport rules that fail the audit will be shown. If no output is shown, the\nrecommendation passes. To pass, all rules with SetSCL set to -1 must not",
    "remediation": "To remediate using the UI:\n1. Navigate to Exchange admin center https://admin.exchange.microsoft.com..\n2. Click to expand Mail Flow and then select Rules.\n3. For each rule that sets the spam confidence level to -1 for a specific domain,\nselect the rule and click Delete.\nTo remediate using PowerShell:\n1. Connect to Exchange online using Connect-ExchangeOnline.\n2. To modify the rule:\nRemove-TransportRule {RuleName}\n3. Verify the rules no longer exists by re-running the audit procedure.",
    "detection_commands": [],
    "remediation_commands": [
      "select the rule and click Delete."
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-",
      "rules/configuration-best-practices",
      "2. https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-",
      "rules/mail-flow-rules"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 341,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "6.2.3",
    "title": "Ensure email from external senders is identified",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "general",
    "domain": "General",
    "subdomain": "Deploy and Maintain Email Server Anti-Malware",
    "m365_profile": "E3",
    "description": "External callouts provide a native experience to identify emails from senders outside the\norganization. This is achieved by presenting a new tag on emails called \"External\" (the\nstring is localized based on the client language setting) and exposing related user\ninterface at the top of the message reading view to see and verify the real sender's\nemail address.\nThe recommended state is ExternalInOutlook set to Enabled True",
    "rationale": "Tagging emails from external senders helps to inform end users about the origin of the\nemail. This can allow them to proceed with more caution and make informed decisions\nwhen it comes to identifying spam or phishing emails.\nMail flow rules are often used by Exchange administrators to accomplish the External\nemail tagging by appending a tag to the front of a subject line. There are limitations to\nthis outlined here. The preferred method in the CIS Benchmark is to use the native\nexperience.\nNote: Existing emails in a user's inbox from external senders are not tagged\nretroactively.",
    "impact": "Mail flow rules using external tagging must be disabled, along with third-party mail\nfiltering tools that offer similar features, to avoid duplicate [External] tags.\nExternal tags can consume additional screen space on systems with limited real estate,\nsuch as thin clients or mobile devices.\nAfter enabling this feature via PowerShell, it may take 24-48 hours for users to see the\nExternal sender tag in emails from outside your organization. Rolling back the feature\ntakes the same amount of time.\nNote: Third-party tools that provide similar functionality will also meet compliance\nrequirements, although Microsoft recommends using the native experience for better\ninteroperability.",
    "audit": "To audit using PowerShell:\n1. Connect to Exchange online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-ExternalInOutlook\n3. For each identity verify Enabled is set to True and the AllowList only contains\nemail addresses the organization has permitted to bypass external tagging.",
    "expected_response": "3. For each identity verify Enabled is set to True and the AllowList only contains",
    "remediation": "To remediate using PowerShell:\n1. Connect to Exchange online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-ExternalInOutlook -Enabled $true",
    "default_value": "Disabled (False)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://techcommunity.microsoft.com/t5/exchange-team-blog/native-external-",
      "sender-callouts-on-email-in-outlook/ba-p/2250098",
      "2. https://learn.microsoft.com/en-us/powershell/module/exchange/set-",
      "externalinoutlook?view=exchange-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 343,
    "dspm_relevant": true,
    "dspm_categories": [
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "6.3.1",
    "title": "Ensure users installing Outlook add-ins is not allowed",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "general",
    "domain": "General",
    "subdomain": "Roles",
    "m365_profile": "E3",
    "description": "Specify the administrators and users who can install and manage add-ins for Outlook in\nExchange Online\nBy default, users can install add-ins in their Microsoft Outlook Desktop client, allowing\ndata access within the client application.",
    "rationale": "Attackers exploit vulnerable or custom add-ins to access user data. Disabling user-\ninstalled add-ins in Microsoft Outlook reduces this threat surface.",
    "impact": "Implementing this change will impact both end users and administrators. End users will\nbe unable to integrate third-party applications they desire, and administrators may\nreceive requests to grant permission for necessary third-party apps.",
    "audit": "To audit using the UI:\n1. Navigate to Exchange admin center https://admin.exchange.microsoft.com.\n2. Click to expand Roles select User roles.\n3. Select Default Role Assignment Policy.\n4. In the properties pane on the right click on Manage permissions.\n5. Under Other roles verify My Custom Apps, My Marketplace Apps and My\nReadWriteMailbox Apps are unchecked.\nNote: As of this release of the Benchmark the manage permissions link no longer\ndisplays anything when a user assigned the Global Reader role clicks on it. Global\nReaders as an alternative can inspect the Roles column or use the PowerShell method\nto perform the audit.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following script:\n$RoleList = @(\n\"My Custom Apps\", \"My Marketplace Apps\", \"My ReadWriteMailbox Apps\"\n)\n$AssignedPolicies = Get-EXOMailbox -PropertySets Policy |\nSelect-Object -Unique RoleAssignmentPolicy\n$Report = foreach ($policy in $AssignedPolicies) {\n$RolePolicy = Get-RoleAssignmentPolicy -Identity `\n$policy.RoleAssignmentPolicy\n$NonCompliantRoles = $RolePolicy.AssignedRoles |\nWhere-Object { $RoleList -eq $_ }\n[pscustomobject]@{\nIdentity     = $RolePolicy.Identity\nFailingRoles = if ($NonCompliantRoles) {\n($NonCompliantRoles -join \", \")\n}\nelse { \"None\" }\n}\n}\n$Report\n3. The output will show a list of all assigned policies and along with any roles\nassigned to those policies that are not compliant.\no Verify My Custom Apps, My Marketplace Apps and My\nReadWriteMailbox Apps are not present in any policy (Identity)\ndisplayed.",
    "expected_response": "3. The output will show a list of all assigned policies and along with any roles",
    "remediation": "To remediate using the UI:\n1. Navigate to Exchange admin center https://admin.exchange.microsoft.com.\n2. Click to expand Roles select User roles.\n3. Select Default Role Assignment Policy.\n4. In the properties pane on the right click on Manage permissions.\n5. Under Other roles uncheck My Custom Apps, My Marketplace Apps and My\nReadWriteMailbox Apps.\n6. Click Save changes.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following command:\n$policy = \"Role Assignment Policy - Prevent Add-ins\"\n$roles = \"MyTextMessaging\", \"MyDistributionGroups\", `\n\"MyMailSubscriptions\", \"MyBaseOptions\", \"MyVoiceMail\", `\n\"MyProfileInformation\", \"MyContactInformation\",\n\"MyRetentionPolicies\", `\n\"MyDistributionGroupMembership\"\nNew-RoleAssignmentPolicy -Name $policy -Roles $roles\nSet-RoleAssignmentPolicy -id $policy -IsDefault\n# Assign new policy to all mailboxes\nGet-EXOMailbox -ResultSize Unlimited | Set-Mailbox -RoleAssignmentPolicy\n$policy\nIf you have other Role Assignment Policies modify the last line to filter out your\ncustom policies",
    "default_value": "UI - My Custom Apps, My Marketplace Apps, and My ReadWriteMailbox Apps are\nchecked\nPowerShell - My Custom Apps My Marketplace Apps and My ReadWriteMailbox\nApps are assigned",
    "detection_commands": [
      "$RoleList = @( \"My Custom Apps\", \"My Marketplace Apps\", \"My ReadWriteMailbox Apps\"",
      "$AssignedPolicies = Get-EXOMailbox -PropertySets Policy | Select-Object -Unique RoleAssignmentPolicy $Report = foreach ($policy in $AssignedPolicies) { $RolePolicy = Get-RoleAssignmentPolicy -Identity ` $policy.RoleAssignmentPolicy $NonCompliantRoles = $RolePolicy.AssignedRoles |",
      "$Report"
    ],
    "remediation_commands": [
      "$policy = \"Role Assignment Policy - Prevent Add-ins\" $roles = \"MyTextMessaging\", \"MyDistributionGroups\", ` \"MyMailSubscriptions\", \"MyBaseOptions\", \"MyVoiceMail\", ` \"MyProfileInformation\", \"MyContactInformation\", \"MyRetentionPolicies\", ` \"MyDistributionGroupMembership\"",
      "$policy"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-",
      "online/add-ins-for-outlook/specify-who-can-install-and-manage-add-",
      "ins?source=recommendations",
      "2. https://learn.microsoft.com/en-us/exchange/permissions-exo/role-assignment-",
      "policies"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 346,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "retention",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D3",
      "D6"
    ]
  },
  {
    "cis_id": "6.5.1",
    "title": "Ensure modern authentication for Exchange Online is enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "general",
    "domain": "General",
    "subdomain": "Settings",
    "m365_profile": "E3",
    "description": "Modern authentication in Microsoft 365 enables authentication features like multifactor\nauthentication (MFA) using smart cards, certificate-based authentication (CBA), and\nthird-party SAML identity providers. When you enable modern authentication in\nExchange Online, Outlook 2016 and Outlook 2013 use modern authentication to log in\nto Microsoft 365 mailboxes. When you disable modern authentication in Exchange\nOnline, Outlook 2016 and Outlook 2013 use basic authentication to log in to Microsoft\n365 mailboxes.\nWhen users initially configure certain email clients, like Outlook 2013 and Outlook 2016,\nthey may be required to authenticate using enhanced authentication mechanisms, such\nas multifactor authentication. Other Outlook clients that are available in Microsoft 365\n(for example, Outlook Mobile and Outlook for Mac 2016) always use modern\nauthentication to log in to Microsoft 365 mailboxes.",
    "rationale": "Strong authentication controls, such as the use of multifactor authentication, may be\ncircumvented if basic authentication is used by Exchange Online email clients such as\nOutlook 2016 and Outlook 2013. Enabling modern authentication for Exchange Online\nensures strong authentication mechanisms are used when establishing sessions\nbetween email clients and Exchange Online.",
    "impact": "Users of older email clients, such as Outlook 2013 and Outlook 2016, will no longer be\nable to authenticate to Exchange using Basic Authentication, which will necessitate\nmigration to modern authentication practices.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings select Org Settings.\n3. Select Modern authentication.\n4. Verify Turn on modern authentication for Outlook 2013 for Windows\nand later (recommended) is checked.\nTo audit using PowerShell:\n1. Run the Microsoft Exchange Online PowerShell Module.\n2. Connect to Exchange Online using Connect-ExchangeOnline.\n3. Run the following PowerShell command:\nGet-OrganizationConfig | Format-Table -Auto Name, OAuth*\n4. Verify OAuth2ClientProfileEnabled is True.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft 365 admin center https://admin.microsoft.com.\n2. Click to expand Settings select Org Settings.\n3. Select Modern authentication.\n4. Check Turn on modern authentication for Outlook 2013 for Windows\nand later (recommended) to enable modern authentication.\nTo remediate using PowerShell:\n1. Run the Microsoft Exchange Online PowerShell Module.\n2. Connect to Exchange Online using Connect-ExchangeOnline.\n3. Run the following PowerShell command:\nSet-OrganizationConfig -OAuth2ClientProfileEnabled $True",
    "default_value": "True",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-",
      "online/enable-or-disable-modern-authentication-in-exchange-online"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 352,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.5.2",
    "title": "Ensure MailTips are enabled for end users",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "mailboxes",
    "domain": "mailboxes",
    "subdomain": "Encrypt Transmittal of Username and",
    "m365_profile": "E3",
    "description": "MailTips are informative messages displayed to users while they're composing a\nmessage. While a new message is open and being composed, Exchange analyzes the\nmessage (including recipients). If a potential problem is detected, the user is notified\nwith a MailTip prior to sending the message. Using the information in the MailTip, the\nuser can adjust the message to avoid undesirable situations or non-delivery reports\n(also known as NDRs or bounce messages).",
    "rationale": "Setting up MailTips gives a visual aid to users when they send emails to large groups of\nrecipients or send emails to recipients not within the tenant.",
    "impact": "Not applicable.",
    "audit": "To audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-OrganizationConfig | fl MailTips*\n3. Verify the values for MailTipsAllTipsEnabled,\nMailTipsExternalRecipientsTipsEnabled, and\nMailTipsGroupMetricsEnabled are set to True and\nMailTipsLargeAudienceThreshold is set to an acceptable value; 25 is the\ndefault value.",
    "expected_response": "MailTipsGroupMetricsEnabled are set to True and\nMailTipsLargeAudienceThreshold is set to an acceptable value; 25 is the",
    "remediation": "To remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\n$TipsParams = @{\nMailTipsAllTipsEnabled                 = $true\nMailTipsExternalRecipientsTipsEnabled  = $true\nMailTipsGroupMetricsEnabled            = $true\nMailTipsLargeAudienceThreshold         = '25'\n}\nSet-OrganizationConfig @TipsParams",
    "default_value": "MailTipsAllTipsEnabled: True MailTipsExternalRecipientsTipsEnabled: False\nMailTipsGroupMetricsEnabled: True MailTipsLargeAudienceThreshold: 25",
    "detection_commands": [],
    "remediation_commands": [
      "$TipsParams = @{"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-",
      "online/mailtips/mailtips",
      "2. https://learn.microsoft.com/en-us/powershell/module/exchange/set-",
      "organizationconfig?view=exchange-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 355,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "6.5.3",
    "title": "Ensure additional storage providers are restricted in Outlook on the web",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "mailboxes",
    "domain": "mailboxes",
    "subdomain": "Encrypt Transmittal of Username and",
    "m365_profile": "E3",
    "description": "This setting allows users to open certain external files while working in Outlook on the\nweb. If allowed, keep in mind that Microsoft doesn't control the use terms or privacy\npolicies of those third-party services.\nEnsure AdditionalStorageProvidersAvailable is restricted on the default OWA\npolicy.",
    "rationale": "By default, additional storage providers are allowed in Office on the Web (such as Box,\nDropbox, Facebook, Google Drive, OneDrive Personal, etc.). This could lead to\ninformation leakage and additional risk of infection from organizational non-trusted\nstorage providers. Restricting this will inherently reduce risk as it will narrow\nopportunities for infection and data leakage.",
    "impact": "The impact associated with this change is highly dependent upon current practices in\nthe tenant. If users do not use other storage providers, then minimal impact is likely.\nHowever, if users do regularly utilize providers outside of the tenant this will affect their\nability to continue to do so.",
    "audit": "To audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command to audit the default OWA policy:\nGet-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default |\nfl AdditionalStorageProvidersAvailable\n3. Verify that AdditionalStorageProvidersAvailable is False.",
    "remediation": "To remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -\nAdditionalStorageProvidersAvailable $false",
    "default_value": "AdditionalStorageProvidersAvailable : True",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/powershell/module/exchange/set-",
      "owamailboxpolicy?view=exchange-ps",
      "2. https://support.microsoft.com/en-us/topic/3rd-party-cloud-storage-services-",
      "supported-by-office-apps-fce12782-eccc-4cf5-8f4b-d1ebec513f72"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 357,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": false
  },
  {
    "cis_id": "6.5.4",
    "title": "Ensure SMTP AUTH is disabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "mailboxes",
    "domain": "mailboxes",
    "subdomain": "Only Allow Access to Authorized Cloud Storage or",
    "m365_profile": "E3",
    "description": "This setting enables or disables authenticated client SMTP submission (SMTP AUTH)\nat an organization level in Exchange Online.\nThe recommended state is Turn off SMTP AUTH protocol for your\norganization (checked).",
    "rationale": "SMTP AUTH is a legacy protocol. Disabling it at the organization level supports the\nprinciple of least functionality and serves to further back additional controls that block\nlegacy protocols, such as in Conditional Access. Virtually all modern email clients that\nconnect to Exchange Online mailboxes in Microsoft 365 can do so without using SMTP\nAUTH.",
    "impact": "This enforces the default behavior, so no impact is expected unless the organization is\nusing it globally. A per-mailbox setting exists that overrides the tenant-wide setting,\nallowing an individual mailbox SMTP AUTH capability for special cases.",
    "audit": "To audit using the UI:\n1. Navigate to Exchange admin center https://admin.exchange.microsoft.com.\n2. Select Settings > Mail flow.\n3. Ensure Turn off SMTP AUTH protocol for your organization is checked.\nTo audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-TransportConfig | Format-List SmtpClientAuthenticationDisabled\n3. Verify that the value returned is True.",
    "expected_response": "3. Ensure Turn off SMTP AUTH protocol for your organization is checked.",
    "remediation": "To remediate using the UI:\n1. Navigate to Exchange admin center https://admin.exchange.microsoft.com.\n2. Select Settings > Mail flow.\n3. Check Turn off SMTP AUTH protocol for your organization to disable\nthe protocol.\nTo remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-TransportConfig -SmtpClientAuthenticationDisabled $true",
    "default_value": "SmtpClientAuthenticationDisabled : True",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-",
      "online/authenticated-client-smtp-submission"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 359,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "6.5.5",
    "title": "Ensure Direct Send submissions are rejected",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "mailboxes",
    "domain": "mailboxes",
    "subdomain": "Use of Secure Network Management and",
    "m365_profile": "E3",
    "description": "Direct Send is a method used to send emails directly to an Exchange Online customer’s\nhosted mailboxes from on-premises devices, applications, or third-party cloud services\nusing the customer’s own accepted domain. This method does not require any form of\nauthentication because, by its nature, it mimics incoming anonymous emails from the\ninternet, apart from the sender domain.\nThe recommended state is to configure RejectDirectSend to True.",
    "rationale": "Direct Send allows devices and applications to transmit unauthenticated email directly\nto Exchange Online. While this method may support legacy systems such as printers or\nscanners, it introduces significant security risks:\n• Unauthenticated Email Delivery: Direct Send does not require authentication,\nmaking it an attractive vector for threat actors to deliver spoofed or malicious\nemails that appear to originate from trusted internal sources.\n• Phishing and Spoofing Risks: Because these emails bypass standard\nauthentication mechanisms, they can easily impersonate internal users or\nservices, increasing the likelihood of successful phishing attacks.\n• Lack of Visibility and Control: Emails sent via Direct Send may not be subject to\nthe same security policies, logging, or filtering as authenticated traffic, reducing\nthe organization's ability to monitor and respond to threats effectively.\nThreat research from Varonis has shown that attackers are actively exploiting Direct\nSend to impersonate internal accounts and distribute malicious content without needing\nto compromise any credentials. These campaigns have successfully targeted\norganizations by leveraging predictable infrastructure and public user data to craft\nconvincing phishing emails. Because these messages originate from outside the tenant\nbut appear internal, they often evade detection and filtering mechanisms.",
    "impact": "Microsoft has identified some known issues with disabling Direct Send:\n• There is a forwarding scenario that could be affected by this feature. It is possible\nthat someone in your organization sends a message to a 3rd party and they in\nturn forward it to another mailbox in your organization. If the 3rd party’s email\nprovider does not support Sender Rewriting Scheme (SRS), the message will\nreturn with the original sender’s address. Prior to this feature being enabled,\nthose messages will already be punished by SPF failing but could still end up in\ninboxes. Enabling the Reject Direct Send feature without a partner mail flow\nconnector being set up will lead to these messages being rejected outright.\n• If you are using the Azure Communication Services (ACS) to send emails to your\ntenant, and if those emails are sent using a “MAIL FROM” address that is one of\nyour Microsoft 365 accepted domains, enabling RejectDirectSend would block\nthose emails sent to your Microsoft 365 tenant. A solution for ACS traffic to be\ncompatible with the setting is being worked on. In case the domains used to send\nemails from ACS are not one of the Microsoft 365 accepted domains or sub-\ndomains, enabling RejectDirectSend should not have an impact on ACS traffic. If\nACS email traffic is using an Exchange Online domain where the MX is pointed\nto a 3rd party service, please refer to the FAQ’s below, which provide instructions\non mail connectors required to enable traffic in Exchange Online.",
    "audit": "To audit using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nGet-OrganizationConfig | fl RejectDirectSend\n3. Verify that the value returned for RejectDirectSend is True.",
    "remediation": "To remediate using PowerShell:\n1. Connect to Exchange Online using Connect-ExchangeOnline.\n2. Run the following PowerShell command:\nSet-OrganizationConfig -RejectDirectSend $true",
    "default_value": "RejectDirectSend : False",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://techcommunity.microsoft.com/blog/exchange/introducing-more-control-",
      "over-direct-send-in-exchange-online/4408790?WT.mc_id=M365-MVP-9501",
      "2. https://techcommunity.microsoft.com/blog/exchange/direct-send-vs-sending-",
      "directly-to-an-exchange-online-tenant/4439865",
      "3. https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-",
      "organizationconfig?view=exchange-ps",
      "4. https://www.varonis.com/blog/direct-send-exploit",
      "5. https://techcommunity.microsoft.com/discussions/microsoft-365/disable-direct-",
      "send-in-exchange-online-to-mitigate-ongoing-phishing-threats/4434649"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 361,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "7.2.1",
    "title": "Ensure modern authentication for SharePoint applications is required",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Policies",
    "m365_profile": "E3",
    "description": "Modern authentication in Microsoft 365 enables authentication features like multifactor\nauthentication (MFA) using smart cards, certificate-based authentication (CBA), and\nthird-party SAML identity providers.",
    "rationale": "Strong authentication controls, such as the use of multifactor authentication, may be\ncircumvented if basic authentication is used by SharePoint applications. Requiring\nmodern authentication for SharePoint applications ensures strong authentication\nmechanisms are used when establishing sessions between these applications,\nSharePoint, and connecting users.",
    "impact": "Implementation of modern authentication for SharePoint will require users to\nauthenticate to SharePoint using modern authentication. This may cause a minor\nimpact to typical user behavior.\nThis may also prevent third-party apps from accessing SharePoint Online resources.\nAlso, this will also block apps using the SharePointOnlineCredentials class to access\nSharePoint Online resources.",
    "audit": "To audit using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint.\n2. Click to expand Policies select Access control.\n3. Select Apps that don't use modern authentication and ensure that it is\nset to Block access.\nTo audit using PowerShell:\n1. Connect to SharePoint Online using Connect-SPOService -Url\nhttps://tenant-admin.sharepoint.com replacing tenant with your value.\n2. Run the following SharePoint Online PowerShell command:\nGet-SPOTenant | ft LegacyAuthProtocolsEnabled\n3. Ensure the returned value is False.",
    "expected_response": "3. Select Apps that don't use modern authentication and ensure that it is\n3. Ensure the returned value is False.",
    "remediation": "To remediate using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint.\n2. Click to expand Policies select Access control.\n3. Select Apps that don't use modern authentication.\n4. Select the radio button for Block access.\n5. Click Save.\nTo remediate using PowerShell:\n1. Connect to SharePoint Online using Connect-SPOService -Url\nhttps://tenant-admin.sharepoint.com replacing tenant with your value.\n2. Run the following SharePoint Online PowerShell command:\nSet-SPOTenant -LegacyAuthProtocolsEnabled $false",
    "default_value": "True (Apps that don't use modern authentication are allowed)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/powershell/module/sharepoint-online/set-",
      "spotenant?view=sharepoint-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 366,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2"
    ]
  },
  {
    "cis_id": "7.2.2",
    "title": "Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Require Multi-factor Authentication",
    "m365_profile": "E3",
    "description": "Entra ID B2B provides authentication and management of guests. Authentication\nhappens via one-time passcode when they don't already have a work or school account\nor a Microsoft account. Integration with SharePoint and OneDrive allows for more\ngranular control of how guest user accounts are managed in the organization's AAD,\nunifying a similar guest experience already deployed in other Microsoft 365 services\nsuch as Teams.\nNote: Global Reader role currently can't access SharePoint using PowerShell.",
    "rationale": "External users assigned guest accounts will be subject to Entra ID access policies, such\nas multi-factor authentication. This provides a way to manage guest identities and\ncontrol access to SharePoint and OneDrive resources. Without this integration, files can\nbe shared without account registration, making it more challenging to audit and manage\nwho has access to the organization's data.",
    "impact": "B2B collaboration is used with other Entra services so should not be new or unusual.\nMicrosoft also has made the experience seamless when turning on integration on\nSharePoint sites that already have active files shared with guest users. The referenced\nMicrosoft article on the subject has more details on this.",
    "audit": "To audit using PowerShell:\n1. Connect to SharePoint Online using Connect-SPOService\n2. Run the following command:\nGet-SPOTenant | ft EnableAzureADB2BIntegration\n3. Ensure the returned value is True.",
    "expected_response": "3. Ensure the returned value is True.",
    "remediation": "To remediate using PowerShell:\n1. Connect to SharePoint Online using Connect-SPOService\n2. Run the following command:\nSet-SPOTenant -EnableAzureADB2BIntegration $true",
    "default_value": "False",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/sharepoint/sharepoint-azureb2b-",
      "integration#enabling-the-integration",
      "2. https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b",
      "3. https://learn.microsoft.com/en-us/powershell/module/sharepoint-online/set-",
      "spotenant?view=sharepoint-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 369,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "7.2.3",
    "title": "Ensure external content sharing is restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Require Multi-factor Authentication",
    "m365_profile": "E3",
    "description": "The external sharing settings govern sharing for the organization overall. Each site has\nits own sharing setting that can be set independently, though it must be at the same or\nmore restrictive setting as the organization.\nThe new and existing guests option requires people who have received invitations to\nsign in with their work or school account (if their organization uses Microsoft 365) or a\nMicrosoft account, or to provide a code to verify their identity. Users can share with\nguests already in your organization's directory, and they can send invitations to people\nwho will be added to the directory if they sign in.\nThe recommended state is New and existing guests or less permissive.",
    "rationale": "Forcing guest authentication on the organization's tenant enables the implementation of\ncontrols and oversight over external file sharing. When a guest is registered with the\norganization, they now have an identity which can be accounted for. This identity can\nalso have other restrictions applied to it through group membership and conditional\naccess rules.",
    "impact": "When using B2B integration, Entra ID external collaboration settings, such as guest\ninvite settings and collaboration restrictions apply.",
    "audit": "To audit using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Locate the External sharing section.\n4. Under SharePoint, ensure the slider bar is set to New and existing guests or\na less permissive level.\nTo audit using PowerShell:\n1. Connect to SharePoint Online service using Connect-SPOService.\n2. Run the following cmdlet:\nGet-SPOTenant | fl SharingCapability\n3. Ensure SharingCapability is set to one of the following values:\no Value1: ExternalUserSharingOnly\no Value2: ExistingExternalUserSharingOnly\no Value3: Disabled",
    "expected_response": "4. Under SharePoint, ensure the slider bar is set to New and existing guests or\n3. Ensure SharingCapability is set to one of the following values:",
    "remediation": "To remediate using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Locate the External sharing section.\n4. Under SharePoint, move the slider bar to New and existing guests or a less\npermissive level.\no OneDrive will also be moved to the same level and can never be more\npermissive than SharePoint.\nTo remediate using PowerShell:\n1. Connect to SharePoint Online service using Connect-SPOService.\n2. Run the following cmdlet to establish the minimum recommended state:\nSet-SPOTenant -SharingCapability ExternalUserSharingOnly\nNote: Other acceptable values for this parameter that are more restrictive include:\nDisabled and ExistingExternalUserSharingOnly.",
    "default_value": "Anyone (ExternalUserAndGuestSharing)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off",
      "2. https://learn.microsoft.com/en-us/powershell/module/sharepoint-online/set-",
      "spotenant?view=sharepoint-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 371,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "7.2.4",
    "title": "Ensure OneDrive content sharing is restricted",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Configure Data Access Control Lists",
    "m365_profile": "E3",
    "description": "This setting governs the global permissiveness of OneDrive content sharing in the\norganization.\nOneDrive content sharing can be restricted independent of SharePoint but can never be\nmore permissive than the level established with SharePoint.\nThe recommended state is Only people in your organization.",
    "rationale": "OneDrive, designed for end-user cloud storage, inherently provides less oversight and\ncontrol compared to SharePoint, which often involves additional content overseers or\nsite administrators. This autonomy can lead to potential risks such as inadvertent\nsharing of privileged information by end users. Restricting external OneDrive sharing\nwill require users to transfer content to SharePoint folders first which have those tighter\ncontrols.",
    "impact": "Users will be required to take additional steps to share OneDrive content or use other\nofficial channels.",
    "audit": "To audit using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Locate the External sharing section.\n4. Under OneDrive, ensure the slider bar is set to Only people in your\norganization.\nTo audit using PowerShell:\n1. Connect to SharePoint Online service using Connect-SPOService.\n2. Run the following cmdlet:\nGet-SPOTenant | fl OneDriveSharingCapability\n3. Ensure the returned value is Disabled.\nAlternative audit method using PowerShell:\n1. Connect to SharePoint Online.\n2. Use one of the following methods:\n# Replace [tenant] with your tenant id\nGet-SPOSite -Identity https://[tenant]-my.sharepoint.com/ | fl\nUrl,SharingCapability\n# Or run this to filter to the specific site without supplying the tenant\nname.\n$OneDriveSite = Get-SPOSite -Filter { Url -like \"*-my.sharepoint.com/\" }\nGet-SPOSite -Identity $OneDriveSite | fl Url,SharingCapability\n2. Ensure the returned value for SharingCapability is Disabled\nNote: As of March 2024, using Get-SPOSite with Where-Object or filtering against the\nentire site and then returning the SharingCapability parameter can result in a\ndifferent value as opposed to running the cmdlet specifically against the OneDrive\nspecific site using the -Identity switch as shown in the example.\nNote 2: The parameter OneDriveSharingCapability may not be yet fully available in\nall tenants. It is demonstrated in official Microsoft documentation as linked in the\nreferences section but not in the Set-SPOTenant cmdlet itself. If the parameter is\nunavailable, then either use the UI method or alternative PowerShell audit method.",
    "expected_response": "4. Under OneDrive, ensure the slider bar is set to Only people in your\n3. Ensure the returned value is Disabled.\n2. Ensure the returned value for SharingCapability is Disabled",
    "remediation": "To remediate using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Locate the External sharing section.\n4. Under OneDrive, set the slider bar to Only people in your organization.\nTo remediate using PowerShell:\n1. Connect to SharePoint Online service using Connect-SPOService.\n2. Run the following cmdlet:\nSet-SPOTenant -OneDriveSharingCapability Disabled\nAlternative remediation method using PowerShell:\n1. Connect to SharePoint Online.\n2. Run one of the following:\n# Replace [tenant] with your tenant id\nSet-SPOSite -Identity https://[tenant]-my.sharepoint.com/ -SharingCapability\nDisabled\n# Or run this to filter to the specific site without supplying the tenant\nname.\n$OneDriveSite = Get-SPOSite -Filter { Url -like \"*-my.sharepoint.com/\" }\nSet-SPOSite -Identity $OneDriveSite -SharingCapability Disabled",
    "default_value": "Anyone (ExternalUserAndGuestSharing)",
    "detection_commands": [
      "$OneDriveSite = Get-SPOSite -Filter { Url -like \"*-my.sharepoint.com/\" }"
    ],
    "remediation_commands": [
      "$OneDriveSite = Get-SPOSite -Filter { Url -like \"*-my.sharepoint.com/\" }"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/powershell/module/sharepoint-online/set-",
      "spotenant?view=sharepoint-ps#-onedrivesharingcapability"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 374,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "7.2.5",
    "title": "Ensure that SharePoint guest users cannot share items they don't own",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Configure Data Access Control Lists",
    "m365_profile": "E3",
    "description": "SharePoint gives users the ability to share files, folders, and site collections. Internal\nusers can share with external collaborators, and with the right permissions could share\nto other external parties.",
    "rationale": "Sharing and collaboration are key; however, file, folder, or site collection owners should\nhave the authority over what external users get shared with to prevent unauthorized\ndisclosures of information.",
    "impact": "The impact associated with this change is highly dependent upon current practices. If\nusers do not regularly share with external parties, then minimal impact is likely.\nHowever, if users do regularly share with guests/externally, minimum impacts could\noccur as those external users will be unable to 're-share' content.",
    "audit": "To audit using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies then select Sharing.\n3. Expand More external sharing settings, verify that Allow guests to\nshare items they don't own is unchecked.\nTo audit using PowerShell:\n1. Connect to SharePoint Online service using Connect-SPOService.\n2. Run the following SharePoint Online PowerShell command:\nGet-SPOTenant | ft PreventExternalUsersFromResharing\n3. Ensure the returned value is True.",
    "expected_response": "3. Ensure the returned value is True.",
    "remediation": "To remediate using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies then select Sharing.\n3. Expand More external sharing settings, uncheck Allow guests to\nshare items they don't own.\n4. Click Save.\nTo remediate using PowerShell:\n1. Connect to SharePoint Online service using Connect-SPOService.\n2. Run the following SharePoint Online PowerShell command:\nSet-SPOTenant -PreventExternalUsersFromResharing $True",
    "default_value": "Checked (False)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off",
      "2. https://learn.microsoft.com/en-us/sharepoint/external-sharing-overview"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 377,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "7.2.6",
    "title": "Ensure SharePoint external sharing is restricted",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Protect Information through Access Control Lists",
    "m365_profile": "E3",
    "description": "The external sharing features of SharePoint and OneDrive let users in the organization\nshare content with people outside the organization (such as partners, vendors, clients,\nor customers). It can also be used to share between licensed users on multiple\nMicrosoft 365 subscriptions if your organization has more than one subscription.\nThe recommended state is Limit external sharing by domain > Allow only\nspecific domains",
    "rationale": "Attackers will often attempt to expose sensitive information to external entities through\nsharing, and restricting the domains that users can share documents with will reduce\nthat surface area.",
    "impact": "Enabling this feature will prevent users from sharing documents with domains outside of\nthe organization unless allowed.",
    "audit": "To audit using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Expand Policies then click Sharing.\n3. Expand More external sharing settings and confirm that Limit external\nsharing by domain is checked.\n4. Click on Add domains and verify the the sub setting Allow only specific\ndomains is selected and with an approved list domains.\nTo audit using PowerShell:\n1. Connect to SharePoint Online using Connect-SPOService.\n2. Run the following PowerShell command:\nGet-SPOTenant | fl SharingDomainRestrictionMode,SharingAllowedDomainList\n3. Ensure that SharingDomainRestrictionMode is set to AllowList and\nSharingAllowedDomainList contains domains trusted by the organization for\nexternal sharing.",
    "expected_response": "3. Ensure that SharingDomainRestrictionMode is set to AllowList and",
    "remediation": "To remediate using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint.\n2. Expand Policies then click Sharing.\n3. Expand More external sharing settings and check Limit external\nsharing by domain.\n4. Select Add domains to add a list of approved domains.\n5. Click Save at the bottom of the page.\nTo remediate using PowerShell:\n1. Connect to SharePoint Online using Connect-SPOService.\n2. Run the following PowerShell command:\nSet-SPOTenant -SharingDomainRestrictionMode AllowList -\nSharingAllowedDomainList \"domain1.com domain2.com\"",
    "default_value": "Limit external sharing by domain is unchecked\nSharingDomainRestrictionMode: None\nSharingDomainRestrictionMode: <Undefined>",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-",
      "off?WT.mc_id=365AdminCSH_spo#more-external-sharing-settings"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 379,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "7.2.7",
    "title": "Ensure link sharing is restricted in SharePoint and OneDrive",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Protect Information through Access Control Lists",
    "m365_profile": "E3",
    "description": "This setting sets the default link type that a user will see when sharing content in\nOneDrive or SharePoint. It does not restrict or exclude any other options.\nThe recommended state is Specific people (only the people the user\nspecifies) or Only people in your organization (more restrictive).",
    "rationale": "By defaulting to specific people, the user will first need to consider whether or not the\ncontent being shared should be accessible by the entire organization versus select\nindividuals. This aids in reinforcing the concept of least privilege.",
    "audit": "To audit using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Scroll to File and folder links.\n4. Ensure that the setting Choose the type of link that's selected by\ndefault when users share files and folders in SharePoint and\nOneDrive is set to Specific people (only the people the user\nspecifies) or Only people in your organization (more restrictive).\nTo audit using PowerShell:\n1. Connect to SharePoint Online using Connect-SPOService.\n2. Run the following PowerShell command:\nGet-SPOTenant | fl DefaultSharingLinkType\n3. Ensure the returned value is Direct or Internal (more restrictive).",
    "expected_response": "4. Ensure that the setting Choose the type of link that's selected by\nOneDrive is set to Specific people (only the people the user\n3. Ensure the returned value is Direct or Internal (more restrictive).",
    "remediation": "To remediate using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Scroll to File and folder links.\n4. Set Choose the type of link that's selected by default when users\nshare files and folders in SharePoint and OneDrive to Specific\npeople (only the people the user specifies) or Only people in your\norganization.\nTo remediate using PowerShell:\n1. Connect to SharePoint Online using Connect-SPOService.\n2. Run the following PowerShell command:\nSet-SPOTenant -DefaultSharingLinkType Direct\n3. Or, to set a more restrictive state:\nSet-SPOTenant -DefaultSharingLinkType Internal",
    "default_value": "Only people in your organization (Internal)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/powershell/module/sharepoint-online/set-",
      "spotenant?view=sharepoint-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 382,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "7.2.8",
    "title": "Ensure external sharing is restricted by security group",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Configure Data Access Control Lists",
    "m365_profile": "E3",
    "description": "External sharing of content can be restricted to specific security groups. This setting is\nglobal, applies to sharing in both SharePoint and OneDrive and cannot be set at the site\nlevel in SharePoint.\nThe recommended state is Enabled or Checked.\nNote: Users in these security groups must be allowed to invite guests in the guest invite\nsettings in Microsoft Entra. Identity > External Identities > External collaboration settings",
    "rationale": "Organizations wishing to create tighter security controls for external sharing can set this\nto enforce role-based access control by using security groups already defined in\nMicrosoft Entra ID.",
    "impact": "OneDrive will also be governed by this and there is no granular control at the\nSharePoint site level.",
    "audit": "To audit using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Scroll to and expand More external sharing settings.\n4. Ensure the following:\no Verify Allow only users in specific security groups to share\nexternally is checked\no Verify Manage security groups is defined and accordance with\ncompany procedure.\nNote: The More external sharing settings drop down in step 3 above may be\nunavailable or limited if the External Sharing slider settings above are set to \"Least\npermissive.\"",
    "expected_response": "4. Ensure the following:\nunavailable or limited if the External Sharing slider settings above are set to \"Least",
    "remediation": "To remediate using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Scroll to and expand More external sharing settings.\n4. Set the following:\no Check Allow only users in specific security groups to share\nexternally\no Define Manage security groups in accordance with company\nprocedure.",
    "default_value": "Unchecked/Undefined",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/sharepoint/manage-security-groups"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 384,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4"
    ]
  },
  {
    "cis_id": "7.2.9",
    "title": "Ensure guest access to a site or OneDrive will expire automatically",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This policy setting configures the expiration time for each guest that is invited to the\nSharePoint site or with whom users share individual files and folders with.\nThe recommended state is 30 or less.",
    "rationale": "This setting ensures that guests who no longer need access to the site or link no longer\nhave access after a set period of time. Allowing guest access for an indefinite amount of\ntime could lead to loss of data confidentiality and oversight.\nNote: Guest membership applies at the Microsoft 365 group level. Guests who have\npermission to view a SharePoint site or use a sharing link may also have access to a\nMicrosoft Teams team or security group.",
    "impact": "Site collection administrators will have to renew access to guests who still need access\nafter 30 days. They will receive an e-mail notification once per week about guest access\nthat is about to expire.\nNote: The guest expiration policy only applies to guests who use sharing links or guests\nwho have direct permissions to a SharePoint site after the guest policy is enabled. The\nguest policy does not apply to guest users that have pre-existing permissions or access\nthrough a sharing link before the guest expiration policy is applied.",
    "audit": "To audit using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Scroll to and expand More external sharing settings.\n4. Ensure Guest access to a site or OneDrive will expire\nautomatically after this many days is checked and set to 30 or less.\nTo audit using PowerShell:\n1. Connect to SharePoint Online service using Connect-SPOService.\n2. Run the following cmdlet:\nGet-SPOTenant | fl ExternalUserExpirationRequired,ExternalUserExpireInDays\n3. Ensure the following values are returned:\no ExternalUserExpirationRequired is True.\no ExternalUserExpireInDays is 30 or less.",
    "expected_response": "4. Ensure Guest access to a site or OneDrive will expire\n3. Ensure the following values are returned:",
    "remediation": "To remediate using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Scroll to and expand More external sharing settings.\n4. Set Guest access to a site or OneDrive will expire automatically\nafter this many days to 30\nTo remediate using PowerShell:\n1. Connect to SharePoint Online service using Connect-SPOService.\n2. Run the following cmdlet:\nSet-SPOTenant -ExternalUserExpireInDays 30 -ExternalUserExpirationRequired\n$True",
    "default_value": "ExternalUserExpirationRequired $false\nExternalUserExpireInDays 60 days",
    "detection_commands": [],
    "remediation_commands": [
      "$True"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-",
      "off#change-the-organization-level-external-sharing-setting",
      "2. https://learn.microsoft.com/en-us/microsoft-365/community/sharepoint-security-a-",
      "team-effort"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 386,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "7.2.10",
    "title": "Ensure reauthentication with verification code is restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This setting configures if guests who use a verification code to access the site or links\nare required to reauthenticate after a set number of days.\nThe recommended state is 15 or less.",
    "rationale": "By increasing the frequency of times guests need to reauthenticate this ensures guest\nuser access to data is not prolonged beyond an acceptable amount of time.",
    "impact": "Guests who use Microsoft 365 in their organization can sign in using their work or\nschool account to access the site or document. After the one-time passcode for\nverification has been entered for the first time, guests will authenticate with their work or\nschool account and have a guest account created in the host's organization.\nNote: If OneDrive and SharePoint integration with Entra ID B2B is enabled as per the\nCIS Benchmark the one-time-passcode experience will be replaced. Please visit Secure\nexternal sharing in SharePoint - SharePoint in Microsoft 365 | Microsoft Learn for more\ninformation.",
    "audit": "To audit using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Scroll to and expand More external sharing settings.\n4. Ensure People who use a verification code must reauthenticate\nafter this many days is set to 15 or less.\nTo audit using PowerShell:\n1. Connect to SharePoint Online service using Connect-SPOService.\n2. Run the following cmdlet:\nGet-SPOTenant | fl EmailAttestationRequired,EmailAttestationReAuthDays\n3. Ensure the following values are returned:\no EmailAttestationRequired True\no EmailAttestationReAuthDays 15 or less days.",
    "expected_response": "4. Ensure People who use a verification code must reauthenticate\nafter this many days is set to 15 or less.\n3. Ensure the following values are returned:",
    "remediation": "To remediate using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Scroll to and expand More external sharing settings.\n4. Set People who use a verification code must reauthenticate after\nthis many days to 15 or less.\nTo remediate using PowerShell:\n1. Connect to SharePoint Online service using Connect-SPOService.\n2. Run the following cmdlet:\nSet-SPOTenant -EmailAttestationRequired $true -EmailAttestationReAuthDays 15",
    "default_value": "EmailAttestationRequired : False\nEmailAttestationReAuthDays : 30",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/sharepoint/what-s-new-in-sharing-in-targeted-",
      "release",
      "2. https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-",
      "off#change-the-organization-level-external-sharing-setting",
      "3. https://learn.microsoft.com/en-us/entra/external-id/one-time-passcode"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 389,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "7.2.11",
    "title": "Ensure the SharePoint default sharing link permission is set",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This setting configures the permission that is selected by default for sharing link from a\nSharePoint site.\nThe recommended state is View.",
    "rationale": "Setting the view permission as the default ensures that users must deliberately select\nthe edit permission when sharing a link. This approach reduces the risk of\nunintentionally granting edit privileges to a resource that only requires read access,\nsupporting the principle of least privilege.",
    "impact": "Not applicable.",
    "audit": "To audit using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Scroll to File and folder links.\n4. Ensure Choose the permission that's selected by default for\nsharing links is set to View.\nTo audit using PowerShell:\n1. Connect to SharePoint Online service using Connect-SPOService.\n2. Run the following cmdlet:\nGet-SPOTenant | fl DefaultLinkPermission\n3. Ensure the returned value is View.",
    "expected_response": "4. Ensure Choose the permission that's selected by default for\nsharing links is set to View.\n3. Ensure the returned value is View.",
    "remediation": "To remediate using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click to expand Policies > Sharing.\n3. Scroll to File and folder links.\n4. Set Choose the permission that's selected by default for sharing\nlinks to View.\nTo remediate using PowerShell:\n1. Connect to SharePoint Online service using Connect-SPOService.\n2. Run the following cmdlet:\nSet-SPOTenant -DefaultLinkPermission View",
    "default_value": "DefaultLinkPermission : Edit",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off#file-",
      "and-folder-links"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 392,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "7.3.1",
    "title": "Ensure Office 365 SharePoint infected files are disallowed for download",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Settings",
    "m365_profile": "E5",
    "description": "By default, SharePoint online allows files that Defender for Office 365 has detected as\ninfected to be downloaded.",
    "rationale": "Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams protects your\norganization from inadvertently sharing malicious files. When an infected file is detected\nthat file is blocked so that no one can open, copy, move, or share it until further actions\nare taken by the organization's security team.",
    "impact": "The only potential impact associated with implementation of this setting is potential\ninconvenience associated with the small percentage of false positive detections that\nmay occur.",
    "audit": "To audit using PowerShell:\n1. Connect to SharePoint Online using Connect-SPOService -Url\nhttps://tenant-admin.sharepoint.com, replacing \"tenant\" with the\nappropriate value.\n2. Run the following PowerShell command:\nGet-SPOTenant | Select-Object DisallowInfectedFileDownload\n3. Ensure the value for DisallowInfectedFileDownload is set to True.\nNote: According to Microsoft, SharePoint cannot be accessed through PowerShell by\nusers with the Global Reader role. For further information, please refer to the reference\nsection.",
    "expected_response": "3. Ensure the value for DisallowInfectedFileDownload is set to True.",
    "remediation": "To remediate using PowerShell:\n1. Connect to SharePoint Online using Connect-SPOService -Url\nhttps://tenant-admin.sharepoint.com, replacing \"tenant\" with the\nappropriate value.\n2. Run the following PowerShell command to set the recommended value:\nSet-SPOTenant –DisallowInfectedFileDownload $true\nNote: The Global Reader role cannot access SharePoint using PowerShell according to\nMicrosoft. See the reference section for more information.",
    "default_value": "False",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-for-spo-",
      "odfb-teams-configure?view=o365-worldwide",
      "2. https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-",
      "for-spo-odfb-teams-about?view=o365-worldwide",
      "3. https://learn.microsoft.com/en-us/entra/identity/role-based-access-",
      "control/permissions-reference#global-reader"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 395,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "7.3.2",
    "title": "Ensure OneDrive sync is restricted for unmanaged devices",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "sharepoint",
    "domain": "SharePoint admin center",
    "subdomain": "Utilize Centrally Managed Anti-malware Software",
    "m365_profile": "E3",
    "description": "Microsoft OneDrive allows users to sign in their cloud tenant account and begin syncing\nselect folders or the entire contents of OneDrive to a local computer. By default, this\nincludes any computer with OneDrive already installed, whether it is Entra Joined ,\nEntra Hybrid Joined or Active Directory Domain joined.\nThe recommended state for this setting is Allow syncing only on computers\njoined to specific domains Enabled: Specify the AD domain GUID(s)",
    "rationale": "Unmanaged devices pose a risk, since their security cannot be verified through existing\nsecurity policies, brokers or endpoint protection. Allowing users to sync data to these\ndevices takes that data out of the control of the organization. This increases the risk of\nthe data either being intentionally or accidentally leaked.\nNote: This setting is only applicable to Active Directory domains when operating in a\nhybrid configuration. It does not apply to Entra domains. If there are devices which are\nonly Entra ID joined, consider using a Conditional Access Policy instead.",
    "impact": "Enabling this feature will prevent users from using the OneDrive for Business Sync\nclient on devices that are not joined to the domains that were defined.",
    "audit": "To audit using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click Settings followed by OneDrive - Sync\n3. Verify that Allow syncing only on computers joined to specific\ndomains is checked.\n4. Verify that the Active Directory domain GUIDS are listed in the box.\no Use the Get-ADDomain PowerShell command on the on-premises server\nto obtain the GUID for each on-premises domain.\nTo audit using PowerShell:\n1. Connect to SharePoint Online using Connect-SPOService -Url\nhttps://tenant-admin.sharepoint.com, replacing \"tenant\" with the\nappropriate value.\n2. Run the following PowerShell command:\nGet-SPOTenantSyncClientRestriction | fl\nTenantRestrictionEnabled,AllowedDomainList\n3. Ensure TenantRestrictionEnabled is set to True and AllowedDomainList\ncontains the trusted domains GUIDs from the on premises environment.",
    "expected_response": "3. Ensure TenantRestrictionEnabled is set to True and AllowedDomainList",
    "remediation": "To remediate using the UI:\n1. Navigate to SharePoint admin center https://admin.microsoft.com/sharepoint\n2. Click Settings then select OneDrive - Sync.\n3. Check the Allow syncing only on computers joined to specific\ndomains.\n4. Use the Get-ADDomain PowerShell command on the on-premises server to\nobtain the GUID for each on-premises domain.\n5. Click Save.\nTo remediate using PowerShell:\n1. Connect to SharePoint Online using Connect-SPOService\n2. Run the following PowerShell command and provide the DomainGuids from the\nGet-AADomain command:\nSet-SPOTenantSyncClientRestriction -Enable -DomainGuids \"786548DD-877B-4760-\nA749-6B1EFBC1190A; 877564FF-877B-4760-A749-6B1EFBC1190A\"\nNote: Utilize the -BlockMacSync:$true parameter if you are not using conditional\naccess to ensure Macs cannot sync.",
    "default_value": "By default there are no restrictions applied to the syncing of OneDrive.\nTenantRestrictionEnabled : False\nAllowedDomainList : {}",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/sharepoint/allow-syncing-only-on-specific-",
      "domains",
      "2. https://learn.microsoft.com/en-us/powershell/module/sharepoint-online/set-",
      "spotenantsyncclientrestriction?view=sharepoint-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 397,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "8.1.1",
    "title": "Ensure external file sharing in Teams is enabled for only approved cloud storage services",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Teams",
    "m365_profile": "E3",
    "description": "Microsoft Teams enables collaboration via file sharing. This file sharing is conducted\nwithin Teams, using SharePoint Online, by default; however, third-party cloud services\nare allowed as well.\nNote: Skype for business is deprecated as of July 31, 2021 although these settings may\nstill be valid for a period of time. See the link in the references section for more\ninformation.",
    "rationale": "Ensuring that only authorized cloud storage providers are accessible from Teams will\nhelp to dissuade the use of non-approved storage providers.",
    "impact": "The impact associated with this change is highly dependent upon current practices in\nthe tenant. If users do not use other storage providers, then minimal impact is likely.\nHowever, if users do regularly utilize providers outside of the tenant this will affect their\nability to continue to do so.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Click Teams to open the Teams settings section.\n4. Under files verify that only organizationally authorized cloud storage options are\nset to On and all others Off.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams\n2. Run the following to verify the recommended state:\n$Params = @(\n'AllowDropbox'\n'AllowBox'\n'AllowGoogleDrive'\n'AllowShareFile'\n'AllowEgnyte'\n)\nGet-CsTeamsClientConfiguration -Identity Global | fl $Params\n3. Verify that only authorized providers are set to True and all others False.",
    "expected_response": "3. Verify that only authorized providers are set to True and all others False.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Click Teams to open the Teams settings section.\n4. Under files set storages providers to Off unless they have first been authorized\nby the organization.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams\n2. Run the following PowerShell command to disable external providers that are not\nauthorized. (the example disables Citrix Files, DropBox, Box, Google Drive and\nEgnyte)\n$Params = @{\nIdentity = 'Global'\nAllowGoogleDrive = $false\nAllowShareFile = $false\nAllowBox = $false\nAllowDropBox = $false\nAllowEgnyte = $false\n}\nSet-CsTeamsClientConfiguration @Params",
    "default_value": "AllowDropBox : True\nAllowBox : True\nAllowGoogleDrive : True\nAllowShareFile : True\nAllowEgnyte : True",
    "detection_commands": [
      "$Params = @( 'AllowDropbox' 'AllowBox' 'AllowGoogleDrive' 'AllowShareFile' 'AllowEgnyte'"
    ],
    "remediation_commands": [
      "$Params = @{"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoftteams/teams-powershell-managing-",
      "teams"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 402,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "8.1.2",
    "title": "Ensure users can't send emails to a channel email address",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Enforce Access Control to Data through Automated",
    "m365_profile": "E3",
    "description": "This setting controls whether Teams channels are allowed to receive emails sent to\ntheir unique email addresses. When enabled, emails sent to a channel's address will be\ndelivered and appear in the channel's conversation thread; when disabled, the channel\nwill reject incoming emails, preventing them from being posted.\nThe recommended state is Off.",
    "rationale": "Channel email addresses are not under the tenant’s domain and organizations do not\nhave control over the security settings for this email address. An attacker could email\nchannels directly if they discover the channel email address.",
    "impact": "Depending on the organization's adoption, disabling this may disrupt workflows that rely\non email-to-channel communication, particularly in environments where email is used to\nbridge external systems or vendors into Teams. This could include reduced visibility of\nimportant updates or alerts that were previously routed into Teams channels via email.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Click Teams to open the Teams settings section.\n4. Under email integration verify that Users can send emails to a channel\nemail address is Off.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to verify the recommended state:\nGet-CsTeamsClientConfiguration -Identity Global | fl AllowEmailIntoChannel\n3. Ensure the returned value is False.",
    "expected_response": "3. Ensure the returned value is False.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Click Teams to open the Teams settings section.\n4. Under email integration set Users can send emails to a channel email\naddress to Off.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to set the recommended state:\nSet-CsTeamsClientConfiguration -Identity Global -AllowEmailIntoChannel $false",
    "default_value": "On (True)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/step-",
      "by-step-guides/reducing-attack-surface-in-microsoft-teams?view=o365-",
      "worldwide#restricting-channel-email-messages-to-approved-domains",
      "2. https://learn.microsoft.com/en-us/microsoftteams/settings-policies-",
      "reference#email-integration",
      "3. https://support.microsoft.com/en-us/office/send-an-email-to-a-channel-in-",
      "microsoft-teams-d91db004-d9d7-4a47-82e6-fb1b16dfd51e"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 406,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "8.2.1",
    "title": "Ensure external domains are restricted in the Teams admin center",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Users",
    "m365_profile": "E3",
    "description": "This policy controls whether external domains are allowed, blocked or permitted based\non an allowlist or denylist. When external domains are allowed, users in your\norganization can chat, add users to meetings, and use audio video conferencing with\nusers in external organizations.\nThe recommended state is Allow only specific external domains or Block all\nexternal domains.",
    "rationale": "Allowlisting external domains that an organization is collaborating with allows for\nstringent controls over who an organization's users are allowed to make contact with.\nSome real-world attacks and exploits delivered via Teams over external access\nchannels include:\n• DarkGate malware\n• Social engineering / Phishing attacks by \"Midnight Blizzard\"\n• GIFShell\n• Username enumeration",
    "impact": "The impact in terms of the type of collaboration users are allowed to participate in and\nthe I.T. resources expended to manage an allowlist will increase. If a user attempts to\njoin the inviting organization's meeting they will be prevented from joining unless they\nwere created as a guest in EntraID or their domain was added to the allowed external\ndomains list.\nNote Organizations may choose create additional policies for specific groups needing\nexternal access.",
    "audit": "The focus of this control at a minimum is the Global (Org-wide default) policy. If\nthe organization-wide setting is configured to Allow only specific external\ndomains or Block all external domains, then this is also considered a passing\nstate due to its increased restrictiveness.\nTo audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com/.\n2. Click to expand Users select External access.\n3. Select the Policies tab.\n4. Click on the Global (Org-wide default) policy.\n5. Ensure Teams and Skype for Business users in external\norganizations is set to Off.\nOrganization settings: Additional passing state\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com/.\n2. Click to expand Users select External access.\n3. Select the Organization settings tab.\n4. Ensure Teams and Skype for Business users in external\norganizations is set to one of the following:\no Allowlist: Allow only specific external domains\no Disabled: Block all external domains\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams\n2. Run the following command:\nGet-CsExternalAccessPolicy -Identity Global\n3. Ensure EnableFederationAccess is False.\nOrganization settings: Additional passing state\n1. Run the following command:\nGet-CsTenantFederationConfiguration | fl AllowFederatedUsers,AllowedDomains\nEnsure the following conditions:\n• State: AllowFederatedUsers is set to False OR,\n• If: AllowFederatedUsers is True then ensure AllowedDomains contains\nauthorized domain names and is not set to AllowAllKnownDomains.\nNote: The organization settings take precedence over the policy settings. The audit is\nconsidered satisfied if the organizational setting is configured as prescribed, regardless\nof whether the Global default policy value is True or False.",
    "expected_response": "the organization-wide setting is configured to Allow only specific external\n5. Ensure Teams and Skype for Business users in external\norganizations is set to Off.\n4. Ensure Teams and Skype for Business users in external\norganizations is set to one of the following:\n3. Ensure EnableFederationAccess is False.\nEnsure the following conditions:\n• State: AllowFederatedUsers is set to False OR,\n• If: AllowFederatedUsers is True then ensure AllowedDomains contains\nconsidered satisfied if the organizational setting is configured as prescribed, regardless",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com/.\n2. Click to expand Users select External access.\n3. Select the Policies tab\n4. Click on the Global (Org-wide default) policy.\n5. Set Teams and Skype for Business users in external organizations to\nOff.\n6. Click Save.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams\n2. Run the following command to configure the Global (Org-wide default)` policy.\nSet-CsExternalAccessPolicy -Identity Global -EnableFederationAccess $false\nNote: Configuring this setting at the organization level in Organization settings to\neither Block all external domains or Allow only specific external domains\nis also a compliant configuration for this control.",
    "default_value": "EnableFederationAccess - $True",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-",
      "meetings-chat?tabs=organization-settings",
      "2. https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-",
      "conducts-targeted-social-engineering-over-microsoft-teams/",
      "3. https://www.bitdefender.com/blog/hotforsecurity/gifshell-attack-lets-hackers-",
      "create-reverse-shell-through-microsoft-teams-gifs/"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 410,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "8.2.2",
    "title": "Ensure communication with unmanaged Teams users is disabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Users",
    "m365_profile": "E3",
    "description": "This policy setting controls chats and meetings with external unmanaged Teams users\n(those not managed by an organization, such as Microsoft Teams (free)).\nThe recommended state is: People in my organization can communicate with\nunmanaged Teams accounts set to Off.",
    "rationale": "Allowing users to communicate with unmanaged Teams users presents a potential\nsecurity threat as little effort is required by threat actors to gain access to a trial or free\nMicrosoft Teams account.\nSome real-world attacks and exploits delivered via Teams over external access\nchannels include:\n• DarkGate malware\n• Social engineering / Phishing attacks by \"Midnight Blizzard\"\n• GIFShell\n• Username enumeration",
    "impact": "Users will be unable to communicate with Teams users who are not managed by an\norganization.\nOrganizations may choose create additional policies for specific groups needing to\ncommunicating with unmanaged external users.\nNote: The settings that govern chats and meetings with external unmanaged Teams\nusers aren't available in GCC, GCC High, or DOD deployments, or in private cloud\nenvironments.",
    "audit": "The focus of this control at a minimum is the Global (Org-wide default) policy. If\nthe equivalent organization-wide setting is configured to Off, then this is also\nconsidered a passing state due to its increased restrictiveness.\nTo audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com/.\n2. Click to expand Users select External access\n3. Select the Policies tab.\n4. Click on the Global (Org-wide default) policy.\n5. Ensure People in my organization can communicate with unmanaged\nTeams accounts is set to Off.\nOrganization settings: Additional passing state\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com/.\n2. Click to expand Users select External access\n3. Select the Organization settings tab.\n4. Ensure People in my organization can communicate with unmanaged\nTeams accounts is set to Off.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams\n2. Run the following command:\nGet-CsExternalAccessPolicy -Identity Global\nEnsure EnableTeamsConsumerAccess is set to False.\nOrganization settings: Additional passing state\n1. Run the following command:\nGet-CsTenantFederationConfiguration | fl AllowTeamsConsumer\nEnsure AllowTeamsConsumer is False\nNote: The organization settings take precedence over the policy settings. The audit is\nconsidered satisfied if the organizational setting is configured as prescribed, regardless\nof whether the Global default policy value is True or False.",
    "expected_response": "the equivalent organization-wide setting is configured to Off, then this is also\n5. Ensure People in my organization can communicate with unmanaged\nTeams accounts is set to Off.\n4. Ensure People in my organization can communicate with unmanaged\nEnsure EnableTeamsConsumerAccess is set to False.\nEnsure AllowTeamsConsumer is False\nconsidered satisfied if the organizational setting is configured as prescribed, regardless",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com/.\n2. Click to expand Users select External access.\n3. Select the Policies tab\n4. Click on the Global (Org-wide default) policy.\n5. Set People in my organization can communicate with unmanaged Teams\naccounts to Off.\n6. Click Save.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams\n2. Run the following command:\nSet-CsExternalAccessPolicy -Identity Global -EnableTeamsConsumerAccess $false\nNote: Configuring the organization settings to block communication is also in\ncompliance with this control.",
    "default_value": "• EnableTeamsConsumerAccess : True",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-",
      "meetings-chat?tabs=organization-settings",
      "2. https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-",
      "conducts-targeted-social-engineering-over-microsoft-teams/",
      "3. https://www.bitdefender.com/blog/hotforsecurity/gifshell-attack-lets-hackers-",
      "create-reverse-shell-through-microsoft-teams-gifs/"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 414,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "8.2.3",
    "title": "Ensure external Teams users cannot initiate conversations",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Users",
    "m365_profile": "E3",
    "description": "This setting prevents external users who are not managed by an organization from\ninitiating contact with users in the protected organization.\nThe recommended state is to uncheck External users with Teams accounts not\nmanaged by an organization can contact users in my organization.\nNote: Disabling this setting is used as an additional stop gap for the previous setting\nwhich disables communication with unmanaged Teams users entirely. If an organization\nchooses to have an exception to (L1) Ensure communication with unmanaged\nTeams users is disabled they can do so while also disabling the ability for the same\ngroup of users to initiate contact. Disabling communication entirely will also disable the\nability for unmanaged users to initiate contact.",
    "rationale": "Allowing users to communicate with unmanaged Teams users presents a potential\nsecurity threat as little effort is required by threat actors to gain access to a trial or free\nMicrosoft Teams account.\nSome real-world attacks and exploits delivered via Teams over external access\nchannels include:\n• DarkGate malware\n• Social engineering / Phishing attacks by \"Midnight Blizzard\"\n• GIFShell\n• Username enumeration",
    "impact": "The impact of disabling this is very low.\nOrganizations may choose to create additional policies for specific groups that need to\ncommunicate with unmanaged external users.\nNote: Chats and meetings with external unmanaged Teams users isn't available in\nGCC, GCC High, or DOD deployments, or in private cloud environments.",
    "audit": "The focus of this control at a minimum is the Global (Org-wide default) policy. If\nthe equivalent organization-wide setting is disabled, then this is also considered a\npassing state due to its increased restrictiveness.\nTo audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com/.\n2. Click to expand Users select External access.\n3. Select the Policies tab.\n4. Click on the Global (Org-wide default) policy.\n5. Ensure External users with Teams accounts not managed by an\norganization can contact users in my organization is not checked\n(false).\nOrganization settings: Additional passing state\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com/.\n2. Click to expand Users select External access.\n3. Select the Organization settings tab.\n4. Locate the parent setting People in my organization can communicate with\nunmanaged Teams accounts.\n5. Ensure External users with Teams accounts not managed by an\norganization can contact users in my organization is not checked\n(false).\nNote: If the parent setting People in my organization can communicate with\nunmanaged Teams accounts is already set to Off then this setting will not be visible in\nthe UI.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams\n2. Run the following command:\nGet-CsExternalAccessPolicy -Identity Global\nEnsure EnableTeamsConsumerInbound is False\nOrganization settings: Additional passing state\n1. Run the following command:\nGet-CsTenantFederationConfiguration | fl AllowTeamsConsumerInbound\nEnsure AllowTeamsConsumerInbound is False\nNote: The organization settings take precedence over the policy settings. The audit is\nconsidered satisfied if the organizational setting is configured as prescribed, regardless\nof whether the Global default policy value is True or False.",
    "expected_response": "the equivalent organization-wide setting is disabled, then this is also considered a\n5. Ensure External users with Teams accounts not managed by an\nEnsure EnableTeamsConsumerInbound is False\nEnsure AllowTeamsConsumerInbound is False\nconsidered satisfied if the organizational setting is configured as prescribed, regardless",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com/.\n2. Click to expand Users select External access.\n3. Select the Policies tab.\n4. Click on the Global (Org-wide default) policy.\n5. Locate the parent setting People in my organization can communicate with\nunmanaged Teams accounts.\n6. Uncheck External users with Teams accounts not managed by an\norganization can contact users in my organization.\n7. Click Save.\nNote: If People in my organization can communicate with unmanaged Teams\naccounts is already set to Off then this setting will not be visible and will satisfy the\nrequirements of this recommendation.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams\n2. Run the following command:\nSet-CsExternalAccessPolicy -Identity Global -EnableTeamsConsumerInbound\n$false\nNote: Configuring the organization settings to block inbound communication is also in\ncompliance with this control.",
    "default_value": "• EnableTeamsConsumerInbound : True",
    "detection_commands": [],
    "remediation_commands": [
      "$false"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-",
      "meetings-chat?tabs=organization-settings",
      "2. https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-",
      "conducts-targeted-social-engineering-over-microsoft-teams/",
      "3. https://www.bitdefender.com/blog/hotforsecurity/gifshell-attack-lets-hackers-",
      "create-reverse-shell-through-microsoft-teams-gifs/"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 417,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "8.2.4",
    "title": "Ensure the organization cannot communicate with accounts in trial Teams tenants",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Users",
    "m365_profile": "E3",
    "description": "This setting controls the organization's external access with Teams \"trial-only\" tenants.\nThese are tenants that don't have any purchased seats.\nWhen set to Blocked, users from these trial-only tenants aren't able to search and\ncontact your users via chats, Teams calls, and meetings (using the users' authenticated\nidentities) and your users aren't able to reach users in these trial-only tenants. Users\nfrom the trial-only tenant are also removed from existing chats.\nThe recommended state for People in my organization can communicate with\naccounts in trial Teams tenant is Off.",
    "rationale": "Microsoft introduced this setting as Off by default on July 29, 2024 in order to block\nattack vectors being exploited by threat actors who have abused trial tenants. Enforcing\nthe default ensures the setting is not reenabled for any reason.\nAllowing users to communicate with unmanaged Teams users presents a potential\nsecurity threat as little effort is required by threat actors to gain access to a trial or free\nMicrosoft Teams account.\nSome real-world attacks and exploits delivered via Teams over external access\nchannels include:\n• DarkGate malware\n• Social engineering / Phishing attacks by \"Midnight Blizzard\"\n• GIFShell\n• Username enumeration",
    "impact": "There is minimal to no legitimate business need for users to communicate with accounts\nin trial tenants. For temporary or testing scenarios, alternative communication methods\nare readily available that do not require enabling this setting.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com/.\n2. Click to expand Users select External access.\n3. Select the Organization settings tab.\n4. Ensure People in my organization can communicate with accounts in\ntrial Teams tenant is set to Off.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams\n2. Run the following command:\nGet-CsTenantFederationConfiguration\nEnsure ExternalAccessWithTrialTenants is set to Blocked.",
    "expected_response": "4. Ensure People in my organization can communicate with accounts in\ntrial Teams tenant is set to Off.\nEnsure ExternalAccessWithTrialTenants is set to Blocked.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com/.\n2. Click to expand Users select External access.\n3. Select the Organization settings tab.\n4. Set People in my organization can communicate with accounts in\ntrial Teams tenant to Off.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams\n2. Run the following command:\nSet-CsTenantFederationConfiguration -ExternalAccessWithTrialTenants \"Blocked\"",
    "default_value": "Off or Blocked",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-",
      "meetings-chat?tabs=organization-settings#block-federation-with-teams-trial-only-",
      "tenants",
      "2. https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-",
      "conducts-targeted-social-engineering-over-microsoft-teams/",
      "3. https://www.bitdefender.com/en-us/blog/hotforsecurity/gifshell-attack-lets-",
      "hackers-create-reverse-shell-through-microsoft-teams-gifs"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 421,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "8.4.1",
    "title": "Ensure app permission policies are configured",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Teams apps",
    "m365_profile": "E3",
    "description": "This policy setting controls which class of apps are available for users to install.",
    "rationale": "Allowing users to install third-party or unverified apps poses a potential risk of\nintroducing malicious software to the environment.",
    "impact": "Users will only be able to install approved classes of apps.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Click to expand Teams apps select Manage apps.\n3. In the upper right click Actions > Org-wide app settings.\n4. For Microsoft apps verify that Let users install and use available\napps by default is On or less permissive.\n5. For Third-party apps verify Let users install and use available apps\nby default is Off.\n6. For Custom apps verify Let users install and use available apps by\ndefault is Off.\n7. For Custom apps verify Let users interact with custom apps in\npreview is Off.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Click to expand Teams apps select Manage apps.\n3. In the upper right click Actions > Org-wide app settings.\n4. For Microsoft apps set Let users install and use available apps by\ndefault to On or less permissive.\n5. For Third-party apps set Let users install and use available apps\nby default to Off.\n6. For Custom apps set Let users install and use available apps by\ndefault to Off.\n7. For Custom apps set Let users interact with custom apps in preview\nto Off.",
    "default_value": "Microsoft apps: On\nThird-party apps: On\nCustom apps: On",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoftteams/app-centric-management",
      "2. https://learn.microsoft.com/en-us/defender-office-365/step-by-step-",
      "guides/reducing-attack-surface-in-microsoft-teams?view=o365-",
      "worldwide#disabling-third-party--custom-apps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 426,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "8.5.1",
    "title": "Ensure anonymous users can't join a meeting",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Meetings",
    "m365_profile": "E3",
    "description": "Anonymous users are users whose identity can't be verified. They may be logged in to\nan organization without a mutual trust relationship or they may not have an account\n(guest or user). Anonymous participants appear with \"(Unverified)\" appended to their\nname in meetings.\nThese users could include:\n• Users who aren't logged in to Teams with a work or school account.\n• Users from non-trusted organizations (as configured in external access) and from\norganizations that you trust but which don't trust your organization. When\ndefining trusted organizations for external meetings and chat, ensure both\norganizations allow each other's domains. Meeting organizers and participants\nshould have user policies that allow external access. These settings prevent\nattendees from being considered anonymous due to external access settings.\nFor details, see IT Admins - Manage external meetings and chat with people and\norganizations using Microsoft identities\nThe recommended state is Anonymous users can join a meeting unverified set\nto Off.",
    "rationale": "For meetings that could contain sensitive information, it is best to allow the meeting\norganizer to vet anyone not directly sent an invite before admitting them to the meeting.\nThis will also prevent the anonymous user from using the meeting link to have meetings\nat unscheduled times.\nNote: Those companies that don't normally operate at a Level 2 environment, but do\ndeal with sensitive information, may want to consider this policy setting.",
    "impact": "Individuals who were not sent or forwarded a meeting invite will not be able to join the\nmeeting automatically.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under meeting join & lobby verify that Anonymous users can join a\nmeeting unverified is set to Off.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to verify the recommended state:\nGet-CsTeamsMeetingPolicy -Identity Global | fl\nAllowAnonymousUsersToJoinMeeting\n3. Ensure the returned value is False.",
    "expected_response": "meeting unverified is set to Off.\n3. Ensure the returned value is False.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under meeting join & lobby set Anonymous users can join a meeting\nunverified to Off.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams\n2. Run the following command to set the recommended state:\nSet-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToJoinMeeting\n$false",
    "default_value": "On (True)",
    "detection_commands": [],
    "remediation_commands": [
      "$false"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/step-by-step-",
      "guides/reducing-attack-surface-in-microsoft-teams?view=o365-",
      "worldwide#configure-meeting-settings",
      "2. https://learn.microsoft.com/en-us/microsoftteams/settings-policies-",
      "reference?WT.mc_id=TeamsAdminCenterCSH#meeting-join--lobby",
      "3. https://learn.microsoft.com/en-us/MicrosoftTeams/configure-meetings-sensitive-",
      "protection",
      "4. https://learn.microsoft.com/en-us/microsoftteams/anonymous-users-in-meetings",
      "5. https://learn.microsoft.com/en-us/microsoftteams/plan-meetings-external-",
      "participants"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 429,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "8.5.2",
    "title": "Ensure anonymous users and dial-in callers can't start a meeting",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Meetings",
    "m365_profile": "E3",
    "description": "This policy setting controls if an anonymous participant can start a Microsoft Teams\nmeeting without someone in attendance. Anonymous users and dial-in callers must wait\nin the lobby until the meeting is started by someone in the organization or an external\nuser from a trusted organization.\nAnonymous participants are classified as:\n• Participants who are not logged in to Teams with a work or school account.\n• Participants from non-trusted organizations (as configured in external access).\n• Participants from organizations where there is not mutual trust.\nNote: This setting only applies when Who can bypass the lobby is set to Everyone.\nIf the anonymous users can join a meeting organization-level setting or meeting\npolicy is Off, this setting only applies to dial-in callers.",
    "rationale": "Not allowing anonymous participants to automatically join a meeting reduces the risk of\nmeeting spamming.",
    "impact": "Anonymous participants will not be able to start a Microsoft Teams meeting.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under meeting join & lobby verify that Anonymous users and dial-in\ncallers can start a meeting is set to Off.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to verify the recommended state:\nGet-CsTeamsMeetingPolicy -Identity Global | fl\nAllowAnonymousUsersToStartMeeting\n3. Ensure the returned value is False.",
    "expected_response": "callers can start a meeting is set to Off.\n3. Ensure the returned value is False.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under meeting join & lobby set Anonymous users and dial-in callers\ncan start a meeting to Off.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to set the recommended state:\nSet-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToStartMeeting\n$false",
    "default_value": "Off (False)",
    "detection_commands": [],
    "remediation_commands": [
      "$false"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoftteams/anonymous-users-in-meetings",
      "2. https://learn.microsoft.com/en-us/microsoftteams/who-can-bypass-meeting-",
      "lobby#overview-of-lobby-settings-and-policies"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 432,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "8.5.3",
    "title": "Ensure only people in my org can bypass the lobby",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Meetings",
    "m365_profile": "E3",
    "description": "This policy setting controls who can join a meeting directly and who must wait in the\nlobby until they're admitted by an organizer, co-organizer, or presenter of the meeting.\nThe recommended state is People who were invited or more restrictive.",
    "rationale": "For meetings that could contain sensitive information, it is best to allow the meeting\norganizer to vet anyone not directly sent an invite before admitting them to the meeting.\nThis will also prevent the anonymous user from using the meeting link to have meetings\nat unscheduled times.",
    "impact": "Individuals who are not part of the organization will have to wait in the lobby until they're\nadmitted by an organizer, co-organizer, or presenter of the meeting.\nAny individual who dials into the meeting regardless of status will also have to wait in\nthe lobby. This includes internal users who are considered unauthenticated when dialing\nin.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under meeting join & lobby verify Who can bypass the lobby is set to\nPeople who were invited or a more restrictive value: People in my org,\nOnly organizers and co-organizers.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to verify the recommended state:\nGet-CsTeamsMeetingPolicy -Identity Global | fl AutoAdmittedUsers\n3. Ensure the returned value is InvitedUsers or more restrictive:\nEveryoneInCompanyExcludingGuests, OrganizerOnly.",
    "expected_response": "4. Under meeting join & lobby verify Who can bypass the lobby is set to\n3. Ensure the returned value is InvitedUsers or more restrictive:",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under meeting join & lobby set Who can bypass the lobby to People who\nwere invited or a more restrictive value: People in my org, Only\norganizers and co-organizers.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to set the recommended state:\nSet-CsTeamsMeetingPolicy -Identity Global -AutoAdmittedUsers \"InvitedUsers\"\nNote: More restrictive values EveryoneInCompanyExcludingGuests or\nOrganizerOnly are also in compliance.",
    "default_value": "People in my org and guests (EveryoneInCompany)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoftteams/who-can-bypass-meeting-",
      "lobby#overview-of-lobby-settings-and-policies",
      "2. https://learn.microsoft.com/en-us/powershell/module/skype/set-",
      "csteamsmeetingpolicy?view=skype-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 435,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "8.5.4",
    "title": "Ensure users dialing in can't bypass the lobby",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This policy setting controls if users who dial in by phone can join the meeting directly or\nmust wait in the lobby. Admittance to the meeting from the lobby is authorized by the\nmeeting organizer, co-organizer, or presenter of the meeting.",
    "rationale": "For meetings that could contain sensitive information, it is best to allow the meeting\norganizer to vet anyone not directly from the organization.",
    "impact": "Individuals who are dialing in to the meeting must wait in the lobby until a meeting\norganizer, co-organizer, or presenter admits them.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under meeting join & lobby verify that People dialing in can bypass the\nlobby is set to Off.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to verify the recommended state:\nGet-CsTeamsMeetingPolicy -Identity Global | fl AllowPSTNUsersToBypassLobby\n3. Ensure the value is False.",
    "expected_response": "lobby is set to Off.\n3. Ensure the value is False.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under meeting join & lobby set People dialing in can bypass the lobby\nto Off.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to set the recommended state:\nSet-CsTeamsMeetingPolicy -Identity Global -AllowPSTNUsersToBypassLobby $false",
    "default_value": "Off (False)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoftteams/who-can-bypass-meeting-",
      "lobby#overview-of-lobby-settings-and-policies",
      "2. https://learn.microsoft.com/en-us/powershell/module/skype/set-",
      "csteamsmeetingpolicy?view=skype-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 438,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2"
    ]
  },
  {
    "cis_id": "8.5.5",
    "title": "Ensure meeting chat does not allow anonymous users",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This policy setting controls who has access to read and write chat messages during a\nmeeting.",
    "rationale": "Ensuring that only authorized individuals can read and write chat messages during a\nmeeting reduces the risk that a malicious user can inadvertently show content that is not\nappropriate or view sensitive information.",
    "impact": "Only authorized individuals will be able to read and write chat messages during a\nmeeting.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under meeting engagement verify that Meeting chat is set to On for\neveryone but anonymous users or a more restrictive value: In-meeting only\nexcept anonymous or Off.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to verify the recommended state:\nGet-CsTeamsMeetingPolicy -Identity Global | fl MeetingChatEnabledType\n3. Ensure the returned value is EnabledExceptAnonymous or a more restrictive\nvalue EnabledInMeetingOnlyForAllExceptAnonymous or Disabled.",
    "expected_response": "4. Under meeting engagement verify that Meeting chat is set to On for\n3. Ensure the returned value is EnabledExceptAnonymous or a more restrictive",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under meeting engagement set Meeting chat to On for everyone but\nanonymous users.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to set the minimum recommended state:\nSet-CsTeamsMeetingPolicy -Identity Global -MeetingChatEnabledType\n\"EnabledExceptAnonymous\"\nNote: The audit section outlines additional compliant states which are more restrictive\nthan the recommended state.",
    "default_value": "On for everyone (Enabled)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/powershell/module/skype/set-",
      "csteamsmeetingpolicy?view=skype-ps#-meetingchatenabledtype"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 440,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "8.5.6",
    "title": "Ensure only organizers and co-organizers can present",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This policy setting controls who can present in a Teams meeting.\nNote: Organizers and co-organizers can change this setting when the meeting is set up.",
    "rationale": "Ensuring that only authorized individuals are able to present reduces the risk that a\nmalicious user can inadvertently show content that is not appropriate.",
    "impact": "Only organizers and co-organizers will be able to present without being granted\npermission.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under content sharing verify Who can present is set to Only organizers\nand co-organizers.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to verify the recommended state:\nGet-CsTeamsMeetingPolicy -Identity Global | fl DesignatedPresenterRoleMode\n3. Ensure the returned value is OrganizerOnlyUserOverride.",
    "expected_response": "4. Under content sharing verify Who can present is set to Only organizers\n3. Ensure the returned value is OrganizerOnlyUserOverride.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under content sharing set Who can present to Only organizers and co-\norganizers.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to set the recommended state:\nSet-CsTeamsMeetingPolicy -Identity Global -DesignatedPresenterRoleMode\n\"OrganizerOnlyUserOverride\"",
    "default_value": "Everyone (EveryoneUserOverride)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-US/microsoftteams/meeting-who-present-request-",
      "control",
      "2. https://learn.microsoft.com/en-us/microsoftteams/meeting-who-present-request-",
      "control#manage-who-can-present",
      "3. https://learn.microsoft.com/en-us/defender-office-365/step-by-step-",
      "guides/reducing-attack-surface-in-microsoft-teams?view=o365-",
      "worldwide#configure-meeting-settings-restrict-presenters",
      "4. https://learn.microsoft.com/en-us/powershell/module/skype/set-",
      "csteamsmeetingpolicy?view=skype-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 442,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "8.5.7",
    "title": "Ensure external participants can't give or request control",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This policy setting allows control of who can present in meetings and who can request\ncontrol of the presentation while a meeting is underway.",
    "rationale": "Ensuring that only authorized individuals and not external participants are able to\npresent and request control reduces the risk that a malicious user can inadvertently\nshow content that is not appropriate.\nExternal participants are categorized as follows: external users, guests, and anonymous\nusers.",
    "impact": "External participants will not be able to present or request control during the meeting.\nWarning: This setting also affects webinars.\nNote: At this time, to give and take control of shared content during a meeting, both\nparties must be using the Teams desktop client. Control isn't supported when either\nparty is running Teams in a browser.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under content sharing verify that External participants can give or\nrequest control is Off.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to verify the recommended state:\nGet-CsTeamsMeetingPolicy -Identity Global | fl\nAllowExternalParticipantGiveRequestControl\n3. Ensure the returned value is False.",
    "expected_response": "3. Ensure the returned value is False.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under content sharing set External participants can give or request\ncontrol to Off.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to set the recommended state:\nSet-CsTeamsMeetingPolicy -Identity Global -\nAllowExternalParticipantGiveRequestControl $false",
    "default_value": "Off (False)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoftteams/meeting-who-present-request-",
      "control",
      "2. https://learn.microsoft.com/en-us/powershell/module/skype/set-",
      "csteamsmeetingpolicy?view=skype-ps"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 444,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "8.5.8",
    "title": "Ensure external meeting chat is off",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This meeting policy setting controls whether users can read or write messages in\nexternal meeting chats with untrusted organizations. If an external organization is on the\nlist of trusted organizations this setting will be ignored.",
    "rationale": "Restricting access to chat in meetings hosted by external organizations limits the\nopportunity for an exploit like GIFShell or DarkGate malware from being delivered to\nusers.",
    "impact": "When joining external meetings users will be unable to read or write chat messages in\nTeams meetings with organizations that they don't have a trust relationship with. This\nwill completely remove the chat functionality in meetings. From an I.T. perspective both\nthe upkeep of adding new organizations to the trusted list and the decision-making\nprocess behind whether to trust or not trust an external partner will increase time\nexpenditure.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under meeting engagement verify that External meeting chat is set to Off.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to verify the recommended state:\nGet-CsTeamsMeetingPolicy -Identity Global | fl\nAllowExternalNonTrustedMeetingChat\n3. Ensure the returned value is False.",
    "expected_response": "4. Under meeting engagement verify that External meeting chat is set to Off.\n3. Ensure the returned value is False.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under meeting engagement set External meeting chat to Off.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to set the recommended state:\nSet-CsTeamsMeetingPolicy -Identity Global -AllowExternalNonTrustedMeetingChat\n$false",
    "default_value": "On(True)",
    "detection_commands": [],
    "remediation_commands": [
      "$false"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoftteams/settings-policies-",
      "reference#meeting-engagement"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 447,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "8.5.9",
    "title": "Ensure meeting recording is off by default",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Apply Secure Design Principles in Application",
    "m365_profile": "E3",
    "description": "This setting controls the ability for a user to initiate a recording of a meeting in progress.\nThe recommended state is Off for the Global (Org-wide default) meeting policy.",
    "rationale": "Disabling meeting recordings in the Global meeting policy ensures that only authorized\nusers, such as organizers, co-organizers, and leads, can initiate a recording. This\nmeasure helps safeguard sensitive information by preventing unauthorized individuals\nfrom capturing and potentially sharing meeting content. Restricting recording\ncapabilities to specific roles allows organizations to exercise greater control over what is\nrecorded, aligning it with the meeting's confidentiality requirements.\nNote: Creating a separate policy for users or groups who are allowed to record is\nexpected and in compliance. This control is only for the default meeting policy.",
    "impact": "If there are no additional policies allowing anyone to record, then recording will\neffectively be disabled.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under Recording & transcription verify that Meeting recording is set to Off.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to verify the recommended state:\nGet-CsTeamsMeetingPolicy -Identity Global | fl AllowCloudRecording\n3. Ensure the returned value is False.",
    "expected_response": "4. Under Recording & transcription verify that Meeting recording is set to Off.\n3. Ensure the returned value is False.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Meetings to open the meeting settings section.\n4. Under Recording & transcription set Meeting recording to Off.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following command to set the recommended state:\nSet-CsTeamsMeetingPolicy -Identity Global -AllowCloudRecording $false",
    "default_value": "On (True)",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/microsoftteams/settings-policies-",
      "reference#recording--transcription"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 449,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "8.6.1",
    "title": "Ensure users can report security concerns in Teams",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "teams",
    "domain": "Microsoft Teams admin center",
    "subdomain": "Messaging",
    "m365_profile": "E3",
    "description": "User reporting settings allow a user to report a message as malicious for further\nanalysis. This recommendation is composed of 3 different settings and all be configured\nto pass:\n• In the Teams admin center: On by default and controls whether users are able\nto report messages from Teams. When this setting is turned off, users can't\nreport messages within Teams, so the corresponding setting in the Microsoft 365\nDefender portal is irrelevant.\n• In the Microsoft 365 Defender portal: On by default for new tenants. Existing\ntenants need to enable it. If user reporting of messages is turned on in the\nTeams admin center, it also needs to be turned on the Defender portal for user\nreported messages to show up correctly on the User reported tab on the\nSubmissions page.\n• Defender - Report message destinations: This applies to more than just\nMicrosoft Teams and allows for an organization to keep their reports contained.\nDue to how the parameters are configured on the backend it is included in this\nassessment as a requirement.",
    "rationale": "Users will be able to more quickly and systematically alert administrators of suspicious\nmalicious messages within Teams. The content of these messages may be sensitive in\nnature and therefore should be kept within the organization and not shared with\nMicrosoft without first consulting company policy.\nNote:\n• The reported message remains visible to the user in the Teams client.\n• Users can report the same message multiple times.\n• The message sender isn't notified that messages were reported.",
    "impact": "Enabling message reporting has an impact beyond just addressing security concerns.\nWhen users of the platform report a message, the content could include messages that\nare threatening or harassing in nature, possibly stemming from colleagues.\nDue to this the security staff responsible for reviewing and acting on these reports\nshould be equipped with the skills to discern and appropriately direct such messages to\nthe relevant departments, such as Human Resources (HR).",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Messaging to open the messaging settings section.\n4. Ensure Report a security concern is On.\n5. Next, navigate to Microsoft 365 Defender https://security.microsoft.com/\n6. Click on Settings > Email & collaboration > User reported settings.\n7. Scroll to Microsoft Teams.\n8. Ensure Monitor reported messages in Microsoft Teams is checked.\n9. Ensure Send reported messages to: is set to My reporting mailbox only\nwith report email addresses defined for authorized staff.\nTo audit using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Run the following cmdlet for to assess Teams:\nGet-CsTeamsMessagingPolicy -Identity Global | fl\nAllowSecurityEndUserReporting\n3. Ensure the value returned is True.\n4. Connect to Exchange Online PowerShell using Connect-ExchangeOnline.\n5. Run this cmdlet to assess Defender:\nGet-ReportSubmissionPolicy | fl Report*\n6. Ensure the output matches the following values with organization specific email\naddresses:\nReportJunkToCustomizedAddress               : True\nReportNotJunkToCustomizedAddress            : True\nReportPhishToCustomizedAddress              : True\nReportJunkAddresses                         : {SOC@contoso.com}\nReportNotJunkAddresses                      : {SOC@contoso.com}\nReportPhishAddresses                        : {SOC@contoso.com}\nReportChatMessageEnabled                    : False\nReportChatMessageToCustomizedAddressEnabled : True",
    "expected_response": "4. Ensure Report a security concern is On.\n8. Ensure Monitor reported messages in Microsoft Teams is checked.\n9. Ensure Send reported messages to: is set to My reporting mailbox only\n3. Ensure the value returned is True.\n6. Ensure the output matches the following values with organization specific email",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Teams admin center\nhttps://admin.teams.microsoft.com.\n2. Select Settings & policies > Global (Org-wide default) settings.\n3. Select Messaging to open the messaging settings section.\n4. Set Report a security concern to On.\n5. Next, navigate to Microsoft 365 Defender https://security.microsoft.com/\n6. Click on Settings > Email & collaboration > User reported settings.\n7. Scroll to Microsoft Teams.\n8. Check Monitor reported messages in Microsoft Teams and Save.\n9. Set Send reported messages to: to My reporting mailbox only with\nreports configured to be sent to authorized staff.\nTo remediate using PowerShell:\n1. Connect to Teams PowerShell using Connect-MicrosoftTeams.\n2. Connect to Exchange Online PowerShell using Connect-ExchangeOnline.\n3. Run the following cmdlet:\nSet-CsTeamsMessagingPolicy -Identity Global -AllowSecurityEndUserReporting\n$true\n4. To configure the Defender reporting policies, edit and run this script:\n$usersub = \"userreportedmessages@fabrikam.com\" # Change this.\n$params = @{\nIdentity                         = \"DefaultReportSubmissionPolicy\"\nEnableReportToMicrosoft          = $false\nReportChatMessageEnabled         = $false\nReportChatMessageToCustomizedAddressEnabled = $true\nReportJunkToCustomizedAddress    = $true\nReportNotJunkToCustomizedAddress = $true\nReportPhishToCustomizedAddress   = $true\nReportJunkAddresses              = $usersub\nReportNotJunkAddresses           = $usersub\nReportPhishAddresses             = $usersub\n}\nSet-ReportSubmissionPolicy @params\nNew-ReportSubmissionRule -Name DefaultReportSubmissionRule -\nReportSubmissionPolicy DefaultReportSubmissionPolicy -SentTo $usersub",
    "default_value": "On (True)\nReport message destination: Microsoft Only",
    "detection_commands": [],
    "remediation_commands": [
      "$true",
      "$usersub = \"userreportedmessages@fabrikam.com\" # Change this. $params = @{"
    ],
    "references": [
      "1. https://learn.microsoft.com/en-us/defender-office-365/submissions-",
      "teams?view=o365-worldwide"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 452,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "9.1.1",
    "title": "Ensure guest user access is restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "fabric",
    "domain": "Microsoft Fabric",
    "subdomain": "Tenant settings",
    "m365_profile": "E3",
    "description": "This setting allows business-to-business (B2B) guests access to Microsoft Fabric, and\ncontents that they have permissions to. With the setting turned off, B2B guest users\nreceive an error when trying to access Power BI.\nThe recommended state is Enabled for a subset of the organization or\nDisabled.",
    "rationale": "Establishing and enforcing a dedicated security group prevents unauthorized access to\nMicrosoft Fabric for guests collaborating in Azure that are new or assigned guest status\nfrom other applications. This upholds the principle of least privilege and uses role-based\naccess control (RBAC). These security groups can also be used for tasks like\nconditional access, enhancing risk management and user accountability across the\norganization.",
    "impact": "Security groups will need to be more closely tended to and monitored.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Export and Sharing settings.\n4. Ensure that Guest users can access Microsoft Fabric adheres to one of\nthese states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.\nTo audit using PowerShell:\n1. Inspect the results of the Get-CISFabricTenantSettings function from the\nsection overview.\n2. Locate the settingName AllowGuestUserToAccessSharedContent in the\noutput.\n3. Verify that the properties adhere to one of the following compliant configurations:\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nat least one security group.\n4. If neither condition is met, the setting is non-compliant.\nNote: If the Specific security groups setting is not enabled then the\nenabledSecurityGroups property does not appear in the output.",
    "expected_response": "4. Ensure that Guest users can access Microsoft Fabric adheres to one of\noutput.\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nenabledSecurityGroups property does not appear in the output.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Export and Sharing settings.\n4. Set Guest users can access Microsoft Fabric to one of these states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.",
    "default_value": "Enabled for the entire organization",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-export-",
      "sharing"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 462,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4"
    ]
  },
  {
    "cis_id": "9.1.2",
    "title": "Ensure external user invitations are restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "fabric",
    "domain": "Microsoft Fabric",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This setting helps organizations choose whether new external users can be invited to\nthe organization through Power BI sharing, permissions, and subscription experiences.\nThis setting only controls the ability to invite through Power BI.\nThe recommended state is Enabled for a subset of the organization or\nDisabled.\nNote: To invite external users to the organization, the user must also have the Microsoft\nEntra Guest Inviter role.",
    "rationale": "Establishing and enforcing a dedicated security group prevents unauthorized access to\nMicrosoft Fabric for guests collaborating in Azure that are new or assigned guest status\nfrom other applications. This upholds the principle of least privilege and uses role-based\naccess control (RBAC). These security groups can also be used for tasks like\nconditional access, enhancing risk management and user accountability across the\norganization.",
    "impact": "Guest user invitations will be limited to only specific employees.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Export and Sharing settings.\n4. Ensure that Users can invite guest users to collaborate through\nitem sharing and permissions adheres to one of these states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.\nTo audit using PowerShell:\n1. Inspect the results of the Get-CISFabricTenantSettings function from the\nsection overview.\n2. Locate the settingName ExternalSharingV2 in the output.\n3. Verify that the properties adhere to one of the following compliant configurations:\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nat least one security group.\n4. If neither condition is met, the setting is non-compliant.\nNote: If the Specific security groups setting is not enabled then the\nenabledSecurityGroups property does not appear in the output.",
    "expected_response": "4. Ensure that Users can invite guest users to collaborate through\n2. Locate the settingName ExternalSharingV2 in the output.\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nenabledSecurityGroups property does not appear in the output.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Export and Sharing settings.\n4. Set Users can invite guest users to collaborate through item\nsharing and permissions to one of these states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.",
    "default_value": "Enabled for the entire organization",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-export-",
      "sharing",
      "2. https://learn.microsoft.com/en-us/power-bi/enterprise/service-admin-azure-ad-",
      "b2b#invite-guest-users"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 465,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4"
    ]
  },
  {
    "cis_id": "9.1.3",
    "title": "Ensure guest access to content is restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "fabric",
    "domain": "Microsoft Fabric",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This setting allows Microsoft Entra B2B guest users to have full access to the browsing\nexperience using the left-hand navigation pane in the organization. Guest users who\nhave been assigned workspace roles or specific item permissions will continue to have\nthose roles and/or permissions, even if this setting is disabled.\nThe recommended state is Enabled for a subset of the organization or\nDisabled.",
    "rationale": "Establishing and enforcing a dedicated security group prevents unauthorized access to\nMicrosoft Fabric for guests collaborating in Entra that are new or assigned guest status\nfrom other applications. This upholds the principle of least privilege and uses role-based\naccess control (RBAC). These security groups can also be used for tasks like\nconditional access, enhancing risk management and user accountability across the\norganization.",
    "impact": "Security groups will need to be more closely tended to and monitored.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Export and Sharing settings.\n4. Ensure that Guest users can browse and access Fabric content adheres\nto one of these states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.\nTo audit using PowerShell:\n1. Inspect the results of the Get-CISFabricTenantSettings function from the\nsection overview.\n2. Locate the settingName ElevatedGuestsTenant in the output.\n3. Verify that the properties adhere to one of the following compliant configurations:\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nat least one security group.\n4. If neither condition is met, the setting is non-compliant.\nNote: If the Specific security groups setting is not enabled then the\nenabledSecurityGroups property does not appear in the output.",
    "expected_response": "4. Ensure that Guest users can browse and access Fabric content adheres\n2. Locate the settingName ElevatedGuestsTenant in the output.\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nenabledSecurityGroups property does not appear in the output.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Export and Sharing settings.\n4. Set Guest users can browse and access Fabric content to one of these\nstates:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.",
    "default_value": "Disabled",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-export-",
      "sharing"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 468,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4"
    ]
  },
  {
    "cis_id": "9.1.4",
    "title": "Ensure 'Publish to web' is restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "fabric",
    "domain": "Microsoft Fabric",
    "subdomain": "Protect Information through Access Control Lists",
    "m365_profile": "E3",
    "description": "Power BI enables users to share reports and materials directly on the internet from both\nthe application's desktop version and its web user interface. This functionality generates\na publicly reachable web link that doesn't necessitate authentication or the need to be\nan Entra ID user in order to access and view it.\nThe recommended state is Enabled for a subset of the organization or\nDisabled.",
    "rationale": "When using Publish to Web anyone on the Internet can view a published report or\nvisual. Viewing requires no authentication. It includes viewing detail-level data that your\nreports aggregate. By disabling the feature, restricting access to certain users and\nallowing existing embed codes organizations can mitigate the exposure of confidential\nor proprietary information.",
    "impact": "Depending on the organization's utilization administrators may experience more\noverhead managing embed codes, and requests.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Export and Sharing settings.\n4. Ensure that Publish to web adheres to one of these states:\no State 1: Disabled\no State 2: Enabled with Choose how embed codes work set to Only\nallow existing codes AND Specific security groups selected and\ndefined\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.\nTo audit using PowerShell:\n1. Inspect the results of the Get-CISFabricTenantSettings function from the\nsection overview.\n2. Locate the settingName PublishToWebPublishToWeb in the output.\n3. Verify that the properties adhere to one of the following compliant configurations:\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND createP2w is set to false AND\nenabledSecurityGroups contains at least one security group.\n4. If neither condition is met, the setting is non-compliant.\nNote: The createP2w property can be found nested under properties.",
    "expected_response": "4. Ensure that Publish to web adheres to one of these states:\n2. Locate the settingName PublishToWebPublishToWeb in the output.\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND createP2w is set to false AND",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Export and Sharing settings.\n4. Set Publish to web to one of these states:\no State 1: Disabled\no State 2: Enabled with Choose how embed codes work set to Only\nallow existing codes AND Specific security groups selected and\ndefined\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.",
    "default_value": "Enabled for the entire organization\nOnly allow existing codes",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/power-bi/collaborate-share/service-publish-to-",
      "web",
      "2. https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-export-",
      "sharing#publish-to-web"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 471,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4"
    ]
  },
  {
    "cis_id": "9.1.5",
    "title": "Ensure 'Interact with and share R and Python' visuals is 'Disabled'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "fabric",
    "domain": "Microsoft Fabric",
    "subdomain": "Apply Secure Design Principles in Application",
    "m365_profile": "E3",
    "description": "Power BI allows the integration of R and Python scripts directly into visuals. This feature\nallows data visualizations by incorporating custom calculations, statistical analyses,\nmachine learning models, and more using R or Python scripts. Custom visuals can be\ncreated by embedding them directly into Power BI reports. Users can then interact with\nthese visuals and see the results of the custom code within the Power BI interface.",
    "rationale": "Disabling this feature can reduce the attack surface by preventing potential malicious\ncode execution leading to data breaches, or unauthorized access. The potential for\nsensitive or confidential data being leaked to unintended users is also increased with\nthe use of scripts.",
    "impact": "Use of R and Python scripting will require exceptions for developers, along with more\nstringent code review.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to R and Python visuals settings.\n4. Ensure that Interact with and share R and Python visuals is Disabled\nTo audit using PowerShell:\n1. Inspect the results of the Get-CISFabricTenantSettings function from the\nsection overview.\n2. Locate the settingName RScriptVisual in the output.\n3. Verify that enabled is false.",
    "expected_response": "4. Ensure that Interact with and share R and Python visuals is Disabled\n2. Locate the settingName RScriptVisual in the output.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to R and Python visuals settings.\n4. Set Interact with and share R and Python visuals to Disabled",
    "default_value": "Enabled",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-r-python-",
      "visuals",
      "2. https://learn.microsoft.com/en-us/power-bi/visuals/service-r-visuals",
      "3. https://www.r-project.org/"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 474,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "9.1.6",
    "title": "Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "fabric",
    "domain": "Microsoft Fabric",
    "subdomain": "Uninstall or Disable Unnecessary Services on",
    "m365_profile": "E3",
    "description": "Information protection tenant settings help to protect sensitive information in the Power\nBI tenant. Allowing and applying sensitivity labels to content ensures that information is\nonly seen and accessed by the appropriate users.\nThe recommended state is Enabled or Enabled for a subset of the\norganization.\nNote: Sensitivity labels and protection are only applied to files exported to Excel,\nPowerPoint, or PDF files, that are controlled by \"Export to Excel\" and \"Export reports as\nPowerPoint presentation or PDF documents\" settings. All other export and sharing\noptions do not support the application of sensitivity labels and protection.\nNote 2: There are some prerequisite steps that need to be completed in order to fully\nutilize labeling. See here.",
    "rationale": "Establishing data classifications and affixing labels to data at creation enables\norganizations to discern the data's criticality, sensitivity, and value. This initial\nidentification enables the implementation of appropriate protective measures, utilizing\ntechnologies like Data Loss Prevention (DLP) to avert inadvertent exposure and\nenforcing access controls to safeguard against unauthorized access.\nThis practice can also promote user awareness and responsibility in regard to the\nnature of the data they interact with. Which in turn can foster awareness in other areas\nof data management across the organization.",
    "impact": "Additional license requirements like Power BI Pro are required, as outlined in the\nLicensed and requirements page linked in the description and references sections.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Information protection.\n4. Ensure that Allow users to apply sensitivity labels for content\nadheres to one of these states:\no State 1: Enabled\no State 2: Enabled with Specific security groups selected and defined.\nTo audit using PowerShell:\n1. Inspect the results of the Get-CISFabricTenantSettings function from the\nsection overview.\n2. Locate the settingName EimInformationProtectionEdit in the output.\n3. Verify that the properties adhere to one of the following compliant configurations:\no Option 1: enabled is set to true.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nat least one security group.\n4. If neither condition is met, the setting is non-compliant.\nNote: If the Specific security groups setting is not enabled then the\nenabledSecurityGroups property does not appear in the output.",
    "expected_response": "4. Ensure that Allow users to apply sensitivity labels for content\n2. Locate the settingName EimInformationProtectionEdit in the output.\no Option 1: enabled is set to true.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nenabledSecurityGroups property does not appear in the output.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Information protection.\n4. Set Allow users to apply sensitivity labels for content to one of\nthese states:\no State 1: Enabled\no State 2: Enabled with Specific security groups selected and defined.",
    "default_value": "Disabled",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/power-bi/enterprise/service-security-enable-",
      "data-sensitivity-labels",
      "2. https://learn.microsoft.com/en-us/fabric/governance/data-loss-prevention-",
      "overview",
      "3. https://learn.microsoft.com/en-us/power-bi/enterprise/service-security-enable-",
      "data-sensitivity-labels#licensing-and-requirements"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 476,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D4"
    ]
  },
  {
    "cis_id": "9.1.7",
    "title": "Ensure shareable links are restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "fabric",
    "domain": "Microsoft Fabric",
    "subdomain": "Establish and Maintain a Data Classification Scheme",
    "m365_profile": "E3",
    "description": "Creating a shareable link allows a user to create a link to a report or dashboard, then\nadd that link to an email or another messaging application.\nThere are 3 options that can be selected when creating a shareable link:\n• People in your organization\n• People with existing access\n• Specific people\nThis setting solely deals with restrictions to People in the organization. External\nusers by default are not included in any of these categories, and therefore cannot use\nany of these links regardless of the state of this setting.\nThe recommended state is Enabled for a subset of the organization or\nDisabled.",
    "rationale": "While external users are unable to utilize shareable links, disabling or restricting this\nfeature ensures that a user cannot generate a link accessible by individuals within the\nsame organization who lack the necessary clearance to the shared data. For example,\na member of Human Resources intends to share sensitive information with a particular\nemployee or another colleague within their department. The owner would be prompted\nto specify either People with existing access or Specific people when\ngenerating the link requiring the person clicking the link to pass a first layer access\ncontrol list. This measure along with proper file and folder permissions can help prevent\nunintended access and potential information leakage.",
    "impact": "If the setting is Enabled then only specific people in the organization would be allowed\nto create general links viewable by the entire organization.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Export and Sharing settings.\n4. Ensure that Allow shareable links to grant access to everyone in\nyour organization adheres to one of these states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.\nTo audit using PowerShell:\n1. Inspect the results of the Get-CISFabricTenantSettings function from the\nsection overview.\n2. Locate the settingName ShareLinkToEntireOrg in the output.\n3. Verify that the properties adhere to one of the following compliant configurations:\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nat least one security group.\n4. If neither condition is met, the setting is non-compliant.\nNote: If the Specific security groups setting is not enabled then the\nenabledSecurityGroups property does not appear in the output.",
    "expected_response": "4. Ensure that Allow shareable links to grant access to everyone in\n2. Locate the settingName ShareLinkToEntireOrg in the output.\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nenabledSecurityGroups property does not appear in the output.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Export and Sharing settings.\n4. Set Allow shareable links to grant access to everyone in your\norganization to one of these states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.",
    "default_value": "Enabled for the entire organization",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/power-bi/collaborate-share/service-share-",
      "dashboards?wt.mc_id=powerbi_inproduct_sharedialog#link-settings",
      "2. https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-export-",
      "sharing"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 479,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4"
    ]
  },
  {
    "cis_id": "9.1.8",
    "title": "Ensure enabling of external data sharing is restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "fabric",
    "domain": "Microsoft Fabric",
    "subdomain": "Configure Data Access Control Lists",
    "m365_profile": "E3",
    "description": "Power BI admins can specify which users or user groups can share datasets externally\nwith guests from a different tenant through the in-place mechanism. Disabling this\nsetting prevents any user from sharing datasets externally by restricting the ability of\nusers to turn on external sharing for datasets they own or manage.\nThe recommended state is Enabled for a subset of the organization or\nDisabled.",
    "rationale": "Establishing and enforcing a dedicated security group prevents unauthorized access to\nMicrosoft Fabric for guests collaborating in Azure that are new or from other\napplications. This upholds the principle of least privilege and uses role-based access\ncontrol (RBAC). These security groups can also be used for tasks like conditional\naccess, enhancing risk management and user accountability across the organization.",
    "impact": "Security groups will need to be more closely tended to and monitored.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Export and Sharing settings.\n4. Ensure that Allow specific users to turn on external data sharing\nadheres to one of these states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.\nTo audit using PowerShell:\n1. Inspect the results of the Get-CISFabricTenantSettings function from the\nsection overview.\n2. Locate the settingName EnableDatasetInPlaceSharing in the output.\n3. Verify that the properties adhere to one of the following compliant configurations:\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nat least one security group.\n4. If neither condition is met, the setting is non-compliant.\nNote: If the Specific security groups setting is not enabled then the\nenabledSecurityGroups property does not appear in the output.",
    "expected_response": "4. Ensure that Allow specific users to turn on external data sharing\n2. Locate the settingName EnableDatasetInPlaceSharing in the output.\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nenabledSecurityGroups property does not appear in the output.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Export and Sharing settings.\n4. Set Allow specific users to turn on external data sharing to one of\nthese states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.",
    "default_value": "Enabled for the entire organization",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-export-",
      "sharing"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 482,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4"
    ]
  },
  {
    "cis_id": "9.1.9",
    "title": "Ensure 'Block ResourceKey Authentication' is 'Enabled'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "fabric",
    "domain": "Microsoft Fabric",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "m365_profile": "E3",
    "description": "This setting blocks the use of resource key based authentication. The Block\nResourceKey Authentication setting applies to streaming and PUSH datasets. If blocked\nusers will not be allowed to send data to streaming and PUSH datasets using the API\nwith a resource key.\nThe recommended state is Enabled.",
    "rationale": "Resource keys are a form of authentication that allows users to access Power BI\nresources (such as reports, dashboards, and datasets) without requiring individual user\naccounts. While convenient, this method bypasses the organization's centralized\nidentity and access management controls. Enabling ensures that access to Power BI\nresources is tied to the organization's authentication mechanisms, providing a more\nsecure and controlled environment.",
    "impact": "Developers will need to request a special exception in order to use this feature.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Developer settings.\n4. Ensure that Block ResourceKey Authentication is Enabled\nTo audit using PowerShell:\n1. Inspect the results of the Get-CISFabricTenantSettings function from the\nsection overview.\n2. Locate the settingName BlockResourceKeyAuthentication in the output.\n3. Verify that enabled is set to true.\nNote: If the Specific security groups setting is not enabled then the\nenabledSecurityGroups property does not appear in the output.",
    "expected_response": "4. Ensure that Block ResourceKey Authentication is Enabled\n2. Locate the settingName BlockResourceKeyAuthentication in the output.\n3. Verify that enabled is set to true.\nenabledSecurityGroups property does not appear in the output.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Developer settings.\n4. Set Block ResourceKey Authentication to Enabled",
    "default_value": "Disabled for the entire organization",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-developer",
      "2. https://learn.microsoft.com/en-us/power-bi/connect-data/service-real-time-",
      "streaming"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 485,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "9.1.10",
    "title": "Ensure access to APIs by service principals is restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "fabric",
    "domain": "Microsoft Fabric",
    "subdomain": "Uninstall or Disable Unnecessary Services on",
    "m365_profile": "E3",
    "description": "Use a service principal to access Fabric public APIs that include create, read, update,\nand delete (CRUD) operations, and are protected by a Fabric permission model.\nTo allow an app to use service principal authentication, its service principal must be\nincluded in an allowed security group. You can control who can access service\nprincipals by creating dedicated security groups and using these groups in other tenant\nsettings.\nThe recommended state is Enabled for a subset of the organization or\nDisabled.",
    "rationale": "Leaving API access unrestricted increases the attack surface in the event an adversary\ngains access to a Service Principal. APIs are a feature-rich method for programmatic\naccess to many areas of Power Bi and should be guarded closely.",
    "impact": "Service principals will need to be members of specific security groups in order to\nperform public API calls.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Developer settings.\n4. Ensure that Service principals can call Fabric public APIs adheres to\none of these states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.\nTo audit using PowerShell:\n1. Inspect the results of the Get-CISFabricTenantSettings function from the\nsection overview.\n2. Locate the settingName ServicePrincipalAccessPermissionAPIs in the\noutput.\n3. Verify that the properties adhere to one of the following compliant configurations:\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nat least one security group.\n4. If neither condition is met, the setting is non-compliant.\nNote: If the Specific security groups setting is not enabled then the\nenabledSecurityGroups property does not appear in the output.",
    "expected_response": "4. Ensure that Service principals can call Fabric public APIs adheres to\noutput.\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nenabledSecurityGroups property does not appear in the output.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Developer settings.\n4. Set Service principals can call Fabric public APIs to one of these\nstates:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.",
    "default_value": "Enabled for the entire organization",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-developer"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 488,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "9.1.11",
    "title": "Ensure service principals cannot create and use profiles",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "fabric",
    "domain": "Microsoft Fabric",
    "subdomain": "Uninstall or Disable Unnecessary Services on",
    "m365_profile": "E3",
    "description": "Service principal profiles provide a flexible solution for apps used in a multitenancy\ndeployment. The profiles enable customer data isolation and tighter security boundaries\nbetween customers that are utilizing the app.\nThe recommended state is Enabled for a subset of the organization or\nDisabled.",
    "rationale": "Service Principals should be restricted to a security group to limit which Service\nPrincipals can interact with profiles. This supports the principle of least privilege.",
    "impact": "Disabled is the default behavior.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Developer settings.\n4. Ensure that Allow service principals to create and use profiles\nadheres to one of these states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.\nTo audit using PowerShell:\n1. Inspect the results of the Get-CISFabricTenantSettings function from the\nsection overview.\n2. Locate the settingName AllowServicePrincipalsCreateAndUseProfiles in\nthe output.\n3. Verify that the properties adhere to one of the following compliant configurations:\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nat least one security group.\n4. If neither condition is met, the setting is non-compliant.\nNote: If the Specific security groups setting is not enabled then the\nenabledSecurityGroups property does not appear in the output.",
    "expected_response": "4. Ensure that Allow service principals to create and use profiles\nthe output.\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nenabledSecurityGroups property does not appear in the output.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Developer settings.\n4. Set Allow service principals to create and use profiles to one of\nthese states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.",
    "default_value": "Disabled for the entire organization",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-developer",
      "2. https://learn.microsoft.com/en-us/power-bi/developer/embedded/embed-multi-",
      "tenancy"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 491,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4"
    ]
  },
  {
    "cis_id": "9.1.12",
    "title": "Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "fabric",
    "domain": "Microsoft Fabric",
    "subdomain": "Uninstall or Disable Unnecessary Services on",
    "m365_profile": "E3",
    "description": "Use a service principal to access these Fabric APIs that aren't protected by a Fabric\npermission model.\n• Create Workspace\n• Create Connection\n• Create Deployment Pipeline\nTo allow an app to use service principal authentication, its service principal must be\nincluded in an allowed security group. You can control who can access service\nprincipals by creating dedicated security groups and using these groups in other tenant\nsettings.\nThe recommended state is Enabled for a subset of the organization or\nDisabled.",
    "rationale": "Leaving API access unrestricted increases the attack surface in the event an adversary\ngains access to a Service Principal. APIs are a feature-rich method for programmatic\naccess to many areas of Power Bi and should be guarded closely.",
    "impact": "Service principals will need to be members of specific security groups in order to\nperform public API calls.",
    "audit": "To audit using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Developer settings.\n4. Ensure that Service principals can create workspaces, connections,\nand deployment pipelines adheres to one of these states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.\nTo audit using PowerShell:\n1. Inspect the results of the Get-CISFabricTenantSettings function from the\nsection overview.\n2. Locate the settingName ServicePrincipalAccessGlobalAPIs in the output.\n3. Verify that the properties adhere to one of the following compliant configurations:\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nat least one security group.\n4. If neither condition is met, the setting is non-compliant.\nNote: If the Specific security groups setting is not enabled then the\nenabledSecurityGroups property does not appear in the output.",
    "expected_response": "4. Ensure that Service principals can create workspaces, connections,\n2. Locate the settingName ServicePrincipalAccessGlobalAPIs in the output.\no Option 1: enabled is set to false.\no Option 2: enabled is set to true AND enabledSecurityGroups contains\nenabledSecurityGroups property does not appear in the output.",
    "remediation": "To remediate using the UI:\n1. Navigate to Microsoft Fabric https://app.powerbi.com/admin-portal\n2. Select Tenant settings.\n3. Scroll to Developer settings.\n4. Set Service principals can create workspaces, connections, and\ndeployment pipelines to one of these states:\no State 1: Disabled\no State 2: Enabled with Specific security groups selected and defined.\nImportant: If the organization doesn't actively use this feature it is recommended to\nkeep it Disabled.",
    "default_value": "Disabled for the entire organization",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-developer"
    ],
    "source_pdf": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.pdf",
    "page": 494,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4"
    ]
  }
]
""")


def get_m365_cis_registry() -> list[dict]:
    """Return the complete CIS control registry as a list of dicts."""
    return M365_CIS_CONTROLS


def get_m365_control_count() -> int:
    """Return total number of CIS controls."""
    return len(M365_CIS_CONTROLS)


def get_m365_automated_count() -> int:
    """Return count of automated controls."""
    return sum(1 for c in M365_CIS_CONTROLS if c["assessment_type"] == "automated")


def get_m365_manual_count() -> int:
    """Return count of manual controls."""
    return sum(1 for c in M365_CIS_CONTROLS if c["assessment_type"] == "manual")


def get_m365_dspm_controls() -> list[dict]:
    """Return controls relevant to DSPM (Data Security Posture Management)."""
    return [c for c in M365_CIS_CONTROLS if c.get("dspm_relevant")]


def get_m365_rr_controls() -> list[dict]:
    """Return controls relevant to Ransomware Readiness."""
    return [c for c in M365_CIS_CONTROLS if c.get("rr_relevant")]


def get_m365_controls_by_service_area(service_area: str) -> list[dict]:
    """Return controls filtered by service area."""
    return [c for c in M365_CIS_CONTROLS if c["service_area"] == service_area]


def get_m365_controls_by_severity(severity: str) -> list[dict]:
    """Return controls filtered by severity."""
    return [c for c in M365_CIS_CONTROLS if c["severity"] == severity]
