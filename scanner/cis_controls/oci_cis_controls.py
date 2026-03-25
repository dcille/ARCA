"""CIS Oracle Cloud Infrastructure Foundations Benchmark v3.0.0 — Complete Control Registry.

Auto-generated from the unified CIS controls library.
Contains ALL 54 controls (44 automated, 10 manual).
Each control includes full metadata, audit procedures, detection commands,
remediation guidance, and DSPM/Ransomware Readiness mapping.

Reference: CIS Oracle Cloud Infrastructure Foundations Benchmark v3.0.0 (2024)
Source: CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf

Total controls: 54 (44 automated, 10 manual)
"""

import json as _json


# Control registry — 54 controls
OCI_CIS_CONTROLS: list[dict] = _json.loads(r"""
[
  {
    "cis_id": "1.1",
    "title": "Ensure service level admins are created to manage resources of particular service",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "description": "To apply least-privilege security principle, one can create service-level administrators in\ncorresponding groups and assigning specific users to each service-level administrative\ngroup in a tenancy. This limits administrative access in a tenancy.\nIt means service-level administrators can only manage resources of a specific service.\nExample policies for global/tenant level service-administrators\nAllow group VolumeAdmins to manage volume-family in tenancy\nAllow group ComputeAdmins to manage instance-family in tenancy\nAllow group NetworkAdmins to manage virtual-network-family in tenancy\nA tenancy with identity domains : An Identity Domain is a container of users,\ngroups, Apps and other security configurations. A tenancy that has Identity\nDomains available comes seeded with a 'Default' identity domain.\nIf a group belongs to a domain different than the default domain, use a\ndomain prefix in the policy statements.\nExample -\nAllow group <identity_domain_name>/<group_name> to <verb> <resource-type> in\ncompartment <compartment_name>\nIf you do not include the <identity_domain_name> before the <group_name>,\nthen the policy statement is evaluated as though the group belongs to the\ndefault identity domain.\nOrganizations have various ways of defining service-administrators. Some may prefer\ncreating service administrators at a tenant level and some per department or per project\nor even per application environment ( dev/test/production etc.). Either approach works\nso long as the policies are written to limit access given to the service-administrators.\nExample policies for compartment level service-administrators\nAllow group NonProdComputeAdmins to manage instance-family in compartment dev\nAllow group ProdComputeAdmins to manage instance-family in compartment\nproduction\nAllow group A-Admins to manage instance-family in compartment Project-A\nAllow group A-Admins to manage volume-family in compartment Project-A\nA tenancy with identity domains : An Identity Domain is a container of users,\ngroups, Apps and other security configurations. A tenancy that has Identity\nDomains available comes seeded with a 'Default' identity domain.\nIf a group belongs to a domain different than the default domain, use a\ndomain prefix in the policy statements.\nExample -\nAllow group <identity_domain_name>/<group_name> to <verb> <resource-type> in\ncompartment <compartment_name>\nIf you do not include the <identity_domain_name> before the <group_name>,\nthen the policy statement is evaluated as though the group belongs to the\ndefault identity domain.",
    "rationale": "Creating service-level administrators helps in tightly controlling access to Oracle Cloud\nInfrastructure (OCI) services to implement the least-privileged security principle.",
    "audit": "From CLI:\n1. Set up OCI CLI with an IAM administrator user who has read access to IAM\nresources such as groups and policies.\n2. Run OCI CLI command providing the root_compartment_OCID\nGet the list of groups in a tenancy\noci iam group list --compartment-id <root_compartment_OCID> | grep name\nA tenancy with identity domains : The above CLI commands work with the\ndefault identity domain only.\nFor IaaS resource management, users and groups created in the default domain\nare sufficient.\n3. Ensure distinct administrative groups are created as per your organization's\ndefinition of service-administrators.\n4. Verify the appropriate policies are created for the service-administrators groups\nto have the right access to the corresponding services. Retrieve the policy\nstatements scoped at the tenancy level and/or per compartment.\noci iam policy list --compartment-id <root_compartment_OCID> | grep \"in\ntenancy\"\noci iam policy list --compartment-id <root_compartment_OCID> | grep \"in\ncompartment\"\nThe --compartment-id parameter can be changed to a child compartment to get policies\nassociated with child compartments.\noci iam policy list --compartment-id <child_compartment_OCID> | grep \"in\ncompartment\"\nVerify the results to ensure the right policies are created for service-administrators to\nhave the necessary access.",
    "expected_response": "3. Ensure distinct administrative groups are created as per your organization's\nVerify the results to ensure the right policies are created for service-administrators to",
    "remediation": "Refer to the policy syntax document and create new policies if the audit results indicate\nthat the required policies are missing. This can be done via OCI console or OCI\nCLI/SDK or API.\nCreating a new policy:\nFrom CLI:\noci iam policy create [OPTIONS]\nCreates a new policy in the specified compartment (either the tenancy or another of\nyour compartments). If you're new to policies, see Getting Started with Policies\nYou must specify a name for the policy, which must be unique across all policies in your\ntenancy and cannot be changed.\nYou must also specify a description for the policy (although it can be an empty string). It\ndoes not have to be unique, and you can change it anytime with UpdatePolicy.\nYou must specify one or more policy statements in the statements array. For\ninformation about writing policies, see How Policies Work and Common Policies.",
    "detection_commands": [
      "oci iam group list --compartment-id <root_compartment_OCID> | grep name",
      "oci iam policy list --compartment-id <root_compartment_OCID> | grep \"in",
      "oci iam policy list --compartment-id <child_compartment_OCID> | grep \"in"
    ],
    "remediation_commands": [
      "oci iam policy create [OPTIONS]"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 17,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "1.2",
    "title": "Ensure permissions on all resources are given only to the tenancy administrator group",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "There is a built-in OCI IAM policy enabling the Administrators group to perform any\naction within a tenancy. In the OCI IAM console, this policy reads:\nAllow group Administrators to manage all-resources in tenancy\nAdministrators create more users, groups, and policies to provide appropriate access to\nother groups.\nAdministrators should not allow any-other-group full access to the tenancy by writing a\npolicy like this -\nAllow group any-other-group to manage all-resources in tenancy\nThe access should be narrowed down to ensure the least-privileged principle is applied.",
    "rationale": "Permission to manage all resources in a tenancy should be limited to a small number of\nusers in the Administrators group for break-glass situations and to set up\nusers/groups/policies when a tenancy is created.\nNo group other than Administrators in a tenancy should need access to all resources\nin a tenancy, as this violates the enforcement of the least privilege principle.",
    "audit": "From CLI:\n1. Run OCI CLI command providing the root compartment OCID to get the list of\ngroups having access to manage all resources in your tenancy.\noci iam policy list --compartment-id <root_compartment_OCID> | grep -i \"to\nmanage all-resources in tenancy\"\n2. Verify the results to ensure only the Administrators group has access to\nmanage all resources in tenancy.\n\"Allow group Administrators to manage all-resources in tenancy\"",
    "expected_response": "2. Verify the results to ensure only the Administrators group has access to",
    "remediation": "From Console:\n1. Login to OCI console.\n2. Go to Identity -> Policies, In the compartment dropdown, choose the root\ncompartment. Open each policy to view the policy statements.\n3. Remove any policy statement that allows any group other than Administrators\nor any service access to manage all resources in the tenancy.\nFrom CLI:\nThe policies can also be updated via OCI CLI, SDK and API, with an example of the CLI\ncommands below:\n• Delete a policy via the CLI:\noci iam policy delete --policy-id <policy-ocid>\n• Update a policy via the CLI:\noci iam policy update --policy-id <policy-ocid> --statements <json-array-of-\nstatements>\nNote: You should generally not delete the policy that allows the Administrators group\nthe ability to manage all resources in the tenancy.",
    "detection_commands": [
      "oci iam policy list --compartment-id <root_compartment_OCID> | grep -i \"to"
    ],
    "remediation_commands": [
      "oci iam policy delete --policy-id <policy-ocid>",
      "oci iam policy update --policy-id <policy-ocid> --statements <json-array-of-"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 21,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "1.3",
    "title": "Ensure IAM administrators cannot update tenancy Administrators group",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Tenancy administrators can create more users, groups, and policies to provide other\nservice administrators access to OCI resources.\nFor example, an IAM administrator will need to have access to manage resources like\ncompartments, users, groups, dynamic-groups, policies, identity-providers, tenancy tag-\nnamespaces, tag-definitions in the tenancy.\nThe policy that gives IAM-Administrators or any other group full access to 'groups'\nresources should not allow access to the tenancy 'Administrators' group.\nThe policy statements would look like -\nAllow group IAMAdmins to inspect users in tenancy\nAllow group IAMAdmins to use users in tenancy where target.group.name !=\n'Administrators'\nAllow group IAMAdmins to inspect groups in tenancy\nAllow group IAMAdmins to use groups in tenancy where target.group.name !=\n'Administrators'\nNote: You must include separate statements for 'inspect' access, because the\ntarget.group.name variable is not used by the ListUsers and ListGroups operations",
    "rationale": "These policy statements ensure that no other group can manage tenancy administrator\nusers or the membership to the 'Administrators' group thereby gain or remove tenancy\nadministrator access.",
    "audit": "From CLI:\n1. Run the following OCI CLI commands providing the root_compartment_OCID\noci iam policy list --compartment-id <root_compartment_OCID> | grep -i \" to\nuse users in tenancy\"\noci iam policy list --compartment-id <root_compartment_OCID> | grep -i \" to\nuse groups in tenancy\"\n2. Verify the results to ensure that the policy statements that grant access to use or\nmanage users or groups in the tenancy have a condition that excludes access to\nAdministrators group or to users in the Administrators group.",
    "expected_response": "2. Verify the results to ensure that the policy statements that grant access to use or",
    "remediation": "From Console:\n1. Login to OCI Console.\n2. Select Identity from Services Menu.\n3. Select Policies from Identity Menu.\n4. Click on an individual policy under the Name heading.\n5. Ensure Policy statements look like this -\nAllow group IAMAdmins to use users in tenancy where target.group.name !=\n'Administrators'\nAllow group IAMAdmins to use groups in tenancy where target.group.name !=\n'Administrators'",
    "detection_commands": [
      "oci iam policy list --compartment-id <root_compartment_OCID> | grep -i \" to use users in tenancy\" oci iam policy list --compartment-id <root_compartment_OCID> | grep -i \" to use groups in tenancy\""
    ],
    "remediation_commands": [],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 23,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "1.4",
    "title": "Ensure IAM password policy requires minimum length of 14 or greater",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Password policies are used to enforce password complexity requirements. IAM\npassword policies can be used to ensure passwords are at least a certain length and\nare composed of certain characters.\nIt is recommended the password policy require a minimum password length 14\ncharacters and contain 1 non-alphabetic character (Number or “Special Character”).",
    "rationale": "In keeping with the overall goal of having users create a password that is not overly\nweak, an eight-character minimum password length is recommended for an MFA\naccount, and 14 characters for a password only account. In addition, maximum\npassword length should be made as long as possible based on system/software\ncapabilities and not restricted by policy.\nIn general, it is true that longer passwords are better (harder to crack), but it is also true\nthat forced password length requirements can cause user behavior that is predictable\nand undesirable. For example, requiring users to have a minimum 16-character\npassword may cause them to choose repeating patterns like fourfourfourfour or\npasswordpassword that meet the requirement but aren’t hard to guess. Additionally,\nlength requirements increase the chances that users will adopt other insecure practices,\nlike writing them down, re-using them or storing them unencrypted in their documents.\nPassword composition requirements are a poor defense against guessing attacks.\nForcing users to choose some combination of upper-case, lower-case, numbers, and\nspecial characters has a negative impact. It places an extra burden on users and many\nwill use predictable patterns (for example, a capital letter in the first position, followed by\nlowercase letters, then one or two numbers, and a “special character” at the end).\nAttackers know this, so dictionary attacks will often contain these common patterns and\nuse the most common substitutions like, $ for s, @ for a, 1 for l, 0 for o.\nPasswords that are too complex in nature make it harder for users to remember, leading\nto bad practices. In addition, composition requirements provide no defense against\ncommon attack types such as social engineering or insecure storage of passwords.",
    "audit": "1. Go to Identity Domains: https://cloud.oracle.com/identity/domains/\n2. Select the Compartment your Domain to review is in\n3. Click on the Domain to review\n4. Click on Settings\n5. Click on Password policy\n6. Click each Password policy in the domain\n7. Ensure Password length (minimum) is greater than or equal to 14\n8. Under The The following criteria apply to passwords section, ensure\nthat the number given in Numeric (minimum) setting is 1, or the Special\n(minimum) setting is 1.\nThe following criteria apply to passwords: 6. Ensure that 1 or more is selected for\nNumeric (minimum) OR Special (minimum)\nFrom Cloud Guard:\nTo Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root\ncompartment of the tenancy. For more information about enabling Cloud Guard, please\nlook at the instructions included in \"Ensure Cloud Guard is enabled in the root\ncompartment of the tenancy\" Recommendation in the \"Logging and Monitoring\" section.\nFrom Console:\n1. Type Cloud Guard into the Search box at the top of the Console.\n2. Click Cloud Guard from the “Services” submenu.\n3. Click Detector Recipes in the Cloud Guard menu.\n4. Click OCI Configuration Detector Recipe (Oracle Managed) under the\nRecipe Name column.\n5. Find Password policy does not meet complexity requirements in the Detector\nRules column.\n6. Select the vertical ellipsis icon and chose Edit on the Password policy does not\nmeet complexity requirements row.\n7. In the Edit Detector Rule window, find the Input Setting box and verify/change the\nRequired password length setting to 14.\n8. Click the Save button.\nFrom CLI:\n1. Update the Password policy does not meet complexity requirements Detector\nRule in Cloud Guard to generate Problems if IAM password policy isn’t\nconfigured to enforce a password length of at least 14 characters with the\nfollowing command:\noci cloud-guard detector-recipe-detector-rule update --detector-recipe-id\n<insert detector recipe ocid> --detector-rule-id PASSWORD_POLICY_NOT_COMPLEX\n--details '{\"configurations\":[{ \"configKey\" : \"passwordPolicyMinLength\",\n\"name\" : \"Required password length\", \"value\" : \"14\", \"dataType\" : null,\n\"values\" : null }]}'",
    "expected_response": "7. Ensure Password length (minimum) is greater than or equal to 14\n8. Under The The following criteria apply to passwords section, ensure\nThe following criteria apply to passwords: 6. Ensure that 1 or more is selected for\nTo Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root\nlook at the instructions included in \"Ensure Cloud Guard is enabled in the root",
    "remediation": "1. Go to Identity Domains: https://cloud.oracle.com/identity/domains/\n2. Select the Compartment the Domain to remediate is in\n3. Click on the Domain to remediate\n4. Click on Settings\n5. Click on Password policy to remediate\n6. Click Edit password rules\n7. Update the Password length (minimum) setting to 14 or greater\n8. Under The Passwords must meet the following character requirements\nsection, update the number given in Special (minimum) setting to 1 or greater\nor\nUnder The Passwords must meet the following character requirements\nsection, update the number given in Numeric (minimum) setting to 1 or greater 7. Click\nSave changes",
    "additional_information": "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains\ncan be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective\nrecommendations.",
    "detection_commands": [
      "oci cloud-guard detector-recipe-detector-rule update --detector-recipe-id"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://www.cisecurity.org/white-papers/cis-password-policy-guide/"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 25,
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
    "cis_id": "1.5",
    "title": "Ensure IAM password policy expires passwords within 365 days",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Establish Secure Configurations",
    "description": "IAM password policies can require passwords to be rotated or expired after a given\nnumber of days. It is recommended that the password policy expire passwords after 365\nand are changed immediately based on events.",
    "rationale": "Excessive password expiration requirements do more harm than good, because these\nrequirements make users select predictable passwords, composed of sequential words\nand numbers that are closely related to each other. In these cases, the next password\ncan be predicted based on the previous one (incrementing a number used in the\npassword for example). Also, password expiration requirements offer no containment\nbenefits because attackers will often use credentials as soon as they compromise them.\nInstead, immediate password changes should be based on key events including, but not\nlimited to:\n1. Indication of compromise\n2. Change of user roles\n3. When a user leaves the organization.\nNot only does changing passwords every few weeks or months frustrate the user, it’s\nbeen suggested that it does more harm than good, because it could lead to bad\npractices by the user such as adding a character to the end of their existing password.\nIn addition, we also recommend a yearly password change. This is primarily because\nfor all their good intentions users will share credentials across accounts. Therefore,\neven if a breach is publicly identified, the user may not see this notification, or forget\nthey have an account on that site. This could leave a shared credential vulnerable\nindefinitely. Having an organizational policy of a 1-year (annual) password expiration is\na reasonable compromise to mitigate this with minimal user burden.",
    "audit": "1. Go to Identity Domains: https://cloud.oracle.com/identity/domains/\n2. Select the Compartment your Domain to review is in\n3. Click on the Domain to review\n4. Click on Settings\n5. Click on Password policy\n6. Click each Password policy in the domain\n7. Ensure Expires after (days) is less than or equal to 365 days",
    "expected_response": "7. Ensure Expires after (days) is less than or equal to 365 days",
    "remediation": "1. Go to Identity Domains: https://cloud.oracle.com/identity/domains/\n2. Select the Compartment the Domain to remediate is in\n3. Click on the Domain to remediate\n4. Click on Settings\n5. Click on Password policy to remediate\n6. Click Edit password rules\n7. Change Expires after (days) to 365",
    "additional_information": "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains\ncan be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective\nrecommendations.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.cisecurity.org/white-papers/cis-password-policy-guide/"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
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
    "cis_id": "1.6",
    "title": "Ensure IAM password policy prevents password reuse",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Establish Secure Configurations",
    "description": "IAM password policies can prevent the reuse of a given password by the same user. It\nis recommended the password policy prevent the reuse of passwords.",
    "rationale": "Enforcing password history ensures that passwords are not reused in for a certain\nperiod of time by the same user. If a user is not allowed to use last 24 passwords, that\nwindow of time is greater. This helps maintain the effectiveness of password security.",
    "audit": "1. Go to Identity Domains: https://cloud.oracle.com/identity/domains/\n2. Select the Compartment your Domain to review is in\n3. Click on the Domain to review\n4. Click on Settings\n5. Click on Password policy\n6. Click each Password policy in the domain\n7. Ensure Previous passwords remembered is set 24 or greater",
    "expected_response": "7. Ensure Previous passwords remembered is set 24 or greater",
    "remediation": "1. Go to Identity Domains: https://cloud.oracle.com/identity/domains/\n2. Select the Compartment the Domain to remediate is in\n3. Click on the Domain to remediate\n4. Click on Settings\n5. Click on Password policy to remediate\n6. Click Edit password rules\n7. Update the number of remembered passwords in Previous passwords\nremembered setting to 24 or greater.",
    "additional_information": "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains\ncan be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective\nrecommendations.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 30,
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
    "cis_id": "1.7",
    "title": "Ensure MFA is enabled for all users with a console password",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Use Unique Passwords",
    "description": "Multi-factor authentication is a method of authentication that requires the use of more\nthan one factor to verify a user’s identity.\nWith MFA enabled in the IAM service, when a user signs in to Oracle Cloud\nInfrastructure, they are prompted for their user name and password, which is the first\nfactor (something that they know). The user is then prompted to provide a verification\ncode from a registered MFA device, which is the second factor (something that they\nhave). The two factors work together, requiring an extra layer of security to verify the\nuser’s identity and complete the sign-in process.\nOCI IAM supports two-factor authentication using a password (first factor) and a device\nthat can generate a time-based one-time password (TOTP) (second factor).\nSee OCI documentation for more details.",
    "rationale": "Multi factor authentication adds an extra layer of security during the login process and\nmakes it harder for unauthorized users to gain access to OCI resources.",
    "audit": "From Console:\n1. Go to Identity Domains: https://cloud.oracle.com/identity/domains/\n2. Select the Compartment your Domain to review is in\n3. Click on the Domain to review\n4. Click on Security\n5. Click Sign-on policies\n6. Select the sign-on policy to review\n7. Under the sign-on rules header, click the three dots on the rule with the highest\npriority.\n8. Select Edit sign-on rule\n9. Verify that allow access is selected and prompt for an additional factor\nis enabled\n• This requires users to enable MFA when they next login next however, to\ndetermine users have enabled MFA use the below CLI.\nFrom the CLI:\n• This CLI command checks which users have enabled MFA for their accounts\n1. Execute the below:\ntenancy_ocid=`oci iam compartment list --raw-output --query\n\"data[?contains(\\\"compartment-id\\\",'.tenancy.')].\\\"compartment-id\\\" | [0]\"`\nfor id_domain_url in `oci iam domain list --compartment-id $tenancy_ocid --\nall | jq -r '.data[] | .url'`\ndo\noci identity-domains users list --endpoint $id_domain_url 2>/dev/null |\njq -r '.data.resources[] | select(.\"urn-ietf-params-scim-schemas-oracle-idcs-\nextension-mfa-user\".\"mfa-status\"!=\"ENROLLED\")' 2>/dev/null | jq -r '.ocid'\ndone\nfor region in `oci iam region-subscription list | jq -r '.data[] | .\"region-\nname\"'`;\ndo\nfor compid in `oci iam compartment list --compartment-id-in-subtree\nTRUE --all 2>/dev/null | jq -r '.data[] | .id'`\ndo\nfor id_domain_url in `oci iam domain list --compartment-id\n$compid --region $region --all 2>/dev/null | jq -r '.data[] | .url'`\ndo\noci identity-domains users list --endpoint $id_domain_url\n2>/dev/null | jq -r '.data.resources[] | select(.\"urn-ietf-params-scim-\nschemas-oracle-idcs-extension-mfa-user\".\"mfa-status\"!=\"ENROLLED\")'\n2>/dev/null | jq -r '.ocid'\ndone\ndone\ndone\n2. Ensure no results are returned",
    "expected_response": "is enabled\ntenancy_ocid=`oci iam compartment list --raw-output --query\n2. Ensure no results are returned",
    "remediation": "Each user must enable MFA for themselves using a device they will have access to\nevery time they sign in. An administrator cannot enable MFA for another user but can\nenforce MFA by identifying the list of non-complaint users, notifying them or disabling\naccess by resetting the password for non-complaint accounts.\nDisabling access from Console:\n1. Go to https://cloud.oracle.com/identity/.\n2. Select Domains from Identity menu.\n3. Select the domain\n4. Click Security\n5. Click Sign-on polices then the \"Default Sign-on Policy\"\n6. Under the sign-on rules header, click the three dots on the rule with the highest\npriority.\n7. Select Edit sign-on rule\n8. Make a change to ensure that allow access is selected and prompt for an\nadditional factor is enabled",
    "additional_information": "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains\ncan be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective\nrecommendations.",
    "detection_commands": [
      "oci identity-domains users list --endpoint $id_domain_url 2>/dev/null |",
      "$compid --region $region --all 2>/dev/null | jq -r '.data[] | .url'`",
      "oci identity-domains users list --endpoint $id_domain_url"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://docs.cloud.oracle.com/en-us/iaas/Content/Identity/Tasks/usingmfa.htm",
      "2. https://docs.oracle.com/en-",
      "us/iaas/Content/Security/Reference/iam_security_topic-IAM_MFA.htm"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 32,
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
    "cis_id": "1.8",
    "title": "Ensure user API keys rotate within 90 days",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Require Multi-factor Authentication",
    "description": "API keys are used by administrators, developers, services and scripts for accessing\nOCI APIs directly or via SDKs/OCI CLI to search, create, update or delete OCI\nresources.\nThe API key is an RSA key pair. The private key is used for signing the API requests\nand the public key is associated with a local or synchronized user's profile.",
    "rationale": "It is important to secure and rotate an API key every 90 days or less as it provides the\nsame level of access that a user it is associated with has.\nIn addition to a security engineering best practice, this is also a compliance\nrequirement. For example, PCI-DSS Section 3.6.4 states, \"Verify that key-management\nprocedures include a defined cryptoperiod for each key type in use and define a\nprocess for key changes at the end of the defined crypto period(s).\"",
    "audit": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. For each domain listed, click on the name and select Users.\n5. Click on an individual user under the Name heading.\n6. Click on API Keys in the lower left-hand corner of the page.\n7. Ensure the date of the API key under the Created column of the API Key is no\nmore than 90 days old.",
    "expected_response": "7. Ensure the date of the API key under the Created column of the API Key is no",
    "remediation": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. For each domain listed, click on the name and select Users.\n5. Click on an individual user under the Name heading.\n6. Click on API Keys in the lower left-hand corner of the page.\n7. Delete any API Keys that are older than 90 days under the Created column of\nthe API Key table.\nFrom CLI:\noci iam user api-key delete --user-id _<user_ocid>_ --fingerprint\n<fingerprint_of_the_key_to_be_deleted>",
    "additional_information": "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains\ncan be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective\nrecommendations.",
    "detection_commands": [],
    "remediation_commands": [
      "oci iam user api-key delete --user-id _<user_ocid>_ --fingerprint"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 35,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "1.9",
    "title": "Ensure user customer secret keys rotate every 90 days",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Establish Secure Configurations",
    "description": "Object Storage provides an API to enable interoperability with Amazon S3. To use this\nAmazon S3 Compatibility API, you need to generate the signing key required to\nauthenticate with Amazon S3.\nThis special signing key is an Access Key/Secret Key pair. Oracle generates the\nCustomer Secret key to pair with the Access Key.",
    "rationale": "It is important to rotate customer secret keys at least every 90 days, as they provide the\nsame level of object storage access that the user they are associated with has.",
    "audit": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. For each domain listed, click on the name and select Users.\n5. Click on an individual user under the Username heading.\n6. Click on Customer Secret Keys in the lower left-hand corner of the page.\n7. Ensure the date of the Customer Secret Key under the Created column of the\nCustomer Secret Key is no more than 90 days old.",
    "expected_response": "7. Ensure the date of the Customer Secret Key under the Created column of the",
    "remediation": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. For each domain listed, click on the name and select Users.\n5. Click on an individual user under the Username heading.\n6. Click on Customer Secret Keys in the lower left-hand corner of the page.\n7. Delete any Access Keys with a date older than 90 days under the Created\ncolumn of the Customer Secret Keys.",
    "additional_information": "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains\ncan be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective\nrecommendations.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 37,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.10",
    "title": "Ensure user auth tokens rotate within 90 days or less",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Establish Secure Configurations",
    "description": "Auth tokens are authentication tokens generated by Oracle. You use auth tokens to\nauthenticate with APIs that do not support the Oracle Cloud Infrastructure signature-\nbased authentication. If the service requires an auth token, the service-specific\ndocumentation instructs you to generate one and how to use it.",
    "rationale": "It is important to secure and rotate an auth token every 90 days or less as it provides\nthe same level of access to APIs that do not support the OCI signature-based\nauthentication as the user associated to it.",
    "audit": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. For each domain listed, click on the name and select Users.\n5. Click on an individual user under the Username heading.\n6. Click on Auth Tokens in the lower left-hand corner of the page.\n7. Ensure the date of the Auth Token under the Created column of the Customer\nSecret Key is no more than 90 days old.",
    "expected_response": "7. Ensure the date of the Auth Token under the Created column of the Customer",
    "remediation": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. For each domain listed, click on the name and select Users.\n5. Click on an individual user under the Username heading.\n6. Click on Auth Tokens in the lower left-hand corner of the page.\n7. Delete any auth token with a date older than 90 days under the Created column\nof the Customer Secret Keys.",
    "additional_information": "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains\ncan be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective\nrecommendations.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 39,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.11",
    "title": "Ensure user IAM Database Passwords rotate within 90 days",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Establish Secure Configurations",
    "description": "Users can create and manage their database password in their IAM user profile and use\nthat password to authenticate to databases in their tenancy. An IAM database password\nis a different password than an OCI Console password. Setting an IAM database\npassword allows an authorized IAM user to sign in to one or more Autonomous\nDatabases in their tenancy.\nAn IAM database password is a different password than an OCI Console password.\nSetting an IAM database password allows an authorized IAM user to sign in to one or\nmore Autonomous Databases in their tenancy.",
    "rationale": "It is important to secure and rotate an IAM Database password 90 days or less as it\nprovides the same access the user would have a using a local database user.",
    "audit": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Users from the Identity menu.\n4. Click on an individual user under the Name heading.\n5. Click on Database Passwords in the lower left-hand corner of the page.\n6. Ensure the date of the Database Passwords under the Created column of the\nDatabase Passwords is no more than 90 days\nFrom Console:\n7. Login to OCI Console.\n8. Select Identity & Security from the Services menu.\n9. Select Domains from the Identity menu.\n10. For each domain listed, click on the name and select Users.\n11. Click on an individual user under the Username heading.\n12. Click on Database Passwords in the lower left-hand corner of the page.\n13. Ensure the date of the Database Passwords under the Created column of the\nDatabase Password is no more than 90 days old.",
    "expected_response": "6. Ensure the date of the Database Passwords under the Created column of the\n13. Ensure the date of the Database Passwords under the Created column of the",
    "remediation": "OCI IAM with Identity Domains\nFrom Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. For each domain listed, click on the name and select Users.\n5. Click on an individual user under the Username heading.\n6. Click on IAM Database Passwords in the lower left-hand corner of the page.\n7. Delete any Database Passwords with a date older than 90 days under the\nCreated column of the Database Passwords.",
    "additional_information": "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains\ncan be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective\nrecommendations.",
    "detection_commands": [],
    "remediation_commands": [
      "OCI IAM with Identity Domains"
    ],
    "references": [
      "1. https://docs.oracle.com/en-",
      "us/iaas/Content/Identity/Concepts/usercredentials.htm#usercredentials_iam_db_",
      "pwd"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 41,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.12",
    "title": "Ensure API keys are not created for tenancy administrator users",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Use Unique Passwords",
    "description": "Tenancy administrator users have full access to the organization's OCI tenancy. API\nkeys associated with user accounts are used for invoking the OCI APIs via custom\nprograms or clients like CLI/SDKs. The clients are typically used for performing day-to-\nday operations and should never require full tenancy access. Service-level\nadministrative users with API keys should be used instead.",
    "rationale": "For performing day-to-day operations tenancy administrator access is not needed.\nService-level administrative users with API keys should be used to apply privileged\nsecurity principle.",
    "audit": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. Click on the 'Default' Domain in the (root).\n5. Click on 'Groups'.\n6. Select the 'Administrators' group by clicking on the Name\n7. Click on each local or synchronized Administrators member profile\n8. Click on API Keys to verify if a user has an API key associated.",
    "remediation": "From Console:\n1. Login to OCI console.\n2. Select Identity from Services menu.\n3. Select Users from Identity menu, or select Domains, select a domain, and select\nUsers.\n4. Select the username of a tenancy administrator user with an API key.\n5. Select API Keys from the menu in the lower left-hand corner.\n6. Delete any associated keys from the API Keys table.\n7. Repeat steps 3-6 for all tenancy administrator users with an API key.\nFrom CLI:\n1. For each tenancy administrator user with an API key, execute the following\ncommand to retrieve API key details:\noci iam user api-key list --user-id <user_id>\n2. For each API key, execute the following command to delete the key:\noci iam user api-key delete --user-id <user_id> --fingerprint\n<api_key_fingerprint>\n3. The following message will be displayed:\nAre you sure you want to delete this resource? [y/N]:\n4. Type 'y' and press 'Enter'.",
    "additional_information": "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains\ncan be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective\nrecommendations.",
    "detection_commands": [],
    "remediation_commands": [
      "oci iam user api-key list --user-id <user_id>",
      "oci iam user api-key delete --user-id <user_id> --fingerprint"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 43,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.13",
    "title": "Ensure all OCI IAM local user accounts have a valid and current email address",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "All OCI IAM local user accounts have an email address field associated with the\naccount. It is recommended to specify an email address that is valid and current.\nIf you have an email address in your user profile, you can use the Forgot Password link\non the sign on page to have a temporary password sent to you.",
    "rationale": "Having a valid and current email address associated with an OCI IAM local user\naccount allows you to tie the account to identity in your organization. It also allows that\nuser to reset their password if it is forgotten or lost.",
    "audit": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. For each domain listed, click on the name and select Users.\n5. Click on an individual user under the Username heading.\n6. Ensure a valid and current email address is next to Email and Recovery email.",
    "expected_response": "6. Ensure a valid and current email address is next to Email and Recovery email.",
    "remediation": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. For each domain listed, click on the name and select Users.\n5. Click on each non-complaint user.\n6. Click on Edit User.\n7. Enter a valid and current email address in the Email and Recovery Email text\nboxes.\n8. Click Save Changes",
    "additional_information": "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains\ncan be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective\nrecommendations.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 45,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D3",
      "D6"
    ]
  },
  {
    "cis_id": "1.14",
    "title": "Ensure Instance Principal authentication is used for OCI instances, OCI Cloud Databases and OCI Functions to access OCI resources",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Establish and Maintain an Inventory of Accounts",
    "description": "OCI instances, OCI database and OCI functions can access other OCI resources either\nvia an OCI API key associated to a user or via Instance Principal. Instance Principal\nauthentication can be achieved by inclusion in a Dynamic Group that has an IAM policy\ngranting it the required access or using an OCI IAM policy that has\nrequest.principal added to the where clause. Access to OCI Resources refers to\nmaking API calls to another OCI resource like Object Storage, OCI Vaults, etc.",
    "rationale": "Instance Principal reduces the risks related to hard-coded credentials. Hard-coded API\nkeys can be shared and require rotation, which can open them up to being\ncompromised. Compromised credentials could allow access to OCI services outside of\nthe expected radius.",
    "impact": "For an OCI instance that contains embedded credential audit the scripts and\nenvironment variables to ensure that none of them contain OCI API Keys or credentials.",
    "audit": "From Console (Dynamic Groups):\n1. Go to https://cloud.oracle.com/identity/domains/\n2. Select a Compartment\n3. Click on a Domain\n4. Click on Dynamic groups\n5. Click on the Dynamic Group\n6. Check if the Matching Rules includes the instances accessing your OCI\nresources.\nFrom Console (request.principal):\n1. Go to https://cloud.oracle.com/identity/policies\n2. Select a Compartment\n3. Click on an individual policy under the Name heading.\n4. Ensure Policy statements look like this :\nallow any-user to <verb> <resource> in compartment <compartment-name> where\nALL {request.principal.type='<resource_type>',\nrequest.principal.id='<resource_ocid>'}\nor\nallow any-user to <verb> <resource> in compartment <compartment-name> where\nALL {request.principal.type='<resource_type>',\nrequest.principal.compartment.id='<compartment_OCID>'}\nFrom CLI (request.principal):\n1. Execute the following for each compartment_OCID:\noci iam policy list --compartment-id <compartment_OCID> | grep\nrequest.principal\n1. Ensure that the condition includes the instances accessing your OCI resources",
    "expected_response": "4. Ensure Policy statements look like this :\n1. Ensure that the condition includes the instances accessing your OCI resources",
    "remediation": "From Console (Dynamic Groups):\n1. Go to https://cloud.oracle.com/identity/domains/\n2. Select a Compartment\n3. Click on the Domain\n4. Click on Dynamic groups\n5. Click Create Dynamic Group.\n6. Enter a Name\n7. Enter a Description\n8. Enter Matching Rules to that includes the instances accessing your OCI\nresources.\n9. Click Create.",
    "additional_information": "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains\ncan be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective\nrecommendations.",
    "detection_commands": [
      "oci iam policy list --compartment-id <compartment_OCID> | grep"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://docs.oracle.com/en-",
      "us/iaas/Content/Identity/Tasks/managingdynamicgroups.htm"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 47,
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
    "cis_id": "1.15",
    "title": "Ensure storage service-level admins cannot delete resources they manage",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "To apply the separation of duties security principle, one can restrict service-level\nadministrators from being able to delete resources they are managing. It means service-\nlevel administrators can only manage resources of a specific service but not delete\nresources for that specific service.\nExample policies for global/tenant level for block volume service-administrators:\nAllow group VolumeUsers to manage volumes in tenancy where\nrequest.permission!='VOLUME_DELETE'\nAllow group VolumeUsers to manage volume-backups in tenancy where\nrequest.permission!='VOLUME_BACKUP_DELETE'\nExample policies for global/tenant level for file storage system service-administrators:\nAllow group FileUsers to manage file-systems in tenancy where\nrequest.permission!='FILE_SYSTEM_DELETE'\nAllow group FileUsers to manage mount-targets in tenancy where\nrequest.permission!='MOUNT_TARGET_DELETE'\nAllow group FileUsers to manage export-sets in tenancy where\nrequest.permission!='EXPORT_SET_DELETE'\nExample policies for global/tenant level for object storage system service-\nadministrators:\nAllow group BucketUsers to manage objects in tenancy where\nrequest.permission!='OBJECT_DELETE'\nAllow group BucketUsers to manage buckets in tenancy where\nrequest.permission!='BUCKET_DELETE'",
    "rationale": "Creating service-level administrators without the ability to delete the resource they are\nmanaging helps in tightly controlling access to Oracle Cloud Infrastructure (OCI)\nservices by implementing the separation of duties security principle.",
    "audit": "From Console:\n1. Login to OCI console.\n2. Go to Identity -> Policies, In the compartment dropdown, choose the\ncompartment.\n3. Open each policy to view the policy statements.\n4. Verify the policies to ensure that the policy statements that grant access to\nstorage service-level administrators have a condition that excludes access to\ndelete the service they are the administrator for.\nFrom CLI:\n1. Execute the following command:\nfor compid in `oci iam compartment list --compartment-id-in-subtree TRUE\n2>/dev/null | jq -r '.data[] | .id'`\ndo\nfor policy in `oci iam policy list --compartment-id $compid\n2>/dev/null | jq -r '.data[] | .id'`\ndo\noutput=`oci iam policy list --compartment-id $compid\n2>/dev/null | jq -r '.data[] | .id, .name, .statements'`\nif [ ! -z \"$output\" ]; then echo $output; fi\ndone\ndone\n2. Verify the policies to ensure that the policy statements that grant access to\nstorage service-level administrators have a condition that excludes access to\ndelete the service they are the administrator for.",
    "expected_response": "4. Verify the policies to ensure that the policy statements that grant access to\noutput=`oci iam policy list --compartment-id $compid\nif [ ! -z \"$output\" ]; then echo $output; fi\n2. Verify the policies to ensure that the policy statements that grant access to",
    "remediation": "From Console:\n1. Login to OCI console.\n2. Go to Identity -> Policies, In the compartment dropdown, choose the\ncompartment. Open each policy to view the policy statements.\n3. Add the appropriate where condition to any policy statement that allows the\nstorage service-level to manage the storage service.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://docs.oracle.com/en/solutions/oci-best-practices/protect-data-",
      "rest1.html#GUID-939A5EA1-3057-48E0-9E02-ADAFCB82BA3E",
      "2. https://docs.oracle.com/en-",
      "us/iaas/Content/Identity/policyreference/policyreference.htm",
      "3. https://docs.oracle.com/en-us/iaas/Content/Block/home.htm",
      "4. https://docs.oracle.com/en-us/iaas/Content/File/home.htm",
      "5. https://docs.oracle.com/en-us/iaas/Content/Object/home.htm"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 50,
    "dspm_relevant": true,
    "dspm_categories": [
      "access",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D3",
      "D6"
    ]
  },
  {
    "cis_id": "1.16",
    "title": "Ensure OCI IAM credentials unused for 45 days or more are disabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "OCI IAM Local users can access OCI resources using different credentials, such as\npasswords or API keys. It is recommended that credentials that have been unused for\n45 days or more be deactivated or removed.",
    "rationale": "Disabling or removing unnecessary OCI IAM local users will reduce the window of\nopportunity for credentials associated with a compromised or abandoned account to be\nused.",
    "audit": "Perform the following to determine if unused credentials exist:\nFrom Console:\nFor Passwords:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. For each domain listed, click on the name\n5. Click Reports\n6. Under Dormant users report click View report\n7. Enter a date 45 days from today’s date in Last Successful Login Date\n8. Check and ensure that Last Successful Login Date is greater than 45 days\nor empty\nFor API Keys:\n1. Login to OCI Console.\n2. Select Observability & Management from the Services menu.\n3. Select Search from Logging menu\n4. Click Show Advanced Mode in the right corner\n5. Select Custom from Filter by time\n6. Under Select regions to search add regions\n7. Under Query enter the following query in the text box:\nsearch \"<tenancy-ocid>/_Audit_Include_Subcompartment\" |\ndata.identity.credentials='<tenancy-ocid>/<user-ocid>/<key-fingerprint>'  |\nsummarize count() by data.identity.principalId\n8. Enter a day range\n• Note each query can only be 14 days multiple queries will be required to go 45\ndays\n9. Click Search\n10. Expand the results\n11. If results the count is not zero the user has used their API key during that period\n12. Repeat steps 8 – 11 for the 45-day period\nFrom CLI:\nFor Passwords:\n1. Execute the below:\noci identity-domains users list --all --endpoint <identity-domain-endpoint> -\n-attributes\nurn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User:lastSuccess\nfulLoginDate --profile Oracle --query '.data.resources[]|.\"user-name\" + \"  \"\n+ .\"urn-ietf-params-scim-schemas-oracle-idcs-extension-user-state-\nuser\".\"last-successful-login-date\"'\n2. Review the output the that the date is under 45 days, or no date means they\nhave not logged in\nFor API Keys:\n1. Create the search query text:\nexport query=\"search \\\"<tenancy-ocid>/_Audit_Include_Subcompartment\\\" |\ndata.identity.credentials='*<key-finger-print>'  | summarize count() by\ndata.identity.principalId\"\n2. Select a day range. Date format is 2024-12-01\n• Note each query can only be 14 days multiple queries will be required to go 45\ndays\n3. Execute the below:\noci logging-search search-logs --search-query $query --time-start <start-\ndate> --time-end <end-date> --query 'data.results[0].data.count'\nexport query=\"search \\\"<tenancy-ocid>/_Audit_Include_Subcompartment\\\" |\ndata.identity.credentials='*<key-finger-print>'  | summarize count() by\ndata.identity.principalId\"\n4. If results the count is not zero, the user has used their API key during that period\n5. Repeat steps 2 – 4 for the 45-day period",
    "expected_response": "8. Check and ensure that Last Successful Login Date is greater than 45 days\n2. Review the output the that the date is under 45 days, or no date means they",
    "remediation": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. For each domain listed, click on the name and select Users.\n5. Click on an individual user under the Username heading.\n6. Click More action\n7. Select Deactivate\nFrom CLI:\n1. Create a input.json:\n{\n\"operations\": [\n{ \"op\": \"replace\", \"path\": \"active\",\"value\": false}\n],\n\"schemas\": [\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\n\"userId\": \"<user-ocid>\"\n}\n2. Execute the below:\noci identity-domains user patch --from-json file://file.json --endpoint\n<identity-domain-endpoint>",
    "additional_information": "This audit should exclude the OCI Administrator, break-glass accounts, and service\naccounts as these accounts should only be used for day-to-day business and would\nlikely be unused for up to 45 days.",
    "detection_commands": [
      "oci identity-domains users list --all --endpoint <identity-domain-endpoint> -",
      "oci logging-search search-logs --search-query $query --time-start <start-"
    ],
    "remediation_commands": [
      "oci identity-domains user patch --from-json file://file.json --endpoint"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 53,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "1.17",
    "title": "Ensure there is only one active API Key for any single OCI IAM user",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days_or_more_be_deactivated_or_removed",
    "domain": "days or more be deactivated or removed",
    "subdomain": "Disable Dormant Accounts",
    "description": "API Keys are long-term credentials for an OCI IAM user. They can be used to make\nprogrammatic requests to the OCI APIs directly or via, OCI SDKs or the OCI CLI.",
    "rationale": "Having a single API Key for an OCI IAM reduces attack surface area and makes it\neasier to manage.",
    "impact": "Deletion of an OCI API Key will remove programmatic access to OCI APIs",
    "audit": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Users from the Identity menu.\n4. Click on an individual user under the Name heading.\n5. Click on API Keys in the lower left-hand corner of the page.\n6. Ensure the has only has a one API Key\nFrom CLI:\n1. Each user and in each Identity Domain\noci raw-request --http-method GET --target-uri \"https://<domain-\nendpoint>/admin/v1/ApiKeys?filter=user.ocid+eq+%<user-ocid>%22\"  | jq\n'.data.Resources[] | \"\\(.fingerprint) \\(.id)\"'\n2. Ensure only one key is returned",
    "expected_response": "6. Ensure the has only has a one API Key\n2. Ensure only one key is returned",
    "remediation": "From Console:\n1. Login to OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Domains from the Identity menu.\n4. For each domain listed, click on the name and select Users.\n5. Click on an individual user under the Name heading.\n6. Click on API Keys in the lower left-hand corner of the page.\n7. Delete one of the API Keys\nFrom CLI:\n1. Follow the audit procedure above.\n2. For API Key ID to be removed execute the following command:\noci identity-domains api-key delete –api-key-id <id> --endpoint <domain-\nendpoint>",
    "default_value": "No API Keys",
    "detection_commands": [
      "oci raw-request --http-method GET --target-uri \"https://<domain-"
    ],
    "remediation_commands": [
      "oci identity-domains api-key delete –api-key-id <id> --endpoint <domain-"
    ],
    "references": [
      "1. https://docs.public.oneportal.content.oci.oraclecloud.com/en-",
      "us/iaas/Content/Security/Reference/iam_security_topic-",
      "IAM_Credentials.htm#IAM_Credentials"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 57,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "2.1",
    "title": "Ensure no security lists allow ingress from 0.0.0.0/0 to port 22",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "description": "Security lists provide stateful and stateless filtering of ingress and egress network traffic\nto OCI resources on a subnet level. It is recommended that no security list allows\nunrestricted ingress access to port 22.",
    "rationale": "Removing unfettered connectivity to remote console services, such as Secure Shell\n(SSH), reduces a server's exposure to risk.",
    "impact": "For updating an existing environment, care should be taken to ensure that\nadministrators currently relying on an existing ingress from 0.0.0.0/0 have access to\nports 22 and/or 3389 through another network security group or security list.",
    "audit": "From Console:\n1. Login to the OCI Console.\n2. Click the search bar at the top of the screen.\n3. Type Advanced Resource Query and hit enter.\n4. Click the Advanced Resource Query button in the upper right corner of the\nscreen.\n5. Enter the following query in the query box:\nquery SecurityList resources where\n(IngressSecurityRules.source = '0.0.0.0/0' &&\nIngressSecurityRules.protocol = 6 &&\nIngressSecurityRules.tcpOptions.destinationPortRange.max >= 22 &&\nIngressSecurityRules.tcpOptions.destinationPortRange.min =<= 22)\n6. Ensure the query returns no results.\nFrom CLI:\n1. Execute the following command:\noci search resource structured-search --query-text \"query SecurityList\nresources where\n(IngressSecurityRules.source = '0.0.0.0/0' &&\nIngressSecurityRules.protocol = 6 &&\nIngressSecurityRules.tcpOptions.destinationPortRange.max >= 22 &&\nIngressSecurityRules.tcpOptions.destinationPortRange.min <= 22)\n\"\n2. Ensure the query returns no results.\nCloud Guard\nEnsure Cloud Guard is enabled in the root compartment of the tenancy. For more\ninformation about enabling Cloud Guard, please look at the instructions included in\nRecommendation 3.15.\nFrom Console:\n1. Type Cloud Guard into the Search box at the top of the Console.\n2. Click Cloud Guard from the “Services” submenu.\n3. Click Detector Recipes in the Cloud Guard menu.\n4. Click OCI Configuration Detector Recipe (Oracle Managed) under the\nRecipe Name column.\n5. Find VCN Security list allows traffic to non-public port from all sources (0.0.0.0/0)\nin the Detector Rules column.\n6. Select the vertical ellipsis icon and chose Edit on the VCN Security list allows\ntraffic to non-public port from all sources (0.0.0.0/0) row.\n7. In the Edit Detector Rule window find the Input Setting box and verify/add to the\nRestricted Protocol: Ports List setting to TCP:[22], UDP:[22].\n8. Click the Save button.\nFrom CLI:\n1. Update the VCN Security list allows traffic to non-public port from all sources\n(0.0.0.0/0) Detector Rule in Cloud Guard to generate Problems if a VCN security\nlist allows public access via port 22 with the following command:\noci cloud-guard detector-recipe-detector-rule update --detector-recipe-id\n<insert detector recipe ocid> --detector-rule-id SECURITY_LISTS_OPEN_SOURCE -\n-details '{\"configurations\":[{ \"configKey\" : \"securityListsOpenSourceConfig\",\n\"name\" : \"Restricted Protocol:Ports List\", \"value\" : \"TCP:[22], UDP:[22]\",\n\"dataType\" : null, \"values\" : null }]}'",
    "expected_response": "6. Ensure the query returns no results.\n2. Ensure the query returns no results.\nEnsure Cloud Guard is enabled in the root compartment of the tenancy. For more",
    "remediation": "From Console:\n1. Follow the audit procedure above.\n2. For each security list in the returned results, click the security list name\n3. Either edit the ingress rule to be more restrictive, delete the ingress rule or\nclick on the VCN and terminate the security list as appropriate.\nFrom CLI:\n1. Follow the audit procedure.\n2. For each of the security lists identified, execute the following command:\noci network security-list get --security-list-id <security list id>\n3. Then either:\n• Update the security list by copying the ingress-security-rules element\nfrom the JSON returned by the above command, edit it appropriately and use it in\nthe following command:\noci network security-list update --security-list-id <security-list-id> --\ningress-security-rules '<ingress security rules JSON>'\nor\n• Delete the security list with the following command:\noci network security-list delete --security-list-id <security list id>",
    "detection_commands": [
      "oci search resource structured-search --query-text \"query SecurityList",
      "oci cloud-guard detector-recipe-detector-rule update --detector-recipe-id"
    ],
    "remediation_commands": [
      "oci network security-list get --security-list-id <security list id>",
      "oci network security-list update --security-list-id <security-list-id> --",
      "oci network security-list delete --security-list-id <security list id>"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 60,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.2",
    "title": "Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "Security lists provide stateful and stateless filtering of ingress and egress network traffic\nto OCI resources on a subnet level. It is recommended that no security group allows\nunrestricted ingress access to port 3389.",
    "rationale": "Removing unfettered connectivity to remote console services, such as Remote Desktop\nProtocol (RDP), reduces a server's exposure to risk.",
    "impact": "For updating an existing environment, care should be taken to ensure that\nadministrators currently relying on an existing ingress from 0.0.0.0/0 have access to\nports 22 and/or 3389 through another network security group or security list.",
    "audit": "From Console:\n1. Login into the OCI Console\n2. Click in the search bar at the top of the screen.\n3. Type Advanced Resource Query and hit enter.\n4. Click the Advanced Resource Query button in the upper right corner of the\nscreen.\n5. Enter the following query in the query box:\nquery SecurityList resources where\n(IngressSecurityRules.source = '0.0.0.0/0' &&\nIngressSecurityRules.protocol = 6 &&\nIngressSecurityRules.tcpOptions.destinationPortRange.max >= 3389 &&\nIngressSecurityRules.tcpOptions.destinationPortRange.min <= 3389)\n6. Ensure query returns no results.\nFrom CLI:\n1. Execute the following command:\noci search resource structured-search --query-text \"query SecurityList\nresources where\n(IngressSecurityRules.source = '0.0.0.0/0' &&\nIngressSecurityRules.protocol = 6 &&\nIngressSecurityRules.tcpOptions.destinationPortRange.max >= 3389 &&\nIngressSecurityRules.tcpOptions.destinationPortRange.min <= 3389)\n\"\n2. Ensure query returns no results.\nCloud Guard\nTo Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root\ncompartment of the tenancy. For more information about enabling Cloud Guard, please\nlook at the instructions included in Recommendation 3.15.\nFrom Console:\n1. Type Cloud Guard into the Search box at the top of the Console .\n2. Click Cloud Guard from the “Services” submenu.\n3. Click Detector Recipes in the Cloud Guard menu.\n4. Click OCI Configuration Detector Recipe (Oracle Managed) under the\nRecipe Name column.\n5. Find VCN Security list allows traffic to non-public port from all sources (0.0.0.0/0)\nin the Detector Rules column.\n6. Select the vertical ellipsis icon and choose Edit on the VCN Security list allows\ntraffic to non-public port from all sources (0.0.0.0/0) row.\n7. In the Edit Detector Rule window find the Input Setting box and verify/add to the\nRestricted Protocol: Ports List setting to TCP:[3389], UDP:[3389].\n8. Click the Save button.\nFrom CLI:\n1. Update the VCN Security list allows traffic to non-public port from all sources\n(0.0.0.0/0) Detector Rule in Cloud Guard to generate Problems if a VCN security\nlist allows public access via port 3389 with the following command:\noci cloud-guard detector-recipe-detector-rule update --detector-recipe-id\n<insert detector recipe ocid> --detector-rule-id SECURITY_LISTS_OPEN_SOURCE -\n-details '{\"configurations\":[{ \"configKey\" : \"securityListsOpenSourceConfig\",\n\"name\" : \"Restricted Protocol:Ports List\", \"value\" : \"TCP:[3389],\nUDP:[3389]\", \"dataType\" : null, \"values\" : null }]}'",
    "expected_response": "6. Ensure query returns no results.\n2. Ensure query returns no results.\nTo Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root",
    "remediation": "From Console:\n1. Follow the audit procedure above.\n2. For each security list in the returned results, click the security list name\n3. Either edit the ingress rule to be more restrictive, delete the ingress rule or\nclick on the VCN and terminate the security list as appropriate.\nFrom CLI:\n1. Follow the audit procedure.\n2. For each of the security lists identified, execute the following command:\noci network security-list get --security-list-id <security list id>\n3. Then either:\n• Update the security list by copying the ingress-security-rules element\nfrom the JSON returned by the above command, edit it appropriately, and use it\nin the following command\noci network security-list update --security-list-id <security-list-id> --\ningress-security-rules '<ingress security rules JSON>'\nor\n• Delete the security list with the following command:\noci network security-list delete --security-list-id <security list id>",
    "additional_information": "This recommendation can also be audited programmatically using REST API\nhttps://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/SecurityList/ListSecurityLists",
    "detection_commands": [
      "oci search resource structured-search --query-text \"query SecurityList",
      "oci cloud-guard detector-recipe-detector-rule update --detector-recipe-id"
    ],
    "remediation_commands": [
      "oci network security-list get --security-list-id <security list id>",
      "oci network security-list update --security-list-id <security-list-id> --",
      "oci network security-list delete --security-list-id <security list id>"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 63,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.3",
    "title": "Ensure no network security groups allow ingress from 0.0.0.0/0 to port 22",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "automated",
    "domain": "(Automated)",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "Network security groups provide stateful filtering of ingress/egress network traffic to OCI\nresources. It is recommended that no security group allows unrestricted ingress to port\n22.",
    "rationale": "Removing unfettered connectivity to remote console services, such as Secure Shell\n(SSH), reduces a server's exposure to risk.",
    "impact": "For updating an existing environment, care should be taken to ensure that\nadministrators currently relying on an existing ingress from 0.0.0.0/0 have access to\nports 22 and/or 3389 through another network security group or security list.",
    "audit": "From Console:\n1. Login into the OCI Console.\n2. Click the search bar at the top of the screen.\n3. Type Advanced Resource Query and hit enter.\n4. Click the Advanced Resource Query button in the upper right corner of the\nscreen.\n5. Enter the following query in the query box:\nquery networksecuritygroup resources where lifeCycleState = 'AVAILABLE'\n6. For each of the network security groups in the returned results, click the name\nand inspect each of the security rules.\n7. Ensure that there are no security rules with direction: Ingress, Source: 0.0.0.0/0,\nand Destination Port Range: 22.\nFrom CLI:\nIssue the following command, it should return no values.\nfor region in $(oci iam region-subscription list | jq -r '.data[] | .\"region-\nname\"')\ndo\necho \"Enumerating region $region\"\nfor compid in $(oci iam compartment list --include-root --compartment-\nid-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id')\ndo\necho \"Enumerating compartment $compid\"\nfor nsgid in $(oci network nsg list --compartment-id $compid --region\n$region --all 2>/dev/null | jq -r '.data[] | .id')\ndo\noutput=$(oci network nsg rules list --nsg-id=$nsgid --all\n2>/dev/null | jq -r '.data[] | select(.source == \"0.0.0.0/0\" and .direction\n== \"INGRESS\" and ((.\"tcp-options\".\"destination-port-range\".max >=  22 and\n.\"tcp-options\".\"destination-port-range\".min <= 22) or .\"tcp-\noptions\".\"destination-port-range\" == null))')\nif [ ! -z \"$output\" ]; then echo \"NSGID: \", $nsgid, \"Security\nRules: \", $output; fi\ndone\ndone\ndone\nCloud Guard:\nTo Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root\ncompartment of the tenancy. For more information about enabling Cloud Guard, please\nlook at the instructions included in Recommendation 3.15.\nFrom Console:\n1. Type Cloud Guard into the Search box at the top of the Console .\n2. Click Cloud Guard from the “Services” submenu.\n3. Click Detector Recipes in the Cloud Guard menu.\n4. Click OCI Configuration Detector Recipe (Oracle Managed) under the\nRecipe Name column.\n5. Find NSG ingress rule contains disallowed IP/port in the Detector Rules column.\n6. Select the vertical ellipsis icon and chose Edit on the NSG ingress rule contains\ndisallowed IP/port row.\n7. In the Edit Detector Rule window find the Input Setting box and verify/add to the\nRestricted Protocol: Ports List setting to TCP:[22], UDP:[22].\n8. Click the Save button.\nFrom CLI:\n1. Update the NSG ingress rule contains disallowed IP/port Detector Rule in Cloud\nGuard to generate Problems if a network security group allows ingress network\ntraffic to port 22 with the following command:\noci cloud-guard detector-recipe-detector-rule update --detector-recipe-id\n<insert detector recipe ocid> --detector-rule-id\nVCN_NSG_INGRESS_RULE_PORTS_CHECK --details '{\"configurations\":[ {\"configKey\"\n: \"nsgIngressRuleDisallowedPortsConfig\", \"name\" : \"Default disallowed ports\",\n\"value\" : \"TCP:[22], UDP:[22]\", \"dataType\" : null, \"values\" : null }]}'",
    "expected_response": "7. Ensure that there are no security rules with direction: Ingress, Source: 0.0.0.0/0,\nIssue the following command, it should return no values.\noutput=$(oci network nsg rules list --nsg-id=$nsgid --all\nif [ ! -z \"$output\" ]; then echo \"NSGID: \", $nsgid, \"Security\nRules: \", $output; fi\nTo Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root",
    "remediation": "From Console:\n1. Login into the OCI Console.\n2. Click the search bar at the top of the screen.\n3. Type Advanced Resource Query and hit enter.\n4. Click the Advanced Resource Query button in the upper right corner of the\nscreen.\n5. Enter the following query in the query box:\nquery networksecuritygroup resources where lifeCycleState = 'AVAILABLE'\n6. For each of the network security groups in the returned results, click the name\nand inspect each of the security rules.\n7. Remove all security rules with direction: Ingress, Source: 0.0.0.0/0, and\nDestination Port Range: 22.\nFrom CLI:\nIssue the following command and identify the security rule to remove.\nfor region in `oci iam region list | jq -r '.data[] | .name'`;\ndo\nfor compid in `oci iam compartment list 2>/dev/null | jq -r '.data[] |\n.id'`;\ndo\nfor nsgid in `oci network nsg list --compartment-id $compid --\nregion $region --all 2>/dev/null | jq -r '.data[] | .id'`\ndo\noutput=`oci network nsg rules list --nsg-id=$nsgid --all\n2>/dev/null | jq -r '.data[] | select(.source == \"0.0.0.0/0\" and .direction\n== \"INGRESS\" and ((.\"tcp-options\".\"destination-port-range\".max >=  22 and\n.\"tcp-options\".\"destination-port-range\".min <= 22) or .\"tcp-\noptions\".\"destination-port-range\" == null))'`\nif [ ! -z \"$output\" ]; then echo \"NSGID=\", $nsgid,\n\"Security Rules=\", $output; fi\ndone\ndone\ndone\n• Remove the security rules\noci network nsg rules remove --nsg-id=<NSGID from audit output>\nor\n• Update the security rules\noci network nsg rules update --nsg-id=<NSGID from audit output> --security-\nrules='[<updated security-rules JSON (without isValid and TimrCreated\nfields)>]'\neg:\noci network nsg rules update --nsg-\nid=ocid1.networksecuritygroup.oc1.iad.xxxxxxxxxxxxxxxxxxxxxx --security-\nrules='[{ \"description\": null, \"destination\": null, \"destination-type\": null,\n\"direction\": \"INGRESS\", \"icmp-options\": null, \"id\": \"709001\", \"is-stateless\":\nnull, \"protocol\": \"6\", \"source\": \"140.238.154.0/24\", \"source-type\":\n\"CIDR_BLOCK\", \"tcp-options\": { \"destination-port-range\": { \"max\": 22, \"min\":\n22 }, \"source-port-range\": null }, \"udp-options\": null }]'",
    "detection_commands": [
      "$region --all 2>/dev/null | jq -r '.data[] | .id')",
      "oci cloud-guard detector-recipe-detector-rule update --detector-recipe-id"
    ],
    "remediation_commands": [
      "oci network nsg rules remove --nsg-id=<NSGID from audit output>",
      "oci network nsg rules update --nsg-id=<NSGID from audit output> --security-",
      "oci network nsg rules update --nsg-"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 66,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.4",
    "title": "Ensure no network security groups allow ingress from 0.0.0.0/0 to port 3389",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "source_port_range_null_udp_options_null",
    "domain": "}, \"source-port-range\": null }, \"udp-options\": null }]'",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "Network security groups provide stateful filtering of ingress/egress network traffic to OCI\nresources. It is recommended that no security group allows unrestricted ingress access\nto port 3389.",
    "rationale": "Removing unfettered connectivity to remote console services, such as Remote Desktop\nProtocol (RDP), reduces a server's exposure to risk.",
    "impact": "For updating an existing environment, care should be taken to ensure that\nadministrators currently relying on an existing ingress from 0.0.0.0/0 have access to\nports 22 and/or 3389 through another network security group or security list.",
    "audit": "From CLI:\nIssue the following command, it should not return anything.\nfor region in $(oci iam region-subscription list | jq -r '.data[] |\n.\"region-name\"')\ndo\necho \"Enumerating region $region\"\nfor compid in $(oci iam compartment list --include-root --compartment-\nid-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id')\ndo\necho \"Enumerating compartment $compid\"\nfor nsgid in $(oci network nsg list --compartment-id $compid --region\n$region --all 2>/dev/null | jq -r '.data[] | .id')\ndo\noutput=$(oci network nsg rules list --nsg-id=$nsgid --all\n2>/dev/null | jq -r '.data[] | select(.source == \"0.0.0.0/0\" and .direction\n== \"INGRESS\" and ((.\"tcp-options\".\"destination-port-range\".max >=  3389 and\n.\"tcp-options\".\"destination-port-range\".min <= 3389) or .\"tcp-\noptions\".\"destination-port-range\" == null))')\nif [ ! -z \"$output\" ]; then echo \"NSGID: \", $nsgid, \"Security\nRules: \", $output; fi\ndone\ndone\ndone\nFrom Cloud Guard:\nTo Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root\ncompartment of the tenancy. For more information about enabling Cloud Guard, please\nlook at the instructions included in Recommendation 3.15.\nFrom Console:\n1. Type Cloud Guard into the Search box at the top of the Console.\n2. Click Cloud Guard from the “Services” submenu.\n3. Click Detector Recipes in the Cloud Guard menu.\n4. Click OCI Configuration Detector Recipe (Oracle Managed) under the\nRecipe Name column.\n5. Find NSG ingress rule contains disallowed IP/port in the Detector Rules column.\n6. Select the vertical ellipsis icon and chose Edit on the NSG ingress rule contains\ndisallowed IP/port row.\n7. In the Edit Detector Rule window find the Input Setting box and verify/add to the\nRestricted Protocol: Ports List setting to TCP:[3389], UDP:[3389].\n8. Click the Save button.\nFrom CLI:\n1. Update the NSG ingress rule contains disallowed IP/port Detector Rule in Cloud\nGuard to generate Problems if a network security group allows ingress network\ntraffic to port 3389 with the following command:\noci cloud-guard detector-recipe-detector-rule update --detector-recipe-id\n<insert detector recipe ocid> --detector-rule-id\nVCN_NSG_INGRESS_RULE_PORTS_CHECK --details '{\"configurations\":[ {\"configKey\"\n: \"nsgIngressRuleDisallowedPortsConfig\", \"name\" : \"Default disallowed ports\",\n\"value\" : \"TCP:[3389], UDP:[3389]\", \"dataType\" : null, \"values\" : null }]}'",
    "expected_response": "Issue the following command, it should not return anything.\noutput=$(oci network nsg rules list --nsg-id=$nsgid --all\nif [ ! -z \"$output\" ]; then echo \"NSGID: \", $nsgid, \"Security\nRules: \", $output; fi\nTo Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root",
    "remediation": "From CLI:\nUsing the details returned from the audit procedure either:\n• Remove the security rules\noci network nsg rules remove --nsg-id=<NSGID from audit output>\nor\n• Update the security rules\noci network nsg rules update --nsg-id=<NSGID from audit output>  --security-\nrules=<updated security-rules JSON (without the isValid or TimeCreated\nfields)>\neg:\noci network nsg rules update --nsg-\nid=ocid1.networksecuritygroup.oc1.iad.xxxxxxxxxxxxxxxxxxxxxx --security-\nrules='[{ \"description\": null, \"destination\": null, \"destination-type\": null,\n\"direction\": \"INGRESS\", \"icmp-options\": null, \"id\": \"709001\", \"is-stateless\":\nnull, \"protocol\": \"6\", \"source\": \"140.238.154.0/24\", \"source-type\":\n\"CIDR_BLOCK\", \"tcp-options\": { \"destination-port-range\": { \"max\": 3389,\n\"min\": 3389 }, \"source-port-range\": null }, \"udp-options\": null }]'",
    "detection_commands": [
      "$region --all 2>/dev/null | jq -r '.data[] | .id')",
      "oci cloud-guard detector-recipe-detector-rule update --detector-recipe-id"
    ],
    "remediation_commands": [
      "oci network nsg rules remove --nsg-id=<NSGID from audit output>",
      "oci network nsg rules update --nsg-id=<NSGID from audit output> --security-",
      "oci network nsg rules update --nsg-"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 70,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.5",
    "title": "Ensure the default security list of every VCN restricts all traffic except ICMP within VCN",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "source_port_range_null_udp_options_null",
    "domain": "}, \"source-port-range\": null }, \"udp-options\": null }]'",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "A default security list is created when a Virtual Cloud Network (VCN) is created and\nattached to the public subnets in the VCN. Security lists provide stateful or stateless\nfiltering of ingress and egress network traffic to OCI resources in the VCN. It is\nrecommended that the default security list does not allow unrestricted ingress and\negress access to resources in the VCN.",
    "rationale": "Removing unfettered connectivity to OCI resource, reduces a server's exposure to\nunauthorized access or data exfiltration.",
    "impact": "For updating existing environments Ingress rules with a source of 0.0.0.0/0, ensure that\nthe necessary access is available through another Network Security Group or Security\nList.\nFor updating existing environments Egress rules with a destination of 0.0.0.0/0 for an\nexisting environment, ensure egress is covered via another Network Security Group,\nSecurity List, or through the stateful nature of the ingress rule.",
    "audit": "From Console:\n1. Login into the OCI Console\n2. Click on Networking -> Virtual Cloud Networks from the services menu\n3. For each VCN listed Click on Security Lists\n4. Click on Default Security List for <VCN Name>\n5. Verify that there is no Ingress rule with 'Source 0.0.0.0/0'\n6. Verify that there is no Egress rule with 'Destination 0.0.0.0/0, All Protocols'",
    "remediation": "From Console:\n1. Login into the OCI Console\n2. Click on Networking -> Virtual Cloud Networks from the services menu\n3. For each VCN listed Click on Security Lists\n4. Click on Default Security List for <VCN Name>\n5. Identify the Ingress Rule with 'Source 0.0.0.0/0'\n6. Either Edit the Security rule to restrict the source and/or port range or delete the\nrule.\n7. Identify the Egress Rule with 'Destination 0.0.0.0/0, All Protocols'\n8. Either Edit the Security rule to restrict the source and/or port range or delete the\nrule.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://docs.oracle.com/en-",
      "us/iaas/Content/Security/Reference/networking_security.htm#Securing_Networki",
      "ng_VCN_Load_Balancers_and_DNS"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 73,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "2.6",
    "title": "Ensure Oracle Integration Cloud (OIC) access is restricted to allowed sources",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "source_port_range_null_udp_options_null",
    "domain": "}, \"source-port-range\": null }, \"udp-options\": null }]'",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "Oracle Integration (OIC) is a complete, secure, but lightweight integration solution that\nenables you to connect your applications in the cloud. It simplifies connectivity between\nyour applications and connects both your applications that live in the cloud and your\napplications that still live on premises. Oracle Integration provides secure, enterprise-\ngrade connectivity regardless of the applications you are connecting or where they\nreside. OIC instances are created within an Oracle managed secure private network\nwith each having a public endpoint. The capability to configure ingress filtering of\nnetwork traffic to protect your OIC instances from unauthorized network access is\nincluded. It is recommended that network access to your OIC instances be restricted to\nyour approved corporate IP Addresses or Virtual Cloud Networks (VCN)s.",
    "rationale": "Restricting connectivity to OIC Instances reduces an OIC instance’s exposure to risk.",
    "impact": "When updating ingress filters for an existing environment, care should be taken to\nensure that IP addresses and VCNs currently used by administrators, users, and\nservices to access your OIC instances are included in the updated filters.",
    "audit": "From Console:\n1. Login into the OCI Console\n2. Click in the search bar, top of the screen.\n3. Type Advanced Resource Query and hit enter.\n4. Click the Advanced Resource Query button in the upper right of the screen.\n5. Enter the following query in the query box:\nquery integrationinstance resources\n6. For each OIC Instance returned click on the link under Display name\n7. Click on Network Access\n8 .Ensure Restrict Network Access is selected and the IP Address/CIDR\nBlock as well as Virtual Cloud Networks are correct\n8. Repeat for other subscribed regions\nFrom CLI:\n1. Execute the following command:\nfor region in `oci iam region list | jq -r '.data[] | .name'`;\ndo\nfor compid in `oci iam compartment list --compartment-id-in-subtree\nTRUE 2>/dev/null | jq -r '.data[] | .id'`\ndo\noutput=`oci integration integration-instance list --compartment-\nid $compid --region $region --all 2>/dev/null | jq -r '.data[] |\nselect(.\"network-endpoint-details\".\"network-endpoint-type\" == null)'`\nif [ ! -z \"$output\" ]; then echo $output; fi\ndone\ndone\n2. Ensure allowlisted-http-ips and allowed-http-vcns are correct",
    "expected_response": "8 .Ensure Restrict Network Access is selected and the IP Address/CIDR\noutput=`oci integration integration-instance list --compartment-\nif [ ! -z \"$output\" ]; then echo $output; fi\n2. Ensure allowlisted-http-ips and allowed-http-vcns are correct",
    "remediation": "From Console:\n1. Follow the audit procedure above.\n2. For each OIC instance in the returned results, click the OIC Instance name\n3. Click Network Access\n4. Either edit the Network Access to be more restrictive\nFrom CLI\n1. Follow the audit procedure.\n2. Get the json input format using the below command:\noci integration integration-instance change-network-endpoint --generate-\nparam-json-input\n3.For each of the OIC Instances identified get its details. 4.Update the Network\nAccess, copy the network-endpoint-details element from the JSON returned by the\nabove get call, edit it appropriately and use it in the following command\nOci integration integration-instance change-network-endpoint --id <oic-\ninstance-id> --from-json '<network endpoints JSON>'",
    "detection_commands": [
      "select(.\"network-endpoint-details\".\"network-endpoint-type\" == null)'`"
    ],
    "remediation_commands": [
      "oci integration integration-instance change-network-endpoint --generate-",
      "Oci integration integration-instance change-network-endpoint --id <oic-"
    ],
    "references": [
      "1. https://docs.oracle.com/en/cloud/paas/integration-cloud/integrations-user/get-",
      "started-integration-cloud-service.html"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 75,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.7",
    "title": "Ensure Oracle Analytics Cloud (OAC) access is restricted to allowed sources or deployed within a Virtual Cloud Network",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "ensure_restrict_network_access_is_selected_and_the_ip_address_cidr",
    "domain": ".Ensure Restrict Network Access is selected and the IP Address/CIDR",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "Oracle Analytics Cloud (OAC) is a scalable and secure public cloud service that\nprovides a full set of capabilities to explore and perform collaborative analytics for you,\nyour workgroup, and your enterprise. OAC instances provide ingress filtering of network\ntraffic or can be deployed with in an existing Virtual Cloud Network VCN. It is\nrecommended that all new OAC instances be deployed within a VCN and that the\nAccess Control Rules are restricted to your corporate IP Addresses or VCNs for existing\nOAC instances.",
    "rationale": "Restricting connectivity to Oracle Analytics Cloud instances reduces an OAC instance’s\nexposure to risk.",
    "impact": "When updating ingress filters for an existing environment, care should be taken to\nensure that IP addresses and VCNs currently used by administrators, users, and\nservices to access your OAC instances are included in the updated filters. Also, these\nchanges will temporarily bring the OAC instance offline.",
    "audit": "From Console: 1 Login into the OCI Console 2. Click in the search bar, top of the\nscreen. 3. Type Advanced Resource Query and hit enter. 4. Click the Advanced\nResource Query button in the upper right of the screen. 5. Enter the following query in\nthe query box:\nquery analyticsinstance resources\n6. For each OAC Instance returned click on the link under Display name.\n7. Ensure Access Control Rules IP Address/CIDR Block as well as Virtual Cloud\nNetworks are correct.\n8. Repeat for other subscribed regions.\nFrom CLI:\n1. Execute the following command:\nfor region in `oci iam region list | jq -r '.data[] | .name'`;\ndo\nfor compid in `oci iam compartment list --compartment-id-in-subtree\nTRUE 2>/dev/null | jq -r '.data[] | .id'`\ndo\noutput=`oci analytics analytics-instance list --compartment-id\n$compid --region $region --all 2>/dev/null | jq -r '.data[] |\nselect(.\"network-endpoint-details\".\"network-endpoint-type\"  == \"PUBLIC\")'`\nif [ ! -z \"$output\" ]; then echo $output; fi\ndone\ndone\n2. Ensure network-endpoint-type are correct.",
    "expected_response": "7. Ensure Access Control Rules IP Address/CIDR Block as well as Virtual Cloud\noutput=`oci analytics analytics-instance list --compartment-id\nif [ ! -z \"$output\" ]; then echo $output; fi\n2. Ensure network-endpoint-type are correct.",
    "remediation": "From Console:\n1. Follow the audit procedure above.\n2. For each OAC instance in the returned results, click the OAC Instance name\n3. Click Edit next to Access Control Rules\n4. Click +Another Rule and add rules as required\nFrom CLI:\n1. Follow the audit procedure.\n2. Get the json input format by executing the below command:\noci analytics analytics-instance change-network-endpoint --generate-full-\ncommand-json-input\n3. For each of the OAC Instances identified get its details.\n4. Update the Access Control Rules, copy the network-endpoint-details\nelement from the JSON returned by the above get call, edit it appropriately and\nuse it in the following command:\noci integration analytics-instance change-network-endpoint --from-json\n'<network endpoints JSON>'",
    "additional_information": "https://docs.oracle.com/en/cloud/paas/analytics-cloud/acoci/manage-service-access-\nand-security.html#GUID-3DB25824-4417-4981-9EEC-29C0C6FD3883",
    "detection_commands": [
      "$compid --region $region --all 2>/dev/null | jq -r '.data[] | select(.\"network-endpoint-details\".\"network-endpoint-type\" == \"PUBLIC\")'`"
    ],
    "remediation_commands": [
      "oci analytics analytics-instance change-network-endpoint --generate-full-",
      "use it in the following command: oci integration analytics-instance change-network-endpoint --from-json '<network endpoints JSON>'"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 78,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.8",
    "title": "Ensure Oracle Autonomous Shared Databases (ADB) access is restricted to allowed sources or deployed within a Virtual Cloud Network",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "ensure_restrict_network_access_is_selected_and_the_ip_address_cidr",
    "domain": ".Ensure Restrict Network Access is selected and the IP Address/CIDR",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "Oracle Autonomous Database Shared (ADB-S) automates database tuning, security,\nbackups, updates, and other routine management tasks traditionally performed by\nDBAs. ADB-S provide ingress filtering of network traffic or can be deployed within an\nexisting Virtual Cloud Network (VCN). It is recommended that all new ADB-S databases\nbe deployed within a VCN and that the Access Control Rules are restricted to your\ncorporate IP Addresses or VCNs for existing ADB-S databases.",
    "rationale": "Restricting connectivity to ADB-S Databases reduces an ADB-S database’s exposure to\nrisk.",
    "impact": "When updating ingress filters for an existing environment, care should be taken to\nensure that IP addresses and VCNs currently used by administrators, users, and\nservices to access your ADB-S instances are included in the updated filters.",
    "audit": "From Console:\n1. Login into the OCI Console\n2. Click in the search bar, top of the screen.\n3. Type Advanced Resource Query and hit enter.\n4. Click the Advanced Resource Query button in the upper right of the screen.\n5. Enter the following query in the query box:\nquery autonomousdatabase resources\n6. For each ABD-S database returned click on the link under Display name\n7. Click Edit next to Access Control List\n8. Ensure `Access Control Rules’ IP Address/CIDR Block as well as VCNs are\ncorrect\n9. Repeat for other subscribed regions\nFrom CLI:\n1. Execute the following command:\nfor region in `oci iam region list | jq -r '.data[] | .name'`;\ndo\nfor compid in `oci iam compartment list --compartment-id-in-subtree\nTRUE 2>/dev/null | jq -r '.data[] | .id'`\ndo\nfor adbid in `oci db autonomous-database list --compartment-id\n$compid --region $region --all 2>/dev/null | jq -r '.data[] | select(.\"nsg-\nids\"  == null).id'`\ndo\noutput=`oci db autonomous-database get --autonomous-database-\nid $adbid --region $region --query=data.{\"WhiteListIPs:\\\"whitelisted-\nips\\\",\"id:id\"\"} --output table 2>/dev/null`\nif [ ! -z \"$output\" ]; then echo $output; fi\ndone\ndone\ndone\n2. Ensure WhiteListIPs are correct.",
    "expected_response": "8. Ensure `Access Control Rules’ IP Address/CIDR Block as well as VCNs are\noutput=`oci db autonomous-database get --autonomous-database-\nips\\\",\"id:id\"\"} --output table 2>/dev/null`\nif [ ! -z \"$output\" ]; then echo $output; fi\n2. Ensure WhiteListIPs are correct.",
    "remediation": "From Console:\n1. Follow the audit procedure above.\n2. For each ADB-S database in the returned results, click the ADB-S database\nname\n3. Click Edit next to Access Control Rules\n4. Click +Another Rule and add rules as required\n5. Click Save Changes\nFrom CLI:\n1. Follow the audit procedure.\n2. Get the json input format by executing the following command:\noci db autonomous-database update --generate-full-command-json-input\n3. For each of the ADB-S Database identified get its details.\n4. Update the whitelistIps, copy the WhiteListIPs element from the JSON\nreturned by the above get call, edit it appropriately and use it in the following\ncommand:\noci db autonomous-database update –-autonomous-database-id <ABD-S OCID> --\nfrom-json '<network endpoints JSON>'",
    "detection_commands": [
      "$compid --region $region --all 2>/dev/null | jq -r '.data[] | select(.\"nsg-"
    ],
    "remediation_commands": [
      "oci db autonomous-database update --generate-full-command-json-input",
      "oci db autonomous-database update –-autonomous-database-id <ABD-S OCID> --"
    ],
    "references": [
      "1. https://docs.oracle.com/en/cloud/paas/autonomous-database/adbsa/network-",
      "access-options.html#GUID-29D62917-0F18-4F3E-8081-B3BD5C0C79F5"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 81,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D3",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.1",
    "title": "Ensure Compute Instance Legacy Metadata service endpoint is disabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "compute",
    "domain": "Compute",
    "description": "Compute Instances that utilize Legacy MetaData service endpoints (IMDSv1) are\nsusceptible to potential SSRF attacks. To bolster security measures, it is strongly\nadvised to reconfigure Compute Instances to adopt Instance Metadata Service v2,\naligning with the industry's best security practices.",
    "rationale": "Enabling Instance Metadata Service v2 enhances security and grants precise control\nover metadata access. Transitioning from IMDSv1 reduces the risk of SSRF attacks,\nbolstering system protection.\nIMDv1 poses security risks due to its inferior security measures and limited auditing\ncapabilities. Transitioning to IMDv2 ensures a more secure environment with robust\nsecurity features and improved monitoring capabilities.",
    "impact": "IMDBSv2 has been available since 2020 and has been supported by Oracle platform\nimages and the Oracle Cloud Agent since mid-2020. Custom images made from Oracle\nplatform images after that availability will support IMDBSv2. This duration has provided\nample time for other custom images and Marketplace images to support IMDSv2.\nIf using a third-party image check with your provider to see if they support IMDSv2.",
    "audit": "From Console:\n1. Login to the OCI Console\n2. Select compute instance in your compartment.\n3. Click on each instance name.\n4. In the Instance Details section, next to Instance metadata service make\nsure Version 2 only is selected.\nFrom CLI:\n1. Run command:\nfor region in `oci iam region-subscription list | jq -r '.data[] | .\"region-\nname\"'`;\ndo\nfor compid in `oci iam compartment list --compartment-id-in-subtree\nTRUE 2>/dev/null | jq -r '.data[] | .id'`\ndo\noutput=`oci compute instance list --compartment-id $compid --\nregion $region --all 2>/dev/null | jq -r '.data[] | select(.\"instance-\noptions\".\"are-legacy-imds-endpoints-disabled\" == false )'`\nif [ ! -z \"$output\" ]; then echo $output; fi\ndone\ndone\n2. No results should be returned",
    "expected_response": "output=`oci compute instance list --compartment-id $compid --\nif [ ! -z \"$output\" ]; then echo $output; fi\n2. No results should be returned",
    "remediation": "From Console:\n1. Login to the OCI Console\n2. Click on the search box at the top of the console and search for compute\ninstance name.\n3. Click on the instance name, In the Instance Details section, next to Instance\nMetadata Service, click Edit.\n4. For the Instance metadata service, select the Version 2 only option.\n5. Click Save Changes.\nNote : Disabling IMDSv1 on an incompatible instance may result issues upon launch.\nTo re-enable IMDSv1, follow these steps:\n1. On the Instance Details page in the Console, click Edit next to Instance\nMetadata Service.\n2. Choose the Version 1 and version 2 option, and save your changes.\nFrom CLI:\nRun Below Command,\noci compute instance update --instance-id [instance-ocid] --instance-options\n'{\"areLegacyImdsEndpointsDisabled\" :\"true\"}'\nThis will set Instance Metadata Service to use Version 2 Only.",
    "default_value": "Versions 1 and 2",
    "detection_commands": [],
    "remediation_commands": [
      "oci compute instance update --instance-id [instance-ocid] --instance-options '{\"areLegacyImdsEndpointsDisabled\" :\"true\"}'"
    ],
    "references": [
      "1. https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 85,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.2",
    "title": "Ensure Secure Boot is enabled on Compute Instance",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "compute",
    "domain": "Compute",
    "subdomain": "Uninstall or Disable Unnecessary Services on",
    "description": "Shielded Instances with Secure Boot enabled prevents unauthorized boot loaders and\noperating systems from booting. This prevent rootkits, bootkits, and unauthorized\nsoftware from running before the operating system loads. Secure Boot verifies the\ndigital signature of the system's boot software to check its authenticity. The digital\nsignature ensures the operating system has not been tampered with and is from a\ntrusted source. When the system boots and attempts to execute the software, it will first\ncheck the digital signature to ensure validity. If the digital signature is not valid, the\nsystem will not allow the software to run. Secure Boot is a feature of UEFI(Unified\nExtensible Firmware Interface) that only allows approved operating systems to boot up.",
    "rationale": "A Threat Actor with access to the operating system may seek to alter boot components\nto persist malware or rootkits during system initialization. Secure Boot helps ensure that\nthe system only runs authentic software by verifying the digital signature of all boot\ncomponents.",
    "impact": "An existing instance cannot be changed to a Shielded instance with Secure boot\nenabled. Shielded Secure Boot not available on all instance shapes and Operating\nsystems. Additionally the following limitations exist:\nThus to enable you have to terminate the instance and create a new one. Also,\nShielded instances do not support live migration. During an infrastructure maintenance\nevent, Oracle Cloud Infrastructure live migrates supported VM instances from the\nphysical VM host that needs maintenance to a healthy VM host with minimal disruption\nto running instances. If you enable Secure Boot on an instance, the instance cannot be\nmigrated, because the hardware TPM is not migratable. This may result in an outage\nbecause the TPM can't be migrate from a unhealthy host to healthy host.",
    "audit": "From Console:\n1. Login to the OCI Console\n2. Select compute instance in your compartment.\n3. Click on each instance name.\n4. In the Launch Options section,\n5. Check if Secure Boot is Enabled.\nFrom CLI:\nRun command:\nfor region in `oci iam region-subscription list | jq -r '.data[] | .\"region-\nname\"'`;\ndo\nfor compid in `oci iam compartment list --compartment-id-in-subtree\nTRUE 2>/dev/null | jq -r '.data[] | .id'`\ndo\noutput=`oci compute instance list --compartment-id $compid --\nregion $region --all 2>/dev/null | jq -r '.data[] | select(.\"platform-config\"\n== null or \"platform-config\".\"is-secure-boot-enabled\" == false )'`\nif [ ! -z \"$output\" ]; then echo $output; fi\ndone\ndone\nIn response, check if platform-config are not null and is-secure-boot-enabled is\nset to true",
    "expected_response": "5. Check if Secure Boot is Enabled.\noutput=`oci compute instance list --compartment-id $compid --\nif [ ! -z \"$output\" ]; then echo $output; fi",
    "remediation": "Note: Secure Boot facility is available on selected VM images and Shapes in OCI. User\nhave to configure Secured Boot at time of instance creation only.\nFrom Console:\n1. Navigate to https://cloud.oracle.com/compute/instances\n2. Select the instance from the Audit Procedure\n3. Click Terminate.\n4. Determine whether or not to permanently delete instance's attached boot volume.\n5. Click Terminate instance.\n6. Click on Create Instance.\n7. Select Image and Shape which supports Shielded Instance configuration. Icon\nfor Shield in front of Image/Shape row indicates support of Shielded Instance.\n8. Click on edit of Security Blade.\n9. Turn On Shielded Instance, then Turn on the Secure Boot Toggle.\n10. Fill in the rest of the details as per requirements.\n11. Click Create.",
    "default_value": "Secure Boot is not Enabled",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-",
      "instances.htm",
      "2. https://uefi.org/sites/default/files/resources/UEFI_Secure_Boot_in_Modern_Com",
      "puter_Security_Solutions_2013.pdf"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 88,
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
    "cis_id": "3.3",
    "title": "Ensure In-transit Encryption is enabled on Compute Instance",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "compute",
    "domain": "Compute",
    "subdomain": "Uninstall or Disable Unnecessary Services on",
    "description": "The Block Volume service provides the option to enable in-transit encryption for\nparavirtualized volume attachments on virtual machine (VM) instances.",
    "rationale": "All the data moving between the instance and the block volume is transferred over an\ninternal and highly secure network. If you have specific compliance requirements\nrelated to the encryption of the data while it is moving between the instance and the\nblock volume, you should enable the in-transit encryption option.",
    "impact": "In-transit encryption for boot and block volumes is only available for virtual machine\n(VM) instances launched from platform images, along with bare metal instances that\nuse the following shapes: BM.Standard.E3.128, BM.Standard.E4.128,\nBM.DenseIO.E4.128. It is not supported on other bare metal instances.",
    "audit": "From Console:\n1. Go to https://cloud.oracle.com/compute/instances\n2. Select compute instance in your compartment.\n3. Click on each instance name.\n4. Click on Boot volume on the bottom left.\n5. Under the In-transit encryption column make sure it is Enabled\nFrom CLI:\n1. Execute the following:\nfor region in `oci iam region-subscription list | jq -r '.data[] | .\"region-\nname\"'`;\ndo\nfor compid in `oci iam compartment list --compartment-id-in-subtree\nTRUE 2>/dev/null | jq -r '.data[] | .id'`\ndo\noutput=`oci compute instance list --compartment-id $compid --\nregion $region --all 2>/dev/null | jq -r '.data[] | select(.\"launch-\noptions\".\"is-pv-encryption-in-transit-enabled\" == false )'`\nif [ ! -z \"$output\" ]; then echo $output; fi\ndone\ndone\n2. Ensure no results are returned",
    "expected_response": "5. Under the In-transit encryption column make sure it is Enabled\noutput=`oci compute instance list --compartment-id $compid --\nif [ ! -z \"$output\" ]; then echo $output; fi\n2. Ensure no results are returned",
    "remediation": "From Console (if available for instance):\n1. Navigate to https://cloud.oracle.com/compute/instances\n2. Select the instance from the Audit Procedure\n3. Click More actions or Actions\n4. Click Edit\n5. Select Show Advanced Options\n6. Enable Use in-transit encryption\n7. Click Save changes\nFrom Console (if above option is NOT available for instance):\n1. Navigate to https://cloud.oracle.com/compute/instances\n2. Select the instance from the Audit Procedure\n3. Click Terminate.\n4. Determine whether or not to permanently delete instance's attached boot volume.\n5. Click Terminate instance.\n6. Click on Create Instance.\n7. Fill in the details as per requirements.\n8. In the Boot volume section ensure Use in-transit encryption is checked.\n9. Fill in the rest of the details as per requirements.\n10. Click Create.",
    "default_value": "Enabled",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://docs.oracle.com/en-",
      "us/iaas/Content/Block/Concepts/overview.htm#BlockVolumeEncryption__intransi",
      "t"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 91,
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
    "cis_id": "4.1",
    "title": "Ensure default tags are used on resources",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "description": "Using default tags is a way to ensure all resources that support tags are tagged during\ncreation. Tags can be based on static or computed values. It is recommended to set up\ndefault tags early after root compartment creation to ensure all created resources will\nget tagged. Tags are scoped to Compartments and are inherited by Child\nCompartments. The recommendation is to create default tags like “CreatedBy” at the\nRoot Compartment level to ensure all resources get tagged. When using Tags it is\nimportant to ensure that Tag Namespaces are protected by IAM Policies otherwise this\nwill allow users to change tags or tag values. Depending on the age of the OCI Tenancy\nthere may already be Tag defaults setup at the Root Level and no need for further\naction to implement this action.",
    "rationale": "In the case of an incident having default tags like “CreatedBy” applied will provide info\non who created the resource without having to search the Audit logs.",
    "impact": "There is no performance impact when enabling the above described features.",
    "audit": "From Console:\n1. Login to OCI Console.\n2. From the navigation menu, select Identity & Security.\n3. Under Identity, select Compartments.\n4. Click the name of the root compartment.\n5. Under Resources, select Tag Defaults.\n6. In the Tag Defaults table, verify that there is a Tag with a value of\n${iam.principal.name} and a Tag Key Status of Active.\nNote: The name of the tag may be different then “CreatedBy” if the Tenancy\nAdministrator has decided to use another tag.\nFrom CLI:\n1. List the active tag defaults defined at the Root compartment level by using the\nTenancy OCID as compartment id.\nNote: The Tenancy OCID can be found in the ~/.oci/config file used by the\nOCI Command Line Tool\noci iam tag-default list --compartment-id=<tenancy_ocid> --query=\"data\n[?\\\"lifecycle-state\\\"=='ACTIVE']\".{\"name:\\\"tag-definition-\nname\\\",\"value:value\"\"} --output table\n2. Verify in the table returned that there is at least one row that contains the value of\n${iam.principal.name}.",
    "expected_response": "name\\\",\"value:value\"\"} --output table",
    "remediation": "From Console:\n1. Login to OCI Console.\n2. From the navigation menu, select Governance & Administration.\n3. Under Tenancy Management, select Tag Namespaces.\n4. Under Compartment, select the root compartment.\n5. If no tag namespace exists, click Create Tag Namespace, enter a name and\ndescription and click Create Tag Namespace.\n6. Click the name of a tag namespace.\n7. Click Create Tag Key Definition.\n8. Enter a tag key (e.g. CreatedBy) and description, and click Create Tag Key\nDefinition.\n9. From the navigation menu, select Identity & Security.\n10. Under Identity, select Compartments.\n11. Click the name of the root compartment.\n12. Under Resources, select Tag Defaults.\n13. Click Create Tag Default.\n14. Select a tag namespace, tag key, and enter ${iam.principal.name} as the tag\nvalue.\n15. Click Create.\nFrom CLI:\n1. Create a Tag Namespace in the Root Compartment\noci iam tag-namespace create --compartment-id=<tenancy_ocid> --name=<name> --\ndescription=<description> --query data.{\"\\\"Tag Namespace OCID\\\":id\"} --output\ntable\n2. Note the Tag Namespace OCID and use it when creating the Tag Key Definition\noci iam tag create --tag-namespace-id=<tag_namespace_ocid> --\nname=<tag_key_name> --description=<description> --query data.{\"\\\"Tag Key\nDefinition OCID\\\":id\"} --output table\n3. Note the Tag Key Definition OCID and use it when creating the Tag Default in the\nRoot compartment\noci iam tag-default create --compartment-id=<tenancy_ocid> --tag-definition-\nid=<tag_key_definition_id> --value=\"\\${iam.principal.name}\"",
    "default_value": "New OCI Tenancies will have Tag Defaults setup for CreatedBy and CreatedOn as\ndefault. If this is the case then there is no remediate action required in the Tenancy in\norder to meet this specific control.",
    "additional_information": "• There is no requirement to use the “Oracle-Tags” namespace to implement this\ncontrol.\nA Tag Namespace Administrator can create any namespace and use it for this\ncontrol.",
    "detection_commands": [
      "OCI Command Line Tool oci iam tag-default list --compartment-id=<tenancy_ocid> --query=\"data"
    ],
    "remediation_commands": [
      "oci iam tag-namespace create --compartment-id=<tenancy_ocid> --name=<name> --",
      "oci iam tag create --tag-namespace-id=<tag_namespace_ocid> --",
      "oci iam tag-default create --compartment-id=<tenancy_ocid> --tag-definition-"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 95,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "4.2",
    "title": "Create at least one notification topic and subscription to receive monitoring alerts",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Maintain Detailed Asset Inventory",
    "description": "Notifications provide a multi-channel messaging service that allow users and\napplications to be notified of events of interest occurring within OCI. Messages can be\nsent via eMail, HTTPs, PagerDuty, Slack or the OCI Function service. Some channels,\nsuch as eMail require confirmation of the subscription before it becomes active.",
    "rationale": "Creating one or more notification topics allow administrators to be notified of relevant\nchanges made to OCI infrastructure.",
    "impact": "There is no performance impact when enabling the above described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Go to the Notifications Service page: https://console.us-ashburn-\n1.oraclecloud.com/notification/topics\n2. Select the Compartment that hosts the notifications\n3. Find and click the Topic relevant to your monitoring alerts.\n4. Ensure a valid active subscription is shown.\nFrom CLI:\n1. List the topics in the Compartment that hosts the notifications\noci ons topic list --compartment-id <compartment OCID> --all\n2. Note the OCID of the monitoring topic(s) using the topic-id field of the returned\nJSON and use it to list the subscriptions\noci ons subscription list --compartment-id <compartment OCID> --topic-id\n<topic OCID> --all\n3. Ensure at least one active subscription is returned",
    "expected_response": "4. Ensure a valid active subscription is shown.\n3. Ensure at least one active subscription is returned",
    "remediation": "From Console:\n1. Go to the Notifications Service page: https://console.us-ashburn-\n1.oraclecloud.com/notification/topics\n2. Select the Compartment that hosts the notifications\n3. Click Create Topic\n4. Set the name to something relevant\n5. Set the description to describe the purpose of the topic\n6. Click Create\n7. Click the newly created topic\n8. Click Create Subscription\n9. Choose the correct protocol\n10. Complete the correct parameter, for instance email address\n11. Click Create\nFrom CLI:\n1. Create a topic in a compartment\noci ons topic create --name <topic name> --description <topic description> --\ncompartment-id <compartment OCID>\n2. Note the OCID of the topic using the topic-id field of the returned JSON and\nuse it to create a new subscription\noci ons subscription create --compartment-id <compartment OCID> --topic-id\n<topic OCID> --protocol <protocol> --subscription-endpoint <subscription\nendpoint>\n3. The returned JSON includes the id of the subscription.",
    "additional_information": "• The console URL shown is for the Ashburn region. Your tenancy might have a\ndifferent home region and thus console URL.\n• The same Notification topic can be reused by many Events. A single topic can\nhave multiple subscriptions allowing the same topic to be published to multiple\nlocations.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "oci ons topic list --compartment-id <compartment OCID> --all",
      "oci ons subscription list --compartment-id <compartment OCID> --topic-id"
    ],
    "remediation_commands": [
      "oci ons topic create --name <topic name> --description <topic description> --",
      "use it to create a new subscription oci ons subscription create --compartment-id <compartment OCID> --topic-id"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 98,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "4.3",
    "title": "Ensure a notification is configured for Identity Provider changes",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Activate audit logging",
    "description": "It is recommended to setup an Event Rule and Notification that gets triggered when\nIdentity Providers are created, updated or deleted. Event Rules are compartment\nscoped and will detect events in child compartments. It is recommended to create the\nEvent rule at the root compartment level.",
    "rationale": "OCI Identity Providers allow management of User ID / passwords in external systems\nand use of those credentials to access OCI resources. Identity Providers allow users to\nsingle sign-on to OCI console and have other OCI credentials like API Keys. Monitoring\nand alerting on changes to Identity Providers will help in identifying changes to the\nsecurity posture.",
    "impact": "There is no performance impact when enabling the above described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Go to the Events Service page:\nhttps://cloud.oracle.com/events/rules\n2. Select the Compartment that hosts the rules\n3. Find and click the Rule that handles Identity Provider Changes (if any)\n4. Ensure the Rule is ACTIVE\n5. Click the Edit Rule button and verify that the RuleConditions section contains\na condition for the Service Identity and Event Types: Identity Provider –\nCreate, Identity Provider - Delete and Identity Provider – Update\n6. Verify that in the Actions section the Action Type contains: Notifications and\nthat a valid Topic is referenced.\nFrom CLI:\n1. Find the OCID of the specific Event Rule based on Display Name and\nCompartment OCID\noci events rule list --compartment-id <compartment-ocid> --query \"data\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n2. List the details of a specific Event Rule based on the OCID of the rule.\noci events rule get --rule-id <rule-id>\n3. In the JSON output locate the Conditions key value pair and verify that the\nfollowing Conditions are present:\ncom.oraclecloud.identitycontrolplane.createidentityprovider\ncom.oraclecloud.identitycontrolplane.deleteidentityprovider\ncom.oraclecloud.identitycontrolplane.updateidentityprovider\n4. Verify the value of the is-enabled attribute is true\n5. In the JSON output verify that actionType is ONS and locate the topic-id\n6. Verify the correct topic is used by checking the topic name\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output\ntable",
    "expected_response": "4. Ensure the Rule is ACTIVE\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n3. In the JSON output locate the Conditions key value pair and verify that the\n5. In the JSON output verify that actionType is ONS and locate the topic-id\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output",
    "remediation": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the compartment that should host the rule\n3. Click Create Rule\n4. Provide a Display Name and Description\n5. Create a Rule Condition by selecting Identity in the Service Name Drop-down\nand selecting Identity Provider – Create, Identity Provider - Delete\nand Identity Provider – Update\n6. In the Actions section select Notifications as Action Type\n7. Select the Compartment that hosts the Topic to be used.\n8. Select the Topic to be used\n9. Optionally add Tags to the Rule\n10. Click Create Rule\nFrom CLI:\n1. Find the topic-id of the topic the Event Rule should use for sending\nnotifications by using the topic name and Compartment OCID\noci ons topic list --compartment-id <compartment-ocid> --all --query \"data\n[?name=='<topic-name>']\".{\"name:name,topic_id:\\\"topic-id\\\"\"} --output table\n2. Create a JSON file to be used when creating the Event Rule. Replace topic id,\ndisplay name, description and compartment OCID.\n{\n\"actions\":\n{\n\"actions\": [\n{\n\"actionType\": \"ONS\",\n\"isEnabled\": true,\n\"topicId\": \"<topic-id>\"\n}]\n},\n\"condition\":\n\"{\\\"eventType\\\":[\\\"com.oraclecloud.identitycontrolplane.createidentityprovide\nr\\\",\\\" com.oraclecloud.identitycontrolplane.deleteidentityprovider\\\",\\\"\ncom.oraclecloud.identitycontrolplane.updateidentityprovider\\\"],\\\"data\\\":{}}\",\n\"displayName\": \"<display-name>\",\n\"description\": \"<description>\",\n\"isEnabled\": true,\n\"compartmentId\": \"<compartment-ocid>\"\n}\n3. Create the actual event rule\noci events rule create --from-json file://event_rule.json\n4. Note in the JSON returned that it lists the parameters specified in the JSON file\nprovided and that there is an OCID provided for the Event Rule",
    "additional_information": "• The same Notification topic can be reused by many Event Rules.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "Create, Identity Provider - Delete and Identity Provider – Update",
      "oci events rule list --compartment-id <compartment-ocid> --query \"data",
      "oci events rule get --rule-id <rule-id>",
      "oci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output"
    ],
    "remediation_commands": [
      "oci ons topic list --compartment-id <compartment-ocid> --all --query \"data",
      "oci events rule create --from-json file://event_rule.json"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 101,
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
    "cis_id": "4.4",
    "title": "Ensure a notification is configured for IdP group mapping changes",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Use Automated Tools to Verify Standard Device",
    "description": "It is recommended to setup an Event Rule and Notification that gets triggered when\nIdentity Provider Group Mappings are created, updated or deleted. Event Rules are\ncompartment scoped and will detect events in child compartments. It is recommended\nto create the Event rule at the root compartment level.",
    "rationale": "IAM Policies govern access to all resources within an OCI Tenancy. IAM Policies use\nOCI Groups for assigning the privileges. Identity Provider Groups could be mapped to\nOCI Groups to assign privileges to federated users in OCI. Monitoring and alerting on\nchanges to Identity Provider Group mappings will help in identifying changes to the\nsecurity posture.",
    "impact": "There is no performance impact when enabling the above described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Go to the Events Service page:\nhttps://cloud.oracle.com/events/rules\n2. Select the Compartment that hosts the rules\n3. Find and click the Rule that handles Idp Group Mapping Changes (if any)\n4. Ensure the Rule is ACTIVE\n5. Click the Edit Rule button and verify that the RuleConditions section contains\na condition for the Service Identity and Event Types: Idp Group Mapping –\nCreate, Idp Group Mapping – Delete and Idp Group Mapping – Update\n6. Verify that in the Actions section the Action Type contains: Notifications and\nthat a valid Topic is referenced.\nFrom CLI:\n1. Find the OCID of the specific Event Rule based on Display Name and\nCompartment OCID\noci events rule list --compartment-id <compartment-ocid> --query \"data\n[?\\\"display-name\\\"=='<displa-name>']\".{\"id:id\"} --output table\n2. List the details of a specific Event Rule based on the OCID of the rule.\noci events rule get --rule-id <rule-id>\n3. In the JSON output locate the Conditions key value pair and verify that the\nfollowing Conditions are present:\ncom.oraclecloud.identitycontrolplane.addidpgroupmapping\ncom.oraclecloud.identitycontrolplane.updateidpgroupmapping\ncom.oraclecloud.identitycontrolplane.removeidpgroupmapping\n4. Verify the value of the is-enabled attribute is true\n5. In the JSON output verify that actionType is ONS and locate the topic-id\n6. Verify the correct topic is used by checking the topic name\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output\ntable",
    "expected_response": "4. Ensure the Rule is ACTIVE\n[?\\\"display-name\\\"=='<displa-name>']\".{\"id:id\"} --output table\n3. In the JSON output locate the Conditions key value pair and verify that the\n5. In the JSON output verify that actionType is ONS and locate the topic-id\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output",
    "remediation": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the compartment that should host the rule\n3. Click Create Rule\n4. Provide a Display Name and Description\n5. Create a Rule Condition by selecting Identity in the Service Name Drop-down\nand selecting Idp Group Mapping – Create, Idp Group Mapping – Delete\nand Idp Group Mapping – Update\n6. In the Actions section select Notifications as Action Type\n7. Select the Compartment that hosts the Topic to be used.\n8. Select the Topic to be used\n9. Optionally add Tags to the Rule\n10. Click Create Rule\nFrom CLI:\n1. Find the topic-id of the topic the Event Rule should use for sending\nnotifications by using the topic name and Compartment OCID\noci ons topic list --compartment-id <compartment-ocid> --all --query \"data\n[?name=='<topic-name>']\".{\"name:name,topic_id:\\\"topic-id\\\"\"} --output table\n2. Create a JSON file to be used when creating the Event Rule. Replace topic id,\ndisplay name, description and compartment OCID.\n{\n\"actions\":\n{\n\"actions\": [\n{\n\"actionType\": \"ONS\",\n\"isEnabled\": true,\n\"topicId\": \"<topic-id>\"\n}]\n},\n\"condition\":\n\"{\\\"eventType\\\":[\\\"com.oraclecloud.identitycontrolplane.addidpgroupmapping\\\",\n\\\"com.oraclecloud.identitycontrolplane.removeidpgroupmapping\\\",\\\"com.oraclecl\noud.identitycontrolplane.updateidpgroupmapping\\\"],\\\"data\\\":{}}\",\n\"displayName\": \"<display-name>\",\n\"description\": \"<description>\",\n\"isEnabled\": true,\n\"compartmentId\": \"<compartment-ocid>\"\n}\n3. Create the actual event rule\noci events rule create --from-json file://event_rule.json\n4. Note in the JSON returned that it lists the parameters specified in the JSON file\nprovided and that there is an OCID provided for the Event Rule",
    "additional_information": "• The same Notification topic can be reused by many Event Rules.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "Create, Idp Group Mapping – Delete and Idp Group Mapping – Update",
      "oci events rule list --compartment-id <compartment-ocid> --query \"data",
      "oci events rule get --rule-id <rule-id>",
      "oci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output"
    ],
    "remediation_commands": [
      "oci ons topic list --compartment-id <compartment-ocid> --all --query \"data",
      "oci events rule create --from-json file://event_rule.json"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 105,
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
    "cis_id": "4.5",
    "title": "Ensure a notification is configured for IAM group changes",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Use Automated Tools to Verify Standard Device",
    "description": "It is recommended to setup an Event Rule and Notification that gets triggered when IAM\nGroups are created, updated or deleted. Event Rules are compartment scoped and will\ndetect events in child compartments, it is recommended to create the Event rule at the\nroot compartment level.",
    "rationale": "IAM Groups control access to all resources within an OCI Tenancy. Monitoring and\nalerting on changes to IAM Groups will help in identifying changes to satisfy least\nprivilege principle.",
    "impact": "There is no performance impact when enabling the above described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Go to the Events Service page:\nhttps://cloud.oracle.com/events/rules\n2. Select the Compartment that hosts the rules\n3. Find and click the Rule that handles IAM Group Changes\n4. Ensure the Rule is ACTIVE\n5. Click the Edit Rule button and verify that the Rule Conditions section\ncontains a condition for the Service Identity and Event Types: Group –\nCreate, Group – Delete and Group – Update\n6. Verify that in the Actions section the Action Type contains: Notifications and\nthat a valid Topic is referenced.\nFrom CLI:\n1. Find the OCID of the specific Event Rule based on Display Name and\nCompartment OCID\noci events rule list --compartment-id <compartment-ocid> --query \"data\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n2. List the details of a specific Event Rule based on the OCID of the rule.\noci events rule get --rule-id <rule-id>\n3. In the JSON output locate the Conditions key value pair and verify that the\nfollowing Conditions are present:\ncom.oraclecloud.identitycontrolplane.creategroup\ncom.oraclecloud.identitycontrolplane.deletegroup\ncom.oraclecloud.identitycontrolplane.updategroup\n4. Verify the value of the is-enabled attribute is true\n5. In the JSON output verify that actionType is ONS and locate the topic-id\n6. Verify the correct topic is used by checking the topic name\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output\ntable",
    "expected_response": "4. Ensure the Rule is ACTIVE\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n3. In the JSON output locate the Conditions key value pair and verify that the\n5. In the JSON output verify that actionType is ONS and locate the topic-id\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output",
    "remediation": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the compartment that should host the rule\n3. Click Create Rule\n4. Provide a Display Name and Description\n5. Create a Rule Condition by selecting Identity in the Service Name Drop-down\nand selecting Group – Create, Group – Delete and Group – Update\n6. In the Actions section select Notifications as Action Type\n7. Select the Compartment that hosts the Topic to be used.\n8. Select the Topic to be used\n9. Optionally add Tags to the Rule\n10. Click Create Rule\nFrom CLI:\n1. Find the topic-id of the topic the Event Rule should use for sending\nNotifications by using the topic name and Compartment OCID\noci ons topic list --compartment-id <compartment-ocid> --all --query \"data\n[?name=='<topic-name>']\".{\"name:name,topic_id:\\\"topic-id\\\"\"} --output table\n2. Create a JSON file to be used when creating the Event Rule. Replace topic id,\ndisplay name, description and compartment OCID.\n{\n\"actions\":\n{\n\"actions\": [\n{\n\"actionType\": \"ONS\",\n\"isEnabled\": true,\n\"topicId\": \"<topic-id>\"\n}]\n},\n\"condition\":\n\"{\\\"eventType\\\":[\\\"com.oraclecloud.identitycontrolplane.creategroup\\\",\\\"com.o\nraclecloud.identitycontrolplane.deletegroup\\\",\\\"com.oraclecloud.identitycontr\nolplane.updategroup\\\"],\\\"data\\\":{}}\",\n\"displayName\": \"<display-name>\",\n\"description\": \"<description>\",\n\"isEnabled\": true,\n\"compartmentId\": \"<compartment-ocid>\"\n}\n3. Create the actual event rule\noci events rule create --from-json file://event_rule.json\n4. Note in the JSON returned that it lists the parameters specified in the JSON file\nprovided and that there is an OCID provided for the Event Rule",
    "additional_information": "• The same Notification topic can be reused by many Event Rules.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "Create, Group – Delete and Group – Update",
      "oci events rule list --compartment-id <compartment-ocid> --query \"data",
      "oci events rule get --rule-id <rule-id>",
      "oci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output"
    ],
    "remediation_commands": [
      "oci ons topic list --compartment-id <compartment-ocid> --all --query \"data",
      "oci events rule create --from-json file://event_rule.json"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 109,
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
    "cis_id": "4.6",
    "title": "Ensure a notification is configured for IAM policy changes",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Use Automated Tools to Verify Standard Device",
    "description": "It is recommended to setup an Event Rule and Notification that gets triggered when IAM\nPolicies are created, updated or deleted. Event Rules are compartment scoped and will\ndetect events in child compartments, it is recommended to create the Event rule at the\nroot compartment level.",
    "rationale": "IAM Policies govern access to all resources within an OCI Tenancy. Monitoring and\nalerting on changes to IAM policies will help in identifying changes to the security\nposture.",
    "impact": "There is no performance impact when enabling the above described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Go to the Events Service page:\nhttps://cloud.oracle.com/events/rules\n2. Select the Compartment that hosts the rules\n3. Find and click the Rule that handles IAM Policy Changes (if any)\n4. Ensure the Rule is ACTIVE\n5. Click the Edit Rule button and verify that the RuleConditions section contains\na condition for the Service Identity and Event Types: Policy – Create,\nPolicy - Delete and Policy – Update\n6. Verify that in the Actions section the Action Type contains: Notifications and\nthat a valid Topic is referenced.\nFrom CLI:\n1. Find the OCID of the specific Event Rule based on Display Name and\nCompartment OCID\noci events rule list --compartment-id <compartment-ocid> --query \"data\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n2. List the details of a specific Event Rule based on the OCID of the rule.\noci events rule get --rule-id <rule-id>\n3. In the JSON output locate the Conditions key value pair and verify that the\nfollowing Conditions are present:\ncom.oraclecloud.identitycontrolplane.createpolicy\ncom.oraclecloud.identitycontrolplane.deletepolicy\ncom.oraclecloud.identitycontrolplane.updatepolicy\n4. Verify the value of the is-enabled attribute is true\n5. In the JSON output verify that actionType is ONS and locate the topic-id\n6. Verify the correct topic is used by checking the topic name\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output\ntable",
    "expected_response": "4. Ensure the Rule is ACTIVE\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n3. In the JSON output locate the Conditions key value pair and verify that the\n5. In the JSON output verify that actionType is ONS and locate the topic-id\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output",
    "remediation": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the compartment that should host the rule\n3. Click Create Rule\n4. Provide a Display Name and Description\n5. Create a Rule Condition by selecting Identity in the Service Name Drop-down\nand selecting Policy – Change Compartment, Policy – Create, Policy -\nDelete and Policy – Update\n6. In the Actions section select Notifications as Action Type\n7. Select the Compartment that hosts the Topic to be used.\n8. Select the Topic to be used\n9. Optionally add Tags to the Rule\n10. Click Create Rule\nFrom CLI:\n1. Find the topic-id of the topic the Event Rule should use for sending\nNotifications by using the topic name and Compartment OCID\noci ons topic list --compartment-id <compartment-ocid> --all --query \"data\n[?name=='<topic-name>']\".{\"name:name,topic_id:\\\"topic-id\\\"\"} --output table\n2. Create a JSON file to be used when creating the Event Rule. Replace topic id,\ndisplay name, description and compartment OCID.\n{\n\"actions\":\n{\n\"actions\": [\n{\n\"actionType\": \"ONS\",\n\"isEnabled\": true,\n\"topicId\": \"<topic-id>\"\n}]\n},\n\"condition\":\n\"{\\\"eventType\\\":[\\\"com.oraclecloud.identitycontrolplane.createpolicy\\\",\\\"com.\noraclecloud.identitycontrolplane.deletepolicy\\\",\\\"com.oraclecloud.identitycon\ntrolplane.updatepolicy\\\"],\\\"data\\\":{}}\",\n\"displayName\": \"<display-name>\",\n\"description\": \"<description>\",\n\"isEnabled\": true,\n\"compartmentId\": \"<compartment-ocid>\"\n}\n3. Create the actual event rule\noci events rule create --from-json file://event_rule.json\n4. Note in the JSON returned that it lists the parameters specified in the JSON file\nprovided and that there is an OCID provided for the Event Rule",
    "additional_information": "• The same Notification topic can be reused by many Event Rules.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "oci events rule list --compartment-id <compartment-ocid> --query \"data",
      "oci events rule get --rule-id <rule-id>",
      "oci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output"
    ],
    "remediation_commands": [
      "oci ons topic list --compartment-id <compartment-ocid> --all --query \"data",
      "oci events rule create --from-json file://event_rule.json"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 112,
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
    "cis_id": "4.7",
    "title": "Ensure a notification is configured for user changes",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Use Automated Tools to Verify Standard Device",
    "description": "It is recommended to setup an Event Rule and Notification that gets triggered when IAM\nUsers are created, updated, deleted, capabilities updated, or state updated. Event\nRules are compartment scoped and will detect events in child compartments, it is\nrecommended to create the Event rule at the root compartment level.",
    "rationale": "Users use or manage Oracle Cloud Infrastructure resources. Monitoring and alerting on\nchanges to Users will help in identifying changes to the security posture.",
    "impact": "There is no performance impact when enabling the above described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Using the search box to navigate to events\n2. Navigate to the rules page\n3. Select the Compartment that hosts the rules\n4. Find and click the Rule that handles IAM User Changes\n5. Ensure the Rule is ACTIVE\n6. Click the Edit Rule button and verify that the Rule Conditions section\ncontains a condition for the Service Identity and Event Types:\nUser – Create, User – Delete, User – Update, User Capabilities –\nUpdate, User State – Update\n7. Verify that in the Actions section the Action Type contains: Notifications and\nthat a valid Topic is referenced.\nFrom CLI:\n1. Find the OCID of the specific Event Rule based on Display Name and\nCompartment OCID\noci events rule list --compartment-id <compartment-ocid> --query \"data\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n2. List the details of a specific Event Rule based on the OCID of the rule.\noci events rule get --rule-id <rule-id>\n3. In the JSON output locate the Conditions key value pair and verify that the\nfollowing Conditions are present:\ncom.oraclecloud.identitycontrolplane.createuser\ncom.oraclecloud.identitycontrolplane.deleteuser\ncom.oraclecloud.identitycontrolplane.updateuser\ncom.oraclecloud.identitycontrolplane.updateusercapabilities\ncom.oraclecloud.identitycontrolplane.updateuserstate\n4. Verify the value of the is-enabled attribute is true\n5. In the JSON output verify that actionType is ONS and locate the topic-id\n6. Verify the correct topic is used by checking the topic name\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output\ntable",
    "expected_response": "5. Ensure the Rule is ACTIVE\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n3. In the JSON output locate the Conditions key value pair and verify that the\n5. In the JSON output verify that actionType is ONS and locate the topic-id\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output",
    "remediation": "From Console:\n1. Using the search box to navigate to events\n2. Navigate to the rules page\n3. Select the compartment that should host the rule\n4. Click Create Rule\n5. Provide a Display Name and Description\n6. Create a Rule Condition by selecting Identity in the Service Name Drop-down\nand selecting:\nUser – Create, User – Delete, User – Update, User Capabilities –\nUpdate, User State – Update\n7. In the Actions section select Notifications as Action Type\n8. Select the Compartment that hosts the Topic to be used.\n9. Select the Topic to be used\n10. Optionally add Tags to the Rule\n11. Click Create Rule\nFrom CLI:\n1. Find the topic-id of the topic the Event Rule should use for sending\nNotifications by using the topic name and Compartment OCID\noci ons topic list --compartment-id <compartment-ocid> --all --query \"data\n[?name=='<topic-name>']\".{\"name:name,topic_id:\\\"topic-id\\\"\"} --output table\n2. Create a JSON file to be used when creating the Event Rule. Replace topic id,\ndisplay name, description and compartment OCID.\n{\n\"actions\":\n{\n\"actions\": [\n{\n\"actionType\": \"ONS\",\n\"isEnabled\": true,\n\"topicId\": \"<topic-id>\"\n}]\n},\n\"condition\":\n\"{\\\"eventType\\\":[\\\"com.oraclecloud.identitycontrolplane.createuser\\\",\\\"com.or\naclecloud.identitycontrolplane.deleteuser\\\",\\\"com.oraclecloud.identitycontrol\nplane.updateuser\\\",\\\"com.oraclecloud.identitycontrolplane.updateusercapabilit\nies\\\",\\\"com.oraclecloud.identitycontrolplane.updateuserstate\\\"],\\\"data\\\":{}}\"\n,\n\"displayName\": \"<display-name>\",\n\"description\": \"<description>\",\n\"isEnabled\": true,\n\"compartmentId\": \"<compartment-ocid>\"\n}\n3. Create the actual event rule\noci events rule create --from-json file://event_rule.json\n4. Note in the JSON returned that it lists the parameters specified in the JSON file\nprovided and that there is an OCID provided for the Event Rule",
    "additional_information": "• The same Notification topic can be reused by many Event Rules.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "oci events rule list --compartment-id <compartment-ocid> --query \"data",
      "oci events rule get --rule-id <rule-id>",
      "oci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output"
    ],
    "remediation_commands": [
      "oci ons topic list --compartment-id <compartment-ocid> --all --query \"data",
      "oci events rule create --from-json file://event_rule.json"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 116,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.8",
    "title": "Ensure a notification is configured for VCN changes",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Use Automated Tools to Verify Standard Device",
    "description": "It is recommended to setup an Event Rule and Notification that gets triggered when\nVirtual Cloud Networks are created, updated or deleted. Event Rules are compartment\nscoped and will detect events in child compartments, it is recommended to create the\nEvent rule at the root compartment level.",
    "rationale": "Virtual Cloud Networks (VCNs) closely resembles a traditional network. Monitoring and\nalerting on changes to VCNs will help in identifying changes to the security posture.",
    "impact": "There is no performance impact when enabling the above described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Go to the Events Service page:\nhttps://cloud.oracle.com/events/rules\n2. Select the Compartment that hosts the rules\n3. Find and click the Rule that handles VCN Changes (if any)\n4. Ensure the Rule is ACTIVE\n5. Click the Edit Rule button and verify that the RuleConditions section contains\na condition for the Service Networking and Event Types: VCN – Create, VCN -\nDelete and VCN – Update\n6. Verify that in the Actions section the Action Type contains: Notifications and\nthat a valid Topic is referenced.\nFrom CLI:\n1. Find the OCID of the specific Event Rule based on Display Name and\nCompartment OCID\noci events rule list --compartment-id <compartment-ocid> --query \"data\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n2. List the details of a specific Event Rule based on the OCID of the rule.\noci events rule get --rule-id <rule-id>\n3. In the JSON output locate the Conditions key value pair and verify that the\nfollowing Conditions are present:\ncom.oraclecloud.virtualnetwork.createvcn\ncom.oraclecloud.virtualnetwork.deletevcn\ncom.oraclecloud.virtualnetwork.updatevcn\n4. Verify the value of the is-enabled attribute is true\n5. In the JSON output verify that actionType is ONS and locate the topic-id\n6. Verify the correct topic is used by checking the topic name\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output\ntable",
    "expected_response": "4. Ensure the Rule is ACTIVE\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n3. In the JSON output locate the Conditions key value pair and verify that the\n5. In the JSON output verify that actionType is ONS and locate the topic-id\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output",
    "remediation": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the compartment that should host the rule\n3. Click Create Rule\n4. Provide a Display Name and Description\n5. Create a Rule Condition by selecting Networking in the Service Name Drop-\ndown and selecting VCN – Create, VCN - Delete and VCN – Update\n6. In the Actions section select Notifications as Action Type\n7. Select the Compartment that hosts the Topic to be used.\n8. Select the Topic to be used\n9. Optionally add Tags to the Rule\n10. Click Create Rule\nFrom CLI:\n1. Find the topic-id of the topic the Event Rule should use for sending\nNotifications by using the topic name and Compartment OCID\noci ons topic list --compartment-id <compartment-ocid> --all --query \"data\n[?name=='<topic-name>']\".{\"name:name,topic_id:\\\"topic-id\\\"\"} --output table\n2. Create a JSON file to be used when creating the Event Rule. Replace topic id,\ndisplay name, description and compartment OCID.\n{\n\"actions\":\n{\n\"actions\": [\n{\n\"actionType\": \"ONS\",\n\"isEnabled\": true,\n\"topicId\": \"<topic-id>\"\n}]\n},\n\"condition\":\n\"{\\\"eventType\\\":[\\\"com.oraclecloud.virtualnetwork.createvcn\\\",\\\"com.oracleclo\nud.virtualnetwork.deletevcn\\\",\\\"com.oraclecloud.virtualnetwork.updatevcn\\\"],\\\n\"data\\\":{}}\",\n\"displayName\": \"<display-name>\",\n\"description\": \"<description>\",\n\"isEnabled\": true,\n\"compartmentId\": \"<compartment-ocid>\"\n}\n3. Create the actual event rule\noci events rule create --from-json file://event_rule.json\n4. Note in the JSON returned that it lists the parameters specified in the JSON file\nprovided and that there is an OCID provided for the Event Rule",
    "additional_information": "• The same Notification topic can be reused by many Event Rules.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "oci events rule list --compartment-id <compartment-ocid> --query \"data",
      "oci events rule get --rule-id <rule-id>",
      "oci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output"
    ],
    "remediation_commands": [
      "oci ons topic list --compartment-id <compartment-ocid> --all --query \"data",
      "oci events rule create --from-json file://event_rule.json"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 120,
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
    "cis_id": "4.9",
    "title": "Ensure a notification is configured for changes to route tables",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Use Automated Tools to Verify Standard Device",
    "description": "It is recommended to setup an Event Rule and Notification that gets triggered when\nroute tables are created, updated or deleted. Event Rules are compartment scoped and\nwill detect events in child compartments, it is recommended to create the Event rule at\nthe root compartment level.",
    "rationale": "Route tables control traffic flowing to or from Virtual Cloud Networks and Subnets.\nMonitoring and alerting on changes to route tables will help in identifying changes these\ntraffic flows.",
    "impact": "There is no performance impact when enabling the above described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Go to the Events Service page:\nhttps://cloud.oracle.com/events/rules\n2. Select the Compartment that hosts the rules\n3. Find and click the Rule that handles Route Table Changes (if any)\n4. Ensure the Rule is ACTIVE\n5. Click the Edit Rule button and verify that the RuleConditions section contains\na condition for the Service Networking and Event Types: Route Table –\nChange Compartment, Route Table – Create, Route Table - Delete and\nRoute Table - Update\n6. Verify that in the Actions section the Action Type contains: Notifications and\nthat a valid Topic is referenced.\nFrom CLI:\n1. Find the OCID of the specific Event Rule based on Display Name and\nCompartment OCID\noci events rule list --compartment-id <compartment-ocid> --query \"data\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n2. List the details of a specific Event Rule based on the OCID of the rule.\noci events rule get --rule-id <rule-id>\n3. In the JSON output locate the Conditions key value pair and verify that the\nfollowing Conditions are present:\ncom.oraclecloud.virtualnetwork.changeroutetablecompartment\ncom.oraclecloud.virtualnetwork.createroutetable\ncom.oraclecloud.virtualnetwork.deleteroutetable\ncom.oraclecloud.virtualnetwork.updateroutetable\n4. Verify the value of the is-enabled attribute is true\n5. In the JSON output verify that actionType is ONS and locate the topic-id\n6. Verify the correct topic is used by checking the topic name\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output\ntable",
    "expected_response": "4. Ensure the Rule is ACTIVE\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n3. In the JSON output locate the Conditions key value pair and verify that the\n5. In the JSON output verify that actionType is ONS and locate the topic-id\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output",
    "remediation": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the compartment that should host the rule\n3. Click Create Rule\n4. Provide a Display Name and Description\n5. Create a Rule Condition by selecting Networking in the Service Name Drop-\ndown and selecting Route Table – Change Compartment, Route Table –\nCreate, Route Table - Delete and Route Table – Update\n6. In the Actions section select Notifications as Action Type\n7. Select the Compartment that hosts the Topic to be used.\n8. Select the Topic to be used\n9. Optionally add Tags to the Rule\n10. Click Create Rule\nFrom CLI:\n1. Find the topic-id of the topic the Event Rule should use for sending\nNotifications by using the topic name and Compartment OCID\noci ons topic list --compartment-id <compartment-ocid> --all --query \"data\n[?name=='<topic-name>']\".{\"name:name,topic_id:\\\"topic-id\\\"\"} --output table\n2. Create a JSON file to be used when creating the Event Rule. Replace topic id,\ndisplay name, description and compartment OCID.\n{\n\"actions\":\n{\n\"actions\": [\n{\n\"actionType\": \"ONS\",\n\"isEnabled\": true,\n\"topicId\": \"<topic-id>\"\n}]\n},\n\"condition\":\n\"{\\\"eventType\\\":[\\\"com.oraclecloud.virtualnetwork.changeroutetablecompartment\n\\\",\\\"com.oraclecloud.virtualnetwork.createroutetable\\\",\\\"com.oraclecloud.virt\nualnetwork.deleteroutetable\\\",\\\"com.oraclecloud.virtualnetwork.updateroutetab\nle\\\"],\\\"data\\\":{}}\",\n\"displayName\": \"<display-name>\",\n\"description\": \"<description>\",\n\"isEnabled\": true,\n\"compartmentId\": \"<compartment-ocid>\"\n}\n3. Create the actual event rule\noci events rule create --from-json file://event_rule.json\n4. Note in the JSON returned that it lists the parameters specified in the JSON file\nprovided and that there is an OCID provided for the Event Rule",
    "additional_information": "• The same Notification topic can be reused by many Event Rules.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "oci events rule list --compartment-id <compartment-ocid> --query \"data",
      "oci events rule get --rule-id <rule-id>",
      "oci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output"
    ],
    "remediation_commands": [
      "Create, Route Table - Delete and Route Table – Update",
      "oci ons topic list --compartment-id <compartment-ocid> --all --query \"data",
      "oci events rule create --from-json file://event_rule.json"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 123,
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
    "cis_id": "4.10",
    "title": "Ensure a notification is configured for security list changes",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Use Automated Tools to Verify Standard Device",
    "description": "It is recommended to setup an Event Rule and Notification that gets triggered when\nsecurity lists are created, updated or deleted. Event Rules are compartment scoped and\nwill detect events in child compartments, it is recommended to create the Event rule at\nthe root compartment level.",
    "rationale": "Security Lists control traffic flowing into and out of Subnets within a Virtual Cloud\nNetwork. Monitoring and alerting on changes to Security Lists will help in identifying\nchanges to these security controls.",
    "impact": "There is no performance impact when enabling the above described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Go to the Events Service page:\nhttps://cloud.oracle.com/events/rules\n2. Select the Compartment that hosts the rules\n3. Find and click the Rule that handles Security List Changes (if any)\n4. Ensure the Rule is ACTIVE\n5. Click the Edit Rule button and verify that the RuleConditions section contains\na condition for the Service Networking and Event Types: Security List –\nChange Compartment, Security List – Create, Security List - Delete\nand Security List – Update\n6. Verify that in the Actions section the Action Type contains: Notifications and\nthat a valid Topic is referenced.\nFrom CLI:\n1. Find the OCID of the specific Event Rule based on Display Name and\nCompartment OCID\noci events rule list --compartment-id <compartment-ocid> --query \"data\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n2. List the details of a specific Event Rule based on the OCID of the rule.\noci events rule get --rule-id <rule-ocid>\n3. In the JSON output locate the Conditions key value pair and verify that the\nfollowing Conditions are present:\ncom.oraclecloud.virtualnetwork.changesecuritylistcompartment\ncom.oraclecloud.virtualnetwork.createsecuritylist\ncom.oraclecloud.virtualnetwork.deletesecuritylist\ncom.oraclecloud.virtualnetwork.updatesecuritylist\n4. Verify the value of the is-enabled attribute is true\n5. In the JSON output verify that actionType is ONS and locate the topic-id\n6. Verify the correct topic is used by checking the topic name\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output\ntable",
    "expected_response": "4. Ensure the Rule is ACTIVE\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n3. In the JSON output locate the Conditions key value pair and verify that the\n5. In the JSON output verify that actionType is ONS and locate the topic-id\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output",
    "remediation": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the compartment that should host the rule\n3. Click Create Rule\n4. Provide a Display Name and Description\n5. Create a Rule Condition by selecting Networking in the Service Name Drop-\ndown and selecting Security List – Change Compartment, Security List\n– Create, Security List - Delete and Security List – Update\n6. In the Actions section select Notifications as Action Type\n7. Select the Compartment that hosts the Topic to be used.\n8. Select the Topic to be used\n9. Optionally add Tags to the Rule\n10. Click Create Rule\nFrom CLI:\n1. Find the topic-id of the topic the Event Rule should use for sending\nNotifications by using the topic name and Compartment OCID\noci ons topic list --compartment-id <compartment-ocid> --all --query \"data\n[?name=='<topic-name>']\".{\"name:name,topic_id:\\\"topic-id\\\"\"} --output table\n2. Create a JSON file to be used when creating the Event Rule. Replace topic-id,\ndisplay name, description and compartment OCID.\n{\n\"actions\":\n{\n\"actions\": [\n{\n\"actionType\": \"ONS\",\n\"isEnabled\": true,\n\"topicId\": \"<topic-id>\"\n}]\n},\n\"condition\":\n\"{\\\"eventType\\\":[\\\"com.oraclecloud.virtualnetwork.changesecuritylistcompartme\nnt\\\",\\\"com.oraclecloud.virtualnetwork.createsecuritylist\\\",\\\"com.oraclecloud.\nvirtualnetwork.deletesecuritylist\\\",\\\"com.oraclecloud.virtualnetwork.updatese\ncuritylist\\\"],\\\"data\\\":{}}\",\n\"displayName\": \"<display-name>\",\n\"description\": \"<description>\",\n\"isEnabled\": true,\n\"compartmentId\": \"<compartment-ocid>\"\n}\n3. Create the actual event rule\noci events rule create --from-json file://event_rule.json\n4. Note in the JSON returned that it lists the parameters specified in the JSON file\nprovided and that there is an OCID provided for the Event Rule",
    "additional_information": "• The same Notification topic can be reused by many Event Rules.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "oci events rule list --compartment-id <compartment-ocid> --query \"data",
      "oci events rule get --rule-id <rule-ocid>",
      "oci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output"
    ],
    "remediation_commands": [
      "oci ons topic list --compartment-id <compartment-ocid> --all --query \"data",
      "oci events rule create --from-json file://event_rule.json"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 127,
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
    "cis_id": "4.11",
    "title": "Ensure a notification is configured for network security group changes",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Use Automated Tools to Verify Standard Device",
    "description": "It is recommended to setup an Event Rule and Notification that gets triggered when\nnetwork security groups are created, updated or deleted. Event Rules are compartment\nscoped and will detect events in child compartments, it is recommended to create the\nEvent rule at the root compartment level.",
    "rationale": "Network Security Groups control traffic flowing between Virtual Network Cards attached\nto Compute instances. Monitoring and alerting on changes to Network Security Groups\nwill help in identifying changes these security controls.",
    "impact": "There is no performance impact when enabling the above described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Go to the Events Service page:\nhttps://cloud.oracle.com/events/rules\n2. Select the Compartment that hosts the rules\n3. Find and click the Rule that handles Network Security Group Changes (if any)\n4. Ensure the Rule is ACTIVE\n5. Click the Edit Rule button and verify that the RuleConditions section contains\na condition for the Service Networking and Event Types: Network Security\nGroup – Change Compartment, Network Security Group – Create,\nNetwork Security Group - Delete and Network Security Group –\nUpdate\n6. Verify that in the Actions section the Action Type contains: Notifications and\nthat a valid Topic is referenced.\nFrom CLI:\n1. Find the OCID of the specific Event Rule based on Display Name and\nCompartment OCID\noci events rule list --compartment-id <compartment-ocid> --query \"data\n[?\\\"display-name\\\"=='<display name used>']\".{\"id:id\"} --output table\n2. List the details of a specific Event Rule based on the OCID of the rule.\noci events rule get --rule-id <rule-id>\n3. In the JSON output locate the Conditions key value pair and verify that the\nfollowing conditions are present:\ncom.oraclecloud.virtualnetwork.changenetworksecuritygroupcompartment\ncom.oraclecloud.virtualnetwork.createnetworksecuritygroup\ncom.oraclecloud.virtualnetwork.deletenetworksecuritygroup\ncom.oraclecloud.virtualnetwork.updatenetworksecuritygroup\n4. Verify the value of the is-enabled attribute is true\n5. In the JSON output verify that actionType is ONS and locate the topic-id\n6. Verify the correct topic is used by checking the topic name\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output\ntable",
    "expected_response": "4. Ensure the Rule is ACTIVE\n[?\\\"display-name\\\"=='<display name used>']\".{\"id:id\"} --output table\n3. In the JSON output locate the Conditions key value pair and verify that the\n5. In the JSON output verify that actionType is ONS and locate the topic-id\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output",
    "remediation": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the compartment that should host the rule\n3. Click Create Rule\n4. Provide a Display Name and Description\n5. Create a Rule Condition by selecting Networking in the Service Name Drop-\ndown and selecting Network Security Group – Change Compartment,\nNetwork Security Group – Create, Network Security Group - Delete\nand Network Security Group – Update\n6. In the Actions section select Notifications as Action Type\n7. Select the Compartment that hosts the Topic to be used.\n8. Select the Topic to be used\n9. Optionally add Tags to the Rule\n10. Click Create Rule\nFrom CLI:\n1. Find the topic-id of the topic the Event Rule should use for sending\nNotifications by using the topic name and Compartment OCID\noci ons topic list --compartment-id <compartment-ocid> --all --query \"data\n[?name=='<topic-name>']\".{\"name:name,topic_id:\\\"topic-id\\\"\"} --output table\n2. Create a JSON file to be used when creating the Event Rule. Replace topic id,\ndisplay name, description and compartment OCID.\n{\n\"actions\": {\n\"actions\": [\n{\n\"actionType\": \"ONS\",\n\"isEnabled\": true,\n\"topicId\": \"<topic-id>\"\n}\n]\n},\n\"condition\":\n\"{\\\"eventType\\\":[\\\"com.oraclecloud.virtualnetwork.changenetworksecuritygroupc\nompartment\\\",\\\"com.oraclecloud.virtualnetwork.createnetworksecuritygroup\\\",\\\"\ncom.oraclecloud.virtualnetwork.deletenetworksecuritygroup\\\",\\\"com.oraclecloud\n.virtualnetwork.updatenetworksecuritygroup\\\"],\\\"data\\\":{}}\",\n\"displayName\": \"<display-name>\",\n\"description\": \"<description>\",\n\"isEnabled\": true,\n\"compartmentId\": \"<compartment-ocid>\"\n}\n3. Create the actual event rule\noci events rule create --from-json file://event_rule.json\n4. Note in the JSON returned that it lists the parameters specified in the JSON file\nprovided and that there is an OCID provided for the Event Rule",
    "additional_information": "• The same Notification topic can be reused by many Event Rules.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "oci events rule list --compartment-id <compartment-ocid> --query \"data",
      "oci events rule get --rule-id <rule-id>",
      "oci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output"
    ],
    "remediation_commands": [
      "oci ons topic list --compartment-id <compartment-ocid> --all --query \"data",
      "oci events rule create --from-json file://event_rule.json"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 131,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.12",
    "title": "Ensure a notification is configured for changes to network gateways",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Log and Alert on Changes to Administrative Group",
    "description": "It is recommended to setup an Event Rule and Notification that gets triggered when\nNetwork Gateways are created, updated, deleted, attached, detached, or moved. This\nrecommendation includes Internet Gateways, Dynamic Routing Gateways, Service\nGateways, Local Peering Gateways, and NAT Gateways. Event Rules are compartment\nscoped and will detect events in child compartments, it is recommended to create the\nEvent rule at the root compartment level.",
    "rationale": "Network Gateways act as routers between VCNs and the Internet, Oracle Services\nNetworks, other VCNS, and on-premise networks. Monitoring and alerting on changes\nto Network Gateways will help in identifying changes to the security posture.",
    "impact": "There is no performance impact when enabling the above described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Go to the Events Service page:\nhttps://cloud.oracle.com/events/rules\n2. Select the Compartment that hosts the rules\n3. Find and click the Rule that handles Network Gateways Changes (if any)\n4. Ensure the Rule is ACTIVE\n5. Click the Edit Rule button and verify that the RuleConditions section contains\na condition for the Service Networking and Event Types:\nDRG – Create\nDRG – Delete\nDRG – Update\nDRG Attachment – Create\nDRG Attachment – Delete\nDRG Attachment – Update\nInternet Gateway – Create\nInternet Gateway – Delete\nInternet Gateway – Update\nInternet Gateway – Change Compartment\nLocal Peering Gateway – Create\nLocal Peering Gateway – Delete End\nLocal Peering Gateway – Update\nLocal Peering Gateway – Change Compartment\nNAT Gateway – Create\nNAT Gateway – Delete\nNAT Gateway – Update\nNAT Gateway – Change Compartment\nService Gateway – Create\nService Gateway – Delete End\nService Gateway – Update\nService Gateway – Attach Service\nService Gateway – Detach Service\nService Gateway – Change Compartment\n6. Verify that in the Actions section the Action Type contains: Notifications and\nthat a valid Topic is referenced.\nFrom CLI:\n1. Find the OCID of the specific Event Rule based on Display Name and\nCompartment OCID\noci events rule list --compartment-id <compartment-ocid> --query \"data\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n2. List the details of a specific Event Rule based on the OCID of the rule.\noci events rule get --rule-id <rule-id>\n3. In the JSON output locate the Conditions key value pair and verify that the\nfollowing Conditions are present:\ncom.oraclecloud.virtualnetwork.createdrg\ncom.oraclecloud.virtualnetwork.deletedrg\ncom.oraclecloud.virtualnetwork.updatedrg\ncom.oraclecloud.virtualnetwork.createdrgattachment\ncom.oraclecloud.virtualnetwork.deletedrgattachment\ncom.oraclecloud.virtualnetwork.updatedrgattachment\ncom.oraclecloud.virtualnetwork.changeinternetgatewaycompartment\ncom.oraclecloud.virtualnetwork.createinternetgateway\ncom.oraclecloud.virtualnetwork.deleteinternetgateway\ncom.oraclecloud.virtualnetwork.updateinternetgateway\ncom.oraclecloud.virtualnetwork.changelocalpeeringgatewaycompartment\ncom.oraclecloud.virtualnetwork.createlocalpeeringgateway\ncom.oraclecloud.virtualnetwork.deletelocalpeeringgateway.end\ncom.oraclecloud.virtualnetwork.updatelocalpeeringgateway\ncom.oraclecloud.natgateway.changenatgatewaycompartment\ncom.oraclecloud.natgateway.createnatgateway\ncom.oraclecloud.natgateway.deletenatgateway\ncom.oraclecloud.natgateway.updatenatgateway\ncom.oraclecloud.servicegateway.attachserviceid\ncom.oraclecloud.servicegateway.changeservicegatewaycompartment\ncom.oraclecloud.servicegateway.createservicegateway\ncom.oraclecloud.servicegateway.deleteservicegateway.end\ncom.oraclecloud.servicegateway.detachserviceid\ncom.oraclecloud.servicegateway.updateservicegateway\n4. Verify the value of the is-enabled attribute is true\n5. In the JSON output verify that actionType is ONS and locate the topic-id\n6. Verify the correct topic is used by checking the topic name\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output\ntable",
    "expected_response": "4. Ensure the Rule is ACTIVE\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n3. In the JSON output locate the Conditions key value pair and verify that the\n5. In the JSON output verify that actionType is ONS and locate the topic-id\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output",
    "remediation": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the compartment that should host the rule\n3. Click Create Rule\n4. Provide a Display Name and Description\n5. Create a Rule Condition by selecting Networking in the Service Name Drop-\ndown and selecting:\nDRG – Create\nDRG – Delete\nDRG – Update\nDRG Attachment – Create\nDRG Attachment – Delete\nDRG Attachment – Update\nInternet Gateway – Create\nInternet Gateway – Delete\nInternet Gateway – Update\nInternet Gateway – Change Compartment\nLocal Peering Gateway – Create\nLocal Peering Gateway – Delete End\nLocal Peering Gateway – Update\nLocal Peering Gateway – Change Compartment\nNAT Gateway – Create\nNAT Gateway – Delete\nNAT Gateway – Update\nNAT Gateway – Change Compartment\nService Gateway – Create\nService Gateway – Delete End\nService Gateway – Update\nService Gateway – Attach Service\nService Gateway – Detach Service\nService Gateway – Change Compartment\n6. In the Actions section select Notifications as Action Type\n7. Select the Compartment that hosts the Topic to be used.\n8. Select the Topic to be used\n9. Optionally add Tags to the Rule\n10. Click Create Rule\nFrom CLI:\n1. Find the topic-id of the topic the Event Rule should use for sending\nNotifications by using the topic name and Compartment OCID\noci ons topic list --compartment-id <compartment-ocid> --all --query \"data\n[?name=='<topic_name>']\".{\"name:name,topic_id:\\\"topic-id\\\"\"} --output table\n2. Create a JSON file to be used when creating the Event Rule. Replace topic id,\ndisplay name, description and compartment OCID.\n{\n\"actions\": {\n\"actions\": [\n{\n\"actionType\": \"ONS\",\n\"isEnabled\": true,\n\"topicId\": \"<topic-id>\"\n}\n]\n},\n\"condition\":\n\"{\\\"eventType\\\":[\\\"com.oraclecloud.virtualnetwork.createdrg\\\",\\\"com.oracleclo\nud.virtualnetwork.deletedrg\\\",\\\"com.oraclecloud.virtualnetwork.updatedrg\\\",\\\"\ncom.oraclecloud.virtualnetwork.createdrgattachment\\\",\\\"com.oraclecloud.virtua\nlnetwork.deletedrgattachment\\\",\\\"com.oraclecloud.virtualnetwork.updatedrgatta\nchment\\\",\\\"com.oraclecloud.virtualnetwork.changeinternetgatewaycompartment\\\",\n\\\"com.oraclecloud.virtualnetwork.createinternetgateway\\\",\\\"com.oraclecloud.vi\nrtualnetwork.deleteinternetgateway\\\",\\\"com.oraclecloud.virtualnetwork.updatei\nnternetgateway\\\",\\\"com.oraclecloud.virtualnetwork.changelocalpeeringgatewayco\nmpartment\\\",\\\"com.oraclecloud.virtualnetwork.createlocalpeeringgateway\\\",\\\"co\nm.oraclecloud.virtualnetwork.deletelocalpeeringgateway.end\\\",\\\"com.oracleclou\nd.virtualnetwork.updatelocalpeeringgateway\\\",\\\"com.oraclecloud.natgateway.cha\nngenatgatewaycompartment\\\",\\\"com.oraclecloud.natgateway.createnatgateway\\\",\\\"\ncom.oraclecloud.natgateway.deletenatgateway\\\",\\\"com.oraclecloud.natgateway.up\ndatenatgateway\\\",\\\"com.oraclecloud.servicegateway.attachserviceid\\\",\\\"com.ora\nclecloud.servicegateway.changeservicegatewaycompartment\\\",\\\"com.oraclecloud.s\nervicegateway.createservicegateway\\\",\\\"com.oraclecloud.servicegateway.deletes\nervicegateway.end\\\",\\\"com.oraclecloud.servicegateway.detachserviceid\\\",\\\"com.\noraclecloud.servicegateway.updateservicegateway\\\"],\\\"data\\\":{}}\",\n\"displayName\": \"<display-name>\",\n\"description\": \"<description>\",\n\"isEnabled\": true,\n\"compartmentId\": \"<compartment-ocid>\"\n}\n3. Create the actual event rule\noci events rule create --from-json file://event_rule.json\n4. Note in the JSON returned that it lists the parameters specified in the JSON file\nprovided and that there is an OCID provided for the Event Rule",
    "additional_information": "• The same Notification topic can be reused by many Event Rules.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "oci events rule list --compartment-id <compartment-ocid> --query \"data",
      "oci events rule get --rule-id <rule-id>",
      "oci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output"
    ],
    "remediation_commands": [
      "oci ons topic list --compartment-id <compartment-ocid> --all --query \"data",
      "oci events rule create --from-json file://event_rule.json"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 135,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.13",
    "title": "Ensure VCN flow logging is enabled for all subnets",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Use Automated Tools to Verify Standard Device",
    "description": "VCN flow logs record details about traffic that has been accepted or rejected based on\nthe security list rule.",
    "rationale": "Enabling VCN flow logs enables you to monitor traffic flowing within your virtual network\nand can be used to detect anomalous traffic.",
    "impact": "Enabling VCN flow logs will not affect the performance of your virtual network but it will\ngenerate additional use of object storage that should be controlled via object lifecycle\nmanagement.\nBy default, VCN flow logs are stored for 30 days in object storage. Users can specify a\nlonger retention period.",
    "audit": "From Console (For Logging enabled Flow logs):\n1. Go to the Virtual Cloud Network (VCN) page\n(https://cloud.oracle.com/networking/vcns)\n2. Select the Compartment\n3. Click on the name of each VCN\n4. Click on each subnet within the VCN\n5. Under Resources click on Logs or the Monitoring tab\n6. Verify that there is a log enabled for the subnet\n7. Click the Log Name\n8. Verify Flowlogs Capture Filter is set to No filter (collecting all\nlogs)\n9. If there is a Capture filter click the 'Capture Filter Name'\n10. Click Edit\n11. Verify Sampling rate is 100%\n12. Click Cancel\n13. Verify there is a in the Rules list that is: Enabled, Traffic disposition:\nAll, Include/Exclude: Include, Source CIDR: Any, Destination\nCIDR: Any, IP Protocol: All\nFrom Console (For Network Command Center Enabled Flow logs):\n1. Go to the Network Command Center page\n(https://cloud.oracle.com/networking/network-command-center)\n2. Click on Flow Logs\n3. Click on the Flow log Name\n4. Click Edit\n5. Verify Sampling rate is 100%\n6. Click Cancel\n7. Verify there is a in the Rules list that is: Enabled, Traffic disposition:\nAll, Include/Exclude: Include, Source CIDR: Any, Destination\nCIDR: Any, IP Protocol: All",
    "expected_response": "8. Verify Flowlogs Capture Filter is set to No filter (collecting all",
    "remediation": "From Console:\nFirst, if a Capture filter has not already been created, create a Capture Filter by the\nfollowing steps:\n1. Go to the Network Command Center page\n(https://cloud.oracle.com/networking/network-command-center)\n2. Click 'Capture filters'\n3. Click 'Create Capture filter'\n4. Type a name for the Capture filter in the Name box.\n5. Select 'Flow log capture filter'\n6. For Sample rating select 100%\n7. Scroll to Rules\n8. For Traffic disposition select All\n9. For Include/Exclude select Include\n10. Level Source IPv4 CIDR or IPv6 prefix and Destination IPv4 CIDR or\nIPv6 prefix empty\n11. For IP protocol select Include\n12. Click Create Capture filter\nSecond, enable VCN flow logging for your VCN or subnet(s) by the following steps:\n1. Go to the Logs page (https://cloud.oracle.com/logging/logs)\n2. Click the Enable Service Log button in the middle of the screen.\n3. Select the relevant resource compartment.\n4. Select Virtual Cloud Networks - Flow logs from the Service drop down\nmenu.\n5. Select the relevant resource level from the resource drop down menu either VCN\nor subnet.\n6. Select the relevant resource from the resource drop down menu.\n7. Select the from the Log Category drop down menu that either Flow Logs -\nsubnet records or Flow Logs - vcn records.\n8. Select the Capture filter from above\n9. Type a name for your flow logs in the Log Name text box.\n10. Select the Compartment for the Log Location\n11. Select the Log Group for the Log Location or Click Create New Group to create\na new log group\n12. Click the Enable Log button in the lower left-hand corner.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://docs.oracle.com/en/solutions/oci-aggregate-logs-siem/index.html#GUID-",
      "601E052A-8A8E-466B-A8A8-2BBBD3B80B6D"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 141,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "4.14",
    "title": "Ensure Cloud Guard is enabled in the root compartment of the tenancy",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Configure Monitoring Systems to Record Network",
    "description": "Cloud Guard detects misconfigured resources and insecure activity within a tenancy\nand provides security administrators with the visibility to resolve these issues. Upon\ndetection, Cloud Guard can suggest, assist, or take corrective actions to mitigate these\nissues. Cloud Guard should be enabled in the root compartment of your tenancy with\nthe default configuration, activity detectors and responders.",
    "rationale": "Cloud Guard provides an automated means to monitor a tenancy for resources that are\nconfigured in an insecure manner as well as risky network activity from these resources.",
    "impact": "There is no performance impact when enabling the above described features, but\nadditional IAM policies will be required.",
    "audit": "From Console:\n1. Type Cloud Guard into the Search box at the top of the Console.\n2. Click Cloud Guard from the \"Services\" submenu.\n3. View if Cloud Guard is enabled\nFrom CLI:\n1. Retrieve the Cloud Guard status from the console\noci cloud-guard configuration get --compartment-id <tenancy-ocid> --query\n'data.status'\n2. Ensure the returned value is \"ENABLED\"`",
    "expected_response": "3. View if Cloud Guard is enabled\n2. Ensure the returned value is \"ENABLED\"`",
    "remediation": "From Console:\n1. Type Cloud Guard into the Search box at the top of the Console.\n2. Click Cloud Guard from the \"Services\" submenu.\n3. Click Enable Cloud Guard.\n4. Click Create Policy.\n5. Click Next.\n6. Under Reporting Region, select a region.\n7. Under Compartments To Monitor, choose Select Compartment.\n8. Under Select Compartments, select the root compartment.\n9. Under Configuration Detector Recipe, select OCI Configuration\nDetector Recipe (Oracle Managed).\n10. Under Activity Detector Recipe, select OCI Activity Detector Recipe\n(Oracle Managed).\n11. Click Enable.\nFrom CLI:\n1. Create OCI IAM Policy for Cloud Guard\noci iam policy create --compartment-id '<tenancy-id>' --name\n'CloudGuardPolicies' --description 'Cloud Guard Access Policy' --statements\n'[\n\"allow service cloudguard to read vaults in tenancy\",\n\"allow service cloudguard to read keys in tenancy\",\n\"allow service cloudguard to read compartments in tenancy\",\n\"allow service cloudguard to read tenancies in tenancy\",\n\"allow service cloudguard to read audit-events in tenancy\",\n\"allow service cloudguard to read compute-management-family in tenancy\",\n\"allow service cloudguard to read instance-family in tenancy\",\n\"allow service cloudguard to read virtual-network-family in tenancy\",\n\"allow service cloudguard to read volume-family in tenancy\",\n\"allow service cloudguard to read database-family in tenancy\",\n\"allow service cloudguard to read object-family in tenancy\",\n\"allow service cloudguard to read load-balancers in tenancy\",\n\"allow service cloudguard to read users in tenancy\",\n\"allow service cloudguard to read groups in tenancy\",\n\"allow service cloudguard to read policies in tenancy\",\n\"allow service cloudguard to read dynamic-groups in tenancy\",\n\"allow service cloudguard to read authentication-policies in tenancy\"\n]'\n2. Enable Cloud Guard in root compartment\noci cloud-guard configuration update --reporting-region '<region-name>' --\ncompartment-id '<tenancy-id>' --status 'ENABLED'",
    "detection_commands": [
      "oci cloud-guard configuration get --compartment-id <tenancy-ocid> --query 'data.status'"
    ],
    "remediation_commands": [
      "oci iam policy create --compartment-id '<tenancy-id>' --name 'CloudGuardPolicies' --description 'Cloud Guard Access Policy' --statements '[ \"allow service cloudguard to read vaults in tenancy\", \"allow service cloudguard to read keys in tenancy\", \"allow service cloudguard to read compartments in tenancy\", \"allow service cloudguard to read tenancies in tenancy\", \"allow service cloudguard to read audit-events in tenancy\", \"allow service cloudguard to read compute-management-family in tenancy\", \"allow service cloudguard to read instance-family in tenancy\", \"allow service cloudguard to read virtual-network-family in tenancy\", \"allow service cloudguard to read volume-family in tenancy\", \"allow service cloudguard to read database-family in tenancy\", \"allow service cloudguard to read object-family in tenancy\", \"allow service cloudguard to read load-balancers in tenancy\", \"allow service cloudguard to read users in tenancy\", \"allow service cloudguard to read groups in tenancy\", \"allow service cloudguard to read policies in tenancy\", \"allow service cloudguard to read dynamic-groups in tenancy\", \"allow service cloudguard to read authentication-policies in tenancy\"",
      "oci cloud-guard configuration update --reporting-region '<region-name>' --"
    ],
    "references": [
      "1. https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 144,
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
    "cis_id": "4.15",
    "title": "Ensure a notification is configured for Oracle Cloud Guard problems detected",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Activate audit logging",
    "description": "Cloud Guard detects misconfigured resources and insecure activity within a tenancy\nand provides security administrators with the visibility to resolve these issues. Upon\ndetection, Cloud Guard generates a Problem. It is recommended to setup an Event\nRule and Notification that gets triggered when Oracle Cloud Guard Problems are\ncreated, dismissed or remediated. Event Rules are compartment scoped and will detect\nevents in child compartments. It is recommended to create the Event rule at the root\ncompartment level.",
    "rationale": "Cloud Guard provides an automated means to monitor a tenancy for resources that are\nconfigured in an insecure manner as well as risky network activity from these resources.\nMonitoring and alerting on Problems detected by Cloud Guard will help in identifying\nchanges to the security posture.",
    "impact": "There is no performance impact when enabling the above described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the Compartment that hosts the rules\n3. Find and click the Rule that handles Cloud Guard Changes (if any)\n4. Ensure the Rule is ACTIVE\n5. Click the Edit Rule button and verify that the RuleConditions section contains a\ncondition for the Service Cloud Guard and Event Types: Detected – Problem,\nRemediated – Problem, and Dismissed - Problem\n6. Verify that in the Actions section the Action Type contains: Notifications and that\na valid Topic is referenced.\nFrom CLI:\n1. Find the OCID of the specific Event Rule based on Display Name and\nCompartment OCID\noci events rule list --compartment-id=<compartment OCID> --query \"data\n[?\\\"display-name\\\"=='<display name used>']\".{\"id:id\"} --output table\n1. List the details of a specific Event Rule based on the OCID of the rule.\n2. In the JSON output locate the Conditions key-value pair and verify that the\nfollowing Conditions are present:\n\"com.oraclecloud.cloudguard.problemdetected\",\"com.oraclecloud.cloudguard.prob\nlemdismissed\",\"com.oraclecloud.cloudguard.problemremediated\"\n1. Verify the value of the is-enabled attribute is true\n2. In the JSON output verify that actionType is ONS and locate the topic-id\n3. Verify the correct topic is used by checking the topic name\noci ons topic get --topic-id=<topic id> --query data.{\"name:name\"} --output\ntable",
    "expected_response": "4. Ensure the Rule is ACTIVE\n[?\\\"display-name\\\"=='<display name used>']\".{\"id:id\"} --output table\n2. In the JSON output locate the Conditions key-value pair and verify that the\n2. In the JSON output verify that actionType is ONS and locate the topic-id\noci ons topic get --topic-id=<topic id> --query data.{\"name:name\"} --output",
    "remediation": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the compartment that should host the rule\n3. Click Create Rule\n4. Provide a Display Name and Description\n5. Create a Rule Condition by selecting Cloud Guard in the Service Name Drop-\ndown and selecting: Detected – Problem, Remediated – Problem, and\nDismissed - Problem\n6. In the Actions section select Notifications as Action Type\n7. Select the Compartment that hosts the Topic to be used.\n8. Select the Topic to be used\n9. Optionally add Tags to the Rule\n10. Click Create Rule\nFrom CLI:\n1. Find the topic-id of the topic the Event Rule should use for sending Notifications\nby using the topic name and Compartment OCID\noci ons topic list --compartment-id=<compartment OCID> --all --query \"data\n[?name=='<topic_name>']\".{\"name:name,topic_id:\\\"topic-id\\\"\"} --output table\n1. Create a JSON file to be used when creating the Event Rule. Replace topic id,\ndisplay name, description and compartment OCID.\n{\n\"actions\":\n{\n\"actions\": [\n{\n\"actionType\": \"ONS\",\n\"isEnabled\": true,\n\"topicId\": \"<topic id>\"\n}]\n},\n\"condition\":\n\"{\\\"eventType\\\":[\\\" com.oraclecloud.cloudguard.problemdetected\\\",\\\"\ncom.oraclecloud.cloudguard.problemdismissed\\\",\\\"\ncom.oraclecloud.cloudguard.problemremediated\\\"],\\\"data\\\":{}}\",\n\"displayName\": \"<display name>\",\n\"description\": \"<description>\",\n\"isEnabled\": true,\n\"compartmentId\": \"compartment OCID\"\n}\n1. Create the actual event rule\noci events rule create --from-json file://event_rule.json\n1. Note in the JSON returned that it lists the parameters specified in the JSON file\nprovided and that there is an OCID provided for the Event Rule",
    "additional_information": "• Your tenancy might have a different Cloud Reporting region than your home\nregion.\n• The same Notification topic can be reused by many Event Rules.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "oci events rule list --compartment-id=<compartment OCID> --query \"data",
      "oci ons topic get --topic-id=<topic id> --query data.{\"name:name\"} --output"
    ],
    "remediation_commands": [
      "oci ons topic list --compartment-id=<compartment OCID> --all --query \"data",
      "oci events rule create --from-json file://event_rule.json"
    ],
    "references": [
      "1. https://docs.oracle.com/en-us/iaas/cloud-guard/using/export-notifs-config.htm"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 147,
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
    "cis_id": "4.16",
    "title": "Ensure customer created Customer Managed Key (CMK) is rotated at least annually",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Conduct Audit Log Reviews",
    "description": "Oracle Cloud Infrastructure Vault securely stores master encryption keys that protect\nyour encrypted data. You can use the Vault service to rotate keys to generate new\ncryptographic material. Periodically rotating keys limits the amount of data encrypted by\none key version.",
    "rationale": "Rotating keys annually limits the data encrypted under one key version. Key rotation\nthereby reduces the risk in case a key is ever compromised.",
    "audit": "From Console:\n1. Login into OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Vault.\n4. Click on the individual Vault under the Name heading.\n5. Ensure the date of each Master Encryption key under the Created column of the\nMaster Encryption key is no more than 365 days old, and that the key is in the\nENABLED state\n6. Repeat for all Vaults in all compartments\nFrom CLI:\n1. Execute the following for each Vault in each compartment\noci kms management key list --compartment-id '<compartment-id>' --endpoint\n'<management-endpoint-url>' --all --query \"data[*].[\\\"time-\ncreated\\\",\\\"display-name\\\",\\\"lifecycle-state\\\"]\"\n2. Ensure the date of the Master Encryption key is no more than 365 days old and\nis also in the ENABLED state.",
    "expected_response": "5. Ensure the date of each Master Encryption key under the Created column of the\n2. Ensure the date of the Master Encryption key is no more than 365 days old and",
    "remediation": "From Console:\n1. Login into OCI Console.\n2. Select Identity & Security from the Services menu.\n3. Select Vault.\n4. Click on the individual Vault under the Name heading.\n5. Click on the menu next to the time created.\n6. Click Rotate Key\nFrom CLI:\n1. Execute the following:\noci kms management key rotate --key-id <key-ocid> --endpoint <management-\nendpoint-url>",
    "detection_commands": [
      "oci kms management key list --compartment-id '<compartment-id>' --endpoint '<management-endpoint-url>' --all --query \"data[*].[\\\"time-"
    ],
    "remediation_commands": [
      "oci kms management key rotate --key-id <key-ocid> --endpoint <management-"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 151,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "4.17",
    "title": "Ensure write level Object Storage logging is enabled for all buckets",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Conduct Audit Log Reviews",
    "description": "Object Storage write logs will log all write requests made to objects in a bucket.",
    "rationale": "Enabling an Object Storage write log, the requestAction property would contain\nvalues of PUT, POST, or DELETE. This will provide you more visibility into changes to\nobjects in your buckets.",
    "impact": "There is no performance impact when enabling the above described features, but will\ngenerate additional use of object storage that should be controlled via object lifecycle\nmanagement.\nBy default, Object Storage logs are stored for 30 days in object storage. Users can\nspecify a longer retention period.",
    "audit": "From Console:\n1. Log into the OCI console.\n2. Go to https://cloud.oracle.com/object-storage/buckets.\n3. Click on the individual Bucket under the Name heading.\n4. Click Monitoring from the Resource menu.\n5. Scroll to Logs.\n6. Ensure Status is Active.\nFrom CLI:\n1. Find the bucket name of the specific bucket.\noci os bucket list --compartment-id <compartment-id>\n2. Find the OCID of the Log Group used for BucketLogs.\noci logging log-group list --compartment-id <compartment-id> --query \"data\n[?\\\"display-name\\\"=='<log-group-name>']\"\n3. List the logs associated with the bucket name for this bucket\noci logging log list --log-group-id <log-group-id> --query \"data\n[?configuration.source.resource=='<bucket-name>']\"\n4. Ensure a log is listed for this bucket name",
    "expected_response": "6. Ensure Status is Active.\n4. Ensure a log is listed for this bucket name",
    "remediation": "From Console:\n1. Log into the OCI console.\n2. Go to https://cloud.oracle.com/object-storage/buckets.\n3. Click on the individual Bucket under the Name heading.\n4. Click Monitoring from the Resource menu.\n5. Scroll to Logs.\n6. Click on the three dots ... on the line with Write Access Events.\n7. Click Enable Log.\n8. Select an existing log group from the list or select Create new group.\n9. Under Configure Log the name of the log.\n10. Select the time period in months each logging entry is to be retained from the list\n11. Select Enable log\nFrom CLI:\nFirst, if a log group for holding these logs has not already been created, create a log\ngroup by the following steps:\n1. Create a log group:\noci logging log-group create --compartment-id <compartment-id> --display-name\n\"<display-name>\" --description \"<description>\"\nThe output of the command gives you a work request id. You can query the work\nrequest to see the status of the job by issuing the following command:\noci logging work-request get --work-request-id <work-request-id>\nLook for status filed to be SUCCEEDED.\nSecond, enable Object Storage write log logging for your bucket(s) by the following\nsteps:\n2. Get the Log group ID needed for creating the Log:\noci logging log-group list --compartment-id <compartment-id> --query\n'data[?contains(\"display-name\", `'\"<display-name>\"'`)].id|join(`\\n`, @)' --\nraw-output\n3. Create a JSON file called config.json with the following content:\n{\n\"compartment-id\":\"<compartment-id>\",\n\"source\": {\n\"resource\": \"<bucket-name.\",\n\"service\": \"ObjectStorage\",\n\"source-type\": \"OCISERVICE\",\n\"category\": \"write\"\n}\n}\nThe compartment-id is the Compartment OCID of where the bucket is exists. The\nresource value is the bucket name.\n4. Create the Service Log:\noci logging log create --log-group-id <log-group-id> --display-name\n\"<display-name>\" --log-type SERVICE --is-enabled TRUE --configuration\nfile://config.json\nThe output of the command gives you a work request id. You can query the work\nrequest to see that status of the job by issuing the following command:\noci logging work-request get --work-request-id <work-request-id>\nLook for the status filed to be SUCCEEDED.",
    "detection_commands": [
      "oci os bucket list --compartment-id <compartment-id>",
      "oci logging log-group list --compartment-id <compartment-id> --query \"data",
      "oci logging log list --log-group-id <log-group-id> --query \"data"
    ],
    "remediation_commands": [
      "oci logging log-group create --compartment-id <compartment-id> --display-name \"<display-name>\" --description \"<description>\"",
      "oci logging work-request get --work-request-id <work-request-id>",
      "oci logging log-group list --compartment-id <compartment-id> --query 'data[?contains(\"display-name\", `'\"<display-name>\"'`)].id|join(`\\n`, @)' --",
      "oci logging log create --log-group-id <log-group-id> --display-name \"<display-name>\" --log-type SERVICE --is-enabled TRUE --configuration"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 153,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.18",
    "title": "Ensure a notification is configured for Local OCI User Authentication",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Activate audit logging",
    "description": "It is recommended that an Event Rule and Notification be set up when a user in the via\nOCI local authentication. Event Rules are compartment-scoped and will detect events in\nchild compartments. This Event rule is required to be created at the root compartment\nlevel.",
    "rationale": "Users should rarely use OCI local authenticated and be authenticated via organizational\nstandard Identity providers, not local credentials. Access in this matter would represent\na break glass activity and should be monitored to see if changes made impact the\nsecurity posture.",
    "impact": "There is no performance impact when enabling the above-described features but\ndepending on the amount of notifications sent per month there may be a cost\nassociated.",
    "audit": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the Root Compartment that hosts the rules\n3. Click the Rule that handles Identity SignOn Changes (if any)\n4. Ensure the Rule is ACTIVE\n5. Click the Edit Rule button and verify that the RuleConditions section contains\na condition Event Type for the Service Identity SignOn and Event Types:\nInteractive Login\n6. On the Action Type contains: Notifications and that a valid Topic is\nreferenced.\nFrom CLI:\n1. Find the OCID of the specific Event Rule based on Display Name and Tenancy\nOCID\noci events rule list --compartment-id <tenancy-ocid> --query \"data\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n2. List the details of a specific Event Rule based on the OCID of the rule.\noci events rule get --rule-id <rule-id>\n3. In the JSON output locate the Conditions key value pair and verify that the\nfollowing Conditions are present:\ncom.oraclecloud.identitysignon.interactivelogin\n4. Verify the value of the is-enabled attribute is true\n5. In the JSON output verify that actionType is ONS and locate the topic-id\n6. Verify the correct topic is used by checking the topic name\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output\ntable",
    "expected_response": "4. Ensure the Rule is ACTIVE\n[?\\\"display-name\\\"=='<display-name>']\".{\"id:id\"} --output table\n3. In the JSON output locate the Conditions key value pair and verify that the\n5. In the JSON output verify that actionType is ONS and locate the topic-id\noci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output",
    "remediation": "From Console:\n1. Go to the Events Service page: https://cloud.oracle.com/events/rules\n2. Select the Root compartment that should host the rule\n3. Click Create Rule\n4. Provide a Display Name and Description\n5. Create a Rule Condition by selecting Identity SignOn in the Service Name\nDrop-down and selecting Interactive Login\n6. In the Actions section select Notifications as Action Type\n7. Select the Compartment that hosts the Topic to be used.\n8. Select the Topic to be used\n9. Optionally add Tags to the Rule\n10. Click Create Rule\nFrom CLI:\n1. Find the topic-id of the topic the Event Rule should use for sending\nnotifications by using the topic name and Tenancy OCID\noci ons topic list --compartment-id <tenacy-ocid> --all --query \"data\n[?name=='<topic-name>']\".{\"name:name,topic_id:\\\"topic-id\\\"\"} --output table\n2. Create a JSON file to be used when creating the Event Rule. Replace topic id,\ndisplay name, description and compartment OCID.\n{\n\"actions\":\n{\n\"actions\": [\n{\n\"actionType\": \"ONS\",\n\"isEnabled\": true,\n\"topicId\": \"<topic-id>\"\n}]\n},\n\"condition\":\n\"{\\\"eventType\\\":[\\\"com.oraclecloud.identitysignon.interactivelogin\\\",data\\\":{\n}}\",\n\"displayName\": \"<display-name>\",\n\"description\": \"<description>\",\n\"isEnabled\": true,\n\"compartmentId\": \"<tenancy-ocid>\"\n}\n3. Create the actual event rule\noci events rule create --from-json file://event_rule.json\n4. Note in the JSON returned that it lists the parameters specified in the JSON file\nprovided and that there is an OCID provided for the Event Rule",
    "default_value": "Not set",
    "additional_information": "• The same Notification topic can be reused by many Event Rules.\n• The generated notification will include an eventID that can be used when\nquerying the Audit Logs in case further investigation is required.",
    "detection_commands": [
      "OCID oci events rule list --compartment-id <tenancy-ocid> --query \"data",
      "oci events rule get --rule-id <rule-id>",
      "oci ons topic get --topic-id <topic-id> --query data.{\"name:name\"} --output"
    ],
    "remediation_commands": [
      "Drop-down and selecting Interactive Login",
      "oci ons topic list --compartment-id <tenacy-ocid> --all --query \"data",
      "oci events rule create --from-json file://event_rule.json"
    ],
    "references": [
      "1. https://docs.oracle.com/en-",
      "us/iaas/Content/Security/Reference/iam_security_topic-",
      "IAM_Federation.htm#IAM_Federation"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 156,
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
    "cis_id": "5.1.1",
    "title": "Ensure no Object Storage buckets are publicly visible",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Object Storage",
    "description": "A bucket is a logical container for storing objects. It is associated with a single\ncompartment that has policies that determine what action a user can perform on a\nbucket and on all the objects in the bucket. By Default a newly created bucket is private.\nIt is recommended that no bucket be publicly accessible.",
    "rationale": "Removing unfettered reading of objects in a bucket reduces an organization's exposure\nto data loss.",
    "impact": "For updating an existing bucket, care should be taken to ensure objects in the bucket\ncan be accessed through either IAM policies or pre-authenticated requests.",
    "audit": "From Console:\n1. Login into the OCI Console\n2. Click in the search bar at the top of the screen.\n3. Type Advanced Resource Query and click enter.\n4. Click the Advanced Resource Query button in the upper right of the screen.\n5. Enter the following query in the query box:\nquery\nbucket resources\nwhere\n(publicAccessType == 'ObjectRead') || (publicAccessType ==\n'ObjectReadWithoutList')\n6. Ensure query returns no results\nFrom CLI:\n1. Execute the following command:\noci search resource structured-search --query-text \"query\nbucket resources\nwhere\n(publicAccessType == 'ObjectRead') || (publicAccessType ==\n'ObjectReadWithoutList')\"\n2. Ensure query returns no results\nCloud Guard\nTo Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root\ncompartment of the tenancy. For more information about enabling Cloud Guard, please\nlook at the instructions included in Recommendation 3.15.\nFrom Console:\n1. Type Cloud Guard into the Search box at the top of the Console.\n2. Click Cloud Guard from the “Services” submenu.\n3. Click Detector Recipes in the Cloud Guard menu.\n4. Click OCI Configuration Detector Recipe (Oracle Managed) under the\nRecipe Name column.\n5. Find Bucket is public in the Detector Rules column.\n6. Verify that the Bucket is public Detector Rule is Enabled.\nFrom CLI:\n1. Verify the Bucket is public Detector Rule in Cloud Guard is enabled to generate\nProblems if Object Storage Buckets are configured to be accessible over the\npublic Internet with the following command:\noci cloud-guard detector-recipe-detector-rule get --detector-recipe-id\n<insert detector recipe ocid> --detector-rule-id BUCKET_IS_PUBLIC",
    "expected_response": "6. Ensure query returns no results\n2. Ensure query returns no results\nTo Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root\n6. Verify that the Bucket is public Detector Rule is Enabled.\n1. Verify the Bucket is public Detector Rule in Cloud Guard is enabled to generate",
    "remediation": "From Console:\n1. Follow the audit procedure above.\n2. For each bucket in the returned results, click the Bucket Display Name\n3. Click Edit Visibility\n4. Select Private\n5. Click Save Changes\nFrom CLI:\n1. Follow the audit procedure\n2. For each of the buckets identified, execute the following command:\noci os bucket update --bucket-name <bucket-name> --public-access-type\nNoPublicAccess",
    "default_value": "Private",
    "detection_commands": [
      "oci search resource structured-search --query-text \"query",
      "oci cloud-guard detector-recipe-detector-rule get --detector-recipe-id"
    ],
    "remediation_commands": [
      "oci os bucket update --bucket-name <bucket-name> --public-access-type"
    ],
    "references": [
      "1. https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 162,
    "dspm_relevant": true,
    "dspm_categories": [
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.1.2",
    "title": "Ensure Object Storage Buckets are encrypted with a Customer Managed Key (CMK)",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Oracle Object Storage buckets support encryption with a Customer Managed Key\n(CMK). By default, Object Storage buckets are encrypted with an Oracle managed key.",
    "rationale": "Encryption of Object Storage buckets with a Customer Managed Key (CMK) provides\nan additional level of security on your data by allowing you to manage your own\nencryption key lifecycle management for the bucket.",
    "impact": "Encrypting with a Customer Managed Keys requires a Vault and a Customer Master\nKey. In addition, you must authorize Object Storage service to use keys on your behalf.\nRequired Policy:\nAllow service objectstorage-<region_name>,  to use keys in compartment\n<compartment-id> where target.key.id = '<key_OCID>'",
    "audit": "From Console:\n1. Go to https://cloud.oracle.com/object-storage/buckets\n2. Click on an individual bucket under the Name heading.\n3. Ensure that the Encryption Key is not set to Oracle managed key.\n4. Repeat for each compartment\nFrom CLI:\n1. Execute the following command\noci os bucket get --bucket-name <bucket-name>\n2. Ensure kms-key-id is not null\nCloud Guard\nTo Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root\ncompartment of the tenancy. For more information about enabling Cloud Guard, please\nlook at the instructions included in Recommendation 3.15.\nFrom Console:\n1. Type Cloud Guard into the Search box at the top of the Console.\n2. Click Cloud Guard from the “Services” submenu.\n3. Click Detector Recipes in the Cloud Guard menu.\n4. Click OCI Configuration Detector Recipe (Oracle Managed) under the\nRecipe Name column.\n5. Find Object Storage bucket is encrypted with Oracle-managed key in the\nDetector Rules column.\n6. Verify that the Object Storage bucket is encrypted with Oracle-managed key\nDetector Rule is Enabled.\nFrom CLI:\n1. Verify the Object Storage bucket is encrypted with Oracle-managed key Detector\nRule in Cloud Guard is enabled to generate Problems if Object Storage Buckets\nare configured without a customer managed key with the following command:\noci cloud-guard detector-recipe-detector-rule get --detector-recipe-id\n<insert detector recipe ocid> --detector-rule-id\nBUCKET_ENCRYPTED_WITH_ORACLE_MANAGED_KEY",
    "expected_response": "3. Ensure that the Encryption Key is not set to Oracle managed key.\n2. Ensure kms-key-id is not null\nTo Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root\nDetector Rule is Enabled.\nRule in Cloud Guard is enabled to generate Problems if Object Storage Buckets",
    "remediation": "From Console:\n1. Go to https://cloud.oracle.com/object-storage/buckets\n2. Click on an individual bucket under the Name heading.\n3. Click Assign next to Encryption Key: Oracle managed key.\n4. Select a Vault\n5. Select a Master Encryption Key\n6. Click Assign\nFrom CLI:\n1. Execute the following command\noci os bucket update --bucket-name <bucket-name> --kms-key-id <master-\nencryption-key-id>",
    "default_value": "Oracle Managed Key for Encryption",
    "detection_commands": [
      "oci os bucket get --bucket-name <bucket-name>",
      "oci cloud-guard detector-recipe-detector-rule get --detector-recipe-id"
    ],
    "remediation_commands": [
      "oci os bucket update --bucket-name <bucket-name> --kms-key-id <master-"
    ],
    "references": [
      "1. https://docs.oracle.com/en/solutions/oci-best-practices/protect-data-",
      "rest1.html#GUID-9C0F713E-4C67-43C6-80CA-525A6AB221F1",
      "2. https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/encryption.htm"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 165,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "5.1.3",
    "title": "Ensure Versioning is Enabled for Object Storage Buckets",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "A bucket is a logical container for storing objects. Object versioning is enabled at the\nbucket level and is disabled by default upon creation. Versioning directs Object Storage\nto automatically create an object version each time a new object is uploaded, an\nexisting object is overwritten, or when an object is deleted. You can enable object\nversioning at bucket creation time or later.",
    "rationale": "Versioning object storage buckets provides for additional integrity of your data.\nManagement of data integrity is critical to protecting and accessing protected data.\nSome customers want to identify object storage buckets without versioning in order to\napply their own data lifecycle protection and management policy.",
    "audit": "From Console:\n1. Login to OCI Console.\n2. Select Storage from the Services menu.\n3. Select Buckets from under the Object Storage & Archive Storage section.\n4. Click on an individual bucket under the Name heading.\n5. Ensure that the Object Versioning is set to Enabled.\n6. Repeat for each compartment\nFrom CLI:\n1. Execute the following command:\nfor region in $(oci iam region-subscription list --all | jq -r '.data[] |\n.\"region-name\"')\ndo\necho \"Enumerating region $region\"\nfor compid in $(oci iam compartment list --include-root --compartment-id-\nin-subtree TRUE 2>/dev/null | jq -r '.data[] | .id')\ndo\necho \"Enumerating compartment $compid\"\nfor bkt in $(oci os bucket list --compartment-id $compid --region $region\n2>/dev/null | jq -r '.data[] | .name')\ndo\noutput=$(oci os bucket get --bucket-name $bkt --region $region\n2>/dev/null | jq -r '.data | select(.\"versioning\" == \"Disabled\").name')\nif [ ! -z \"$output\" ]; then echo $output; fi\ndone\ndone\ndone\n2. Ensure no results are returned.",
    "expected_response": "5. Ensure that the Object Versioning is set to Enabled.\noutput=$(oci os bucket get --bucket-name $bkt --region $region\nif [ ! -z \"$output\" ]; then echo $output; fi\n2. Ensure no results are returned.",
    "remediation": "From Console:\n1. Follow the audit procedure above.\n2. For each bucket in the returned results, click the Bucket Display Name\n3. Click Edit next to Object Versioning: Disabled\n4. Click Enable Versioning\nFrom CLI:\n1. Follow the audit procedure\n2. For each of the buckets identified, execute the following command:\noci os bucket update --bucket-name <bucket name> --versioning Enabled",
    "default_value": "Object versioning is Disabled.",
    "detection_commands": [],
    "remediation_commands": [
      "oci os bucket update --bucket-name <bucket name> --versioning Enabled"
    ],
    "references": [
      "1. https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingversioning.htm",
      "2. https://docs.oracle.com/en-",
      "us/iaas/api/#/en/objectstorage/20160918/Bucket/GetBucket"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 168,
    "dspm_relevant": true,
    "dspm_categories": [
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.2.1",
    "title": "Ensure Block Volumes are encrypted with Customer Managed Keys (CMK)",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Block Volumes",
    "description": "Oracle Cloud Infrastructure Block Volume service lets you dynamically provision and\nmanage block storage volumes. By default, the Oracle service manages the keys that\nencrypt block volumes. Block Volumes can also be encrypted using a customer\nmanaged key.\nTerminated Block Volumes cannot be recovered and any data on a terminated volume\nis permanently lost. However, Block Volumes can exist in a terminated state within the\nOCI Portal and CLI for some time after deleting. As such, any Block Volumes in this\nstate should not be considered when assessing this policy.",
    "rationale": "Encryption of block volumes provides an additional level of security for your data.\nManagement of encryption keys is critical to protecting and accessing protected data.\nCustomers should identify block volumes encrypted with Oracle service managed keys\nin order to determine if they want to manage the keys for certain volumes and then\napply their own key lifecycle management to the selected block volumes.",
    "impact": "Encrypting with a Customer Managed Key requires a Vault and a Customer Master Key.\nIn addition, you must authorize the Block Volume service to use the keys you create.\nRequired IAM Policy:\nAllow service blockstorage to use keys in compartment <compartment-id> where\ntarget.key.id = '<key_OCID>'",
    "audit": "From Console:\n1. Login to the OCI Console.\n2. Click the search bar at the top of the screen.\n3. Type 'Advanced Resource Query' and press return.\n4. Click Advanced resource query.\n5. Enter the following query in the query box:\nquery volume resources\n6. For each block volume returned, click the link under Display name.\n7. Ensure the value for Encryption Key is not Oracle-managed key.\n8. Repeat for other subscribed regions.\nFrom CLI:\n1. Execute the following command:\nfor region in $(oci iam region-subscription list --all| jq -r '.data[] |\n.\"region-name\"')\ndo\necho \"Enumerating region: $region\"\nfor compid in `oci iam compartment list --compartment-id-in-subtree  TRUE\n2>/dev/null | jq -r '.data[] | .id'`\ndo\necho \"Enumerating compartment: $compid\"\nfor bvid in `oci bv volume list --compartment-id $compid --region\n$region 2>/dev/null | jq -r '.data[] | select(.\"kms-key-id\" == null).id'`\ndo\noutput=`oci bv volume get --volume-id $bvid --region $region --\nquery=data.{\"name:\\\"display-name\\\",\"id:id\"\"} --output table 2>/dev/null`\nif [ ! -z \"$output\" ]; then echo $output; fi\ndone\ndone\ndone\n2. Ensure the query returns no results.",
    "expected_response": "3. Type 'Advanced Resource Query' and press return.\n7. Ensure the value for Encryption Key is not Oracle-managed key.\noutput=`oci bv volume get --volume-id $bvid --region $region --\nquery=data.{\"name:\\\"display-name\\\",\"id:id\"\"} --output table 2>/dev/null`\nif [ ! -z \"$output\" ]; then echo $output; fi\n2. Ensure the query returns no results.",
    "remediation": "From Console:\n1. Follow the audit procedure above.\n2. For each block volume returned, click the link under Display name.\n3. If the value for Encryption Key is Oracle-managed key, click Assign next to\nOracle-managed key.\n4. Select a Vault Compartment and Vault.\n5. Select a Master Encryption Key Compartment and Master Encryption\nkey.\n6. Click Assign.\nFrom CLI:\n1. Follow the audit procedure.\n2. For each boot volume identified, get the OCID.\n3. Execute the following command:\noci bv volume-kms-key update –volume-id <volume OCID> --kms-key-id <kms key\nOCID>",
    "detection_commands": [
      "$region 2>/dev/null | jq -r '.data[] | select(.\"kms-key-id\" == null).id'`"
    ],
    "remediation_commands": [
      "oci bv volume-kms-key update –volume-id <volume OCID> --kms-key-id <kms key OCID>"
    ],
    "references": [
      "1. https://docs.oracle.com/en/solutions/oci-best-practices/protect-data-",
      "rest1.html#GUID-BA1F5A20-8C78-49E3-8183-927F0CC6F6CC",
      "2. https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/overview.htm"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 172,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.2.2",
    "title": "Ensure boot volumes are encrypted with Customer Managed Key (CMK)",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "When you launch a virtual machine (VM) or bare metal instance based on a platform\nimage or custom image, a new boot volume for the instance is created in the same\ncompartment. That boot volume is associated with that instance until you terminate the\ninstance. By default, the Oracle service manages the keys that encrypt this boot\nvolume. Boot Volumes can also be encrypted using a customer managed key.",
    "rationale": "Encryption of boot volumes provides an additional level of security for your data.\nManagement of encryption keys is critical to protecting and accessing protected data.\nCustomers should identify boot volumes encrypted with Oracle service managed keys in\norder to determine if they want to manage the keys for certain boot volumes and then\napply their own key lifecycle management to the selected boot volumes.",
    "impact": "Encrypting with a Customer Managed Keys requires a Vault and a Customer Master\nKey. In addition, you must authorize the Boot Volume service to use the keys you\ncreate. Required IAM Policy:\nAllow service Bootstorage to use keys in compartment <compartment-id> where\ntarget.key.id = '<key_OCID>'",
    "audit": "From Console:\n1. Login into the OCI Console\n2. Click in the search bar, top of the screen.\n3. Type Advanced Resource Query and click enter.\n4. Click the Advanced Resource Query button in the upper right of the screen.\n5. Enter the following query in the query box:\nquery bootvolume resources\n6. For each boot volume returned click on the link under Display name\n7. Ensure Encryption Key does not say Oracle managed key\n8. Repeat for other subscribed regions\nFrom CLI:\n1. Execute the following command:\nfor region in `oci iam region list | jq -r '.data[] | .name'`;\ndo\nfor bvid in `oci search resource structured-search --region $region --\nquery-text \"query bootvolume resources\" 2>/dev/null | jq -r '.data.items[] |\n.identifier'`\ndo\noutput=`oci bv boot-volume get --boot-volume-id $bvid  2>/dev/null\n| jq -r '.data | select(.\"kms-key-id\" == null).id'`\nif [ ! -z \"$output\" ]; then echo $output; fi\ndone\ndone\n2. Ensure query returns no results.",
    "expected_response": "7. Ensure Encryption Key does not say Oracle managed key\noutput=`oci bv boot-volume get --boot-volume-id $bvid  2>/dev/null\nif [ ! -z \"$output\" ]; then echo $output; fi\n2. Ensure query returns no results.",
    "remediation": "From Console:\n1. Follow the audit procedure above.\n2. For each Boot Volume in the returned results, click the Boot Volume name\n3. Click Assign next to Encryption Key\n4. Select the Vault Compartment and Vault\n5. Select the Master Encryption Key Compartment and Master Encryption\nkey\n6. Click Assign\nFrom CLI:\n1. Follow the audit procedure.\n2. For each boot volume identified get its OCID. Execute the following command:\noci bv boot-volume-kms-key update --boot-volume-id <Boot Volume OCID> --kms-\nkey-id <KMS Key OCID>",
    "detection_commands": [],
    "remediation_commands": [
      "oci bv boot-volume-kms-key update --boot-volume-id <Boot Volume OCID> --kms-"
    ],
    "references": [
      "1. https://docs.oracle.com/en/solutions/oci-best-practices/protect-data-",
      "rest1.html#GUID-BA1F5A20-8C78-49E3-8183-927F0CC6F6CC"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 175,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.3.1",
    "title": "Ensure File Storage Systems are encrypted with Customer Managed Keys (CMK)",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "File Storage Service",
    "description": "Oracle Cloud Infrastructure File Storage service (FSS) provides a durable, scalable,\nsecure, enterprise-grade network file system. By default, the Oracle service manages\nthe keys that encrypt FSS file systems. FSS file systems can also be encrypted using a\ncustomer managed key.",
    "rationale": "Encryption of FSS systems provides an additional level of security for your data.\nManagement of encryption keys is critical to protecting and accessing protected data.\nCustomers should identify FSS file systems that are encrypted with Oracle service\nmanaged keys in order to determine if they want to manage the keys for certain FSS file\nsystems and then apply their own key lifecycle management to the selected FSS file\nsystems.",
    "impact": "Encrypting with a Customer Managed Keys requires a Vault and a Customer Master\nKey. In addition, you must authorize the File Storage service to use the keys you create.\nRequired IAM Policy:\nAllow service FssOc1Prod to use keys in compartment <compartment-id> where\ntarget.key.id = '<key_OCID>'",
    "audit": "From Console:\n1. Login into the OCI Console\n2. Click in the search bar, top of the screen.\n3. Type Advanced Resource Query and click enter.\n4. Click the Advanced Resource Query button in the upper right of the screen.\n5. Enter the following query in the query box:\nquery filesystem resources\n6. For each file storage system returned click on the link under Display name\n7. Ensure Encryption Key does not say Oracle-managed key\n8. Repeat for other subscribed regions\nFrom CLI:\n1. Execute the following command:\nfor region in `oci iam region list | jq -r '.data[] | .name'`;\ndo\nfor fssid in `oci search resource structured-search --region $region -\n-query-text \"query filesystem resources\" 2>/dev/null | jq -r '.data.items[] |\n.identifier'`\ndo\noutput=`oci fs file-system get --file-system-id $fssid --region\n$region 2>/dev/null | jq -r '.data | select(.\"kms-key-id\" == \"\").id'`\nif [ ! -z \"$output\" ]; then echo $output; fi\ndone\ndone\n2. Ensure query returns no results",
    "expected_response": "7. Ensure Encryption Key does not say Oracle-managed key\noutput=`oci fs file-system get --file-system-id $fssid --region\nif [ ! -z \"$output\" ]; then echo $output; fi\n2. Ensure query returns no results",
    "remediation": "From Console:\n1. Follow the audit procedure above.\n2. For each File Storage System in the returned results, click the File System\nStorage\n3. Click Edit next to Encryption Key\n4. Select Encrypt using customer-managed keys\n5. Select the Vault Compartment and Vault\n6. Select the Master Encryption Key Compartment and Master Encryption\nkey\n7. Click Save Changes\nFrom CLI:\n1. Follow the audit procedure.\n2. For each File Storage System identified get its OCID. Execute the following\ncommand:\noci bv volume-kms-key update –volume-id <volume OCID> --kms-key-id <kms key\nOCID>",
    "detection_commands": [
      "$region 2>/dev/null | jq -r '.data | select(.\"kms-key-id\" == \"\").id'`"
    ],
    "remediation_commands": [
      "oci bv volume-kms-key update –volume-id <volume OCID> --kms-key-id <kms key OCID>"
    ],
    "references": [
      "1. https://docs.oracle.com/en/solutions/oci-best-practices/protect-data-",
      "rest1.html#GUID-BA1F5A20-8C78-49E3-8183-927F0CC6F6CC",
      "2. https://docs.oracle.com/en-",
      "us/iaas/Content/File/Concepts/filestorageoverview.htm"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 179,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.1",
    "title": "Create at least one compartment in your tenancy to store cloud resources",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "asset_management",
    "domain": "Asset Management",
    "description": "When you sign up for Oracle Cloud Infrastructure, Oracle creates your tenancy, which is\nthe root compartment that holds all your cloud resources. You then create additional\ncompartments within the tenancy (root compartment) and corresponding policies to\ncontrol access to the resources in each compartment.\nCompartments allow you to organize and control access to your cloud resources. A\ncompartment is a collection of related resources (such as instances, databases, virtual\ncloud networks, block volumes) that can be accessed only by certain groups that have\nbeen given permission by an administrator.",
    "rationale": "Compartments are a logical group that adds an extra layer of isolation, organization and\nauthorization making it harder for unauthorized users to gain access to OCI resources.",
    "impact": "Once the compartment is created an OCI IAM policy must be created to allow a group\nto resources in the compartment otherwise only group with tenancy access will have\naccess.",
    "audit": "From Console:\n1. Login into the OCI Console.\n2. Click in the search bar, top of the screen.\n3. Type Advanced Resource Query and hit enter.\n4. Click the Advanced Resource Query button in the upper right of the screen.\n5. Enter the following query in the query box:\nquery\ncompartment resources\nwhere\n(compartmentId='<tenancy-id>' && lifecycleState='ACTIVE')\n6. Ensure query returns at least one compartment in addition to the\nManagedCompartmentForPaaS compartment\nFrom CLI:\n1. Execute the following command\noci search resource structured-search --query-text \"query\ncompartment resources\nwhere\n(compartmentId='<tenancy-id>' && lifecycleState='ACTIVE')\"\n2. Ensure items are returned.",
    "expected_response": "6. Ensure query returns at least one compartment in addition to the\n2. Ensure items are returned.",
    "remediation": "From Console:\n1. Login to OCI Console.\n2. Select Identity from the Services menu.\n3. Select Compartments from the Identity menu.\n4. Click Create Compartment\n5. Enter a Name\n6. Enter a Description\n7. Select the root compartment as the Parent Compartment\n8. Click Create Compartment\nFrom CLI:\n1. Execute the following command\noci iam compartment create --compartment-id '<tenancy-id>' --name\n'<compartment-name>' --description '<compartment description>'",
    "detection_commands": [
      "oci search resource structured-search --query-text \"query"
    ],
    "remediation_commands": [
      "oci iam compartment create --compartment-id '<tenancy-id>' --name '<compartment-name>' --description '<compartment description>'"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 183,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "6.2",
    "title": "Ensure no resources are created in the root compartment",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "asset_management",
    "domain": "Asset Management",
    "subdomain": "Establish and Maintain a Data Management Process",
    "description": "When you create a cloud resource such as an instance, block volume, or cloud network,\nyou must specify to which compartment you want the resource to belong. Placing\nresources in the root compartment makes it difficult to organize and isolate those\nresources.",
    "rationale": "Placing resources into a compartment will allow you to organize and have more\ngranular access controls to your cloud resources.",
    "impact": "Placing a resource in a compartment will impact how you write policies to manage\naccess and organize that resource.",
    "audit": "From Console:\n1. Login into the OCI Console.\n2. Click in the search bar, top of the screen.\n3. Type Advance Resource Query and hit enter.\n4. Click the Advanced Resource Query button in the upper right of the screen.\n5. Enter the following query into the query box:\nquery\nVCN, instance, bootvolume, volume, filesystem, bucket,\nautonomousdatabase, database, dbsystem resources\nwhere compartmentId = '<tenancy-id>'\n6. Ensure query returns no results.\nFrom CLI:\n1. Execute the following command:\noci search resource structured-search --query-text \"query\nVCN, instance, volume, bootvolume, filesystem, bucket,\nautonomousdatabase, database, dbsystem resources\nwhere compartmentId = '<tenancy-id>'\"\n2. Ensure query return no results.",
    "expected_response": "6. Ensure query returns no results.\n2. Ensure query return no results.",
    "remediation": "From Console:\n1. Follow audit procedure above.\n2. For each item in the returned results, click the item name.\n3. Then select Move Resource or More Actions then Move Resource.\n4. Select a compartment that is not the root compartment in CHOOSE NEW\nCOMPARTMENT.\n5. Click Move Resource.\nFrom CLI:\n1. Follow the audit procedure above.\n2. For each bucket item execute the below command:\noci os bucket update --bucket-name <bucket-name> --compartment-id <not root\ncompartment-id>\n3. For other resources use the change-compartment command for the resource\ntype:\noci <service-command> <resource-command> change-compartment --<item-id>\n<item-id> --compartment-id <not root compartment-id>\ni. Example for an Autonomous Database:\noci db autonomous-database change-compartment --autonomous-database-id\n<autonmous-database-id> --compartment-id <not root compartment-id>",
    "additional_information": "https://docs.cloud.oracle.com/en-\nus/iaas/Content/GSG/Concepts/settinguptenancy.htm#Understa",
    "detection_commands": [
      "oci search resource structured-search --query-text \"query"
    ],
    "remediation_commands": [
      "oci os bucket update --bucket-name <bucket-name> --compartment-id <not root",
      "oci <service-command> <resource-command> change-compartment --<item-id>",
      "oci db autonomous-database change-compartment --autonomous-database-id"
    ],
    "source_pdf": "CIS_Oracle_Cloud_Infrastructure_Foundations_Benchmark_v3.1.0.pdf",
    "page": 185,
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
  }
]
""")


def get_oci_cis_registry() -> list[dict]:
    """Return the complete CIS control registry as a list of dicts."""
    return OCI_CIS_CONTROLS


def get_oci_control_count() -> int:
    """Return total number of CIS controls."""
    return len(OCI_CIS_CONTROLS)


def get_oci_automated_count() -> int:
    """Return count of automated controls."""
    return sum(1 for c in OCI_CIS_CONTROLS if c["assessment_type"] == "automated")


def get_oci_manual_count() -> int:
    """Return count of manual controls."""
    return sum(1 for c in OCI_CIS_CONTROLS if c["assessment_type"] == "manual")


def get_oci_dspm_controls() -> list[dict]:
    """Return controls relevant to DSPM (Data Security Posture Management)."""
    return [c for c in OCI_CIS_CONTROLS if c.get("dspm_relevant")]


def get_oci_rr_controls() -> list[dict]:
    """Return controls relevant to Ransomware Readiness."""
    return [c for c in OCI_CIS_CONTROLS if c.get("rr_relevant")]


def get_oci_controls_by_service_area(service_area: str) -> list[dict]:
    """Return controls filtered by service area."""
    return [c for c in OCI_CIS_CONTROLS if c["service_area"] == service_area]


def get_oci_controls_by_severity(severity: str) -> list[dict]:
    """Return controls filtered by severity."""
    return [c for c in OCI_CIS_CONTROLS if c["severity"] == severity]
