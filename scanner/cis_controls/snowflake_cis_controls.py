"""CIS Snowflake Foundations Benchmark v1.1.0 — Complete Control Registry.

Auto-generated from the unified CIS controls library.
Contains ALL 39 controls (23 automated, 16 manual).
Each control includes full metadata, audit procedures, detection commands,
remediation guidance, and DSPM/Ransomware Readiness mapping.

Reference: CIS Snowflake Foundations Benchmark v1.1.0 (2024)
Source: CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf

Total controls: 39 (23 automated, 16 manual)
"""

import json as _json


# Control registry — 39 controls
SNOWFLAKE_CIS_CONTROLS: list[dict] = _json.loads(r"""
[
  {
    "cis_id": "1.1",
    "title": "Ensure single sign-on (SSO) is configured for your account / organization",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "description": "Federated authentication enables users to connect to Snowflake using secure SSO\n(single sign-on). With SSO enabled, users authenticate through an external (SAML 2.0-\ncompliant or OAuth 2.0) identity provider (IdP). Once authenticated by an IdP, users can\naccess their Snowflake account for the duration of their IdP session without having to\nauthenticate to Snowflake again. Users can choose to initiate their sessions from within\nthe interface provided by the IdP or directly in Snowflake.\nSnowflake offers native support for federated authentication and SSO through Okta and\nMicrosoft ADFS.\nSnowflake also supports most SAML 2.0-compliant vendors as an IdP, including Google\nG Suite, Microsoft Azure Active Directory, OneLogin, and Ping Identity PingOne. To use\nan IdP other than Okta or ADFS, you must define a custom application for Snowflake in\nthe IdP.\nThere are two ways to configure SAML:\n• By creating the security integration (recommended)\n• By setting the SAML_IDENTITY_PROVIDER account parameter (deprecated)",
    "rationale": "Configuring your Snowflake authentication so that users can log in using SSO reduces\nthe attack surface for your organization because users only log in once across multiple\napplications and do not have to manage a separate set of credentials for their\nSnowflake account.",
    "impact": "There may be costs associated with provisioning and using an IdP service.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List all the security integrations in your account.\nSHOW SECURITY INTEGRATIONS;\n2. Ensure that there are security integrations of type SAML2 and EXTERNAL_OAUTH\nconfigured for an account.\nSELECT *\nFROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))\nWHERE (\"type\" LIKE 'EXTERNAL_OAUTH%' OR \"type\" LIKE 'SAML2')\nAND \"enabled\" = TRUE;\n3. Ensure that there is an SSO integration configured for the account.\nNote: The presence of a configured security integration does not mean that it is\nconfigured correctly and working. Configuration correctness should be explicitly\ntested\nRequired privileges:\nTo be able to execute the above audit query above, the caller needs the USAGE privilege\non every security integration in your Snowflake account.",
    "expected_response": "2. Ensure that there are security integrations of type SAML2 and EXTERNAL_OAUTH\n3. Ensure that there is an SSO integration configured for the account.\nconfigured correctly and working. Configuration correctness should be explicitly",
    "remediation": "The steps for configuring an IdP differ depending on whether you choose SAML2 or\nOAuth. They further differ depending on what identity provider you choose: Okta, AD\nFS, Ping Identity, Azure AD, or custom. For specific instructions, see Snowflake\ndocumentation on SAML and External OAuth.\nNote: If your SAML integration is configured using the deprecated account parameter\nSAML_IDENTITY_PROVIDER, you should migrate to creating a security integration using the\nsystem$migrate_saml_idp_registration function. For more information, see the\nMigrating to a SAML2 Security Integration documentation.",
    "default_value": "By default, Snowflake is not configured to use SSO-based authentication.",
    "detection_commands": [
      "SHOW SECURITY INTEGRATIONS;",
      "SELECT *"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/admin-security-fed-auth.html",
      "2. https://docs.snowflake.com/en/user-guide/admin-security-fed-auth-configure-",
      "idp.html",
      "3. https://docs.snowflake.com/en/user-guide/oauth-external.html",
      "4. https://docs.snowflake.com/en/user-guide/admin-security-fed-auth-",
      "advanced.html",
      "5. https://docs.snowflake.com/en/sql-reference/parameters#saml-identity-provider",
      "6. https://docs.snowflake.com/en/user-guide/admin-security-fed-auth-configure-",
      "snowflake"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 14,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "1.2",
    "title": "Ensure Snowflake SCIM integration is configured to automatically provision and deprovision users and groups (i.e. roles)",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Configure Centralized Point of Authentication",
    "description": "The System for Cross-domain Identity Management (SCIM) is an open specification\ndesigned to help facilitate the automated management of user identities and groups (i.e.\nroles) in cloud applications using RESTful APIs.\nSnowflake supports SCIM 2.0 integration with Okta, Microsoft Azure AD and custom\nidentity providers. Users and groups from the identity provider can be provisioned into\nSnowflake, which functions as the service provider.",
    "rationale": "While SSO enables seamless authentication with a federated identity to the Snowflake\napplication, user accounts still need to be created, managed, and deprovisioned.\nOperations like adding and deleting users, changing permissions, and adding new types\nof accounts usually take up valuable admin time and when done manually may be error-\nprone.\nWith SCIM, user identities can be created either directly in your identity provider, or\nimported from external systems like HR software or Active Directory. SCIM enables IT\ndepartments to automate the user provisioning and deprovisioning process while also\nhaving a single system to manage permissions and groups. Since data is transferred\nautomatically, risk of error is reduced.",
    "impact": "None.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List the security integrations in your account:\nSHOW SECURITY INTEGRATIONS;\n2. Ensure that a SCIM integration is configured. The output of the following\ncommand shows all SCIM security integrations configured for an account. No\noutput means no SCIM integration has been configured for the account.\n3. Ensure that there are security integrations of type SCIM% with enabled set to true.\nSELECT *\nFROM TABLE(result_scan(last_query_id()))\nWHERE (\"type\" like 'SCIM%') AND \"enabled\" = true;\nNote: The presence of a SCIM security integration does not mean that it is\nconfigured correctly and working.\nRequired privileges:\nTo be able to execute the above audit query above, the caller needs the USAGE privilege\non every security integration in an account.",
    "expected_response": "2. Ensure that a SCIM integration is configured. The output of the following\noutput means no SCIM integration has been configured for the account.\n3. Ensure that there are security integrations of type SCIM% with enabled set to true.",
    "remediation": "Follow the instructions in the Snowflake documentation to set up SCIM configuration for\nOkta, Azure AD, or configure a custom SCIM integration.",
    "default_value": "By default, SCIM integration is not set-up for Snowflake.",
    "detection_commands": [
      "SHOW SECURITY INTEGRATIONS;",
      "SELECT *"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/scim-intro.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 17,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "1.3",
    "title": "Ensure that Snowflake password is unset for SSO users",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Configure Centralized Point of Authentication",
    "description": "Ensure that Snowflake password is unset for SSO users.",
    "rationale": "Allowing users to sign in with Snowflake passwords in the presence of a configured\nthird-party identity provider SSO may undermine mandatory security controls configured\non the SSO and degrade the security posture of the account. For example, the SSO\nsign-in flow may be configured to require multi-factor authentication (MFA), whereas the\nSnowflake password sign-in flow may not.\nNote:\n• This benchmark does not preclude configuration of key pair authentication for\nSSO users. Key pair authentication may be necessary for users to interact with\nSnowflake programmatically or through third party tools.\n• To mitigate the risk of users not being able to sign-in due to SSO provider\noutage, ensure that at least one SSO break-glass user exists with Snowflake\npassword reset privileges for account users. This break-glass user should be\nable to sign in using a Snowflake native password (coupled with MFA) or a key\npair.",
    "impact": "Users will not be able to sign into their Snowflake accounts if SSO sign-in flow breaks,\nfor example due to SSO provider outage.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Show all users in an account that have a password set:\nSELECT NAME, HAS_PASSWORD\nFROM SNOWFLAKE.ACCOUNT_USAGE.USERS\nWHERE HAS_PASSWORD\nAND DELETED_ON IS NULL\nAND NOT DISABLED;\n2. Check your IdP configurations and ensure that, if there are users with\npasswords, these users are not SSO users. An exception should be allowed for a\nthe break-glass SSO user which needs to be able to log-in with a Snowflake\npassword and MFA (or with a key pair).\nRequired privileges:\nRunning the query requires the SECURITY_VIEWER role on the Snowflake database.",
    "expected_response": "2. Check your IdP configurations and ensure that, if there are users with\npasswords, these users are not SSO users. An exception should be allowed for a",
    "remediation": "Programmatically:\nFor each SSO user <username> with a password, run the following command to set\npassword to null:\nALTER USER <username>\nSET PASSWORD = NULL;",
    "default_value": "When a user is created using the CREATE USER command in Snowflake, providing a\npassword is optional. When a password is not specified, it is set to NULL.\nWhen System for Cross-domain Identity Management (SCIM) integration is configured\nand users are managed in an external identity provider, whether a Snowflake password\nis set for a user by default depends on the default configuration of the SCIM client. For\nexample, the Okta SCIM client by default is configured to generate and set a new\nrandom password whenever the user's Okta password changes.",
    "detection_commands": [
      "SELECT NAME, HAS_PASSWORD"
    ],
    "remediation_commands": [
      "ALTER USER <username>"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/sql-reference/sql/create-user.html",
      "2. https://docs.snowflake.com/en/user-guide/scim-okta.html#features",
      "3. https://docs.snowflake.com/en/user-guide/key-pair-auth.html",
      "4. https://community.snowflake.com/s/article/FAQ-User-and-Password-",
      "Management"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 20,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.4",
    "title": "Ensure multi-factor authentication (MFA) is turned on for all human users with password-based authentication",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Configure Centralized Point of Authentication",
    "description": "Multi-factor authentication (MFA) is a security control used to add an additional layer of\nlogin security. It works by requiring the user to present two or more proofs (factors) of\nuser identity. An MFA example would be requiring a password and a verification code\ndelivered to the user's phone during user sign-in.\nThe MFA feature for Snowflake users is powered by the Duo Security service.",
    "rationale": "MFA mitigates security threats of users creating weak passwords and user passwords\nbeing stolen or accidentally leaked.",
    "impact": "If users lose access to the second factor of authentication, an account admin may need\nto reset their access.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List all active users with passwords and no MFA enabled:\nSELECT NAME, EXT_AUTHN_DUO AS MFA_ENABLED\nFROM SNOWFLAKE.ACCOUNT_USAGE.USERS\nWHERE DELETED_ON IS NULL\nAND NOT DISABLED\nAND HAS_PASSWORD;\n2. Ensure that the query above does not return any results.\nNote: If users have SSO enabled, the MFA authentication will be handled by the\nIdentity Provider and does not reflect in the query above. For SSO users,\nconfigure and check MFA status on your Identity Provider.\nRequired privileges:\nRunning the query requires the SECURITY_VIEWER role on the Snowflake database.",
    "expected_response": "2. Ensure that the query above does not return any results.",
    "remediation": "Users have to individually enroll into MFA using the Snowflake web UI.\nFrom the UI:\n1. Each user with a password should go to https://app.snowflake.com/ and sign into\ntheir Snowflake account.\n2. Click on the username on the top left side.\n3. Click on Profile.\n4. Next to Multi-factor authentication click Enroll.\n5. Click Start setup.\n6. Select the type of device and click Continue.\n7. Follow the steps to finish the enrollment.\nIf MFA needs to be enabled for a large population of users, consider prioritizing users\nwith ACCOUNTADMIN, SECURITYADMIN or other highly privileged roles.\nFor specific instructions, see the documentation page Enrolling in MFA (Multi-Factor\nAuthentication).\nNote: If you use SSO authentication, you will have to check and configure MFA with\nyour Identity Provider.",
    "default_value": "By default MFA is not enabled for Snowflake users.",
    "detection_commands": [
      "SELECT NAME, EXT_AUTHN_DUO AS MFA_ENABLED"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-access-control-configure.html",
      "2. https://docs.snowflake.com/en/user-guide/security-mfa.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 23,
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
    "cis_id": "1.5",
    "title": "Ensure minimum password length is set to 14 characters or more",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Require Multi-factor Authentication",
    "description": "To mitigate the risk of unauthorized access to a Snowflake account through easily\nguessable password, Snowflake enforces the following password policy as a minimum\nrequirement while using the ALTER USER command and the web interface:\n• Must be at least 8 characters long.\n• Must contain at least 1 digit.\n• Must contain at least 1 uppercase letter and 1 lowercase letter.\nSnowflake password policies can be used to specify and enforce further constraints on\npassword length and complexity.\nSnowflake supports setting a password policy for your Snowflake account and for\nindividual users. Only one password policy can be set at any given time for your\nSnowflake account or a user. If a password policy exists for the Snowflake account and\nanother password policy is set for a user in the same Snowflake account, the user-level\npassword policy takes precedence over the account-level password policy.\nThe password policy applies to new passwords that are set in your Snowflake account.\nTo ensure that users with existing passwords meet the password policy requirements,\nrequire users to change their password during their next login to Snowflake as shown in\nStep 6: Require a Password Change.",
    "rationale": "While Snowflake recommends configuring SSO authentication for users and ensuring\nthat SSO users do not have a password set, there may be exceptions when users still\nneed to log in with a password (e.g., setting up a break-glass user with password login\nto recover from SSO outages). For those few users that still need to have a password,\nsetting a password policy can help ensure that, throughout subsequent password\nchanges, the passwords used remain complex and therefore harder to guess or brute-\nforce.",
    "impact": "None.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List account-level password policies that enforce a minimum password length of\n14 characters.\nWITH PWDS_WITH_MIN_LEN AS (\nSELECT ID\nFROM SNOWFLAKE.ACCOUNT_USAGE.PASSWORD_POLICIES\nWHERE PASSWORD_MIN_LENGTH >= 14\nAND DELETED IS NULL\n)\nSELECT A.*\nFROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A\nLEFT JOIN PWDS_WITH_MIN_LEN AS B ON A.POLICY_ID = B.ID\nWHERE A.REF_ENTITY_DOMAIN = 'ACCOUNT'\nAND A.POLICY_KIND = 'PASSWORD_POLICY'\nAND A.POLICY_STATUS = 'ACTIVE'\nAND B.ID IS NOT NULL;\n2. Ensure that the query above returns a password policy.\n3. List all user-level password policies. All password policies applied on the user\nlevel also need to be checked, therefore a password policy set for a user\noverrides a password policy set on an account.\nWITH PWDS_WITH_MIN_LEN AS (\nSELECT ID\nFROM SNOWFLAKE.ACCOUNT_USAGE.PASSWORD_POLICIES\nWHERE PASSWORD_MIN_LENGTH >= 14\nAND DELETED IS NULL\n)\nSELECT A.*\nFROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A\nLEFT JOIN PWDS_WITH_MIN_LEN AS B ON A.POLICY_ID = B.ID\nWHERE A.REF_ENTITY_DOMAIN = 'USER'\nAND A.POLICY_STATUS = 'ACTIVE'\nAND B.ID IS NULL;\n4. Ensure that the query above does not return any results.",
    "expected_response": "2. Ensure that the query above returns a password policy.\n4. Ensure that the query above does not return any results.",
    "remediation": "Follow the following steps to set and enforce a password policy:\n1. Create the password policy if it does not exist:\nCREATE PASSWORD POLICY <password_policy>\nPASSWORD_MIN_LENGTH = 14\nPASSWORD_MAX_AGE_DAYS = 0;\n2. Set password policy on the account level:\nALTER ACCOUNT\nSET PASSWORD POLICY <password_policy>;\nNote: It may take up to 2 hours for the password policies created to show up in\nthe account usage view. For more information on latency, see the Data latency\nfor Account Usage documentation.",
    "default_value": "The default value for minimum password length is 8 characters.",
    "additional_information": "Snowflake password policies are effective only for Snowflake users authenticating with\nSnowflake-managed passwords. For users accessing Snowflake accounts integrated\nwith an SSO provider, password policy should be set on the SSO provider side.",
    "detection_commands": [
      "SELECT ID",
      "SELECT A.*"
    ],
    "remediation_commands": [
      "CREATE PASSWORD POLICY <password_policy>",
      "ALTER ACCOUNT"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/admin-user-management#password-",
      "policies"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 26,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.6",
    "title": "Ensure that service accounts use key pair authentication",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "characters",
    "domain": "characters",
    "subdomain": "Use Unique Passwords",
    "description": "Service account is an identity used by scripts, jobs, applications, pipelines, etc. to talk to\nSnowflake. It is also sometimes known as \"application user\", \"service principal\", \"system\naccount\", or \"daemon user\".\nOn the platform level Snowflake does not differentiate between Snowflake users\ncreated for and used by humans and Snowflake users created for and used by services.\nPassword-based authentication used by humans can be augmented by a second factor\n(MFA), e.g. a hardware token, or a security code pushed to a mobile device. Services\nand automation cannot be easily configured to authenticate with a second factor.\nInstead, for such use cases, Snowflake supports using key pair authentication as a\nmore secure alternative to password-based authentication.\nNote that password-based authentication for a service account can be enabled along\nwith a key-based authentication. To ensure that only key-based authentication is\nenabled for a service account, the PASSWORD parameter for that Snowflake user must be\nset to null.",
    "rationale": "Password-based authentication has a set of disadvantages that increase probability of a\nsecurity incident, especially when used without MFA:\n• Passwords created by humans are generally more predictable and less random\nthan keys generated by a computer. Consequently, passwords are easier to\nbrute force both online (against a live service) or offline (against a hashed\npassword database).\n• Passwords are usually transmitted over the network and can be leaked when the\ntransmission channel is insecure or when an application is accidentally\nmisconfigured to log passwords.\n• Passwords are easier to leak by writing them down on a sticky note attached to\nthe back of a keyboard.\n• It is easier to trick (phish) a user into revealing their password to an unauthorized\nparty.\nUsing key-based authentication for service accounts helps with mitigating the\naforementioned issues.",
    "impact": "Snowflake authentication for existing automation and services that use service accounts\nwith password-based authentication will be broken if corresponding configuration is not\nupdated before service accounts passwords are set to null.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. If Snowflake service account users are marked with ACCOUNT_TYPE=service tag,\nthen all non-compliant service account users that either have a password or do\nnot have key authentication enabled can be identified with the following query:\n-- The query assumes that service accounts are tagged with\nACCOUNT_TYPE=service tag.\nselect tr.object_name\nfrom snowflake.account_usage.tag_references tr\nleft join snowflake.account_usage.users u on tr.object_name = u.name\nwhere  tr.tag_name = 'ACCOUNT_TYPE'\nand tr.tag_value = 'service'\nand tr.domain = 'USER'\nand u.deleted_on is null\nand (u.has_password = true OR has_rsa_public_key = false);\n2. Ensure that the query above does not return any results.\nRequired privileges:\nThe query requires the following privileges:\n• Database role snowflake.security_viewer.\n• Database role snowflake.governance_viewer.",
    "expected_response": "2. Ensure that the query above does not return any results.",
    "remediation": "Programmatically:\nFor every non-compliant service account:\n1. Follow the Configuring Key Pair Authentication instructions to generate the key\n<rsa_public_key>.\n2. In a Snowsight worksheet or through the SnowSQL CLI, run the following\ncommand:\nALTER USER <service_account_name>\nSET RSA_PUBLIC_KEY='<rsa_public_key>';\n3. Update configuration of the automation and services that rely on the service\naccount to use key-based authentication. This is going to be specific to the\nservice in question.\n4. Disable password-based authentication:\nALTER USER <service_account_name> SET PASSWORD = null;",
    "default_value": "To enable key based authentication for a Snowflake user either RSA_PUBLIC_KEY or\nRSA_PUBLIC_KEY_2 parameters must be set on the Snowflake user. By default the\nCREATE USER command does not require setting either of the parameters. Also,\nsetting either of the parameters does not prevent from additionally setting a password\nfor the same user.",
    "detection_commands": [
      "select tr.object_name"
    ],
    "remediation_commands": [
      "ALTER USER <service_account_name>",
      "ALTER USER <service_account_name> SET PASSWORD = null;"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/key-pair-auth.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 29,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "1.7",
    "title": "Ensure authentication key pairs are rotated every 180 days",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "characters",
    "domain": "characters",
    "subdomain": "Use Unique Passwords",
    "description": "Snowflake supports using RSA key pair authentication as an alternative to password\nauthentication and as a primary way to authenticate service accounts.\nAuthentication key pair rotation is a process of replacing an existing authentication key\npair with a freshly generated key pair.\nSnowflake supports two active authentication key pairs to allow for uninterrupted key\nrotation. Rotate and replace your authentication key pairs based on the expiration\nschedule at least once every 180 days.",
    "rationale": "Periodic authentication key pair rotation mitigates the threat of compromised or leaked\nkeys. It reduces the window of opportunity during which a given key is valid and can be\nused by a threat actor.",
    "impact": "Existing automation and services that rely on key pair authentication may break if they\nare not updated to use a new authentication key before the old key is inactivated.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Parse the account query history and output all users and key pair names for key\npairs that were set more than 180 days ago.\nWITH FILTERED_QUERY_HISTORY AS (\n-- Extract necessary fields and apply initial filters\nSELECT END_TIME AS SET_TIME,\nUPPER(REGEXP_SUBSTR(QUERY_TEXT, 'USER\\\\s+\"?([\\\\w]+)\"?', 1, 1,\n'i', 1)) AS PROCESSED_USERNAME,\nQUERY_TEXT\nFROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY\nWHERE EXECUTION_STATUS = 'SUCCESS'\nAND QUERY_TYPE IN ('ALTER_USER', 'CREATE_USER')\nAND TO_DATE(SET_TIME) < DATEADD(day, -180, CURRENT_DATE())\nAND (QUERY_TEXT ILIKE '%rsa_public_key%' OR QUERY_TEXT ILIKE\n'%rsa_public_key_2%')\n),\nEXTRACTED_KEYS AS (\nSELECT SET_TIME,\nPROCESSED_USERNAME,\nCASE\nWHEN POSITION('rsa_public_key' IN LOWER(QUERY_TEXT)) > 0\nTHEN 'rsa_public_key'\nWHEN POSITION('rsa_public_key_2' IN LOWER(QUERY_TEXT)) > 0\nTHEN 'rsa_public_key_2'\nELSE NULL\nEND AS RSA_KEY_NAME\nFROM FILTERED_QUERY_HISTORY\nWHERE POSITION('rsa_public_key' IN LOWER(QUERY_TEXT)) > 0 OR\nPOSITION('rsa_public_key_2' IN LOWER(QUERY_TEXT)) > 0\n),\nRECENT_KEYS AS (\nSELECT EK.SET_TIME,\nEK.PROCESSED_USERNAME AS USERNAME,\nEK.RSA_KEY_NAME AS RSA_PUBLIC_KEY,\nROW_NUMBER() OVER (PARTITION BY ek.processed_username,\nek.rsa_key_name ORDER BY ek.set_time DESC) AS rnum\nFROM EXTRACTED_KEYS EK\nINNER JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS AU ON\nEK.PROCESSED_USERNAME = AU.NAME\nWHERE AU.DELETED_ON IS NULL\nAND AU.DISABLED = FALSE\nAND EK.RSA_KEY_NAME IS NOT NULL\n)\n-- Select the most recent RSA key name for each user\nSELECT SET_TIME,\nUSERNAME,\nRSA_PUBLIC_KEY\nFROM RECENT_KEYS\nWHERE RNUM = 1;\n2. Ensure that the query above does not return any results.\nNote: This query above is limited by the query history length that goes back to 360 days\nonly. Key pairs set more than 360 days ago will not be surfaced by this query.\nRequired privileges:\nTo run the query above, the caller needs the:\n• The SECURITY_VIEWER role on the Snowflake database.\n• The GOVERNANCE_VIEWER role on the Snowflake database.",
    "expected_response": "1. Parse the account query history and output all users and key pair names for key\n2. Ensure that the query above does not return any results.",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. For every Snowflake service account whose authentication key pair age is >=\n180 days, generate a new RSA authentication keypair.\n2. Update either RSA_PUBLIC_KEY and RSA_PUBLIC_KEY_2 properties of a user,\nwhichever is currently unset.\nALTER USER <username> SET RSA_PUBLIC_KEY_2='JERUEHtcve...';\n3. Identify all services and automation that authenticate using existing keypair and\nupdate them to authenticate using freshly generated keypair.\n4. Unset either RSA_PUBLIC_KEY or RSA_PUBLIC_KEY_2 properties of a user,\nwhichever is assigned the old public key.\nALTER USER <username> UNSET RSA_PUBLIC_KEY;\nFor more information, see Configuring Key Pair Rotation.",
    "default_value": "No authentication key pairs are rotated automatically.",
    "detection_commands": [
      "SELECT END_TIME AS SET_TIME,",
      "SELECT SET_TIME,",
      "SELECT EK.SET_TIME,"
    ],
    "remediation_commands": [
      "ALTER USER <username> SET RSA_PUBLIC_KEY_2='JERUEHtcve...';",
      "ALTER USER <username> UNSET RSA_PUBLIC_KEY;"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/key-pair-auth.html#configuring-key-",
      "pair-rotation"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 32,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5"
    ]
  },
  {
    "cis_id": "1.8",
    "title": "Ensure that users who did not log in for 90 days are disabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days_generate_a_new_rsa_authentication_keypair",
    "domain": "days, generate a new RSA authentication keypair",
    "description": "Access grants tend to accumulate over time unless explicitly set to expire. Regularly\nrevoking unused access grants and disabling inactive user accounts is a good\ncountermeasure to this dynamic.\nIf credentials of an inactive user account are leaked or stolen, it may take longer to\ndiscover the compromise.\nIn Snowflake an user account can be disabled by users with the ACCOUNTADMIN role.",
    "rationale": "Disabling inactive user accounts supports the principle of least privilege and generally\nreduces attack surface.",
    "impact": "There is a chance of disabling users or service accounts that are used consistently, but\nvery infrequently, e.g. once or twice a year. Such users should be tagged and filtered\nout in the audit query.",
    "audit": "From the UI:\n1. Go to https://app.snowflake.com/ and sign into your Snowflake account.\n2. On the left side navigation bar, click on Admin.\n3. Under Admin, click on Users & Roles.\n4. Under the Users tab, sort by LAST LOGIN.\n5. Ensure that all users whose last login is older than 90 days have STATUS set to\nDisabled.\nProgrammatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List all users in the account\nSHOW USERS;\n2. For each user, ensure that if disabled is set to false, the value of the\nlast_success_login field is less than 90 days ago.",
    "expected_response": "5. Ensure that all users whose last login is older than 90 days have STATUS set to\n2. For each user, ensure that if disabled is set to false, the value of the",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\nFor each user <user_name> that has not logged in in the last 90 days, run the following\nquery to disable their account:\nALTER USER  <user_name> SET DISABLED = true;\nIf there is a need for re-enabling an account, a user must contact one of the Snowflake\naccount administrative users.",
    "default_value": "By default Snowflake users are not disabled due to inactivity. An ACCOUNTADMIN must\nexplicitly disable an inactive user.",
    "detection_commands": [
      "SHOW USERS;"
    ],
    "remediation_commands": [
      "ALTER USER <user_name> SET DISABLED = true;"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/admin-user-",
      "management.html#disabling-enabling-a-user"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 35,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.9",
    "title": "Ensure that the idle session timeout is set to 15 minutes or less for users with the ACCOUNTADMIN and SECURITYADMIN roles",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days_generate_a_new_rsa_authentication_keypair",
    "domain": "days, generate a new RSA authentication keypair",
    "subdomain": "Disable Dormant Accounts",
    "description": "A session begins when a user connects to Snowflake and authenticates successfully\nusing a Snowflake programmatic client, Snowsight, or the classic web interface.\nA session is maintained indefinitely with continued user activity. After a period of\ninactivity in the session, known as the idle session timeout, the user must authenticate\nto Snowflake again. Session policies can be used to modify the idle session timeout\nperiod. The idle session timeout has a maximum value of four hours.",
    "rationale": "Tightening up the idle session timeout reduces sensitive data exposure risk when users\nforget to sign out of Snowflake and an unauthorized person gains access to their\ndevice.",
    "impact": "Too short idle session timeout may result in poor user experience due to users\ncontinuously being logged out of their accounts.",
    "audit": "Programmatically:\nIn the Snowsight UI or from the SnowSQL CLI:\n1. Identify all users with the ACCOUNTADMIN and SECURITYADMIN roles with session\ntimeout greater than 15 minutes or not explicitly set, thus defaulting to 240\nminutes.\n--SESSION POLICIES APPLIED TO PRIVILEGE USERS DIRECTLY\n--FIND ALL PRIVILEGED USERS\nWITH PRIV_USERS AS (\nSELECT DISTINCT GRANTEE_NAME\nFROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS\nWHERE DELETED_ON IS NULL\nAND ROLE IN ('ACCOUNTADMIN','SECURITYADMIN')\nAND DELETED_ON IS NULL\n)\n--CHECK IF THERE IS AN ACTIVE SESSION POLICY OF 15 MINUTES CREATED FOR\nUSERS\n, POLICY_REFS AS (\nSELECT *\nFROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A\nLEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.SESSION_POLICIES AS B ON A.POLICY_ID\n= B.ID\nWHERE A.POLICY_KIND = 'SESSION_POLICY'\nAND A.POLICY_STATUS = 'ACTIVE'\nAND A.REF_ENTITY_DOMAIN = 'USER'\nAND B.DELETED IS NULL\nAND B.SESSION_IDLE_TIMEOUT_MINS <= 15\n)\n--SHOW ALL PRIVILEGED USERS THAT DO NOT HAVE THE SESSION POLICY APPLIED\nSELECT A.*,\nB.POLICY_ID,\nB.POLICY_KIND,\nB.POLICY_STATUS,\nB.SESSION_IDLE_TIMEOUT_MINS\nFROM PRIV_USERS AS A\nLEFT JOIN POLICY_REFS AS B ON A.GRANTEE_NAME = B.REF_ENTITY_NAME\nWHERE B.POLICY_ID IS NULL;\n2. Ensure that the query above does not return any users.\n3. In addition to user-attached session policies, session policies can be applied at\nan account level. The following query will check if there is a satisfactory session\npolicy created at an account level, which would by default be applied to all users\n(including privileged users).\n--SESSION POLICIES APPLIED TO AT AN ACCOUNT LEVEL\nSELECT *\nFROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A\nLEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.SESSION_POLICIES AS B ON A.POLICY_ID\n= B.ID\nWHERE A.POLICY_KIND = 'SESSION_POLICY'\nAND A.POLICY_STATUS = 'ACTIVE'\nAND A.REF_ENTITY_DOMAIN = 'ACCOUNT'\nAND B.DELETED IS NULL\nAND B.SESSION_IDLE_TIMEOUT_MINS <= 15;\n4. Ensure that the query above returns a result.\nNote: Latency for the session policy view can be up to 2 hours.",
    "expected_response": "2. Ensure that the query above does not return any users.\n4. Ensure that the query above returns a result.",
    "remediation": "Programmatically:\nIn the Snowsight UI or from the SnowSQL CLI:\n1. Create the session policy if it does not exist yet. Execute the following commands\nto create and set the idle session timeout for highly privileged users in your\nSnowflake account:\nCREATE SESSION POLICY <session_policy>\nSESSION_IDLE_TIMEOUT_MINS = 15,\nSESSION_UI_IDLE_TIMEOUT_MINS = 15;\n2. Set session policy for every highly privileged user.\nALTER USER <username> SET SESSION POLICY <session_policy>;",
    "default_value": "The default value for Snowflake idle session timeout is 4 hours.",
    "detection_commands": [
      "SELECT DISTINCT GRANTEE_NAME",
      "SELECT *",
      "SELECT A.*,"
    ],
    "remediation_commands": [
      "CREATE SESSION POLICY <session_policy>",
      "ALTER USER <username> SET SESSION POLICY <session_policy>;"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/session-policies",
      "2. https://docs.snowflake.com/en/user-guide/session-policies#step-3-create-a-new-",
      "session-policy"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 38,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.10",
    "title": "Limit the number of users with ACCOUNTADMIN and SECURITYADMIN",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "description": "By default, ACCOUNTADMIN is the most powerful role in a Snowflake account. Users with\nthe SECURITYADMIN role grant can trivially escalate their privileges to that of\nACCOUNTADMIN.\nFollowing the principle of least privilege that prescribes limiting user's privileges to those\nthat are strictly required to do their jobs, the ACCOUNTADMIN and SECURITYADMIN roles\nshould be assigned to a limited number of designated users (e.g., less than 10, but at\nleast 2 to ensure that access can be recovered if one ACCOUNTAMIN user is having login\ndifficulties).",
    "rationale": "While it is important to apply the principle of least privilege to all access grants, it is\nespecially important to apply it to highly privileged roles. Examples of such roles are\nACCOUNTADMIN, SECURITYADMIN and their equivalents. The fewer users with full\nadministrator privileges, the smaller the attack surface and the probability of a full\naccount compromise.",
    "impact": "Users who lose the ACCOUNTADMIN or SECURITYADMIN role grant and are not granted a\nmore scoped down role appropriate to their job function may lose certain privileges\nrequired to do their job.",
    "audit": "From the UI:\n1. Go to https://app.snowflake.com/ and sign into your Snowflake account.\n2. On the left side navigation bar, click on Admin.\n3. Under Admin, click on Users & Roles.\n4. Ensure that a limited number of users have the ACCOUNTADMIN or SECURITYADMIN\nroles.\nProgrammatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List all the users granted the ACCOUNTADMIN or SECURITYADMIN roles:\nSELECT DISTINCT A.GRANTEE_NAME AS NAME,\nA.ROLE\nFROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS AS A\nLEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS AS B ON A.GRANTEE_NAME =\nB.NAME\nWHERE A.ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN')\nAND A.DELETED_ON IS NULL\nAND B.DELETED_ON IS NULL\nAND NOT B.DISABLED\nORDER BY A.ROLE;\n2. Ensure that the query above returns a small number of users (e.g., less than 10).\nTo ensure that access is not being lost, the number of account users should be\nat least 2.\nPrivileges required:\nTo be able to execute the query above, the caller must have the role SECURITY_VIEWER\non the Snowflake databases.",
    "expected_response": "4. Ensure that a limited number of users have the ACCOUNTADMIN or SECURITYADMIN\n2. Ensure that the query above returns a small number of users (e.g., less than 10).\nTo ensure that access is not being lost, the number of account users should be\nTo be able to execute the query above, the caller must have the role SECURITY_VIEWER",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. For each user <username> that does not need all the privileges a role provides to\nfulfill their job responsibilities, revoke the ACCOUNTADMIN or all equivalently\nprivileged roles.\nREVOKE ROLE ACCOUNTADMIN FROM USER <username>\n2. For each user <username> that does not need all the privileges a role provides to\nfulfill their job responsibilities, revoke the SECURITYADMIN or all equivalently\nprivileged roles.\nREVOKE ROLE SECURITYADMIN FROM USER <username>",
    "default_value": "By default, only the user who creates a Snowflake account is assigned the\nACCOUNTADMIN role.",
    "detection_commands": [
      "SELECT DISTINCT A.GRANTEE_NAME AS NAME,"
    ],
    "remediation_commands": [
      "REVOKE ROLE ACCOUNTADMIN FROM USER <username>",
      "REVOKE ROLE SECURITYADMIN FROM USER <username>"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-access-control-",
      "considerations.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 42,
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
    "title": "Ensure that all users granted the ACCOUNTADMIN role have an email address assigned",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "description": "Every Snowflake user can be assigned an email address. The email addresses are then\nused by Snowflake features like notification integration, resource monitor and support\ncases to deliver email notifications to Snowflake users. In trial Snowflake accounts\nthese email addresses are used for password reset functionality.\nThe email addresses assigned to ACCOUNTADMIN users are used by Snowflake to notify\nadministrators about important events related to their accounts. For example,\nACCOUNTADMIN users are notified about impending expiration of SAML2 certificates or\nSCIM access tokens.",
    "rationale": "If users with the ACCOUNTADMIN role are not assigned working email addresses that are\nbeing monitored and if SAML2 certificate used in SSO integration is not proactively\nrenewed, expiration of SAML2 certificate may break the SSO authentication flow.\nSimilarly, uncaught expiration of SCIM access token may break the SCIM integration.\nAdditionally, emails assigned to ACCOUNTADMIN users can be used by Snowflake Support\nto contact account administrators in urgent situations.",
    "impact": "None.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List users with no email address set:\nSELECT DISTINCT a.grantee_name as name, b.email\nFROM snowflake.account_usage.grants_to_users AS a\nLEFT JOIN snowflake.account_usage.users AS b\nON a.grantee_name = b.name\nWHERE a.role = 'ACCOUNTADMIN'\nAND a.deleted_on IS NULL\nAND b.email IS NULL\nAND b.deleted_on IS NULL\nAND NOT b.disabled;\n2. Ensure that the query above does not return any results.\nRequired privileges:\nTo be able to execute the above audit query, the caller must have the SECURITY_VIEWER\nrole on the SNOWFLAKE database.",
    "expected_response": "2. Ensure that the query above does not return any results.\nTo be able to execute the above audit query, the caller must have the SECURITY_VIEWER",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. For every ACCOUNTADMIN user <username> that does not have email assigned run\nthe following command to assign it:\nALTER USER <username>\nSET EMAIL = <email_address>;",
    "default_value": "The trial account creation form requires an email address. The first user of a newly\ncreated trial account is assigned that email address by default. All other users created in\na Snowflake account must be assigned email addresses explicitly.",
    "detection_commands": [
      "SELECT DISTINCT a.grantee_name as name, b.email"
    ],
    "remediation_commands": [
      "ALTER USER <username>"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/admin-user-",
      "management.html#resetting-the-password-for-an-administrator"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 45,
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
    "cis_id": "1.12",
    "title": "Ensure that no users have ACCOUNTADMIN or SECURITYADMIN as the default role",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "description": "The ACCOUNTADMIN system role is the most powerful role in a Snowflake account\nand is intended for performing initial setup and managing account-level objects.\nSECURITYADMIN role can trivially escalate their privileges to that of ACCOUNTADMIN. Neither\nof these roles should be used for performing daily non-administrative tasks in a\nSnowflake account.\nInstead, users should be assigned custom roles containing only those privileges that are\nnecessary for successfully completing their job responsibilities.",
    "rationale": "When ACCOUNTADMIN is not set as a default user role, it forces account\nadministrators to explicitly change their role to ACCOUNTADMIN each time they log in. This\ncan help make account administrators aware of the purpose of roles in the system,\nprevent them from inadvertently using the ACCOUNTADMIN role for non-administrative\ntasks, and encourage them to change to the appropriate role for a given task. Same\nlogic applies to the SECURITYADMIN role.",
    "impact": "None.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List users with ACCOUNTADMIN or SECURITYADMIN as the default role:\nSELECT NAME, DEFAULT_ROLE\nFROM SNOWFLAKE.ACCOUNT_USAGE.USERS\nWHERE DEFAULT_ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN')\nAND DELETED_ON IS NULL\nAND NOT DISABLED;\n2. Ensure that the query above does not return any users.\nRequired privileges:\nRunning the query above requires the security_viewer role on the Snowflake database",
    "expected_response": "2. Ensure that the query above does not return any users.",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. For each user <user_name> who has ACCOUNTADMIN or SECURITYADMIN as their\ndefault role, choose a less privileged role <job_appropriate_role> appropriate\nfor their daily job responsibilities and run the following query:\nALTER USER <user_name>\nSET DEFAULT_ROLE = <job_appropriate_role>;\nNote: You could also unset the default role, thus forcing users to explicitly\nassume a role every time they log in.",
    "default_value": "By default, only the user who creates a Snowflake account is assigned the\nACCOUNTADMIN role as the default role.",
    "detection_commands": [
      "SELECT NAME, DEFAULT_ROLE"
    ],
    "remediation_commands": [
      "ALTER USER <user_name>"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-access-control-configure.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 48,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.13",
    "title": "Ensure that the ACCOUNTADMIN or SECURITYADMIN role is not granted to any custom role",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "The principle of least privilege requires that every identity is only given privileges that\nare necessary to complete its tasks.\nThe ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is\nintended for performing initial setup and managing account-level objects. SECURITYADMIN\nrole can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles\nshould be used for performing daily non-administrative tasks in a Snowflake account.",
    "rationale": "Granting ACCOUNTADMIN role to any custom role effectively elevates privileges of that\nrole to the ACCOUNTADMIN role privileges. Roles that include the ACCOUNTADMIN role can\nthen be mistakenly used in access grants that do not require ACCOUNTADMIN privileges\nthus violating the principle of least privilege and increasing the attack surface. The same\nlogic applies to the SECURITYADMIN role.",
    "impact": "Users who lose the ACCOUNTADMIN or SECURITYADMIN privileges granted to them indirectly\nthrough a custom role may not be able to perform their job duties until they regain\nprivileges they legitimately require through a more scoped down role.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List all custom roles granted ACCOUNTADMIN or SECURITYADMIN:\nSELECT GRANTEE_NAME AS CUSTOM_ROLE,\nPRIVILEGE AS GRANTED_PRIVILEGE,\nNAME AS GRANTED_ROLE\nFROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES\nWHERE GRANTED_ON = 'ROLE'\nAND NAME IN ('ACCOUNTADMIN','SECURITYADMIN')\nAND DELETED_ON IS NULL;\n2. Ensure that the query above returns only one row where the CUSTOM_ROLE is\nACCOUNTADMIN, GRANTED_PRIVILEGE is SECURITYADMIN and GRANTED_ROLE is USAGE.\nRequired privileges:\nThe query requires the SECURITY_VIEWER role on the Snowflake database.",
    "expected_response": "2. Ensure that the query above returns only one row where the CUSTOM_ROLE is",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI, find all custom roles that are\ngranted ACCOUNTADMIN role and revoke that grant.\nREVOKE SECURITYADMIN ON ACCOUNT FROM ROLE <custom_role>;\nREVOKE ACCOUNTADMIN ON ACCOUNT FROM ROLE <custom_role>;",
    "default_value": "By default no custom roles are granted the ACCOUNTADMIN role.",
    "detection_commands": [
      "SELECT GRANTEE_NAME AS CUSTOM_ROLE,"
    ],
    "remediation_commands": [
      "REVOKE SECURITYADMIN ON ACCOUNT FROM ROLE <custom_role>; REVOKE ACCOUNTADMIN ON ACCOUNT FROM ROLE <custom_role>;"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-access-control-configure.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 51,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.14",
    "title": "Ensure that Snowflake tasks are not owned by the ACCOUNTADMIN or SECURITYADMIN roles",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "The ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is\nintended for performing initial setup and managing account-level objects. SECURITYADMIN\nrole can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles\nshould be used for running Snowflake tasks. A task should be running using a custom\nrole containing only those privileges that are necessary for successful execution of the\ntask.\nSnowflake executes tasks with the privileges of the task owner. The role that has\nOWNERSHIP privilege on the task owns the task.\nTo avoid granting a task inappropriate privileges, the OWNERSHIP privilege on the task run\nas owner should be assigned to a custom role containing only those privileges that are\nnecessary for successful execution of the task.",
    "rationale": "The principle of least privilege requires that every identity, including service identities, is\nonly given privileges that are necessary to complete its job.\nIf a threat actor finds a way to influence or hijack the task execution flow, they may be\nable to exploit privileges given to the task. In the case of an ACCOUNTADMIN or\nSECURITYADMIN roles, that may lead to a full account takeover. Additionally, a mistake in\nthe task implementation coupled with excessive privileges may lead to a reliability\nincident, e.g. accidentally dropping database objects.",
    "impact": "Existing stored procedures that are owned by the ACCOUNTADMIN or SECURITYADMIN roles\nand run with their privileges will need to be updated to use a task specific custom role. If\nthat role does not have all the privileges required by the task, the task execution may\nfail.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List all tasks owned by the ACCOUNTADMIN or SECURITYADMIN roles:\nSELECT NAME AS STORED_PROCEDURE_NAME,\nGRANTED_TO,\nGRANTEE_NAME AS ROLE_NAME,\nPRIVILEGE\nFROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES\nWHERE GRANTED_ON = 'TASK'\nAND DELETED_ON IS NULL\nAND GRANTED_TO = 'ROLE'\nAND PRIVILEGE = 'OWNERSHIP'\nAND GRANTEE_NAME IN ('ACCOUNTADMIN' , 'SECURITYADMIN');\n2. Ensure that the query above does not return any results.",
    "expected_response": "2. Ensure that the query above does not return any results.",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. For each task <task_name> that runs with ACCOUNTADMIN or SECURITYADMIN\nprivileges, create a new role <task_specific_role> and assign it to the tasks:\nCREATE ROLE <task_specific_role>;\nGRANT OWNERSHIP ON TASK <task_name> TO ROLE <task_specific_role>;\n2. After creating a new role and granting ownership of each task to it, for each task\n<task_name> that is owned by ACCOUNTADMIN or SECURITYADMIN roles, ensure all\nprivileges on the tasks are revoked from the roles:\nREVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE ACCOUNTADMIN;\nREVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE SECURITYADMIN;",
    "default_value": "By default new tasks are granted permissions of the role that was used to create them.",
    "detection_commands": [
      "SELECT NAME AS STORED_PROCEDURE_NAME,"
    ],
    "remediation_commands": [
      "CREATE ROLE <task_specific_role>; GRANT OWNERSHIP ON TASK <task_name> TO ROLE <task_specific_role>;",
      "REVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE ACCOUNTADMIN; REVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE SECURITYADMIN;"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-access-control-",
      "considerations.html",
      "2. https://docs.snowflake.com/en/user-guide/security-access-control-configure.html",
      "3. https://docs.snowflake.com/en/user-guide/tasks-intro.html#task-security"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 54,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.15",
    "title": "Ensure that Snowflake tasks do not run with the ACCOUNTADMIN or SECURITYADMIN role privileges",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "The ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is\nintended for performing initial setup and managing account-level objects. SECURITYADMIN\nrole can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles\nshould be used for running Snowflake tasks. A task should be running using a custom\nrole containing only those privileges that are necessary for successful execution of the\ntask.",
    "rationale": "The principle of least privilege requires that every identity, including service identities, is\nonly given privileges that are necessary to complete its job.\nIf a threat actor finds a way to influence or hijack the task execution flow, they may be\nable to exploit privileges given to the task. In the case of an ACCOUNTADMIN or\nSECURITYADMIN roles, that may lead to a full account takeover. Additionally, a mistake in\nthe task implementation coupled with excessive privileges may lead to a reliability\nincident, e.g. accidentally dropping database objects.",
    "impact": "Existing stored procedures that are owned by the ACCOUNTADMIN or SECURITYADMIN roles\nand run with their privileges will need to be updated to use a task specific custom role. If\nthat role does not have all the privileges required by the task, the task execution may\nfail.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List all tasks that have privileges granted to ACCOUNTADMIN or SECURITYADMIN\nroles:\nSELECT NAME AS STORED_PROCEDURE_NAME,\nGRANTED_TO,\nGRANTEE_NAME AS ROLE_NAME,\nPRIVILEGE\nFROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES\nWHERE GRANTED_ON = 'TASK'\nAND DELETED_ON IS NULL\nAND GRANTED_TO = 'ROLE'\nAND GRANTEE_NAME IN ('ACCOUNTADMIN' , 'SECURITYADMIN');\n2. Ensure that the query above does not return any results.",
    "expected_response": "2. Ensure that the query above does not return any results.",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. For each task <task_name> that runs with ACCOUNTADMIN or SECURITYADMIN\nprivileges, create a new role <task_specific_role> and assign it to the tasks:\nCREATE ROLE <task_specific_role>;\nGRANT OWNERSHIP ON TASK <task_name> TO ROLE <task_specific_role>;\n2. After creating a new role and granting privileges to each task, ensure all\nprivileges on the tasks are revoked from the ACCOUNTADMIN and SECURITYADMIN\nroles:\nREVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE ACCOUNTADMIN;\nREVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE SECURITYADMIN;",
    "default_value": "By default new tasks are granted permissions of the role that was used to create them.",
    "detection_commands": [
      "SELECT NAME AS STORED_PROCEDURE_NAME,"
    ],
    "remediation_commands": [
      "CREATE ROLE <task_specific_role>; GRANT OWNERSHIP ON TASK <task_name> TO ROLE <task_specific_role>;",
      "REVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE ACCOUNTADMIN; REVOKE ALL PRIVILEGES ON TASK <task_name> FROM ROLE SECURITYADMIN;"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-access-control-",
      "considerations.html",
      "2. https://docs.snowflake.com/en/user-guide/security-access-control-configure.html",
      "3. https://docs.snowflake.com/en/user-guide/tasks-intro.html#task-security"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 57,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.16",
    "title": "Ensure that Snowflake stored procedures are not owned by the ACCOUNTADMIN or SECURITYADMIN roles",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "The ACCOUNTADMIN system role is the most powerful role in a Snowflake account and is\nintended for performing initial setup and managing account-level objects. SECURITYADMIN\nrole can trivially escalate their privileges to that of ACCOUNTADMIN. Neither of these roles\nshould be used for running Snowflake stored procedures. A stored procedure should be\nrunning using a custom role containing only those privileges that are necessary for\nsuccessful execution of the stored procedure.\nSnowflake executes stored procedures with the privileges of the stored procedure\nowner or the caller. Role that has OWNERSHIP privilege on the stored procedure owns it.\nTo avoid granting a stored procedure inappropriate privileges, the OWNERSHIP privilege\non the stored procedure run as owner should be assigned to a custom role containing\nonly those privileges that are necessary for successful execution of the stored\nprocedure.",
    "rationale": "The principle of least privilege requires that every identity, including service identities, is\nonly given privileges that are necessary to complete its job.\nIf a threat actor finds a way to influence or hijack the stored procedure execution flow,\nthey may be able to exploit privileges given to the stored procedure. In the case of an\nACCOUNTADMIN or SECURITYADMIN roles, that may lead to a full account takeover.\nAdditionally, a mistake in the stored procedure implementation coupled with excessive\nprivileges may lead to a reliability incident, e.g. accidentally dropping database objects.",
    "impact": "Existing stored procedures that are owned by the ACCOUNTADMIN or SECURITYADMIN roles\nand run with their privileges will need to be updated to use a stored procedure specific\ncustom role. If that role does not have all the privileges required by the stored\nprocedure, the stored procedure execution may fail.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Find all stored procedures that are owned by the ACCOUNTADMIN or SECURITYADMIN\nroles.\nSELECT *\nFROM SNOWFLAKE.ACCOUNT_USAGE.PROCEDURES\nWHERE DELETED IS NULL\nAND PROCEDURE_OWNER IN ('ACCOUNTADMIN','SECURITYADMIN');\n2. Ensure that the query above does not return any results.",
    "expected_response": "2. Ensure that the query above does not return any results.",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. For each stored procedure <procedure_name> that runs with ACCOUNTADMIN or\nSECURITYADMIN privileges, create a new role <procedure_specific_role> and\nassign it to the stored procedure:\nCREATE ROLE <procedure_specific_role>;\nGRANT OWNERSHIP ON PROCEDURE <procedure_name> TO ROLE\n<procedure_specific_role>;\n2. After creating a new role and granting ownership of each stored procedure to it,\nfor each stored procedure that is owned by ACCOUNTADMIN or SECURITYADMIN roles,\nensure all privileges on the stored procedure are revoked from the roles:\nREVOKE ALL PRIVILEGES ON PROCEDURE <procedure_name> FROM ROLE\nACCOUNTADMIN;\nREVOKE ALL PRIVILEGES ON PROCEDURE <procedure_name> FROM ROLE\nSECURITYADMIN;",
    "default_value": "By default stored procedures that run as owner are granted permissions of the role that\nwas used to create them.",
    "detection_commands": [
      "SELECT *"
    ],
    "remediation_commands": [
      "CREATE ROLE <procedure_specific_role>; GRANT OWNERSHIP ON PROCEDURE <procedure_name> TO ROLE",
      "REVOKE ALL PRIVILEGES ON PROCEDURE <procedure_name> FROM ROLE"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-access-control-",
      "considerations.html",
      "2. https://docs.snowflake.com/en/user-guide/security-access-control-configure.html",
      "3. https://docs.snowflake.com/en/sql-reference/stored-procedures-rights"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 60,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.17",
    "title": "Ensure Snowflake stored procedures do not run with ACCOUNTADMIN or SECURITYADMIN role privileges",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "minutes_for_mobile_end_user_devices_the_period_must_not_exceed_2_minutes",
    "domain": "minutes. For mobile end-user devices, the period must not exceed 2 minutes",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "The ACCOUNTADMIN system role is the most powerful role in a Snowflake account; it is\nintended for performing initial setup and managing account-level objects. Users and\nstored procedures with the SECURITYADMIN role can escalate their privileges to\nACCOUNTADMIN.\nSnowflake stored procedures should not run with the ACCOUNTADMIN or SECURITYADMIN\nroles. Instead, stored procedures should be run using a custom role containing only\nthose privileges that are necessary for successful execution of the stored procedure.",
    "rationale": "The principle of least privilege requires that every identity, including service identities, is\nonly given privileges that are necessary to complete its job.\nIf a threat actor finds a way to influence or hijack the stored procedure execution flow,\nthey may be able to exploit privileges given to the stored procedure. In the case of an\nACCOUNTADMIN or SECURITYADMIN roles, that may lead to a full account takeover.\nAdditionally, a mistake in the stored procedure implementation coupled with excessive\nprivileges may lead to a reliability incident, e.g. accidentally dropping database objects.",
    "impact": "Existing stored procedures that are owned by the ACCOUNTADMIN or\nSECURITYADMIN roles and run with their privileges will need to be updated to use a\nstored procedure specific custom role. If that role does not have all the privileges\nrequired by the stored procedure, the stored procedure execution may fail.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or using the SnowSQL CLI:\n1. Find the list of stored procedures that run with ACCOUNTADMIN or SECURITYADMIN\nrole privileges:\nSELECT NAME AS STORED_PROCEDURE_NAME,\nGRANTED_TO,\nGRANTEE_NAME AS ROLE_NAME\nFROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES\nWHERE GRANTED_ON = 'PROCEDURE'\nAND DELETED_ON IS NULL\nAND GRANTED_TO = 'ROLE'\nAND GRANTEE_NAME IN ('ACCOUNTADMIN' , 'SECURITYADMIN');\n2. Ensure that the query above does not return any results.",
    "expected_response": "2. Ensure that the query above does not return any results.",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or using the SnowSQL CLI:\n1. For each stored procedure <procedure_name> that runs with ACCOUNTADMIN or\nSECURITYADMIN privileges, create a new role <procedure_specific_role> and\nassign it to the stored procedure:\nCREATE ROLE <procedure_specific_role>;\nGRANT OWNERSHIP ON PROCEDURE <procedure_name> TO ROLE\n<procedure_specific_role>;\n2. After creating a new role and granting privileges to each stored procedure,\nensure all privileges on the stored procedure <procedure_name> are revoked from\nthe ACCOUNTADMIN and SECURITYADMIN roles:\nREVOKE ALL PRIVILEGES ON PROCEDURE <procedure_name> FROM ROLE\nACCOUNTADMIN;\nREVOKE ALL PRIVILEGES ON PROCEDURE <procedure_name> FROM ROLE\nSECURITYADMIN;",
    "default_value": "By default stored procedures that run as owner are granted permissions of the role that\nwas used to create them.",
    "detection_commands": [
      "SELECT NAME AS STORED_PROCEDURE_NAME,"
    ],
    "remediation_commands": [
      "CREATE ROLE <procedure_specific_role>; GRANT OWNERSHIP ON PROCEDURE <procedure_name> TO ROLE",
      "REVOKE ALL PRIVILEGES ON PROCEDURE <procedure_name> FROM ROLE"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-access-control-",
      "considerations.html",
      "2. https://docs.snowflake.com/en/user-guide/security-access-control-configure.html",
      "3. https://docs.snowflake.com/en/sql-reference/stored-procedures-rights"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 63,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "2.1",
    "title": "Ensure monitoring and alerting exist for ACCOUNTADMIN and SECURITYADMIN role grants",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "monitoring_alerting",
    "domain": "Monitoring and Alerting",
    "description": "By default, ACCOUNTADMIN is the most powerful role in a Snowflake account and users\nwith SECURITYADMIN role grant can trivially escalate their privileges to that of\nACCOUNTADMIN.\nFollowing the principle of least privilege that prescribes limiting user's privileges to those\nthat are strictly required to do their jobs, the ACCOUNTADMIN and SECURITYADMIN roles\nshould be assigned to a limited number of designated users. Any new ACCOUNTADMIN\nand SECURITYADMIN role grants should be scrutinized.",
    "rationale": "Every new ACCOUNTADMIN and SECURITYADMIN role assignment increases the attack\nsurface of a Snowflake environment. It may also indicate unauthorized privilege\nescalation performed by a threat actor.\nIf monitoring for ACCOUNTADMIN role assignments is not configured, inappropriate or\nunauthorized ACCOUNTADMIN role access grants may be missed. The latter can lead to\neventual security posture degradation or late detection of an ongoing security incident.\nThe same logic applies to the SECURITYADMIN role.",
    "impact": "If the principle of least privilege is not strictly applied and ACCOUNTADMIN and\nSECURITYADMIN role assignments happen frequently, monitoring and alerting on this\nevent may generate undue load on the detection and response team.",
    "audit": "Confirm that your security monitoring and alerting solution is configured to generate\nalerts on new ACCOUNTADMIN and SECURITYADMIN role assignments.",
    "expected_response": "Confirm that your security monitoring and alerting solution is configured to generate",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Configure your monitoring task to alert on ACCOUNTADMIN and SECURITYADMIN role\ngrants. You can find those grants with the following query:\nSELECT *\nFROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES\nWHERE NAME IN ('ACCOUNTADMIN', 'SECURITYADMIN');",
    "default_value": "There is no ACCOUNTADMIN or SECURITYADMIN role assignment event monitoring and\nalerting by default.",
    "detection_commands": [],
    "remediation_commands": [
      "SELECT *"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/ui-snowsight-activity.html",
      "2. https://docs.snowflake.com/en/user-guide/security-access-control-",
      "considerations.html",
      "3. https://docs.snowflake.com/en/sql-reference/sql/create-notification-integration",
      "4. https://docs.snowflake.com/en/sql-reference/sql/create-task;",
      "5. https://docs.snowflake.com/en/user-guide/email-stored-procedures"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 67,
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
    "cis_id": "2.2",
    "title": "Ensure monitoring and alerting exist for MANAGE GRANTS privilege grants",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "monitoring_alerting",
    "domain": "Monitoring and Alerting",
    "subdomain": "Conduct Audit Log Reviews",
    "description": "The MANAGE GRANTS privilege is one of the most powerful privileges in the Snowflake\nenvironment. This privilege gives the ability to grant or revoke privileges on any object\nas if the invoking role were the owner of the object.\nA custom role with the MANAGE GRANTS privilege on account level will not be able to grant\nprivileges on the account level as that privilege is implicitly reserved for the\nACCOUNTADMIN and SECURITYADMIN roles. However, such custom roles will be able to\ngrant any privileges on any objects below the account level.\nFollowing the principle of least privilege and given how powerful the MANAGE GRANTS\nprivilege is, any new MANAGE GRANTS privilege grants should be scrutinized.",
    "rationale": "Every new role granted the MANAGE GRANTS privilege increases the attack surface of a\nSnowflake environment. It may also indicate unauthorized privilege escalation\nperformed by a threat actor.\nIf monitoring for MANAGE GRANTS privilege grants is not configured, inappropriate or\nunauthorized MANAGE GRANTS privilege grants may be missed. The latter can lead to\neventual security posture degradation or late detection of an ongoing security incident.",
    "impact": "If MANAGE GRANTS privilege grants happen frequently, monitoring and alerting on this\nevent may generate undue load on the detection and response team.",
    "audit": "Confirm that your security monitoring and alerting solution is configured to generate\nalerts on new MANAGE GRANTS privilege grants.",
    "expected_response": "Confirm that your security monitoring and alerting solution is configured to generate",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Configure your monitoring task to alert on manage grants privilege grants.\nselect end_time, query_type\nquery_text,\nuser_name,\nrole_name\nfrom snowflake.account_usage.query_history\nwhere execution_status = 'SUCCESS'\nand query_type = 'GRANT'\nand regexp_instr(query_text, 'manage\\\\s*grants', 1, 1, 0, 'i') > 0\norder by end_time desc;",
    "default_value": "There is no MANAGE GRANTS privilege grant event monitoring and alerting set up by\ndefault.",
    "detection_commands": [],
    "remediation_commands": [
      "select end_time, query_type"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/ui-snowsight-activity.html",
      "2. https://docs.snowflake.com/en/user-guide/security-access-control-privileges.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 69,
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
    "cis_id": "2.3",
    "title": "Ensure monitoring and alerting exist for password sign-ins of SSO users",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "monitoring_alerting",
    "domain": "Monitoring and Alerting",
    "subdomain": "Conduct Audit Log Reviews",
    "description": "The security benefit of SSO is to relieve users from having to set up and manage\ndistinct sets of credentials for distinct applications and services. It also allows security\nadministrators to focus on hardening and defending only one identity storage and\nlimited number of user credentials.",
    "rationale": "Allowing users to sign in with Snowflake passwords in the presence of a configured\nthird-party identity provider SSO may undermine mandatory security controls configured\non the SSO and degrade security posture of the account. For example, the SSO sign-in\nflow may be configured to require multi-factor authentication (MFA), where Snowflake\npassword sign-in flow may not.\nEvery Snowflake password-based sign-in may indicate an unapproved authentication\nflow taking place.",
    "impact": "If password sign-in events happen frequently, monitoring and alerting on this event may\ngenerate undue load on the detection and response team.",
    "audit": "Confirm that your security monitoring and alerting solution is configured to generate\nalerts on new password sign-in events.",
    "expected_response": "Confirm that your security monitoring and alerting solution is configured to generate",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Configure your security monitoring solution to alert on password sign-ins of SSO\nusers. The following query can be run periodically.\nselect event_timestamp,\nuser_name,\nclient_ip,\nreported_client_type,\nreported_client_version,\nfirst_authentication_factor,\nsecond_authentication_factor\nfrom snowflake.account_usage.login_history\nwhere first_authentication_factor = 'PASSWORD'\norder by event_timestamp desc;",
    "default_value": "There is no password sign-in event monitoring and alerting by default.",
    "detection_commands": [],
    "remediation_commands": [
      "select event_timestamp,"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/ui-snowsight-activity.html",
      "2. https://docs.snowflake.com/en/user-guide/admin-security-fed-auth.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 71,
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
    "cis_id": "2.4",
    "title": "Ensure monitoring and alerting exist for password sign-in without MFA",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "monitoring_alerting",
    "domain": "Monitoring and Alerting",
    "subdomain": "Conduct Audit Log Reviews",
    "description": "Multi-factor authentication (MFA) is a security control used to add an additional layer of\nlogin security. It works by requiring the user to present two or more proofs (factors) of\nuser identity. An MFA example would be requiring a password and a verification code\ndelivered to the user's phone during user sign-in.\nThe MFA feature for Snowflake users is powered by the Duo Security service.",
    "rationale": "MFA mitigates security threats of users creating weak passwords and user passwords\nbeing stolen or accidentally leaked.",
    "impact": "If password sign-in events without MFA happen frequently, monitoring and alerting on\nthis event may generate undue load on the detection and response team.",
    "audit": "Confirm that your security monitoring and alerting solution is configured to generate\nalerts on new password sign-in without MFA events.",
    "expected_response": "Confirm that your security monitoring and alerting solution is configured to generate",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Configure your security monitoring solution to alert on password sign-ins without\nMFA. The following query can be run periodically.\nselect event_timestamp,\nuser_name,\nclient_ip,\nreported_client_type,\nreported_client_version,\nfirst_authentication_factor,\nsecond_authentication_factor\nfrom snowflake.account_usage.login_history\nwhere first_authentication_factor = 'PASSWORD'\nand second_authentication_factor is null\norder by event_timestamp desc;",
    "default_value": "There is no password sign-in without MFA event monitoring and alerting by default.",
    "detection_commands": [],
    "remediation_commands": [
      "select event_timestamp,"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-access-control-configure.html",
      "2. https://docs.snowflake.com/en/user-guide/security-mfa.html",
      "3. https://docs.snowflake.com/en/user-guide/ui-snowsight-activity.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 73,
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
    "cis_id": "2.5",
    "title": "Ensure monitoring and alerting exist for creation, update and deletion of security integrations",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "monitoring_alerting",
    "domain": "Monitoring and Alerting",
    "subdomain": "Conduct Audit Log Reviews",
    "description": "Security integration object is used to configure SSO and SCIM integrations.",
    "rationale": "Creation of an unauthorized security integration, in case of SCIM, can lead to creation\nof rogue Snowflake users. Incase of SSO, it can lead to hijacking of existing Snowflake\nusers through rogue authentication flow.\nUpdate or deletion of an existing security integration can lead to weakening security\nposture of that integration or denial of service, e.g. when users cannot sign into\nSnowflake accounts due to broken SSO authentication flow.",
    "impact": "If security integration creation, update and deletion events happen frequently,\nmonitoring and alerting on this event may generate undue load on the detection and\nresponse team.",
    "audit": "Confirm that your security monitoring and alerting solution is configured to generate\nalerts on new security integration creation, update and deletion events.",
    "expected_response": "Confirm that your security monitoring and alerting solution is configured to generate",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Configure your security monitoring solution to alert on creation, update and\ndeletion of security integrations.\nselect end_time,\nquery_type,\nquery_text,\nuser_name,\nrole_name\nfrom snowflake.account_usage.query_history\nwhere execution_status = 'SUCCESS'\nand query_type in ('CREATE', 'ALTER', 'DROP')\nand query_text ilike '%security integration%'\norder by end_time desc;",
    "default_value": "There is no security integration creation, update and deletion event monitoring and\nalerting by default.",
    "detection_commands": [],
    "remediation_commands": [
      "select end_time,"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/sql-reference/sql/create-security-integration.html",
      "2. https://docs.snowflake.com/en/user-guide/ui-snowsight-activity.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 75,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.6",
    "title": "Ensure monitoring and alerting exist for changes to network policies and associated objects",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "monitoring_alerting",
    "domain": "Monitoring and Alerting",
    "subdomain": "Conduct Audit Log Reviews",
    "description": "Network policies allow restricting access to a Snowflake account based on source IP\naddresses. A network policy can be configured either on the account level, for all users\nof the account, or on the user level, for a specific user. In the presence of both account-\nlevel and user-level policies the latter takes precedence.\nA network policy can also be configured on the SCIM and Snowflake OAuth security\nintegrations to restrict the list of source IP addresses allowed when exchanging an\nauthorization code for an access or refresh token and when using a refresh token to\nobtain a new access token. If network policy is not set on the security integration of the\naforementioned types, the account-level network policy, if any, is used.",
    "rationale": "Creation and application of unauthorized network policies can weaken access control\nthrough expansion of the allowed source IP addresses, or lead to a denial of service\nthrough blocklisting legitimate source IP addresses. Unauthorized changes and\ndeletions of existing network policies can lead to the same undesirable results.",
    "impact": "If network policy creation, update, deletion and object association events happen\nfrequently, monitoring and alerting on this event may generate undue load on the\ndetection and response team.",
    "audit": "Confirm that your security monitoring and alerting solution is configured to generate\nalerts on new security integration creation, update and deletion events.",
    "expected_response": "Confirm that your security monitoring and alerting solution is configured to generate",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Configure your security monitoring solution to alert on changes to network\npolicies.\nselect end_time,\nquery_type,\nquery_text,\nuser_name,\nrole_name\nfrom snowflake.account_usage.query_history\nwhere execution_status = 'SUCCESS'\nand (\nquery_type in ('CREATE_NETWORK_POLICY', 'ALTER_NETWORK_POLICY',\n'DROP_NETWORK_POLICY')\nor (query_text ilike '%set%network_policy%'\nor query_text ilike '%unset%network_policy%')\n)\norder by end_time desc;",
    "default_value": "There is no network policy creation, update, deletion or object association event\nmonitoring and alerting by default.",
    "detection_commands": [],
    "remediation_commands": [
      "select end_time,"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/network-policies.html",
      "2. https://docs.snowflake.com/en/sql-reference/sql/create-security-integration-",
      "oauth-snowflake.html",
      "3. https://docs.snowflake.com/en/sql-reference/sql/create-security-integration-",
      "scim.html",
      "4. https://docs.snowflake.com/en/user-guide/scim-custom.html#limitations",
      "5. https://docs.snowflake.com/en/user-guide/ui-snowsight-activity.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 77,
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
    "title": "Ensure monitoring and alerting exist for SCIM token creation",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "monitoring_alerting",
    "domain": "Monitoring and Alerting",
    "subdomain": "Conduct Audit Log Reviews",
    "description": "The System for Cross-domain Identity Management (SCIM) is an open specification\ndesigned to help facilitate the automated management of user identities and groups (i.e.\nroles) in cloud applications using RESTful APIs.\nSnowflake supports SCIM 2.0 integration with Okta, Microsoft Azure AD and custom\nidentity providers. Users and groups from the identity provider can be provisioned into\nSnowflake, which functions as the service provider.\nSCIM access token is a bearer token used by SCIM clients to authenticate to Snowflake\nSCIM server.",
    "rationale": "SCIM access tokens generated without proper authorization may be used for\nconfiguring rogue SCIM integrations. Such SCIM integrations can then be used for\nprovisioning rogue users that through existing roles are granted unauthorized access to\nSnowflake data and other objects.",
    "impact": "If SCIM access token creation events happen frequently, monitoring and alerting on this\nevent may generate undue load on the detection and response team. That said, a SCIM\naccess token is valid for 6 months and there is usually only one SCIM integration per\naccount. Frequent SCIM access token creation would likely be an unusual event.",
    "audit": "Confirm that your security monitoring and alerting solution is configured to generate\nalerts on new security SCIM access token events.",
    "expected_response": "Confirm that your security monitoring and alerting solution is configured to generate",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Configure your security monitoring solution to alert on SCIM token creation. The\nfollowing query can be run periodically.\nselect end_time,\nquery_type,\nquery_text,\nuser_name,\nrole_name\nfrom snowflake.account_usage.query_history\nwhere execution_status = 'SUCCESS'\nand query_type = 'SELECT'\nand regexp_instr(query_text,\n'system\\\\$generate_scim_access_token\\\\s*\\\\(', 1, 1, 0, 'i') > 0\norder by end_time desc;",
    "default_value": "There is no SCIM access token creation event monitoring and alerting by default.",
    "detection_commands": [],
    "remediation_commands": [
      "select end_time,"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/scim-intro.html#scim-overview",
      "2. https://docs.snowflake.com/en/user-guide/scim-custom.html#create-a-custom-",
      "scim-security-integration-and-api-token",
      "3. https://docs.snowflake.com/en/user-guide/ui-snowsight-activity.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 79,
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
    "cis_id": "2.8",
    "title": "Ensure monitoring and alerting exists for new share exposures",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "monitoring_alerting",
    "domain": "Monitoring and Alerting",
    "subdomain": "Conduct Audit Log Reviews",
    "description": "Snowflake tables, views and UDFs can be shared across Snowflake accounts using\nshare objects created by data providers and imported by data consumers.\nTo expose a share to another account, the share provider account needs to add or set\nconsumer accounts on a share using the ALTER SHARE command. The consumer\naccount can then import the share using the CREATE DATABASE FROM SHARE command.",
    "rationale": "A share exposed to another Snowflake account can be used for data exfiltration.",
    "impact": "If exposing shares to another account event happens frequently, monitoring and alerting\non this event may generate undue load on the detection and response team.",
    "audit": "Confirm that your security monitoring and alerting solution is configured to generate\nalerts on new share exposures.",
    "expected_response": "Confirm that your security monitoring and alerting solution is configured to generate",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Configure your security monitoring solution to alert on new share exposures. The\nfollowing query can be run periodically.\nselect end_time,\nquery_type,\nquery_text,\nuser_name,\nrole_name\nfrom snowflake.account_usage.query_history\nwhere execution_status = 'SUCCESS'\nand query_type = 'ALTER'\nand regexp_instr(query_text,\n'^alter\\\\s*share.*(add|set)\\\\s*accounts\\\\s*=', 1, 1, 0, 'is') > 0\norder by end_time desc;",
    "default_value": "There is no share exposure event monitoring and alerting by default.",
    "detection_commands": [],
    "remediation_commands": [
      "select end_time,"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/data-sharing-intro",
      "2. https://docs.snowflake.com/en/sql-reference/sql/alter-share"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 81,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.9",
    "title": "Ensure monitoring and alerting exists for sessions from unsupported Snowflake Connector for Python and JDBC and ODBC drivers",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "monitoring_alerting",
    "domain": "Monitoring and Alerting",
    "subdomain": "Conduct Audit Log Reviews",
    "description": "Snowflake provides client software (drivers, connectors, etc.) for connecting to\nSnowflake and using certain Snowflake features (e.g. Apache Kafka for loading data,\nApache Hive metadata for external tables). The clients must be installed on each local\nworkstation or system from which you wish to connect. The Snowflake Connector for\nPython, JDBC and ODBC drivers are some of the most used Snowflake clients.\nOld versions of drivers and connectors may contain security vulnerabilities that have\nbeen fixed in the latest version. To ensure that only up-to-date software is used, you\nshould actively monitor session logins coming from unsupported clients and upgrade\nthose to the latest available versions.",
    "rationale": "Using out-of-date Snowflake clients can expose your account to security risks. You\nshould monitor for connections from unsupported Snowflake Connector for Python and\nJDBC and ODBC drivers and upgrade to the latest versions available.",
    "impact": "None.",
    "audit": "Confirm that your security monitoring and alerting solution is configured to generate\nalerts on sessions coming from unsupported Snowflake connectors and drivers.",
    "expected_response": "Confirm that your security monitoring and alerting solution is configured to generate",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Check the Recommended Client Versions documentation and note the minimum\nversions of the Snowflake Connector for Python, JDBC driver and ODBC driver.\n2. Create a UDF to help you compare version numbers:\nCREATE OR REPLACE FUNCTION compare_versions(v1 VARCHAR, v2 VARCHAR)\n-- result compares v1 and v2\n-- result == lower means that v1 is lower than v2\nRETURNS VARCHAR\nAS\n$$\ncase\nwhen CAST(SPLIT(v1, '.')[0] AS NUMBER) < CAST(SPLIT(v2, '.')[0]\nAS NUMBER) then 'lower'\nwhen CAST(SPLIT(v1, '.')[0] AS NUMBER) > CAST(SPLIT(v2, '.')[0]\nAS NUMBER) then 'higher'\nwhen CAST(SPLIT(v1, '.')[1] AS NUMBER) < CAST(SPLIT(v2, '.')[1]\nAS NUMBER) then 'lower'\nwhen CAST(SPLIT(v1, '.')[1] AS NUMBER) > CAST(SPLIT(v2, '.')[1]\nAS NUMBER) then 'higher'\nwhen CAST(SPLIT(v1, '.')[2] AS NUMBER) < CAST(SPLIT(v2, '.')[2]\nAS NUMBER) then 'lower'\nwhen CAST(SPLIT(v1, '.')[2] AS NUMBER) > CAST(SPLIT(v2, '.')[2]\nAS NUMBER) then 'higher'\nelse 'equal'\nend\n$$\n;\n3. Configure your security monitoring solution to alert on sessions from unsupported\nversions. Replace the version numbers below with the latest versions from the\nprevious step. The following query can be run periodically.\nSELECT CREATED_ON, USER_NAME,\nSPLIT(CLIENT_APPLICATION_ID, ' ')[0]::varchar AS \"CLIENT_APP\",\nCLIENT_APPLICATION_VERSION,\nCLIENT_ENVIRONMENT\nFROM SNOWFLAKE.ACCOUNT_USAGE.SESSIONS\nWHERE (\"CLIENT_APP\" = 'JDBC' AND\nCOMPARE_VERSIONS(CLIENT_APPLICATION_VERSION, '3.13.6') = 'lower')\nOR (\"CLIENT_APP\" = 'ODBC' AND\nCOMPARE_VERSIONS(CLIENT_APPLICATION_VERSION, '2.23.3') = 'lower')\nOR (\"CLIENT_APP\" = 'PythonConnector' AND\nCOMPARE_VERSIONS(CLIENT_APPLICATION_VERSION, '2.5.0') = 'lower')\nORDER BY CLIENT_APPLICATION_ID;\n4. When detecting the use of unsupported clients, upgrade to the latest,\nrecommended version.",
    "default_value": "By default, there is no monitoring and alerting on unsupported clients.",
    "detection_commands": [],
    "remediation_commands": [
      "CREATE OR REPLACE FUNCTION compare_versions(v1 VARCHAR, v2 VARCHAR) -- result compares v1 and v2 -- result == lower means that v1 is lower than v2",
      "SELECT CREATED_ON, USER_NAME,"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/release-notes/requirements",
      "2. https://community.snowflake.com/s/article/how-to-report-on-the-clients-",
      "connecting-to-a-snowflake-account"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 83,
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
    "cis_id": "3.1",
    "title": "Ensure that an account-level network policy has been configured to only allow access from trusted IP addresses",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "networking",
    "domain": "Networking",
    "description": "Network policies allow restricting access to a Snowflake account based on source IP\naddresses. A network policy can be configured either on the account level, for all users\nof the account, or on the user level, for a specific user. In the presence of both account-\nlevel and user-level policies, the user-level policies take precedence.\nA network policy can also be configured on the SCIM and Snowflake OAuth security\nintegrations to restrict the list of source IP addresses allowed when exchanging an\nauthorization code for an access or refresh token and when using a refresh token to\nobtain a new access token. If network policy is not set on the security integration of the\naforementioned types, the account-level network policy is set, if used.",
    "rationale": "Network policies help mitigate the threat of leaked user credentials. If an account\nnetwork policy is not configured limiting source IP addresses, leaked Snowflake\ncredentials can be used from anywhere in the world.\nNetwork policies are especially useful when there is a heightened risk of leaking\ncredentials. For example, if instead of using SSO, users authenticate to Snowflake\nusing Snowflake passwords.\nNetwork policy set on the account level can serve as a coarse-grained baseline for the\nmajority of the Snowflake users and can be further tightened on the specific highly\nprivileged user, service account, and security integration level.",
    "impact": "If a network policy is misconfigured to disallow IP addresses from which users usually\naccess Snowflake, their productivity may be impacted.\nIf a network policy is misconfigured to disallow IP addresses from which services and\nautomation usually access Snowflake, reliability of those services and automation may\nbe impacted.\nIf a network policy is misconfigured to disallow IP addresses used by one of the\nSnowflake security integrations that support network policies, those integrations will be\nbroken.\nIf a user with permissions to configure network policies on the account accidentally\nlocks themselves and everybody else with such permission out, they will need to\ncontact Snowflake customer support to restore access to their account.",
    "audit": "From the UI:\n1. Go to https://app.snowflake.com/ and sign into your Snowflake account.\n2. On the left side navigation bar, click on Admin.\n3. Under Admin, click on Security.\n4. Under the Network Policies tab, ensure that a network policy is configured\nproperly and set to Active.\nProgrammatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List the network policies active at the account level.\nSHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT;\n2. Ensure that the query returns a result.\n3. Note the name of the network policy and replace <policy_name> in the query\nbelow with your network policy name:\nDESCRIBE NETWORK POLICY <policy_name>;\n4. Ensure that ALLOWED_IP_LIST is set for the network policy and that it contains\nonly trusted IP address ranges.",
    "expected_response": "4. Under the Network Policies tab, ensure that a network policy is configured\n2. Ensure that the query returns a result.\n4. Ensure that ALLOWED_IP_LIST is set for the network policy and that it contains",
    "remediation": "From the UI:\n1. Go to https://app.snowflake.com/ and sign into your Snowflake account.\n2. On the left side navigation bar, click on Admin.\n3. Under Admin, click on Security.\n4. Under the Network Policies tab, click the + Network Policy button on the top\nright side.\n5. Enter a Policy Name and list of Allowed IP Addresses.\n6. Click Create network policy.\n7. Find your policy in the list of network policies and click Activate policy. This will\nset the network policy at the account level.\nProgrammatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Create a network policy. Replace <policy_name> with the name you want to give\nthe policy, and customize the list of allowed and blocked IP addresses:\nCREATE NETWORK POLICY <policy_name> ALLOWED_IP_LIST=('192.168.1.0/24');\n2. Set the network policy at the account level:\nALTER ACCOUNT SET NETWORK_POLICY = <policy_name>;\nFor more information, see the documentation on creating network policies.\nNote:\n• When a network policy includes values for both ALLOWED_IP_LIST and\nBLOCKED_IP_LIST, Snowflake applies the blocked list first.\n• Do not add 0.0.0.0/0 to BLOCKED_IP_LIST. Because Snowflake applies the\nblocked list first, this would block your own access. Additionally, in order to block\nall IP addresses except a select list, you only need to add IP addresses to\nALLOWED_IP_LIST. Snowflake automatically blocks all IP addresses not included\nin the allowed list.\n• You can create and set a network policy on a security integration to configure\nallowed IP addresses from your IdP used to exchange an authorization code for\nan access or refresh token and when using a refresh token to obtain a new\naccess token.",
    "default_value": "No network policies are configured by default. Access from any IP address is allowed.",
    "detection_commands": [
      "SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT;",
      "DESCRIBE NETWORK POLICY <policy_name>;"
    ],
    "remediation_commands": [
      "CREATE NETWORK POLICY <policy_name> ALLOWED_IP_LIST=('192.168.1.0/24');",
      "ALTER ACCOUNT SET NETWORK_POLICY = <policy_name>;"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/network-policies.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 87,
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
    "cis_id": "3.2",
    "title": "Ensure that user-level network policies have been configured for service accounts",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Apply Host-based Firewalls or Port Filtering",
    "description": "Network policies allow restricting access to a Snowflake account based on source IP\naddresses. A network policy can be configured either on the account level, for all users\nof the account, or on the user level, for a specific user. In the presence of both account-\nlevel and user-level policies, the user-level policies take precedence.\nA service account is a Snowflake user whose credentials are used by scripts, jobs,\napplications, pipelines, etc. to talk to Snowflake. Other names include \"application user\",\n\"service principal\", \"system account\", or \"daemon user\". Service account is not a\nSnowflake specific term.",
    "rationale": "Network policies help mitigate the threat of leaked user credentials. If network policies\nare not configured limiting source IP addresses, leaked Snowflake credentials can be\nused from anywhere in the world.\nService accounts often have direct access to raw sensitive data not appropriate for most\nhuman users. Service accounts are also generally deployed in production environments\nwith source IP address ranges distinct from the IP address ranges used by the human\nusers. To decrease the risk of inappropriate data access with service account\ncredentials, user-level network policies can be applied to service accounts.",
    "impact": "If a network policy is misconfigured to disallow IP addresses from which service\naccounts access Snowflake, it can cause a reliability impact.\nIf a user with permissions to configure network policies on the account accidentally\nlocks themselves and everybody else with such permission out, they will need to\ncontact Snowflake customer support to restore access to their account.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. Get the list of users in the account.\nSELECT object_name\nFROM snowflake.account_usage.users\nWHERE domain = 'USER' AND u.deleted_on IS NULL;\n2. Identify the users that are used to run tasks, also known as service accounts.\n3. For each service account <service_account_name>, check if there is a network\npolicy associated with it:\nSHOW PARAMETERS LIKE 'NETWORK_POLICY' FOR USER <service_account_name>;\nNote: The name of the network policy from the value field.\n4. Describe the policy. Replace <policy_name> in the query below with your network\npolicy name from above:\nDESCRIBE NETWORK POLICY <policy_name>;\n5. Ensure that ALLOWED_IP_LIST is set for the network policy and that it contains\nonly trusted IP address ranges.\nRequired Privileges:\nTo run the queries above, the caller needs:\n•\nOWNERSHIP privilege on every network policy in an account.\n•\nSECURITY_VIEWER role on the Snowflake database\n•\nGOVERNANCE_VIEWER role on the Snowflake database",
    "expected_response": "5. Ensure that ALLOWED_IP_LIST is set for the network policy and that it contains",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or through the SnowSQL ALI:\n1. Create a network policy. Replace <policy_name> with the name you want to give\nthe policy, and customize the list of allowed and blocked IP addresses:\nCREATE NETWORK POLICY <policy_name> ALLOWED_IP_LIST=('192.168.1.0/24');\n2. For each service account user <service_account_name>, set the desired network\npolicy <policy_name>:\nALTER USER <service_account_name>\nSET NETWORK_POLICY = <policy_name>;\nFor more information, see the documentation on creating network policies.\nNote:\n• When a network policy includes values for both ALLOWED_IP_LIST and\nBLOCKED_IP_LIST, Snowflake applies the blocked list first.\n• Do not add 0.0.0.0/0 to BLOCKED_IP_LIST. Because Snowflake applies the\nblocked list first, this would block your own access. Additionally, in order to block\nall IP addresses except a select list, you only need to add IP addresses to\nALLOWED_IP_LIST. Snowflake automatically blocks all IP addresses not included\nin the allowed list.",
    "default_value": "No network policies are configured by default for any user. Access from any IP address\nis allowed.",
    "detection_commands": [
      "SELECT object_name",
      "SHOW PARAMETERS LIKE 'NETWORK_POLICY' FOR USER <service_account_name>;",
      "DESCRIBE NETWORK POLICY <policy_name>;"
    ],
    "remediation_commands": [
      "CREATE NETWORK POLICY <policy_name> ALLOWED_IP_LIST=('192.168.1.0/24');",
      "ALTER USER <service_account_name>"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/network-policies.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 91,
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
    "cis_id": "4.1",
    "title": "Ensure yearly rekeying is enabled for a Snowflake account",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "description": "All Snowflake customer data is encrypted by default using the latest security standards\nand best practices. Snowflake uses strong AES 256-bit encryption with a hierarchical\nkey model rooted in a hardware security module.\nAll Snowflake-managed keys are automatically rotated when they are more than 30\ndays old. Furthermore, data can be automatically re-encrypted (\"rekeyed\") on a yearly\nbasis. Data encryption and key rotation is entirely transparent and requires no\nconfiguration or management.\nKey rotation transitions an active encryption key to a retired state. Practically this means\ntransitioning of the active encryption key from being used for encrypting new data and\ndecrypting data encrypted with that key to only decrypting data encrypted with that key.\nRekeying transitions a retired encryption key to being destroyed. Practically this means\nre-encryption of the data encrypted by a retired key with a new key and destroying the\ndisposing of the retired key.",
    "rationale": "Rekeying constrains the total duration in which a key is used for recipient usage,\nfollowing NIST recommendations. Furthermore, when rekeying data, Snowflake can\nincrease encryption key sizes and utilize better encryption algorithms that may be\nstandardized since the previous key generation was created.\nRekeying, therefore, ensures that all customer data, new and old, is encrypted with the\nlatest security technology.",
    "impact": "None.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or from the SnowSQL CLI:\n1. List the value of the PERIODIC_DATA_REKEYING parameter:\nSHOW PARAMETERS LIKE 'PERIODIC_DATA_REKEYING' IN ACCOUNT;\n2. Ensure that the parameter is set to true.",
    "expected_response": "2. Ensure that the parameter is set to true.",
    "remediation": "Programmatically:\nSet parameter value to true:\nALTER ACCOUNT\nSET PERIODIC_DATA_REKEYING=true;",
    "default_value": "By default, yearly re-keying is disabled.",
    "additional_information": "Periodic data rekeying setting is only available to Enterprise Edition or higher.",
    "detection_commands": [
      "SHOW PARAMETERS LIKE 'PERIODIC_DATA_REKEYING' IN ACCOUNT;"
    ],
    "remediation_commands": [
      "ALTER ACCOUNT"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-encryption-manage.html",
      "2. https://docs.snowflake.com/en/sql-reference/parameters.html#periodic-data-",
      "rekeying"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 96,
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
    "cis_id": "4.2",
    "title": "Ensure AES encryption key size used to encrypt files stored in internal stages is set to 256 bits",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "All ingested data stored in Snowflake tables is encrypted using 256-bit long AES\nencryption keys. However, data uploaded to internal stages is by default encrypted with\n128-bit long AES encryption keys.",
    "rationale": "The field of cryptanalysis is continuously advancing and new vulnerabilities and attacks\nare discovered that obsolete cryptographic primitives that once were considered secure.\nThe 128-bit long AES encryption keys are still considered secure today and there are no\nstrong reasons to believe this will change soon. Usage of the 256-bit long AES\nencryption keys today is generally recommended out of an abundance of caution.",
    "impact": "None.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or using the SnowSQL CLI:\n1. Check length of the AES encryption keys used to encrypt data uploaded to\ninternal stages:\nSHOW PARAMETERS LIKE 'CLIENT_ENCRYPTION_KEY_SIZE' IN ACCOUNT;\n2. Ensure that value is set to 256.",
    "expected_response": "2. Ensure that value is set to 256.",
    "remediation": "Programmatically:\nTo set the length of the AES encryption keys used to encrypt data uploaded to internal\nstages, run the following command:\nALTER ACCOUNT\nSET CLIENT_ENCRYPTION_KEY_SIZE=256;",
    "default_value": "By default, files uploaded to internal stages are encrypted with 128-bit long AES\nencryption keys.",
    "detection_commands": [
      "SHOW PARAMETERS LIKE 'CLIENT_ENCRYPTION_KEY_SIZE' IN ACCOUNT;"
    ],
    "remediation_commands": [
      "ALTER ACCOUNT"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/sql-reference/parameters#client-encryption-key-",
      "size"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 98,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2"
    ]
  },
  {
    "cis_id": "4.3",
    "title": "Ensure that the DATA_RETENTION_TIME_IN_DAYS parameter is set to 90 for critical data",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "Snowflake Time Travel enables accessing historical data (i.e., data that has been\nchanged or deleted) at any point within a defined period. It relies on configuring a data\nretention period for your critical data assets.\nThe DATA_RETENTION_TIME_IN_DAYS object parameter is used to set data retention period\non the account, database, schema, or table level. When the\nMIN_DATA_RETENTION_TIME_IN_DAYS parameter is set at the account level, the effective\nminimum data retention period for an object is determined by\nMAX(DATA_RETENTION_TIME_IN_DAYS, MIN_DATA_RETENTION_TIME_IN_DAYS).",
    "rationale": "Time Travel can be used to recover critical data that was maliciously destroyed or\nencrypted by ransomware.",
    "impact": "Data retention requires additional storage which will be reflected in the monthly storage\ncharges. For more information about storage charges, see Storage Costs for Time\nTravel and Fail-safe.",
    "audit": "Programmatically:\nFrom a Snowsight worksheet or from the SnowSQL CLI:\n1. For each table <table_name>, list the DATA_RETENTION_TIME_IN_DAYS value:\nSHOW PARAMETERS\nLIKE 'DATA_RETENTION_TIME_IN_DAYS'\nIN TABLE <table_name>;\n2. Ensure that the parameter value is set to 90.",
    "expected_response": "2. Ensure that the parameter value is set to 90.",
    "remediation": "An organization's compliance, legal and privacy groups may have important inputs on\nhow long certain data should and can be retained for. For example, in the context of\nGDPR. It is important to take those inputs into account when data retention periods are\ndetermined for critical data.\nProgrammatically:\nFor every non-compliant table with critical data set the retention period to 90 days:\nALTER TABLE <table_name>\nSET DATA_RETENTION_TIME_IN_DAYS=90;\nIf all tables within a given schema or database contain critical data, the data retention\nperiod can be set on the schema or database level correspondingly.",
    "default_value": "The standard retention period is 1 day (24 hours) and is automatically enabled for all\nSnowflake accounts.\nFor Snowflake Standard Edition, the retention period can be set to 0 (or unset back to\nthe default of 1 day) at the account and object level (i.e. databases, schemas, and\ntables).\nFor Snowflake Enterprise Edition (and higher):\nFor transient databases, schemas, and tables, the retention period can be set to 0 (or\nunset back to the default of 1 day). The same is also true for temporary tables.\nFor permanent databases, schemas, and tables, the retention period can be set to any\nvalue from 0 up to 90 days.",
    "additional_information": "Data retention period can only be set for permanent databases, schemas and tables. It\ncannot be set for transient databases, schemas and tables. It also cannot be set for\ntemporary tables.\nA threat actor with OWNERSHIP or MODIFY privilege on a database, schema, or table can\noverride DATA_RETENTION_TIME_IN_DAYS parameter and effectively disable time travel,\nunless the MIN_DATA_RETENTION_TIME_IN_DAYS parameter is set at the account level.\nData retention setting is only available to Enterprise Edition or higher.",
    "detection_commands": [
      "SHOW PARAMETERS"
    ],
    "remediation_commands": [
      "ALTER TABLE <table_name>"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/data-time-travel.html",
      "2. https://docs.snowflake.com/en/user-guide/data-cdp-storage-costs.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 100,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "retention"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D3",
      "D5"
    ]
  },
  {
    "cis_id": "4.4",
    "title": "Ensure that the MIN_DATA_RETENTION_TIME_IN_DAYS account parameter is set to 7 or higher",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "subdomain": "Perform Complete System Backups",
    "description": "The MIN_DATA_RETENTION_TIME_IN_DAYS account parameter can be set by users with the\nACCOUNTADMIN role to set a minimum retention period for the account. This parameter\ndoes not alter or replace the DATA_RETENTION_TIME_IN_DAYS parameter value. However\nit may change the effective data retention time. When this parameter is set at the\naccount level, the effective minimum data retention period for an object is determined by\nMAX(DATA_RETENTION_TIME_IN_DAYS, MIN_DATA_RETENTION_TIME_IN_DAYS).",
    "rationale": "Setting the MIN_DATA_RETENTION_TIME_IN_DAYS to 7 helps restore data-related objects\n(tables, schemas, and databases) that might have been accidentally or intentionally\ndeleted.",
    "impact": "Data retention requires additional storage which will be reflected in the monthly storage\ncharges. For more information about storage charges, see Storage Costs for Time\nTravel and Fail-safe.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or from the SnowSQL CLI:\n1. List the value of the parameter:\nSHOW PARAMETERS LIKE 'MIN_DATA_RETENTION_TIME_IN_DAYS' IN ACCOUNT;\n2. Ensure that the parameter is set to 7 or higher.",
    "expected_response": "2. Ensure that the parameter is set to 7 or higher.",
    "remediation": "Programmatically:\nSet the MIN_DATA_RETENTION_TIME_IN_DAYS on the account level to 7 or higher:\nALTER ACCOUNT\nSET MIN_DATA_RETENTION_TIME_IN_DAYS=7;",
    "default_value": "The default value for the MIN_DATA_RETENTION_TIME_IN_DAYS account parameter is 0.",
    "detection_commands": [
      "SHOW PARAMETERS LIKE 'MIN_DATA_RETENTION_TIME_IN_DAYS' IN ACCOUNT;"
    ],
    "remediation_commands": [
      "ALTER ACCOUNT"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/data-time-travel.html",
      "2. https://docs.snowflake.com/en/user-guide/data-cdp-storage-costs.html"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 103,
    "dspm_relevant": true,
    "dspm_categories": [
      "retention"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D3"
    ]
  },
  {
    "cis_id": "4.5",
    "title": "Ensure that the REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATIO N account parameter is set to true",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "subdomain": "Perform Complete System Backups",
    "description": "Ensure that creating an external stage to access a private cloud storage location\nrequires referencing a storage integration object as cloud credentials.",
    "rationale": "Using storage integration removes the need to supply credentials when creating\nexternal stages or when loading or unloading data. This reduces the risk of those\ncredentials being leaked and data compromised.\nRequiring a storage integration when creating a new stage reduces the risk or data\nexfiltration by accidentally exporting sensitive data to an external stage that does not\nhave the appropriate network security, access control, or encryption security and is not\napproved by the organization’s security team.",
    "impact": "Setting the REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION account level\nparameter to true can break existing manual and automated flows relying on creation of\nexternal stages not backed by a storage integration.",
    "audit": "Programmatically:\nIn the Snowsight UI or from the SnowSQL CLI:\n1. List the value of the REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION\nparameter:\nSHOW PARAMETERS LIKE 'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION'\nIN ACCOUNT;\n2. Ensure that the parameter is set to true;",
    "expected_response": "2. Ensure that the parameter is set to true;",
    "remediation": "Programmatically:\nIn a Snowsight worksheet or from the SNOWSQL cli, run the following command to set\nthe parameter value to true:\nALTER ACCOUNT\nSET REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION=true;\nNote: To avoid disruption of existing workflow relying on creation of external stages not\nreferencing a storage integration, all such workflows should be identified and migrated\nto creation of external stages referencing storage integrations.",
    "default_value": "By default, the REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION account level\nparameters is set to false.",
    "detection_commands": [
      "SHOW PARAMETERS LIKE 'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION'"
    ],
    "remediation_commands": [
      "ALTER ACCOUNT"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/sql-reference/parameters#require-storage-",
      "integration-for-stage-creation",
      "2. https://www.snowflake.com/blog/how-to-configure-a-snowflake-account-to-",
      "prevent-data-exfiltration/"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 105,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2"
    ]
  },
  {
    "cis_id": "4.6",
    "title": "Ensure that the REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATI ON account parameter is set to true",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "subdomain": "Establish and Maintain a Data Management Process",
    "description": "Ensure that loading data from or unloading data to a private cloud storage location\nrequires using a named external stage that references a storage integration object.\nIf this parameter is not set, then users can specify the explicit cloud provider credentials\ndirectly in the COPY statement.",
    "rationale": "Using storage integration removes the need to supply credentials when loading and\nunloading data from external stages or when loading or unloading data to a private\ncloud storage location. This reduces the risk of data exfiltration by accidentally exporting\nsensitive data to an external stage that does not have the appropriate network security,\naccess control, or encryption security and is not approved by the organization’s security\nteam.",
    "impact": "Setting the REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION account level\nparameter to true can break existing manual and automated flows relying on loading or\nunloading data to external stages not backed by a storage integration.",
    "audit": "Programmatically:\nIn a Snowsight worksheet or from the SnowSQL CLI:\n1. List the value of the REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION\nparameter:\nSHOW PARAMETERS LIKE 'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION'\nIN ACCOUNT;\n2. Ensure that the parameter is set to true.",
    "expected_response": "2. Ensure that the parameter is set to true.",
    "remediation": "Programmatically:\nSet the REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION on the account level to\ntrue:\nALTER ACCOUNT\nSET REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION=true;\nNOTE:\nTo avoid disruption of existing workflow relying on external stages not referencing a\nstorage integration, all such workflows should be identified and migrated to external\nstages referencing storage integrations.",
    "default_value": "By default the REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION account level\nparameter is set to false.",
    "detection_commands": [
      "SHOW PARAMETERS LIKE 'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION'"
    ],
    "remediation_commands": [
      "ALTER ACCOUNT"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/sql-reference/parameters#require-storage-",
      "integration-for-stage-operation",
      "2. https://www.snowflake.com/blog/how-to-configure-a-snowflake-account-to-",
      "prevent-data-exfiltration/"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 107,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2"
    ]
  },
  {
    "cis_id": "4.7",
    "title": "Ensure that all external stages have storage integrations",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "subdomain": "Establish and Maintain a Data Management Process",
    "description": "External stage is a Snowflake object used for loading data from external storage\nlocations into Snowflake tables and unloading data from Snowflake tables into external\nstorage locations. Currently supported external storage locations are Amazon S3\nbuckets, Google Cloud Storage buckets and Microsoft Azure containers.\nStorage integration is a Snowflake object that encapsulates external storage\nauthentication configuration as well as an optional set of allowed or blocked storage\nlocations. When configuring an external stage, a storage integration can be referenced\nin lieu of storage service credentials.",
    "rationale": "Using storage integration removes the need to supply credentials when creating\nexternal stages or when loading or unloading data. This reduces the risk of those\ncredentials being leaked and data compromised.\nAdditionally, security administrators creating storage integration can constrain CSP\nstorage locations allowed to be used as destinations in external stages. This further\nreduces the risk of data being leaked or compromised.",
    "impact": "None.",
    "audit": "Programmatically:\nIn the Snowsight UI or from the SnowSQL CLI:\n1. List all external stages:\nSHOW STAGES;\n2. For each stage, ensure that if type is set to EXTERNAL, then storage_integration\nis not null.\nRequired privileges:\nTo run the query above, the caller needs the:\n•\nUSAGE privilege on every external stage in an account.\n•\nUSAGE privilege on the parenting schema of every external stage in an account.\n•\nUSAGE privilege on the parenting database of every external stage in an account.",
    "expected_response": "2. For each stage, ensure that if type is set to EXTERNAL, then storage_integration",
    "remediation": "Programmatically:\n1. For each external stage, create a storage integration <my_storage_integration>:\nCREATE STORAGE INTEGRATION <my_storage_integration>\nTYPE = EXTERNAL_STAGE\nSTORAGE_PROVIDER = 'S3'\nENABLED = TRUE\nSTORAGE_AWS_ROLE_ARN = 'arn:aws:iam::001234567890:role/myrole';\n2. Update the external stage <my_external_stage> to use the new storage\nintegration:\nALTER STAGE <my_external_stage> SET STORAGE_INTEGRATION =\n<my_storage_integration>;",
    "default_value": "By default, external stages may be created without storage integrations.",
    "detection_commands": [
      "SHOW STAGES;"
    ],
    "remediation_commands": [
      "CREATE STORAGE INTEGRATION <my_storage_integration>",
      "ALTER STAGE <my_external_stage> SET STORAGE_INTEGRATION ="
    ],
    "references": [
      "1. https://docs.snowflake.com/en/sql-reference/sql/create-stage",
      "2. https://docs.snowflake.com/en/sql-reference/sql/create-storage-integration",
      "3. https://www.snowflake.com/blog/how-to-configure-a-snowflake-account-to-",
      "prevent-data-exfiltration/",
      "4. https://docs.snowflake.com/en/sql-reference/sql/alter-stage"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 110,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "4.8",
    "title": "Ensure that the PREVENT_UNLOAD_TO_INLINE_URL account parameter is set to true",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "subdomain": "Establish and Maintain a Data Management Process",
    "description": "Prevent ad hoc data unload operations to external cloud storage by enabling the\nPREVENT_UNLOAD_TO_INLINE_URL account parameter.",
    "rationale": "Direct data unloading can be employed by threat actors to exfiltrate sensitive data from\nSnowflake to a supported external storage location of their choice. A well-intended\nemployee with a legitimate business task can unknowingly unload data to publicly\navailable storage locations and unintentionally leak it. Prevention of the direct data\nunloading reduces risk of data exfiltration and leakage.\nSetting the PREVENT_UNLOAD_TO_INLINE_URL account parameter to true will prevent ad\nhoc data unload operations to external cloud storage locations (i.e. through COPY INTO\n<location> statements that specify the cloud storage URL and access settings directly\nin the statement).",
    "impact": "Setting the PREVENT_UNLOAD_TO_INLINE_URL account level parameter to true can break\nexisting manual and automated flows relying on direct unloading data to external\nstorage locations.",
    "audit": "Programmatically:\nFrom a Snowsight worksheet or from the SnowSQL CLI:\n1. List the value of the PREVENT_UNLOAD_TO_INLINE_URL account level parameter:\nSHOW PARAMETERS LIKE 'PREVENT_UNLOAD_TO_INLINE_URL' IN ACCOUNT;\n2. Ensure that PREVENT_UNLOAD_TO_INLINE_URL is set to true;",
    "expected_response": "2. Ensure that PREVENT_UNLOAD_TO_INLINE_URL is set to true;",
    "remediation": "Programmatically:\nSet the PREVENT_UNLOAD_TO_INLINE_URL on the account level to true:\nALTER ACCOUNT\nSET PREVENT_UNLOAD_TO_INLINE_URL=true;\nNOTE: To avoid disruption of existing workflow relying on direct unloading data to\nexternal storage locations, all such workflows should be identified and migrated to\nunloading data to external stages referencing storage integrations.",
    "default_value": "By default the PREVENT_UNLOAD_TO_INLINE_URL account level parameter is set to false.",
    "detection_commands": [
      "SHOW PARAMETERS LIKE 'PREVENT_UNLOAD_TO_INLINE_URL' IN ACCOUNT;"
    ],
    "remediation_commands": [
      "ALTER ACCOUNT"
    ],
    "references": [
      "1. https://docs.snowflake.com/en/sql-reference/sql/copy-into-location",
      "2. https://docs.snowflake.com/en/sql-reference/parameters#prevent-unload-to-",
      "inline-url"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 113,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": false
  },
  {
    "cis_id": "4.9",
    "title": "Ensure that Tri-Secret Secure is enabled for the Snowflake account",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Tri-Secret Secure is the combination of a Snowflake-maintained key and a customer-\nmanaged key in the cloud provider platform that hosts your Snowflake account to create\na composite master key to protect your Snowflake data. The composite master key acts\nas an account master key and wraps all of the keys in the hierarchy; however, the\ncomposite master key never encrypts raw data.",
    "rationale": "If the customer-managed key in the composite master key hierarchy is revoked, your\ndata can no longer be decrypted by Snowflake, providing a level of security and control\nabove Snowflake’s standard encryption.",
    "impact": "This feature relies on the customer managing and providing an encryption key. There is\na reliability risk associated with it: If the key is lost, all data encrypted within the\nSnowflake account will be lost.",
    "audit": "Follow the instructions in the How To: Validate Tri-Secret Secure is configured for your\nSnowflake account successfully documentation.",
    "expected_response": "Follow the instructions in the How To: Validate Tri-Secret Secure is configured for your",
    "remediation": "To enable Snowflake Tri-Secret Secure for your Business Critical (or higher) account,\nplease contact Snowflake Support.",
    "default_value": "By default the tri-secret secure feature is not enabled for a Snowflake account.",
    "additional_information": "The tri-secret secure feature is currently available only to Business Critical Edition or\nhigher.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-encryption-manage#tri-secret-",
      "secure",
      "2. https://community.snowflake.com/s/article/How-to-test-Tri-Secret-Secure-is-",
      "enabled"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 115,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2"
    ]
  },
  {
    "cis_id": "4.10",
    "title": "Ensure that data masking is enabled for sensitive data",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "Data masking policy is a fine-grained access control used to protect sensitive data from\nunauthorized access by selectively masking plain-text data in table and view columns at\nquery time.",
    "rationale": "Masking policy allows for a wide range of use cases where data can be queried,\naggregated and analyzed in a privacy preserving manner.",
    "impact": "Manual and automated workflows relying on querying unmasked data may be broken\nunless updated prior to application of a masking policy.",
    "audit": "Ensure appropriate masking policies are applied to columns with sensitive data across\nall tables and views in a Snowflake account.\nEnsure appropriate row access policies are applied to rows with special access\nrequirements across all tables and views in a Snowflake account.\nFrom the UI:\n1. Go to https://app.snowflake.com/ and sign into your Snowflake account.\n2. On the left side navigation bar, click on Data.\n3. Under Data, click on Governance.\n4. Look for Columns with a masking policy. Ensure that at least one row access\npolicy has been configured.\nProgrammatically:\nIn a Snowsight worksheet or through the SnowSQL CLI:\n1. List all the configured row access policies:\nSHOW MASKING POLICIES IN ACCOUNT;\n2. Ensure that the query returns at least one result.",
    "expected_response": "Ensure appropriate masking policies are applied to columns with sensitive data across\nEnsure appropriate row access policies are applied to rows with special access\n4. Look for Columns with a masking policy. Ensure that at least one row access\n2. Ensure that the query returns at least one result.",
    "remediation": "Identify columns with sensitive data across all account tables and views and apply\nappropriate masking policies following steps described in the documentation.\nIf columns with sensitive data are tagged appropriately, tag-based masking can be\nused.\nSensitive data columns can be identified and tagged with assistance of the\nEXTRACT_SEMANTIC_CATEGORIES and ASSOCIATE_SEMANTIC_CATEGORY_TAGS system\nfunctions. See the Data Classification documentation for details.\nTo create a data masking policy, follow the steps in this documentation.",
    "default_value": "No masking policies are applied by default in a Snowflake account.",
    "additional_information": "The masking policy feature is currently available only to Enterprise Edition or higher.",
    "detection_commands": [
      "SHOW MASKING POLICIES IN ACCOUNT;"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-column-intro",
      "2. https://docs.snowflake.com/en/user-guide/security-column-ddm-intro",
      "3. https://docs.snowflake.com/en/user-guide/security-column-ext-token-intro"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 117,
    "dspm_relevant": true,
    "dspm_categories": [
      "access",
      "classification"
    ],
    "rr_relevant": false
  },
  {
    "cis_id": "4.11",
    "title": "Ensure that row-access policies are configured for sensitive data",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "data_protection",
    "domain": "Data Protection",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "Row access policies are used to determine which rows to return in the query result.\nRow access policies can include conditions and functions in the policy expression to\ntransform the data at query runtime when those conditions are met.",
    "rationale": "Row-access policy is a fine-grained access control used to protect table and view rows\nwith special access requirements from unauthorized access at query time. It can be\nused to control access to certain data rows even if a user has access to query a table or\nview.",
    "impact": "Manual and automated workflows relying on having access to all rows in a table or view\nmay be broken unless updated prior to application of a row access policy.",
    "audit": "Ensure appropriate row access policies are applied to rows with special access\nrequirements across all tables and views in a Snowflake account.\nFrom the UI:\n1. Go to https://app.snowflake.com/ and sign into your Snowflake account.\n2. On the left side navigation bar, click on Data.\n3. Under Data, click on Governance.\n4. Look for Tables with row access policies. Ensure that at least one row access\npolicy has been configured.\nProgrammatically:\nIn a Snowsight worksheet or from the SnowSQL CLI:\n1. List all the configured row access policies:\nSHOW ROW ACCESS POLICIES IN ACCOUNT;\n2. Ensure that the query returns at least one result.",
    "expected_response": "Ensure appropriate row access policies are applied to rows with special access\n4. Look for Tables with row access policies. Ensure that at least one row access\n2. Ensure that the query returns at least one result.",
    "remediation": "Identify rows with special access requirements across all account tables and views and\napply appropriate row access policies following steps described in the Using Row\nAccess Policies documentation.",
    "default_value": "No row access policies are applied by default in a Snowflake account.",
    "additional_information": "The row access policy feature is currently available only to Enterprise Edition or higher.",
    "detection_commands": [
      "SHOW ROW ACCESS POLICIES IN ACCOUNT;"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://docs.snowflake.com/en/user-guide/security-row-intro",
      "2. https://docs.snowflake.com/en/user-guide/security-row-using"
    ],
    "source_pdf": "CIS_Snowflake_Foundations_Benchmark_v1.0.0.pdf",
    "page": 119,
    "dspm_relevant": true,
    "dspm_categories": [
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  }
]
""")


def get_snowflake_cis_registry() -> list[dict]:
    """Return the complete CIS control registry as a list of dicts."""
    return SNOWFLAKE_CIS_CONTROLS


def get_snowflake_control_count() -> int:
    """Return total number of CIS controls."""
    return len(SNOWFLAKE_CIS_CONTROLS)


def get_snowflake_automated_count() -> int:
    """Return count of automated controls."""
    return sum(1 for c in SNOWFLAKE_CIS_CONTROLS if c["assessment_type"] == "automated")


def get_snowflake_manual_count() -> int:
    """Return count of manual controls."""
    return sum(1 for c in SNOWFLAKE_CIS_CONTROLS if c["assessment_type"] == "manual")


def get_snowflake_dspm_controls() -> list[dict]:
    """Return controls relevant to DSPM (Data Security Posture Management)."""
    return [c for c in SNOWFLAKE_CIS_CONTROLS if c.get("dspm_relevant")]


def get_snowflake_rr_controls() -> list[dict]:
    """Return controls relevant to Ransomware Readiness."""
    return [c for c in SNOWFLAKE_CIS_CONTROLS if c.get("rr_relevant")]


def get_snowflake_controls_by_service_area(service_area: str) -> list[dict]:
    """Return controls filtered by service area."""
    return [c for c in SNOWFLAKE_CIS_CONTROLS if c["service_area"] == service_area]


def get_snowflake_controls_by_severity(severity: str) -> list[dict]:
    """Return controls filtered by severity."""
    return [c for c in SNOWFLAKE_CIS_CONTROLS if c["severity"] == severity]
