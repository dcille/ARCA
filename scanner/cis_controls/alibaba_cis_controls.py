"""CIS Alibaba Cloud Foundation Benchmark v2.0.0 — Complete Control Registry.

Auto-generated from the unified CIS controls library.
Contains ALL 85 controls (41 automated, 44 manual).
Each control includes full metadata, audit procedures, detection commands,
remediation guidance, and DSPM/Ransomware Readiness mapping.

Reference: CIS Alibaba Cloud Foundation Benchmark v2.0.0 (2024)
Source: CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf

Total controls: 85 (41 automated, 44 manual)
"""

import json as _json


# Control registry — 85 controls
ALIBABA_CIS_CONTROLS: list[dict] = _json.loads(r"""
[
  {
    "cis_id": "1.1",
    "title": "Avoid the use of the \"root\" account",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "description": "An Alibaba Cloud account can be viewed as a “root” account. The \"root\" account has\nfull control permissions to all cloud products and resources under such account. It is\nhighly recommended that the use of this account should be avoided.",
    "rationale": "The \"root\" account is the owner of the resources under an Alibaba Cloud account. This\naccount pays for and has full control permissions to resources. Minimizing the use of\nsuch account and adopting the principle of least privilege for access management can\nreduce the risk of accidental or unauthorized changes and disclosure of highly\nprivileged credentials.",
    "audit": "You can enable ActionTrail for your account, and create a trail to deliver all action logs\nto Alibaba Cloud Log Service. Then, you can enable an alarm to discover the usage of\n\"root\" account and receive notifications on those conditions.\nImplement the Ensure a log metric filter and alarm exist for usage of \"root\"\naccount recommendation in the Logging and Monitoring section to receive notifications\nof root account usage.\nNote: There are a few conditions under which the use of the root account is required,\nsuch as requesting account security report or configuring multi-factor authentication\n(MFA) for the root account.",
    "expected_response": "Implement the Ensure a log metric filter and alarm exist for usage of \"root\"",
    "remediation": "All users should operate resources at the RAM user level and follow the principle of\nleast privilege. Follow the remediation instructions of the Ensure RAM policies are\nattached only to groups or roles recommendation. For more information about RAM\nuser, see terms of RAM user.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/102600.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 18,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.2",
    "title": "Ensure no root account access key exists",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "Access keys provide programmatic access to a given Alibaba Cloud account. It is\nrecommended that all access keys associated with the root account be removed.",
    "rationale": "An Alibaba Cloud account can be viewed as a “root” account. The root account has the\nhighest privilege of an Alibaba Cloud account. Removing access keys associated with\nthe root account limits the opportunity that the account can be compromised.",
    "impact": "Programs that already use root account access keys may stop working if you disable or\ndelete the access keys without replacing them with other RAM user access keys in your\nprogram.",
    "audit": "Perform the following to determine if the root account has access keys:\nUsing the management console:\n1. Logon to Resource Access Management (RAM) console\nhttps://ram.console.aliyun.com/overview by using your Alibaba Cloud account\n(root account).\n2. In the left-side navigation pane, click Overview.\n3. In the Security Check section, make sure that No AK for Root Account is\nmarked as Finished.",
    "remediation": "Perform the following to delete or disable active root access keys:\nUsing the management console\n1. Logon to RAM console by using your Alibaba Cloud account (root account).\n2. Move the pointer over the account icon in the upper-right corner and click\nAccessKey.\n3. Click Continue to manage AccessKey.\n4. On the Security Management page, find the target access keys and perform the\nfollowing operations:\no Click Disable to disable the target access keys temporarily.\no Click Delete to delete the target access keys permanently.",
    "default_value": "By default, no access key is created for the root account.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/102600.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 20,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.3",
    "title": "Ensure MFA is enabled for the \"root\" account",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "With MFA enabled, anytime the “root” account logs on to Alibaba Cloud, it will be\nprompted for username and password followed by an authentication code from the\nvirtual MFA device. It is recommended that MFA be enabled for the “root” user.",
    "rationale": "It is important to prevent “root” account from being compromised. Enabling MFA\nrequires the “root” account holder to provide additional information on top of username\nand password.\nWhen MFA is enabled, an attacker faces at least two different authentication\nmechanisms. The additional security makes it harder for an attacker to gain access to\nprotected resources or data.",
    "audit": "Perform the following to determine if an MFA device is enabled for the “root” account:\nUsing the management console:\n1. Logon to RAM console by using your Alibaba Cloud account (root account).\n2. In the left-side navigation pane, click Overview.\n3. In the Security Check section, make sure that Enable MFA for Root\nAccount is marked as Finished.",
    "expected_response": "Perform the following to determine if an MFA device is enabled for the “root” account:",
    "remediation": "Perform the following to enable MFA for “root” account\nUsing the management console:\n1. Logon to RAM console by using your Alibaba Cloud account (root account).\n2. Move the pointer over the account icon in the upper-right corner and click\nSecurity Settings.\n3. In the Account Protection section, Click Edit.\n4. On the displayed page, select a scenario and select TOTP.\n5. Click Submit.\n6. On the displayed page, click Verify now.\n7. Enter the verification code and click Submit.\n8. Download and install a mobile application that supports TOTP MFA, such as\nGoogle Authenticator, on your mobile phone.\nNote: If you already installed Google Authenticator, click Next.\no For iOS: Install Google Authenticator from the App Store.\no For Android: Install Google Authenticator from the Google Play Store.\nNote: You need to install a QR code scanner from the Google Play Store\nfor Google Authenticator to identify QR codes.\n9. After you install Google Authenticator, go back to the Identity Verification\npage and click Next.\n10. Open Google Authenticator and tap BEGIN SETUP.\no Tap Scan barcode and scan the QR code on the Identity\nVerification page.\no Tap Manual entry, enter the username and key, and then tap the check\nmark (√) icon.\nNote: You can obtain the username and key by moving the pointer over\nScan failed on the Identity Verification page.\n11. On the Identity Verification page, enter the 6-digit verification code\nobtained from Google Authenticator and click Next.\nNote: The verification code is refreshed at an interval of 30 seconds.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. http://tools.ietf.org/html/rfc6238",
      "2. https://www.alibabacloud.com/help/doc-detail/28635.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 22,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.4",
    "title": "Ensure that multi-factor authentication is enabled for all RAM users that have a console password",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Use Multifactor Authentication For All Administrative",
    "description": "Multi-Factor Authentication (MFA) adds an extra layer of protection on top of a\nusername and password. With MFA enabled, when a user logs on to Alibaba Cloud,\nthey will be prompted for their user name and password followed by an authentication\ncode from their virtual MFA device. It is recommended that MFA be enabled for all users\nthat have a console password.",
    "rationale": "MFA requires users to verify their identities by entering two authentication factors. When\nMFA is enabled, an attacker faces at least two different authentication mechanisms.\nThe additional security makes it harder for an attacker to gain access to protected\nresources or data.",
    "audit": "Perform the following to determine if an MFA device is enabled for all RAM users having\na console password:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Identities > Users.\n3. In the User Logon Name/Display Name column, click the username of each\nRAM user.\n4. In the Console Logon Management section, if Console Access is set to\nEnabled, make sure that Required to Enable MFA is set to Yes.\nUsing the CLI\nRun the following command to determine if an MFA device is enabled for a RAM user:\naliyun ram GetUserMFAInfo --UserName <ram_user>\nNote: If an error is reported, no MFA device is enabled for the RAM user.",
    "expected_response": "Perform the following to determine if an MFA device is enabled for all RAM users having\n4. In the Console Logon Management section, if Console Access is set to\nEnabled, make sure that Required to Enable MFA is set to Yes.\nRun the following command to determine if an MFA device is enabled for a RAM user:\nNote: If an error is reported, no MFA device is enabled for the RAM user.",
    "remediation": "Perform the following to determine if an MFA device is enabled for all RAM users having\na console password:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Identities > Users.\n3. In the User Logon Name/Display Name column, click the username of each\nRAM user.\n4. In the Console Logon Management section, click Modify Logon Settings.\n5. Select Enabled for Console Password Logon, and Required for Enable\nMFA.\nNote: After you select Enabled for Console Password Logon, and Required\nfor Enable MFA when modifying the logon settings of a RAM user, the user can\ngo to step 7 when logging on to the RAM console for the first time.\n6. In the MFA Device section, click Enable the device.\n7. Download and install Google Authenticator on your mobile phone.\no For iOS: Install Google Authenticator from the App Store.\no For Android: Install Google Authenticator from the Google Play Store.\nNote: You need to install a QR code scanner from the Google Play Store\nfor Google Authenticator to identify QR codes.\n8. Open Google Authenticator and tap BEGIN SETUP.\no Tap Scan barcode and scan the QR code displayed on the Scan the\ncode tab in the console.\no Tap Manual entry, enter the username and key, and then tap the check\nmark (√) icon.\nNote: You can obtain the username and key from the Retrieval\nmanually enter information tab in the console.\n9. On the Scan the code tab, enter the two consecutive security codes obtained\nfrom Google Authenticator and click Enable.\nNote: The security code is refreshed at an interval of 30 seconds.\nFor more information, see Enable an MFA device for a RAM user.",
    "default_value": "MFA is enabled by default for RAM users",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. http://tools.ietf.org/html/rfc6238",
      "2. https://www.alibabacloud.com/help/doc-detail/93720.htm",
      "3. https://www.alibabacloud.com/help/doc-detail/119555.htm",
      "4. https://www.alibabacloud.com/help/en/ram/user-guide/bind-an-mfa-device-to-a-",
      "ram-user?"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 24,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.5",
    "title": "Ensure users not logged on for 90 days or longer are disabled for console logon",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Require Multi-factor Authentication",
    "description": "Alibaba Cloud RAM users can logon to Alibaba Cloud console by using their user name\nand password. If a user has not logged on for 90 days or longer, it is recommended to\ndisable the console access of the user.",
    "rationale": "Disabling users from having unnecessary logon privileges will reduce the opportunity\nthat an abandoned user or a user with compromised password to be used.",
    "impact": "RAM users who still need to log on to the management console or other Alibaba Cloud\nsites may encounter logon failure.",
    "audit": "Perform the following to determine if a user has not logged on for 90 days or longer:\nUsing the management console:\n1. Logon RAM console.\n2. Choose Identities > Users.\n3. In the User Logon Name/Display Name column, click the username of each\nRAM user.\n4. In the Console Logon Management section, check the latest logon time of each\nuser in the Last Console Logon field.\n5. Make sure that each user does not have a last console logon time dated earlier\nthan 90 days ago.",
    "remediation": "Perform the following to disable console logon for a user:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Identities > Users.\n3. In the User Logon Name/Display Name column, click the username of the\ntarget RAM user.\n4. In the Console Logon Management section, click Modify Logon Settings.\n5. In the Console Password Logon section, select Disabled.\n6. Click OK.\nUsing the CLI\naliyun ram DeleteLoginProfile --UserName <ram_user>",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 27,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.6",
    "title": "Ensure access keys are rotated every 90 days or less",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Configure Centralized Point of Authentication",
    "description": "An access key consists of an access key ID and a secret, which are used to sign\nprogrammatic requests that you make to Alibaba Cloud. RAM users need their own\naccess keys to make programmatic calls to Alibaba Cloud from the Alibaba Cloud\nSDKs, CLIs, or direct HTTP/HTTPS calls using the APIs for individual Alibaba Cloud\nservices. It is recommended that all access keys be regularly rotated.",
    "rationale": "Access keys might be compromised by leaving them in codes, configuration files, on\npremise and cloud storages, and then stolen by attackers. Rotating access keys will\nreduce the window of opportunity that a compromised access key to be used.",
    "audit": "Perform the following to determine if access keys are rotated within 90 days:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Identities > Groups.\n3. In the User Logon Name/Display Name column, click the username of each\nRAM user.\n4. In the User AccessKeys section, check the date and time that an access key\nwas created.\n5. Make sure that no user has an access key created earlier than 90 days ago.\nUsing the CLI:\nRun the following command to obtain a list of access keys of a RAM user, and then\ndetermine if the access keys are rotated within 90 days according to the CreateDate\nparameter:\naliyun ram ListAccessKeys --UserName <ram_user>\nNote: In the output, if the AccessKey parameter is empty, no access key exists.",
    "expected_response": "Note: In the output, if the AccessKey parameter is empty, no access key exists.",
    "remediation": "Perform the following to disable and delete access keys:\nUsing the management console:\n1. Logon to RAM console.\n2. In the left-side navigation pane, click Users under Identities.\n3. In the User Logon Name/Display Name column, click the username of the\ntarget RAM user.\n4. In the User AccessKeys section, click Create AccessKey.\n5. Click OK to create a new AccessKy pair for rotation.\n6. Update all applications and systems to use the new AccessKey pair.\n7. Disable the original AccessKey pair by following below steps:\na) Log on to RAM console.\nb) In the left-side navigation pane, click Users under Identities.\nc) On the Users page, click username of the target RAM user in the User Logon\nName/Display Name column.\nd) In the User AccessKeys section, find the target AccessKey pair and click\nDisable.\n8. Confirm that your applications and systems are working.\n9. Delete the original AccessKey pair by following below steps:\na) Log on to RAM console.\nb) In the left-side navigation pane, click Users under Identities.\nc) In the User Logon Name/Display Name column, click the username of the\ntarget RAM user.\nd) In the User AccessKeys section, find the target access keys and Click\nDelete.\ne) In the dialog box that appears, select I am aware of the risk and confirm the\ndeletion.\n10. Click OK.\nUsing the CLI:\n• Run the following command to delete an access key:\naliyun ram DeleteAccessKey --UserAccessKeyId <access_key_ID> --UserName\n<ram_user >\n• Run the following command to disable an active access key:\naliyun ram UpdateAccessKey --UserAccessKeyId <access_key_ID> --Status\nInactive --UserName <ram_user>\n• Run the following command to delete an access key:\naliyun ram DeleteAccessKey --UserAccessKeyId <access_key_ID> --UserName\n<ram_user >\nYour programs that use access keys may stop working if you rotate the access keys\nwithout replacing them in your program prior to the rotation.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/116806.htm",
      "2. https://www.alibabacloud.com/help/doc-detail/116808.htm",
      "3. https://www.alibabacloud.com/help/doc-detail/152682.htm",
      "4. https://www.alibabacloud.com/help/doc-detail/116401.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 29,
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
    "cis_id": "1.7",
    "title": "Ensure RAM password policy requires at least one uppercase letter",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Configure Centralized Point of Authentication",
    "description": "RAM password policies can be used to ensure password complexity. It is recommended\nthat the password policy require at least one uppercase letter.",
    "rationale": "Enhancing complexity of a password policy increases account resiliency against brute\nforce logon attempts.",
    "audit": "Perform the following to ensure the password policy is configured as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, make sure that the value of Charset contains Upper\ncase.\nUsing the CLI:\naliyun ram GetPasswordPolicy\nIn the output, make sure that the RequireUppercaseCharacters parameter is set to\ntrue.",
    "expected_response": "Perform the following to ensure the password policy is configured as expected:\nIn the output, make sure that the RequireUppercaseCharacters parameter is set to",
    "remediation": "Perform the following to set the password policy as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, click Modify.\n4. In the Charset section, select Upper case.\n5. Click OK.\nUsing the CLI:\naliyun ram SetPasswordPolicy --RequireUppercaseCharacters true",
    "default_value": "The default password policy does not enforce any charset in a password.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/116413.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 32,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.8",
    "title": "Ensure RAM password policy requires at least one lowercase letter",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Use Unique Passwords",
    "description": "RAM password policies can be used to ensure password complexity. It is recommended\nthat the password policy require at least one lowercase letter.",
    "rationale": "Enhancing complexity of a password policy increases account resiliency against brute\nforce logon attempts.",
    "audit": "Perform the following to ensure the password policy is configured as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, make sure that the value of Charset contains Lower\ncase.\nUsing the CLI:\naliyun ram GetPasswordPolicy\nIn the output, make sure that the RequireLowercaseCharacters parameter is set to\ntrue.",
    "expected_response": "Perform the following to ensure the password policy is configured as expected:\nIn the output, make sure that the RequireLowercaseCharacters parameter is set to",
    "remediation": "Perform the following to set the password policy as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, click Modify.\n4. In the Charset section, select Upper case.\n5. Click OK.\nUsing the CLI:\naliyun ram SetPasswordPolicy --RequireLowercaseCharacters true",
    "default_value": "The default password policy does not enforce any Charset in a password.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/116413.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 34,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.9",
    "title": "Ensure RAM password policy require at least one symbol",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Use Unique Passwords",
    "description": "RAM password policies can be used to ensure password complexity. It is recommended\nthat the password policy require at least one symbol.",
    "rationale": "Enhancing complexity of a password policy increases account resiliency against brute\nforce logon attempts.",
    "audit": "Perform the following to ensure the password policy is configured as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, make sure that the value of Charset contains Symbol.\nUsing the CLI:\naliyun ram GetPasswordPolicy\nIn the output, make sure that the RequireSymbols parameter is set to true.",
    "expected_response": "Perform the following to ensure the password policy is configured as expected:\nIn the output, make sure that the RequireSymbols parameter is set to true.",
    "remediation": "Perform the following to set the password policy as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, click Modify.\n4. In the Charset section, select Symbol.\n5. Click OK.\nUsing the CLI:\naliyun ram SetPasswordPolicy --RequireSymbols true",
    "default_value": "The default password policy does not enforce any Charset in a password.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/116413.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 36,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.10",
    "title": "Ensure RAM password policy require at least one number",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Use Unique Passwords",
    "description": "RAM password policies can be used to ensure password complexity. It is recommended\nthat the password policy require at least one number.",
    "rationale": "Enhancing complexity of a password policy increases account resiliency against brute\nforce logon attempts.",
    "audit": "Perform the following to ensure the password policy is configured as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, make sure that the value of Charset contains Number.\nUsing the CLI:\naliyun ram GetPasswordPolicy\nIn the output, make sure that the RequireNumbers parameter is set to true.",
    "expected_response": "Perform the following to ensure the password policy is configured as expected:\nIn the output, make sure that the RequireNumbers parameter is set to true.",
    "remediation": "Perform the following to set the password policy as expected:\nUsing the management console\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, click Modify.\n4. In the Charset section, select Number.\n5. Click OK.\nUsing the CLI\naliyun ram SetPasswordPolicy --RequireNumbers true",
    "default_value": "The default password policy does not enforce any charset in a password.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/116413.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 38,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.11",
    "title": "Ensure RAM password policy requires minimum length of 14 or greater",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Use Unique Passwords",
    "description": "RAM password policies can be used to ensure password complexity. It is recommended\nthat the password policy require a minimum of 14 or greater characters for any\npassword.",
    "rationale": "Enhancing complexity of a password policy increases account resiliency against brute\nforce logon attempts.",
    "audit": "Perform the following to ensure the password policy is configured as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, make sure that the value of Length is a value of 14 to\n32.\nUsing the CLI:\naliyun ram GetPasswordPolicy\nIn the output, make sure that the MinimumPasswordLength parameter is set to 14 or a\ngreater number.",
    "expected_response": "Perform the following to ensure the password policy is configured as expected:\nIn the output, make sure that the MinimumPasswordLength parameter is set to 14 or a",
    "remediation": "Perform the following to set the password policy:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, click Modify.\n4. In the Length section, enter 14 or a greater number.\n5. Click OK.\nUsing the CLI\naliyun ram SetPasswordPolicy --MinimumPasswordLength 14",
    "default_value": "The default password policy requires a minimum of 8 characters for a password.",
    "additional_information": "The value range of Password Retry Constraint Policy is from 0 to 32.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/116413.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 40,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.12",
    "title": "Ensure RAM password policy prevents password reuse",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Use Unique Passwords",
    "description": "It is recommended that the password policy prevent the reuse of passwords.",
    "rationale": "Preventing password reuse increases account resiliency against brute force logon\nattempt.",
    "audit": "Perform the following to ensure the password policy is configured as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, make sure that the value of Do Not Repeat History\nis set to 5.\nUsing the CLI:\naliyun ram GetPasswordPolicy\nIn the output, make sure that the PasswordReusePrevention parameter is set to 5.",
    "expected_response": "Perform the following to ensure the password policy is configured as expected:\nis set to 5.\nIn the output, make sure that the PasswordReusePrevention parameter is set to 5.",
    "remediation": "Perform the following to set the password policy as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, click Modify.\n4. In the Do Not repeat History section field, enter '5'.\n5. Click OK.\nUsing the CLI:\naliyun ram SetPasswordPolicy --PasswordReusePrevention 5",
    "default_value": "The default password policy does not prevent password reuse.",
    "additional_information": "The value range of Password History Check Policy is from 0 to 24.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/116413.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
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
    "cis_id": "1.13",
    "title": "Ensure RAM password policy expires passwords in 365 days or greater",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Use Unique Passwords",
    "description": "RAM password policies can require passwords to be expired after a given number of\ndays. It is recommended that the password policy expire passwords after 365 days or\ngreater.",
    "rationale": "To frequent password changes are more harmful than beneficial. They offer no\ncontainment benefits and enforce bad habits—since they encourage users to choose\nvariants of older passwords. In an effort to scale back, the CIS now recommends an\nannual password reset. Users inevitably share credentials between accounts, and this\nmeasure causes minimal burden.\nThis compliments other industry best practices that call for password to \"be changed\nonly when there's a confirmed or suspected breach.\"",
    "audit": "Perform the following to ensure the password policy is configured as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, make sure that the value of Max Age is either disabled\nor greater than 365.\nUsing the CLI:\naliyun ram GetPasswordPolicy\nIn the output, make sure that the MaxPasswordAge parameter is set to <365> or a\ngreater number.",
    "expected_response": "Perform the following to ensure the password policy is configured as expected:\nIn the output, make sure that the MaxPasswordAge parameter is set to <365> or a",
    "remediation": "Perform the following to set the password policy as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Setting.\n3. In the Password section, click Modify.\n4. check the box under Max Age, enter 365 or a greater number up to 1095.\n5. Click OK.\nUsing the CLI:\naliyun ram SetPasswordPolicy --MaxPasswordAge 365",
    "default_value": "The default password policy does not define max age.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/116413.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 44,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.14",
    "title": "Ensure RAM password policy temporarily blocks logon after 5 incorrect logon attempts within an hour",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Use Unique Passwords",
    "description": "RAM password policies can temporarily block logon after several incorrect logon\nattempts within an hour. It is recommended that the password policy is set to\ntemporarily block logon after 5 incorrect logon attempts within an hour.",
    "rationale": "Temporarily blocking logon for incorrect password input increases account resiliency\nagainst brute force logon attempts.",
    "audit": "Perform the following to ensure the password policy is configured as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, make sure that the value of Max Attempts is 5.\nUsing the CLI:\naliyun ram GetPasswordPolicy\nIn the output, make sure that the MaxLoginAttemps parameter is set to <5>.",
    "expected_response": "Perform the following to ensure the password policy is configured as expected:\nIn the output, make sure that the MaxLoginAttemps parameter is set to <5>.",
    "remediation": "Perform the following to set the password policy as expected:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Settings.\n3. In the Password section, click MOdify.\n4. In the Max Attempts field, Check the box next to Enable and enter 5 in the field.\n5. Click OK.\nUsing the CLI:\naliyun ram SetPasswordPolicy --MaxLoginAttemps 5",
    "default_value": "The default password policy does not define Max Attempts.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/116413.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 46,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.15",
    "title": "Ensure RAM policies that allow full \"*:*\" administrative privileges are not created",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "incorrect_logon_attempts_within_an_hour_automated",
    "domain": "incorrect logon attempts within an hour (Automated)",
    "description": "RAM policies represent permissions that can be granted to users, groups, or roles. It is\nrecommended and considered a standard security advice to grant least privilege—that\nis, granting only the permissions required to perform tasks. Determine what users need\nto do and then create policies with permissions only fits those tasks, instead of allowing\nfull administrative privileges.",
    "rationale": "It is more secure to start with a minimum set of permissions and grant additional\npermissions as necessary, rather than starting with permissions that exceed the\nnecessity and then trying to tighten them later.\nProviding full administrative privileges exposes your resources on Alibaba Cloud to\npotentially unwanted actions.\nRAM policies that have a statement with \"Effect\": \"Allow\", \"Action\": \"*\", and\n\"Resource\": \"*\" should be prohibited.",
    "impact": "If you edit the policy document, or remove all references from the policy, the identities\nusing this policy may encounter access denied errors for the actions and resources that\nare not covered by their current permissions.",
    "audit": "Perform the following to check what permissions are allowed inside a policy:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Permissions > Policies.\n3. From the Policy Type drop-down list, select Custom Policy.\n4. In the Policy Name column, click the name of each policy.\n5. In the Policy Document section, make sure that no policy has a statement that\nincludes \"Effect\": \"Allow\", \"Action\": \"*\", and \"Resource\": \"*\", or\nany policy with such statement is not attached to any RAM identities (including\nRAM user, group, or role).\nUsing the CLI:\n1. Run the following command to obtain a list of policies\naliyun ram ListPolicies --PolicyType Custom\n2. For each policy returned, run the following command to determine if any policies\nallow full administrative privileges:\naliyun ram GetPolicy --PolicyName <policy_name> --PolicyType Custom\nNote: In the preceding command, policy_name is the value of the PolicyName\nparameter in each policy the ListPolicies command returned.\nIn the output, check the value of PolicyDocument under DefaultPolicyVersion to make\nsure that no policy has a statement that includes \"Effect\": \"Allow\", \"Action\":\n\"*\", and \"Resource\": \"*\", or make sure that the value of AttachmentCount under\nPolicy is set to 0 for such policies.",
    "expected_response": "In the output, check the value of PolicyDocument under DefaultPolicyVersion to make\nPolicy is set to 0 for such policies.",
    "remediation": "Perform the following to detach the policy that has full administrative privileges and\nremove them:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Permissions > Policies.\n3. From the Policy Type drop-down list, select Custom Policy.\n4. In the Policy Name column, click the name of the target policy.\n5. In the Policy Document section, check whether the policy has a statement that\nincludes \"Effect\": \"Allow\", \"Action\": \"\", and \"Resource\": \"\".\no If it does not, skip this section.\no If it does, edit the policy to remove such statement or remove the policy\nfrom any RAM users, user groups, or roles that have this policy attached.\n- To edit the policy:\na. On the Policy Document tab, click Modify Policy Document.\nb. Remove the entire “Statement” element which contains the full :\nadministrative privilege, or modify it to a\nsmaller permission.\n- To remove all references from the policy:\na. Go to the References tab, review if there is any reference of the\ncustom policy.\nb. For each reference, click Revoke Permission.\n6. Click OK.\nUsing the CLI:\n1. Run the following command to list all RAM users, groups, and roles to which the\nspecified policy (i.e. policy with .) is attached:\naliyun ram ListEntitiesForPolicy --PolicyName <policy_name> --PolicyType\nCustom\n2. Run the following command to detach the policy from all RAM users:\naliyun ram DetachPolicyFromUser --PolicyName <policy_name> --PolicyType\nCustom --UserName <ram_user >\n3. Run the following command to detach the policy from all RAM user groups:\naliyun ram DetachPolicyFromGroup --PolicyName <policy_name> --PolicyType\nCustom --GroupName <ram_group>\n4. Run the following command to detach the policy from all RAM roles:\naliyun ram DetachPolicyFromRole --PolicyName <policy_name> --PolicyType\nCustom --RoleName <ram_role>",
    "default_value": "By default, no custom policy is created.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/93733.htm",
      "2. https://www.alibabacloud.com/help/doc-detail/116803.htm",
      "3. https://www.alibabacloud.com/help/doc-detail/116818.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 48,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.16",
    "title": "Ensure RAM policies are attached only to groups or roles",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "incorrect_logon_attempts_within_an_hour_automated",
    "domain": "incorrect logon attempts within an hour (Automated)",
    "subdomain": "Restrict Administrator Privileges to Dedicated",
    "description": "By default, RAM users, groups, and roles have no access to Alibaba Cloud resources.\nRAM policies are the means by which privileges are granted to users, groups, or roles.\nIt is recommended that RAM policies be applied directly to groups and roles but not\nusers.",
    "rationale": "Assigning privileges at the group or role level reduces the complexity of access\nmanagement as the number of users grows. Reducing access management complexity\nmay in-turn reduce opportunity for a principal to inadvertently receive or retain\nexcessive privileges.",
    "impact": "There may be cases that a user needs to have permissions that cannot be covered by\nthe groups it joins or roles it can assume. It may still be needed to attach specific\npolicies to RAM users for certain operation that cannot be grouped with other\npermission under role or group.",
    "audit": "Perform the following to determine if policies are attached directly to users:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Identities > Users.\n3. In the User Logon Name/Display Name column, click the username of each\nRAM user.\n4. Click the Permissions tab.\n5. On the Individual tab, make sure that no policy exists.\nUsing the CLI:\n1. Run the following command to obtain a list of RAM users:\naliyun ram ListUsers\n2. For each user returned, run the following command to determine if any policies\nare attached to the user:\naliyun ram ListPoliciesForUser --UserName <ram_user>\nIf any polices are returned, the user has a direct policy attached.",
    "remediation": "Perform the following to create a RAM user group and assign a policy to it:\nUsing the management console:\n1. Log on to RAM console.\n2. Choose Identities > Users.\n3. Click Create Group, and enter the group name, display name, and description.\n4. Click OK.\n5. In the Group Name/Display Name column, find the target RAM user group and\nclick Add Permissions.\n6. In the Select Policy section, select the target policy or policies and click OK.\nUsing the CLI:\n1. Run the following command to create a RAM user group:\naliyun ram CreateGroup –GroupName <ram_user_group>\n2. Run the following command to attach a policy to the group:\naliyun ram AttachPolicyToGroup --GroupName <ram_user_group> --PolicyName\n<policy_name> --PolicyType <System|Custom>\nPerform the following to add a user to a given group:\nUsing the management console:\n1. Log on to RAM console.\n2. Choose Identities > Groups.\n3. In the Group Name/Display Name column, find the target RAM user group and\nclick Add Group Members.\n4. In the User section, select the target RAM user and click OK.\nUsing the CLI:\nRun the following command to add a RAM user to a user group:\naliyun ram AddUserToGroup --GroupName <ram_user_group> --UserName <ram_user >\nPerform the following to remove a direct association between a user and policy:\nUsing the management console:\n1. Logon to RAM console.\n2. Choose Permissions > Grants.\n3. In the Principal column, find the target RAM user and click Revoke\nPermission.\n4. Click OK.\nUsing the CLI:\nRun the following command to remove a policy from a RAM user:\naliyun ram DetachPolicyFromUser --PolicyName <policy_name> --PolicyType\n<System|Custom> --UserName <ram_user >",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/116809.htm",
      "2. https://www.alibabacloud.com/help/doc-detail/116815.htm",
      "3. https://www.alibabacloud.com/help/doc-detail/116147.htm",
      "4. https://www.alibabacloud.com/help/doc-detail/116820.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 51,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "2.1",
    "title": "Ensure that ActionTrail are configured to export copies of all Log entries",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "description": "ActionTrail is a web service that records API calls for your account and delivers log files\nto you. The recorded information includes the identity of the API caller, the time of the\nAPI call, the source IP address of the API caller, the request parameters, and the\nresponse elements returned by the Alibaba Cloud service. ActionTrail provides a history\nof API calls for an account, including API calls made via the Management Console,\nSDKs, command line tools.",
    "rationale": "The API call history produced by ActionTrail enables security analysis, resource change\ntracking, and compliance auditing. Moreover, ensuring that a multi-regions trail exists\nwill ensure that any unexpected activities occurring in otherwise unused regions are\ndetected. Global Service Logging should be enabled by default to capture recording of\nevents generated on Alibaba Cloud global services for a multi-regions trail, therefore,\nensuring the recording of management operations that are performed on all resources\nin an Alibaba Cloud account.",
    "impact": "OSS lifecycle features can be used to manage the accumulation and management of\nlogs over time. See the following resource for more information on these features:\nhttp://help.aliyun.com/document_detail/31863.html",
    "audit": "Perform the following to determine if ActionTrail is enabled for all regions:\nUsing the management Console:\n1. Logon to ActionTrail Console.\n2. Click on Trails on the left navigation pane, you will be presented with a list of\ntrails across all regions.\n3. Ensure at least one Trail has All specified in the Region column.\n4. Click on a trail via the link in the Name column.\n5. Ensure Logging is set to Enable to export log copies to OSS for storage.\n6. Ensure Yes is selected for Apply Trail to All Regions.\nUsing CLI:\nEnsure Trail is set to enable and Trail Region is set to All\naliyun actiontrail DescribeTrails",
    "expected_response": "Perform the following to determine if ActionTrail is enabled for all regions:\n3. Ensure at least one Trail has All specified in the Region column.\n5. Ensure Logging is set to Enable to export log copies to OSS for storage.\n6. Ensure Yes is selected for Apply Trail to All Regions.\nEnsure Trail is set to enable and Trail Region is set to All",
    "remediation": "Perform the following to enable global (Multi-region) ActionTrail logging:\nUsing the management Console:\n1. Logon to ActionTrail Console.\n2. Click on Trails on the left navigation pane.\n3. Click Add new trail.\na. Enter a trail name in the Trail name box.\nb. Set Yes for Apply Trail to All Regions.\nc. Specify an OSS bucket name in the OSS bucket box.\nd. Specify an SLS project name in the SLS project box.\ne. Click Create.\nUsing CLI:\naliyun actiontrail CreateTrail --Name <trail_name> --OssBucketName\n<oss_bucket_for_actiontrail> --RoleName aliyunactiontraildefaultrole\n--SlsProjectArn <sls_project_arn_for_actiontrail> --SlsWriteRoleArn\n<sls_role_arn_for_actiontrail> --EventRW <api_type_for_actiontrail>\naliyun actiontrail UpdateTrail --Name <trail_name> --OssBucketName\n<oss_bucket_for_actiontrail> --RoleName aliyunactiontraildefaultrole\n--SlsProjectArn <sls_project_arn_for_actiontrail> --SlsWriteRoleArn\n<sls_role_arn_for_actiontrail> --EventRW <api_type_for_actiontrail>",
    "default_value": "By default, there are no trails configured. Once the trail is enabled, it applies to all\nregions by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/28829.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 55,
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
    "cis_id": "2.2",
    "title": "Ensure the OSS used to store ActionTrail logs is not publicly accessible",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Ensure adequate storage for logs",
    "description": "ActionTrail logs a record of every API call made in your Alibaba Cloud account. These\nlogs file are stored in an OSS bucket. It is recommended that the access control list\n(ACL) of the OSS bucket, which ActionTrail logs to, shall prevent public access to the\nActionTrail logs.",
    "rationale": "Allowing public access to ActionTrail log content may aid an adversary in identifying\nweaknesses in the affected account's use or configuration.",
    "audit": "Perform the following to determine if any public access is granted to an OSS bucket via\nan\nACL:\nUsing the Management Console:\n1. Logon to ActionTrail Console.\n2. In the API activity history pane on the left, click Trails.\n3. In the Trails pane, note the bucket names in the OSS bucket column.\n4. Log on to OSS Console.\n5. For each bucket noted in step 3, click on the bucket and click Basic Settings.\n6. In the Access Control List pane, click the Configure.\n7. The Bucket ACL tab shows three kind of grants, Private Public Read, Public\nRead/Write.\n8. Ensure Private be set to the bucket.\nUsing CLI:\n1. Get the name of the OSS bucket that ActionTrail is logging to:\naliyuncli actiontrail DescribeTrails\n2. Ensure the Bucket ACL is to be set private:\nossutil set-acl oss://<bucketName> private -b",
    "expected_response": "8. Ensure Private be set to the bucket.\n2. Ensure the Bucket ACL is to be set private:",
    "remediation": "Perform the following to remove any public access that has been granted to the bucket\nvia an ACL:\nUsing the Management Console:\n1. Logon to OSS Console.\n2. Right on the bucket and click Basic Settings.\n3. In the Access Control List pane, click the Configure.\n4. The Bucket ACL tab shows three kind of grants. Like Private, Public Read,\nPublic Read/Write.\n5. Ensure Private be set to the bucket.\n6. Click Save to save the ACL.",
    "default_value": "By default, OSS buckets are not publicly accessible.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://help.aliyun.com/document_detail/31954.html"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 58,
    "dspm_relevant": true,
    "dspm_categories": [
      "access",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.3",
    "title": "Ensure audit logs for multiple cloud resources are integrated with Log Service",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Conduct Audit Log Reviews",
    "description": "Log Service provides functions of log collection and analysis in real time across multiple\ncloud resources under the authorized resource owners. This enable the large-scale\ncorporate for security governance over all resources owned by multiple accounts by\nintegrating the log from different sources and monitoring. For example, Log Service\nsupports the integration to collect logs from the following sources:\n• ActionTrail is a cloud service that records API calls made in a given Alibaba\nCloud account.\n• ApsaraDB RDS and DRDS audit records all data manipulation language (DML)\nand data definition language (DDL) operations through network protocol analysis\nand only consumes a small amount of CPU resources. The Trial Edition of SQL\nExplorer retains SQL log data generated within up to one day free of charge.\n• Object Storage Service (OSS) support recording every changes to its resources\nincluding bucket, ACL, replications, and files, as well as file access logs.\n• The access log feature of SLB can be applied to HTTP- and HTTPS-based Layer\n7 load balancing. Access logs can contain about 30 fields such as the time when\na request is received, the IP address of the client, processing latency, request\nURI, backend server (ECS instance) address, and returned status code. As an\nInternet access point, SLB needs to distribute a large number of access\nrequests.\n• Alibaba Cloud API Gateway provides API hosting service to facilitate micro-\nservice aggregation, frontend and backend isolation, and system integration.\nEach API request corresponds to an access record, which contains information\nsuch as the IP address of the API caller, requested URL, response latency,\nreturned status code, and number of bytes for each request and response. With\nthe preceding information, you can understand the operating status of your web\nservices.\n• NAS audit and access log support to record each request to Network File System\n(NFS) file system including file changes and access, details of the access\nrequest, such as the operation type, target object, and response status of the\ncurrent user. Log Service also provides rich functions such as real-time query\nand analysis, and dashboard presentation for this part of logs.",
    "rationale": "Sending the audit logs to Log Service will facilitate real-time and historic activity logging\nbased on user, API, resource, and IP address, and provides benefits to collect logs\nunder multiple accounts, store logs centrally, establish alarms and notifications for\nanomalous or sensitivity account activity, and extend the default log retention period to\n180 days.",
    "impact": "RDS Audit Log integration requires to enable SQL Explorer feature on RDS side, which\nmay introduce extra charge.",
    "audit": "Perform the following to ensure the logs are integrated with Log Services:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail, RDS SQL Audit Logs, OSS Access Logs, SLB\nAccess Log, NAS Access Log, API Gateway Access log are Enabled under\nthe Access to Cloud Products > Global Configuration page.\n4. Ensure all resource owners account are tracked under the Multi-Account\nConfigurations > Global Configuration page.\n5. Ensure the Status is Green under the Access to Cloud Products > Status\nDashboard page.",
    "expected_response": "Perform the following to ensure the logs are integrated with Log Services:\n3. Ensure the Action Trail, RDS SQL Audit Logs, OSS Access Logs, SLB\n4. Ensure all resource owners account are tracked under the Multi-Account\n5. Ensure the Status is Green under the Access to Cloud Products > Status",
    "remediation": "Perform the following to ensure the logs are integrated with Log Services:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the appropriate product logging selection, such as Action Trail, RDS\nSQL Audit Logs, OSS Access Logs, SLB Access Log, NAS Access Log, API\nGateway Access log and configure a proper storage period (in days).\nc. Click Save to save the changes.\n4. Go to Multi-Account Configurations > Global Configuration page.\na. Modify it to input the other resource owner account ID.\nb. Click Save to save the changes.\n5. Go to Access to Cloud Products > Status Dashboard page to ensure the\nStatus is Green.",
    "default_value": "Not enabled.",
    "additional_information": "1. Multi-Account configurations enable to collect audit logs into one log store under\none central account.\n2. If you configure log collection for the first time, please authorize Log Service\nupon the prompts on the user console page. The authorization enables Log\nService to distribute product audit related logs to your Logstore.\n3. If you configure log collection for a specific resource owner in Multi-Account page\nfor the first time, please authorize between the current resource owner and the\nother resource owner by referring to the guide from the reference page below.\n4. After changes to the configuration, The Status will become either Green, Red or\nOrange in several minutes. Refresh the page to check the latest status. If it’s not\nGreen, please refer to the guide from the reference page below.\n5. RDS Audit Logs collection only support specific regions for certain types of RDS,\nplease refer to the guide from the reference page below.\n6. Audit log collection by Log Service is from the time when you enable the Audit\nLog function on Log Service. It does not support historical audit log collection to\ntrace back the audit log records before Audit Log function on Log Service is\nenabled.\n7. The audit log collection for newly created instance are automatically enabled\nonce the instance is created by default for NAS and API Gateway. However it\nmay delay several minutes for RDS and SLB audit logs collection.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/84920.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 60,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "backup",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.4",
    "title": "Ensure Log Service is enabled for Container Service for Kubernetes",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Central Log Management",
    "description": "Log Service shall be connected with Kubernetes clusters of Alibaba Cloud Container\nService to collect the audit log for central monitoring and analysis. You can simply\nenable Log Service when creating a cluster for log collection.",
    "rationale": "By enabling Log Service Audit Log function to integrate audit log of Kubernetes, it is\npossible to capture all events on container to improve the security of serverless cluster.\nCentral log collection and monitoring allows access to all log information on one\ndashboard which can be useful in security and incident response workflows.",
    "audit": "Perform the following to ensure the Kubernetes logs are integrated with Log Services:\n1. Logon to ACK Console.\n2. Click Cluster > Clusters in the left-side navigation pane and select a cluster\nto click Action > Manage.\n3. Ensure the Cluster Auditing page is available.",
    "expected_response": "Perform the following to ensure the Kubernetes logs are integrated with Log Services:\n3. Ensure the Cluster Auditing page is available.",
    "remediation": "Perform the following ensure the Log Service for Kubernetes clusters is enabled:\n1. Logon to ACK Console.\n2. Click Clusters in the left-side navigation pane and click Create Kubernetes\nCluster in the upper-right corner.\n3. Scroll to the bottom of the page and select the Using Log Service check box.\nThe log plug-in will be installed in the newly created Kubernetes cluster.\n4. When you select the Using Log Service check box, project options are\ndisplayed. A project is the unit in Log Service to manage logs.\n5. After you complete the configuration, click Create in the upper-right corner.\n6. In the displayed dialog box, click OK.",
    "default_value": "Logging is disabled.",
    "additional_information": "It’s highly recommended to enable the log service when creating a cluster. If it's not\nenabled, a relative complex set of steps needs to be followed in order to enable the log\nservice. Please refer to https://www.alibabacloud.com/help/doc-detail/87540.htm for\nmore detail.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/87540.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 64,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.5",
    "title": "Ensure virtual network flow log service is enabled",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enforce Detail Logging for Access or Changes to",
    "description": "The flow log can be used to capture the traffic of an Elastic Network Interface (ENI),\nVirtual Private Cloud (VPC) or Virtual Switch (VSwitch). The flow log of a VPC or\nVSwitch shall be integrated with Log Service to capture the traffic of all ENIs in the VPC\nor VSwtich including the ENIs created after the flow log function is enabled. The traffic\ndata captured by flow logs is stored in Log Service for real-time monitoring and analysis.\nA capture window is about 10 minutes, during which the traffic data is aggregated and\nthen released to flow log record.",
    "rationale": "By integrating virtual network flow log to Log Service, the inbound and outbound traffic\nover the ENI in your VPC is captured for monitoring and analysis which can be useful in\nmonitoring network traffic and access control rules as well as network trouble shooting.",
    "audit": "Perform the following ensure the virtual network flow log is enabled:\n1. Logon to VPC console.\n2. In the left-side navigation pane, click FlowLog.\n3. Select the region to which the target flow log belongs.\n4. On the FlowLog page, ensure the target flow log and logstore is configured.",
    "expected_response": "Perform the following ensure the virtual network flow log is enabled:\n4. On the FlowLog page, ensure the target flow log and logstore is configured.",
    "remediation": "Perform the following ensure the virtual network flow log is enabled:\n1. Logon to VPC console.\n2. In the left-side navigation pane, click FlowLog.\n3. Select the region to which the flow log is to be created.\n4. On the FlowLog page, click Create FlowLog.\n5. On the Create FlowLog page, set the required parameters by following the\ninstruction, and then click OK.",
    "default_value": "Logging is disabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/90628.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 66,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "2.6",
    "title": "Ensure Anti-DDoS access and security log service is enabled",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "Alibaba Cloud Anti-DDoS Pro supports integration with Log Service for website access\nlog (including HTTP flood attack logs) to enable the real-time analysis and reporting\ncenter features. The log collected can be monitored on a central dashboard on Log\nService.",
    "rationale": "By integrating Anti-DDoS access and security log to Log Service, the website access\nlog and flood attack logs can be collected and monitored to enable real-time query and\nimprove the network security.",
    "impact": "Extra charge will incur.",
    "audit": "Perform the following ensure the Anti-DDoS access and security log is enabled:\n1. Logon to Anti-DDoS Pro Console, and go to the Log > Full Log page.\n2. Select the specific website.\n3. Ensure the Log Collection is turned on.\n4. Ensure the log volume usage indicator is sufficient for log storage.",
    "expected_response": "Perform the following ensure the Anti-DDoS access and security log is enabled:\n3. Ensure the Log Collection is turned on.\n4. Ensure the log volume usage indicator is sufficient for log storage.",
    "remediation": "Perform the following ensure the Anti-DDoS access and security log is enabled:\n1. Logon to Anti-DDoS Pro Console, and go to the Log > Full Log page.\n2. Select the specific website for which you want to enable the Full Log service\nand click to turn on the Status switch.",
    "default_value": "Logging is disabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/85007.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 68,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "2.7",
    "title": "Ensure Web Application Firewall access and security log service is enabled",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "Log Service collects log entries that record visits to and attacks on websites that are\nprotected by Alibaba Cloud Web Application Firewall (WAF), and supports real-time log\nquery and analysis. The query results are centrally displayed in dashboards.",
    "rationale": "The WAF access and security log shall be enabled to enable timely analytical\ninvestigation on visits to and attacks on your websites and help security engineers to\ndevelop protection strategies.",
    "impact": "Extra charge will incur by enabling the log.",
    "audit": "Perform the following ensure the WAF access and security log is enabled:\n1. Logon to WAF Console.\n2. Choose App Market > App Management.\n3. Click Configure in Real-time Log Query and Analysis Service.\n4. On Log Service page, select the specific domain name of your website.\n5. Ensure the Status switch on the right is turned on.\n6. Ensure the log volume usage indicator is sufficient for log storage.",
    "expected_response": "Perform the following ensure the WAF access and security log is enabled:\n5. Ensure the Status switch on the right is turned on.\n6. Ensure the log volume usage indicator is sufficient for log storage.",
    "remediation": "Perform the following ensure the Anti-DDoS access and security log is enabled:\n1. Logon to WAF Console.\n2. Choose App Market > App Management.\n3. Select the region where your WAF instance is located.\n4. Click Upgrade in Real-time Log Query and Analysis Service.\n5. Enable Log Service.\n6. Select the log storage period and the log storage size, and click Buy Now.\n7. Return to the WAF Console and choose App Market > App Management, and\nthen click Authorize in Real-time Log Query and Analysis Service.\n8. Click Agree to authorize WAF to write log entries to your exclusive logstore.\n9. Return to the WAF Console and choose App Market > App Management and\nthen, click Configure in Real-time Log Query and Analysis Service.\n10. On the Log Service page, select the domain name of your website that is\nprotected by WAF, and turn on the Status switch on the right to enable WAF Log\nService. These log entries can be queried and analyzed in real time.",
    "default_value": "Logging is disabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/95267"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 70,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.8",
    "title": "Ensure Cloud Firewall access and security log analysis is enabled",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "Log Service collects log entries of internet traffic that are protected by Cloud Firewall,\nand supports real-time log query and analysis. The query results are centrally displayed\nin dashboards.",
    "rationale": "The Cloud Firewall log shall be enabled with the Log Service to collect and store real-\ntime log of both inbound and outbound traffic for timely analysis, reports, alarms and\ndownstream computing interconnection and provides the detailed results displaying\ncentrally on dashboard to monitor and improve network security.",
    "impact": "Extra charge will incur by enabling the log.",
    "audit": "Perform the following ensure the Cloud Firewall access and security log is enabled:\n1. Logon to Cloud Firewall Console.\n2. In the left-side navigation pane, select Advanced Features > Log Analysis.\n3. Ensure the Status switch on the right side is enabled.\n4. Ensure the log volume usage indicator is not exhausted.",
    "expected_response": "Perform the following ensure the Cloud Firewall access and security log is enabled:\n3. Ensure the Status switch on the right side is enabled.\n4. Ensure the log volume usage indicator is not exhausted.",
    "remediation": "Perform the following ensure the Cloud Firewall access and security log is enabled:\n1. Logon to Cloud Firewall Console.\n2. In the left-side navigation pane, select Advanced Features > Log Analysis.\n3. Click Active Now on the Log Analysis page.\n4. Select your log storage capacity, and then click Pay to complete the\npayment.\n5. Go back to Log Analysis page on Cloud Firewall console.\n6. Click the Status on the right side to enable the Log Analysis service.",
    "default_value": "Logging is disabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/113184.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 72,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "2.9",
    "title": "Ensure Security Center Network, Host and Security log analysis is enabled",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "Log Service collects log entries of Security Center for security logs, network logs, and\nhost logs, with 14 subtypes, including\n1. Security logs\na. Vulnerability logs\nb. Baseline logs\nc. Security alerting logs\n2. Security logs\na. Vulnerability logs\nb. Baseline logs\nc. Security alerting logs\n3. Network logs\na. DNS logs\nb. Local DNS logs\nc. Network session logs\nd. Web logs\n4. Server logs\na. Process initiation logs\nb. Network connection logs\nc. System logon logs\nd. Brute-force cracking logs\ne. Process snapshots\nf. Account snapshots\ng. Port listening snapshots\nThe Log Service supports real-time log query and analysis over the logs mentioned\nabove. The query results are centrally displayed in dashboards.",
    "rationale": "The Security Center log shall be enabled to collect and store real-time security log,\nnetwork log and server log to better protect your assets in real time.",
    "impact": "Extra charge will incur by enabling the log.",
    "audit": "Perform the following ensure the Cloud Firewall access and security log is enabled:\n1. Logon to Security Center Console.\n2. In the left-side navigation pane, select Investigation > Log Analysis to\nenter the Activate Log Analysis page.\n3. In the Activate Log Analysis page, ensure the switch for the specific log type\nare turned on.\n4. Ensure the log volume usage indicator is not exhausted.",
    "expected_response": "Perform the following ensure the Cloud Firewall access and security log is enabled:\n3. In the Activate Log Analysis page, ensure the switch for the specific log type\n4. Ensure the log volume usage indicator is not exhausted.",
    "remediation": "Perform the following ensure the Cloud Firewall access and security log is enabled:\n1. Logon to Security Center Console.\n2. In the left-side navigation pane, select Investigation > Log Analysis to\nenter the Activate Log Analysis page.\n3. Click Active Now on the Activate log Analysis page.\n4. On the Purchase page, check Full Log and configure some other settings as\nneeded.\n5. Click Purchase Now.\n6. In the Activate log Analysis click Activate log Analysis to complete the\nauthorization.\n7. In the log type menu, check the log types to enable the log collection.",
    "default_value": "Logging is disabled.",
    "additional_information": "Only Security Center Enterprise Edition supports full log service and provides features\nfor accurate real-time log querying and log analysis.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/93065.htm",
      "2. https://www.alibabacloud.com/help/doc-detail/93117.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 74,
    "dspm_relevant": true,
    "dspm_categories": [
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D3",
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.10",
    "title": "Ensure log monitoring and alerts are set up for RAM Role changes",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "It is recommended that a query and alarm should be established for RAM Role creation,\ndeletion and updating activities.",
    "rationale": "Alibaba Cloud Resource Access Management (RAM) provides predefined roles that\ngive granular access to specific resources and prevent unwanted access to other\nresources. Log Service provides ability to create custom monitoring query: monitoring\nrole creation, deletion and updating activities will help in identifying any potential\nmalicious actions at early stage.",
    "audit": "Perform the following to ensure the log monitoring and alerts are set up for RAM Role\nChanges:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\nGlobal Configuration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log\n(\"event.serviceName\": ResourceManager or \"event.serviceName\": Ram) and\n(\"event.eventName\": CreatePolicy or \"event.eventName\": DeletePolicy or\n\"event.eventName\": CreatePolicyVersion or \"event.eventName\":\nUpdatePolicyVersion or \"event.eventName\": SetDefaultPolicyVersion  or\n\"event.eventName\": DeletePolicyVersion) | select count(1) as c",
    "expected_response": "Perform the following to ensure the log monitoring and alerts are set up for RAM Role\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up for RAM Role\nChanges:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the Action Trail and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > Actiontrail Log.\n6. In the search/analytics console, input below query\n(\"event.serviceName\": ResourceManager or \"event.serviceName\": Ram) and\n(\"event.eventName\": CreatePolicy or \"event.eventName\": DeletePolicy or\n\"event.eventName\": CreatePolicyVersion or \"event.eventName\":\nUpdatePolicyVersion or \"event.eventName\": SetDefaultPolicyVersion  or\n\"event.eventName\": DeletePolicyVersion) | select count(1) as c\n7. Create a dashboard and set alert for the query result.",
    "default_value": "The monitoring dashboard and alert is not set by default",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/91784.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
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
    "cis_id": "2.11",
    "title": "Ensure log monitoring and alerts are set up for Cloud Firewall changes",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "It is recommended that a metric filter and alarm be established for Cloud Firewall rule\nchanges.",
    "rationale": "Monitoring for Create or Update firewall rule events gives insight network access\nchanges and may reduce the time it takes to detect suspicious activity.",
    "audit": "Perform the following to ensure the log monitoring and alerts are set up for Cloud\nFirewall Changes:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\nGlobal Configuration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log\n\"event.serviceName\": \"Cloudfw\" and (\"event.eventName\":\nCreateVpcFirewallControlPolicy or \"event.eventName\":\nDeleteVpcFirewallControlPolicy or \"event.eventName\":\nModifyVpcFirewallControlPolicy) | select count(1) as c",
    "expected_response": "Perform the following to ensure the log monitoring and alerts are set up for Cloud\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up Cloud Firewall\nChanges:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the Action Trail and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > Actiontrail Log.\n6. In the search/analytics console, input below query\n\"event.serviceName\": \"Cloudfw\" and (\"event.eventName\":\nCreateVpcFirewallControlPolicy or \"event.eventName\":\nDeleteVpcFirewallControlPolicy or \"event.eventName\":\nModifyVpcFirewallControlPolicy) | select count(1) as c\n7. Create a dashboard and set alert for the query result.",
    "default_value": "The monitoring dashboard and alert is not set by default",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/en/doc-detail/91784.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 79,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.12",
    "title": "Ensure log monitoring and alerts are set up for VPC network route changes",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "It is recommended that a metric filter and alarm be established for VPC network route\nchanges.",
    "rationale": "Routes define the paths network traffic takes from a VM instance to another\ndestinations. The other destination can be inside your VPC network (such as another\nVM) or outside of it. Every route consists of a destination and a next hop. Traffic whose\ndestination IP is within the destination range is sent to the next hop for delivery.\nMonitoring changes to route tables will help ensure that all VPC traffic flows through an\nexpected path.",
    "audit": "Perform the following steps to ensure log monitoring and alerts are set for VPC network\nroute changes.\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\nGlobal Configuration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log\n(\"event.serviceName\": Ecs or \"event.serviceName\": Vpc) and\n(\"event.eventName\": CreateRouteEntry or \"event.eventName\":\nDeleteRouteEntry or \"event.eventName\": ModifyRouteEntry or\n\"event.eventName\": AssociateRouteTable or \"event.eventName\":\nUnassociateRouteTable) | select count(1) as c",
    "expected_response": "Perform the following steps to ensure log monitoring and alerts are set for VPC network\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up for VPC\nnetwork route changes:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the Action Trail and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > Actiontrail Log.\n6. In the search/analytics console, input below query\n(\"event.serviceName\": Ecs or \"event.serviceName\": Vpc) and\n(\"event.eventName\": CreateRouteEntry or \"event.eventName\":\nDeleteRouteEntry or \"event.eventName\": ModifyRouteEntry or\n\"event.eventName\": AssociateRouteTable or \"event.eventName\":\nUnassociateRouteTable) | select count(1) as c\n7. Create a dashboard and set alert for the query result.",
    "default_value": "The monitoring dashboard and alert is not set by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/en/doc-detail/91784.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 81,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.13",
    "title": "Ensure log monitoring and alerts are set up for VPC changes",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "It is recommended that a log search/analysis query and alarm be established for VPC\nchanges.",
    "rationale": "Monitoring changes to VPC will help ensure VPC traffic flow is not getting impacted.",
    "audit": "Perform the following steps to ensure log monitoring and alerts are set for VPC\nchanges.\n1. Logon to the SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\nGlobal Configuration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log\n(\"event.serviceName\": Ecs or \"event.serviceName\": Vpc) and\n(\"event.eventName\": CreateVpc or \"event.eventName\": DeleteVpc or\n\"event.eventName\": DisableVpcClassicLink or \"event.eventName\":\nEnableVpcClassicLink or \"event.eventName\": DeletionProtection or\n\"event.eventName\": AssociateVpcCidrBlock or \"event.eventName\":\nUnassociateVpcCidrBlock or \"event.eventName\": RevokeInstanceFromCen or\n\"event.eventName\": CreateVSwitch or \"event.eventName\": DeleteVSwitch or\n\"event.eventName\": CreateVSwitch) | select count(1) as c",
    "expected_response": "Perform the following steps to ensure log monitoring and alerts are set for VPC\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up for VPC\nchanges:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the Action Trail and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > Actiontrail Log.\n6. In the search/analytics console, input below query\n(\"event.serviceName\": Ecs or \"event.serviceName\": Vpc) and\n(\"event.eventName\": CreateVpc or \"event.eventName\": DeleteVpc or\n\"event.eventName\": DisableVpcClassicLink or \"event.eventName\":\nEnableVpcClassicLink or \"event.eventName\": DeletionProtection or\n\"event.eventName\": AssociateVpcCidrBlock or \"event.eventName\":\nUnassociateVpcCidrBlock or \"event.eventName\": RevokeInstanceFromCen or\n\"event.eventName\": CreateVSwitch or \"event.eventName\": DeleteVSwitch or\n\"event.eventName\": CreateVSwitch) | select count(1) as c\n7. Create a dashboard and set alert for the query result.",
    "default_value": "The monitoring dashboard and alert is not set by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/en/doc-detail/91784.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 83,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.14",
    "title": "Ensure log monitoring and alerts are set up for OSS permission changes",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "It is recommended that a metric filter and alarm be established for OSS Bucket RAM\nchanges.",
    "rationale": "Monitoring changes to OSS permissions may reduce time to detect and correct\npermissions on sensitive OSS bucket and objects inside the bucket.",
    "audit": "Perform the following steps to ensure log monitoring and alerts are set for OSS\npermission changes.\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the OSS are Enabled under the Access to Cloud Products > Global\nConfiguration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target oss_log\n(operation:  PutBucket and request_uri: acl) or operation: PutObjectAcl|\nselect bucket, count (1) as c group by bucket",
    "expected_response": "Perform the following steps to ensure log monitoring and alerts are set for OSS\n3. Ensure the OSS are Enabled under the Access to Cloud Products > Global\n5. Ensure below alert rule has been enabled and saved in the target oss_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up for OSS\npermission changes:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the OSS and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > OSS Log.\n6. In the search/analytics console, input below query\n(operation:  PutBucket and request_uri: acl) or operation: PutObjectAcl|\nselect bucket, count (1) as c group by bucket\n7. Create a dashboard and set alert for the query result.",
    "default_value": "The monitoring dashboard and alert is not set by default.",
    "detection_commands": [
      "select bucket, count (1) as c group by bucket"
    ],
    "remediation_commands": [
      "select bucket, count (1) as c group by bucket"
    ],
    "references": [
      "1. https://www.alibabacloud.com/help/en/doc-detail/91784.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 85,
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
    "cis_id": "2.15",
    "title": "Ensure log monitoring and alerts are set up for RDS instance configuration changes",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "It is recommended that a metric filter and alarm be established for RDS Instance\nconfiguration changes.",
    "rationale": "Monitoring changes to RDS Instance configuration changes may reduce time to detect\nand correct misconfigurations done on database server.\nBelow are the few of configurable Options which may impact security posture of a RDS\nInstance:\n1. Enable auto backups and high availability: Misconfiguration may adversely\nimpact Business continuity, Disaster Recovery and High Availability.\n2. Authorize networks : Misconfiguration may increase exposure to the untrusted\nnetworks.",
    "audit": "Perform the following steps to ensure log monitoring and alerts are set for SQL instance\nconfiguration changes.\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\nGlobal Configuration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log\n\"event.serviceName\": rds and (\"event.eventName\": ModifyHASwitchConfig or\n\"event.eventName\": ModifyDBInstanceHAConfig or \"event.eventName\":\nSwitchDBInstanceHA or \"event.eventName\": ModifyDBInstanceSpec or\n\"event.eventName\": MigrateSecurityIPMode or \"event.eventName\":\nModifySecurityIps or \"event.eventName\": ModifyDBInstanceSSL or\n\"event.eventName\": MigrateToOtherZone or \"event.eventName\":\nUpgradeDBInstanceKernelVersion or \"event.eventName\":\nUpgradeDBInstanceEngineVersion or \"event.eventName\":\nModifyDBInstanceMaintainTime or \"event.eventName\":\nModifyDBInstanceAutoUpgradeMinorVersion or \"event.eventName\":\nAllocateInstancePublicConnection or \"event.eventName\":\nModifyDBInstanceConnectionString or \"event.eventName\":\nModifyDBInstanceNetworkExpireTime or \"event.eventName\":\nReleaseInstancePublicConnection or \"event.eventName\": SwitchDBInstanceNetType\nor \"event.eventName\": ModifyDBInstanceNetworkType or \"event.eventName\":\nModifyDBInstanceSSL or \"event.eventName\":\nModifyDTCSecurityIpHostsForSQLServer or \"event.eventName\":\nModifySecurityGroupConfiguration or \"event.eventName\": CreateBackup or\n\"event.eventName\": ModifyBackupPolicy or \"event.eventName\": DeleteBackup or\n\"event.eventName\": CreateDdrInstance or \"event.eventName\":\nModifyInstanceCrossBackupPolicy) | select count(1) as cnt",
    "expected_response": "Perform the following steps to ensure log monitoring and alerts are set for SQL instance\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up for RDS\ninstance configuration changes:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the Action Trail and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > Actiontrail Log.\n6. In the search/analytics console, input below query\n\"event.serviceName\": rds and (\"event.eventName\": ModifyHASwitchConfig or\n\"event.eventName\": ModifyDBInstanceHAConfig or \"event.eventName\":\nSwitchDBInstanceHA or \"event.eventName\": ModifyDBInstanceSpec or\n\"event.eventName\": MigrateSecurityIPMode or \"event.eventName\":\nModifySecurityIps or \"event.eventName\": ModifyDBInstanceSSL or\n\"event.eventName\": MigrateToOtherZone or \"event.eventName\":\nUpgradeDBInstanceKernelVersion or \"event.eventName\":\nUpgradeDBInstanceEngineVersion or \"event.eventName\":\nModifyDBInstanceMaintainTime or \"event.eventName\":\nModifyDBInstanceAutoUpgradeMinorVersion or \"event.eventName\":\nAllocateInstancePublicConnection or \"event.eventName\":\nModifyDBInstanceConnectionString or \"event.eventName\":\nModifyDBInstanceNetworkExpireTime or \"event.eventName\":\nReleaseInstancePublicConnection or \"event.eventName\": SwitchDBInstanceNetType\nor \"event.eventName\": ModifyDBInstanceNetworkType or \"event.eventName\":\nModifyDBInstanceSSL or \"event.eventName\":\nModifyDTCSecurityIpHostsForSQLServer or \"event.eventName\":\nModifySecurityGroupConfiguration or \"event.eventName\": CreateBackup or\n\"event.eventName\": ModifyBackupPolicy or \"event.eventName\": DeleteBackup or\n\"event.eventName\": CreateDdrInstance or \"event.eventName\":\nModifyInstanceCrossBackupPolicy) | select count(1) as cnt\n7. Create a dashboard and set alert for the query result.",
    "default_value": "The monitoring dashboard and alert is not set by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/en/doc-detail/91784.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 87,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
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
    "cis_id": "2.16",
    "title": "Ensure a log monitoring and alerts are set up for unauthorized API calls",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "Real-time monitoring of API calls can be achieved by directing ActionTrail Logs to\nLogService and establishing corresponding query and alarms. It is recommended that a\nquery and alarm be established for unauthorized API calls.",
    "rationale": "Monitoring unauthorized API calls will help reveal application errors and may reduce\ntime to detect malicious activity.",
    "audit": "Perform the following steps to ensure log monitoring and alerts are set for unauthorized\nAPI calls.\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\nGlobal Configuration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log\n\"event.eventType\": ApiCall and (\"event.errorCode\": \"NoPermission\" or\n\"event.errorCode\": \"NoPermission.*\" or \"event.errorCode\": \"Forbidden\" or\n\"event.errorCode\": \"Forbbiden\" or \"event.errorCode\": \"Forbidden.*\" or\n\"event.errorCode\": \"InvalidAccessKeyId\" or \"event.errorCode\":\n\"InvalidAccessKeyId.*\" or \"event.errorCode\": \"InvalidSecurityToken\" or\n\"event.errorCode\": \"InvalidSecurityToken.*\" or \"event.errorCode\":\n\"SignatureDoesNotMatch\" or \"event.errorCode\": \"InvalidAuthorization\" or\n\"event.errorCode\": \"AccessForbidden\" or \"event.errorCode\": “NotAuthorized\")\n| select count(1) as cnt",
    "expected_response": "Perform the following steps to ensure log monitoring and alerts are set for unauthorized\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up for unauthorized\nAPI calls:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the Action Trail and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > Actiontrail Log.\n6. In the search/analytics console, input below query\n\"event.eventType\": ApiCall and (\"event.errorCode\": \"NoPermission\" or\n\"event.errorCode\": \"NoPermission.*\" or \"event.errorCode\": \"Forbidden\" or\n\"event.errorCode\": \"Forbbiden\" or \"event.errorCode\": \"Forbidden.*\" or\n\"event.errorCode\": \"InvalidAccessKeyId\" or \"event.errorCode\":\n\"InvalidAccessKeyId.*\" or \"event.errorCode\": \"InvalidSecurityToken\" or\n\"event.errorCode\": \"InvalidSecurityToken.*\" or \"event.errorCode\":\n\"SignatureDoesNotMatch\" or \"event.errorCode\": \"InvalidAuthorization\" or\n\"event.errorCode\": \"AccessForbidden\" or \"event.errorCode\": \"NotAuthorized\")\n| select count(1) as cnt\n7. Create a dashboard and set alert for the query result.",
    "default_value": "The monitoring dashboard and alert is not set by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/en/doc-detail/91784.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 91,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.17",
    "title": "Ensure a log monitoring and alerts are set up for Management Console sign-in without MFA",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "Real-time monitoring of API calls can be achieved by directing ActionTrail Logs to Log\nService and establishing corresponding query and alarms. It is recommended that a\nquery and alarm be established for console logins that are not protected by multi-factor\nauthentication (MFA).",
    "rationale": "Monitoring for single-factor console logins will increase visibility into accounts that are\nnot protected by MFA.",
    "audit": "Perform the following steps to ensure log monitoring and alerts are set for Management\nConsole sign-in without MFA.\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\nGlobal Configuration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log\n\"event.eventName\": ConsoleSignin and \"addionalEventData.loginAccount\": false",
    "expected_response": "Perform the following steps to ensure log monitoring and alerts are set for Management\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up for\nManagement Console sign-in without MFA:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the Action Trail and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > Actiontrail Log.\n6. In the search/analytics console, input below query\n\"event.eventName\": ConsoleSignin and \"addionalEventData.loginAccount\": false\n7. Create a dashboard and set alert for the query result.",
    "default_value": "The monitoring dashboard and alert is not set by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/en/doc-detail/91784.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 94,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.18",
    "title": "Ensure a log monitoring and alerts are set up for usage of \"root\" account",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Enable Detailed Logging",
    "description": "Real-time monitoring of API calls can be achieved by directing ActionTrail Logs to Log\nService and establishing corresponding query and alarms. It is recommended that a\nquery and alarm be established for console logins that are not protected by root login\nattempts.",
    "rationale": "Monitoring for root account logins will provide visibility into the use of a fully privileged\naccount and an opportunity to reduce the use of it.",
    "audit": "Perform the following steps to ensure log monitoring and alerts are set for usage of\n“root” account.\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\nGlobal Configuration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log\n\"event.eventName\": ConsoleSignin and \"event.userIdentity.type\" : root-account",
    "expected_response": "Perform the following steps to ensure log monitoring and alerts are set for usage of\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up for usage of\n“root” account:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the Action Trail and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > Actiontrail Log.\n6. In the search/analytics console, input below query\n\"event.eventName\": ConsoleSignin and \"event.userIdentity.type\" : root-account\n7. Create a dashboard and set alert for the query result.",
    "default_value": "The monitoring dashboard and alert is not set by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/en/doc-detail/91784.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 96,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.19",
    "title": "Ensure a log monitoring and alerts are set up for Management Console authentication failures",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Log and Alert on Unsuccessful Administrative Account",
    "description": "Real-time monitoring of API calls can be achieved by directing ActionTrail Logs to Log\nService and establishing corresponding query and alarms. It is recommended that a\nquery and alarm be established for failed console authentication attempts.",
    "rationale": "Monitoring failed console logins may decrease lead time to detect an attempt to brute\nforce a credential, which may provide an indicator, such as source IP, that can be used\nin other event correlation.",
    "audit": "Perform the following steps to ensure log monitoring and alerts are set for Management\nConsole authentication failures.\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\nGlobal Configuration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log\n\"event.eventName\": ConsoleSignin and \"event.errorCode\" : *  and not\n\"event.errorCode\" : \"\" | select count(1) as cnt",
    "expected_response": "Perform the following steps to ensure log monitoring and alerts are set for Management\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up for\nManagement Console authentication failures:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the Action Trail and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > Actiontrail Log.\n6. In the search/analytics console, input below query\n\"event.eventName\": ConsoleSignin and \"event.errorCode\" : *  and not\n\"event.errorCode\" : \"\" | select count(1) as cnt\n7. Create a dashboard and set alert for the query result.",
    "default_value": "The monitoring dashboard and alert is not set by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/en/doc-detail/28810.htm",
      "2. https://www.alibabacloud.com/help/en/doc-detail/91784.htm",
      "3. https://www.alibabacloud.com/help/en/doc-detail/93517.html"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 98,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.20",
    "title": "Ensure a log monitoring and alerts are set up for disabling or deletion of customer created CMKs",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Log and Alert on Unsuccessful Administrative Account",
    "description": "Real-time monitoring of API calls can be achieved by directing ActionTrail Logs to Log\nService and establishing corresponding query and alarms. It is recommended that a\nquery and alarm be established for customer created KMSs which have changed state\nto disabled or deletion.",
    "rationale": "Data encrypted with disabled or deleted keys will no longer be accessible.",
    "audit": "Perform the following steps to ensure log monitoring and alerts are set for disabling or\ndeletion of customer created CMKs.\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\nGlobal Configuration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log\n\"event.serviceName\": Kms and (\"event.eventName\": DisableKey or\n\"event.eventName\": ScheduleKeyDeletion or \"event.eventName\":\nDeleteKeyMaterial",
    "expected_response": "Perform the following steps to ensure log monitoring and alerts are set for disabling or\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up for disabling or\nscheduled deletion of customer created CMKs:\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the Action Trail and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > Actiontrail Log.\n6. In the search/analytics console, input below query.\n\"event.serviceName\": Kms and (\"event.eventName\": DisableKey or\n\"event.eventName\": ScheduleKeyDeletion or \"event.eventName\":\nDeleteKeyMaterial\n7. Create a dashboard and set alert for the query result",
    "default_value": "The monitoring dashboard and alert is not set by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/en/doc-detail/91784.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 100,
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
    "cis_id": "2.21",
    "title": "Ensure a log monitoring and alerts are set up for OSS bucket policy changes",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Log and Alert on Unsuccessful Administrative Account",
    "description": "Real-time monitoring of API calls can be achieved by directing ActionTrail Logs to Log\nService and establishing corresponding query and alarms. It is recommended that a\nquery and alarm be established for changes to OSS bucket policies.",
    "rationale": "Monitoring changes to OSS bucket policies may reduce time to detect and correct\npermissive policies on sensitive OSS buckets.",
    "audit": "Perform the following steps to ensure log monitoring and alerts are set for OSS bucket\npolicy changes.\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\nGlobal Configuration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log\n\"event.eventName\": PutBucketLifecycle or \"event.eventName\": PutBucketPolicy\nor \"event.eventName\": PutBucketCors or \"event.eventName\": PutBucketEncryption\nor \"event.eventName\": PutBucketReplication or \"event.eventName\":\nDeleteBucketPolicy or \"event.eventName\": DeleteBucketCors or\n\"event.eventName\": DeleteBucketLifecycle or \"event.eventName\":\nDeleteBucketEncryption or \"event.eventName\": DeleteBucketReplication) |\nselect bucket, count(1) as cnt",
    "expected_response": "Perform the following steps to ensure log monitoring and alerts are set for OSS bucket\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up for OSS bucket\npolicy changes.\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the Action Trail and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > Actiontrail Log.\n6. In the search/analytics console, input below query.\n\"event.eventName\": PutBucketLifecycle or \"event.eventName\": PutBucketPolicy\nor \"event.eventName\": PutBucketCors or \"event.eventName\": PutBucketEncryption\nor \"event.eventName\": PutBucketReplication or \"event.eventName\":\nDeleteBucketPolicy or \"event.eventName\": DeleteBucketCors or\n\"event.eventName\": DeleteBucketLifecycle or \"event.eventName\":\nDeleteBucketEncryption or \"event.eventName\": DeleteBucketReplication) |\nselect bucket, count(1) as cnt\n7. Create a dashboard and set alert for the query result.",
    "default_value": "The monitoring dashboard and alert is not set by default.",
    "detection_commands": [
      "select bucket, count(1) as cnt"
    ],
    "remediation_commands": [
      "select bucket, count(1) as cnt"
    ],
    "references": [
      "1. https://www.alibabacloud.com/help/en/doc-detail/91784.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 102,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "retention",
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
    "cis_id": "2.22",
    "title": "Ensure a log monitoring and alerts are set up for security group changes",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Activate audit logging",
    "description": "Real-time monitoring of API calls can be achieved by directing ActionTrail Logs to Log\nService and establishing corresponding query and alarms. Security Groups are a\nstateful packet filter that controls ingress and egress traffic within a VPC. It is\nrecommended that a query and alarm be established changes to Security Groups.",
    "rationale": "Monitoring changes to security group will help ensure that resources and services are\nnot unintentionally exposed.",
    "audit": "Perform the following steps to ensure log monitoring and alerts are set for security\ngroup changes.\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane to go to the Log\nService Audit Service page.\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\nGlobal Configuration page, and click Central Project.\n4. Select Alerts.\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log\n(event_name: CreateSecurityGroup or event_name: AuthorizeSecurityGroup or\nevent_name: AuthorizeSecurityGroupEgress or event_name: RevokeSecurityGroup\nor event_name: RevokeSecurityGroupEgress or event_name: JoinSecurityGroup or\nevent_name: LeaveSecurityGroup or event_name: DeleteSecurityGroup or\nevent_name: ModifySecurityGroupPolicy) | select count(1) as cnt",
    "expected_response": "Perform the following steps to ensure log monitoring and alerts are set for security\n3. Ensure the Action Trail are Enabled under the Access to Cloud Products >\n5. Ensure below alert rule has been enabled and saved in the target actiontrail_log",
    "remediation": "Perform the following to ensure the log monitoring and alerts are set up for security\ngroup changes。\n1. Logon to SLS Console.\n2. Click Log Service Audit Service in the navigation pane.\n3. Go to Access to Cloud Products > Global Configuration page.\na. Select a location of project for logs.\nb. Check the Action Trail and configure a proper days.\nc. Click Save to save the changes.\n4. Go to Access to Cloud Products > Global Configurations click Central\nProject.\n5. Select Log Management > Actiontrail Log.\n6. In the search/analytics console, input below query.\n(event_name: CreateSecurityGroup or event_name: AuthorizeSecurityGroup or\nevent_name: AuthorizeSecurityGroupEgress or event_name: RevokeSecurityGroup\nor event_name: RevokeSecurityGroupEgress or event_name: JoinSecurityGroup or\nevent_name: LeaveSecurityGroup or event_name: DeleteSecurityGroup or\nevent_name: ModifySecurityGroupPolicy) | select count(1) as cnt\n7. Create a dashboard and set alert for the query result.",
    "default_value": "The monitoring dashboard and alert is not set by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/en/doc-detail/91784.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 104,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.23",
    "title": "Ensure that Logstore data retention period is set 365 days or greater",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Log and Alert on Changes to Administrative Group",
    "description": "Ensure Activity Log Retention is set for 365 days or greater",
    "rationale": "Logstore life cycle controls how your activity log is exported and retained. It is\nrecommended to retain your activity log for 365 days or more in order to have time to\nrespond to any incidents.",
    "audit": "Perform below steps to ensure the log retention is set to 365 days or greater.\n1. Logon to SLS Console.\n2. In the Projects section, click the target project name. On the page that appears,\nclick the plus sign (+) next to the search box.\n3. In the dialog box that appears, check whether the Permanent Storage is turned\non, which means the log data will be stored permanently, or else\n4. Ensure the Data Retention Period is set to 365 or greater.",
    "expected_response": "Perform below steps to ensure the log retention is set to 365 days or greater.\n4. Ensure the Data Retention Period is set to 365 or greater.",
    "remediation": "Perform below steps to ensure the log retention is set to 365 days or greater.\n1. Logon to SLS Console.\n2. Find the project in the Projects section, and then click the target project name.\n3. On the page that appears, click Modify a Logstore icon next to the Logstore,\nand then choose Modify.\n4. On the page that appears, click Modify, modify the Data Retention Period, to\n365 or greater and then click Save.",
    "default_value": "The Permanent Storage is turned off by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/48990.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 106,
    "dspm_relevant": true,
    "dspm_categories": [
      "retention"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D6"
    ]
  },
  {
    "cis_id": "3.1",
    "title": "Ensure legacy networks does not exist",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "networking",
    "domain": "Networking",
    "description": "In order to prevent use of legacy networks, ECS instances should not have a legacy\nnetwork configured.",
    "rationale": "Legacy networks have a single network IPv4 prefix range and a single gateway IP\naddress for the whole network. With legacy networks, you cannot create subnetworks or\nswitch from legacy to auto or custom subnet networks. Legacy networks can thus have\nan impact for high network traffic ECS instance and subject to the single point of failure.",
    "audit": "1. Logon to ECS Console\n2. In the left-side navigation pane, choose Instance & Image > Instances.\n3. Check all ECS instances to ensure the Network Type is not classic",
    "expected_response": "3. Check all ECS instances to ensure the Network Type is not classic",
    "remediation": "1. Logon to ECS Console\n2. In the left-side navigation pane, choose Instance & Image > Instances.\n3. Click Create Instance.\n4. Specify the basic instance information required by following the instruction and\nclick Next: Networking.\n5. Select the Network Type of VPC.",
    "default_value": "By default the ECS are created with VPC Network Type.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/87190.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 109,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.2",
    "title": "Ensure that SSH access is restricted from the internet",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Maintain Standard Security Configurations for",
    "description": "Security groups provide stateful filtering of ingress/egress network traffic to Alibaba\nCloud resources. It is recommended that no security group allows unrestricted ingress\naccess to port 22 or port 3389.",
    "rationale": "Removing unfettered connectivity to remote console services, such as SSH or RDP,\nreduces a server's exposure to risk.",
    "impact": "All SSH or RDP connections from outside of the network to the concerned VPC(s) will\nbe blocked. There could be a business need where ssh access is required from outside\nof the network to access resources associated with the VPC. In that case, specific\nsource IP(s) should be mentioned in firewall rules to white-list access to SSH or RDP\nport for the concerned VPC(s).",
    "audit": "1. Logon to ECS Console\n2. In the left-side navigation pane, choose Network & Security > Security\nGroups.\n3. Ensure Port is not equal to 22 or 3389 and Action is not Allow.\n4. Ensure IP Ranges is not equal to 0.0.0.0 under Source filters.",
    "expected_response": "3. Ensure Port is not equal to 22 or 3389 and Action is not Allow.\n4. Ensure IP Ranges is not equal to 0.0.0.0 under Source filters.",
    "remediation": "1. Logon to ECS Console\n2. Go to Security Group\n3. Find the Security Group you want to modify\n4. Modify Source IP range to specific IP\n5. Save",
    "default_value": "SSH connection is allowed by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/25475.htm",
      "2. https://www.alibabacloud.com/help/doc-detail/100380.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 111,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "3.3",
    "title": "Ensure VPC flow logging is enabled in all VPCs",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Deny Communication over Unauthorized Ports",
    "description": "You can use the flow log function to monitor the IP traffic information for an ENI, a\nVSwitch or a VPC. If you create a flow log for a VSwitch or a VPC, all the Elastic\nNetwork Interfaces, including the newly created Elastic Network Interfaces, are\nmonitored. Such flow log data is stored in Log Service, where you can view and analyze\nIP traffic information. It is recommended that VPC Flow Logs be enabled for packet\n\"Rejects\" for VPCs.",
    "rationale": "VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be\nused to detect anomalous traffic or insight during security workflows.",
    "impact": "Currently, the flow log function is available for free. However, corresponding storage\nand indexing fees associated with the use of Log Service are billed. Before you activate\nthe flow log function, note the following: • The object where a flow log is created can\nonly be ENI. • Only the following resource types support the creation of flow logs: VPC,\nVSwitch, and ENI. • The maximum number of flow log instances that can be created in\neach region is 10. If you need to create more flow log instances, open a ticket.",
    "audit": "1. Logon to VPC console.\n2. In the left-side navigation pane, click FlowLog.\n3. Check for every existing VPC to ensure that there is an associated VPC ID on\nthe FlowLog tab.",
    "expected_response": "3. Check for every existing VPC to ensure that there is an associated VPC ID on",
    "remediation": "1. Logon to VPC console.\n2. In the left-side navigation pane, click FlowLog.\n3. Follow the instruction to create FlowLog for each of your VPCs",
    "default_value": "By default, Flow Logs is not enabled when you create a new VPC",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/90628.html"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 113,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "3.4",
    "title": "Ensure routing tables for VPC peering are \"least access\"",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Configure Monitoring Systems to Record Network",
    "description": "Once a VPC peering connection is established, routing tables must be updated to\nestablish any connections between the peered VPCs. These routes can be as specific\nas desired, even peering a VPC to only a single host on the other side of the\nconnection.",
    "rationale": "Although the routing table is empty by default upon creation for any newly created\nrouting table, hence it denies any default access, it is recommended that the table entry\nis only added based on the least access principle. Being highly selective in peering\nrouting tables is a very effective way of minimizing the impact of breach as resources\noutside of these routes are inaccessible to the peered VPC.",
    "audit": "1. Logon to VPC console.\n2. Open the routing table\n3. Review routing tables of peered VPCs for whether they route all subnets of\neach VPC and whether that is necessary to accomplish the intended purposes\nfor peering the VPCs.",
    "remediation": "1. Logon to VPC console.\n2. Open the routing table\n3. Remove and add route table entries to ensure that the least number of\nsubnets or hosts as is required to accomplish the purpose for peering are\nroutable.",
    "default_value": "Routing table is empty by default upon creation for any newly created routing table,\nhence it denies any default access",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/97766.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 115,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.5",
    "title": "Ensure the security group are configured with fine grained rules",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Security groups provide stateful filtering of ingress/egress network traffic to Alibaba\nCloud resources. It is recommended that all security group configured with fine grained\nrules.",
    "rationale": "Configure fine grained security group rules is a very effective way of minimizing the\nimpact of breach as resources outside of these rules are inaccessible to the ECS\ninstance.",
    "audit": "1. Logon to ECS Console.\n2. In the left-side navigation pane, choose Network & Security > Security\nGroups.\n3. Ensure the rules in each of your security groups are all necessary for your\noperation.",
    "expected_response": "3. Ensure the rules in each of your security groups are all necessary for your",
    "remediation": "1. Logon to ECS Console.\n2. In the left-side navigation pane, choose Network & Security > Security\nGroups.\n3. Remove any unnecessary rules in all security groups.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/25475.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 117,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.1",
    "title": "Ensure that 'Unattached disks' are encrypted",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "description": "Ensure that unattached disks in a subscription are encrypted.",
    "rationale": "Cloud disk encryption protects your data at rest. The cloud disk data encryption feature\nautomatically encrypts data when data is transferred from ECS instances to disks, and\ndecrypts data when the data is read from disks.",
    "audit": "1. Logon to ECS Console\n2. In the left pane, click to expand Storage and Snapshots, click Disks\n3. Select each Disk\n4. Ensure that each disk has Disks Encryption has Encryption checked with the\nvalue of key tag is true",
    "expected_response": "4. Ensure that each disk has Disks Encryption has Encryption checked with the",
    "remediation": "1. Logon to ECS Console\n2. In the left-side navigation pane, choose Storage & Snapshots > Disk.\n3. In the upper-right corner of the Disks page, click Create Disk.\n4. In the Disk section, check the Disk Encryption box and then select a key from\nthe drop-down list.",
    "default_value": "By default, data disks are not encrypted.",
    "additional_information": "After a data disk is created, you can only encrypt the data disk by manually copying\ndata on the unencrypted disk to a new encrypted disk. The disk encryption status\ncannot be directly converted from unencrypted to encrypted.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/59643.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 120,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D3",
      "D6"
    ]
  },
  {
    "cis_id": "4.2",
    "title": "Ensure that ‘Virtual Machine’s disk’ are encrypted",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "Ensure that disk are encrypted when it is created with the creation of VM instance.",
    "rationale": "ECS cloud disk encryption protects your data at rest. The cloud disk data encryption\nfeature automatically encrypts data when data is transferred from ECS instances to\ndisks, and decrypts data when the data is read from disks.",
    "audit": "1. Logon to ECS Console\n2. In the left pane, click to expand Storage and Snapshots, click Disks\n3. Select each Data disk\n4. Ensure that each disk under Data disks has encryption",
    "expected_response": "4. Ensure that each disk under Data disks has encryption",
    "remediation": "Encrypt a system disk when copying an image in the ECS console by following the\nbelow steps:\n1. Logon to ECS Console\n2. In the left-side navigation pane, choose Instances & Images > Instances\n3. In the top navigation bar, select a region.\n4. On the Images page, click the Custom Image tab.\n5. Select the target image and click copy Image in the Actions column.\n6. In the Copy Image dialog box, check the Encrypt box and then select a key from\nthe drop-down list.\n7. Click OK.\nYou can encrypt a data disk when creating an instance by following the below steps:\n1. Logon to ECS Console\n2. In the left-side navigation pane, choose Instances & Images > Instances\n3. On the Instances page, click Create Instance\n4. On the Basic Configurations page, find the Storage section and perform the\nfollowing steps\na) Click Add Disk\nb) Specify the disk category and capacity of data disk\nc) Select Disk Encryption and then select a key from the drop-down list.",
    "default_value": "Not checked",
    "additional_information": "You cannot directly convert unencrypted disks to encrypted disks. You can encrypt\nsystem disks only when you are copying the custom images. You can encrypt the data\ndisk by manually creating an encrypted data disk and then copy the data on\nunencrypted disk to the new encrypted disk.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/59643.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 122,
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
    "cis_id": "4.3",
    "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "Security groups provide stateful filtering of ingress/egress network traffic to Alibaba\nCloud resources. It is recommended that no security group allows unrestricted ingress\naccess to port 22.",
    "rationale": "Rationale: Removing unfettered connectivity to remote console services, such as SSH,\nreduces a server's exposure to risk.",
    "impact": "For valid operation needs, such as updating an existing environment, care should be\ntaken to ensure that administrators currently relying on an existing ingress from\n0.0.0.0/0 have access to ports 22 through another security group.",
    "audit": "1. Logon to ECS Console .\n2. In the left pane, click to expand Network and Security, click Security\nGroups\n3. For each security group, perform the following:\n4. Select the security group\n5. Click Add Rules\n6. Click the Inbound tab\n7. Ensure no rule exists that has a port range that includes port 22 and has an\nAuthorization Object of 0.0.0.0/0\nNote: A Port value of ALL or a port range such as 0-1024 also includes port 22.",
    "expected_response": "7. Ensure no rule exists that has a port range that includes port 22 and has an",
    "remediation": "1. Logon to ECS Console .\n2. In the left pane, click to expand Network* and Security, click Security\nGroups\n3. For each security group, perform the following:\na)Select the security group\nb)Click Add Rules\nc)Click the Inbound tab\nd)Identify the rules to be removed\nf)Click Delete in the Remove column\ng)Click OK",
    "default_value": "By default, Authorization Object and port range are not set.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/51170.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 124,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "4.4",
    "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "manual",
    "domain": "(Manual)",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "Security groups provide filtering of ingress/egress network traffic to Aliyun resources. It\nis recommended that no security group allows unrestricted ingress access to port 3389.",
    "rationale": "Removing unfettered connectivity to remote console services, such as RDP, reduces a\nserver's exposure to risk.",
    "impact": "For valid operation needs, such as updating an existing environment, care should be\ntaken to ensure that administrators currently relying on an existing ingress from\n0.0.0.0/0 have access to ports 3389 through another security group.",
    "audit": "1. Logon to ECS Console .\n2. In the left pane, click to expand Network and Security, click Security Groups\n3. For each security group, perform the following:\n4. Select the security group\n5. Click Add Rules\n6. Click the Inbound tab\n7. Ensure no rule exists that has a port range that includes port 3389 and has an\nAuthorization Object of 0.0.0.0/0\nNote: A Port value of ALL or a port range such as 0-1024 also includes port 3389.",
    "expected_response": "7. Ensure no rule exists that has a port range that includes port 3389 and has an",
    "remediation": "1. Logon to ECS Console .\n2. In the left pane, click to expand Network and Security, click Security Groups\nFor each security group, perform the following:\n1. Select the security group\n2. Click Add Rules\n3. Click the Inbound tab\n4. Identify the rules to be removed\n5. Click Delete in the Remove column\n6. Click OK",
    "default_value": "By default, Authorization Object and port range are not set.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/51170.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 126,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "4.5",
    "title": "Ensure that the latest OS Patches for all Virtual Machines are applied",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "manual",
    "domain": "(Manual)",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "Ensure that the latest OS patches for all virtual machines are applied.",
    "rationale": "Windows and Linux virtual machines should be kept updated to:\n• Address a specific bug or flaw\n• Improve an OS or application’s general stability\n• Fix a security vulnerability The Alibaba Cloud Security Center checks for the\nlatest updates in Linux and Windows systems. If an ECS instance is missing a\nsystem update, the Security Center will recommend system updates be applied.",
    "audit": "1. Logon to Security Center Console\n2. Select Vulnerabilities\n3. Ensure all vulnerabilities are fixed",
    "expected_response": "3. Ensure all vulnerabilities are fixed",
    "remediation": "1. Logon to Security Center Console\n2. Select Vulnerabilities\n3. Apply all patches for vulnerabilities",
    "default_value": "By default, patches are not automatically deployed.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 128,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.6",
    "title": "Ensure that the endpoint protection for all Virtual Machines is installed",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "manual",
    "domain": "(Manual)",
    "subdomain": "Deploy Automated Operating System Patch",
    "description": "Install endpoint protection for all virtual machines.",
    "rationale": "Installing endpoint protection systems (like Security Center for Alibaba Cloud) provides\nfor real-time protection capability that helps identify and remove viruses, spyware, and\nother malicious software, with configurable alerts when known malicious software\nattempts to install itself or run on ECS.",
    "audit": "Using the Alibaba Cloud Management Console:\n1. Logon to Security Center Console\n2. Select Overview\n3. Ensure all ECS are installed with Security Center agent",
    "expected_response": "3. Ensure all ECS are installed with Security Center agent",
    "remediation": "Using the Alibaba Cloud Management Console:\n1. Logon to Security Center Console\n2. Select Settings\n3. Click Agent\n4. On the Agent tab, select the virtual machines without Security Center agent\ninstalled\n5. Click Install",
    "default_value": "Not installed",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 130,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.1",
    "title": "Ensure that OSS bucket is not anonymously or publicly accessible",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "storage",
    "domain": "Storage",
    "description": "A bucket is a container used to store objects in Object Storage Service (OSS). All\nobjects in OSS are stored in buckets.\nIt is recommended that the access policy on OSS bucket does not allows anonymous\nand/or public access.",
    "rationale": "Allowing anonymous and/or public access grants permissions to anyone to access\nbucket content. Such access might not be desired if you are storing any sensitive data.\nHence, ensure that anonymous and/or public access to a bucket is not allowed.",
    "impact": "Customers may set ACL to public due to the business needs.",
    "audit": "The anonymous or public access to OSS bucket can be restricted through both Bucket\nAccess Control List (ACL) and Bucket Policy.\nUsing the Bucket ACL:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Click on Basic Setting in top middle of the console\n4. Under ACL section, ensure the Bucket ACL is set to `Private.\nUsing Bucket Policy:\n1. Logon to OSS console.\n2. Click Bucket, and then click the name of target bucket.\n3. Click the Files tab. On the page that appears, click Authorize.\n4. In the Authorize dialog box that appears, click Authorize.\n5. In the Authorize dialog box that appears, ensure the Anonymous Accounts (*)\nis selected under Accounts and None is selected under Authorized\nOperation.",
    "expected_response": "4. Under ACL section, ensure the Bucket ACL is set to `Private.\n5. In the Authorize dialog box that appears, ensure the Anonymous Accounts (*)",
    "remediation": "The anonymous or public access to OSS bucket can be restricted through both Bucket\nACL and Bucket Policy.\nUsing the Bucket ACL:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Click on Basic Setting in top middle of the console\n4. Under ACL section, click on configure\n5. Click Private\n6. Click Save\nUsing Bucket Policy:\n1. Logon to OSS console.\n2. Click Bucket, and then click the name of target bucket.\n3. Click the Files tab. On the page that appears, click Authorize.\n4. In the Authorize dialog box that appears, click Authorize.\n5. In the Authorize dialog box that appears, choose the Anonymous Accounts (*)\nfor Accounts and choose None for Authorized Operation`.\n6. Click OK.",
    "default_value": "Private",
    "additional_information": "To implement access restrictions on buckets, configuring Bucket Policy is a preferred\nway than configuring Bucket ACL considering the general access control rules on\nAlibaba Cloud as below:\n1. If the access control is configured through both Bucket Policy and Bucket ACL,\nthe ultimate access control effect is the combination of the “allowed” policy\nconfigured through Bucket Policy and Bucket ACL. For example, if the public\nread is selected under Bucket ACL and certain RAM account is configured as\nallowed to read and write under Bucket Policy, the ultimate access allowed is to\nallow public read and write by certain RAM account.\n2. If there is any conflict between the configuration of Bucket Policy and Bucket\nACL, “Deny” rules prevails. For example, if the public read is selected under\nBucket ACL and certain RAM account is configured as configured as None for\nAuthorized Operation under Bucket Policy, the ultimate access allow the public\nready except those RAM accounts configured as “Deny” through Authorized\nOperation.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/31896.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 133,
    "dspm_relevant": true,
    "dspm_categories": [
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.2",
    "title": "Ensure that there are no publicly accessible objects in storage buckets",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Deny Communication over Unauthorized Ports",
    "description": "A bucket is a container used to store objects in Object Storage Service (OSS). All\nobjects in OSS are stored in buckets.\nIt is recommended that storage object ACL should not grant public access.",
    "rationale": "Allowing public access to objects allows anyone with an internet connection to access\nsensitive data that is important to your business. Also note that even if a bucket ACL\napplied on storage does not allow public access, there could be object specific ACLs\nthat allows public access to the specific access to the specific objects inside the\nbuckets. Hence it is important to check object ACLs at individual object level.",
    "impact": "Customers may set ACL to public due to the business needs.",
    "audit": "Using the Management Console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Click on Files in top middle of the console\n4. Click on View details in the right column on a target object\n5. Ensure File ACL is set to private",
    "expected_response": "5. Ensure File ACL is set to private",
    "remediation": "Using the Management Console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Click on Files in top middle of the console\n4. Hover on More in the right column on a target object\n5. Click Set ACL\n6. Click Private\n7. Click Save",
    "default_value": "By Default, object ACLs is inherited from corresponding bucket ACL.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/31909.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 136,
    "dspm_relevant": true,
    "dspm_categories": [
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "5.3",
    "title": "Ensure that logging is enabled for OSS buckets",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Deny Communication over Unauthorized Ports",
    "description": "OSS Bucket Access Logging generates a log that contains access records for each\nrequest made to your OSS bucket. An access log record contains details about the\nrequest, such as the request type, the resources specified in the request worked, and\nthe time and date the request was processed. It is recommended that bucket access\nlogging be enabled on the OSS bucket.",
    "rationale": "By enabling OSS bucket logging on target OSS buckets, it is possible to capture all\nevents which may affect objects within an target buckets. Configuring logs to be placed\nin a separate bucket allows access to log information which can be useful in security\nand incident response workflows.",
    "impact": "Extra cost for log storage may incur.",
    "audit": "Perform the following ensure the OSS bucket has access logging is enabled:\nThrough the management console:\n1. Logon to the OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Under Log, ensure Enabled is checked.",
    "expected_response": "Perform the following ensure the OSS bucket has access logging is enabled:\n3. Under Log, ensure Enabled is checked.",
    "remediation": "Perform the following to enable OSS bucket logging:\nThrough the management console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Under Log, click configure\n4. Configure bucket logging\n5. Click the Enabled checkbox\n6. Select Target Bucket from list\n7. Enter a Target Prefix\n8. Click Save",
    "default_value": "Logging is disabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/31900.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 138,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "5.4",
    "title": "Ensure that 'Secure transfer required' is set to 'Enabled'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Activate audit logging",
    "description": "Enable the data encryption in transit.",
    "rationale": "The secure transfer enhances the security of OSS bucket by only allowing requests to\nthe storage account by a secure connection. For example, when calling REST APIs to\naccess storage accounts, the connection must use HTTPS. Any requests using HTTP\nwill be rejected.",
    "audit": "Using the management console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Click on Files in top middle of the console\n4. Click on Authorize\n5. Ensure a policy is set to None (Authorized Operation) and http\n(Conditions:Access Method)",
    "expected_response": "5. Ensure a policy is set to None (Authorized Operation) and http",
    "remediation": "USing the management console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Click on Files in top middle of the console\n4. Click on Authorize\n5. Click on Whole Bucket,*, None (Authorized Operation) and http\n(Conditions:Access Method)\n6. Click on Save",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/85111.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 140,
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
    "cis_id": "5.5",
    "title": "Ensure that the shared URL signature expires within an hour",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Data in Transit",
    "description": "Expire the shared URL signature within an hour.",
    "rationale": "URL signature is a URL that grants access rights to OSS. You can add signature\ninformation to a URL so that you can forward the URL to the third party for authorized\naccess.\nA URL signature can be provided to the third party for authorized access. Providing a\nURL signature to these clients allows them access to a resource for a specified period\nof time. This time should be set as low as possible, and preferably no longer than an\nhour.",
    "audit": "Through the management console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Click Files in top middle of the console\n4. Click View Details in the right column on a target object\n5. Ensure Validity Period is set to less than 3600",
    "expected_response": "5. Ensure Validity Period is set to less than 3600",
    "remediation": "Through the management console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Click on Files in top middle of the console\n4. Click on View Details in the right column on a target object\n5. Set Validity Period to a value less than 3600",
    "default_value": "300 seconds.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/31912.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 142,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "5.6",
    "title": "Ensure that URL signature is allowed only over https",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "seconds",
    "domain": "seconds",
    "description": "URL signature is a URL that grants access rights to OSS. You can add signature\ninformation to a URL so that you can forward the URL to the third party for authorized\naccess.A URL signature can be provided to the third party for authorized access.",
    "rationale": "It is recommended to allow such access requests over HTTPS protocol only.\nURL signature should be allowed only over HTTPS protocol.",
    "audit": "Using the management console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Click on Files in top middle of the console\n4. Click on View Details in the right column on a target object\n5. Ensure HTTPS is set to Enabled",
    "expected_response": "5. Ensure HTTPS is set to Enabled",
    "remediation": "Using the management console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Click on Files in top middle of the console\n4. Click on View Details in the right column on a target object\n5. Set HTTPS to Enabled",
    "default_value": "Enabled",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 144,
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
    "cis_id": "5.7",
    "title": "Ensure network access rule for storage bucket is not set to publicly accessible",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "seconds",
    "domain": "seconds",
    "subdomain": "Ensure All Accounts Have An Expiration Date",
    "description": "Restricting default network access helps to provide a new layer of security, since OSS\naccept connections from clients on any network. To limit access to selected networks,\nthe default action must be changed.",
    "rationale": "Access can be granted to public internet IP address ranges, to enable connections from\nspecific internet or on-premises clients. When network rules are configured, only\napplications from allowed networks can access OSS bucket.",
    "audit": "Using the management console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Click on Files in top middle of the console\n4. Click on Authorize\n5. Ensure a policy is set to be granted to public internet IP address ranges",
    "expected_response": "5. Ensure a policy is set to be granted to public internet IP address ranges",
    "remediation": "Using the management console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on a target OSS bucket\n3. Click on Files in top middle of the console\n4. Click on Authorize\n5. Click on Whole Bucket,*,None, Condition IP = specified IP address or IP address\nsegment\n6. Click on Save",
    "default_value": "Not set.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/85111.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 146,
    "dspm_relevant": true,
    "dspm_categories": [
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "5.8",
    "title": "Ensure server-side encryption is set to ‘Encrypt with Service Key’",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "seconds",
    "domain": "seconds",
    "subdomain": "Encrypt Sensitive Data at Rest",
    "description": "Enable server-side encryption (Encrypt with Service Key) for objects.",
    "rationale": "Server-side encryption protects your data at rest.",
    "impact": "Service key incurs an additional cost from accessing the KMS service.",
    "audit": "Perform the following to determine if the OSS bucket is configured to use SSE-KMS:\nUsing the management console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on the target OSS bucket\n3. Click on Basic Setting in top middle of the console\n4. Under the Server-side Encryption section, ensure the target OSS Bucket\nEncryption is set to KMS and the Encryption Method of KMS and the service key\n(alias/acs/oss) is selected.",
    "expected_response": "Perform the following to determine if the OSS bucket is configured to use SSE-KMS:\n4. Under the Server-side Encryption section, ensure the target OSS Bucket\nEncryption is set to KMS and the Encryption Method of KMS and the service key",
    "remediation": "Using the management console:\nPerform the following to configure the OSS bucket to use SSE-KMS:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on the target OSS bucket\n3. Click Basic Setting in top middle of the console\n4. Under the Server-side Encryption section, click on configure\n5. Click KMS and select KMS service key(alias/acs/oss)",
    "default_value": "Not encrypted.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/108880.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 148,
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
    "cis_id": "5.9",
    "title": "Ensure server-side encryption is set to ‘Encrypt with BYOK’",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "seconds",
    "domain": "seconds",
    "subdomain": "Encrypt Sensitive Data at Rest",
    "description": "Enable server-side encryption (Encrypt with BYOK) for objects.",
    "rationale": "Server-side encryption protects your data at rest.",
    "impact": "Service key incurs an additional cost from accessing the KMS service.",
    "audit": "Perform the following to determine if the OSS bucket is configured to use SSE-KMS:\nUsing the management console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on the target OSS bucket\n3. Click on Basic Setting in top middle of the console\n4. Under the Server-side Encryption section, ensure the target OSS Bucket\nEncryption is set to KMS and a customer created KMS key ID is specified in the\nKMS Key Id field.",
    "expected_response": "Perform the following to determine if the OSS bucket is configured to use SSE-KMS:\n4. Under the Server-side Encryption section, ensure the target OSS Bucket\nEncryption is set to KMS and a customer created KMS key ID is specified in the",
    "remediation": "Perform the following to configure the OSS bucket to use SSE-KMS:\nUsing the management console:\n1. Logon to OSS console.\n2. In the bucket-list pane, click on the target OSS bucket\n3. Click on Basic Setting in top middle of the console\n4. Under the Server-side Encryption section, click on configure\n5. Click on KMS and select an existing CMK from the KMS key Id drop-down menu\n6. Click save",
    "default_value": "By default, Buckets are not set to be encrypted.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/108880.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 150,
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
    "title": "Ensure that RDS instance requires all incoming connections to use SSL",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "database",
    "domain": "Relational Database Services",
    "description": "It is recommended to enforce all incoming connections to SQL database instance to use\nSSL.",
    "rationale": "SQL database connections if successfully trapped (MITM); can reveal sensitive data like\ncredentials, database queries, query outputs etc. For security, it is recommended to\nalways use SSL encryption when connecting to your instance. This recommendation is\napplicable for PostgreSQL and MySQL Instances.",
    "audit": "Using the management console:\n1. Logon to RDS Console.\n2. Select the region where the target instance is located.\n3. Click the ID of the target instance to enter the Basic Information page.\n4. In the left-side navigation pane, click Data Security to go to the Security page.\n5. Click the SSL Encryption tab.\n6. Check the button SSL Encryption is Enabled.",
    "expected_response": "6. Check the button SSL Encryption is Enabled.",
    "remediation": "Using the management console:\n1. Logon to RDS Console.\n2. Select the region where the target instance is located.\n3. Click the ID of the target instance to enter the Basic Information page.\n4. In the left-side navigation pane, click Data Security.\n5. Click the SSL Encryption tab.\n6. Click the switch next to Disabled in the SSL Encryption parameter.\n7. In the Configure SSL dialog box, select the endpoint for which you want to\nenable SSL encryption and then click OK.\n8. Click Download CA Certificate to download an SSL certificate.\n9. The downloaded SSL certificate is a package including the following files:\np7b file: is used to import the CA certificate on Windows OS.\nPEM file: is used to import the CA certificate on other systems or for other\napplications.\nJKS file: is a Java truststore certificate file used for importing CA certificate\nchains in Java programs. The password is apsaradb.",
    "default_value": "Encryption is off by default.",
    "additional_information": "You can choose to encrypt the private or public endpoint, but note that you can encrypt\nonly one endpoint.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/32474.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 153,
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
    "cis_id": "6.2",
    "title": "Ensure that RDS Instances are not open to the world",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "database",
    "domain": "Relational Database Services",
    "subdomain": "Encrypt Transmittal of Username and",
    "description": "Database Server should accept connections only from trusted Network(s)/IP(s) and\nrestrict access from the world.",
    "rationale": "To minimize attack surface on a Database server Instance, only trusted/known and\nrequired IP(s) should be white-listed to connect to it. Authorized network should not\nhave IPs/networks configured to 0.0.0.0 or /0 which will allow access to the instance\nfrom anywhere in the world.",
    "audit": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper left corner, select the region where the target instance is located.\n3. Locate the target instance and click its ID.\n4. In the left-side navigation pane, click Data Security to visit the Security page.\n5. On the Whitelist Settings tab, check if the authorized servers’ IPs have been\nconfigured, and it is not configured as 0.0.0.0 or /0.\nNote: You can also click Add a Whitelist Group to create a new group.",
    "remediation": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper left corner, select the region where the target instance is located.\n3. Locate the target instance and click its ID.\n4. In the left-side navigation pane, click Data Security to visit the Security page.\n5. On the Whitelist Settings tab page, follow below instructions based on your\nscenario:\n• To access the RDS instance from an ECS instance located within a VPC, click\nEdit for the default VPC whitelist.\n• To access the RDS instance from an ECS instance located within a classic\nnetwork, click Edit for the default Classic Network whitelist.\n• To access the RDS instance from a server or computer located in a public\nnetwork, click Edit for the default Classic Network whitelist.\n6. In the displayed Edit Whitelist dialog box, remove any 0.0.0.0 or /0 entries, and\nonly add the IP addresses that need to access the instance, and then click OK.\n• If you add an IP address range, such as 10.10.10.0/24, any IP address in\n10.10.10.X format can access the RDS instance.\n• If you add multiple IP addresses or IP address ranges, separate them with a\ncomma (without spaces), for example, 192.168.0.1,172.16.213.9.\n• You can click Add Internal IP Addresses of ECS Instance to display the IP\naddresses of all the ECS instances under your Alibaba Cloud account and add to\nthe whitelist.",
    "default_value": "By default, the whitelist setting is ’127.0.0.1’ that is not allowing any connection from\nany server.",
    "additional_information": "For RDS instances that is upgraded to IPv6, please use the appropriate IPv6\nconfiguration to ensure the whitelist is not open for all.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/26198.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 155,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "6.3",
    "title": "Ensure that 'Auditing' is set to 'On' for applicable database instances",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "database",
    "domain": "Relational Database Services",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Enable SQL auditing on all RDS except SQL Server 2012/2016/2017 and MariaDB TX.",
    "rationale": "The Alibaba Cloud allows MySQL instance to be created as a service. Enabling auditing\nat the server level ensures that all existing and newly created databases on the MySQL\ninstance are audited. Auditing policy applied on the MySQL database does not override\nauditing policy and settings applied on the particular MySQL server where the database\nis hosted. Auditing tracks database events and writes them to an audit log in the Alibaba\nCloud MySQL account. It also helps to maintain regulatory compliance, understand\ndatabase activity, and gain insight into discrepancies and anomalies that could indicate\nbusiness concerns or suspected security violations.",
    "impact": "By activating Auditing, the system then automatically starts charging an hourly fee of\nUS$ 0.0018 per GB.",
    "audit": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID.\n4. In the left-side navigation pane, select SQL Explorer.\n5. Check if there is a “Welcome to Use SQL Explore” page, as such a page\nindicates that the auditing is not yet enabled. If the auditing is enabled, then the\nSQL Explorer should show the SQL Explore dashboard directly.",
    "expected_response": "indicates that the auditing is not yet enabled. If the auditing is enabled, then the\nSQL Explorer should show the SQL Explore dashboard directly.",
    "remediation": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID.\n4. In the left-side navigation pane, select SQL Explorer.\n5. Click Activate Now.\n6. Specify the SQL log storage duration (for how long you want to keep the SQL\nlog), and click Activate.",
    "default_value": "Disable",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/96123"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 157,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "6.4",
    "title": "Ensure that 'Auditing' Retention is 'greater than 6 months'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "database",
    "domain": "Relational Database Services",
    "subdomain": "Enforce Detail Logging for Access or Changes to",
    "description": "Database SQL Audit Retention should be configured to be greater than 90 days.",
    "rationale": "Audit Logs can be used to check for anomalies and give insight into suspected\nbreaches or misuse of information and access.",
    "audit": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID.\n4. In the left-side navigation pane, select SQL Explore.\n5. Click Service Setting button on the top right corner.\n6. In the service setting page, assure the storage duration is set as ‘6 months’ or\nlonger.",
    "remediation": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID.\n4. In the left-side navigation pane, select SQL Explore.\n5. Click Service Setting button on the top right corner.\n6. In the service setting page, enable ‘Activate SQL Explore’, set the storage\nduration as ‘6 months’ or longer.",
    "default_value": "Active SQL Explorer is disabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/96123.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 159,
    "dspm_relevant": true,
    "dspm_categories": [
      "retention"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.5",
    "title": "Ensure that 'TDE' is set to 'Enabled' on for applicable database instance",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "database",
    "domain": "Relational Database Services",
    "subdomain": "Enforce Detail Logging for Access or Changes to",
    "description": "Enable Transparent Data Encryption on every RDS instance.",
    "rationale": "RDS Database transparent data encryption helps protect against the threat of malicious\nactivity by performing real-time encryption and decryption of the database, associated\nbackups, and log files at rest without requiring changes to the application.",
    "audit": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID.\n4. In the left-side navigation pane, click Data Security to go to the Security page.\n5. Click the TDE tab.\n6. Check the button TDE Status is Enabled.",
    "expected_response": "6. Check the button TDE Status is Enabled.",
    "remediation": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID to enter the Basic\nInformation page.\n4. In the left-side navigation pane, click Data Security to go to the Security page.\n5. Click the TDE tab.\n6. On the TDE tab, find TDE Status and click the switch next to Disabled.\n7. In the displayed dialog box, choose automatically generated key or custom key,\nclick Confirm.\n• Encrypt a table\na. For RDS for MySQL, connect to the instance and run the following command to\nencrypt tables.\nalter table <tablename> engine=innodb, block_format=encrypted\nb. For RDS for SQL Server, click Configure TDE, select the databases to encrypt, add\nthem to the right, and click OK.\n• Decrypt data\na. To decrypt a MySQL table encrypted by TDE, run the following command:\nalter table <tablename> engine=innodb, block_format=default\nb. To decrypt a SQL Server table encrypted by TDE, click Configure TDE and move the\ndatabase to the left.",
    "default_value": "Disabled",
    "additional_information": "SQL Server 2008 R2, SQL Server 2008R2, SQL Server 2012 Enterprise Edition, SQL\nServer 2016 Enterprise Edition, SQL Server 2017 Enterprise Edition and MySQL\n5.6/5.7/8.0 all support TED enablement. You have logged in with an Alibaba Cloud\naccount rather than a RAM user account. KMS shall be activated. If KMS is not yet\nactivated, you will be prompted to activate it when attempting to enable TDE.",
    "detection_commands": [],
    "remediation_commands": [
      "alter table <tablename> engine=innodb, block_format=encrypted",
      "alter table <tablename> engine=innodb, block_format=default"
    ],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/33510.html"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 161,
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
    "cis_id": "6.6",
    "title": "Ensure RDS instance TDE protector is encrypted with BYOK (Use your own key)",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "database",
    "domain": "Relational Database Services",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "TDE with BYOK support provides increased transparency and control, increased\nsecurity with an HSM-backed KMS service, and promotion of separation of duties. With\nTDE, data is encrypted at rest with a symmetric key (called the database encryption\nkey). With BYOK support for TDE, the DEK can be protected with an asymmetric key\nthat is stored in the KMS. Based on business needs or criticality of data, it is\nrecommended that the TDE protector is encrypted by a key that is managed by the data\nowner (BYOK).",
    "rationale": "Bring Your Own Key (BYOK) support for Transparent Data Encryption (TDE) allows\nuser control of TDE encryption keys and restricts who can access them and when.\nAlibaba Cloud KMS, a cloud-based key management system is the service where TDE\nhas integrated support for BYOK. With BYOK, the database encryption key is protected\nby an asymmetric key stored in the KMS.",
    "impact": "Additional investment in administration time is needed to produce, maintain, store, etc.\ncustomer provided keys.",
    "audit": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID.\n4. In the left-side navigation pane, click Data Security to go to the Security page.\n5. Click the TDE tab.\n6. Check the button TDE Status is Enabled and a custom key ID is shown for the\nKey field and the status is Valid.",
    "expected_response": "6. Check the button TDE Status is Enabled and a custom key ID is shown for the",
    "remediation": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID to enter the Basic\nInformation page.\n4. In the left-side navigation pane, click Data Security to go to the Security page.\n5. Click the TDE tab.\n6. On the TDE tab, find TDE Status and click the switch next to Disabled.\n7. In the displayed dialog box, choose custom key, click Confirm.",
    "default_value": "Disabled",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/96121.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 163,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "6.7",
    "title": "Ensure parameter 'log_connections' is set to 'ON' for PostgreSQL Database",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "database",
    "domain": "Relational Database Services",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "Enable log_connections on PostgreSQL Servers.",
    "rationale": "Enabling log_connections helps PostgreSQL Database to log attempted connection to\nthe server, as well as successful completion of client authentication. Log data can be\nused to identify, troubleshoot, and repair configuration errors and suboptimal\nperformance.",
    "audit": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID to enter the Basic\nInformation page.\n4. In the left-side navigation pane, select Parameters and ensure the\nlog_connection is set as On in the Actual Value column.",
    "expected_response": "4. In the left-side navigation pane, select Parameters and ensure the",
    "remediation": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID to enter the Basic\nInformation page.\n4. In the left-side navigation pane, select Parameters.\n5. Click the Edit icon of log_connection parameter next the Actual Value\ncolumn.\n6. Enter On as the Actual Value and click Confirm.\n7. Click Apply Changes.\n8. In the message that appears, click Confirm.",
    "default_value": "Off",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/96751.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 165,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "6.8",
    "title": "Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "database",
    "domain": "Relational Database Services",
    "subdomain": "Enforce Detail Logging for Access or Changes to",
    "description": "Enable log_disconnections on PostgreSQL Servers.",
    "rationale": "Enabling log_disconnections helps PostgreSQL Database to log session terminations of\nthe server, as well as duration of the session. Log data can be used to identify,\ntroubleshoot, and repair configuration errors and suboptimal performance.",
    "audit": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID to enter the Basic\nInformation page.\n4. In the left-side navigation pane, select Parameters and ensure the\nlog_disconnections is set as On in the Actual Value column.",
    "expected_response": "4. In the left-side navigation pane, select Parameters and ensure the",
    "remediation": "Using the management console:\n1. Login to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID to enter the Basic\nInformation page.\n4. In the left-side navigation pane, select Parameters.\n5. Click the Edit icon of log_disconnections parameter next the Actual Value\ncolumn.\n6. Enter On as the Actual Value and click Confirm.\n7. Click Apply Changes.\n8. In the message that appears, click Confirm.",
    "default_value": "Off",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/96751.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 167,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "6.9",
    "title": "Ensure server parameter 'log_duration is set to 'ON' for PostgreSQL Database Server",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "database",
    "domain": "Relational Database Services",
    "subdomain": "Enforce Detail Logging for Access or Changes to",
    "description": "Enable log_duration on PostgreSQL Servers.",
    "rationale": "Enabling log_duration helps PostgreSQL Database to Logs the duration of each\ncompleted SQL statement which in turn generates query and error logs. Query and\nerror logs can be used to identify, troubleshoot, and repair configuration errors and sub-\noptimal performance.",
    "audit": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID to enter the Basic\nInformation page.\n4. In the left-side navigation pane, select Parameters and ensure the\nlog_durantion is set as On in the Actual Value column.",
    "expected_response": "4. In the left-side navigation pane, select Parameters and ensure the",
    "remediation": "Using the management console:\n1. Logon to RDS Console.\n2. In the upper-left corner, select the region of the target instance.\n3. Locate the target instance, and click the instance ID to enter the Basic\nInformation page.\n4. In the left-side navigation pane, select Parameters.\n5. Click the Edit icon of log_durantion parameter next the Actual Value\ncolumn.\n6. Enter On as the Actual Value and click Confirm.\n7. Click Apply Changes.\n8. In the message that appears, click Confirm.",
    "default_value": "Off",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/96751.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 169,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "7.1",
    "title": "Ensure Log Service is set to ‘Enabled’ on Kubernetes Engine Clusters",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "kubernetes",
    "domain": "Kubernetes Engine",
    "description": "Log Service is a complete real-time data logging service on Alibaba Cloud to support\ncollection, shipping, search, storage and analysis for logs. It includes a user interface to\ncall the Log Viewer and an API to management logs pragmatically. Log Service could\nautomatically collect, process, and store your container and audit logs in a dedicated,\npersistent datastore. Container logs are collected from your containers. Audit logs are\ncollected from the kube-apiserver or the deployed ingress. Events are logs about\nactivity in the cluster, such as the deleting of Pods or Secrets.",
    "rationale": "By enabling you will have container and system logs, Kubernetes Engine deploys a per-\nnode logging agent that reads container logs, adds helpful metadata, and then stores\nthem. The logging agent would help to collecting the following sources:\n• kube-apiserver audit logs\n• ingress visiting logs\n• Standard output and standard error logs from containerized processes\nFor events, Kubernetes Engine uses a Deployment in the kube-system namespace\nwhich automatically collects events and sends them to Log Service. Log Service is\ncompatible with JSON formats.",
    "audit": "Using the management console:\n1. Logon to ACK console\n2. Select the target cluster and click its name into cluster detail page\n3. Select Cluster Auditing on the left column and check if audit page shown",
    "remediation": "Using the management console:\n1. Logon to ACK console\n2. Click Create Kubernetes Cluster and set Enable Log Service to Enabled\nwhen creating cluster",
    "default_value": "By default, logging service is disabled when you create a new cluster using console.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://help.aliyun.com/document_detail/91406.html",
      "2. https://help.aliyun.com/document_detail/86532.html"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 172,
    "dspm_relevant": true,
    "dspm_categories": [
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "7.2",
    "title": "Ensure CloudMonitor is set to Enabled on Kubernetes Engine Clusters",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "kubernetes",
    "domain": "Kubernetes Engine",
    "subdomain": "Activate audit logging",
    "description": "The monitoring service in Kubernetes Engine clusters depends on the Alibaba Cloud\nCloudMonitor agent to access additional system resources and application services in\nvirtual machine instances. The monitor can access metrics about CPU utilization, some\ndisk traffic metrics, network traffic, and disk IO information, which help to monitor\nsignals and build operations in your Kubernetes Engine clusters.",
    "rationale": "By Enabling CloudMonitor installation you will have system metrics and custom metrics.\nSystem metrics are measurements of the cluster's infrastructure, such as CPU or\nmemory usage. For system metrics, a monitor controller would be created and\nperiodically connects to each node and collects metrics about its Pods and containers,\nthen sends the metrics to CloudMonitor server. Metrics for usage of system resources\nare collected from the CPU, Memory, Evictable memory, Non-evictable memory, and\nDisk sources.",
    "audit": "Using the management console:\n1. Logon to ACK console\n2. Select the target cluster and click its name into cluster detail page\n3. Select the Nodes on the left column and click the Monitor link on the Actions\ncolumn of the selected node\n4. Check if OS Metrics data existing in the CloudMonitor page of the selected ECS\nnode",
    "remediation": "Using the management console:\n1. Logon to ACK console\n2. Click the Create Kubernetes Cluster button and set CloudMonitor Agent to\nEnabled under creation options.",
    "default_value": "By default, CloudMonitor Agent installation is disenabled when you create a new cluster\nusing console.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://help.aliyun.com/document_detail/125508.html",
      "2. https://help.aliyun.com/document_detail/102337.html"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 174,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "7.3",
    "title": "Ensure role-based access control (RBAC) authorization is Enabled on Kubernetes Engine Clusters",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "kubernetes",
    "domain": "Kubernetes Engine",
    "subdomain": "Activate audit logging",
    "description": "In Kubernetes, authorizers interact by granting a permission if any authorizer grants the\npermission. The legacy authorizer in Kubernetes Engine grants broad, statically defined\npermissions. To ensure that RBAC limits permissions correctly, you must disable the\nlegacy authorizer. RBAC has significant security advantages, can help you ensure that\nusers only have access to specific cluster resources within their own namespace and is\nnow stable in Kubernetes.",
    "rationale": "In Kubernetes, RBAC is used to grant permissions to resources at the cluster and\nnamespace level. RBAC allows you to define roles with rules containing a set of\npermissions, and the subaccounts who bind the roles could only have the permissions\nto access the specific resources in the cluster or namespaces defined in RBAC policies.",
    "audit": "Using the management console:\n1. Logon to ACK console\n2. Select the target RAM sub-account in the Clusters -> Authorizations page\n3. After RAM user/role is selected, configure the RBAC roles on specific clusters or\nnamespaces",
    "remediation": "Using the management console:\n1. Logon to ACK console\n2. Select the target RAM sub-account and configure the RBAC roles on specific\nclusters or namespaces.",
    "default_value": "By default, RBAC authorization is enabled on ACK clusters, and the legacy\nauthorizations as ABAC is disenable. Besides, the RAM sub-users have no permissions\nto access any resources in ACK clusters by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://help.aliyun.com/document_detail/87656.html",
      "2. https://help.aliyun.com/document_detail/119596.html"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 176,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "7.4",
    "title": "Ensure Cluster Check triggered at least once per week for Kubernetes Clusters",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "kubernetes",
    "domain": "Kubernetes Engine",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "description": "Kubernetes Engine's cluster check feature helps you verify the system nodes and\ncomponents healthy status. When you trigger the checking, the process would check on\nthe health state of each node in your cluster and also the cluster configuration as\nkubelet\\docker daemon\\kernel and network iptables configuration, if there are fails\nconsecutive health checks, the diagnose would report to admin for further repair.",
    "rationale": "Kubernetes Engine uses the node's health status to determine if a node needs to be\nrepaired. A node reporting a Ready status is considered healthy. The cluster\nadministrator could choose to trigger the cluster check periodically. An cluster healthy\nchecking including:\n• The cloud resource healthy status, including the VPC/VSwitch SLB and every ECS\nnode status in cluster.\n• The kubelet, docker daemon, kernel, iptables configurations on every node in cluster.\nKubernetes Engine generates the diagnose report when checking finish. You can check\nthe diagnose suggestion on ACK console.",
    "audit": "Using the management console:\n1. Logon to ACK console\n2. Select the target cluster and open the More pop-menu for advance options on\ncluster.\n3. Select Overview page on left column and check if the Last check status is\nNormal.\n4. Verify the checking time and details in Global Check.",
    "remediation": "Using the management console:\n1. Logon to ACK console\n2. Select the target cluster and open the More pop-menu for advance options on\ncluster\n3. Select Global Check and click the Start button to trigger the checking",
    "default_value": "By default, the cluster checking process is not auto triggered, the cluster administrator\ncould start it in ACK console.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://help.aliyun.com/document_detail/114882.html"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 178,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "7.5",
    "title": "Ensure Kubernetes web UI / Dashboard is not enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "kubernetes",
    "domain": "Kubernetes Engine",
    "subdomain": "Define and Maintain Role-Based Access Control",
    "description": "Dashboard is a web-based Kubernetes user interface. It can be used to deploy\ncontainerized applications to a Kubernetes cluster, troubleshoot your containerized\napplication, and manage the cluster itself along with its attendant resources. You can\nuse Dashboard to get an overview of applications running on your cluster, as well as for\ncreating or modifying individual Kubernetes resources (such as Deployments, Jobs,\nDaemonSets, etc). For example, you can scale a Deployment, initiate a rolling update,\nrestart a pod or deploy new applications using a deploy wizard.",
    "rationale": "You should disable the Kubernetes Web UI (Dashboard) when running on Kubernetes\nEngine. The Kubernetes Web UI (Dashboard) is backed by a highly privileged\nKubernetes Service Account. It is recommended to use ACK User Console instead of\nDashboard to avoid any privileged escalation via compromise the dashboard.",
    "audit": "Using the management console:\n1. Logon to ACK console\n2. Select the target cluster and select the kube-system namespace in the\nNamespace pop-menu\n3. Input dashboard in the deploy filter bar, and make sure there is no result exist\nafter the filter.",
    "remediation": "Using the management console:\n1. Logon to ACK console\n2. Select the target cluster and select the kube-system namespace in the\nNamespace pop-menu\n3. Input dashboard in the deploy filter bar, make sure there is no result exist after\nthe filter, delete the dashboard deployment by selecting the Delete in More pop-\nmenu.",
    "default_value": "By default, the kube-dashboard would not install in cluster, and the overview console\nuse the managed dashboard which controlled by ACK service.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 180,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "7.6",
    "title": "Ensure Basic Authentication is not enabled on Kubernetes Engine Clusters",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "kubernetes",
    "domain": "Kubernetes Engine",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "Basic authentication allows a user to authenticate to the cluster with a username and\npassword and it is stored in plain text without any encryption. Disabling Basic\nauthentication will prevent attacks like brute force. Its recommended to use either client\ncertificate or RAM for authentication.",
    "rationale": "When disabled, you will still be able to authenticate to the cluster with client certificate or\nRAM. A client certificate is a base 64-encoded public certificate used by clients to\nauthenticate to the cluster endpoint, and ACK cluster would auto generate the client\ncertificate for each logging RAM user.",
    "audit": "1. ssh into any master node in cluster\n2. Make sure the basic-auth-file not exist in apiserver manifest with below\ncommand:\ncat /etc/kubernetes/manifests/kube-apiserver.yaml | grep basic-auth-file",
    "remediation": "1. ssh into any master node in cluster\n2. Make sure the basic-auth-file not exist in apiserver manifest with below\ncommand:\ncat /etc/kubernetes/manifests/kube-apiserver.yaml | grep basic-auth-file\n3. If you found basic-auth-file existing in apiserver manitfest, please override the\nmanifest file with new manifest content to not include the basic-auth-file and then\nrestart the apiserver, you need repeat the action on all of the master nodes",
    "default_value": "By default, Basic authentication is not enabled when you create a new cluster.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://help.aliyun.com/document_detail/86494.html",
      "2. https://help.aliyun.com/document_detail/123848.html",
      "3. https://github.com/AliyunContainerService/ack-ram-authenticator"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 182,
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
    "cis_id": "7.7",
    "title": "Ensure Network policy is enabled on Kubernetes Engine Clusters",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "kubernetes",
    "domain": "Kubernetes Engine",
    "subdomain": "Centralize Account Management",
    "description": "A network policy is a specification of how groups of pods are allowed to communicate\nwith each other and other network endpoints. NetworkPolicy resources use labels to\nselect pods and define rules which specify what traffic is allowed to the selected pods.\nThe Kubernetes Network Policy API allows the cluster administrator to specify what\npods are allowed to communicate with each other.",
    "rationale": "By default, pods are non-isolated; they accept traffic from any source. Pods become\nisolated by having a NetworkPolicy that selects them. Once there is any NetworkPolicy\nin a namespace selecting a particular pod, that pod will reject any connections that are\nnot allowed by any NetworkPolicy. (Other pods in the namespace that are not selected\nby any NetworkPolicy will continue to accept all traffic.)",
    "audit": "Using the management console:\n1. Logon to ACK console\n2. Click the Create Kubernetes Cluster button and make sure Terway is\nselected in Network Plugin option.",
    "remediation": "Only the Terway network plugin support the Network Policy feature, so please make\nsure not choose Flannel as network plugin when creating cluster.\nUsing the management console:\n1. Logon to ACK console\n2. Click the Create Kubernetes Cluster button and select Terway in Network\nPlugin option.",
    "default_value": "By default, Network Policy is disabled when you create a new cluster, and you should\nchoose the Terway as the cluster network plugin when creating the cluster.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://help.aliyun.com/document_detail/97621.html",
      "2. https://help.aliyun.com/document_detail/86949.html"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 184,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "7.8",
    "title": "Ensure ENI multiple IP mode support for Kubernetes Cluster",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "kubernetes",
    "domain": "Kubernetes Engine",
    "subdomain": "Segment the Network Based on Sensitivity",
    "description": "Alibaba Cloud ENI (Elastic Network Interface) has supported assign ranges of internal\nIP addresses as aliases to a single virtual machine's ENI network interfaces. This is\nuseful if you have lots of services running on a VM and you want to assign each service\na different IP address without quota limitation.",
    "rationale": "With the feature of ENI multiple IP mode, Kubernetes Engine clusters can allocate IP\naddresses from a CIDR block known to Terway network plugin. This makes your cluster\nmore scalable and allows your cluster to better interact with other Alibaba Cloud\nproducts and entities. Using ENI multiple IPs has several benefits:\n• Pod IPs are reserved within the network ahead of time, which prevents conflict with\nother compute resources.\n• Firewall controls for Pods can be applied separately from their nodes.\n• Alias IPs allow Pods to directly access hosted services without using a NAT gateway.",
    "audit": "Using the management console:\n1. Logon to ACK console\n2. Select the target cluster name and go into the cluster detail page\n3. Check if the meta of Network Plugin in Cluster Information is Terway",
    "remediation": "Only the Terway network plugin support the Network Policy feature, so please make\nsure not choose Flannel as network plugin when creating cluster.\nUsing the management console:\n1. Logon to ACK console\n2. Click the Create Kubernetes Cluster button and select Terway in Network\nPlugin option.",
    "default_value": "By default, ENI multiple IP mode is not support in Flannel network plugin which is the\ndefault plugin when creating the cluster, and you should choose the Terway as the\ncluster network plugin when creating the cluster.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://github.com/AliyunContainerService/terway/blob/master/README.md#eni-",
      "secondary-ip-pod",
      "2. https://help.aliyun.com/document_detail/97467.html"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 186,
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
    "cis_id": "7.9",
    "title": "Ensure Kubernetes Cluster is created with Private cluster enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "kubernetes",
    "domain": "Kubernetes Engine",
    "subdomain": "Segment the Network Based on Sensitivity",
    "description": "A private cluster is a cluster that makes your master inaccessible from the public\ninternet. In a private cluster, nodes do not have public IP addresses, so your workloads\nrun in an environment that is isolated from the internet. Nodes have addresses only in\nthe private address space. Nodes and masters communicate with each other privately\nusing VPC peering.",
    "rationale": "With a Private cluster enabled, VPC network peering gives you several advantages over\nusing external IP addresses or VPNs to connect networks, including:\n• Network Latency: Public IP networking suffers higher latency than private networking.\n• Network Security: Service owners do not need to have their services exposed to the\npublic Internet to reduce any associated risks.\n• Network Cost: Alibaba Cloud charges egress bandwidth pricing for networks using\nexternal IPs to communicate even if the traffic is within the same zone. If, however, the\nnetworks are peered they can use internal IPs to communicate and save on those\negress costs. Regular network pricing still applies to all traffic.",
    "audit": "Using the management console:\n1. Logon to ACK console\n2. Select the target cluster name and go into the cluster detail page\n3. Check if there is no meta of API Server Public Network Endpoint under Cluster\nInformation",
    "remediation": "Using the management console:\n1. Logon to ACK console\n2. Click the Create Kubernetes Cluster button and make sure Public Access\nis not enabled.",
    "default_value": "By default, public access is not enabled when creating new cluster.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://help.aliyun.com/document_detail/100380.html"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 188,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "8.1",
    "title": "Ensure that Security Center is Advanced or Enterprise Edition",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Center",
    "description": "The Advanced or Enterprise Edition enables threat detection for network and endpoints,\nproviding malware detection, webshell detection and anomaly detection in Security\nCenter.",
    "rationale": "The Advanced or Enterprise Edition allows for full protection to defend cloud threats.",
    "impact": "Additional cost will be incurred by enabling other versions of Security Center",
    "audit": "Using the management console:\n1. Logon to Security Center Console\n2. Select Overview\n3. Ensure Current Edition is Advanced or Enterprise Edition",
    "expected_response": "3. Ensure Current Edition is Advanced or Enterprise Edition",
    "remediation": "Using the management console:\n1. Logon to Security Center Console.\n2. Select Overview.\n3. Click Upgrade.\n4. Select Advanced or Enterprise Edition.\n5. Finish order placement.",
    "default_value": "Not installed.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/product/28498.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 191,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "8.2",
    "title": "Ensure that all assets are installed with security agent",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Center",
    "subdomain": "Utilize Centrally Managed Anti-malware Software",
    "description": "Enable protection on all endpoints.",
    "rationale": "The endpoint protection of Security requires an agent to be installed on the endpoint to\nwork. Such an agent-based approach allows the security center to provide a set of more\ncomprehensive endpoint intrusion detection and protection capabilities, such as\nincludes remote logon detection, webshell detection and removal, anomaly detection\n(detection of abnormal process behaviors and abnormal network connections), and\ndetection of changes in key files and suspicious accounts in systems and applications.",
    "impact": "Additional cost may be incurred by enabling Security Center and install the agent",
    "audit": "Using the management console:\n1. Logon to Security Center Console.\n2. Select Overview.\n3. Ensure Unprotected Assets is 0.",
    "expected_response": "3. Ensure Unprotected Assets is 0.",
    "remediation": "Using the management console:\n1. Logon to Security Center Console.\n2. Select Settings.\n3. Click Agent.\n4. On Client to be installed tab, select all items on the list.\n5. Click On-click installation to install the agent all asset.",
    "default_value": "Not installed.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/111650.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 193,
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
    "cis_id": "8.3",
    "title": "Ensure that Automatic Quarantine is enabled",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Center",
    "subdomain": "Utilize Centrally Managed Anti-malware Software",
    "description": "Enable automatic quarantine in Security Center may 1ncure additional cost.",
    "rationale": "Once a virus is detected, the automatic quarantine feature prevents the virus from being\nexecuted.",
    "impact": "Enabling Automatic Quarantine in security center may incur additional cost",
    "audit": "Using the management console:\n1. Logon to Security Center Console.\n2. Select Settings.\n3. Click General.\n4. Ensure Virus Blocking is enabled.",
    "expected_response": "4. Ensure Virus Blocking is enabled.",
    "remediation": "Using the management console:\n1. Logon to Security Center Console.\n2. Select Settings.\n3. Click General.\n4. Enable Virus Blocking.",
    "default_value": "Not enabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/111847.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 195,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "8.4",
    "title": "Ensure that Webshell detection is enabled on all web servers",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Center",
    "subdomain": "Utilize Centrally Managed Anti-malware Software",
    "description": "Enable webshell detection on all web servers to scans periodically the Web directories\nfor detecting webshells on servers.",
    "rationale": "Web servers are exposed to the Internet and they are commonly attacked through\ninjected webshell by attackers.",
    "audit": "Using the management console:\n1. Logon to Security Center Console.\n2. Select Settings.\n3. Click General.\n4. Click Manage in Webshell Detection.\n5. Ensure all web servers are included.",
    "expected_response": "5. Ensure all web servers are included.",
    "remediation": "Using the management console:\n1. Logon to Security Center Console.\n2. Select Settings.\n3. Click General.\n4. Click Manage in Webshell Detection.\n5. Add all web servers.",
    "default_value": "Not enabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/111847.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 197,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D6"
    ]
  },
  {
    "cis_id": "8.5",
    "title": "Ensure that notification is enabled on all high risk items",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Center",
    "subdomain": "Run Automated Vulnerability Scanning Tools",
    "description": "Enable all risk item notification in Vulnerability, Baseline Risks, Alerts and Accesskey\nLeak event detection categories.",
    "rationale": "To make sure that relevant security operators would receive notifications as soon as\nsecurity events happens.",
    "audit": "Using the management console:\n1. Logon to Security Center Console.\n2. Select Settings.\n3. Click Notification.\n4. Review notification settings and ensure all high-risk items are enabled.",
    "expected_response": "4. Review notification settings and ensure all high-risk items are enabled.",
    "remediation": "Using the management console:\n1. Logon to Security Center Console.\n2. Select Settings.\n3. Click Notification.\n4. Enable all high-risk items on Notification setting.",
    "default_value": "Not enabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/111648.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 199,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "8.6",
    "title": "Ensure that Config Assessment is granted with privilege",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Center",
    "subdomain": "Utilize a Risk-rating Process",
    "description": "Grant Security Center’s Cloud Platform Configuration Assessment the privilege to\naccess other cloud product.",
    "rationale": "Prior to using Cloud Platform Configuration Assessment, it requires privilege to assess\nother cloud product’s settings.",
    "audit": "Using the management console:\n1. Logon to Security Center Console.\n2. Select Config Assessment.\n3. Ensure that the prompt of asking privilege is not shown.",
    "expected_response": "3. Ensure that the prompt of asking privilege is not shown.",
    "remediation": "Using the management console:\n1. Logon to Security Center Console.\n2. Select Config Assessment.\n3. Click Authorize.",
    "default_value": "No privilege is authorized by default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/42302.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 201,
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
    "cis_id": "8.7",
    "title": "Ensure that scheduled vulnerability scan is enabled on all servers",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security",
    "domain": "Security Center",
    "subdomain": "Protect Dedicated Assessment Accounts",
    "description": "Ensure that scheduled vulnerability scan is enabled on all servers.",
    "rationale": "Be sure that vulnerability scan is performed periodically to discover system\nvulnerabilities in time.",
    "audit": "1. Logon to Security Center Console.\n2. Select Vulnerabilities.\n3. Click Settings.\n4. Ensure that all type of vulnerabilities is enabled.\n5. Ensure that High and Medium vulnerabilities scan level are enabled.",
    "expected_response": "4. Ensure that all type of vulnerabilities is enabled.\n5. Ensure that High and Medium vulnerabilities scan level are enabled.",
    "remediation": "1. Login to Security Center Console.\n2. Select Vulnerabilities.\n3. Click Settings.\n4. Apply all type of vulnerabilities.\n5. Enable High and Medium vulnerabilities scan level.",
    "default_value": "Not enabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/109076.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 203,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "8.8",
    "title": "Ensure that Asset Fingerprint automatically collects asset fingerprint data",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "security",
    "domain": "Security Center",
    "subdomain": "Compare Back-to-back Vulnerability Scans",
    "description": "The Enterprise Edition enables asset fingerprint collection for endpoints providing a\ncollection of port, software, processes, scheduled tasks and middleware in Security\nCenter.",
    "rationale": "The Enterprise Edition allows for enhanced investigation collection of artifacts to identify\nroot cause in a more timely manner of single or multiple server instances hosted within\nthe cloud.",
    "audit": "Using the management console:\n1. Logon to Security Center Console\n2. Select Investigation > Asset Fingerprints\n3. Click Settings\n4. Ensure the Refresh Frequencies are all set to Collected once a day",
    "expected_response": "4. Ensure the Refresh Frequencies are all set to Collected once a day",
    "remediation": "Using the management console:\n1. Logon to Security Center Console\n2. Select Investigation> Asset Fingerprints\n3. Click Setting and set the Refresh Frequencies\n4. Set refresh frequency Automatic collection to Collected once a day",
    "default_value": "Not Enabled",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://www.alibabacloud.com/help/doc-detail/146565.htm"
    ],
    "source_pdf": "CIS_CIS_Alibaba_Cloud_Foundation_Benchmark_v2.0.0.pdf",
    "page": 205,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D6"
    ]
  }
]
""")


def get_alibaba_cis_registry() -> list[dict]:
    """Return the complete CIS control registry as a list of dicts."""
    return ALIBABA_CIS_CONTROLS


def get_alibaba_control_count() -> int:
    """Return total number of CIS controls."""
    return len(ALIBABA_CIS_CONTROLS)


def get_alibaba_automated_count() -> int:
    """Return count of automated controls."""
    return sum(1 for c in ALIBABA_CIS_CONTROLS if c["assessment_type"] == "automated")


def get_alibaba_manual_count() -> int:
    """Return count of manual controls."""
    return sum(1 for c in ALIBABA_CIS_CONTROLS if c["assessment_type"] == "manual")


def get_alibaba_dspm_controls() -> list[dict]:
    """Return controls relevant to DSPM (Data Security Posture Management)."""
    return [c for c in ALIBABA_CIS_CONTROLS if c.get("dspm_relevant")]


def get_alibaba_rr_controls() -> list[dict]:
    """Return controls relevant to Ransomware Readiness."""
    return [c for c in ALIBABA_CIS_CONTROLS if c.get("rr_relevant")]


def get_alibaba_controls_by_service_area(service_area: str) -> list[dict]:
    """Return controls filtered by service area."""
    return [c for c in ALIBABA_CIS_CONTROLS if c["service_area"] == service_area]


def get_alibaba_controls_by_severity(severity: str) -> list[dict]:
    """Return controls filtered by severity."""
    return [c for c in ALIBABA_CIS_CONTROLS if c["severity"] == severity]
