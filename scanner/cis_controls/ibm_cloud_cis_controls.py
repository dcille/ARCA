"""CIS IBM Cloud Foundations Benchmark v2.0.0 — Complete Control Registry.

Auto-generated from the unified CIS controls library.
Contains ALL 73 controls (7 automated, 66 manual).
Each control includes full metadata, audit procedures, detection commands,
remediation guidance, and DSPM/Ransomware Readiness mapping.

Reference: CIS IBM Cloud Foundations Benchmark v2.0.0 (2024)
Source: CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf

Total controls: 73 (7 automated, 66 manual)
"""

import json as _json


# Control registry — 73 controls
IBM_CLOUD_CIS_CONTROLS: list[dict] = _json.loads(r"""
[
  {
    "cis_id": "1.1",
    "title": "Monitor account owner for frequent, unexpected, or unauthorized logins",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "description": "Monitor login activity of the account owner to prevent unauthorized usage of the\nprivileged account.",
    "rationale": "The owner of an IBM Cloud account by default has administrative privileges across the\naccount. There may be other users also assigned administrative privileges to the\naccount.\nTo prevent unauthorized or unintended usage, login credentials should never be shared\nand users in an organization should be granted least privilege to complete their required\ntasks. To manage the account, administrators are granted permissions to manage\nservices and Cloud resources. Therefore, access by the account owner to the account\nto run tasks should be minimum. By monitoring the number of times that the account\nowner and administrative users log in to the account, you can:\n• Monitor administrative access to the IBM Cloud account\n• Identify abnormal behavior\n• Enforce that administrators and operators of the services in your Cloud account\nare the ones managing the Cloud resources with their controlled and limited\npermissions.\nWhen a user logs in to the account, a security login event is generated. The event\nreports who has logged in successfully in the account. You can use these security\nevents to monitor the number of times that administrative privilege users have logged in\nto the account and generate an alert if the number exceeds a threshold that you set in a\nperiod of time that you specify.\nMonitoring login activity of users with administrative privileges can help prevent\nunauthorized or unintended actions taken in the account. Account switching may result\nin multiple login events being logged and this should be taken into account.",
    "audit": "Before you can monitor and manage IBM event data with IBM Cloud Logs, you must\nprovision an instance of the IBM Cloud Logs service.\nRefer to the IBM Cloud Logs documentation to provision and start using an instance of\nIBM Cloud Logs https://cloud.ibm.com/docs/cloud-logs?topic=cloud-logs-getting-started.",
    "expected_response": "Before you can monitor and manage IBM event data with IBM Cloud Logs, you must",
    "remediation": "Complete the following steps to monitor how many times an account owner logs in to\nthe account:\nFirst, you need to identify the email of the account owner.\n1. In the Cloud UI, go to Manage, Access (IAM), then select Users.\n2. Identify the users identified with administrator privileges.\n3. Select the account owner. Then, click Details.\n4. Copy the email address of the account owner.\nLaunch the Activity Tracker instance in Frankfurt. This is the instance where login\nsecurity events are collected in the account. In the Views section, select the\nEverything view. Then, enter the following query in the search bar:\n(action login) AND initiator.name:<email address>\nReplace with the account owner's email address. The view now reports all the login\nactions that are reported for the account owner.\nNext, you can define an alert on the view to get a notification when N number of events\nare received within a 24 hour period. The value of N depends on how you operate your\ncloud. You can start with a default value of 25 and increase or decrease depending on\nthe tasks that the account administrator can perform in the account.",
    "default_value": "no default value.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/cloud-logs"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 18,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.2",
    "title": "Ensure API keys unused for 180 days are detected and optionally disabled",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Alert on Account Login Behavior Deviation",
    "description": "Monitor API key usage in your account and search for API keys that are unused or used\ninfrequently.",
    "rationale": "If an API key is unused for long period in your account, it must be suspended or\ndisabled as a security best practice. All API keys, even those that are used infrequently,\nmust be rotated periodically.\nTo reduce the likelihood of accidental exposure or leaking, monitoring for infrequently\nused API keys can indicate that an API key can be suspended and even deleted, if\nthere is no anticipated future usage.",
    "audit": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Click Manage, Access (IAM), and select Inactive Identities\n3. Click Update report to view the most recent report of inactive identities in your\naccount\n4. Select the API keys tab to review a list of unused API keys",
    "remediation": "On the Inactive Identities report under API keys tab, review and remove the API\nkeys no longer in use.\nTo delete inactive identities that are no longer in use for over 180 days, click the\nActions icon, Remove",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-id-inactive-identities"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
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
    "title": "Ensure API keys are rotated every 90 days",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Disable Dormant Accounts",
    "description": "Replace production API keys with new API keys regularly, every 90 days for example,\nas a best practice to secure your account.",
    "rationale": "API key rotation can help reduce the impact to your organization if an API key becomes\nexposed or compromised. If you suspect that a key might have been leaked or\ncompromised, the key must be rotated out of production and deleted.",
    "impact": "Any resource that is using an API key that has been rotated out of production will\nencounter errors until the API key has been updated.",
    "audit": "Using Console:\nTo find out when an API key was created, complete the following steps:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access(IAM), API keys.\n3. Identify an API key and from the Actions menu, select Details.\n4. View the date the API key was created.",
    "remediation": "Using Console:\nTo create new API key, complete the following steps:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM), API keys.\n3. Click Create an IBM Cloud API key.\nTo rotate an API key, replace an old API key anywhere it is used with the newly\ncreated API key.\nDelete an old API key:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM), API keys.\n3. Identify the API key you want to delete, and from the Actions menu, select\nDelete.\nYou can also opt to use IBM Cloud Secrets Manager to auto-rotate keys -\nhttps://www.ibm.com/products/secrets-manager",
    "default_value": "By default, an API key rotation mechanism is not enabled. API key rotation is a manual\nprocess.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-userapikey",
      "2. https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-automatic-",
      "rotation&interface=ui"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 22,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
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
    "cis_id": "1.4",
    "title": "Restrict user API key creation and service ID creation in the account via IAM roles",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Limit Access to Script Tools",
    "description": "Use IAM settings to restrict user API key creation and service ID (and related API key)\ncreation in the account. Enable both settings to restrict all users in the account from\ncreating user API keys and service IDs except those with an IAM policy that explicitly\nallows it.",
    "rationale": "API keys authenticate IBM Cloud identities. Once an API key has been created, an\nidentity can use it to authenticate and perform any action the identity has access to in\nany account where that identity is valid and has access, even a different account from\nthe one where the API key was created. Service IDs can be granted a subset of access\nthat a user has, and then used to authenticate and perform actions in the account.\nService IDs are intended to be used by applications and other programmatic entities,\nand so they persist in an account even after users who created them or had access to\nthem have been deleted.\nCreating an unauthorized service ID or API key on an existing service ID could be a way\nfor a user to gain unauthorized access to an account after they've been deleted, and so\ncreation of service IDs and API keys should be limited to those users who have a\nlegitimate need to do so.",
    "impact": "This process involves two IAM controls. Enabling the restriction of user API keys will\nprevent users in an account from creating user API keys, except those with an explicit\nIAM policy to do so. Enabling the restriction of service ID creation will prevent users in\nan account from creating service IDs, except those with an explicit IAM policy to do so.",
    "audit": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Click Manage, Access (IAM).\n3. Click Settings.\n4. In the Account section of the Settings page, ensure that Restrict API key creation\nand Restrict service ID creation are enabled.",
    "expected_response": "4. In the Account section of the Settings page, ensure that Restrict API key creation",
    "remediation": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Click Manage, Access (IAM).\n3. Click Settings.\n4. In the Account section of the Settings page, ensure that Restrict API key creation\nand Restrict service ID creation are enabled.\n5. Once enabled, only users with the correct IAM policies will be able to create user\nAPI keys and service IDs.",
    "default_value": "By default, user API key creation and service ID creation are not restricted.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/cloud-logs",
      "2. https://cloud.ibm.com/docs/account?topic=account-userapikey"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 24,
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
    "cis_id": "1.5",
    "title": "Ensure no owner account API key exists",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "API keys by definition allow access to your account and resources in your account. The\nAPI key authenticates the identity and allows all access assigned to the identity for\nwhich it was created, therefore an API key created by user with administrative privileges\nhas administrative level access to resources in the account.",
    "rationale": "In accordance with the practice of granting least privilege, API keys should not be\ncreated by an account owner because of the level of privilege automatically granted to\naccount-owner created API keys.",
    "impact": "The API key authenticates the identity and allows all access assigned to the identity for\nwhich it was created, therefore an API key created by an account owner has account-\nowner level access to resources in the account.",
    "audit": "To check for the existence of an API key created by an administrative user, complete\nthe following steps.\n1. Login as any administrative user at cloud.ibm.com\n2. Click Manage, Access (IAM)\n3. Click API keys\n4. Check for any API keys that appear under the My IBM Cloud API keys view",
    "remediation": "To delete an API key, complete the following steps:\n1. Login as the administrative user at cloud.ibm.com\n2. In the console, go to Manage, Access (IAM)\n3. Click on API keys\n4. Identify the row of the API key that you want to delete and select Delete from the\nActions List of actions icon menu (found on the right hand side of the row).\n5. Then, confirm the deletion by clicking Delete.\n6. If you have scenarios where you need a higher level of access, then you should\nsetup a Trusted Profile with these privileges and use it with a less privileged\nidentity",
    "default_value": "By default, there are no account-owner API keys created in an account.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-userapikey",
      "2. https://cloud.ibm.com/docs/account?topic=account-create-trusted-profile"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 26,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.6",
    "title": "Ensure multi-factor authentication (MFA) is enabled for all users in account",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Limit Access to Script Tools",
    "description": "Requires users to provide multiple factors of login credentials to authenticate their\nidentity and gain access to IBM Cloud resources.",
    "rationale": "Multifactor authentication (MFA) adds an additional layer of security to an account by\nrequiring users to provide an additional login credential. This requirement helps protect\naccounts from stolen, phished, or weak password exploits.",
    "impact": "Depending on the administrator’s selection, users might be required to provide an\nadditional authentication factor prior to gaining access to IBM Cloud resources. API\nkeys for users and service IDs continue to work after MFA is enabled.",
    "audit": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. Click Settings, Account login.\n4. Verify Multifactor authentication does not say None",
    "remediation": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. Click Settings, Account login.\n4. Click Edit for the Account login setting.\n5. Select Non-federated users only, or All users depending on which type of\nauthentication you want to require.\n6. Select the checkbox to confirm that you understand the impact of requiring MFA\nfor users in your account, if you select the non-federated users only option.\n7. Click Update.",
    "default_value": "By default, MFA is disabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-enablemfa"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 28,
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
    "title": "Ensure multi-factor authentication (MFA) is enabled for the account owner and all administrative users",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Require Multi-factor Authentication",
    "description": "Requires account owner to provide multiple factors of login credentials to authenticate\ntheir identity and gain access to IBM Cloud resources.",
    "rationale": "Multifactor authentication (MFA) adds an additional layer of security to an account by\nrequiring users to provide an additional login credential. This requirement helps protect\naccounts from stolen, phished, or weak password exploits.",
    "impact": "Depending on the administrator’s selection, users might be required to provide an\nadditional authentication factor prior to gaining access to IBM Cloud resources. API\nkeys for users and service IDs continue to work after MFA is enabled.",
    "audit": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. Click Settings, Account login.\n4. Verify Multifactor authentication does not say None.",
    "remediation": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. Click Settings, Account login.\n4. Click Edit for the Account login setting.\n5. Select Non-federated users only, or All users depending on which type of\nauthentication you want to require.\n6. Select the checkbox to confirm that you understand the impact of requiring MFA\nfor users in your account, if you select the non-federated users only option.\n7. Click Update.",
    "default_value": "By default, MFA is disabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-enablemfa"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 30,
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
    "cis_id": "1.8",
    "title": "Ensure multi-factor authentication (MFA) is enabled at the account level",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Use Multifactor Authentication For All Administrative",
    "description": "Requires users to provide multiple factors of login credentials to authenticate their\nidentity and gain access to IBM Cloud resources.",
    "rationale": "Multifactor authentication (MFA) adds an additional layer of security to an account by\nrequiring users to provide an additional login credential. This requirement helps protect\naccounts from stolen, phished, or weak password exploits.",
    "impact": "Depending on the administrator’s selection, users might be required to provide an\nadditional authentication factor prior to gaining access to IBM Cloud resources. API\nkeys for users and service IDs continue to work after MFA is enabled.",
    "audit": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. Click Settings, Account login.\n4. Verify Multifactor authentication does not say None",
    "remediation": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. Click Settings, Account login.\n4. Click Edit for the Account login setting.\n5. Select Non-federated users only, or All users depending on which type of\nauthentication you want to require.\n6. Select the checkbox to confirm that you understand the impact of requiring MFA\nfor users in your account, if you select the non-federated users only option.\n7. Click Update.",
    "default_value": "By default, MFA is enabled but older accounts may not have this as a default.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-enablemfa"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 32,
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
    "cis_id": "1.9",
    "title": "Ensure contact email is valid",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Use Multifactor Authentication For All Administrative",
    "description": "In order to receive emails and account alerts related to an IBM Cloud account, a valid\nemail address should always be on record with IBM Cloud. If you lose access to an\nemail address, you should update your email address on record to ensure continuity of\ncorrespondence.",
    "rationale": "Maintaining a valid email address on record is important to make sure you receive\nimportant account related information.",
    "impact": "Maintaining a valid email address on record allows you to receive correspondence from\nIBM Cloud about your account.",
    "audit": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Click Avatar icon, Profile.\n3. Verify the Email field in the Contact information section contains your correct\nemail address.",
    "remediation": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Click Avatar icon, Profile.\n3. Click the Edit link in the Contact information section\n4. Update your email to the correct email address.",
    "default_value": "By default, the email address on record is provided during account creation.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-usersettings"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 34,
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
    "cis_id": "1.10",
    "title": "Ensure contact phone number is valid",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Maintain Contact Information For Reporting Security",
    "description": "A valid phone number should be on record with IBM Cloud in the event that IBM needs\nto contact you regarding your IBM Cloud account.",
    "rationale": "Maintaining a valid phone number on record is important to make sure you receive\nimportant account related information from IBM Cloud when necessary.",
    "audit": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Click Avatar icon, Profile.\n3. Verify the Primary phone number and Alternate phone number fields in the\nContact information section contain your correct phone numbers.",
    "remediation": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Click Avatar icon, Profile.\n3. Click the Edit link in the Contact information section\n4. Update your Primary and Alternate phone numbers.",
    "default_value": "By default, there is no phone number on record.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-usersettings"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 36,
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
    "cis_id": "1.11",
    "title": "Ensure Trusted Profiles are used in place of ServiceIDs wherever feasible",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Maintain Contact Information For Reporting Security",
    "description": "IBM Cloud trusted profiles are used to securely manage identity and access for\napplications running on IBM Cloud without relying on static credentials like API keys.",
    "rationale": "One use of Trusted Profiles is to allow an application running on an IBM Cloud compute\nresource to assume the Trusted Profile and its access based on the identity of the\ncompute resource where it is running, eliminating the need for the application to store\nand manage an API key.\nTrusted Profiles are preferred over ServiceIDs because they offer a more secure,\nscalable, and maintainable approach to identity and access management. Unlike\nServiceIDs, which are static and tied to specific credentials, Trusted Profiles leverage\nthe built-in identities of compute resources to assign least privilege access to\napplications running on those compute resources. They reduce the risk of credential\nsprawl and simplify auditing and compliance. By using Trusted Profiles for application\nidentities, organizations can reduce the need to store and rotate API keys, improving\ntheir security posture and streamlining management.",
    "impact": "When a Trusted Profile is created in IBM Cloud, you can assign compute resources a\ntrust relationship, allowing them to assume the Trusted Profile, and configure access\npolicies.",
    "audit": "To check if you have trusted profiles set up in your IBM Cloud account\n1. Log in to the IBM Cloud Console\n2. Navigate to IAM, Trusted Profiles.\nThis section displays all existing profiles, including those assigned to users, federated\nidentities, or compute resources like Kubernetes clusters.",
    "remediation": "To create new trusted profile, complete the following steps:\n1. Log in to the IBM Cloud Console\n2. Navigate to Manage, Access (IAM), Trusted profiles\n3. Click Create and define the profile’s name, description, trusted entity type (such\nas federated users or compute resources), and access conditions.",
    "default_value": "By default, IBM Cloud accounts do not have trusted profile configured.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-create-trusted-profile"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 38,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.12",
    "title": "Ensure Context-Based Restrictions are implemented to enforce secure, conditional access to critical resources based on network location, IP range, or identity attributes",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Maintain Contact Information For Reporting Security",
    "description": "IBM Cloud Context-Based Restrictions are a security feature that allows administrators\nto control access to cloud resources based on the context of the request, such as the IP\naddress the request is made from, not just the identity of the user or service.",
    "rationale": "IBM Cloud's Context-Based Restrictions (CBRs) provide an essential layer of defense\nby enforcing access conditions based on network location or type of endpoint, not just\nIAM roles. This means even if a user has the correct permissions, their request can be\nblocked if it originates from an untrusted context. By implementing CBRs, organizations\ncan reduce the risk of unauthorized access, enforce compliance policies, and protect\ncritical services like Cloud Object Storage, Key Protect, and Secrets Manager. In short,\nCBRs help turn identity-based access into context-aware security, which is vital in\ntoday’s hybrid and distributed environments.",
    "impact": "Once a context-based restriction is enabled in IBM Cloud, you can enforce access\ncontrols that go beyond identity and role by evaluating the context of each request.",
    "audit": "To check if you have a Context-Based Restriction (CBR) set in IBM Cloud, follow these\nsteps:\n1. Log in to the IBM Cloud Console:\n2. Navigate to IAM, Context-based restrictions in the left-hand menu\n3. Under the Rules tab, you'll see a list of all active CBR rules in your account. Each\nrule will show:\no The network zone it applies to (e.g., IP ranges, VPCs)\no The target service or resource (e.g., Cloud Object Storage, Key Protect)\no The action (allow or deny)\no Any conditions or exceptions\n4. You can click on each rule to view its details, including which users or services it\naffects and when it was last modified.\n5. If no rules are listed, then no CBRs are currently enforced in your account.",
    "remediation": "To create new trusted profile, complete the following steps:\n1. Log in to the IBM Cloud Console:\n2. Navigate to Manage, Context-based restrictions, then select Network\nzones from the left navigation menu.\n3. click Create and define the network zone(s) you want to allow access from,\nusing allowed or denied IP addresses, subnets, or ranges, VPCs, and IBM Cloud\nservices.\n4. Select Rules from the left navigation menu\n5. Click Create and select the service, APIs, and resources you want the rule to\napply to, select the context including the zone you defined, and specify whether\nto enable or report on this rule.",
    "default_value": "By default, there are no context-based restriction (CBR) rules set and are an optional\nsecurity feature that must be explicitly configured by an administrator.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-cbr",
      "2. https://cloud.ibm.com/docs/account?topic=account-context-restrictions-",
      "whatis#cbr-adopters"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 40,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "1.13",
    "title": "Ensure limitations on External Identity Interactions are Enabled",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Maintain Contact Information For Reporting Security",
    "description": "Use IAM settings to restrict external identity interactions in your account. This will block\nall API calls if the calling userID is not authenticated to your account and has logged in\nusing an API key in a different account.",
    "rationale": "When a user authenticates using an API key in one account, that user can use their\ntoken to do actions in any account they are a member of providing they have access\npolicy.",
    "impact": "A user’s exposed or unrotated API key in another account can’t be used to access that\nuser’s resources in your account.",
    "audit": "To check if you have the External identities interactions limitation set in IBM Cloud,\nfollow these steps:\n1. Log in to the IBM Cloud Console\n2. Go to Manage, IAM\n3. Select Settings in the left-hand menu\n4. Select the Resources tab\n5. In the External identity interactions box, select Edit\n6. Ensure the Limited option is selected",
    "expected_response": "6. Ensure the Limited option is selected",
    "remediation": "1. Log in to the IBM Cloud Console\n2. Go to Manage, IAM\n3. Select Settings in the left-hand menu\n4. Select the Resources tab\n5. In the External identity interactions box, select Edit\n6. When turning the setting on for the first time in an existing account, it is\nrecommended to enable the setting in Report-only mode for 30 days, then\nmonitor ICL logs for any calls made from other accounts. If valid cross-account\nflows are found, they can be explicitly allowed by creating a trusted profile with\nthe appropriate access and allowing the identity in a different account to assume\nthe trusted profile in your account.\n7. After remediating any desired cross-account interactions, set the value of the\nsetting to Limited.",
    "default_value": "By default, there are no restrictions on interactions when a user in your account has\nauthenticated in a different account they are also a member of.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-cross-acct"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
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
    "cis_id": "1.14",
    "title": "Ensure IAM users with the same level of access are members of access groups and IAM policies are assigned only to access groups or Trusted Profiles",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Maintain Contact Information For Reporting Security",
    "description": "Simplify and secure the access management process by using access groups or\nTrusted Profiles when you assign access to groups of users with identical access\nneeds.",
    "rationale": "You can create an access group or a Trusted Profile so that you can organize a set of\nusers and service IDs into a single entity that makes it easy for you to assign access.\nYou can assign a single policy to the group instead of assigning the same access\nmultiple times for each individual user or service ID.\nUsing access groups or Trusted Profiles reduces the number of policies that must be\ncreated and managed in the account and simplifies the process of adding new users or\nservice IDs or modifying user and service IDs access.",
    "audit": "Using Console:\nAudit user access policies:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. Click Users and select a user by clicking on the username.\n4. Click Access Policies.\n***If the user has individual access policies and you wish to remove them, complete the\nappropriate remediation steps.",
    "remediation": "Using Console:\nAssign an access policy to an Access Group:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access(IAM).\n3. Click Access Groups or Trusted Profiles\n4. Click an Access Group or Trusted Profile name, then click the Access tab\n5. Click Assign access.\nAdd members to an Access Group or Trusted Profile:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access(IAM).\n3. Click Access Groups or Trusted Profiles.\n4. Click an Access Group or Trusted Profile name.\n5. Click Add.\nDelete an access policy for a user:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access(IAM).\n3. Click Users.\n4. Click on a user name.\n5. Click the Access tab\n6. Locate the row containing the access policy you wish to remove. Click the\nactions icon corresponding to that row and click Remove.",
    "default_value": "By default, only the Public Access Group is enabled in IBM Cloud accounts.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-groups",
      "2. https://cloud.ibm.com/docs/account?topic=account-create-trusted-profile"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 44,
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
    "cis_id": "1.15",
    "title": "Ensure a support access group has been created to manage incidents with IBM Support",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "If you experience problems with IBM Cloud®, you can use support cases to get help\nwith technical, access (IAM), billing & usage, and invoice or sales inquiry issues. You\ncan create and manage a support case by using the Support Center. Access to Support\nCenter is governed via IAM roles. In order to access Support Center, a user must have\nviewer or higher on the Support Center service. To create or edit service cases, a user\nmust have editor or higher on the Support Center service. After you submit a support\ncase, the support team investigates the issue based on your type of support plan.\nThe types of available support depends on the support level of the account. Your\nsupport plan also determines the severity level that you can assign to support cases.\nFor more information, see Case severity and response time.",
    "rationale": "Support cases are used to raise issues to IBM Cloud. Access to IBM Cloud Support\nCenter is managed via IAM roles. IAM roles can be used to efficiently control which\nusers in an organization can view support cases, which can view, edit, and delete\nsupport cases, and which have no access at all. You can configure different levels of\nSupport Center access using Access Groups.",
    "impact": "Users with access to IBM Cloud Support Center can create and/or manage support\ntickets based on their IAM role. Support Center access should be managed and\nassigned using Access Groups.",
    "audit": "Using Console:\n1. In the IBM Cloud console, go to Manage, Access (IAM), and then select Access\nGroups.\n2. Look for an access group relating to Support Center. Access Group names are\ncustomizable and vary from customer to customer.\n3. To verify the access policies for an Access Group, click on an Access Group\nname and then click Access policies.\n4. Check for access policies on the Support Center service.",
    "remediation": "Using Console:\n1. In the IBM Cloud console, go to Manage, Access (IAM), and then select Access\nGroups.\n2. Select Create Access Group.\n3. Give the Access Group a descriptive name, for example, Support Center Viewers\nor Support Center Admins.\n4. Optionally, provide a brief description.\n5. Click Create.\n6. Once the Access Group is created, click on the Access Policies tab.\n7. Click Assign Access.\n8. Click on Account Management and select Support Center from the drop down\nmenu.\n9. Select the Support Center role(s) that meet your use case. Descriptions are\nprovided for each role in the IAM UI.\n10. Click add.\n11. Click Assign.\n12. Click on the Users tab.\n13. Click Add users\n14. Select users from the list and click Add to group.",
    "default_value": "By default, users do not have access to IBM Cloud Support Center.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-using-avatar"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 46,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "1.16",
    "title": "Ensure Minimal Number of Users are Granted Administrative Privileges",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Designate Management Personnel to Support Incident",
    "description": "Comply with the principle of granting least privilege by using Access Groups or Trusted\nProfiles to manage admin privileges and by avoiding the use of broadly scoped access\npolicies.",
    "rationale": "The principle of granting least privilege mandates that a user must only be given access\nto the resources that are required to complete their task. This task can be hard to\nmaintain when managing large numbers of users. Instead of assigning administrative\nprivileges to individual users, create Access Groups with administrative privileges and\nadd or remove users from these Access Groups as needed. Additionally, instead of\nusing the Platform Administrator role for all Platform Services or all IAM-enabled\nservices, IBM Cloud users can grant access to specific resources and account\nmanagement services to better comply with the principle of granting least privilege.",
    "impact": "Managing administrative access via Access Groups or Trusted Profiles simplifies the\nprocess of adding/removing admin privileges from users in the account. Having too\nmany users with Administrative privileges goes against the principle of granting least\nprivileges and mean many possible holes for any security attack.",
    "audit": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access(IAM).\n3. Click Users and select a User by clicking on the User name.\n4. Click on the Access Policies tab.\nView the access policies assigned to the User to verify if that User has\nAdministrator Role assigned.\n5. Review Access Groups and Trusted Profiles to determine which grant\nAdministrator privileges.\n6. For Access Groups and Trusted Profiles that grant Administrator.\nprivileges, review which users are members of the Access Groups or allowed to\nassume the Trusted Profiles.\n7. Verify that all users who have Administrator privileges have a legitimate need for\nthose privileges.",
    "remediation": "Using Console:\nTo remove excessive number of Users with Administrative privileges, follow the\nfollowing steps.\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access(IAM).\n3. Click Users and select an User by clicking on the User name.\n4. Click on the Access Policies tab.\n5. View the access policies assigned to the User to verify if that User has\nAdministrator Role. assigned on all Platform Services or all IAM-enabled\nservices.\n6. Review Access Groups and Trusted Profiles to determine which grant\nAdministrator privileges.\n7. For Access Groups and Trusted Profiles that grant Administrator privileges,\nreview which users are members of the Access Groups or allowed to assume the\nTrusted Profiles.\n8. If there are users who have Administrator privileges but do not have a legitimate\nneed for them, remove the user’s access policy or remove the user from the\nAccess Group or Trusted. Profile. Alternatively you may remove the user from\nthe account.",
    "default_value": "By default, there are no administrator Access Groups in the account.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-userroles"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 48,
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
    "cis_id": "1.17",
    "title": "Ensure Minimal Number of Service IDs are Granted Administrative Privileges",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Maintain Inventory of Administrative Accounts",
    "description": "Comply with the principle of granting least privilege by using Access Groups to manage\nadmin privileges and by avoiding the use of many Service IDs with Administrative\nPrivileges.",
    "rationale": "The principle of granting least privilege mandates that a Service ID must only be given\naccess to the resources that are required to complete their task. This task can be hard\nto maintain when managing large numbers of users. Instead of assigning administrative\nprivileges to an individual Service ID, create Access Groups with administrative\nprivileges and add or remove Service IDs from these Access Groups as needed.\nAdditionally, instead of using the Platform Administrator role for all Platform Services or\nIAM-enabled services, IBM Cloud users can grant access to specific resources and\naccount management services to better comply with the principle of granting least\nprivilege.",
    "impact": "Managing administrative access via Access Groups simplifies the process of\nadding/removing admin privileges from users in the account. Having too many Service\nIDs with Administrative privileges goes against the principle of granting least privileges\nand mean many possible holes for any security attack.",
    "audit": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access(IAM).\n3. Click Service IDs and select a Service ID by clicking on the Service ID name.\n4. Click on the Access Policies tab.\n5. View the access policies assigned to the Service ID to verify if that Service ID\nhas Administrator Role assigned on all Platform Services or all IAM-enabled\nservices\n6. Verify that all service IDs that have Administrator privileges are in use and have a\nlegitimate need for those privileges.",
    "remediation": "Using Console:\nTo remove excessive number of Users with Administrative privileges, follow the\nfollowing steps.\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access(IAM).\n3. Click Service IDs and select a Service ID by clicking on the Service ID name.\n4. Click on the Access Policies tab.\n5. View the access policies assigned to the Service IDUser to verify if that Service\nID has Administrator Role assigned on all IAM-Enabled services or all Platform\nService\n6. Review Access Groups and Trusted Profiles to determine which grant\nAdministrator privileges.\n7. For Access Groups and Trusted Profiles that grant Administrator privileges,\nreview which Service IDs are members of the Access Groups or allowed to\nassume the Trusted Profiles.\n8. If there are Service IDs that have Administrator privileges but do not have a\nlegitimate need for them, remove the Service ID’s access policy or remove the\nService ID from the Access Group or Trusted Profile. Alternatively you may\nremove the Service ID from the account.",
    "default_value": "By default, there are no administrator Access Groups in the account.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-userroles"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 51,
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
    "cis_id": "1.18",
    "title": "Ensure IAM Does Not Allow Public Access to Cloud Services",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "IBM Cloud features the capability for users with specific access roles to create access\npolicies that allow all users (authenticated and non-authenticated) to access resources\nin the account. This “all users” access in turn ends up in public (including non-\nauthenticated) access to resources. Determine if this capability is required by your\norganization and disable if not required.",
    "rationale": "Some customer use cases require that certain files or data are made available for all\nusers to access, both authenticated and non-authenticated. Even if the public access\nsetting is enabled, resources in your account are not publicly accessible unless an\nadministrator level user has explicitly created a policy to create public access for a\nresource. As a best practice, if this capability is not required by your organization, it\nmust be disabled to prevent unintentional misuse.",
    "impact": "If the public access setting is enabled in the account, an administrator level user can\ncreate access policies to make resources publicly accessible. Resources are not\npublicly accessible unless an administrator creates an access policy, regardless of\nsetting.",
    "audit": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. Click Settings.\n4. In the public access section of IAM Settings, observe the Public access group\nsetting.\n5. If the Public access group setting is disabled, IAM is not providing public access.\n6. If the Public access group setting is enabled, proceed to the Access groups page\nby clicking Access Groups.\n7. From the list of Access Groups, select Public Access by clicking on the Access\nGroup name.\n8. Ensure that there are no access policies present for services in the list of access\npolicies.",
    "expected_response": "5. If the Public access group setting is disabled, IAM is not providing public access.\n6. If the Public access group setting is enabled, proceed to the Access groups page\n8. Ensure that there are no access policies present for services in the list of access",
    "remediation": "Using Console:\nTo disable the Public Access Group:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. Click Settings, Public Access.\n4. Disable Public Access to disable the Public Access Group.\nTo keep the Public Access Group enabled and verify that no access policies exist:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. Click Settings.\n4. In the public access section of IAM Settings, observe the Public access group\nsetting.\n5. If the Public access group setting is disabled, IAM is not providing public access.\n6. If the Public access group setting is enabled, proceed to the Access groups page\nby clicking Access Groups.\n7. From the list of Access Groups, select Public Access by clicking on the Access\nGroup name.\n8. Ensure that there are no access policies present in the list of access policies.\n9. To delete an access policy, click on the action menu icon for the access policy\nand click Remove.",
    "default_value": "By default, the public access group is enabled and there is no public access allowed.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-public",
      "2. https://cloud.ibm.com/docs/account?topic=account-public&interface=ui#disable-",
      "public-api"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 54,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "1.19",
    "title": "Ensure Inactive User Accounts are Suspend",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Revoke access privileges for users in an IBM Cloud account that are inactive, typically\ndefined as user accounts with no logins in a given time frame.",
    "rationale": "Users and other identities can become inactive for a number of reasons, for example,\nvacation, parental leave, new roles within the company, or sick leave for user identities.\nIf an identity's access needs to be temporarily revoked, you can suspend the user in the\naccount to prevent access.",
    "impact": "After a user’s status is updated to Suspended, the user is unable to gain access to any\nIBM Cloud resources.",
    "audit": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM)`.\n3. To view a list of inactive identities in the account, click Gain Insight, Inactive\nIdentities\n4. Click Update report to view the most recent report of inactive identities in your\naccount\n5. The list will also show the status for each user in the account.\n6. To change a users' status, click on the Actions menu and select Remove name.\n7. Under User details, select the desired status in the User status drop down.\n8. Click Apply.\nTo check the last time a user logged in, follow the steps to enable Activity Tracker with\nIBM Cloud Logs in recommendation Enable audit logging for IBM Cloud Identity and\nAccess Management.",
    "remediation": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. To view a list of users in the account, click Users.\n4. The user list will also show the status for each user in the account.\n5. To suspend a user, click on a user name.\n6. Under User details, select Suspended in the User status drop down.\n7. Click Apply.",
    "default_value": "By default, if an IBMid is associated with the user, user accounts are Active; if no IBMid\nis associated with the user, user accounts are Pending. When a new user completes\nthe IBM Cloud onboarding agreement, the Pending status changes to Active.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/status",
      "2. https://cloud.ibm.com/apidocs/user-management#get-user-profile"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 57,
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
    "cis_id": "1.20",
    "title": "Enable audit logging for IBM Cloud Identity and Access Management",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management (IAM)",
    "subdomain": "Disable Dormant Accounts",
    "description": "Use the IBM Cloud Activity Tracker with IBM Cloud Logs service to monitor certain IAM\nevents.",
    "rationale": "As a security officer, auditor, or manager, you can use the IBM Cloud Activity Tracker\nwith IBM Cloud Logs service to track how users and applications interact with IBM\nCloud Identity and Access Management (IAM). You can use this service to investigate\nabnormal activity and critical actions and comply with regulatory audit requirements.",
    "impact": "Activity Tracker with IBM Cloud Logs allows you to track the following IAM events:\n• Managing access groups by creating and deleting groups or adding and\nremoving users\n• Creating, updating, or deleting service IDs\n• Creating, updating, or deleting API keys\n• Creating, updating, or deleting access policies\n• Logging in to IBM Cloud by using an API key, authorization code, passcode,\npassword, or an API key that is associated with a service ID",
    "audit": "Using Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Go to the Menu icon. Then, select Observability to access the Observability\ndashboard.\n3. Select Activity Tracker from the page navigation menu\n4. Check that you can see an IBM Cloud Activity Tracker with IBM Cloud Logs\ninstance in Frankfurt and one instance for each location where you operate in the\nIBM Cloud.",
    "remediation": "You must create an instance of the IBM Cloud Activity Tracker with IBM Cloud Logs\nservice in the Frankfurt region to start tracking IAM events. Use a minimum of a 7-day\nevent search.\nUsing Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Go to the Menu icon. Then, select Observability to access the Observability\ndashboard.\n3. Select Activity Tracker from the page navigation menu\n4. Click Create instance to create an instance of IBM Cloud Activity Tracker\nwith IBM Cloud Logs.\n5. In the Select a region drop down, choose Frankfurt.\n6. Select a pricing plan, service name, resource group, and provide optional tags.\nChoose a plan that offers a minimum of 7-day event search.\n7. Click Create",
    "default_value": "By default, audit logging with Activity Tracker with IBM Cloud Logs is not enabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account",
      "2. https://cloud.ibm.com/docs/atracker?topic=atracker-",
      "route_v2&interface=cli#route_behaviour",
      "3. https://cloud.ibm.com/docs/atracker?topic=atracker-getting-started",
      "4. https://cloud.ibm.com/docs/cloud-logs"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 59,
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
    "cis_id": "2.1.1.1",
    "title": "Ensure Cloud Object Storage encryption is done with customer managed keys",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Cloud Object Storage",
    "description": "Users can store objects in IBM Cloud Object Storage buckets by providing their own\nencryption keys which get applied at a per object level.",
    "rationale": "Users can have added security and granular control over the encryption keys at a per\nobject level.",
    "impact": "Users can configure Cloud Object Storage and use their own root keys when uploading\nobjects. For any key rotation (or new key usage) users will have to issue a GET\noperation with the old key and a PUT operation with the new key.",
    "audit": "Using API/CLI:\nUse of Server-Side Encryption with Customer-Provided Keys (SSE-C) can be validated\nby the following steps:\nNote: Ensure that you have completed the configuration setup to use the CLI by\nfollowing the guidelines on the Using the AWS CLI page\n1. Review the metadata of the object that is encrypted using the customer-provided\nkey. The operation can be performed using an API call or via a command-line\ninterface. Here is an example call to get the object metadata:\naws --endpoint https://s3.private.au-syd.cloud-object-storage.appdomain.cloud\ns3api head-object --bucket <bucket-name> --key <object-name> --sse-customer-\nalgorithm=AES256 --sse-customer-key=<customer-key-used-to encrypt-the-object>\n1. The presence of the object headers SSECustomerKeyMD5 and\nSSECustomerAlgorithm from the API/CLI response should confirm that the\nobject is encrypted using the key.",
    "expected_response": "Note: Ensure that you have completed the configuration setup to use the CLI by\nSSECustomerAlgorithm from the API/CLI response should confirm that the",
    "remediation": "Using API/CLI:\nObjects can be uploaded with your own key by using a PUT object request with key\nspecific headers.\nPlease refer to Server-Side Encryption with Customer-Provided Keys for additional\ninformation.",
    "default_value": "By default, all objects stored in IBM Cloud Object Storage are encrypted by using\nrandomly generated keys and an all-or-nothing-transform (AONT) also known as\nprovider managed keys. Clients can provide their own encryption keys for a per-object\nlevel encryption by using the IBM Cloud Object Storage Server-Side Encryption with\nCustomer-Provided Keys (SSE-C) option.",
    "detection_commands": [
      "Use of Server-Side Encryption with Customer-Provided Keys (SSE-C) can be validated",
      "aws --endpoint https://s3.private.au-syd.cloud-object-storage.appdomain.cloud"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-",
      "encryption",
      "2. https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-sse-",
      "c"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 64,
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
    "cis_id": "2.1.1.2",
    "title": "Ensure Cloud Object Storage Encryption is set to On with BYOK",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "You can use IBM Cloud encryption key management service, for example Key Protect,\nto bring your own root key (BYOK) to IBM Cloud and use it to add envelope encryption\nfor data that is stored in IBM Cloud Object Storage buckets.",
    "rationale": "When it comes to encryption of data at rest in IBM Cloud, the best practice is to allow\ncustomers to manage customer root keys (CRK) that are used to protect customer data\nstored in data and storage services in IBM Cloud. Bring your Own Key (BYOK) allows\ncustomers to ensure no one outside of their organization has access to the root key and\nand with the support of BYOK, customers can manage the lifecycle of their customer\nroot keys where they can create, rotate, delete those keys. This provides a significant\nlevel of control where those CRKs are managed by the customer, which in turn\nincreases both security control as well as meet relevant compliance requirements.\nThese CRKs can be used in turn to protect the data encryption keys used to encrypt the\ndata.",
    "impact": "For Bring your Own Key (BYOK) encryption with Cloud Object Storage integration and\nKey Protect key management service you will need to review and understand how you\ncan leverage the integration to handle key lifecycle events (for example key rotation,\ndeletion, restore). Refer to the Cloud Object Storage integration with Key Protect\nsection to learn about key lifecycle management and Key Protect product page to find\nout more about the key lifecycle events.",
    "audit": "You can use the IBM Cloud Object Storage bucket configuration properties to verify\nwhether a Cloud Object Storage bucket is enabled to use Key Protect.\nUsing Console:\nNavigate to your Cloud Object Storage instance:\n1. Log in to IBM Cloud at https://cloud.ibm.com\n2. Click the Menu icon and select Resource List\n3. On the Resource List page under Storage, select the Cloud Object Storage\ninstance that you have provisioned.\n4. Click on the appropriate bucket that you would like to check\n5. Click on Configuration and scroll down to Associated key management\nservice to check/confirm if a Key Protect key management service is associated",
    "expected_response": "whether a Cloud Object Storage bucket is enabled to use Key Protect.",
    "remediation": "You will not be able to add Key Protect as the key management service once data is\nalready written to a Cloud Object Storage bucket. In order to ensure that objects are\nencrypted using Key Protect root keys you will need to create a new Cloud Object\nStorage bucket, set it to use Key Protect key management service and then\nupload/copy the existing objects to this new bucket.",
    "default_value": "By default, use of Key Protect encryption key management service with IBM Cloud\nObject Storage buckets is not enabled.",
    "additional_information": "Creating a Cloud Object Storage bucket with Key Protect (Bring Your Own Key):\n1. From your Cloud Object Storage instance page, create a new Cloud Object\nStorage bucket by clicking Create bucket.\n2. To create the bucket, in the Create bucket section, select Custom bucket.\n3. In the bucket configuration section, you can select the option to use Key Protect\nunder Key management services\nNote: In order to configure a Cloud Object Storage bucket to use Key Protect key\nmanagement service you will need an instance of Key Protect along with appropriate\naccess authorization to your Cloud Object Storage instance.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. • Data encryption with IBM Cloud Object Storage:",
      "https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-",
      "encryption",
      "2. • Integrated service availability page: https://cloud.ibm.com/docs/services/cloud-",
      "object-storage/basics?topic=cloud-object-storage-service-availability",
      "3. • https://cloud.ibm.com/docs/services/cloud-object-storage/basics?topic=cloud-",
      "object-storage-compatibility-api-bucket-operations#compatibility-api-key-protect"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 66,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2"
    ]
  },
  {
    "cis_id": "2.1.1.3",
    "title": "Ensure Cloud Object Storage Encryption is set to On with KYOK",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "You can use IBM Cloud encryption key management services, for example, Hyper\nProtect Crypto Services to keep and manage exclusive control over the root keys used\nto add envelop encryption for data that is stored in IBM Cloud Object Storage buckets.",
    "rationale": "When it comes to encryption of data at rest in IBM Cloud, the best practice is to allow\ncustomers use encryption capabilities offered by Hardware Security Module crypto\nservice. IBM Cloud Hyper Protect Crypto Services offers Keep your Own Key (KYOK)\ncapabilities that allow customers to have exclusive key control over encryption keys.\nThis provides a significant level of control over encryption keys where only authorized\nusers have access (no privileged users included IBM Cloud Admins) to encryption keys,\nin turn increases both security control as well as meet relevant compliance\nrequirements.",
    "impact": "For Keep your Own Key (KYOK) encryption using IBM Cloud Hyper Protect Crypto\nServices key management service you will need to review and understand how key\nlifecycle events (for example key rotation) need to be handled. Refer to the Hyper\nProtect Crypto Services product page for details around the key lifecycle events\nsupported.",
    "audit": "You can use the IBM Cloud Object Storage bucket configuration properties to verify\nwhether a Cloud Object Storage bucket is configured to use Hyper Protect Crypto\nServices key management service.\nUsing Console:\nNavigate to your Cloud Object Storage instance:\n1. Log in to IBM Cloud at https://cloud.ibm.com\n2. Click the Menu icon and select Resource List\n3. On the Resource List page under Storage, select the Cloud Object Storage\ninstance that you have provisioned.\n4. Click on the appropriate bucket that you would like to check\n5. Click on Configuration and scroll down to Associated key management\nservice to check/confirm if Hyper Protect Crypto Services key is configured with\nthe bucket",
    "expected_response": "whether a Cloud Object Storage bucket is configured to use Hyper Protect Crypto\nservice to check/confirm if Hyper Protect Crypto Services key is configured with",
    "remediation": "You will not be able to add Hyper Protect Crypto Services as the key management\nservice once data is already written to a Cloud Object Storage bucket. In order to\nensure that objects are encrypted using Hyper Protect Crypto Services root keys you\nwill need to create a new Cloud Object Storage bucket, set it to use Hyper Protect\nCrypto Services key management service and then upload/copy the existing objects to\nthis new bucket.",
    "default_value": "By default, use of Hyper Protect Crypto Services key management service with IBM\nCloud Object Storage buckets is not enabled.",
    "additional_information": "Create a Cloud Object Storage bucket with Hyper Protect Crypto Services (Keep Your\nOwn Key):\n1. From your Cloud Object Storage instance page, create a new Cloud Object\nStorage bucket by clicking Create bucket.\n2. To create the bucket, in the Create bucket section, select Custom bucket.\n3. In the bucket configuration section, you can select the option to use Hyper\nProtect Crypto Services under Key management services\nNote: In order to configure a Cloud Object Storage bucket to use Hyper Protect Crypto\nServices you will need an instance of Hyper Protect Crypto Services along with\nappropriate access authorization to your Cloud Object Storage instance.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. • Data encryption with IBM Cloud Object Storage:",
      "https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-",
      "encryption",
      "2. • Integrated service availability page: https://cloud.ibm.com/docs/services/cloud-",
      "object-storage/basics?topic=cloud-object-storage-service-availability"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 69,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2"
    ]
  },
  {
    "cis_id": "2.1.2",
    "title": "Ensure network access for Cloud Object Storage is restricted to specific IP range",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "IBM Cloud Object Storage bucket level context-based restriction rules allow users to\nrestricts all access to data unless the request originates from a list of allowed IP\naddresses. Context-based restrictions are recommended over legacy bucket Firewalls\nfor restricting IP addresses that can be used to access buckets.",
    "rationale": "Restrict access to the data stored in Cloud Object Storage buckets and enhance\nsecurity controls by creating a context-based restriction that will only allow data to be\naccessed from specific IP addresses.",
    "impact": "For any application(s) that depends upon or accesses data stored in Cloud Object\nStorage buckets to conduct its operation(s), administrators should ensure that the\nnetwork used to access Cloud Object Storage buckets is trusted. This can be achieved\nthrough Cloud Object Storage context-based restriction rules. Allowing all network\naddresses to access Cloud Object Storage buckets could result unnecessary data\nexposure.",
    "audit": "To verify that an IBM Cloud Object Storage bucket is accessible only from authorized IP\naddresses, administrators can navigate to Permissions tab available under your\nbucket information and check the Context-base restrictions rule set.\nUsing Console\n1. Navigate to IBM Cloud Console: https://cloud.ibm.com/resources.\n2. Under Storage click on the Cloud Object Storage instance to verify (users will be\ndirected to a default bucket listing page)\n3. Click on the Cloud Object Storage bucket name to review the bucket information.\n4. At the bucket information screen, click on the Permissions tab in bucket\ndescription on the right navigation pane.\n5. Within Bucket access policies you will see a list of policies that can be used\nto control access to the bucket, choose Context-based restrictions\n6. If no Context-based restriction exists, one can be created using the Create\nrule button following directions in the public documentation here:\nhttps://cloud.ibm.com/docs/account?topic=account-context-restrictions-\ncreate&interface=ui.\n7. If Context-based restrictions exist, users can view the rules by following the\nManage context-based restrictions link in the interface.\n8. Review the rules to ensure they includes the IPs you want authorized.",
    "expected_response": "8. Review the rules to ensure they includes the IPs you want authorized.",
    "remediation": "Follow the steps outlined to add an IP to the list of Authorized IPs in context restriction\nrules.\nUsing Console\nFrom the IBM Cloud console dashboard, you can restrict access to your content by\nsetting a context-based restriction.\nSet a list of authorized IP addresses\n1. Start by selecting Storage to view your resource list.\n2. Next, select the service instance with the target bucket from within the Storage\nmenu. The Object Storage Console will be displayed.\n3. Select the bucket to navigate to the bucket details interface.\n4. Select Permissions from the navigation menu.\n5. Select the Context-based restrictions tab.\n6. Click on Create rule and follow the instructions here:\nhttps://cloud.ibm.com/docs/account?topic=account-context-restrictions-\ncreate&interface=ui\nNote that all objects in this bucket are only accessible from those IP addresses.",
    "default_value": "By default Cloud Object Storage buckets can only be accessed by authenticated users.",
    "detection_commands": [
      "create&interface=ui."
    ],
    "remediation_commands": [
      "create&interface=ui"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-",
      "setting-a-firewall",
      "2. https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-",
      "setting-a-firewall#firewall-api"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 72,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4"
    ]
  },
  {
    "cis_id": "2.1.3",
    "title": "Ensure network access for Cloud Object Storage is set to be exposed only on Private end-points",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Data in Transit",
    "description": "IBM Cloud Object Storage bucket context-based restrictions allows administrators to\nrestricts all access to data unless the request originates from a list of allowed IP\naddresses that are part of the private subnets only.",
    "rationale": "Restrict access to data stored in Cloud Object Storage buckets and enhance security\ncontrols by creating a context-based restriction rule that will only allow data access to\nthe list of IP addresses that are part of your private subnet.",
    "impact": "Ensuring network access is accessible via private subnets requires that you update the\nsettings in Cloud Object Storage bucket configuration by following additional steps\noutlined in the remediation section.",
    "audit": "To check or confirm that an IBM Cloud Object Storage bucket is accessible only from a\nlist of authorized IP addresses from private subnets, you can navigate to Access\npolicies section available under your bucket information and check Authorized IPs\nlist.\nUsing Console:\n1. Go to IBM Cloud Console: https://cloud.ibm.com/resources\n2. Under Storage click on the Cloud Object Storage instance you want to check.\n(you will be directed to a default bucket listing page)\n3. Click on the Cloud Object Storage bucket for which you want to review the\nbucket policy/context-based restriction information\n4. At the bucket information screen, click on the Permissions section on the right\nnavigation in the bucket description.\n5. Within Bucket access policies one can view the tab Context-based\nrestrictions\n6. Review the list of rules to ensure one includes the IPs/subnets you want\nauthorized, for example, 10.0.0.0/8 would authorize all the private IP\naddresses that are part of the IBM Cloud Infrastructure to access the bucket.",
    "expected_response": "6. Review the list of rules to ensure one includes the IPs/subnets you want",
    "remediation": "Follow the steps outlined to add an IP/subnet to the list of Authorized IPs in bucket\ncontext-based restriction policies.\nUsing Console:\nFrom the IBM Cloud console dashboard, you can restrict access to your content by\nsetting a Context-based Restriction.\nSet a list of authorized IP addresses\n1. Start by selecting Storage to view your resource list.\n2. Next, select the service instance with the target bucket from within the Storage\nmenu. The Object Storage Console will be displayed.\n3. Select the bucket to navigate to the bucket details interface.\n4. Select Permissions from the navigation menu.\n5. Select the Context-based restrictions tab.\n6. Click on Create rule and follow the instructions here:\nhttps://cloud.ibm.com/docs/account?topic=account-context-restrictions-\ncreate&interface=ui\nNote that all objects in this bucket are only accessible from those IP addresses.",
    "default_value": "By default, Cloud Object Storage buckets can only be accessed by authenticated users.",
    "detection_commands": [],
    "remediation_commands": [
      "create&interface=ui"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-",
      "setting-a-firewall",
      "2. https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-",
      "setting-a-firewall#firewall-api"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 75,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D4"
    ]
  },
  {
    "cis_id": "2.1.4",
    "title": "Ensure Cloud Object Storage bucket access is restricted by using IAM and S3 access control",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Access controls on the Cloud Object Storage buckets are governed via IBM Identity and\nAccess Management (IAM). However, some permissions can also be granted (or\nrestricted) via S3 access controls.",
    "rationale": "Assign IAM access roles for users and Service IDs against buckets, by using either the\nUI or the CLI to create policies. The S3 Access Control is performed using ACLs\ngranted against buckets and objects.",
    "impact": "Organizations can use Cloud Object Storage to store sensitive data that may need to be\nrestricted. Therefore, creation of a new Cloud Object Storage bucket requires careful\nreview and planning around access controls provided by IBM Cloud environment to\nensure data access can be restricted to only those having valid business need.",
    "audit": "Using Console:\nComplete the following steps to review your assigned access in an account that you\nhave been added to:\n1. In the console, click Manage, Access (IAM), and select Users or Manage,\nAccess (IAM), and select Service IDs, depending on which identity you want\nto review.\n2. Select your name or the service ID.\n3. Review the assigned access in the Access policies section.\nUsing CLI:\nReviewing S3 ACLs to buckets\nView the S3 ACLs via API or CLI. A typical API call is shown:\ncurl -X \"GET\" \"https://{endpoint}/{bucket-name}?acl\" \\\n-H \"Authorization: Bearer {token}\" \\",
    "remediation": "Granting Access to a COS Bucket using IAM\nUsing Console:\nTo create a new bucket-level policy:\n1. Navigate to the Access IAM console from the Manage menu.\n2. Select Users from the left navigation menu.\n3. Select a user.\n4. Select the Access Policies tab to view the user's existing policies, assign a\nnew policy, or edit an existing policy.\n5. Click Assign access to create a new policy.\n6. Choose Assign access to resources.\n7. First, select Cloud Object Storage from the services menu.\n8. Then, select the appropriate service instance. Enter bucket\nin the Resource type field and the bucket name in the Resource ID field.\n9. Select the wanted service access role. Selecting the lozenge with the number of\nactions show the actions available to the role.\n10. Click Assign\nUsing CLI:\nFrom a terminal run the following command:\nibmcloud iam user-policy-create <user-name> \\\n--roles <role> \\\n--service-name cloud-object-storage \\\n--service-instance <resource-instance-id> \\\n--resource-type bucket \\\n--resource <bucket-name>\nTo list existing policies:\nibmcloud iam user-policies <user-name>\nTo edit an existing policy:\nibmcloud iam user-policy-update <user-name> <policy-id> \\\n--roles <role> \\\n--service-name cloud-object-storage \\\n--service-instance <resource-instance-id> \\\n--resource-type bucket \\\n--resource <bucket-name>\nThe same set of accesses can be assigned to a service id as well. Please follow the\nprocedure documented in https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-\nobject-storage-iam-bucket-permissions#iam-service-id\nGranting S3 ACLs to buckets\nGrant the S3 ACLs via API or CLI. A Typical API call is shown:\ncurl -X \"PUT\" \"https://{endpoint}/{bucket-name}?acl\" \\\n-H \"Authorization: Bearer {token}\" \\\n-H \"x-amz-acl: <scope>\"",
    "default_value": "By default, users or service ids which have Cloud Object Storage service role access to\nthe Cloud Object Storage service instances will have access to the Cloud Object\nStorage buckets under them as well.",
    "detection_commands": [
      "curl -X \"GET\" \"https://{endpoint}/{bucket-name}?acl\" -H \"Authorization: Bearer {token}\""
    ],
    "remediation_commands": [
      "ibmcloud iam user-policy-create <user-name> --roles <role> --service-name cloud-object-storage --service-instance <resource-instance-id> --resource-type bucket --resource <bucket-name>",
      "ibmcloud iam user-policies <user-name>",
      "ibmcloud iam user-policy-update <user-name> <policy-id> --roles <role> --service-name cloud-object-storage --service-instance <resource-instance-id> --resource-type bucket --resource <bucket-name>",
      "Grant the S3 ACLs via API or CLI. A Typical API call is shown: curl -X \"PUT\" \"https://{endpoint}/{bucket-name}?acl\" -H \"Authorization: Bearer {token}\""
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-iam-",
      "bucket-permissions",
      "2. https://cloud.ibm.com/docs/account?topic=account-assign-access-resources",
      "3. https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-iam-",
      "public-access#public-access-object"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 78,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "2.1.5",
    "title": "Ensure Public (anonymous) Access to IBM Cloud Object Storage buckets is Disabled",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Configure Data Access Control Lists",
    "description": "You can disable public (anonymous) access to IBM Cloud Object Storage buckets.",
    "rationale": "Buckets might have to hold open data sets for academic, research, or image\nrepositories that are used by web applications and content delivery networks. You can\nmake these buckets publicly accessible by using the Public Access group. But when\nbuckets contain non-public data (e.g., restricted, internal, confidential or sensitive data),\nit is important to have public access disabled. To disable the public access, a previously\ndefined access policy must be removed.\nBy default, public access to Cloud Object Storage buckets is disabled. If an access\npolicy is defined that allows public access, you can disable the policy by using the\nconsole.",
    "audit": "To check if an access policy exists for a Cloud Object Storage bucket, you can list the\naccess policies for the Public Access group.\nUsing Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. Click Access groups.\n4. Select Public Access\n5. Check the list of access polices to see if one exists for the relevant Cloud Object\nStorage bucket.",
    "remediation": "To disable public access for buckets, complete the following steps:\nUsing Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. From the Menu bar, click Manage, Access (IAM).\n3. Click Access groups.\n4. Click Public Access to see a list of all public access policies currently in use.\n5. Find the policy that corresponds to the bucket that you want to return to enforced\naccess control.\n6. From the list of actions, select Remove.\n7. Confirm that you want to remove the policy.",
    "default_value": "By default, public access to Cloud Object Storage buckets is disabled.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. Information around Enabling and Disabling Public access to the COS bucket is",
      "available from the product page: https://cloud.ibm.com/docs/services/cloud-",
      "object-storage/basics?topic=cloud-object-storage-iam-public-access#iam-public-",
      "access-console"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 81,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "2.2.1.1",
    "title": "Ensure IBM Cloud® Block Storage for Virtual Private Cloud is encrypted with BYOK",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Block and File Storage",
    "description": "By default, IBM Cloud® Block Storage for Virtual Private Cloud provides provider-\nmanaged encryption for all data. For enhanced security, customers can bring their own\nencryption keys and manage them through IBM Key Management Service – Key\nProtect. The customer can choose to use BYOK instead of provider-managed keys for\nenhanced security.",
    "rationale": "When it comes to encryption of data at rest in IBM Cloud, the best practice is to allow\ncustomers to manage customer root keys(CRK) that are used to protect customer data\nstored in data and storage services in IBM Cloud. Bring your Own Key(BYOK) allows\ncustomers to ensure no one outside of their organization has access to the root key and\nwith the support of BYOK, customers can manage the lifecycle of their customer root\nkeys where they can create, rotate, delete those keys. This provides a significant level\nof control where those CRKs are managed by the customer, which in turn increases\nboth security control as well as meet relevant compliance requirements. These CRKs\ncan be used in turn to protect the data encryption keys used to encrypt the data.",
    "impact": "With BYOK managed encryption, the customer manages their own encryption keys\nthrough IBM Key Management Service – Key Protect. This may create additional\nadministrative overhead.",
    "audit": "You can use the IBM® Cloud Block Storage for Virtual Private Cloud configuration\nproperties to verify whether a block volume is enabled to use Key Protect. From\nConsole, Navigate to your block volume resource:\n1. In the IBM Cloud console, go to the Menu icon, VPC Infrastructure, Storage,\nBlock storage volumes. A list of all block storage volumes displays.\n2. For each of the volumes listed, ensure the encryption field specifies Key\nProtect.",
    "expected_response": "properties to verify whether a block volume is enabled to use Key Protect. From\n2. For each of the volumes listed, ensure the encryption field specifies Key",
    "remediation": "You will not be able to add Key Protect as the key management service once data is\nalready written to a Cloud Block Storage Volume. In order to ensure that the data is\nencrypted using Key Protect keys you will need to create a new Cloud Block Storage\nvolume, set it to use Key Protect key management service and then upload/copy the\nexisting data to this new volume.",
    "default_value": "Provider Managed",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/vpc?topic=vpc-block-storage-vpc-",
      "encryption&interface=ui"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 85,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2"
    ]
  },
  {
    "cis_id": "2.2.1.2",
    "title": "Ensure IBM Cloud® Block Storage for Virtual Private Cloud is encrypted with KYOK",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "By default, IBM Cloud® Block Storage for Virtual Private Cloud provides provider-\nmanaged encryption for all data. For enhanced security, customers can bring their own\nencryption keys and manage them through IBM Key Management Service – Hyper\nProtect Crypto Services (HPCS). The customer can choose to use KYOK instead of\nprovider-managed keys for enhanced security.",
    "rationale": "When it comes to encryption of data at rest in IBM Cloud, the best practice is to allow\ncustomers use encryption capabilities offered by Hardware Security Module crypto\nservice. IBM Cloud Hyper protect Crypto Service (HPCS) offers Keep your Own Key\n(KYOK) capabilities that allow customers to have exclusive key control over encryption\nkeys. This provides a significant level of control over encryption keys where only\nauthorized users have access (no privileged users included IBM Cloud Admins) to\nencryption keys, in turn increases both security control as well as meet relevant\ncompliance requirements.",
    "impact": "With KYOK managed encryption, the customer manages their own encryption keys\nthrough IBM Key Management Service - HPCS.",
    "audit": "You can use the IBM® Cloud Block Storage for Virtual Private Cloud configuration\nproperties to verify whether a block volume is enabled to use Hyper Protect Crypto\nService. From Console, Navigate to your block volume resource:\n1. In the IBM Cloud console, go to the Menu icon, VPC Infrastructure, Storage,\nBlock storage volumes. A list of all block storage volumes displays.\n2. For each of the volumes listed, ensure the encryption field specifies Hyper\nProtect.",
    "expected_response": "properties to verify whether a block volume is enabled to use Hyper Protect Crypto\n2. For each of the volumes listed, ensure the encryption field specifies Hyper",
    "remediation": "You will not be able to add Hyper Protect Crypto Services as the key management\nservice once data is already written to a Cloud Block Storage Volumes. In order to\nensure that data is encrypted using Hyper Protect Crypto Services you will need to\ncreate a new Cloud Block Storage volume, set it to use Hyper Protect Crypto Services\nkey management service and then upload/copy the existing data to this new volume.",
    "default_value": "Provider managed",
    "detection_commands": [],
    "remediation_commands": [
      "create a new Cloud Block Storage volume, set it to use Hyper Protect Crypto Services"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/vpc?topic=vpc-block-storage-vpc-",
      "encryption&interface=ui"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 87,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2"
    ]
  },
  {
    "cis_id": "2.2.2.1",
    "title": "Ensure IBM Cloud® File Storage for Virtual Private Cloud is encrypted with provider managed keys",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "By default, IBM Cloud® File Storage for Virtual Private Cloud provides provider-\nmanaged encryption for all data. For enhanced security, customers can bring their own\nencryption keys and manage them through IBM Key Management Services – Key\nProtect or Hyper Protect Crypto Services (HPCS).",
    "rationale": "With provider-managed keys, the file service manages encryption at rest by default with\nno additional configuration needed by the customer.\nWith provider managed encryption, the service manages the root encryption keys on\nbehalf of the customer.",
    "audit": "You can use the IBM® Cloud File Storage for Virtual Private Cloud configuration\nproperties to verify whether a file share is enabled with provider managed encryption.\nFrom the IBM Cloud Console, Navigate to your file share resource:\n1. In the IBM Cloud console, go to Menu icon, VPC Infrastructure, Storage,\nFile Storage Shares. A list of all file shares is displays.\n2. For each of the shares listed, ensure the encryption field specifies Provider\nManaged.",
    "expected_response": "properties to verify whether a file share is enabled with provider managed encryption.\n2. For each of the shares listed, ensure the encryption field specifies Provider",
    "remediation": "You will not be able to change the encryption option once data is already written to a\nFile Share. In order to change your encryption setting you will need to create a new File\nShare, set it to use your desired encryption setting and then upload/copy the existing\ndata to this new share.",
    "default_value": "Provider managed",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/vpc?topic=vpc-block-storage-about&interface=ui"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 90,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2"
    ]
  },
  {
    "cis_id": "2.2.2.2",
    "title": "Ensure IBM Cloud® File Storage for Virtual Private Cloud is encrypted with BYOK",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "By default, IBM® Cloud File Storage for Virtual Private Cloud provides provider-\nmanaged encryption for all data. For enhanced security, customers can bring their own\nencryption keys and manage them through IBM Key Management Service – Key\nProtect. The customer can choose to use BYOK instead of provider-managed keys for\nenhanced security.",
    "rationale": "When it comes to encryption of data at rest in IBM Cloud, the best practice is to allow\ncustomers to manage customer root keys(CRK) that are used to protect customer data\nstored in data and storage services in IBM Cloud. Bring your Own Key(BYOK) allows\ncustomers to ensure no one outside of their organization has access to the root key and\nwith the support of BYOK, customers can manage the lifecycle of their customer root\nkeys where they can create, rotate, delete those keys. This provides a significant level\nof control where those CRKs are managed by the customer, which in turn increases\nboth security control as well as meet relevant compliance requirements. These CRKs\ncan be used in turn to protect the data encryption keys used to encrypt the data.",
    "impact": "With BYOK managed encryption, the customer manages their own encryption keys\nthrough IBM Key Management Service – Key Protect. This may create additional\nadministrative overhead.",
    "audit": "You can use the IBM® Cloud File Storage for Virtual Private Cloud configuration\nproperties to verify whether a file share is enabled to use Key Protect.\nFrom Console, Navigate to your fie share resource:\n1. In the IBM Cloud console, go to Menu icon, VPC Infrastructure, Storage,\nFile storage shares. A list of all file shares displays.\n2. For each of the shares listed, ensure the encryption field specifies Key Protect.",
    "expected_response": "properties to verify whether a file share is enabled to use Key Protect.\n2. For each of the shares listed, ensure the encryption field specifies Key Protect.",
    "remediation": "You will not be able to add Key Protect as the key management service once data is\nalready written to a File Share. In order to ensure that the data is encrypted using Key\nProtect keys you will need to create a new File Share, set it to use Key Protect key\nmanagement service and then upload/copy the existing data to this new volume.",
    "default_value": "Provider managed",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/vpc?topic=vpc-block-storage-about&interface=ui"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 92,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2"
    ]
  },
  {
    "cis_id": "2.2.2.3",
    "title": "Ensure IBM Cloud® File Storage for Virtual Private Cloud is encrypted with KYOK",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "By default, IBM Cloud® File Storage for Virtual Private Cloud provides provider-\nmanaged encryption for all data. For enhanced security, customers can bring their own\nencryption keys and manage them through IBM Key Management Service – Hyper\nProtect Crypto Services (HPCS). The customer can choose to use KYOK instead of\nprovider-managed keys for enhanced security.",
    "rationale": "When it comes to encryption of data at rest in IBM Cloud, the best practice is to use\nencryption capabilities offered by Hardware Security Module crypto service. IBM Cloud\nHyper protect Crypto Service (HPCS) offers Keep your Own Key (KYOK) capabilities\nthat allow customers to have exclusive key control over encryption keys. This provides a\nsignificant level of control over encryption keys where only authorized users have\naccess (no privileged users included IBM Cloud Admins) to encryption keys, in turn\nincreases both security control as well as meet relevant compliance requirements.",
    "impact": "With KYOK managed encryption, the customer manages their own encryption keys\nthrough IBM Key Management Service - HPCS. This may create additional\nadministrative overhead.",
    "audit": "You can use the IBM® Cloud File Storage for Virtual Private Cloud configuration\nproperties to verify whether a file share is enabled to use Hyper Protect Crypto Service.\nFrom Console, Navigate to your file share resource:\n1. In the IBM Cloud console, go to Menu icon, VPC Infrastructure, Storage,\nfile storage shares. A list of all file shares is displays.\n2. For each of the share listed, ensure the encryption field specifies Hyper\nProtect.",
    "expected_response": "properties to verify whether a file share is enabled to use Hyper Protect Crypto Service.\n2. For each of the share listed, ensure the encryption field specifies Hyper",
    "remediation": "You will not be able to add Hyper Protect Crypto Services as the key management\nservice once data is already written to a file share. In order to ensure that data is\nencrypted using Hyper Protect Crypto Services you will need to create a new file share,\nset it to use Hyper Protect Crypto Services key management service and then\nupload/copy the existing data to this new volume.",
    "default_value": "Provider managed",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 94,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2"
    ]
  },
  {
    "cis_id": "2.2.3",
    "title": "Ensure boot volumes are encrypted with Customer managed keys",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "By default, IBM Cloud® Block Storage for Virtual Private Cloud provides provider-\nmanaged encryption for all data. For enhanced security, customers can bring their own\nencryption keys and manage them through IBM Key Management Services – Key\nProtect or Hyper Protect Crypto Services (HPCS).",
    "rationale": "With customer-managed keys, only customers can access and manage their master\nroot keys, giving them full control over their data security.",
    "impact": "With BYOK or KYOK managed encryption, the customer manages their own encryption\nkeys through either Key Protect or Hyper Protect Crypto Services.",
    "audit": "You can use the IBM® Cloud Block Storage for Virtual Private Cloud configuration\nproperties to verify whether a block volume is enabled to use Key Protect or Hyper\nProtect key management services.\nFrom Console, Navigate to your block volume resource:\n1. In the IBM Cloud console, go to Menu icon, VPC Infrastructure, Storage,\nBlock storage volumes. A list of all block storage volumes displays.\n2. For each volumes listed with Attachment Type column value Boot, ensure the\nencryption field is Not pointing to Provider Managed.",
    "expected_response": "properties to verify whether a block volume is enabled to use Key Protect or Hyper\n2. For each volumes listed with Attachment Type column value Boot, ensure the",
    "remediation": "You will not be able to change encryption option once data is already written to a Cloud\nBlock Storage Volume. In order to ensure that data is encrypted using customer\nmanaged keys you will need to create a new Cloud Block Storage volume, set it to use\neither Key Protect or Hyper Protect key management service and then upload/copy the\nexisting objects to this new volume.",
    "default_value": "Provider Managed",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/vpc?topic=vpc-block-storage-vpc-",
      "encryption&interface=ui"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 96,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2"
    ]
  },
  {
    "cis_id": "2.2.4",
    "title": "Ensure secondary volumes are encrypted with customer managed keys",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "By default, IBM Cloud® Block Storage for Virtual Private Cloud provides provider-\nmanaged encryption for all data. For enhanced security, customers can bring their own\nencryption keys and manage them through IBM Key Management Services – Key\nProtect or Hyper Protect Crypto Services (HPCS).",
    "rationale": "With customer-managed keys, only customers can access and manage their master\nroot keys, giving them full control over their data security.",
    "impact": "With BYOK or KYOK managed encryption, the customer manages their own encryption\nkeys through either Key Protect or Hyper Protect Crypto Services.",
    "audit": "You can use the IBM® Cloud Block Storage for Virtual Private Cloud configuration\nproperties to verify whether a block volume is enabled to use Key Protect or Hyper\nProtect key management services.\nFrom Console, Navigate to your block volume resource:\n1. In the IBM Cloud console, go to Menu icon, VPC Infrastructure, Storage,\nBlock storage volumes. A list of all block storage volumes will be displayed.\n2. For each volumes listed with Attachment Type column value \"Data\", ensure the\nencryption field is Not pointing to \"Provider Managed\".",
    "expected_response": "properties to verify whether a block volume is enabled to use Key Protect or Hyper\n2. For each volumes listed with Attachment Type column value \"Data\", ensure the",
    "remediation": "You will not be able to change encryption option once data is already written to a Cloud\nBlock Storage Volume. In order to ensure that data is encrypted using customer\nmanaged keys you will need to create a new Cloud Block Storage volume, set it to use\neither Key Protect or Hyper Protect key management service and then upload/copy the\nexisting data to this new volume.",
    "default_value": "Provider managed",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/vpc?topic=vpc-block-storage-vpc-",
      "encryption&interface=ui"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 98,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2"
    ]
  },
  {
    "cis_id": "2.2.5",
    "title": "Ensure unattached volumes are encrypted with customer managed keys",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "By default, IBM Cloud® Block Storage provides provider-managed encryption for all\ndata. For enhanced security, customers can bring their own encryption keys and\nmanage them through IBM Key Management Services – Key Protect or Hyper Protect\nCrypto Services (HPCS).",
    "rationale": "With customer-managed keys, only customers can access and manage their master\nroot keys, giving them full control over their data security.",
    "impact": "With BYOK or KYOK managed encryption, the customer manages their own encryption\nkeys through either Key Protect or Hyper Protect Crypto Services.",
    "audit": "You can use the IBM® Cloud Block Storage for Virtual Private Cloud configuration\nproperties to verify whether a block volume is enabled to use Key Protect or Hyper\nProtect key management services.\nFrom Console, Navigate to your Cloud Object Storage instance:\n1. In the IBM Cloud console, go to Menu icon, VPC Infrastructure, Storage,\nBlock storage volumes. A list of all block storage volumes will be displayed.\n2. For each volumes listed without any value in the \"Attachment Type\" column,\nensure the encryption field is Not pointing to \"Provider Managed\".",
    "expected_response": "properties to verify whether a block volume is enabled to use Key Protect or Hyper\nensure the encryption field is Not pointing to \"Provider Managed\".",
    "remediation": "You will not be able to change encryption option once data is already written to a Cloud\nBlock Storage Volume. In order to ensure that data is encrypted using customer\nmanaged keys you will need to create a new Cloud Block Storage volume, set it to use\neither Key Protect or Hyper Protect key management service and then upload/copy the\nexisting data to this new volume.",
    "default_value": "Provider managed",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/vpc?topic=vpc-block-storage-vpc-",
      "encryption&interface=ui"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 100,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2"
    ]
  },
  {
    "cis_id": "3.1",
    "title": "Ensure auditing is configured in the IBM Cloud account",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Maintenance, Monitoring and Analysis of Audit Logs",
    "description": "Collect audit events from IBM Cloud resources so that you can monitor activity in your\nIBM Cloud account.",
    "rationale": "Use IBM Cloud® Activity Tracker Event Routing to configure how to route auditing\nevents, both global and location-based event data, in your IBM Cloud. Auditing events\nare critical data for security operations and a key element for meeting compliance\nrequirements. Control of the storage location is critical to building enterprise-grade\nsolutions on the IBM Cloud.\nYou can use Activity Tracker Event Routing, a platform service, to manage auditing\nevents at the account-level by configuring targets and routes that define where auditing\ndata is routed. Activity Tracker Event Routing can route events that are generated in\nsupported regions.\nFor example, you can use these audit events to investigate abnormal activity and critical\nactions, and comply with regulatory audit requirements. The audit events that are\ncollected comply with the Cloud Auditing Data Federation (CADF) standard. Each audit\nevent includes information about the initiator of the action, the action that is run, the\ntarget resource on which the action is requested, the observer, and the outcome of the\naction. For more information about the format, see Event fields.\nActivity Tracker events are collected as two types of events for audit-enabled services in\nthe IBM Cloud:\n• Management events\n• Data events\nData events access or modify customer data. Management events report on operational\nactions on IBM Cloud resources. Both types of events generate events for create, read,\nupdate, and delete (CRUD) actions.\nFor the highest set of log analysis and monitoring capabilities, use IBM Cloud® Activity\nTracker Event Routing to route all audit events to IBM Cloud Logs.",
    "impact": "Failure to meet this recommendation limits your ability to monitor activity in your IBM\nCloud account. It also restricts your ability to identify the initiator of actions in your\naccount, the resources affected, and details about the request.",
    "audit": "To check that you are collecting audit events from IBM Cloud resources so that you can\nmonitor activity in your IBM Cloud account, you can use the following check list to\nensure that auditing is configured in an IBM Cloud account:\n1. Ensure that routes and/or targets are defined for audit events in IBM Cloud®\nActivity Tracker Event Routing. Be sure to include Global events, as well as for\neach region that you operate within.\n2. Use the validate function within IBM Cloud® Activity Tracker Event Routing,\nwhich ensures the configured route or target are working and are able to\nauthenticate to the specified destination.\nTo check if routes and/or targets are defined for audit events in IBM Cloud® Activity\nTracker Event Routing, complete the following steps:\nNote: To complete these steps, your IBM Cloud user ID (IBMid) must have the following\nroles:\n• A platform role with viewer role for the IBM Cloud® Activity Tracker Event\nRouting service for the account\n• A service role with reader role for the IBM Cloud® Activity Tracker Event Routing\nservice for the account\n• Identity and Access Management (IAM) permissions to read and list targets and\nroutes in the account, including the following IAM actions: atracker.target.read,\natracker.target.list, atracker.route.read, atracker.route.list.\nUsing Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Go to the Menu icon. Then, select Observability to access the\nObservability dashboard.\n3. Select Activity Tracker from the page navigation menu\n4. Select Routing from the page navigation menu\n5. Select Routes from the page navigation menu\n6. All configured Routes will be listed. Review to ensure the routes cover all\nlocations, including global.\n7. Select Targets from the page navigation menu\n8. All configured Targets will be listed. Ensure the Target Status is Active for all\ntargets. If the target status is Error, the target is misconfigured and events will\nnot be routed to the destination.\nUsing CLI:\n1. Log in to IBM Cloud. Run the following command:\nibmcloud login -a cloud.ibm.com\nFor a federated account, run the following command:\nibmcloud login -a cloud.ibm.com --sso\n2. List all routes that are configured in your account. Run the following command:\nibmcloud atracker route ls\n3. Get the details of each configured route found in the list from the previous\ncommand:\nibmcloud atracker route get --route ROUTE\nwhere ROUTE is the name or ID of the route.\n4. List all targets that are configured in your account. Run the following command:\nibmcloud atracker target ls\n5. Get the details of each configured target found in the list from the previous\ncommand:\nibmcloud atracker target get --target TARGET\nwhere TARGET is the name or ID of the route.\n6. Validate each target to ensure it is operating successfully Ensure the write status\nis \"Success\". Run the following command:\nibmcloud atracker target validate --target TARGET\nwhere TARGET is the name or ID of the route.\nUsing API:\nTo make API calls to manage routes and targets, complete the following steps:\n• Get an IAM access token. For more information, see Retrieving IAM access\ntokens.\n• Identify the API endpoint in the region where you plan to configure or manage a\nroute. For more information, see Endpoints.\nIn this set of instructions, cURL will be used to execute the API calls.\n1. List all routes that are configured in your account. Run the following command:\ncurl -X GET   <ENDPOINT>/api/v2/routes   -H \"Authorization:  $ACCESS_TOKEN\"\n-H \"content-type: application/json\"\nwhere <ENDPOINT> is the API endpoint in the region where you plan to configure or\nmanage a route.\n2. Get the details of each configured route found in the list from the previous\ncommand:\ncurl -X GET   <ENDPOINT>/api/v2/routes/<ROUTE_ID>   -H \"Authorization:\n$ACCESS_TOKEN\"   -H \"content-type: application/json\"\nwhere <ENDPOINT> is the API endpoint in the region where you plan to configure or\nmanage a route and <ROUTE_ID> is the ID of the route.\n3. List all targets that are configured in your account. Run the following command:\ncurl -X GET <ENDPOINT>/api/v2/targets -H \"Authorization: $ACCESS_TOKEN\" -H\n\"content-type: application/json\"\nwhere <ENDPOINT> is the API endpoint in the region where you plan to configure or\nmanage a route.\n4. Get the details of each configured target found in the list from the previous\ncommand:\ncurl -X GET <ENDPOINT>/api/v2/targets/<TARGET_ID> -H \"Authorization:\n$ACCESS_TOKEN\" -H \"content-type: application/json\"\nwhere <ENDPOINT> is the API endpoint in the region where you plan to configure or\nmanage a route and <TARGET_ID> is the ID of the target.\n5. Validate each target to ensure it is operating successfully Ensure the write_status\nhas a status of \"success\". Run the following command:\ncurl -X POST <ENDPOINT>/api/v2/targets/<TARGET_ID>/validate -H\n\"Authorization: $ACCESS_TOKEN\" -H \"content-type: application/json\"\nwhere <ENDPOINT> is the API endpoint in the region where you plan to configure or\nmanage a route and <TARGET_ID> is the ID of the target.",
    "expected_response": "ensure that auditing is configured in an IBM Cloud account:\n1. Ensure that routes and/or targets are defined for audit events in IBM Cloud®\nNote: To complete these steps, your IBM Cloud user ID (IBMid) must have the following\n6. All configured Routes will be listed. Review to ensure the routes cover all\n8. All configured Targets will be listed. Ensure the Target Status is Active for all\n6. Validate each target to ensure it is operating successfully Ensure the write status\n5. Validate each target to ensure it is operating successfully Ensure the write_status",
    "remediation": "1. If a route is not configured within IBM Cloud® Activity Tracker Event Routing for\neach of the locations where you operate in IBM Cloud (including global), you\nmust create or update a route.\nTo create a route, choose any of the following options:\no Creating a route using the CONSOLE.\no Creating a route using the CLI.\no Creating a route using the API.\n2. If a target is not configured within IBM Cloud® Activity Tracker Event Routing for\neach of the locations where you which to receive your audit events, you must\ncreate or update a target.\nTo create a target, choose any of the following options:\no Creating a IBM Cloud Logs target using the CONSOLE.\no Creating a IBM Cloud Logs target using the CLI.\no Creating a IBM Cloud Logs target using the API.\n3. If any of the targets have a status or write status of ERROR, you must update the\nconfigured target to resolve the authentication issue with the destination.\nTo update a target, choose any of the following options:\no Updating a IBM Cloud Logs target using the CONSOLE.\no Updating a IBM Cloud Logs target using the CLI.\no Updating a IBM Cloud Logs target using the API.",
    "default_value": "By default, management audit events are generated and collected automatically.\nHowever, you must configure routes and targets to receive those audit events using the\nIBM Cloud® Activity Tracker Event Routing platform service in your account, as no\nroutes and targets are created by default.\nFor most of the services in IBM Cloud, data events are generated and collected\nautomatically. However, there are some exceptions where you must opt-in to collect\nthem, such as IBM Cloud Object Storage.",
    "detection_commands": [
      "ibmcloud login -a cloud.ibm.com",
      "ibmcloud login -a cloud.ibm.com --sso",
      "ibmcloud atracker route ls",
      "ibmcloud atracker route get --route ROUTE",
      "ibmcloud atracker target ls",
      "ibmcloud atracker target get --target TARGET",
      "ibmcloud atracker target validate --target TARGET",
      "curl -X GET <ENDPOINT>/api/v2/routes -H \"Authorization: $ACCESS_TOKEN\"",
      "curl -X GET <ENDPOINT>/api/v2/routes/<ROUTE_ID> -H \"Authorization: $ACCESS_TOKEN\" -H \"content-type: application/json\"",
      "curl -X GET <ENDPOINT>/api/v2/targets -H \"Authorization: $ACCESS_TOKEN\" -H \"content-type: application/json\"",
      "curl -X GET <ENDPOINT>/api/v2/targets/<TARGET_ID> -H \"Authorization: $ACCESS_TOKEN\" -H \"content-type: application/json\"",
      "curl -X POST <ENDPOINT>/api/v2/targets/<TARGET_ID>/validate -H \"Authorization: $ACCESS_TOKEN\" -H \"content-type: application/json\""
    ],
    "remediation_commands": [
      "create or update a target."
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/atracker?topic=atracker-getting-started",
      "2. https://cloud.ibm.com/docs/atracker?topic=atracker-route_v2",
      "3. https://cloud.ibm.com/docs/atracker?topic=atracker-target_v2"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 103,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "3.2",
    "title": "Ensure data retention for audit events",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Maintenance, Monitoring and Analysis of Audit Logs",
    "subdomain": "Enable Detailed Logging",
    "description": "Create Cloud Object Storage buckets for long-term storage of all audit log events so\nthat you have access to data for a longer period of time, you can comply with highly\nregulated environments, you can recover quickly in the eventuality of a disaster\nscenario, and you can adhere to internal data storage policies.",
    "rationale": "When you provision an instance of IBM Cloud Logs, you must have an IBM Cloud\nObject Storage (COS) instance in the same account where your IBM Cloud Logs\ninstance is provisioned. Cloud Logs supports having all logs go to the COS bucket, and\nalso has Priority Insights, which provides enhanced interaction with the logs. However,\nPriority Insights does not provide long-term storage. As such, it is important to ensure\nthat a Cloud Object Storage bucket has been created and that all data is stored there, in\naddition to any optional use of Priority Insights.\nThe maximum number of days that data can be available for search within Priority\nInsights (90 days) is not sufficient and requires a long-term data storage solution. For\nexample, highly regulated environments impose strict storage policies where they define\nthe minimum number of days that log data must be saved for. Internal corporate\nregulations can also impose data storage policies. You might be affected by a natural\ndisaster and you must recover fast. In any of these sample scenarios, you must\nimplement a storage solution that allows you to keep data for long-term retention.\nData that is managed by the IBM Cloud Logs service is encrypted at rest. Data that is\nstored in a bucket that is hosted in IBM Cloud Object Storage is encrypted by default\nusing randomly generated keys and an all-or-nothing-transform.\nWhile this IBM Cloud Object Storage default encryption model provides at-rest security,\nsome workloads need to be in possession of the encryption keys used. You can\nmanage your keys manually by providing your own encryption keys - referred to as\nServer-Side Encryption with Customer-Provided Keys (SSE-C). With IBM Cloud Object\nStorage, you also have a choice to use IBM's integration capabilities with IBM Cloud\nKey Management Services like IBM Key Protect and Hyper Protect Crypto Services.\nDepending on the security requirements, you can decide whether to use IBM Key\nProtect or IBM Hyper Protect Crypto Services for your IBM Cloud Object Storage\nbuckets.\n• IBM Key Protect for IBM Cloud helps you provision encrypted keys for apps\nacross IBM Cloud services. As you manage the lifecycle of your keys, you can\nbenefit from knowing that your keys are secured by FIPS 140-2 Level 3 certified\ncloud-based hardware security modules (HSMs) that protect against the theft of\ninformation.\n• Hyper Protect Crypto Services is a single-tenant, dedicated HSM that is\ncontrolled by you. The service is built on FIPS 140-2 Level 4-certified hardware,\nthe highest offered by any cloud provider in the industry.\nIf you use IBM Cloud Logs, you can store data that is available through an audit\ninstance in an IBM Cloud Object Storage bucket. You can configure the bucket to meet\nall your internal and external regulations.\nThere are two types of data that you must consider retaining: events, and service\ninstance metadata, such as views, templates, screens, and alerts.\nAs guidance, events must be kept for as long as internal compliance requires. If no\nrequirements exist, consider a minimum of 365 days.",
    "impact": "If you have regulatory or organizational requirements that determine the number of days\nthat data must be available, failure to meet this control can result in breaching\ncompliance.\nIn addition, if data is corrupted or not archived, and you do not export it within the\nnumber of days that are available for Priority Insights, you can lose data.\nIf you have requirements that define the bucket specification, policies, and encrypting\nrequirements, you might be in breach of infrastructure compliance.",
    "audit": "Use the following check list to ensure that long-term retention is configured for each of\nyour Cloud Logs instances:\n1. Ensure that IBM Cloud Logs instances are provisioned in a region that also\ncontains one or more Cloud Object Storage buckets to configure long-term\nstorage to an external storage service.\n2. Ensure that each IBM Cloud Logs has a COS bucket enabled and configured.\na. Log in to IBM Cloud at https://cloud.ibm.com.\nb. From the Menu bar, select Observability.\nc. Select Logging, Instances. You might need to click the Cloud Logs tab to see your\nIBM Cloud Logs instances.\nd. Select the instance to which you want to verify a data bucket.\ne. In the Storage section, confirm the Bucket CRN, and the Bucket endpoint.\n3. Ensure that you have access to storage, for example, check that you have an\ninstance of the IBM Cloud Object Storage service provisioned in your account.\nYou must define a service to service (S2S) authorization between IBM Cloud\nLogs and IBM Cloud Object Storage to allow IBM Cloud Logs to read and write\ndata into the data bucket. For more information, see Creating a S2S\nauthorization to grant access to a bucket.\n4. Ensure that you have COS buckets available to retain your data. Separate\nbuckets for the Data Bucket and Metrics bucket may be required, such as when\nyou wish to apply separate data retention settings to each type of data. Check\nthe bucket configuration to verify that it meets your corporate and external market\nregulations.\nConsider using a bucket for each Cloud Logs instance so that you can customize\nthe bucket to meet security requirements. These requirements might be related\nto the type of data that is archived and to external regulations like EU-managed\nrequirements, for example.\n5. Ensure that the bucket has the following features enabled:\no A key management service is configured. For example, check IBM Cloud\nKey Protect is configured so that you can use your own key to encrypt\ndata.\no Auditing to IBM Cloud Object Storage is enabled and that the options read\nand data events are included for write and read operations.\no Monitoring with IBM Cloud Monitoring with Sysdig is enabled.\no Expiration rules are configured that define when audit logs are\nautomatically deleted. As guidance, events must be kept for as long as\ninternal compliance requires. If no requirements exist, consider a rule that\nkeeps files for a minimum of 365 days.\no [Optional] An archive policy is configured so that objects that are rarely\naccessed are moved from their default bucket storage class to the archive\nstorage class after a certain period. Note that Cloud Logs cannot read or\nsearch objects which are archived within the Cloud Object Storage bucket,\nhowever the archived data can be restored within COS to re-enable Cloud\nLogs to read and search that data.",
    "expected_response": "Use the following check list to ensure that long-term retention is configured for each of\n1. Ensure that IBM Cloud Logs instances are provisioned in a region that also\n2. Ensure that each IBM Cloud Logs has a COS bucket enabled and configured.\n3. Ensure that you have access to storage, for example, check that you have an\nYou must define a service to service (S2S) authorization between IBM Cloud\n4. Ensure that you have COS buckets available to retain your data. Separate\n5. Ensure that the bucket has the following features enabled:\no A key management service is configured. For example, check IBM Cloud\nKey Protect is configured so that you can use your own key to encrypt\no Auditing to IBM Cloud Object Storage is enabled and that the options read\no Monitoring with IBM Cloud Monitoring with Sysdig is enabled.\nautomatically deleted. As guidance, events must be kept for as long as\no [Optional] An archive policy is configured so that objects that are rarely",
    "remediation": "1. If the Cloud Logs instance cannot connect to the Cloud Object Storage bucket,\nyou must define a service to service (S2S) authorization between IBM Cloud\nLogs and IBM Cloud Object Storage to allow IBM Cloud Logs to read and write\ndata into the data bucket. For more information, see Creating a S2S\nauthorization to grant access to a bucket.\n2. If no Data Bucket is defined, you must define the Data Bucket within Cloud Logs\nas follows:\na. Log in to IBM Cloud at https://cloud.ibm.com.\nb. From the Menu bar, select Observability.\nc. Select Logging, Instances. You might need to click the Cloud Logs tab to\nsee your IBM Cloud Logs instances.\nd. Select the instance to which you want to configure a data bucket.\ne. In the Storage section, click edit.\nf. In the Logs data section, configure the Bucket CRN, and the Bucket endpoint.\n• Select Insert CRN from search to get the list of buckets in your account.\nYou can choose a CRN from the list.\n• Select View endpoints in docs to find the endpoints per location. Choose\nthe endpoint based on your bucket configuration.\ng. Click Save to save the configuration.\n3. If no Metrics Bucket is defined, you must define the Data Bucket within Cloud\nLogs as follows:\na. Log in to IBM Cloud at https://cloud.ibm.com.\nb. From the Menu bar, select Observability.\nc. Select Logging, Instances. You might need to click the Cloud Logs tab to\nsee your IBM Cloud Logs instances.\nd. Select the instance to which you want to configure a metrics bucket.\ne. In the Storage section, click edit.\nf. In the Events to metrics data section, configure the Bucket CRN, and the\nBucket endpoint.\n• Select Insert CRN from search to get the list of buckets in your account.\nYou can choose a CRN from the list.\n• Select View endpoints in docs to find the endpoints per location. Choose\nthe endpoint based on your bucket configuration.\ng. Click Save to save the configuration.\n4. If you cannot find an instance of IBM Cloud Object Storage (COS) in your\naccount, provision one.\n5. If you have a bucket that does not have full control over the data encryption keys,\nconfigure one of the supported options. IBM® Cloud Object Storage provides\nseveral options to encrypt your data.\n6. If you have a bucket that does not have an expiration rule to automatically delete\nobjects, configure one for the bucket based on your compliance and\norganizational requirements. The minimum expiration must be 365 days. For\nmore information, see Delete stale data with expiration rules.\n7. If you have a bucket that does not have an archive policy to store long-term data\nthat is rarely accessed, configure one for the bucket based on your compliance\nand organizational requirements. For more information, see Archive cold data\nwith transition rules.\n8. If you have a bucket that does not have Activity Tracker events enabled so that\nyou can monitor any interaction of users and services with the bucket, enable\nActivity Tracker events for the bucket.\n9. If you have a bucket that does not enable monitoring with IBM Cloud Monitoring\nwith Sysdig, configure the bucket.\n10. If you want to create a bucket, see create and configure a bucket.\no Configure one of the supported options to add additional encryption\ncapabilities. For more information, see IBM® Cloud Object Storage\nprovides several options to encrypt your data.\no Configure an expiration rule to automatically delete objects. Configure a\nrule for the bucket based on your compliance and organizational\nrequirements. The minimum expiration must be 365 days. For more\ninformation, see Delete stale data with expiration rules.\no Configure an archive policy to store long-term data that is rarely accessed.\nConfigure a policy for the bucket based on your compliance and\norganizational requirements. For more information, see Archive cold data\nwith transition rules.\no Enable Activity Tracker events on the bucket so that you can monitor any\ninteraction of users and services with the bucket. For more information,\nsee enable Activity Tracker events for the bucket.\no Enable monitoring for the bucket.\no Define a service to service (S2S) authorization between IBM Cloud Logs\nand IBM Cloud Object Storage to allow IBM Cloud Logs to read and write\ndata into the data bucket. For more information, see Creating a S2S\nauthorization to grant access to a bucket.",
    "default_value": "By default, Cloud Logs uses a Cloud Object Storage bucket for storage of events and\nmetadata. However, some settings and options, such as Priority Insights, may change\nthis behavior. Additionally, the default Cloud Object Storage bucket does not have all\ndata protection settings in place that are required to properly secure audit logs and\nensure long-term storage.\nIBM Cloud Logs does not backup your data. You are responsible for retaining your\nevents. When you enable Cloud Object Storage for your data, you are responsible for\nchecking that your retained files are protected, and the maintenance of your retained\nfiles.",
    "detection_commands": [
      "Use the following check list to ensure that long-term retention is configured for each of"
    ],
    "remediation_commands": [],
    "references": [
      "1. IBM Cloud Logs: Managing COS Buckets: https://cloud.ibm.com/docs/cloud-",
      "logs?group=managing-cos-buckets",
      "2. IBM Cloud Logs: TCO Data Pipelines: https://cloud.ibm.com/docs/cloud-",
      "logs?topic=cloud-logs-tco-data-pipelines",
      "3. IBM Cloud Object Storage: https://cloud.ibm.com/docs/cloud-object-",
      "storage?topic=cloud-object-storage-getting-started-cloud-object-storage",
      "4. IBM Cloud Object Storage managing encryption:",
      "https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-",
      "encryption"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 109,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "retention",
      "logging"
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
    "cis_id": "3.3",
    "title": "Ensure that events are collected and processed to identify anomalies or abnormal events",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "logging_monitoring",
    "domain": "Maintenance, Monitoring and Analysis of Audit Logs",
    "subdomain": "Ensure adequate storage for logs",
    "description": "Events that you collect and centralize in the IBM Cloud Logs service provide information\nabout actions that take place on your account. You can analyze this data to resolve\nproblems, identify anomalies, and be notified of abnormal situations.",
    "rationale": "IBM Cloud Logs and IBM Cloud Activity Tracker Event Routing add audit capabilities to\nyour IBM Cloud architecture.\nEach event reports information about who requested an action on your account (initiator\ndetails), what action was requested, the resource on which the action was requested\n(target details), and outcome of the request. Each event is based on the Cloud Auditing\nData Federation (CADF) standard. For more information about the IBM event definition,\nsee Event types and Event fields.\nIn IBM Cloud Activity Tracker Event Routing, events from core IBM Cloud platform\nservices are collected automatically and can be routed to a destination for analysis such\nas the IBM Cloud Logs service instances in your account. Events are also collected\nautomatically for enabled-AT services. However, some services might require an\nupgrade of the service plan, a configuration setting, or both, for you to be able to collect\nand analyze them.\nCore platform Activity Tracker events are available for all IBM Cloud services. These\nevents include provisioning and deletion of service instances, tagging, and IAM\nmanagement.\nThrough an audit instance, you can troubleshoot events in real time to diagnose issues\nand identify problems.\nBy using the live tail feature, you can diagnose issues, analyze stack traces and\nexceptions, identify the source of errors, and monitor different event sources through a\nsingle view. See Using Livetail for more information.\nIBM® Cloud Logs custom views feature helps organize specific, relevant log\ninformation, as well as create views that help other users work and retrieve important\ndata more efficiently. You can define private and shared views.",
    "impact": "The recommended custom views allow you to monitor actions that take place in your\naccount, the level of threat of those actions in your account, and abnormal situations.\nMissing any of these views and the ability to check that events are available through\nthem, exposes a potential security risk by hiding a possible gap of events that are\ncritical to control what happens in the account. In addition, views can have alerts\nattached to them so that you are notified quickly of abnormal situations. If you do not\nhave the right views, you lose the ability to configure alerts and pre-empt situations that\nmight require your attention.",
    "audit": "Use the following checklist to ensure that events are collected and processed to identify\nanomalies or abnormal events:\nThis checklist assumes that you have a different IBM Cloud account for development,\nstaging, Q&A, and production. When you separate accounts by domain (for example,\nproduction versus development), you isolate events for each domain and location. You\nuse IAM to define permissions to view and manage events in an instance.\nNote: When a user gets read permissions to see events in an IBM Cloud Logs instance,\nthe user gets visibility of all events in the region. Therefore, separate domains by\naccount to avoid exposing production logs to non-authorized users.\nChecklist\nThe checklist must be applied to each environment independently.\n1. Ensure that events from core IBM Cloud core platform services, such as IAM are\ncollected and available in the Cloud Logs instance where 'global' events have\nbeen routed to. Check that each core service has one or more custom views to\nanalyze the data.\no Check that you see provisioning events\no Check that you see IAM identity login events\no Check that you see IAM access group and policy events.\n2. Ensure that events from enabled IBM Cloud services are collected in each region\nwhere you operate. Check that events are available in the audit instance that is\navailable in the same region as your service instances.\no Check for additional configuration steps that a service might require.\no Check that you have a custom view for each service.\no Check that events for a specific service are available for analysis through\nthe custom view.\n3. Views can be classified in categories. For example, a category might be aligned\nwith a line of business.\no Ensure that views are grouped in categories.\no Check that each view belongs to the correct category.\n4. Check that custom views are defined for each service to monitor events that\nhave an outcome of failure.\n5. Check that custom views are defined for each service to monitor events that\nreport high level threat actions in your account. These events report deletion\nactions in the account.\n6. Check that custom views are defined for each service to monitor events that\nreport changes to resources in the account. For example, these events report\nactions that modify the state of a resource in your account.\n7. Check that custom views are defined for each service to monitor events that\nreport unauthorized or forbidden access to run actions in the account.\n8. Check that custom views are defined for each service to monitor events that\nreport user management actions in the account.\n9. Check that custom views are defined for each service to monitor events that\nreport actions on user management and related IAM actions.\nUI Instructions\nUI instructions that you can use to check that you have custom views to monitor activity\nin your account:\n1. Log in to your IBM Cloud account at https://cloud.ibm.com.\n2. Go to the Menu icon. Then, select Observability to access the\nObservability dashboard.\n3. Click Logging. By default Instances are displayed.\n4. Click the Cloud Logs tab.\n5. The list of instances that are available on IBM Cloud is displayed.\nIf the instances are not displayed, click Instances, Cloud Logs to display the\nlist of logging instances.\n6. Click Open dashboard for your selected instance.\n7. Look for views that report events from core IBM Cloud core platform services,\nsuch as IAM. Check that the search criteria of the views match the query\nindicated in the search criteria provided.\no Check that each view displays events with actions listed in the Events that\nare generated section.\no Check the description of each view and ensure that it is clear and reflects\nthe type of events that are available through the view.\no Name your view according to your organization’s naming convention.\nService to check: IAM Identity\nQuery: *_platform:iam-identity*\nEvents that are generated: [Events that are generated when a user or\napp logs in to the IBM\nCloud](https://cloud.ibm.com/docs/account?topic=account-\nat_events_iam#at_events_iam_login)\nService to check: IAM Access Management (IAM AM)\nQuery: *_platform:iam-am*\nEvents that are generated: [Events that are generated when you manage\nIAM policies](https://cloud.ibm.com/docs/account?topic=account-\nat_events_iam#at_events_iam_policies)\nService to check: IAM Groups\nQuery: *_platform:iam-groups*\nEvents that are generated: [Events that are generated when you manage\naccess groups](https://cloud.ibm.com/docs/account?topic=account-\nat_events_iam#at_events_iam_access)\n8. Look for views that report events from enabled IBM Cloud services.\no Check that the search query to filter data in the custom view is in the\nfollowing format:\n_platform:<Service Name>\no Check the description for each view.\no Check that the name of each view follows your organization’s naming\nconvention.\nTo see the list of available services, see Cloud services.\n9. Check that views are organized and grouped by category.\na. In the Cloud Logs web UI, select All Views\nb. Check the views that are within each folder.\n10. Look for views that report events that fail from enabled IBM Cloud services.\no Check that the search query to filter data in the custom view is in the\nfollowing format:\n_platform:<Service Name> AND outcome:failure\no Check the description for each view.\no Check that the name of each view follows your organization’s naming\nconvention.\nTo see the list of available services, see Cloud services.\n11. Look for views that report high level of threat actions in your account.\no Check that the search query to filter data in the custom view is in the\nfollowing format:\n_platform:<Service Name> AND severity:critical\no Check the description for each view.\no Check that the name of each view follows your organization’s naming\nconvention.\nTo see the list of available services, see Cloud services.\n12. Look for views that report actions that modify the state of resources in your\naccount.\no Check that the search query to filter data in the custom view is in the\nfollowing format:\n_platform:<Service Name> AND severity:warning\no Check the description for each view.\no Check the name of each view follows your organizations naming\nconvention.\nTo see the list of available services, see Cloud services.\n13. Look for views that report unauthorized or forbidden permissions on in your\naccount.\no Use the following search query to check that the custom view reports\nunauthorized access to run the action due to lack of permissions (RC\n401):\nreason.reasonCode:401\no Use the following search query to check that the custom view reports\nforbidden access to run the action due to missing credentials (RC 403):\nreason.reasonCode:403\no Check the description for each view.\no Check that the name of each view follows your organization’s naming\nconvention.\n14. Look for views that report user management actions in your account.\no Use the following search query to check that the custom view reports user\nmanagement actions in the account:\n(_platform:BSS AND action:user-management)\no Use the following search query to check user management and related\nIAM actions in your account:\n-(_platform:iam-identity AND (action login)) AND  (_platform:iam\nOR (_platform:BSS AND action:user-management))\no Check the description for each view.\no Check that the name of each view follows your organization’s naming\nconvention.\n15. Look for views that report successful logins in your account.\no Use the following search query to check the custom view:\n_platform:iam-identity AND (action login)\no Check the description for each view.\no Check that the name of each view follows your organization’s naming\nconvention.\n16. Look for views that report Security Advisor findings, that is, security incidents that\nare monitored by IBM Cloud Security Advisor in your account.\no Check the description for each view.\no Check that the name of each view follows your organization’s naming\nconvention.",
    "expected_response": "Use the following checklist to ensure that events are collected and processed to identify\nThe checklist must be applied to each environment independently.\n1. Ensure that events from core IBM Cloud core platform services, such as IAM are\n2. Ensure that events from enabled IBM Cloud services are collected in each region\no Ensure that views are grouped in categories.\no Check the description of each view and ensure that it is clear and reflects",
    "remediation": "UI instructions that you can use to create custom views when one or more are missing\nin the account:\n1. Log in to your IBM Cloud account at https://cloud.ibm.com.\n2. Go to the Menu icon. Then, select Observability to access the\nObservability dashboard.\n3. Click Logging. By default Instances are displayed.\n4. Click the Cloud Logs tab.\n5. The list of instances that are available on IBM Cloud is displayed.\nIf the instances are not displayed, click Instances, Cloud Logs to display the\nlist of logging instances.\n6. Click Open dashboard for your selected instance.\n7. In the left navigation, click the Explore logs icon, Logs.\n8. The last view you had opened will be displayed. If no view was previously open,\nall views will be displayed.\n9. Select the fields to be included in the view. By default you can select\nApplications, Subsystems, and log Severities.\n10. (Optional) Add additional filters click + Add Filter and select and configure\nadditional field and filter values.\n11. Select if you want you view to only include Priority Logs (those in the Priority\ninsights pipeline) or All Logs, that is, logs that are stored in IBM Cloud Object\nStorage. Logs in IBM Cloud Object Storage includes logs collected through all\nthe data pipelines.\n12. (Optional) Add a Lucene or DataPrime query to further filter your data.\n13. Specify the time interval for the view, for example Last 2 Days.\n14. Save your view by clicking the three dots ...\na. Enter a name for your view.\nb. If you want to save the query and filter values you configured, check Save query\nand filters.\nc. If you want your view to be the default view, check Set as default view. This sets\nthe view as the default for you as the user. It does not set the view as the default view\nfor the entire account.\nd. Set the privacy of your view. Private views can only be seen by you. You can set a\nview as Private or Shared.\n15. If you are missing views to monitor events from core IBM Cloud core platform\nservices, such as IAM, create custom views for each of the following services.\nUse the search criteria provided.\no Check that each view displays events with actions listed in the Events that\nare generated section.\no Check the description of each view and ensure that it is clear and reflects\nthe type of events that are available through the view.\no Name your view according to your organization’s naming convention.\nService to check: IAM Identity\nQuery: *_platform:iam-identity*\nEvents that are generated: [Events that are generated when a user or\napp logs in to the IBM\nCloud](https://cloud.ibm.com/docs/account?topic=account-\nat_events_iam#at_events_iam_login)\nService to check: IAM Access Management (IAM AM)\nQuery: *_platform:iam-am*\nEvents that are generated: [Events that are generated when you manage\nIAM policies](https://cloud.ibm.com/docs/account?topic=account-\nat_events_iam#at_events_iam_policies)\nService to check: IAM Groups\nQuery: *_platform:iam-groups*\nEvents that are generated: [Events that are generated when you manage\naccess groups](https://cloud.ibm.com/docs/account?topic=account-\nat_events_iam#at_events_iam_access)\n16. If you are missing views to monitor events from enabled IBM Cloud services,\ncreate custom views for each one of them.\no Use the following search query to filter data in the custom view:\n_platform:<Service Name>\no Add a description to each view.\no Name your view according to your organization’s naming convention.\nTo see the list of available services, see Cloud services.\n17. If views are not organized and grouped by folder, create as many folders as you\nwant, and assign views.\n1. In the Cloud Logs web UI, select All Views.\n2. To create a new folder, click the folder icon. Enter a folder name, and click\nCreate.\n3. Move views to folders by dragging them to the folder.\n18. If you are missing views to monitor events from enabled IBM Cloud services that\nreport failures, create custom views for each one of them.\nUse the following search query to filter data in the custom view:\n_platform:<Service Name> AND outcome:failure\nAdd a description to each view.\nName your view according to your organization’s naming convention.\nTo see the list of available services, see Cloud services.\n19. If you are missing views to monitor events that report high level of threat actions\nin your account, create custom views for each one of them.\nUse the following search query to filter data in the custom view:\n_platform:<Service Name> AND severity:critical\nAdd a description to each view.\nName your view according to your organization’s naming convention.\nTo see the list of available services, see Cloud services.\n20. If you are missing views to monitor events that report actions that modify the\nstate of resources in your account, create custom views for each one of them.\nUse the following search query to filter data in the custom view:\n_platform:<Service Name> AND severity:warning\nAdd a description to each view.\nName your view according to your organization’s naming convention.\nTo see the list of available services, see Cloud services.\n21. If you are missing views to monitor events that report unauthorized or forbidden\npermissions in your account, create custom views for each one of them.\nUse the following search query to filter data in the custom view that reports\nunauthorized access to run the action due to lack of permissions (RC 401):\nreason.reasonCode:401\nUse the following search query to filter data in the custom view that reports\nforbidden access to run the action due to missing credentials (RC 403):\nreason.reasonCode:403\nAdd a description to each view.\nName your view according to your organization’s naming convention.\n22. If you are missing views to monitor events that report user management actions\nin your account, create custom views for each one of them.\nUse the following search query to filter data in the custom view that report user\nmanagement actions in the account:\n(_platform:BSS AND action:user-management)\nUse the following search query to filter data in the custom view to report user\nmanagement and related IAM actions in your account:\n-(_platform:iam-identity AND (action login)) AND  (_platform:iam OR\n(_platform:BSS AND action:user-management))\nAdd a description to each view.\nName your view according to your organization’s naming convention.\n23. If you are missing views to monitor events that report successful logins in your\naccount, create a custom view.\nUse the following search query to filter data in the custom view:\n_platform:iam-identity AND (action login)\nAdd a description to the view.\nName your view according to your organization’s naming convention.",
    "default_value": "IBM Cloud Logs does not include default templates for views or alerts.\nYou can define your own views, alerts, and notification channels. Default notification\nchannels are configured by using presets.",
    "detection_commands": [
      "Use the following checklist to ensure that events are collected and processed to identify",
      "use IAM to define permissions to view and manage events in an instance."
    ],
    "remediation_commands": [
      "Use the search criteria provided.",
      "create custom views for each one of them.",
      "Create.",
      "Use the following search query to filter data in the custom view:",
      "Use the following search query to filter data in the custom view that reports",
      "Use the following search query to filter data in the custom view that report user",
      "Use the following search query to filter data in the custom view to report user"
    ],
    "references": [
      "1. IBM Cloud Activity Tracker Event Routing: Available Services:",
      "https://cloud.ibm.com/docs/atracker?topic=atracker-cloud_services_atracker",
      "2. IBM Cloud Activity Tracker Event Routing: Services Requiring Opt-In:",
      "https://cloud.ibm.com/docs/atracker?topic=atracker-events-opt-in",
      "3. IBM Cloud Logs: Custom Views: https://cloud.ibm.com/docs/cloud-",
      "logs?topic=cloud-logs-custom_views",
      "4. IBM Cloud Activity Tracker Event Types:",
      "https://cloud.ibm.com/docs/atracker?topic=atracker-event_types",
      "5. IBM Cloud Activity Tracker Event Fields:",
      "https://cloud.ibm.com/docs/atracker?topic=atracker-event"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 115,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
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
    "cis_id": "3.4",
    "title": "Ensure alerts are defined on custom views to notify of unauthorized requests, critical account actions, and high-impact operations in your account",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "logging_monitoring",
    "domain": "Maintenance, Monitoring and Analysis of Audit Logs",
    "subdomain": "Deploy SIEM or Log Analytic tool",
    "description": "Events that you collect and centralize in the IBM Cloud Logs service provide information\nabout actions that take place on your account. You can define alerts to notify promptly\nof problems, anomalies, and abnormal situations.",
    "rationale": "Each event reports information about who requested an action on your account (initiator\ndetails), what action was requested, the resource on which the action was requested\n(target details), and outcome of the request. Each event is based on the Cloud Auditing\nData Federation (CADF) standard. For more information about the IBM event definition,\nsee Event types and Event fields.\nIn IBM Cloud Activity Tracker Event Routing, events from core IBM Cloud platform\nservices are collected automatically and can be routed to a destination for analysis such\nas the IBM Cloud Logs service instances in your account. Events are also collected\nautomatically for enabled-AT services. However, some services might require an\nupgrade of the service plan, a configuration setting, or both, for you to be able to collect\nand analyze them.\nCore platform Activity Tracker events are available for all IBM Cloud services. These\nevents include provisioning and deletion of service instances, tagging, and IAM\nmanagement.\nThrough an audit instance, you can troubleshoot events in real time to diagnose issues\nand identify problems.\nBy using the live tail feature, you can diagnose issues, analyze stack traces and\nexceptions, identify the source of errors, and monitor different event sources through a\nsingle view. See Using Livetail for more information.\nIBM® Cloud Logs custom views feature helps organize specific, relevant log\ninformation, as well as create views that help other users work and retrieve important\ndata more efficiently. You can define private and shared views.\nIBM Cloud Logs and IBM Cloud Activity Tracker Event Routing add audit capabilities to\nyour IBM Cloud architecture.\nEach event reports information about who requested an action on your account (initiator\ndetails), what action was requested, the resource on which the action was requested\n(target details), and outcome of the request. Each event is based on the Cloud Auditing\nData Federation (CADF) standard. For more information about the IBM event definition,\nsee Event types and Event fields.\nIn IBM Cloud Activity Tracker Event Routing, events from core IBM Cloud platform\nservices are collected automatically and can be routed to a destination for analysis such\nas the IBM Cloud Logs service instances in your account. Events are also collected\nautomatically for enabled-AT services. However, some services might require an\nupgrade of the service plan, a configuration setting, or both, for you to be able to collect\nand analyze them.\nCore platform Activity Tracker events are available for all IBM Cloud services. These\nevents include provisioning and deletion of service instances, tagging, and IAM\nmanagement.\nThrough an audit instance, you can troubleshoot events in real time to diagnose issues\nand identify problems.\nBy using the live tail feature, you can diagnose issues, analyze stack traces and\nexceptions, identify the source of errors, and monitor different event sources through a\nsingle view. See Using Livetail for more information.\nIBM Cloud Logs custom views feature helps organize specific, relevant log information,\nas well as create views that help other users work and retrieve important data more\nefficiently. You can define private and shared views.\nIBM Cloud Logs alerts allow for timely detection of anomalies, proactive incident\nresponse, improved mean time to resolution (MTTR), reduced manual monitoring effort,\ncustomization, and flexibility. Powered by machine learning, alerting proactively notifies\nteams of potential problems, correlates incidents, and provides root cause analysis.",
    "impact": "The recommended alerts on custom views allow you to monitor actions that take place\nin your account, the level of threat of those actions in your account, and abnormal\nsituations. If you are missing any of these views and the ability to check that events are\navailable through them, exposes a potential security risk by hiding a possible gap of\nevents that are critical to control what happens in the account. In addition, views can\nhave alerts attached to them so that you are notified quickly about abnormal situations.\nIf you do not have the right views, you lose the ability to configure alerts and pre-empt\nsituations that might require your attention.",
    "audit": "Use the following checklist to ensure alerts are defined on custom views to notify of\nunauthorized requests, critical account actions, and high-impact operations in your\naccount.\nThis checklist assumes that you have a different IBM Cloud account for development,\nstaging, Q&A, and production. The checklist must be applied to each environment\nindependently.\nIn IBM Cloud Logs, you configure alerts that define the triggering conditions on filtered\ndata on which you want to be notified. In IBM Cloud Event Notifications, you configure\nthe destinations where you want to be notified for an alert and the conditions that define\nto which destination an event is routed. You can route events to one or more\ndestinations based on conditions that you configure. You can notify to a service\ndestination such as a webhook or PagerDuty, or to a human destination such as email\nor slack.\nTo check and confirm that alerts are correctly configured, perform the following checks:\n1. Verify the outbound connection from IBM Cloud Logs to the IBM Cloud Event\nNotifications service.\na. First, complete the following steps in the Event Notifications instance:\ni. Verify the source with name IBM Cloud Logs - <CLOUD_LOGS_INSTANCE_ID>, that\nmatches your integration name, is created in the IBM Cloud Event Notifications\ninstance.\n• Select Sources.\n• Look for the source with name IBM Cloud Logs -\n<CLOUD_LOGS_INSTANCE_ID>.\nii. Create a topic that specifies this Cloud Logs instance as the source and Event\ntype scoped to Test Event.\n• Select Topics. Then, click Create.\n• Enter a topic name, for example, CloudLogsInstance-test.\n• Select the source IBM Cloud Logs - <CLOUD_LOGS_INSTANCE_ID> for the\ninstance whose integration you want to test.\n• Select the Event type Test Event.\n• Select Add a condition, Save source.\n• Click Create.\niii. Create a destination and verify the destination is configured. For example, you\ncan configure a Slack destination or an email.\niv. Create a Subscription pairing the topic and the destination.\n• Enter a name, for example, Test integration.\n• Select the topic CloudLogsInstance-test.\n• Select a destination.\n• Click Create.\nb. Next, in the IBM Cloud Logs UI, complete the following steps:\ni. Edit the outbound integration.\nii. Click Test.\niii. Check your chosen destination and verify the test event has been sent.\n2. Ensure all required alerts are defined in the IBM Cloud Logs instance. Normal\nuse and behavior can vary depending on the workload that each client is running.\nEach client is encouraged to develop and maintain a list of critical alert. Review\nthe configured alerts to ensure there is coverage for all rules required by your\norganization.\n3. Ensure the IBM Cloud Event Notifications instance is configured to route event\nnotifications when an alert is triggered in IBM Cloud Logs to your target\ndestinations.\na. Ensure 1 or more topics are defined.\n• A topic defines the alert conditions that you want to group together.\n• For example, if you have multiple alert definitions in your IBM Cloud Logs\ninstance that notify through the same slack channel, you can configure these\nalerts within the same topic.\n• Another example, if you have multiple alert definitions in your IBM Cloud Logs\ninstance that notify through different slack channels, you must configure as many\ntopics as slack channels you use, and include in a topic the alerts that notify\nthrough the same slack channel.\nb. Define 1 or more destinations.\n• A destination defines a notification channel that you can use to notify when an\nalert is triggered.\n• For more information on destinations, see Supported destinations.\nc. Define 1 or more subscriptions.\n• A subscription links 1 topic with 1 destination.\n• You must add subscriptions to define the alerts configured in a topic are the ones\nnotified through the destination selected in the subscription configuration.\n• A subscription correlates one topic with a notification channel.\n• You can have multiple subscriptions with the same topic so you can alert through\nmultiple destination channels.\n4. For each custom view in Cloud Logs, check the purpose of the view and ensure\nsuitable alerts have been created based on the insights gained from that view\n5. Check that alerts have been configured for each of the following custom views:\n• Custom views that are defined for each service to monitor events that have an\noutcome of failure.\n• Custom views that are defined for each service to monitor events that have a\nseverity set to critical. These events report deletion actions in the account.\n• Custom views that are defined for service to monitor events that have a severity\nset to warning. These events report actions that modify the state of a resource in\nyour account.\n• Custom views that are defined for each service to monitor events that have a\nreason code set to 403 or 409. These events report requests on a service that\nare not authorized.\n• Custom views that are defined for each service to monitor events that report\nactions on access groups, changes of policies, user management, service IDs.\nThese events report IAM actions in the account.\n• Custom views that report Security Advisor findings, that is, security incidents that\nare monitored by IBM Cloud Security Advisor in your account.\nUI instructions that you can use to check that alerts on custom views are defined\nand working.\nThis checklist assumes that you have a different IBM Cloud account for development,\nstaging, Q&A, and production. The checklist must be applied to each environment\nindependently.\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Go to the Menu icon. Then, select Observability to access the\nObservability dashboard.\n3. Click Logging. By default Instances are displayed.\n4. Click the Cloud Logs tab.\n5. The list of instances that are available on IBM Cloud is displayed. If the instances\nare not displayed, click Instances, Cloud Logs to display the list of logging\ninstances.\n6. Click Open dashboard for your selected instance.\n7. Look for views that report events from core IBM Cloud core platform services,\nsuch as IAM, as well as those related to the conditions described in the\nBenchmark section 3.3.\n8. Check that alert definitions are defined. In the IBM Cloud Logs navigation, click\nthe Alerts icon, Alerts Management.\n9. For each custom view and alert notification channel, verify that you see an alert\nnotification so that you can validate that the alert is being generated.",
    "expected_response": "Use the following checklist to ensure alerts are defined on custom views to notify of\nstaging, Q&A, and production. The checklist must be applied to each environment\niii. Create a destination and verify the destination is configured. For example, you\n2. Ensure all required alerts are defined in the IBM Cloud Logs instance. Normal\nthe configured alerts to ensure there is coverage for all rules required by your\n3. Ensure the IBM Cloud Event Notifications instance is configured to route event\na. Ensure 1 or more topics are defined.\ninstance that notify through different slack channels, you must configure as many\n• You must add subscriptions to define the alerts configured in a topic are the ones\n4. For each custom view in Cloud Logs, check the purpose of the view and ensure",
    "remediation": "UI instructions that you can use to create alerts on custom views:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Go to the Menu icon. Then, select Observability to access the\nObservability dashboard.\n3. Click Logging. By default Instances are displayed.\n4. Click the Cloud Logs tab.\n5. The list of instances that are available on IBM Cloud is displayed. If the instances\nare not displayed, click Instances, Cloud Logs to display the list of logging\ninstances.\n6. Click Open dashboard for your selected instance.\n7. Configure alerts for any missing alerts.\nUI Instructions that you can use to create missing outbound integration to\nconnect IBM Cloud Logs with IBM Cloud Event Notifications:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. In the console, click the Navigation Menu icon, Resource list.\n3. Select your instance of IBM Cloud Logs.\n4. In the IBM Cloud Logs navigation, click the Integrations icon, Outbound\nintegrations.\n5. In the outbound integrations section, find Event Notifications and click Add.\n6. On the Integrations page, click Add new.\n7. If an IAM authorization between IBM Cloud Logs and Event Notifications doesn't\nexist in your account, you must configure one by clicking IAM Authorizations.\nFollow the prompts to grant access between the services. For more information,\nsee Creating a S2S authorization to work with the IBM Cloud Event Notifications\nservice.\n8. Enter a name for the integration.\n9. Select the Event Notifications service instance that you want to connect to your\nIBM Cloud Logs instance.\n10. Select the Endpoint Type as public or private. For more information, see\nService endpoints for Event Notifications\n11. To confirm the connection, click Save.",
    "default_value": "IBM Cloud Logs does not include default templates for views, alerts, and notification\nchannels.\nYou can define your own views, alerts, and notification channels.",
    "detection_commands": [
      "Use the following checklist to ensure alerts are defined on custom views to notify of",
      "use and behavior can vary depending on the workload that each client is running."
    ],
    "remediation_commands": [],
    "references": [
      "1. IBM Cloud Logs: Working with Alerts: https://cloud.ibm.com/docs/cloud-",
      "logs?topic=cloud-logs-event-notifications-about",
      "2. Configuring an outbound integration to connect IBM Cloud Logs with IBM Cloud",
      "Event Notifications: https://cloud.ibm.com/docs/cloud-logs?topic=cloud-logs-",
      "event-notifications-configure",
      "3. IBM Cloud Logs: Alerting: https://cloud.ibm.com/docs/cloud-logs?topic=cloud-",
      "logs-alerts"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 125,
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
    "cis_id": "3.5",
    "title": "Ensure the account owner can login only from a list of authorized countries/IP ranges",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "logging_monitoring",
    "domain": "Maintenance, Monitoring and Analysis of Audit Logs",
    "subdomain": "Regularly Tune SIEM",
    "description": "Monitor the account owner's access to the IBM Cloud account is done from authorized\nlocations that are restricted by IP addresses.",
    "rationale": "By default, a user can log in from any IP address.\nIn IBM Cloud, you can restrict a user to log in only from specific IP addresses.\nTherefore, you can define for the account owner the list of IP addresses that are\nallowed. Other IP addresses will be restricted.\nThis configuration feature per user allows you to restrict access from controlled\nlocations and adds an additional level of security into your IBM Cloud account.\nWhen a user such as the account owner logs in, information about its IP address is\nincluded in the Activity Tracker security event. You can monitor and be notified when\nthis event is generated in the account. You can obtain in the security event information\nabout unauthorized location.",
    "impact": "Failure to meet this recommendation limits your ability to control that the account\nmanager can only access and operate in the account from locations that are authorized\nand allowed by your organization.",
    "audit": "Complete the following steps to check if you monitor the locations from which the\naccount owner logs in to the account:\nFirst, you need to identify the email of the account owner.\n1. In the Cloud UI, go to Manage, Access (IAM), then select Users.\n2. Identify the user that has the tag owner.\n3. Select the account owner. Then, click Details.\n4. Copy the email address of the account owner.\nSecond, launch the IBM Cloud Logs instance in the region where Frankfurt and 'global'\nevents are routed. This is the instance where login security events are collected in the\naccount.\nIn the All Views section, look for a view that monitors the account owner login\nattempts. The search query should be set to: (action login) AND\ninitiator.name:<email address> AND -initiator.host.address:(<list of\nIP addresses>), where is the account owner email address, and <list of IP\naddresses> is the list of authorized IP addresses that are separated by OR, for example,\n(xxx.xxx.xxx.xxx OR xxx.xxx.xxx.xxx).\nThen, check that at least one alert has been configured for audit events that deviate\nfrom the expected source IPs.\nAdditionally, context-based restrictions protect your resources by denying access to\nidentities that don't satisfy context requirements, such as making access requests from\nthe network zones and endpoint types that you define. You can enable context-based\nrestrictions upon creation, or choose to set the rule to report-only mode. Use IBM Cloud\nLogs to monitor enabled rules and report-only rules to view how the rule affects your\nusers, applications, and workflows without enforcing the rule.\nComplete the following steps to check if you monitor for context-based restrictions\nviolations that occur in report-only mode:\n1. In the IBM Cloud console, go to the Navigation Menu icon, Observability,\nLogging, Instances, Cloud Logs.\n2. Click Open dashboard on the dashboard that you use to monitor context-based\nrestrictions.\n3. Use the search field to narrow the results to report-only context-based\nrestrictions events.\n• To view potentially blocked access requests, search for action:context-\nbased-restrictions.policy.eval responseData.isEnforced:==false\nresponseData.decision:Deny.\n• isEnforced:==false indicates that the rule is in report-only mode.\n• responseData.decision:Deny indicates that, if you enable the rule, this access\nrequest is blocked.\n4. Check that at least one alert has been configured for audit events that detect\nhigh volumes of context-based restriction violations that are not being enforced.\n5. Check that an alert is configured to trigger on any/all context-based restriction\nviolations that are not being enforced which occur for the email address of the\nAccount Owner.",
    "expected_response": "attempts. The search query should be set to: (action login) AND\n5. Check that an alert is configured to trigger on any/all context-based restriction",
    "remediation": "Complete the following steps to monitor the locations from which the account owner\nlogs in to the account:\nFirst, you need to identify the email of the account owner.\n1. In the Cloud UI, go to Manage, Access (IAM), then select Users.\n2. Identify the user that has the tag owner.\n3. Select the account owner. Then, click Details.\n4. Copy the email address of the account owner and the list of authorized IP\naddresses.\n5. Launch the IBM Cloud Logs instance in the region where Frankfurt and global\nevents are routed. This is the instance where login security events are collected\nin the account.\n6. Create an alert based on any deviations where the Account Owner logs in from\nan unauthorized IP address. For example, use the following query: (action\nlogin) AND initiator.name:<email address> AND -\ninitiator.host.address:(<list of IP addresses>). Replace with the\naccount owner's email address. Replace <list of IP addresses> with the list of IP\naddresses that are separated by OR, for example, (xxx.xxx.xxx.xxx OR\nxxx.xxx.xxx.xxx) and configured for the account owner.\nComplete the following steps to monitor for context-based restriction violations that are\nnot being enforced:\nFirst, you need to identify the email of the account owner.\n1. In the Cloud UI, go to Manage, Access (IAM), then select Users.\n2. Identify the user that has the tag owner.\n3. Select the account owner. Then, click Details.\n4. Copy the email address of the account owner and the list of authorized IP\naddresses.\n5. Launch the IBM Cloud Logs instance in the region where Frankfurt and global\nevents are routed. This is the instance where login security events are collected\nin the account.\n6. Create an alert that monitors for any context-based restriction deviations where\nthe Account Owner's email is identified in an event for a context-based restriction\nthat is not being enforced but would have resulted in a deny.\n• Use the query field to narrow the results to report-only context-based restrictions\nevents. Search for action:context-based-restrictions.policy.eval\nresponseData.isEnforced:==false responseData.decision:Deny.\n• isEnforced:==false indicates that the rule is in report-only mode.\n• responseData.decision:Deny indicates that, if you enable the rule, this access\nrequest is blocked.",
    "default_value": "By default, there are no restrictions of which IP Address or contexts the account owner\ncan login from, and there are no alerts in place to monitor this.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. Monitoring context-based restrictions:",
      "https://cloud.ibm.com/docs/account?topic=account-cbr-monitor",
      "2. IBM Cloud Logs: Create an alert: https://cloud.ibm.com/docs/cloud-",
      "logs?topic=cloud-logs-alerts-config"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 132,
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
    "cis_id": "3.6",
    "title": "Ensure Activity Tracker data is encrypted at rest",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Maintenance, Monitoring and Analysis of Audit Logs",
    "subdomain": "Alert on Account Login Behavior Deviation",
    "description": "Ensure Activity Tracker data is encrypted at rest.",
    "rationale": "IBM Cloud Logs uses encrypted storage for all its rest data.\nIBM Cloud Logs stores the Activity Tracker data in an IBM Cloud Object Storage (COS)\nbucket for long-term storage. By default, all objects that are stored in COS are\nencrypted by using randomly generated keys and an all-or-nothing-transform (AONT).\nCloud Object Storage further supports additional key management scenarios to encrypt\nyour data. This encryption model is called customer-managed encryption:\n1. You can manage your keys manually by providing your own encryption keys -\nreferred to as Server-Side Encryption with Customer-Provided Keys (SSE-C).\n2. You can choose to use the integration capabilities with IBM Cloud® Key\nManagement Services like IBM® Key Protect and Hyper Protect Crypto Services.",
    "impact": "Failure to adopt a customer-managed encryption model for audit data that is retained for\nlong-term storage can breach infrastructure compliance where you are required to use\nyour keys for encrypting data that you manage.",
    "audit": "1. Ensure IBM Cloud Activity Tracker Event Routing is configured to route audit\nevents to one or more IBM Cloud Logs instances as documented.\n2. For each IBM Cloud Logs instance, identify the IBM Cloud Object Storage\nbuckets that are used for both the data bucket and the metrics bucket. In some\ncases, these will both use the same bucket, but for some clients separate COS\nbuckets will be used.\n3. Verify the data encryption configuration of the COS buckets being used by IBM\nCloud Logs to store your data. Check the bucket configuration to verify that it\nmeets your corporate and external market regulations.\n4. Ensure that the CIS control 3.2 Ensure data retention for audit events\nis met, which outlines the encryptions settings in detail.",
    "expected_response": "1. Ensure IBM Cloud Activity Tracker Event Routing is configured to route audit\n4. Ensure that the CIS control 3.2 Ensure data retention for audit events",
    "remediation": "If you have Cloud Object Storage buckets in use that do not meet your enterprise or\nindustry encryption compliance requirements, use one of these options to implement the\nnecessary encryption settings:\nA. Implement Server-Side Encryption with Customer-Provided Keys (SSE-C)\nB. Implement Server-Side Encryption with IBM Key Protect (SSE-KP)\nC. Implement Server-Side Encryption with Hyper Protect Crypto Services",
    "default_value": "IBM Cloud Logs uses encrypted storage for all data at rest.\nBy default, all objects that are stored in Cloud Object Storage are encrypted by using\nrandomly generated keys and an all-or-nothing-transform (AONT).",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. IBM Cloud Object Storage: https://cloud.ibm.com/docs/cloud-object-",
      "storage?topic=cloud-object-storage-getting-started-cloud-object-storage",
      "2. IBM Cloud Object Storage managing encryption:",
      "https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-",
      "encryption"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 136,
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
    "cis_id": "4.1",
    "title": "Ensure IBM Cloud Databases disk encryption is enabled with customer managed keys",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "database",
    "domain": "IBM Cloud Databases Family",
    "description": "IBM Cloud Databases provides automatic encryption at rest when provisioning the\nservice. It is not an option to deploy a database service without encryption at rest.\nHowever, using the service's integration with IBM Key Protect, customers can bring their\nown encryption key at the time of database provisioning. Furthermore, IBM Cloud\nDatabases backups are also encrypted by default.\nBefore any UI or CLI commands. Follow the authorization instructions between the HSM\nand Database service.\n1. Open your IBM Cloud dashboard.\n2. From the menu bar, click Manage, Access (IAM).\n3. In the side navigation, click Authorizations.\n4. Click Create.\n5. In the Source service menu, select the service of the deployment. For\nexample, Databases for PostgreSQL or Messages for RabbitMQ\n6. In the Source service instance menu, select All instances.\n7. In the Target service menu, select Key Protect.\n8. Select or retain the default value Account as the resource group for the Target\nService.\n9. In the Target service Instance ID menu, select the service instances to\nauthorize.\n10. Under Service access, check the box to enable the Reader role.\n11. Click Authorize.\n12. Service Creation via UI or CLI with the appropriate encryption key from IBM Key\nProtect\nUsing Console:\n1. Head to the respective catalog page of the service you want to provision with a\ncustomer-managed encryption key (e.g.,\nhttps://cloud.ibm.com/catalog/services/databases-for-postgresql)\n2. Fill out the form with the desired region, RAM, CPU, Disk, Database version, and\nNetworking settings.\n3. Click Select a Key Protect instance, your authorized Key Protect instances\nwill appear in the dropdown. Select the one you want to use.\n4. Directly to the right, click Select a disk encryption key. A list of available\nencryption keys from the previously selected Key Protect instance will be\nselectable for encrypting your database at rest.\nUsing CLI:\nRun the following command after logging into IBM Cloud via the CLI\nibmcloud resource service-instance-create example-database <service-name>\nstandard us-south \\\n-p \\ '{\"disk_encryption_key_crn\": \"crn:v1:<...>:key:<id>\"}'",
    "rationale": "When it comes to encryption of data at rest in IBM Cloud, we recommend for customers\nto manage customer root keys that are used to protect customer data stored in data and\nstorage services in IBM Cloud. With the support of Bring Your Own Key (BYOK),\ncustomers can manage lifecycle of their customer root keys where they can create,\nrotate, delete those keys. This provides a significant level of control where those CRKs\nare managed by the customer, which in turn increases both security control as well as\nmeet relevant compliance requirements. These CRKs are usd in turn to protect the data\nencryption keys used to encrypt the data.",
    "impact": "If a customer does not bring their own encryption key at provision time, they are not\nable to cryptoshred the database or revoke the database's access to the encryption key\nrendering it unable to boot storage.",
    "audit": "Using Console:\n1. Log on to your IBM Cloud account\n2. Go to the Menu icon, Resource List to access your list of account resources\n3. Click the Database service you are interested in to open the service dashboard.\n4. Ensure you are on the Manage page in the left pane.\n5. You should be on the Overview tab. Scroll down to the security section.\n6. The security section will show an Encryption Key section under Disks. If the\nvalue shown is Automatic Key this means the deployment does not have a\ncustomer-managed encryption key through IBM Key Protect\nUsing CLI:\n1. At a minimum, have the Viewer role for the IBM Cloud Databases deployment.\n2. Run\nibmcloud cdb deployment-about <CRN> [--all] [--json]\nThis will return the Encryption Key Status, if the deployment is created with a customer-\nmanaged encryption key, the key CRN will display here.",
    "expected_response": "4. Ensure you are on the Manage page in the left pane.\n5. You should be on the Overview tab. Scroll down to the security section.\nThis will return the Encryption Key Status, if the deployment is created with a customer-",
    "remediation": "There is no zero-downtime remediation procedure . Customer must restore a backup\nwith a new encryption key or create a net new database instance with Bring Your Own\nKey enabled.\nTo restore a backup with a new encryption key:\n1. Ensure you have the Viewer Privileges on the IBM Cloud Databases deployment\nto read a backup file and X privileges on IBM Cloud platform to create a resource\n2. Ensure you have service to service authorization set up between IBM Cloud\nDatabases and IBM Key Protect, directions for granting this access can be found\nhere\n3. Be sure to replace SERVICE_INSTANCE_NAME and KEY PROTECT KEY CRN\nwith a new service instance name and your desired Key Protect key CRN\nrespectively before running this command. For more information, please view our\ndocumentation.\nibmcloud resource service-instance-create SERVICE_INSTANCE_NAME databases-\nfor-postgresql standard us-south -p '{\"backup_id\":\"xyz-inital-\nbackup\",\"disk_encryption_key_crn\":\"DISK_ENCRYPTION_KEY_CRN\"}'\n4. This will create a new database instance from backup with the requested\ncustomer managed encryption key.",
    "default_value": "The default value when creating a deployment is automatic disk and backup encryption\nkey management by IBM Cloud Databases",
    "detection_commands": [
      "ibmcloud cdb deployment-about <CRN> [--all] [--json]"
    ],
    "remediation_commands": [
      "ibmcloud resource service-instance-create SERVICE_INSTANCE_NAME databases-"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 139,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "backup",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D3",
      "D6"
    ]
  },
  {
    "cis_id": "4.2",
    "title": "Ensure network access to IBM Cloud Databases service is set to be exposed on “Private end points only”",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "database",
    "domain": "IBM Cloud Databases Family",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "All Cloud Databases deployments offer integration with IBM Cloud Service Endpoints. It\ngives you the ability to enable connections to your deployments from the public internet\nand over the IBM Cloud Private network.\nService Endpoints are available in all IBM Cloud Multi-Zone Regions and Single-Zone\nRegions. In other words, Deployments in all regions can utilize the available service\nendpoint options.\nPublic endpoints provide a connection to your deployment on the public network.\nHowever, at provision time, a private endpoint is the default option for all deployments.\nYour environment needs to have internet access to connect to a deployment.\nA deployment with a service endpoint on the private network gets an endpoint that is not\naccessible from the public internet. All traffic is routed to hardware dedicated to Cloud\nDatabases deployments and remains on the IBM Cloud Private network. All traffic to\nand from this endpoint is free and unmetered as long as the traffic remains in IBM\nCloud. Once your environment has access to the IBM Cloud Private network, an\ninternet connection is not required to connect to your deployment.",
    "rationale": "The use of public endpoints exposes data that is contained in the database to\nunnecessary risk from the outside internet.",
    "impact": "Some applications are not run in the IBM Cloud. Therefore, they cannot rely on the IBM\nCloud network backbone to maintain communication from application to the database\nover the private network. In this case, the customer may choose to enable \"Public\"\nendpoints which allow access to the database from the internet. Customers that are\nrequired to do should IP Whitelist the database before enabling \"Public\" endpoints.",
    "audit": "Using Console:\n1. Log on to your IBM Cloud account\n2. Go to the Menu icon, Resource List to access your list of account resources\n3. Click the Database service you are interested in to open the service dashboard.\n4. Ensure you are on the Manage page in the left pane.\n5. Click the Settings tab in the middle of the page and scroll down to Service\nendpoints\n6. Review the toggle that displays the status of Private endpoint and Public\nendpoint enablement. Ensure, Public is toggled off and Private is toggled on.\n(Private is the default setting)\nUsing API:\n1. Access to the API uses token authentication, by using the header Authorization:\nBearer . The token must be IAM-issued. You can send in an IAM API key directly\nas the token or use the API key to generate an IAM Bearer Token.\n2. Insert the region your deployment is in and the CRN of your deployment as\nindicated by {}\ncurl -X GET\nhttps://api.{region}.databases.cloud.ibm.com/v4/ibm/deployments/{id} -H\n'Authorization: Bearer <>' \\\nThis will return something like:\n{\n\"deployment\": {\n\"id\": \"crn\",\n\"name\": \"crn\",\n\"type\": \"database\",\n\"platform_options\": {\n\"key_protect_key_id\": \"\"\n},\n\"version\": \"x.y\",\n\"admin_username\": \"admin\",\n\"enable_private_endpoints\": true,\n\"enable_public_endpoints\": false\n}\n}\nEnsure that enable_private_endpoints is true and that enable_public_endpoints\nis false.",
    "expected_response": "4. Ensure you are on the Manage page in the left pane.\nendpoint enablement. Ensure, Public is toggled off and Private is toggled on.\nBearer . The token must be IAM-issued. You can send in an IAM API key directly\nThis will return something like:\nEnsure that enable_private_endpoints is true and that enable_public_endpoints",
    "remediation": "Using Console:\n1. Log on to your IBM Cloud account\n2. Go to the Menu icon, Resource List to access your list of account resources\n3. Click the Database service you are interested in to open the service dashboard.\n4. Ensure you are on the Manage page in the left pane.\n5. Click the Settings tab in the middle of the page and scroll down to Service\nendpoints\n6. Select Private endpoint toggle to be turned on and Public endpoint to be\nturned off.\n7. Click Update Endpoints\nUsing CLI:\nYou can use the ibmcloud resource service-instance-update command in the CLI,\nspecifying the endpoint with the --service-endpoints flag. This can be done online with\nno downtime\nibmcloud resource service-instance-update <service-name> --service-endpoints\n<endpoint-type>\nChanging the type of endpoints available on your deployment does not cause any\ndowntime from a database perspective. However, if you disable an endpoint that is\nbeing used by you or your applications, those connections are dropped.\nFrom the API:\nYou can use the Resource Controller API, with a PATCH request to the\n/resource_instances/{id} endpoint.\nFigure out more detail here, should be copy and paste for every service",
    "default_value": "Private",
    "detection_commands": [
      "curl -X GET"
    ],
    "remediation_commands": [
      "ibmcloud resource service-instance-update <service-name> --service-endpoints"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 143,
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
    "cis_id": "4.3",
    "title": "Ensure incoming connections are limited to allowed sources",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "database",
    "domain": "IBM Cloud Databases Family",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Restrict incoming connections to database instances to approved sources, ensuring\naccess is limited to authorized entities.",
    "rationale": "IBM Cloud Databases supports Context-Based Restrictions (CBR) for both public and\nprivate endpoints. Context-based restrictions give account owners and administrators\nthe ability to define and enforce access restrictions for resources based on a rule's\ncriteria. The criteria include the network location of access requests, the endpoint type\nfrom where the request is sent, the multifactor authentication level of an identity, and\nsometimes the API that the request tries to access.",
    "audit": "Using Console:\n1. Log on to your IBM Cloud account\n2. On the top bar, click on Manage and then on Context-Based Restrictions\n3. On the left, click on Network zones and then on the Create button.\n4. Give the rule a name and fill out the other details as appropriate. Complete\ncreation.\n5. On the left, click on Network rules and then on the Create button\n6. Select the appropriate database resource, such as Databases for\nPostgreSQL. Click on next.\n7. When asked for APIs to protect, deselect All and select Data Plane instead.\nClick on next.\n8. Under Resources, select Specific resources, and then in the dropdown, select\ninstance\n9. Click on Select a value, and you can choose a database to match. Click on\nreview and then on continue.\nUsing CLI:\n1. Create a zone for IP 192.0.2.2\nibmcloud cbr zone-create --addresses=192.0.2.2 --name=my_zone\n2. Note the ID of the zone from the response, or from the zones list\nibmcloud cbr zones\n3. Create the rule that only allows the defined zone to connect to our PostgreSQL\ndatabase\nibmcloud cbr rule-create --enforcement-mode enabled --context-attributes\nnetworkZoneId=ac31d7c9911cd0b98bb77490b2254258  --service-name databases-for-\npostgresql --service-instance 8e4ce809-5edd-47c0-b4cd-8737f030f29d --api-\ntypes crn:v1:bluemix:public:context-based-restrictions::::api-type:data-plane\n--description my_cbr_rule\n4. Examine the list of rules.\nibmcloud cbr rules\nNote that the direct “Using IP Allowlists on your Deployment” mechanism, as described\nin https://cloud.ibm.com/docs/cloud-databases?topic=cloud-databases-\nallowlisting&interface=ui, has been deprecated in favor of CBR.",
    "remediation": "Configure restrictions using the following procedure:\nUsing Console:\n1. Log on to your IBM Cloud account\n2. On the top bar, click on Manage and then on Context-Based Restrictions\n3. On the left, click on Network zones and then on the Create button.\n4. Give the rule a name and fill out the other details as appropriate. Complete\ncreation.\n5. On the left, click on Network rules and then on the Create button\n6. Select the appropriate database resource, such as Databases for\nPostgreSQL. Click on next.\n7. When asked for APIs to protect, deselect All and select Data Plane instead.\nClick on next.\n8. Under Resources, select Specific resources, and then in the dropdown, select\ninstance\n9. Click on Select a value, and you can choose a database to match. Click on\nreview and then on continue.\n10. Select the check mark for the zone that you want to give access to (the one\ncreated at the start of the process), then click on the Add button. You will see it\non the right side. Click on continue.\n11. Give it a descriptive name, and then click on Create.\nUsing CLI:\n1. Create a zone for IP 192.0.2.2\nibmcloud cbr zone-create --addresses=192.0.2.2 --name=my_zone\n2. Note the ID of the zone from the response, or from the zones list\nibmcloud cbr zones\n3. Create the rule that only allows the defined zone to connect to our PostgreSQL\ndatabase\nibmcloud cbr rule-create --enforcement-mode enabled --context-attributes\nnetworkZoneId=ac31d7c9911cd0b98bb77490b2254258  --service-name databases-for-\npostgresql --service-instance 8e4ce809-5edd-47c0-b4cd-8737f030f29d --api-\ntypes crn:v1:bluemix:public:context-based-restrictions::::api-type:data-plane\n--description my_cbr_rule\n4. Examine the list of rules.\nibmcloud cbr rules\nNote that the direct “Using IP Allowlists on your Deployment” mechanism, as described\nin https://cloud.ibm.com/docs/cloud-databases?topic=cloud-databases-\nallowlisting&interface=ui, has been deprecated in favor of CBR.",
    "default_value": "All incoming connections allowed.",
    "detection_commands": [
      "ibmcloud cbr zone-create --addresses=192.0.2.2 --name=my_zone",
      "ibmcloud cbr zones",
      "ibmcloud cbr rule-create --enforcement-mode enabled --context-attributes",
      "ibmcloud cbr rules"
    ],
    "remediation_commands": [
      "ibmcloud cbr zone-create --addresses=192.0.2.2 --name=my_zone",
      "ibmcloud cbr zones",
      "ibmcloud cbr rule-create --enforcement-mode enabled --context-attributes",
      "ibmcloud cbr rules"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 146,
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
    "cis_id": "5.1",
    "title": "Ensure IBM Cloudant encryption is enabled with customer managed keys",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "cloudant",
    "domain": "Cloudant",
    "description": "IBM Cloudant encrypts all client data at-rest by default. For customers using a\nDedicated Hardware plan instance, it is optional to use the service's integration with IBM\nKey Protect for customers to bring their own encryption key at provision time for the\ninstance.\nTo provision a Cloudant Dedicated Hardware plan instance using Bring-Your-Own-Key\nwith Key Protect, first ensure you are logged into your IBM Cloud account at\nhttps://cloud.ibm.com/. Note a paid account is required to provision a Cloudant\nDedicated Hardware plan instance.\nBefore provisioning the Dedicated Hardware plan instance with BYOK with Key Protect,\nfollow the authorization instructions between Key Protect and Cloudant:\n1. Open your IBM Cloud dashboard.\n2. From the menu bar, click Manage, Access (IAM).\n3. In the side navigation, click Authorizations.\n4. Click Create.\n5. In the Source service menu, select the Cloudant in Account.\n6. In the Source service instance menu, select All instances.\n7. In the Target service menu, select Key Protect in Account, and leave Instance\nID of string equals All instances.\n8. Enable the Reader role by checking the checkbox.\n9. Click Authorize.\nEnsure the necessary encryption key(s) in Key Protect have been created. (See IBM\nKey Protect documentation for those steps.)\nNext provision a Cloudant Dedicated Hardware plan instance and choose the BYOK\nwith Key Protect option during the provisioning process:\nUsing Console:\n1. From the IBM Cloud Dashboard, click on Create resource.\n2. Type Cloudant in the search bar and click the Cloudant tile to open it.\n3. Select Cloudant offering.\n4. Click the Dedicated tab.\n5. Click Create Host.\n6. Select the IBM Cloud region.\n7. Configure the Cloudant instance by specifying the Instance name and\nResource group.\n8. Under Configure Host, choose the Location for deployment to specify the\nphysical location of the Dedicated Hardware plan instance.\n9. Choose Yes or No for Will the data stored require HIPPA compliance?.\n10. To use a customer-managed (BYOK) encryption key, choose the KMS instance\nunder Key Management Service instance.\n11. Under Disk encryption key, choose the name of the encryption key to use from\nthe KMS instance in the previous step.\n12. Click Create to provision the Dedicated Hardware plan instance. Note that\nduring provisioning, a spinning wheel appears next to the instance in your IBM\nCloud Dashboard. A request is sent to provision a Dedicated Hardware plan\ninstance on bare metal servers. Provisioning time is asynchronous and can take\nup to 5 days.\nUsing CLI:\n1. Login to the IBM Cloud via the CLI.\n2. Run the following command to provision a Cloudant Dedicated Hardware plan\ninstance using a customer-managed encryption key stored in IBM Key Protect:\nibmcloud resource service-instance-create <name> cloudantnosqldb dedicated-\nhardware <region> -p '{\"location\":\"<location>\", \"hipaa\":\"<hipaa>\",\n\"kms_instance_crn\": \"<kms_instance_crn>\", \"kms_key_crn\": \"<kms_key_crn>\"}'\nWhere the customer parameters to enter are as follows:\n• name: An arbitrary name of the Cloudant Dedicated Hardware instance.\n• region: The major region where you want to deploy, for example us-south, us-\neast, etc.\n• location: The actual physical location of the Dedicated Hardware plan instance,\nwhich might differ from the region. The location can be in any IBM Cloud\nlocation, including major regions and locations outside the major regions.\n• hipaa: Either true or false.\n• kms_instance_crn: An optional parameter that must be set to the CRN of the\nKey Protect instance housing the encryption key for BYOK. All IBM Cloudant\nenvironments are encrypted. If you would like to BYOK with Key Protect, supply\nthe CRN of the Key Protect instance that holds the encryption key. Otherwise,\ndon't supply this parameter in the CLI, which means the environment is\nencrypted with an IBM Cloudant-managed key.\n• kms_key_crn: This parameter is required if you use the kms_instance_crn\nparameter. Otherwise, it must not be supplied in the CLI command. The\nkms_key_crn parameter is set to the CRN of the encryption key stored in the\nKey Protect instance defined by the kms_instance_crn parameter.\nBelow is an example CLI command with the parameters populated with sample values:\nibmcloud resource service-instance-create cloudant-dedicated-with-byok\ncloudantnosqldb dedicated-hardware us-south -p '{\"location\":\"dallas\",\n\"hipaa\":\"false\", \"kms_instance_crn\": \"crn:v1:bluemix:public:kms:us-\nsouth:a/abcdefg7df5907a4ae72ad28d9f493d6:888a5a41-543c-4ca7-af83-\n74da3bb8f711::\", \"kms_key_crn\": \"crn:v1:bluemix:public:kms:us-\nsouth:a/abcdefg7df5907a4ae72ad28d9f493d6:888a5a41-543c-4ca7-af83-\n74da3bb8f711:key:0123c653-f904-4fe7-9fdb-5097e1ed85db\"}'",
    "rationale": "When it comes to encryption of data at rest in IBM Cloud, we recommend for customers\nto manage customer root keys that are used to protect customer data stored in data and\nstorage services in IBM Cloud. With the support of Bring Your Own Key (BYOK),\ncustomers can manage lifecycle of their customer root keys where they can create,\nrotate, delete those keys. This provides a significant level of control where those CRKs\nare managed by the customer, which in turn increases both security control as well as\nmeet relevant compliance requirements. These CRKs are used in turn to protect the\ndata encryption keys used to encrypt the data.",
    "impact": "Additional administrative time will be required for the creation, transport, storage, and\nmanagement of keys when using customer managed keys. If a customer does not bring\ntheir own encryption key at provision time, they are not able to crypto-shred the data or\nrevoke the database's access to the encryption key, which would render the database\nunable to read the data.",
    "audit": "Users can audit whether a Cloudant Dedicated Hardware environment is using a\ncustomer-managed key by viewing associations between root keys and associated\ncloud services in the IBM Key Protect UI or API. Use the steps below to see the\nassociations and verify that the Cloudant Dedicated Hardware plan instance(s) have the\nappropriate associations listed to show the use of customer-managed encryption key in\nKey Protect.\nUsing Console:\n1. Log in to the IBM Cloud console.\n2. Go to Menu, Resource List to view a list of your resources.\n3. From your IBM Cloud resource list, select your provisioned instance of Key\nProtect.\n4. On the application details page, select the Associated Resources tab on the\nleft side menu.\n5. On the Associated resources page, use the Associated Resources table to\nbrowse the registrations in your service.\n6. Click the ^ icon under the Details column to view a list of details for a specific\nregistration.\n7. Click Filter button to filter for resources by key ID, Cloud Resource Name\n(CRN), and retention policy.\nUsing API:\nYou can retrieve the registration details that are associated with a specific root key by\nmaking a GET call to the following endpoint:\nhttps://<region>.kms.cloud.ibm.com/api/v2/keys/<key_ID>/registrations\nView the registrations that are associated with a root key by running the following cURL\ncommand:\n$ curl -X GET \\\n\"https://<region>.kms.cloud.ibm.com/api/v2/keys/<key_ID>/registrations\"\n\\\n-H \"authorization: Bearer <IAM_token>\" \\\n-H \"bluemix-instance: <instance_ID>\"\nwhere the variables are as follows:\n• region: Required. The region abbreviation, such as us-south or eu-gb, that\nrepresents the geographic area where your Key Protect instance resides.\n• key_ID: Required. The identifier for the root key that is associated with the cloud\nresources that you want to view.\n• IAM_token: Required. Your IBM Cloud access token. Include the full contents of\nthe IAM token, including the Bearer value, in the cURL request.\n• instance_ID: Required. The unique identifier that is assigned to your Key\nProtect service instance.",
    "remediation": "The process to remediate a configuration where there is no use of a customer-managed\nencryption is as follows:\n1. Provision a new Cloudant Dedicated Hardware plan instance using a customer-\nmanaged key as shown in details above.\n2. Create new Cloudant instance(s) on the Dedicated Hardware plan instance that\nis using a customer-managed key as needed.\n3. Replicate data over from the Cloudant instances not using a customer-managed\nkey to the instances on the Dedicaed Hardware environment using the customer-\nmanaged key. This process requires use of the Cloudant replication feature as\nshown in the Cloudant documentation.\n4. Delete any Cloudant instances on environments that do not use customer-\nmanaged keys once the replication is complete.",
    "default_value": "The default value is Automatic disk encryption key (default), which means the\ndisk encryption will be done with an IBM-managed key and not a customer managed\nkey. Customers must choose to use IBM Key Protect with a customer-managed key.",
    "detection_commands": [],
    "remediation_commands": [],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 151,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "backup",
      "key_management"
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
    "cis_id": "6.1.1",
    "title": "Enable TLS 1.2 at minimum for all inbound traffic on IBM Cloud Internet Services Proxy",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "IBM Cloud Internet Services",
    "description": "The Transport Layer Security (TLS) options let you control whether visitors can browse\nyour website over a secure connection, and when they do, how IBM Cloud™ Internet\nServices connects to your origin server. Ensure minimum TLS level for TLS termination\nis set to TLS 1.2. Use the latest version of the TLS protocol (TLS 1.3) for improved\nsecurity and performance by switching from Disabled to Enabled or Enabled+ORTT in\nthe list.\nTLS encryption modes\nSet the TLS mode by selecting one of the following options from the Mode list.\nThese options are listed in the order from the least secure (Off) to the most secure\n(End-to-End CA signed).\n• Off (not recommended)\n• Client-to-Edge (edge to origin not encrypted, self-signed certificates are not\nsupported)\n• End-to-End flexible (edge to origin certificates can be self-signed)\n• End-to-End CA signed (default and recommended)\n• HTTPS only origin pull (Enterprise only)\nTraffic encryption - Minimum TLS version\nSet the minimum TLS version for traffic trying to connect to your site by selecting one of\nthe versions from the list.\nBy default, this is set to 1.2. Higher TLS versions provide additional security, but might\nnot be supported by all browsers. This could result in some customers being unable to\nconnect to your site.\nThe minimum TLS version applies to whichever TLS encryption mode is selected.",
    "rationale": "Use the latest version of the TLS protocol for improved security and performance.\nTLS1.1 is now considered obsolete and has some vulnerabilities.",
    "impact": "Higher TLS versions provide additional security, but might not be supported by all\nbrowsers. This could result in some customers being unable to connect to your site.",
    "audit": "The Minimum TLS setting can be audited using the following mechanisms\nIBM Cloud Console\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Click Menu icon --> Resource list\n3. Select the Cloud Internet Service Instance\n4. Select the domain that needs to be audited from the domains drop down\n5. Choose the Security section from the left panel.\n6. Click on the TLS tab in the Security panel.\n7. Verify the Traffic Encryption - Minimum TLS Version is set to a value of TLS\n1.2(default) or higher\nIBM Cloud CLI\n1. Verify min_tls_version must be set to 1.2 or higher\nibmcloud cis tls-settings e476aba943b5d7d29b96135c78aa55c9 --output json\n{\n\"min_tls_version\": \"1.2\",\n\"ssl\": \"strict\",\n\"tls_1_2_only\": \"off\",\n\"tls_1_3\": \"off\",\n\"universal\": true\n}",
    "expected_response": "7. Verify the Traffic Encryption - Minimum TLS Version is set to a value of TLS\n1. Verify min_tls_version must be set to 1.2 or higher\nibmcloud cis tls-settings e476aba943b5d7d29b96135c78aa55c9 --output json",
    "remediation": "IBM Cloud Console\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Click Menu icon -- Resource list\n3. Select the Cloud Internet Service Instance that needs to be remediated from the\ndomains drop down.\n4. Choose the Security section from the left panel.\n5. Click on the TLS tab in the Security panel.\n6. Change the TLS version on Traffic Encryption - Minimum TLS Version to TLS\n1.2(default)\nIBM Cloud CLI\n1. Set min_tls_version to 1.2\nibmcloud cis tls-settings-update  <DOMAIN_ID> -i <Instance-Name> --min-\ntls-version 1.2",
    "default_value": "The default TLS mode is set to TLS1.2 for any TLS termination on Cloud Internet\nServices",
    "detection_commands": [
      "ibmcloud cis tls-settings e476aba943b5d7d29b96135c78aa55c9 --output json"
    ],
    "remediation_commands": [
      "ibmcloud cis tls-settings-update <DOMAIN_ID> -i <Instance-Name> --min-"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/cis?topic=cis-cis-tls-options",
      "2. https://cloud.ibm.com/docs/cis?topic=cis-manage-your-ibm-cis-for-optimal-",
      "security",
      "3. https://cloud.ibm.com/docs/cis?topic=cis-cli-plugin-cis-cli#waf",
      "4. https://cloud.ibm.com/docs/cis?topic=cis-cli-plugin-cis-cli#overview",
      "5. https://cloud.ibm.com/docs/cis?topic=cis-getting-started"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 158,
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
    "cis_id": "6.1.2",
    "title": "Ensure Web application firewall is ENABLED in IBM Cloud Internet Services (CIS)",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Encrypt Sensitive Data in Transit",
    "description": "A Web Application Firewall (WAF) is a security solution designed to protect web\napplications by monitoring, filtering, and blocking malicious HTTP/S (OSI Layer 7) traffic\nbetween a client (usually a browser) and a web server.\nWhat is a Web Application Firewall?\nA WAF sits between the internet and your web application, acting as a reverse proxy\nthat inspects incoming and outgoing web traffic. It uses rule-based logic, machine\nlearning, or behavioral analysis to detect and prevent common threats including the\nOWASP Top-10 attack techniques.\nA WAF may use one or more of the following detection methods:\n• Signature-based detection (matches known attack patterns)\n• Anomaly-based detection (flags behavior outside the baseline)\n• Policy-based rules (user-defined or vendor-supplied rules)\nKey benefits of a CIS WAF\nThe IBM Cloud™ Internet Services WAF is an easy way to set up, manage, and\ncustomize security rules to protect your web applications from common web threats.\nSee the following list for key features:\n• Easy setup: The CIS WAF is part of our overall service, which takes just a few\nminutes to set up. After you redirect your DNS to us, you can switch on the WAF\nand set up the rules you need.\n• Always on protection: Once CIS WAF is deployed and enabled it will protect\nagainst some of the common web application attack patterns like\no Zero-day vulnerabilities -\no Top-10 attack techniques\no Use of stolen/leaked credentials\n• Detailed reporting: See greater detail in the reporting, for example, threats\nblocked by rule/rule group.",
    "rationale": "A WAF or Web Application Firewall helps protect web applications by filtering and\nmonitoring HTTP traffic between a web application and the client on the Internet.\nTypes of attacks WAF can prevent\nA WAF typically protects web applications from attacks such as cross-site forgery,\ncross-site-scripting (XSS), file inclusion, and SQL injection, among others. A WAF\nusually is part of a suite of tools, which together can create a holistic defense against a\nrange of attack vectors.\nHow a WAF works\nWAF is a type of reverse-proxy that protects the server from exposure by having the\nclient requests pass through the WAF before reaching the server. It acts as shield\nplaced between the web application and the internet.\nA WAF operates through a set of rules often called policies. These policies aim to\nprotect against vulnerabilities in the application by filtering out malicious traffic.\nThe value of a WAF comes from the speed and ease with which its policy modifications\ncan be implemented, thereby allowing a faster response to varying attack vectors. For\nexample, for a zero-day vulnerability the WAF vendor can deploy a patch on that will\nprevent the expolitation of the vulnerability.",
    "impact": "A WAF is an OSI protocol Layer-7 defense in the OSI model, and it is not designed to\ndefend against all types of attacks. When a WAF is enabled on Cloud Internet Services\nthe TLS traffic is terminated at the proxy, unencrypted, inspected for any attacks, and\nthen re-encrypted and forwarded on to the application. Another thing to consider with\nWAF is that there may be false positives based on the application patterns and clients\nmay get blocked or challenged. This can be mitigated by tuning the WAF or creating\ncustom policies that would let traffic pass under certain conditions.",
    "audit": "The Web Application Firewall setting can be audited using the following mechanisms\nUsing Console:\n1. Login to the IBM Cloud at https://cloud.ibm.com\n2. Click Menu icon, Resource list\n3. Select the Cloud Internet Service Instance\n4. Select the domain that needs to be audited from the domains drop down\n5. Choose the Security section from the left panel.\n6. Click on the WAF tab in the Security panel.\n7. Make sure the CIS Managed Ruleset and CIS OWASP Core Ruleset are both\ndeployed and enabled\nUsing API:\n1. Run the curl command below. The value for $iam_token will be the IBM Cloud\niam token retrieved by running the command\nibmcloud iam oauth-tokens\nRequest:\ncurl -s\nhttps://api.cis.cloud.ibm.com/v1/{crn}/zones/{zoneid}/rulesets/phases/http_re\nquest_firewall_managed/entrypoint \\\n-H 'content-type: application/json' \\\n-H 'accept: application/json' \\\n-H \"x-auth-user-token: Bearer $iam_token\" | jq '.result.rules[] |\n{ruleid: .action_parameters.id, enabled: .enabled}'\nResponse:\n{\n\"ruleid\": \"efb7b8c949ac4650a09736fc376e9aee\",\n\"enabled\": true\n}\n{\n\"ruleid\": \"4814384a9e5d4991b9815dcfc25d2f1f\",\n\"enabled\": true\n}\nIn the above response rules map to the deployed ruleset ids as shown below\nCIS Managed Ruleset: efb7b8c949ac4650a09736fc376e9aee\nCIS OWASP Core Ruleset: 4814384a9e5d4991b9815dcfc25d2f1f",
    "remediation": "The Web Application Firewall can be enabled in Cloud Internet Services using the\nfollowing procedure\nUsing Console\n1. Login to the IBM Cloud at https://cloud.ibm.com\n2. Click Menu icon, Resource list\n3. Select the Cloud Internet Service Instance\n4. Select the domain that needs to be audited from the domains drop down\n5. Choose the Security section from the left panel.\n6. Click on the WAF tab in the Security panel.\n7. Deploy the following WAF managed rulesets by clicking the Deploy button next\nto them\no CIS Managed Ruleset\no CIS OWASP Core Ruleset\n8. After rulesets are deployed or if they are already deployed, make sure they are\nenabled by clicking on the toggle under the Status column.\nNote: For WAF to be inline of the request flow, the DNS records or global load\nbalancers need to have proxies enabled. Only when the records are proxied, the\ntraffic will flow through the Cloud Internet Services reverse proxy and will get\ninspected.",
    "default_value": "By default the Managed rulesets for WAF will not be deployed in Cloud Internet\nServices.",
    "additional_information": "The proxy mode for the dns record or the global load balancer must be enabled for the\ntraffic to pass through the Web Application Firewall.",
    "detection_commands": [
      "ibmcloud iam oauth-tokens",
      "curl -s"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/cis?topic=cis-manage-your-ibm-cis-for-optimal-",
      "security#best-practice-activate-waf-safely",
      "2. https://cloud.ibm.com/docs/cis?topic=cis-waf-q-and-a",
      "3. https://cloud.ibm.com/docs/cis?topic=cis-using-the-cis-security-events-capability",
      "4. https://cloud.ibm.com/docs/cis?topic=cis-getting-started"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 161,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
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
    "cis_id": "6.1.3",
    "title": "Ensure DDoS protection is Active on IBM Cloud Internet Services",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Implement Application Firewalls",
    "description": "Proxied                       true\nTTL                           30\nFallback Pool                 9f3fa92d0c7c59d96b179450aff0fc8e\nDefault Pools                 9f3fa92d0c7c59d96b179450aff0fc8e\nRegion Pools\nSession Affinity              none\nSession Affinity TTL          0\nSession Affinity Attributes\nSamesite                  Auto\nSecure                    Auto\nDrain Duration            0\nSteering Policy               off\nAvailable Pools               0/1\n• DNS Records\nibmcloud cis dns-record-update <DOMAIN_ID> <DNS_RECORD_ID> --proxied true\nUpdating DNS Record '98d434c268fd613ac28937176a8b86b5' in domain\n'681c5cf97f44e5da2f66924f5a4db5b2' for service instance 'WAF Epoch June 12th'\n...\nOK\nID            98d434c268fd613ac28937176a8b86b5\nCreated On    2024-12-13 23:37:25.43331 +0000 UTC\nModified On   2024-12-13 23:37:35.834688 +0000 UTC\nName          advanced-cert-test.batflare.com\nType          A\nContent       1.2.3.4\nDomain ID\nDomain Name\nProxied       true\nTTL           1",
    "rationale": "A distributed denial of service (DDoS) attack is a malicious attempt to disrupt normal\ntraffic of a server, service, or network by overwhelming the target or its surrounding\ninfrastructure with a flood of internet traffic. DDoS attacks achieve effectiveness by\nutilizing many compromised computer systems as sources of attack traffic. Exploited\nmachines can include computers and other networked resources such as IoT devices.\nFrom a high level, a DDoS attack is like a traffic jam clogging up a highway, preventing\nregular traffic from arriving at its destination.\nDDoS attack vectors target varying components of a network connection. While nearly\nall DDoS attacks involve overwhelming a target device or network with traffic, attacks\ncan be divided into three categories. An attacker can use one or multiple attack vectors,\nand might even cycle through these attack vectors based on countermeasures taken by\nthe target.\nCommon types are:\n• Application layer attacks (Layer 7)\n• Protocol attacks (Layer 3 and Layer 4)\n• Volumetric attacks (amplification attacks)\nApplication layer attacks An application layer attack is sometimes referred to as a\nLayer-7 DDoS attack (in reference to the 7th layer of the OSI model). The goal of these\nattacks is to exhaust the resources of the victim, by targeting the layer where web\npages are generated on the server and delivered to the visitors in response to HTTP\nrequests (that is, the application layer). Layer-7 attacks are challenging, because the\ntraffic can be difficult to identify as malicious.\nProtocol attacks Protocol attacks utilize weaknesses in Layer 3 and Layer 4 of the ISO\nprotocol stack to render the target inaccessible. These attacks, also known as a state-\nexhaustion attacks, cause a service disruption by consuming all the available state table\ncapacity of web application servers, or of intermediate resources such as firewalls and\nload balancers.\nVolumetric attacks This category of attacks attempts to create congestion by\nconsuming all available bandwidth between the target and the wider internet. Large\namounts of data are sent to a target using a form of amplification, or by other means of\ncreating massive traffic, such as requests from a botnet.",
    "impact": "Allowing proxy will route your data through the Cloud Internet Services proxy and will be\ndecrypted and inspected for layer7 DDoS attacks.",
    "audit": "The different types of mechanisms to audit if DDoS is enabled are as follows:\nUsing Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Click Menu icon, Resource list\n3. Select the Cloud Internet Service Instance\n4. Click on Reliability on the Left Navigation panel.\n5. Click on the Global Load Balancers tab.\n6. Verify each GLB indicates that proxy is enabled by the green toggle.\n7. Click on the DNS tab.\n8. Verify each DNS record indicates that proxy is enabled by the green toggle.\nUsing CLI:\nRun the following ibmcloud cli command and review the value of the proxied property\nto verify it is set to true for any global load balancers. This ensures that the traffic is\ninspected by the proxy and detect and layer 7 DDoS attacks.\nic cis glbs <DOMAIN_ID> --output JSON | jq '.[] | {Name: .name, Proxied:\n.proxied}'\n{\n\"Name\": \"tt.advanced-cert-test.batflare.com\",\n\"Proxied\": true\n}\nRun the following ibmcloud cli command and review the value of the proxied property\nto verify it is set to true for any DNS records that are proxiable (that can be proxied).\nThis ensures that the traffic is inspected by the proxy and detect and layer 7 DDoS\nattacks.\nic cis dns-records <DOMAIN_ID> --output JSON | jq '.[] | {Name: .name, Type:\n.type, Content: .content, Proxiable: .proxiable, Proxied: .proxied}'\n{\n\"Name\": \"advanced-cert-test.batflare.com\",\n\"Type\": \"A\",\n\"Content\": \"1.2.3.4\",\n\"Proxiable\": true,\n\"Proxied\": true\n}\n{\n\"Name\": \"tanya.advanced-cert-test.batflare.com\",\n\"Type\": \"A\",\n\"Content\": \"20.43.161.105\",\n\"Proxiable\": true,\n\"Proxied\": true\n}\n{\n\"Name\": \"test.advanced-cert-test.batflare.com\",\n\"Type\": \"AAAA\",\n\"Content\": \"2001:db8::2:1\",\n\"Proxiable\": true,\n\"Proxied\": true\n}\n{\n\"Name\": \"www.advanced-cert-test.batflare.com\",\n\"Type\": \"CNAME\",\n\"Content\": \"www.google.com\",\n\"Proxiable\": true,\n\"Proxied\": true\n}",
    "expected_response": "The different types of mechanisms to audit if DDoS is enabled are as follows:\n6. Verify each GLB indicates that proxy is enabled by the green toggle.\n8. Verify each DNS record indicates that proxy is enabled by the green toggle.\nto verify it is set to true for any global load balancers. This ensures that the traffic is\nic cis glbs <DOMAIN_ID> --output JSON | jq '.[] | {Name: .name, Proxied:\nto verify it is set to true for any DNS records that are proxiable (that can be proxied).\nic cis dns-records <DOMAIN_ID> --output JSON | jq '.[] | {Name: .name, Type:",
    "remediation": "The different types of mechanisms to set if DDoS is enabled are as follows:\nUsing Console:\n1. Log in to IBM Cloud at https://cloud.ibm.com.\n2. Click Menu icon, Resource list\n3. Select the Cloud Internet Service Instance\n4. Click on Reliability on the Left Navigation panel.\n5. Click on the Global Load Balancers tab.\n6. Change the toggle for the Proxied column to green.\n7. Click on the DNS tab.\n8. Change the toggle for Proxy column for the relevant DNS records to green.\nUsing CLI:\n1. Run the following ibmcloud cli commands to set the value of the proxied\nproperty to true\n• Global Load Balancer\nibmcloud cis glb-update <DNS Domain Id> <DNS GLB ID> --json '{\n\"name\": \"tt.advanced-cert-test.batflare.com\",\n\"fallback_pool\": \"9f3fa92d0c7c59d96b179450aff0fc8e\",\n\"default_pools\": [\"9f3fa92d0c7c59d96b179450aff0fc8e\"],\n\"proxied\": true\n}'\nUpdating GLB '8d9b09da038741ca319fa3ec0262bb19' in domain\n'681c5cf97f44e5da2f66924f5a4db5b2' for service instance 'WAF Epoch June 12th'\n...\nOK\nID                            8d9b09da038741ca319fa3ec0262bb19\nName                          tt.advanced-cert-test.batflare.com\nCreated On                    0001-01-01 00:00:00 +0000 UTC\nModified On                   2025-08-19 18:58:47.038104 +0000 UTC",
    "default_value": "Default value for Proxy for all DNS records and GLBs are set to disabled.",
    "detection_commands": [],
    "remediation_commands": [
      "ibmcloud cis glb-update <DNS Domain Id> <DNS GLB ID> --json '{ \"name\": \"tt.advanced-cert-test.batflare.com\", \"fallback_pool\": \"9f3fa92d0c7c59d96b179450aff0fc8e\", \"default_pools\": [\"9f3fa92d0c7c59d96b179450aff0fc8e\"], \"proxied\": true"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/cis?topic=cis-distributed-denial-of-service-ddos-",
      "attack-concepts",
      "2. https://cloud.ibm.com/docs/cis?topic=cis-manage-your-ibm-cis-for-optimal-",
      "security#best-practice-activate-waf-safely",
      "3. https://cloud.ibm.com/docs/cis?topic=cis-cis-allowlisted-ip-addresses"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 165,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
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
    "cis_id": "6.2.1",
    "title": "Ensure no VPC access control lists allow ingress from 0.0.0.0/0 to port 22",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "IBM Virtual Private Cloud (VPC)",
    "description": "VPC access control lists filter all incoming and outgoing traffic in IBM Cloud VPC. An\nACL is a built-in, virtual firewall where ACL rules control traffic to and from the subnets,\nrather than to and from the virtual servers. It is recommended that no ACL allows\nunrestricted ingress access to port 22.",
    "rationale": "Removing uncontrolled connectivity to remote console services, such as SSH, reduces\na server's exposure to risk.",
    "impact": "For updating an existing environment, care should be taken to ensure that\nadministrators currently relying on an ingress from 0.0.0.0/0 have access to ports 22\nthrough another, more restrictive, access control list.",
    "audit": "Using Console:\n1. Log in to the IBM Cloud Portal at https://cloud.ibm.com\n2. Navigate to the Infrastructure section by clicking on the Menu icon and selecting\nInfrastructure, Network, Access Control Lists\n3. For each access control list, follow these steps:\na. Click on the access control list name to view its details.\nb. In the Inbound Rules tab, examine each rule to ensure it does not contain a\nport range that includes port 22 and has a Source of ANY IP OR 0.0.0.0/0. A\nport range value of ALL or a range that includes port 22, such as 0-1024 are\ninclusive of port 22.",
    "expected_response": "b. In the Inbound Rules tab, examine each rule to ensure it does not contain a",
    "remediation": "Using Console:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com.\n2. Select the Navigation Menu, then click Infrastructure, Network, Access\ncontrol lists.\n3. For the ACL that need to be remediated, perform the following:\na. Select the access control list name.\nb. Identify the Inbound rule to be removed.\nc. Using the Options icon, select Delete.",
    "default_value": "Unless modified, the allow-all-network-acl access control list has Access set to Allow,\nprotocol set to Any, a port range of Any and a Source of 0.0.0.0/0.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/vpc?topic=vpc-using-acls"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 171,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "6.2.2",
    "title": "Ensure the default security group of every VPC restricts all traffic",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "VPC security groups provide stateful filtering of ingress/egress network traffic to Virtual\nServer. It is recommended that no security group allows unrestricted ingress access to\na Virtual Server. Unless modified, the default security group allows inbound traffic from\nall members of the group that is, all other virtual servers that are attached to this\nsecurity group.",
    "rationale": "Removing uncontrolled connectivity to a Virtual Server, reduces a server's exposure to\nrisk.",
    "impact": "For updating an existing environment, care should be taken to ensure that Virtual\nServers currently relying on ingress have the required access.",
    "audit": "Perform the following tasks to determine if the account is configured as prescribed:\nUsing Console:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com.\n2. At the Menu icon, select VPC Infrastructure, VPC Layout, Security Groups`.\n3. For the default security group, perform the following:\na. Ensure no Inbound Rule exists that allows unrequited traffic to the Virtual\nServers.",
    "expected_response": "Perform the following tasks to determine if the account is configured as prescribed:\na. Ensure no Inbound Rule exists that allows unrequited traffic to the Virtual",
    "remediation": "Using Console:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com.\n2. At the Menu icon, select VPC Infrastructure, VPC Layout, Security Groups.\n3. For the default security group, perform the following:\na. Identify the Inbound rule.\nb. Update the rule to only allow the required traffic flow.",
    "default_value": "Unless modified, the default security group allows inbound traffic from all members of\nthe group that is, all other virtual servers that are attached to this security group.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/vpc?topic=vpc-updating-the-default-security-group"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 173,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "6.2.3",
    "title": "Ensure no VPC security groups allow ingress from 0.0.0.0/0 to port 3389",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "VPC security groups provide stateful filtering of ingress/egress network traffic to Virtual\nServer Instances. It is recommended that no security group allows unrestricted ingress\naccess to port 3389.",
    "rationale": "Removing uncontrolled connectivity to remote console services, such as RDP, reduces\na server's exposure to risk.",
    "impact": "For updating an existing environment, care should be taken to ensure that\nadministrators currently relying on an ingress from 0.0.0.0/0 have access to port 3389\nthrough another, more restrictive, access control list.",
    "audit": "Perform the following tasks to determine if the account is configured as prescribed:\nUsing Console:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com.\n2. At the Menu icon, select Infrastructure, Network, Security Groups.\n3. For each security group, perform the following:\na. Select the security group name.\nb. Ensure no Inbound Rule exists that has a port range that includes port 3389\nand has a Source of 0.0.0.0/0. Note that a port range value of ANY or a port\nrange that includes port 3389, e.g. 3300-3400, are inclusive of port 3389.",
    "expected_response": "Perform the following tasks to determine if the account is configured as prescribed:\nb. Ensure no Inbound Rule exists that has a port range that includes port 3389",
    "remediation": "Using Console:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com.\n2. At the Menu icon, select Infrastructure, Network, Security Groups.\n3. For each security group, perform the following:\na. Select the access control list name.\nb. Identify the Inbound rule to be removed.\nc. Using the Options icon, select Delete.",
    "default_value": "There are no default rules in the default security group with a value of 3389.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/vpc?topic=vpc-using-acls",
      "2. https://cloud.ibm.com/docs/vpc?topic=vpc-configuring-the-security-",
      "group&interface=ui"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 175,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "6.2.4",
    "title": "Ensure no VPC security groups allow ingress from 0.0.0.0/0 to port 22",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "VPC security groups provide stateful filtering of ingress/egress network traffic to Virtual\nServers. It is recommended that no security group allows unrestricted ingress access to\nport 22.",
    "rationale": "Removing uncontrolled connectivity to remote console services, such as SSH, reduces\na server's exposure to risk.",
    "impact": "For updating an existing environment, care should be taken to ensure that\nadministrators currently relying on an ingress from 0.0.0.0/0 have access to port 22\nthrough another, more restrictive, security group.",
    "audit": "Perform the following tasks to determine if the account is configured as prescribed:\nUsing Console:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com.\n2. At the Menu icon, select Infrastructure, Network, Security Groups.\n3. For each security group, perform the following:\na. Select the security group name.\nb. Ensure no Inbound Rule exists that has a value that includes port 22 and has\na Source of 0.0.0.0/0. Note that a port range value of ANY or a port range\nthat includes port 22, e.g. 0-1024, are inclusive of port 22.",
    "expected_response": "Perform the following tasks to determine if the account is configured as prescribed:\nb. Ensure no Inbound Rule exists that has a value that includes port 22 and has",
    "remediation": "Using Console:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com.\n2. At the Menu icon, select Infrastructure, Network, Security Groups.\n3. For each security group, perform the following:\na. Select the security group name.\nb. Identify the Inbound rule to be removed.\nc. Using the Options icon, select Delete.",
    "default_value": "Unless modified, the default security group includes a rule with protocol set to TCP, a\nvalue of 22 and a Source of 0.0.0.0/0.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/vpc?topic=vpc-using-acls"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 177,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "6.2.5",
    "title": "Ensure no VPC access control lists allow ingress from 0.0.0.0/0 to port 3389",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "VPC access control lists filter all incoming and outgoing traffic in IBM Cloud VPC. An\nACL is a built-in, virtual firewall where ACL rules control traffic to and from the subnets,\nrather than to and from the virtual servers. It is recommended that no ACL allows\nunrestricted ingress access to port 3389.",
    "rationale": "Removing uncontrolled connectivity to remote console services, such as RDP, reduces\na server's exposure to risk.",
    "impact": "For updating an existing environment, care should be taken to ensure that\nadministrators currently relying on an ingress from 0.0.0.0/0 have access to port 3389\nthrough another, more restrictive, access control list.",
    "audit": "Perform the following tasks to determine if the account is configured as prescribed:\nUsing Console:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com.\n2. At the Menu icon, select Infrastructure, Network, Access Control Lists.\n3. For each access control list, perform the following:\na. Select the access control list name.\nb. Ensure no Inbound Rule exists that has a port range that includes port 3389\nand has a Source of 0.0.0.0/0. Note that a port range value of ANY or a port\nrange that includes port 3389, e.g. 3300-3400, are inclusive of port 3389.",
    "expected_response": "Perform the following tasks to determine if the account is configured as prescribed:\nb. Ensure no Inbound Rule exists that has a port range that includes port 3389",
    "remediation": "1. Login to the IBM Cloud Portal at https://cloud.ibm.com.\n2. At the Menu icon, select Infrastructure, Network, Access Control Lists.\n3. For the ACL that need to be remediated, perform the following:\na. Select the access control list name.\nb. Identify the Inbound rule to be removed.\nc. Using the Options icon, select Delete.",
    "default_value": "Unless modified, the allow-all-network-acl access control list has Access set to\nAllow, protocol set to Any, a port range of Any and a Source of 0.0.0.0/0.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/vpc?topic=vpc-using-acls"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 179,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "7.1.1",
    "title": "Ensure data in Kubernetes secrets is encrypted using a Key Management Service (KMS) provider",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "containers",
    "domain": "Containers",
    "subdomain": "IBM Cloud Kubernetes Service",
    "description": "Protect sensitive information in your IBM Cloud Kubernetes Service cluster to ensure\ndata integrity and to prevent your data from being exposed to unauthorized users.\nUnderstanding Key Management Service (KMS) providers When you enable a key\nmanagement service (KMS) provider for your cluster, you bring your own root key. The\nroot key is used to encrypt the data encryption keys (DEKs) which are then used to\nencrypt the secrets in your cluster. The root key is stored in the KMS provider instance\nthat you control. The encrypted DEKs are stored in etcd and can only be unencrypted\nusing the root key from the KMS provider.\nSupported KMS providers IBM Cloud Kubernetes Service supports the following KMS\nproviders:\n• IBM Key Protect for IBM Cloud.\n• Hyper Protect Crypto Services.\nKey Protect leverages FIPS 140-2 Level 3 certified cloud-based hardware security\nmodules. Hyper Protect Crypto Services is built on FIPS 140-2 Level 4 certified\nhardware.\nAs adding a different KMS provider requires updating the managed master default\nconfiguration, you can have only one KMS provider and key enabled in the cluster at a\ntime.",
    "rationale": "Kubernetes secrets are base64 encoded by default. You can further protect Kubernetes\nsecrets and any credentials stored in your secrets by enabling a key management\nservice (KMS) provider to encrypt secrets with encryption keys that you control.\nWhen it comes to encryption of data at rest, IBM Cloud recommend for customers to\nmanage customer root keys (CRK) that are used to protect customer data stored in data\nand storage services in IBM Cloud. With the support of Bring Your Own Key (BYOK),\ncustomers can create, store, and manage the lifecycle of their root keys to achieve full\ncontrol of other DEKs stored in the cloud.",
    "impact": "Review the following notes about cluster secret encryption.\n• Standard pricing for Key Protect and Hyper Protect Crypto Services applies.\n• Cluster secrets are encrypted by using your KMS.\n• Cluster secrets are automatically updated after rotating root keys.\n• Clusters that use the root key are viewable from the KMS provider interface.\n• Clusters automatically respond if you disable, enable, rotate, or restore root keys.\n• Disabling a root key restricts cluster functionality until you reenable the key.\n• If a deleted root key cannot be restored, the cluster becomes unusable and\nunrecoverable.\no Both Key Protect and Hyper Protect Crypto Services provide features that\nallow deleted keys to be restored for a period of time after deletion.\n• Deleting the KMS instance will delete the keys as well, making the cluster\nunstable and unrecoverable.\n• You can have only one KMS provider and key enabled in the cluster at a time.\n• You can switch the KMS provider and key.\n• You can't disable KMS provider encryption.",
    "audit": "1. To check that KMS encryption is enabled, verify that the Key Management\nService status is set to enabled in the output of the following command.\nibmcloud ks cluster get -c <cluster_name_or_ID>\n2. Log in to your account. If applicable, target the appropriate resource group. Set\nthe context for your cluster.\n3. Verify that you can list the secrets in your cluster\nkubectl get secrets --all-namespaces\n4. In your KMS instance, disable the root key that is used to encrypt your cluster.\nNote: the CRK can only be disabled from the account where it is located.\n5. Wait for the cluster to detect the change to your root key.\n6. Try to list your secrets. You will get a timeout error because you can no longer\nconnect to your cluster. If you try to set the context for your cluster by running\nibmcloud ks cluster config, the command fails.\nkubectl get secrets --all-namespaces\n7. Check that your cluster is in a warning state. Your cluster remains in this state\nand is unusable until you enable your root key again.\nibmcloud ks cluster get -c <cluster_name_or_ID>\n8. In your KMS instance, enable the root key so that your cluster returns to a\nnormal state and becomes usable again.",
    "expected_response": "1. To check that KMS encryption is enabled, verify that the Key Management\nService status is set to enabled in the output of the following command.\n8. In your KMS instance, enable the root key so that your cluster returns to a",
    "remediation": "Using Console:\nThe following remediation steps assume you are not using cross account KMS\nencryption.\n1. Create a KMS instance and root key.\n2. Log in to the IBM Cloud console.\n3. To view a list of your resources, go to Menu, Containers, Clusters.\n4. From the Clusters page, select your cluster.\n5. In the Cluster details section, under Cluster encryption click Enable. If you\nalready enabled the KMS provider, click Update.\n6. Select the Root key that you want to use for the encryption, by KMS instance or\nRoot key CRN.\n7. Click Enable (or Update).\n8. Verify that the KMS enablement process is finished. The process is finished\nwhen that the Master Status is Ready and Key management service is\nenabled.\n9. After the KMS provider is enabled in the cluster, all cluster secrets are\nautomatically encrypted.\nUsing Command Line:\nThe following remediation steps assume you are not using cross account KMS\nencryption.\n1. Create a KMS instance and root key.\n2. Obtain the ID of the KMS instance that you previously created.\nibmcloud ks kms instance ls\n3. Get the ID of the root key that you previously created.\nibmcloud ks kms crk ls --instance-id <KMS_instance_ID>\n4. Enable the KMS provider to encrypt secrets in your cluster. Complete the options\nwith the information that you previously retrieved. The KMS provider's private\ncloud service endpoint is used by default to download the encryption keys. To\nuse the public cloud service endpoint instead, include the --public-endpoint\noption. The enablement process can take some time to complete.\nibmcloud ks kms enable -c <cluster_name_or_ID> --instance-id\n<kms_instance_ID> --crk <root_key_ID> [--public-endpoint]\n5. Verify that the KMS enablement process is finished. The process is finished\nwhen that the Master Status is Ready and Key management service is\nenabled.\n6. After the KMS provider is enabled in the cluster, all cluster secrets are\nautomatically encrypted.",
    "default_value": "Kubernetes secrets are base64 encoded but not encrypted.",
    "detection_commands": [
      "ibmcloud ks cluster get -c <cluster_name_or_ID>",
      "kubectl get secrets --all-namespaces",
      "ibmcloud ks cluster config, the command fails. kubectl get secrets --all-namespaces"
    ],
    "remediation_commands": [
      "ibmcloud ks kms instance ls",
      "ibmcloud ks kms crk ls --instance-id <KMS_instance_ID>",
      "use the public cloud service endpoint instead, include the --public-endpoint",
      "ibmcloud ks kms enable -c <cluster_name_or_ID> --instance-id"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/containers?topic=containers-encryption-secrets",
      "2. https://cloud.ibm.com/docs/containers?topic=containers-encryption#cluster-",
      "secret-encryption",
      "3. https://cloud.ibm.com/docs/key-protect",
      "4. https://cloud.ibm.com/catalog/services/key-protect",
      "5. https://cloud.ibm.com/docs/hs-crypto",
      "6. https://cloud.ibm.com/catalog/services/hyper-protect-crypto-services"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 183,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification",
      "key_management"
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
    "cis_id": "7.1.2",
    "title": "Ensure TLS 1.2+ for all inbound traffic at IBM Cloud Kubernetes Service Ingress",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "containers",
    "domain": "Containers",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "Ensure that all insecure (HTTP) client requests to applications and services hosted on\nIBM Cloud Kubernetes Service are redirected to secure TLS connections (HTTPS) and\nensure that only TLS versions 1.2+ are supported.\nYou set up Ingress application load balancers (ALBs) in your cluster to secure your\ndomain with the IBM-provided TLS certificate or your custom TLS certificate. Some\nusers might try to access your apps by using an insecure http request to your ALB\ndomain, for example http://www.myingress.com, instead of using https.",
    "rationale": "Hypertext transfer protocol secure (HTTPS) is the secure version of HTTP and uses the\nTransport Layer Security (TLS) protocol to provide a secure, encrypted connection\nbetween the client and the server. This protocol encrypts communication to protect\nusers from attack, for example, man in the middle attacks.\nIBM Cloud Kubernetes Service provides configuration options that redirect HTTP\nrequests to HTTPS, and it is highly recommended to enable this. If you do not use this\nconfiguration, insecure HTTP requests are not converted into HTTPS requests by\ndefault and might expose unencrypted confidential information to the public.",
    "impact": "Incoming requests will not be able to use HTTP because all requests will be redirected\nto HTTPS. Legacy clients that require TLS 1.0 or 1.1 support will not be able to access\nyour applications.",
    "audit": "1. Obtain the configuration for the ibm-k8s-controller-config ConfigMap resource.\nkubectl get cm ibm-k8s-controller-config -n kube-system -o yaml\n2. In the data section, ensure that the ssl-protocols key is not present, or if it is\npresent, ensure that it only includes TLSv1.2 and/or TLSv1.3.\n3. In the data section, ensure that the ssl-redirect key is present and is set to\ntrue.\napiVersion: v1\ndata:\nssl-protocols: \"TLSv1.2 TLSv1.3\"\nssl-redirect: “true”\nkind: ConfigMap\nmetadata:\nname: ibm-k8s-controller-config\nnamespace: kube-system\n4. Obtain the configuration for your Ingress resource by running the following\ncommand:\nkubectl get ingress <my_ingress> -n <my_namespace> -o yaml\n5. In the annotations section, ensure that the\nnginx.ingress.kubernetes.io/ssl-redirect key is present and is set to\ntrue.\napiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\nname: myingress\nannotations:\nnginx.ingress.kubernetes.io/ssl-redirect: \"true\"\nspec:\ntls:\n- hosts:\n- myhost\nsecretName: mytlssecret\nrules:\n- host: myhost\nhttp:\npaths:\n- backend:\nservice:\nname: myservice\nport:\nnumber: 8080\npath: /",
    "expected_response": "2. In the data section, ensure that the ssl-protocols key is not present, or if it is\npresent, ensure that it only includes TLSv1.2 and/or TLSv1.3.\n3. In the data section, ensure that the ssl-redirect key is present and is set to\n5. In the annotations section, ensure that the\nnginx.ingress.kubernetes.io/ssl-redirect key is present and is set to",
    "remediation": "1. Edit the configuration file for the ibm-k8s-controller-config ConfigMap\nresource by running the following command:\nkubectl edit cm ibm-k8s-controller-config -n kube-system\n2. In the data section, remove the ssl-protocols key, or ensure it is set to ssl-\nprotocols: \"TLSv1.2 TLSv1.3\".\n3. In the data section, add ssl-redirect: \"true\".\napiVersion: v1\ndata:\nssl-protocols: \"TLSv1.2 TLSv1.3\"\nssl-redirect: “true”\nkind: ConfigMap\nmetadata:\nname: ibm-k8s-controller-config\nnamespace: kube-system\n4. Edit the configuration for your Ingress resource by running the following\ncommand:\nkubectl edit ingress <my_ingress> -n <my_namespace>\n5. In the annotations section, add nginx.ingress.kubernetes.io/ssl-\nredirect: \"true\".\napiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\nname: myingress\nannotations:\nnginx.ingress.kubernetes.io/ssl-redirect: \"true\"\nspec:\ntls:\n- hosts:\n- myhost\nsecretName: mytlssecret\nrules:\n- host: myhost\nhttp:\npaths:\n- backend:\nservice:\nname: myservice\nport:\nnumber: 8080\npath: /",
    "default_value": "The default setting supports only TLS 1.2 and 1.3 for HTTPS. Redirecting HTTP\nrequests to HTTPS is disabled by default.",
    "detection_commands": [
      "kubectl get cm ibm-k8s-controller-config -n kube-system -o yaml",
      "kubectl get ingress <my_ingress> -n <my_namespace> -o yaml"
    ],
    "remediation_commands": [
      "kubectl edit cm ibm-k8s-controller-config -n kube-system",
      "kubectl edit ingress <my_ingress> -n <my_namespace>"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/containers?topic=containers-encryption#keyprotect",
      "2. https://cloud.ibm.com/docs/hs-crypto"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 187,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "7.1.3",
    "title": "Ensure IBM Cloud Kubernetes Service worker nodes are updated to the latest version to ensure patching of vulnerabilities",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "containers",
    "domain": "Containers",
    "subdomain": "Encrypt Sensitive Data in Transit",
    "description": "Update the worker nodes in a cluster to the latest patch version so that security fixes\nare applied to those worker nodes.",
    "rationale": "As security updates and patches are put in place for the API server and other master\ncomponents, you must be sure that the worker nodes remain in sync. You can make\ntwo types of updates: updating only the patch version, or updating the major.minor\nversion with the patch version. This benchmark is only in relation to updating the patch\nversion, not the major or minor versions. Updating the patch version in a timely manner\nensures patching of known vulnerabilities and will keep your worker nodes more secure.",
    "impact": "The worker node update also updates the worker node to the same major.minor\nversion as the master if a major.minor update is also available.",
    "audit": "Using Console:\n1. Log in to the IBM Cloud console.\n2. To view a list of your clusters, go to Menu, Containers, Clusters.\n3. From the Clusters page, select your cluster.\n4. Select the Worker Nodes tab.\n5. For each listed worker node, ensure that next to the Version no information icon\nis present indicating that an update is available. If there is an information icon\nindicating there is an update available, then the worker node is not running the\nlatest available image.\nUsing Command Line:\n1. List the clusters in your IBM Cloud account\nibmcloud ks cluster ls\n2. List the workers for a given cluster.\nibmcloud ks workers -c <cluster_name_or_ID>\n3. Ensure that next to the version for a worker node no asterisk (*) is present\nindicating that an update is available.\nHere is an example output for a VPC cluster that shows that there is an available\nupdate for a worker node:\nibmcloud ks worker -c mykubecluster\nOK\nID                                                       Primary IP\nFlavor         State    Status   Zone       Version         Operating System\nkube- btdsgk5d0t1lpluh7f40-mykubeclust-default-000000d1      12.345.678.90\ngx3.16x80.l4   normal   Ready    ca-tor-3   1.31.11_1559*   UBUNTU_24_64\n* To update to 1.31.11_1560 version, run 'ibmcloud ks worker replace'. Review\nand make any required version changes before you update:\n'https://ibm.biz/upworker'",
    "expected_response": "5. For each listed worker node, ensure that next to the Version no information icon\nis present indicating that an update is available. If there is an information icon\n3. Ensure that next to the version for a worker node no asterisk (*) is present\nHere is an example output for a VPC cluster that shows that there is an available",
    "remediation": "Using Console:\n1. Complete the prerequisite steps for VPC worker nodes.\n2. Log in to the IBM Cloud console.\n3. Optional: Add capacity to your cluster by resizing the worker pool. The pods on\nthe worker node can be rescheduled and continue running on the added worker\nnodes during the update.\n4. To view a list of your clusters, go to Menu, Containers, Clusters.\n5. From the clusters page, select your cluster.\n6. Select the Worker Nodes tab.\n7. Select the checkbox for each worker node that you want to update. An action bar\nis displayed over the table header row.\n8. From the action bar, click Update.\nUsing Command Line:\n1. Complete the prerequisite steps for VPC worker nodes.\n2. Optional: Add capacity to your cluster by resizing the worker pool. The pods on\nthe worker node can be rescheduled and continue running on the added worker\nnodes during the update.\n3. List the worker nodes in your cluster and note the note the details of the worker\nnode that you want to update.\nibmcloud ks worker ls --cluster <cluster_name_or_ID>\n4. Replace the worker node to update the worker node to the latest patch version at\nthe same major.minor version (such as from 1.31.8_1530 to 1.31.9_1533)..\nibmcloud ks worker replace --cluster <cluster_name_or_ID> --worker\n<worker_node_ID>\nUsing the --update option will update the VPC worker node to the same major.minor\nversion as the master (such as from 1.31 to 1.32).\nibmcloud ks worker replace --cluster <cluster_name_or_ID> --worker\n<worker_node_ID> --update\n5. Repeat these steps for each worker node that you want to update.\n6. Optional: After the replaced worker nodes are in a Ready status, resize the\nworker pool to meet the cluster capacity that you want.",
    "default_value": "Worker nodes are not updated unless the user initiates an update.",
    "detection_commands": [
      "ibmcloud ks cluster ls",
      "ibmcloud ks workers -c <cluster_name_or_ID>",
      "ibmcloud ks worker -c mykubecluster"
    ],
    "remediation_commands": [
      "ibmcloud ks worker ls --cluster <cluster_name_or_ID>",
      "ibmcloud ks worker replace --cluster <cluster_name_or_ID> --worker"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/containers?topic=containers-",
      "update&#vpc_worker_node",
      "2. https://cloud.ibm.com/docs/containers?topic=containers-",
      "cs_versions#update_types"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 191,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "7.1.4",
    "title": "Ensure IBM Cloud Kubernetes Service cluster has image pull secrets enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "containers",
    "domain": "Containers",
    "subdomain": "Only Use Up-to-date And Trusted Third-Party",
    "description": "To pull container images from a registry, your IBM Cloud Kubernetes Service cluster\nuses a special type of Kubernetes secret - an imagePullSecret. This image pull secret\nstores the credentials to access a container registry.\nBy default, your cluster is set up to pull images from only your account's namespaces in\nIBM Cloud Container Registry and deploy containers from these images to the default\nKubernetes namespace in your cluster.",
    "rationale": "IBM Cloud Kubernetes Service clusters pull container images from container registries\nto run containers. If the registry is private, the cluster needs credentials to pull images\nfrom it. Because IBM Cloud Kubernetes Service and IBM Cloud Container Registry are\noften used in tandem, it is important to have image pull secrets for IBM Cloud Container\nRegistry enabled in your cluster.",
    "impact": "Pull secrets are created in the default namespace of your cluster. If you want to pull\nimages to other Kubernetes namespaces, then you must copy the pull secrets to those\nother namespaces.",
    "audit": "1. Login to your VPC cluster and check the image pull secrets by running:\nkubectl get secrets -n default | grep \"icr-io\"\n2. As image pull secrets are automatically added to clusters at creation time, if no\nicr secrets are listed, the person who created the cluster might not have had the\nrequired permissions to IBM Cloud Container Registry.",
    "remediation": "1. Run the following command to create an IBM Cloud IAM service ID for the\ncluster, create a policy for the service ID that assigns the Reader service access\nrole in IBM Cloud Container Registry, and then create an API key for the service\nID. The API key is then stored in a Kubernetes image pull secret.\nNote: This process happens automatically when you create a cluster, but sometimes\nerrors can occur during the cluster creation process.\nibmcloud ks cluster pull-secret apply --cluster <cluster_name_or_ID>\n2. Verify that the image pull secrets are created in your cluster.\nkubectl get secrets | grep icr-io",
    "default_value": "Image pull secrets are enabled by default unless the user that created the cluster did\nnot have the required permissions for IBM Cloud Container Registry in IAM. Clusters\ncreated before 25 February 2019 have token-based image pull secrets rather than API\nkey-based image pull secrets, and therefore must be updated.",
    "detection_commands": [
      "kubectl get secrets -n default | grep \"icr-io\""
    ],
    "remediation_commands": [
      "ibmcloud ks cluster pull-secret apply --cluster <cluster_name_or_ID>",
      "kubectl get secrets | grep icr-io"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/containers?topic=containers-",
      "registry#imagePullSecret_migrate_api_key",
      "2. https://cloud.ibm.com/docs/containers?topic=containers-",
      "registry#cluster_registry_auth"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 194,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2"
    ]
  },
  {
    "cis_id": "7.1.5",
    "title": "Ensure IBM Cloud Kubernetes Service clusters have the monitoring service enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "containers",
    "domain": "Containers",
    "subdomain": "Deploy System Configuration Management Tools",
    "description": "The following recommendation should be considered optional, as while adhering\nto it would provide enhanced security, IBM Cloud Monitoring is a costed\noption.\nIBM Cloud services, such as IBM Cloud Kubernetes Service, generate platform metrics\nthat you can use to gain operational visibility into the performance and health of the\nservice in your account.\nEvery Kubernetes master is continuously monitored by the IBM Cloud Kubernetes\nService; however, you are responsible for monitoring the rest of your cluster\ncomponents.\nIBM Cloud Monitoring is a cloud-native, container-intelligence management system that\ncan be included as part of your IBM Cloud architecture. It offers administrators, DevOps\nteams, and developers full-stack telemetry with advanced features to monitor and\ntroubleshoot, define alerts, and design custom dashboards.\nWith IBM Cloud Monitoring, by deploying a monitoring agent to your worker nodes you\ncan collect cluster and pod metrics, such as the CPU and memory usage of your worker\nnodes, incoming and outgoing HTTP traffic for your pods, and data about several\ninfrastructure components. In addition, the agent can collect custom application metrics\nby using either a Prometheus-compatible scraper or a StatsD facade.",
    "rationale": "Gaining operational visibility into the performance and health of your applications and\nclusters not only helps you maintain operational continuity but can also act as an early\nwarning system for anomalies caused by security incidents. Monitoring can also help\nidentify patterns of unexpected activity on your applications and clusters, which in turn\nprovide indicators of compromise.\nIBM Cloud Monitoring includes alerts and multi-channel notifications that you can use to\naccelerate your reaction and response time to anomalies, downtime, and performance\ndegradation.",
    "impact": "While adhering to this recommendation would provide enhanced security, IBM Cloud\nMonitoring is a costed option. Standard pricing for IBM Cloud Monitoring applies.",
    "audit": "From Console:\n1. Log in to the IBM Cloud console.\n2. To view a list of your clusters, go to Menu, Containers, Clusters.\n3. From the Clusters page, select your cluster.\n4. Select the Overview tab\n5. Under Integrations, the Monitoring item should have a button to Launch the\nIBM Cloud Monitoring dashboard. If instead the button is labelled Connect, then\nCloud Monitoring is not enabled.\nFrom Command Line:\n1. Verify the status of the monitoring agent in your cluster. You should see one or\nmore running sysdig-agent pods, with the number of sysdig-agent pods\nequal to the number of worker nodes in your cluster.\nkubectl get pods -n ibm-observe",
    "expected_response": "5. Under Integrations, the Monitoring item should have a button to Launch the\n1. Verify the status of the monitoring agent in your cluster. You should see one or\nequal to the number of worker nodes in your cluster.",
    "remediation": "From Console:\n1. Log in to the IBM Cloud console.\n2. To view a list of your clusters, go to Menu, Containers, Clusters.\n3. From the Clusters page, select your cluster.\n4. Select the Overview tab\n5. Under Integrations, go to the Monitoring item and click Connect.\n6. Select the Monitoring checkbox and select the IBM Cloud Monitoring instance\nthat you want to use (or create a new instance). Click Save.\nFrom Command Line:\n1. If required, provision an IBM Cloud Monitoring instance.\n2. Obtain the access key for the monitoring instance.\nibmcloud resource service-key APIKEY_NAME\n3. Obtain the ingestion URL from the IBM Cloud Monitoring collector endpoints.\n4. If the ibm-observe namespace is not available in your cluster, create it with:\nkubectl create namespace ibm-observe\n5. Add the Sysdig helm repository.\nhelm repo add sysdig https://charts.sysdig.com\n6. Update the repos to retrieve the latest versions of all Helm charts.\nhelm repo update\n7. Verify the Helm chart sysdig/sysdig-deploy is listed when listing the helm\ncharts for the sysdig repo.\nhelm search repo sysdig\n8. Define a yaml file and include the values to deploy the IBM Cloud Monitoring\nagent. The following yaml is a template that you can use, updating the fields as\nappropriate. More details available here.\nglobal:\nclusterConfig:\nname: CLUSTER_NAME\nsysdig:\naccessKey: SERVICE_ACCESS_KEY\nagent:\ncollectorSettings:\ncollectorHost: INGESTION_ENDPOINT\nnodeAnalyzer:\nenabled: false\n9. Run the following command to install the agent by using the Helm chart and the\nvariables yaml file.\nhelm install -n ibm-observe sysdig-agent sysdig/sysdig-deploy -f <agent-\nvalues yaml file>\n10. Verify that the monitoring agent is created successfully.\nkubectl get pods -n ibm-observe",
    "default_value": "IBM Cloud Monitoring is not enabled by default.",
    "detection_commands": [
      "kubectl get pods -n ibm-observe"
    ],
    "remediation_commands": [
      "ibmcloud resource service-key APIKEY_NAME",
      "kubectl create namespace ibm-observe",
      "kubectl get pods -n ibm-observe"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/containers?topic=containers-monitoring",
      "2. https://cloud.ibm.com/docs/monitoring?topic=monitoring-kubernetes_cluster",
      "3. https://cloud.ibm.com/docs/monitoring?topic=monitoring-agent-deploy-kube-helm",
      "4. https://cloud.ibm.com/observability/catalog/ibm-cloud-monitoring"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 196,
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
    "cis_id": "7.1.6",
    "title": "Ensure IBM Cloud Kubernetes Service clusters have the logging service enabled",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "containers",
    "domain": "Containers",
    "subdomain": "Deploy SIEM or Log Analytic tool",
    "description": "The following recommendation should be considered optional, as while adhering\nto it would provide enhanced security, IBM Cloud Logs is a costed option.\nBy default, logs are generated and written locally for all the following IBM Cloud\nKubernetes Service cluster components: worker nodes, containers, applications,\npersistent storage, Ingress application load balancer, Kubernetes API, and the kube-\nsystem namespace.\nIBM Cloud Logs supports integration with common workload environments on IBM\nCloud - including IBM Cloud Kubernetes Service - and provides observability services\nso you can view, analyze, and alert on activity tracking events and logging activity.\nA logging agent collects logs with the extension *.log and extensionless files that are\nstored in the /var/log/containers directory of your pod from all namespaces,\nincluding kube-system. The agent then forwards the logs to your service IBM Cloud\nLogs instance. You can also track user-initiated administrative activity made in your\ncluster. Kubernetes Service automatically generates cluster management events and\nforwards these event logs to IBM Cloud Logs.",
    "rationale": "Logging is the foundation on which security monitoring and situational awareness are\nbuilt, as logging is pivotal in identifying - and thus addressing - security risks. This is\nbecause logs record a richness of data about activity, changes, requests, interactions,\nconnections, etc. In addition, logging data can be used to investigate performance\nissues, provide administrative alerts, and help verify that organisational policies are\nworking as intended.\nHowever, as workloads generate an expanding amount of observability data, pressure\nis increasing on collection tools to process it all. The data becomes expensive to\nmanage and makes it harder to detect signal in the noise and obtain actionable insights.\nIBM Cloud Logs is designed to help users take control of their observability data and\nexpedite insights to reduce application downtime, recover quickly from incidents, and\ndevelop your defences.",
    "impact": "While adhering to this recommendation would provide enhanced security, IBM Cloud\nLogs is a costed option. Standard pricing for IBM Cloud Logs applies.",
    "audit": "From Console:\n1. Log in to the IBM Cloud console.\n2. To view a list of your clusters, go to Menu, Containers, Clusters.\n3. From the Clusters page, select your cluster.\n4. Select the Overview tab\n5. Under Integrations, the Logging item should have a button to Launch the IBM\nCloud Log dashboard. If instead the button is labelled Connect, then logging is\nnot enabled.\nFrom Command Line:\n1. Check that a daemonset logs-agent exists in the namespace ibm-observe.\nkubectl get ds -n ibm-observe\n2. Verify the log agents are started.\nkubectl -n ibm-observe get ds logs-agent\n3. Verify that a logs-agent pod is ready for each node in your cluster.\nkubectl get pods -n ibm-observe -o wide\n4. Optionally: view the logs of a pod.\nkubectl logs <POD_NAME>> -n ibm-observe",
    "expected_response": "5. Under Integrations, the Logging item should have a button to Launch the IBM",
    "remediation": "From Console:\n1. Log in to the IBM Cloud console.\n2. To view a list of your clusters, go to Menu, Containers, Clusters.\n3. From the Clusters page, select your cluster.\n4. Select the Overview tab\n5. Under Integrations, go to the Logging item and click Connect.\n6. Select the IBM Cloud Logs instance that you want to use (or create a new\ninstance). Click Connect.\nFrom Command Line:\nThe following steps deploy the agent using a service ID API key. You can also deploy\nthe agent using a trusted profile. For more information, see Deploying the Logging\nagent for Kubernetes clusters using a Helm chart.\n1. If required, follow the steps at create some buckets to store your data to create\nnew IBM Cloud Object Storage buckets.\n2. If required, follow the steps in provisioning an instance to set up an IBM Cloud\nLogs instance.\n3. Create a service ID.\nibmcloud iam service-id-create kubernetes-logs-agent --description \"Service\nID for sending logs from IKS\"\n4. Grant the Sender role for IBM Cloud Logs to the created service ID.\nibmcloud iam service-policy-create kubernetes-logs-agent --service-name logs\n--roles Sender\n5. Create an IAM API key by running the following command. You can customize\nthe key name (kubernetes-logs-agent-apikey) and description (--d) if\nneeded.\nibmcloud iam service-api-key-create kubernetes-logs-agent-apikey kubernetes-\nlogs-agent --description \"API key for sending logs to the IBM Cloud Logs\nservice\"\n6. Determine the logging ingestion endpoint for your IBM Cloud Logs instance.\nibmcloud resource service-instances --service-name logs --long --output JSON\n| jq '[.[] | {name: .name, id: .id, region: .region_id, ingestion_endpoint:\n.extensions.external_ingress}]'\n7. Define a yaml file and include the values to deploy the IBM Cloud Logs agent\ndaemonset. The following yaml is a template that you can use, updating the\nfields as appropriate. More details available here.\nmetadata:\nname: \"logs-agent\"\nimage:\nversion: \"1.6.1\"  # required\nclusterName: \"ENTER_CLUSTER_NAME\" # Enter the name of your cluster. This\ninformation is used to improve the metadata and help with your filtering.\nenv:\n# ingestionHost is a required field. For example:\n# ingestionHost: \"<logs instance>.ingress.us-east.logs.cloud.ibm.com\"\ningestionHost: \"\" # required\n# If you are using private CSE proxy, then use port number \"3443\"\n# If you are using private VPE Gateway, then use port number \"443\"\n# If you are using the public endpoint, then use port number \"443\"\ningestionPort: \"\" # required\niamMode: \"\"\n# trustedProfileID - trusted profile id - required for iam trusted profile\nmode\ntrustedProfileID: \"Profile-yyyyyyyy-xxxx-xxxx-yyyy-zzzzzzzzzzzz\" # required\nif iamMode is set to TrustedProfile\n8. Log in to the cluster. For more information, see access your cluster.\n9. Perform a Helm dry run to see the resources that will be created by the Helm\nchart. If you are using the iamMode=IAMAPIKey then the complete command is:\nhelm install <install-name> --dry-run oci://icr.io/ibm-observe/logs-agent-\nhelm --version <chart-version> --values <PATH>/logs-values.yaml -n ibm-\nobserve --create-namespace --set secret.iamAPIKey=<APIKey-value> --hide-\nsecret\n10. Once the resources to be created are verified, then run the Helm install without\nthe --dry-run option. If you are using the iamMode=IAMAPIKey then the complete\ncommand is:\nhelm install <install-name> oci://icr.io/ibm-observe/logs-agent-helm --\nversion <chart-version> --values <PATH>/logs-values.yaml -n ibm-observe --\ncreate-namespace --set secret.iamAPIKey=<APIKey-value>\n11. Verify the log agents are started.\nkubectl -n ibm-observe get ds logs-agent\n12. Verify that a logs-agent pod is ready for each node in your cluster.\nkubectl get pods -n ibm-observe -o wide\n13. Go to the web UI for your IBM Cloud Logs instance and verify logs are being\ndelivered to your target destination by querying for log records tagged with\nkubernetes.cluster_name:<CLUSTER_NAME>.",
    "default_value": "By default, logs are generated and written locally for all the following IBM Cloud\nKubernetes Service cluster components: worker nodes, containers, applications,\npersistent storage, Ingress application load balancer, Kubernetes API, and the kube-\nsystem namespace.\nHowever, by default the logging service for collecting, forwarding, and viewing these\nlogs to IBM Cloud Logs is not enabled for IBM Cloud Kubernetes Service clusters.",
    "detection_commands": [
      "kubectl get ds -n ibm-observe",
      "kubectl -n ibm-observe get ds logs-agent",
      "kubectl get pods -n ibm-observe -o wide",
      "kubectl logs <POD_NAME>> -n ibm-observe"
    ],
    "remediation_commands": [
      "ibmcloud iam service-id-create kubernetes-logs-agent --description \"Service",
      "ibmcloud iam service-policy-create kubernetes-logs-agent --service-name logs --roles Sender",
      "ibmcloud iam service-api-key-create kubernetes-logs-agent-apikey kubernetes-",
      "ibmcloud resource service-instances --service-name logs --long --output JSON | jq '[.[] | {name: .name, id: .id, region: .region_id, ingestion_endpoint:",
      "create-namespace --set secret.iamAPIKey=<APIKey-value>",
      "kubectl -n ibm-observe get ds logs-agent",
      "kubectl get pods -n ibm-observe -o wide"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/containers?topic=containers-logging",
      "2. https://cloud.ibm.com/docs/cloud-logs?topic=cloud-logs-agent-helm-kube-deploy",
      "3. https://cloud.ibm.com/catalog/services/cloud-logs"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 200,
    "dspm_relevant": true,
    "dspm_categories": [
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "8.1.1.1",
    "title": "Ensure IBM Key Protect has automated rotation for customer managed keys enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "security_compliance",
    "domain": "Security and Compliance",
    "subdomain": "Key Management",
    "description": "IBM® Key Protect for IBM Cloud® allows you to rotate your root key (CRK) which is the\nkey material created within the KMS Hardware Security Module (HSM) when you\ncreated the root key using KP APIs. This CRK is used to encrypt the Data Encryption\nKey (DEK) that is used to encrypt your data. By encrypting the DEK (wDEK), wDEK can\nbe stored with the data.\nIt is a best practice to rotate your CRK (that is, to create a new version of the key) on a\nregular basis. Regular rotations reduce what is known as the \"cryptoperiod\" of the key\nand can also be used in specific cases such as personnel turnover, process\nmalfunctions, or the detection of a security issue.\nYou can set a rotation interval on the CRK or manually rotate the CRK based on your\norganization policy.\nWhen it's time to rotate the key based on the rotation interval that you specify, Key\nProtect automatically creates a new root key in the HSM. Automated key rotation\ncurrently retains all prior CRK key versions so that only decryption of encrypted data\nwith the older version of the CRK can take place transparently.\nFrequency of key rotation After you generate a root key in Key Protect, you decide the\nfrequency of its rotation. You might want to rotate your keys due to personnel turnover,\nprocess malfunction, or according to your organization's internal key expiration policy.\nRotate your keys regularly, for example every 30 days, to meet cryptographic best\npractices.",
    "rationale": "Rotating keys on a regular basis helps you meet industry standards and cryptographic\nbest practices. The following describes the main benefits of key rotation:\n• Cryptoperiod management for keys - Key rotation limits how long your\ninformation is protected by a single key. By rotating your root keys at regular\nintervals, you also shorten the cryptoperiod of the keys. The longer the lifetime of\nan encryption key, the higher the probability for a security breach.\n• Incident mitigation - If your organization detects a security issue, you can\nimmediately rotate the key to mitigate or reduce costs that are associated with\nkey compromise.",
    "impact": "After CRK is rotated, to secure your envelope encryption workflow, rewrap your DEKs\nafter you rotate a root key so that your at-rest data is protected by the newest root key.\nAlternatively, if Key Protect detects that you're using retired key versions to unwrap a\nDEK, the service automatically re-encrypts the DEK and returns a wrapped data\nencryption key (WDEK) that's based on the latest root key.",
    "audit": "Using Console:\n1. Log in to the IBM Cloud® console.\n2. Go to Menu, Resource List to view a list of your resources.\n3. From your IBM Cloud resource list, click on Security select your provisioned\ninstance of Key Protect.\n4. On the left-hand panel, click on Policies and view the rotation policy\nenabled for the instance\n5. If the rotation policy is not enabled, you can view rotation policy set per key by\nclicking keys on the left-hand panel\n6. From the list of keys displayed, you can click on overflow menu (three dots) at\nthe end of the key to view the rotation policy for the key\nUsing API:\nYou can view automatic rotation policy using GET call to the following endpoint.\nhttps://<region>.kms.cloud.ibm.com/api/v2/keys/{id}/policies\nAPI: For a high-level view, you can browse the rotation policies that are associated with\na key by making a GET call to the following endpoint.\nhttps://<region>.kms.cloud.ibm.com/api/v2/keys/<key_ID>/policies\n1. Retrieve your service and authentication credentials.\n2. Retrieve the rotation policy for a specified key by running the following cURL\ncommand.\n$ curl -X GET \\\n\"https://<region>.kms.cloud.ibm.com/api/v2/keys/<key_ID>/policies\" \\\n-H \"authorization: Bearer <IAM_token>\" \\\n-H \"bluemix-instance: <instance_ID>\" \\\n-H \"content-type: application/vnd.ibm.kms.policy+json\" \\ -H \"correlation-id:\n<correlation_ID>\"",
    "remediation": "Using Console:\n1. Log in to the IBM Cloud console.\n2. Go to Menu, Resource List to view a list of your resources.\n3. From your IBM Cloud resource list, select your provisioned instance of Key\nProtect.\n4. On the application details page, use the Keys table to browse the keys in your\nservice. If you have many keys, you can narrow your search by using the search\nbars to only search for enabled keys (since other kinds of keys cannot be\nrotated), keys in a particular key ring, and keys with a particular alias.\n5. Once the key has been found, click the overflow menu (three dots) to open a list\nof options for the key that you want to rotate.\n6. From the options menu, click Rotate to open the Rotation side panel.\n7. If your rotation policy is Enabled, you can edit this policy by changing the number\nof months selected. This will set the 30-day interval for your root key. If a key is\nset to be rotated every 2 months, for example, it will be rotated every 60 days,\nregardless of the number of days in a particular month. If your rotation policy is\nDisabled, and the key was created at a time when your instance had a rotation\npolicy, a rotation interval number can be seen. This is the rotation policy that was\nwritten to your key in a Disabled state at key creation time. You can also change\nthe rotation interval at this time.\n8. Click Set policy. The policy is now in effect.\nIf you want to rotate the key immediately, click Rotate key. Note: these actions\nare not mutually exclusive. If your key has an existing rotation policy, the\ninterface displays the key's existing rotation period.\nUsing API:\nCreate or update a rotation policy for your root key by making a PUT call to the following\nendpoint. https://<region>.kms.cloud.ibm.com/api/v2/keys/<key_ID>/policies\nCreate or update a rotation policy for a specified key by running the following cURL\ncommand.\ncurl -X PUT\nhttps://<region>.kms.cloud.ibm.com/api/v2/keys/<key_ID_or_alias>/policies   -\nH 'authorization: Bearer <IAM_token>'   -H 'bluemix-instance: <instance_ID>'\n-H 'content-type: application/vnd.ibm.kms.policy+json'   -d '{\n\"metadata\": {\n\"collectionType\": \"application/vnd.ibm.kms.policy+json\",\n\"collectionTotal\": 2\n},\n\"resources\": [\n{\n\"type\": \"application/vnd.ibm.kms.policy+json\",\n\"rotation\": {\n\"enabled\": <true|false>,\n\"interval_month\": <rotation_interval>\n}\n},\n{\n\"type\": \"application/vnd.ibm.kms.policy+json\",\n\"dualAuthDelete\": {\n\"enabled\": <true|false>\n}\n}\n]\n}'",
    "default_value": "By default, IBM Cloud accounts depend on the account admin or Key Management\nadmin to set key rotation policy.",
    "additional_information": "Check whether Key Protect encryption keys are rotated at least 2 months",
    "detection_commands": [],
    "remediation_commands": [
      "Create or update a rotation policy for your root key by making a PUT call to the following",
      "Create or update a rotation policy for a specified key by running the following cURL",
      "curl -X PUT"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/key-protect?topic=key-protect-key-rotation",
      "2. https://cloud.ibm.com/docs/key-protect?topic=key-protect-set-rotation-policy",
      "3. https://cloud.ibm.com/docs/key-protect?topic=key-protect-view-key-versions",
      "4. https://cloud.ibm.com/docs/key-protect?topic=key-protect-rotate-keys",
      "5. https://cloud.ibm.com/docs/key-protect?topic=key-protect-cli-reference#kp-key-",
      "policies",
      "6. https://cloud.ibm.com/docs/key-protect?topic=key-protect-cli-reference#kp-key-",
      "policy-update-rotation"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 208,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "key_management"
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
    "cis_id": "8.1.1.2",
    "title": "Ensure Keys in the IBM Cloud® Key Protect Service are configured for high availability",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "security_compliance",
    "domain": "Security and Compliance",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "IBM® Key Protect for IBM Cloud® is a highly available, regional service with multiple\navailability zones and automatic features that help keep your applications secure and\noperational. Within a region high availability is achieved through routing traffic to other\navailability zones if one zone is down.\nHigh Availability across regions can be achieved by two ways.\nDynamic cross-region high availability:\nThere are three regions, us-south (located in Dallas, Texas, United States), jp-tok\n(located in Tokyo, Japan), and eu-de (located in Frankfurt, Germany) where Key Protect\nhas failover support into a separate region where data is replicated into standby\ninfrastructure (fail-over region) if you select the Cross-region plan. This allows your keys\nare available in another region if the primary region goes down. In the event primary\nregion goes down, your requests are routed to the fail-over region transparently,\ntherefore you can continue to call same endpoint without any disruption.\nManual cross-region high availability:\nIn case if you cannot use any of these three regions, you can still achieve high\navailability, however it is your responsibility to own the process to achieve high\navailability for the keys. The process involves you creating a Key Protect instance in two\ndifferent regions and import same root key in both regions. Because keys created using\nthe same key material are effectively identical, either key can be used to wrap or\nunwrap any data encryption keys (DEKs). Note that the Key Protect endpoint, instance\nid and key id are different in each region, so you need to change the endpoint, instance\nid and key id when you switch using the other region. Also, every time a root key is\nrotated, new key material is added to the key, which creates a new version of the key.\nTherefore, import the rotated key into Key Protect in both regions. This process works\nonly for Bring Your Own Key (root key).",
    "rationale": "Accessing your data requires decryption of the Data Encryption Key using Root Key, it\nis critical to have high availability feature for the root key. High availability of the key\nmanagement service is necessary for both load balancing and fault tolerance.\nDisaster recovery is about surviving a catastrophic failure or loss of availability in a\nsingle location. Key Protect takes care of disaster recovery for your keys automatically\nin cross-regions supported Key Protect service.",
    "impact": "By using high availability and disaster recovery feature, your application and services\ncan run without disruption in the event of one region going down preventing denial of\nservice.",
    "audit": "To check if a of Key Protect instance is provisioned in one of the cross-regions\nsupported Key Protect Service, complete the following steps.\nUsing Console:\n1. Log in to the IBM Cloud® console.\n2. Go to Menu, Resource List to view a list of your resources.\n3. From your IBM Cloud resource list, click on Security select to view all your\nprovisioned Key Protect instances.\n4. Click on instance you want to check cross-region high availability\n5. Click on the endpoints on the left-hand panel and verify if the region in the\nendpoint is one of the regions that has cross-region high availability.",
    "remediation": "To get a list of Key Protect instances from the IBM Cloud console, complete the\nfollowing steps. Log in to your IBM Cloud account.\nUsing Console:\n1. Click Catalog to view the list of services that are available on IBM Cloud.\n2. From the All-Categories navigation pane, click the Security and Identity\ncategory.\n3. From the list of services, click the Key Protect tile.\n4. Select a service plan, and click Create to provision an instance of Key Protect in\nthe account, region that has cross-region support, and resource group where you\nare logged in.",
    "default_value": "By default, IBM Cloud Key Protect Service with cross-region provides High Availability.\nIn the regions where cross-region is supported,\nIt is the customer discretion to configure HA according to their needs.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/key-protect?topic=key-protect-provision",
      "2. https://cloud.ibm.com/docs/key-protect?topic=key-protect-regions",
      "3. https://cloud.ibm.com/docs/key-protect?topic=key-protect-ha-dr"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 213,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "backup"
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
    "cis_id": "8.1.1.3",
    "title": "Ensure all data stores are encrypted in the IBM Cloud®",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "security_compliance",
    "domain": "Security and Compliance",
    "subdomain": "Perform Automated Backups",
    "description": "When you provision any data services in the IBM Cloud, such as Cloud Object Storage,\nDatabases such as PostGreSQL, MongoDB, database for ElasticSearch, ETCD,\nbackups created for any data store, and data volumes for compute etc., you want to\nencrypt the data-at-rest with your root key that you created in Key Protect key\nmanagement service. You can use Bring Your Own Key (CRK) or provider key to\nenable encryption of your data-at-rest in data store associated with any of the services\nin the IBM Cloud that is integrated with the Key Protect Service.",
    "rationale": "By encrypting your data with your own root key or service provided root key, you are\nprotecting your data from unwanted access to your data. Even if the data is accessed,\nattacker cannot view the data as the encryption key is not stored with the data",
    "impact": "Once you provide your root key (CRK) to the IBM Cloud Service where your data is\nstored, the service will use your root key to decrypt the Data Encryption Key, that is\nused to encrypt your data by the service, when you access your data. You need to have\nthe required role to do this operation.",
    "audit": "Using Console:\n1. Log in to the IBM Cloud® console.\n2. Go to Menu, Resource List to view a list of your resources.\n3. From your IBM Cloud resource list, click on Storage\n4. From the list of Cloud Object Storage instances, click on one of the Instances\n5. Cloud Object Storage dashboard shows a list of created buckets in that instance\n6. Click on a bucket name to look at the details\n7. Click on Key Management to see if the bucket is encrypted with an encryption\nkey",
    "remediation": "After you designate a root key in Key Protect and grant access between your services,\nyou can enable envelope encryption for a specified storage bucket by using the IBM\nCloud Object Storage GUI.\nTip: To enable advanced configuration options for your storage bucket, ensure that an\nauthorization exists between your IBM Cloud Object Storage and Key Protect instances.\nUsing Console:\nTo add envelope encryption to your storage bucket:\n1. From your IBM Cloud® Object Storage dashboard, click Create bucket.\n2. Specify the bucket's details.\n3. In the Advanced Configuration section, select Add Key Protect Keys.\n4. From the list of Key Protect service instances, select the instance that contains\nthe root key that you want to use for key wrapping.\n5. For Key Name, select the alias of the root key.\n6. Click Create to confirm the bucket creation.\nFrom the IBM Cloud® Object Storage GUI, you can browse the buckets that are\nprotected by a Key Protect root key.",
    "default_value": "User has to select encryption at the data source service.",
    "additional_information": "1. Check whether Databases for PostgreSQL are encrypted with customer\nmanaged keys\n2. Check whether Databases for PostgreSQL backups are encrypted with\ncustomer-managed keys\n3. Check whether Databases for MongoDB are encrypted with customer-managed\nkeys\n4. Check whether Databases for MongoDB backups are encrypted with customer-\nmanaged keys\n5. Check whether Databases for Redis are encrypted with customer-managed keys\n6. Check whether Databases for Redis backups are encrypted with customer-\nmanaged keys\n7. Check whether Databases for Elasticsearch are encrypted with customer-\nmanaged keys\n8. Check whether Databases for Elasticsearch backups are encrypted with\ncustomer-managed keys\n9. Check whether data disks are encrypted with customer-managed keys\n10. Check whether Virtual Servers for VPC boot volumes are encrypted with\ncustomer-managed keys\n11. Check whether OS disks are encrypted with customer-managed keys\n12. Check whether Kubernetes Service Cluster is enabled with customer-managed\nencryption\n13. Check whether Event Streams is enabled with customer-managed encryption\n14. Check whether Databases for MySql is enabled with encryption\n15. Check whether IBM Activity Tracker logs are encrypted at rest\n16. Check whether Block Storage Snapshots for VPC is enabled with customer-\nmanaged encryption\n17. Check whether Virtual Servers for VPC data volumes are enabled with customer-\nmanaged encryption\n18. Check whether Virtual Servers for VPC boot volumes are enabled with customer-\nmanaged encryption",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/solution-tutorials?topic=solution-tutorials-cloud-e2e-",
      "security",
      "2. https://cloud.ibm.com/docs/key-protect?topic=key-protect-integrate-services",
      "3. https://cloud.ibm.com/docs/key-protect?topic=key-protect-integrate-",
      "services#grant-access",
      "4. https://cloud.ibm.com/docs/key-protect?topic=key-protect-integrate-cos"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 216,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D3",
      "D5"
    ]
  },
  {
    "cis_id": "8.2.1",
    "title": "Ensure certificates imported into or generated through IBM Cloud® Secrets Manager are automatically renewed before expiration",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "security_compliance",
    "domain": "Security and Compliance",
    "subdomain": "IBM Cloud Secrets Manager",
    "description": "You can use the IBM Cloud Secrets Manager service dashboard to set the renewable\nperiod for the certificates that you manage in the Secrets Manager service. Private\ncertificates generated through Secrets Manger are rotated by replacing existing\ncertificate value with new certificate version. Public certificates generated in Secrets\nManager are moved to Active, Rotation Pending status to indicate that the request to\nrenew the certificate is being processed. Secrets Manager does DNS validation to verify\nthat you own the domain listed in the certificate, if succeeded, Secrets Manager gets a\nnew certificate and status changes back to Active. if validation failed, the status of the\ncertificate changes to Active, Rotation failed.",
    "rationale": "Cloud applications and services running on the platform might use certificate for\ndifferent purposes - TLS or mTLS, client/server authentication and more. Ensuring your\ncertificates are stored securely, and renewed before they expired is crucial to\nmaintaining high security posture.",
    "impact": "Without proper Certificate Management practices in place organization risk to be\nvulnerable to impersonation attacks in case certificates used for authentication will be\nleaked and service outages in case certificates are not renewed on time.",
    "audit": "Using Console:\n1. You can view the certificate renewal settings such as expiration date, rotation\ninterval or state\n2. Log in to the IBM Cloud® console.\n3. Go to Menu, Resource List to view a list of your resources.\n4. Click on Security and click on the Secrets Manager instance that you want to\nuse\n5. In the Secrets table, click the Actions menu to open a list of options for your\nsecret\n6. To view the secret value, click Details\nTo download a certificate by using Secrets Manager UI, complete the following steps\n1. In the Secrets table, open the overflow menu for the certificate that you want to\ndownload\n2. Click Download, the certificate file is downloaded to your local system",
    "remediation": "Using Console:\n1. Log in to the IBM Cloud® console.\n2. Go to Menu, Resource List to view a list of your resources.\n3. Click on Security and click on the Secrets Manager instance that you want to\nuse\n4. If you're ordering a public certificate, enable the rotation options.\na. To rotate the certificate automatically, switch the rotation toggle to On. Your\ncertificate is automatically reordered 31 days before its expiration date. b. To\nrequest a new private key for the certificate on each rotation, switch the rekey\ntoggle to On.\n5. If you're editing an existing public certificate, schedule automatic rotation by\nupdating its details.\na. In the Secrets table, view a list of your existing Public certificates. b. In the\nrow for the certificate that you want to edit, click the Actions menu, Edit\ndetails c. Use the Automatic rotation option to add or remove a rotation\npolicy for the secret\n6. If you're creating private certificates, enable the rotation options.\na. To rotate the certificate automatically, switch the rotation toggle to ON b. Select\nan interval and unit that specifies the number of days between scheduled\nrotations. Note: Note: Depending on the certificate template that is associated\nwith your private certificate, some restrictions on the rotation interval for the\ncertificate might apply. For example, the rotation interval can't exceed the time-\nto-live (TTL) that is defined in the template. For more information, see Certificate\ntemplates.\n7. If you're editing an existing private certificate, schedule automatic rotation by\nupdating its details.\na. In the Secrets table, view a list of your existing Private certificates. b. In the\nrow for the certificate that you want to edit, click the Actions menu, Edit\ndetails c. Use the Automatic rotation option to add or remove a rotation policy\nfor the secret",
    "additional_information": "Check whether certificates in Secrets Manager are automatically renewed before\nexpiration",
    "detection_commands": [
      "use"
    ],
    "remediation_commands": [
      "use"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-automatic-",
      "rotation&interface=ui",
      "2. https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-access-",
      "secrets&interface=cli",
      "3. https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-access-",
      "secrets&interface=api"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 220,
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
    "cis_id": "8.2.2",
    "title": "Ensure access settings to secrets follow least privilege rule and allow access for a limited time to applications and non- administrative users as needed",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "security_compliance",
    "domain": "Security and Compliance",
    "subdomain": "Encrypt Sensitive Data in Transit",
    "description": "You can enable different levels of access to IBM Cloud® Secrets Manager resources in\nyour IBM Cloud account by creating and modifying IBM Cloud IAM access policies. As\nan account owner, determine an access policy type for users, service IDs, and access\ngroups based on your internal access control requirements. For example, if you want to\ngrant user access to Secrets Manager at the most minimal scope available, you can\nassign access to a secret group in an instance.\nReview your IAM settings to confirm that permissive access to the Secrets Manager\nservice is not allowed. Grant access to secrets for non-administrative users and\napplications only for the duration necessary to complete their tasks and promptly revoke\naccess when it is no longer required.\nLimit access to specific Secrets Manager instances or secret groups and assign only\nthe minimum service role necessary for the required operations. Additionally, you can\nconfigure custom IAM roles to restrict access to a specific set of Secrets Manager\nactions tailored to a workload's needs.",
    "rationale": "Adopting least privilege rule improves organizations security posture and using secrets\nthat are valid only for a limited time reduces blast radius. Also using secrets groups to\nassign needed access enables to follow least privilege strategy.",
    "impact": "Controlled access to secrets as needed for a limited time enables automation of\napplications and services seamlessly use secrets.",
    "audit": "Using Console:\n1. Log in to the IBM Cloud® console.\n2. Go to Manage, Access (IAM) and assign access to your Secrets Manager\ninstance:\na. Create an access group for the users and service IDs that you want to give\naccess to and add those users to the access group in IAM. For example, you\nmight have a group of security admins that might need the same level of access.\nb. After you create an access group and add users, go to Manage, Access\n(IAM), Access Groups.\nc. Select a table row and click the Actions menu to open a list of options for that\naccess group.\nd. Click Assign Access.\ne. From the list of services, select Secrets Manager and click Next.\nf. In the Resources section, select Specific resources. Choose a region and\nSecrets Manager service instance. Then, click Next. If you choose not to provide\na specific instance, access is assigned for all instances of the service within the\nregion that you selected. If you choose not to select a region, access is granted\nfor all instances of the service in your account. Choose a combination of platform\nand service access roles to assign access for access group.\ng. Review your selections and click Add.\nh. Click Assign.\ni. Now you can add users and service IDs to the access group so that you can\nassign access to Secrets Manager with a single access policy. For more\ninformation, see Setting up access groups.\n3. Go to Menu, Resource list to view a list of your resources.\n4. Click on Security and click on the Secrets Manager instance that you want to\nuse.\n5. Assign access to a secret group.\na. In the navigation, click Secret groups.\nb. Use the Secret groups table to browse the groups in your instance.\nc. In the row of the group that you want to manage, click the Actions menu\nManage access.\nd. Select an access group to give its contained users and service IDs access to\nyour secret group.\ne. Choose a combination of access roles to assign.\nf. Click Review.\ng. Review your selections and click Assign.",
    "remediation": "Using Console:\nRemove a user from an Access Group\n1. Log in to the IBM Cloud® console.\n2. Go to Manage, Access (IAM), Access Groups\na. Select your Access Group and click the Actions menu to open a list of options\nfor that access group.\nb. Click Manage group.\nc. Select the user you would like to remove and click the Actions menu to remove\nit.",
    "default_value": "User has to set access controls to secrets.",
    "additional_information": "1. Check whether permissive access is given to Secrets Manager service\n2. Check whether Secrets Manager default secret group contains no secrets",
    "detection_commands": [
      "use."
    ],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/account?topic=account-custom-roles&interface=ui",
      "2. https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-assign-",
      "access&interface=ui",
      "3. https://cloud.ibm.com/docs/account?topic=account-",
      "groups&interface=ui#create_ag"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 223,
    "dspm_relevant": true,
    "dspm_categories": [
      "access",
      "key_management"
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
    "cis_id": "8.2.3",
    "title": "Ensure notification service is enabled in the IBM Cloud Secrets Manager to notify life cycle events",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "access_control",
    "domain": "Access Control Management",
    "subdomain": "Use Multifactor Authentication For All Administrative",
    "description": "Secrets stored in the Secrets Manager go through life-cycle changes, as an\nadministrator of your Secrets Manager instance, you may want to notify your users,\napplications through available delivery channels such as email, SMS etc., or through\nevent-driven programming using webhooks.",
    "rationale": "Ensuring all secrets life cycle management is handled on-time to ensure users are not\nlocked out and applications run without disruptions.",
    "impact": "Relevant personal gets notification and take action.\nAdditional cost may be incurred by enabling notification services.",
    "audit": "Using Console:\n1. Log in to the IBM Cloud® console.\n2. Go to Menu, Resource List to view a list of your resources.\n3. Click on Security and click on the Secrets Manager instance that you want to\nuse\n4. Click on Settings on the left-hand panel to check if event notification is\nconfigured for the instance.",
    "remediation": "Using Console:\n1. Log in to the IBM Cloud® console.\n2. Go to Menu, Resource List to view a list of your resources.\n3. Click on Security and click on the Secrets Manager instance that you want to\nuse\n4. In the Secrets Manager navigation, click Settings.\n5. In the Event Notifications section and click Connect.\n6. In the side panel, review the source details for the connection.\n7. Select the resource group and Event Notifications service instance that you want\nto connect.\n8. To confirm the connection, click `Connect'.\n9. A success message is displayed to indicate that Secrets Manager is now\nconnected to Event Notifications.\nIf an IAM authorization between Secrets Manager and Event Notifications doesn't exist\nin your account, a dialog is displayed. Follow the prompts to grant access between the\nservices.\n1. To grant access between Secrets Manager and Event Notifications, click\nAuthorize.\n2. In the side panel, select Event Notifications as the target service.\n3. From the list of instances, select the Event Notifications service instance that you\nwant to authorize.\n4. Select the Event Source Manager role.\n5. Click Review.\n6. Click Assign.",
    "default_value": "Event Notification is not enabled by default.",
    "detection_commands": [
      "use"
    ],
    "remediation_commands": [
      "use"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-event-",
      "notifications&interface=ui"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 227,
    "dspm_relevant": true,
    "dspm_categories": [
      "access",
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
    "cis_id": "8.2.4",
    "title": "Ensure secrets stored in the IBM Cloud® Secrets Manager are rotated periodically",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "access_control",
    "domain": "Access Control Management",
    "subdomain": "Centralize Security Event Alerting",
    "description": "As you use Secrets Manager to design your secrets management strategy, consider\nhow often you want to rotate your secrets based on the internal guidelines for your\norganization. Determine ahead of time which users or service IDs require access to\nrotate secrets, and how those secrets can be rotated to avoid interruptions to your\napplications.\nBy scheduling automatic rotation of secrets at regular intervals, you reduce the\nlikelihood of compromised credentials. When it's time to rotate the secret based on the\nrotation interval that you specify, Secrets Manager automatically creates a new version\nof your secret. You can safely delete old version of the secrets only after their newest\nversions are fully deployed to your applications. If any secrets are in use, you can use\nSecrets Manager LOCK feature to lock the secrets from getting deleted.",
    "rationale": "Rotating secrets enables to meet your internal and external regulatory requirements.\nCompromised secrets can be removed by rotating secrets.",
    "impact": "Rotated secrets (new version) need to be updated in the applications, services that are\nusing the secrets to avoid interruptions to applications and services functioning.\nAdditional cost may be incurred by scheduling automatic rotation of secrets",
    "audit": "Using Console:\n1. Log in to the IBM Cloud® console.\n2. Go to Menu, Resource List to view a list of your resources.\n3. Click on Security and click on the Secrets Manager instance that you want to\nview\n4. In the Secrets table, click the Actions menu to open a list of options for your\nsecret\n5. To view the secret value, click View Secret\n6. Click Confirm after you ensure that you are in a safe environment\n7. To retrieve a secret’s details such as rotation interval or state; In the Secrets\ntable, click the Actions menu, to open a list of options for your secret\n8. To view the secret value, click Details.",
    "expected_response": "6. Click Confirm after you ensure that you are in a safe environment",
    "remediation": "Using Console:\n1. Log in to the IBM Cloud® console.\n2. Go to Menu, Resource List to view a list of your resources.\n3. Click on Security and click on the Secrets Manager instance that you want to\nuse\n4. If you're adding a secret, enable the rotation option.\n5. If you're editing an existing secret, enable automatic rotation by updating its\ndetails.\n6. In the Secrets table, view a list of your existing secrets.\n7. In the row for the secret that you want to edit, click the Actions menu, Edit\ndetails\n8. Use the Automatic rotation option to enable or disable automatic rotation for\nthe secret.",
    "default_value": "Rotation is not enabled, user has to enable it for the service to rotate automatically\nbased on selected interval.",
    "additional_information": "1. Check whether secrets stored in Secrets Manager are set to automatically\nrotated\n2.Check whether Secrets Manager user credentials are rotated at least every 60\ndays 3.Check whether Secrets Manager user credentials are not expired",
    "detection_commands": [],
    "remediation_commands": [
      "use"
    ],
    "references": [
      "1. https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-automatic-",
      "rotation&interface=ui",
      "2. https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-manual-",
      "rotation&interface=cli",
      "3. https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-manual-",
      "rotation&interface=api"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 229,
    "dspm_relevant": true,
    "dspm_categories": [
      "access",
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
    "cis_id": "9.1",
    "title": "Ensure the Default Network Security Group of Every Workspace Restricts All Traffic",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "powervs",
    "domain": "IBM Power Virtual Server on IBM Cloud (PowerVS)",
    "description": "It is recommended that the default security group for every workspace restricts all\ninbound (ingress) traffic, to enforce a least-privilege security posture and reduce\nunintended exposure of PowerVS resources.",
    "rationale": "Starting with a default security group configuration that restricts all inbound (ingress)\ntraffic reduces the chance of exposing PowerVS resources to unintended risks.",
    "audit": "Perform the following tasks to determine if the account is configured as prescribed:\nUsing Console:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power\nVirtual Server user interface.\n2. In the navigation panel, click Workspaces, then for each workspace that contains\nNetwork Security Groups, open the Workspace details page.\n3. From the workspace details page, click view virtual servers.\n4. In the left navigation panel, expand Networking and then select Network\nSecurity Groups.\n5. For the default security group, perform the following:\na. Ensure no rule exists that allows inbound (ingress) traffic flow to the Virtual\nServers in the group.",
    "expected_response": "Perform the following tasks to determine if the account is configured as prescribed:\na. Ensure no rule exists that allows inbound (ingress) traffic flow to the Virtual",
    "remediation": "Using Console:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power\nVirtual Server user interface.\n2. In the navigation panel, click Workspaces, then for each workspace that contains\nNetwork Security Groups, open the Workspace details page.\n3. From the workspace details page, click view virtual servers.\n4. In the left navigation panel, expand Networking and then select Network\nSecurity Groups.\n5. For the default security group, perform the following:\na. Identify the rule that allows inbound (ingress) traffic flows.\nb. Remove the rule.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. 1. https://cloud.ibm.com/docs/power-iaas?topic=power-iaas-nsg",
      "2. 2. https://cloud.ibm.com/apidocs/power-cloud#v1-networksecuritygroups-list",
      "3. 3. IBM Power Virtual Server Security Essentials: NSGs and NAGs Explained"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 232,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "9.2",
    "title": "Ensure no workspace security groups allow ingress from 0.0.0.0/0 to port 3389",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "powervs",
    "domain": "IBM Power Virtual Server on IBM Cloud (PowerVS)",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "It is recommended that workspace security groups do not allow unrestricted ingress\naccess from 0.0.0.0/0 to port 3389, which is the Remote Desktop Protocol (RDP) port\nused for remote server administration.",
    "rationale": "Restricting access to the RDP port reduces the attack surface and lowers risk to\nPowerVS resources by preventing access to a critical administrative port.",
    "audit": "Perform the following tasks to determine if the account is configured as prescribed:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power\nVirtual Server user interface.\n2. In the navigation panel, click Workspaces, then select the workspace that\ncontains the Network Security Groups to review and open the Workspace\ndetails page.\n3. From the workspace details page, click view virtual servers.\n4. In the left navigation panel, expand Networking and then select Network\nsecurity groups. For each NSG perform the following:\na. Select the access control list name\nb. Ensure no Inbound Rule exists that has a port range that includes port 22 and\nhas a Source of 0.0.0.0/0. Note that a port range value of ALL or a port range\nthat includes port 3389, e.g. 3300-3400, are inclusive of port 3389.",
    "expected_response": "Perform the following tasks to determine if the account is configured as prescribed:\nb. Ensure no Inbound Rule exists that has a port range that includes port 22 and",
    "remediation": "1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power\nVirtual Server user interface.\n2. In the navigation panel, click Workspaces, then select the workspace that\ncontains the Network Security Groups to review and open the Workspace\ndetails page.\n3. From the workspace details page, click view virtual servers.\n4. For each network security group, perform the following:\na. Select the network security group name.\nb. Identify the Inbound rule to be removed, then select Delete.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. 1. https://cloud.ibm.com/docs/power-iaas?topic=power-iaas-nsg2.",
      "https://cloud.ibm.com/apidocs/power-cloud#v1-networksecuritygroups-list3. IBM",
      "Power Virtual Server Security Essentials: NSGs and NAGs Explained"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 234,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "9.3",
    "title": "Ensure no workspace network security groups allow ingress from 0.0.0.0/0 to port 22",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "powervs",
    "domain": "IBM Power Virtual Server on IBM Cloud (PowerVS)",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "It is recommended that no workspace security groups allow unrestricted ingress access\nto SSH on port 22.",
    "rationale": "This control is intended to reduce the PowerVS resource attack surface and risk of\ncompromise by preventing access to administrative ports, like SSH.",
    "impact": "When updating an existing environment, care should be taken to ensure that\nadministrators currently relying on an ingress from 0.0.0.0/0 have access to ports 22\nthrough another, more restrictive, access control list, private network connection or VPN\nas a Service.",
    "audit": "Perform the following tasks to determine if the account is configured as prescribed:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power\nVirtual Server user interface.\n2. In the navigation panel, click Workspaces, then select the workspace that\ncontains the Network Security Groups to review and open the Workspace\ndetails page.\n3. From the workspace details page, click view virtual servers.\n4. In the left navigation panel, expand Networking and then select Network\nsecurity groups. For each NSG perform the following:\na. Select the access control list name\nb. Ensure no Inbound Rule exists that has a port range that includes port 22 and\nhas a Source of 0.0.0.0/0. A port range value of ALL or a port range that includes\nport 22, e.g. 0-1024, are inclusive of port 22.",
    "expected_response": "Perform the following tasks to determine if the account is configured as prescribed:\nb. Ensure no Inbound Rule exists that has a port range that includes port 22 and",
    "remediation": "1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power\nVirtual Server user interface.\n2. In the navigation panel, click Workspaces, then select the workspace that\ncontains the Network Security Groups to review and open the Workspace\ndetails page.\n3. From the workspace details page, click view virtual servers.\n4. For each network security group, perform the following:\na. Select the network security group name.\nb. Identify the Inbound rule to be removed, then select Delete.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/power-iaas?topic=power-iaas-nsg",
      "2. https://cloud.ibm.com/apidocs/power-cloud#v1-networksecuritygroups-list",
      "3. https://community.ibm.com/community/user/blogs/arka-",
      "chakraborty/2025/03/03/ibm-powervs-security-essentials-nsgs-and-nags"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 236,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "9.4",
    "title": "Ensure no workspace network security groups allow inbound traffic from the Internet from 0.0.0.0/0 to any infrastructure ports",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "powervs",
    "domain": "IBM Power Virtual Server on IBM Cloud (PowerVS)",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "It is recommended that inbound traffic from the Internet to high-risk ports is restricted,\nfollowing the principle of least privilege access. The ports specified in this control are\nDNS (53), POP3 (110), SMTP (25). DHCP (67, 68), SNMP (161, 162).",
    "rationale": "Removing unrestricted inbound connectivity from the Internet to infrastructure ports and\nservices, such as DNS and DHCP, reduces PowerVS resources’ exposure to risk.",
    "audit": "Perform the following tasks to determine if the account is configured as prescribed:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power\nVirtual Server user interface.\n2. In the navigation panel, click Workspaces, then select the workspace that\ncontains the Network Security Groups to review and open the Workspace\ndetails page.\n3. From the workspace details page, click view virtual servers.\n4. In the left navigation panel, expand Networking and then select Network\nsecurity groups. For each NSG perform the following:\na. Select the access control list name\nb. Ensure no Inbound Rule exists that has a port range that includes ports\n53,110, 25, 67, 68, 161 or 162 and has a Source of 0.0.0.0/0.",
    "expected_response": "Perform the following tasks to determine if the account is configured as prescribed:\nb. Ensure no Inbound Rule exists that has a port range that includes ports",
    "remediation": "1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power\nVirtual Server user interface.\n2. In the navigation panel, click Workspaces, then select the workspace that\ncontains the Network Security Groups to review and open the Workspace\ndetails page.\n3. From the workspace details page, click view virtual servers.\n4. For each network security group, perform the following:\na. Select the network security group name.\nb. Identify the Inbound rule to be removed, then select Delete.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/power-iaas?topic=power-iaas-nsg",
      "2. https://cloud.ibm.com/apidocs/power-cloud#v1-networksecuritygroups-list",
      "3. https://community.ibm.com/community/user/blogs/arka-",
      "chakraborty/2025/03/03/ibm-powervs-security-essentials-nsgs-and-nags"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 238,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "9.5",
    "title": "Ensure no workspace network security groups allow inbound traffic from the Internet from 0.0.0.0/0 to any administrative ports",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "powervs",
    "domain": "IBM Power Virtual Server on IBM Cloud (PowerVS)",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "It is recommended that inbound traffic from the Internet to administrative ports is\nrestricted, following the principle of least privilege access. These ports are RDP (3389),\nSSH (22), VNC (Listener: 5500, Server: 5900) and RPC (135, 111).",
    "rationale": "Removing unrestricted connectivity from the Internet to administrative services, such as\nSSH, reduces a PowerVS resources risk exposure.",
    "impact": "When updating an existing environment, care should be taken to ensure that\nadministrators currently relying on an ingress from 0.0.0.0/0 have access to\nadministrative ports through another, more restrictive, access control list, private\nnetwork connection or VPN as a Service.",
    "audit": "Perform the following tasks to determine if the account is configured as prescribed:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power\nVirtual Server user interface.\n2. In the navigation panel, click Workspaces, then select the workspace that\ncontains the Network Security Groups to review and open the Workspace\ndetails page.\n3. From the workspace details page, click view virtual servers.\n4. In the left navigation panel, expand Networking and then select Network\nsecurity groups. For each NSG perform the following:\na. Select the access control list name\nb. Ensure no Inbound Rule exists that has a port range that includes ports 3389,\n22, 5500, 5900, 135 or 111 and has a Source of 0.0.0.0/0.",
    "expected_response": "Perform the following tasks to determine if the account is configured as prescribed:\nb. Ensure no Inbound Rule exists that has a port range that includes ports 3389,",
    "remediation": "1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power\nVirtual Server user interface.\n2. In the navigation panel, click Workspaces, then select the workspace that\ncontains the Network Security Groups to review and open the Workspace\ndetails page.\n3. From the workspace details page, click view virtual servers.\n4. For each network security group, perform the following:\na. Select the network security group name.\nb. Identify the Inbound rule to be removed, then select Delete.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/power-iaas?topic=power-iaas-nsg",
      "2. https://cloud.ibm.com/apidocs/power-cloud#v1-networksecuritygroups-list",
      "3. https://community.ibm.com/community/user/blogs/arka-",
      "chakraborty/2025/03/03/ibm-powervs-security-essentials-nsgs-and-nags"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 240,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "9.6",
    "title": "Ensure no workspace network security groups allow inbound traffic from the Internet from 0.0.0.0/0 to any fileshare port",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "powervs",
    "domain": "IBM Power Virtual Server on IBM Cloud (PowerVS)",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "It is recommended that inbound traffic from the Internet to file sharing application ports\nis restricted, following the principle of least privilege access. These ports are NetBIOS\n(139), SMB (445), FTP (21).",
    "rationale": "Removing uncontrolled connectivity from the Internet to file sharing services, such as\nSMB, reduces a PowerVS resources’ risk exposure.",
    "audit": "1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power\nVirtual Server user interface.\n2. In the navigation panel, click Workspaces, then select the workspace that\ncontains the Network Security Groups to review and open the Workspace\ndetails page.\n3. From the workspace details page, click view virtual servers.\n4. In the left navigation panel, expand Networking and then select Network\nsecurity groups. For each NSG perform the following:\na. Select the access control list name\nb. Ensure no Inbound Rule exists that has a port range that includes ports 139,\n445 or 21 and has a Source of 0.0.0.0/0.",
    "expected_response": "b. Ensure no Inbound Rule exists that has a port range that includes ports 139,",
    "remediation": "1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power\nVirtual Server user interface.\n2. In the navigation panel, click Workspaces, then select the workspace that\ncontains the Network Security Groups to review and open the Workspace\ndetails page.\n3. From the workspace details page, click view virtual servers.\n4. For each network security group, perform the following:\na. Select the network security group name.\nb. Identify the Inbound rule to be removed, then select Delete.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/power-iaas?topic=power-iaas-nsg",
      "2. https://cloud.ibm.com/apidocs/power-cloud#v1-networksecuritygroups-list",
      "3. https://community.ibm.com/community/user/blogs/arka-",
      "chakraborty/2025/03/03/ibm-powervs-security-essentials-nsgs-and-nags"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 242,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D4",
      "D6"
    ]
  },
  {
    "cis_id": "9.7",
    "title": "Ensure no workspace network security groups allow inbound traffic from the Internet allowing access from 0.0.0.0/0 to telnet port (23) or RSH port (514)",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "or_21_and_has_a_source_of_0_0_0_0_0",
    "domain": "or 21 and has a Source of 0.0.0.0/0",
    "subdomain": "Deny Communication over Unauthorized Ports",
    "description": "It is recommended the inbound traffic from the Internet to telnet port (23) or remote shell\n(RSH, port 514) is restricted.",
    "rationale": "These protocols are insecure/deprecated and should not be used in general.",
    "audit": "Perform the following tasks to determine if the account is configured as prescribed:\n1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power Virtual\nServer user interface.\n2. In the navigation panel, click Workspaces, then select the workspace that\ncontains the Network Security Groups to review and open the Workspace\ndetails page.\n3. From the workspace details page, click view virtual servers.\n4. In the left navigation panel, expand Networking and then select Network\nsecurity groups. For each NSG perform the following:\na. Select the access control list name\nb. Ensure no Inbound Rule exists that has a port range that includes ports 23 or\n514 and has a Source of 0.0.0.0/0.",
    "expected_response": "Perform the following tasks to determine if the account is configured as prescribed:\nb. Ensure no Inbound Rule exists that has a port range that includes ports 23 or",
    "remediation": "1. Login to the IBM Cloud Portal at https://cloud.ibm.com and select Power Virtual\nServer user interface.\n2. In the navigation panel, click Workspaces, then select the workspace that\ncontains the Network Security Groups to review and open the Workspace\ndetails page.\n3. From the workspace details page, click view virtual servers.\n4. For each network security group, perform the following:\na. Select the network security group name.\nb. Identify the Inbound rule to be removed, then select Delete.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.ibm.com/docs/power-iaas?topic=power-iaas-nsg",
      "2. https://cloud.ibm.com/apidocs/power-cloud#v1-networksecuritygroups-list",
      "3. https://community.ibm.com/community/user/blogs/arka-",
      "chakraborty/2025/03/03/ibm-powervs-security-essentials-nsgs-and-nags"
    ],
    "source_pdf": "CIS_IBM_Cloud_Foundations_Benchmark_v2.0.0.pdf",
    "page": 244,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D4",
      "D6"
    ]
  }
]
""")


def get_ibm_cloud_cis_registry() -> list[dict]:
    """Return the complete CIS control registry as a list of dicts."""
    return IBM_CLOUD_CIS_CONTROLS


def get_ibm_cloud_control_count() -> int:
    """Return total number of CIS controls."""
    return len(IBM_CLOUD_CIS_CONTROLS)


def get_ibm_cloud_automated_count() -> int:
    """Return count of automated controls."""
    return sum(1 for c in IBM_CLOUD_CIS_CONTROLS if c["assessment_type"] == "automated")


def get_ibm_cloud_manual_count() -> int:
    """Return count of manual controls."""
    return sum(1 for c in IBM_CLOUD_CIS_CONTROLS if c["assessment_type"] == "manual")


def get_ibm_cloud_dspm_controls() -> list[dict]:
    """Return controls relevant to DSPM (Data Security Posture Management)."""
    return [c for c in IBM_CLOUD_CIS_CONTROLS if c.get("dspm_relevant")]


def get_ibm_cloud_rr_controls() -> list[dict]:
    """Return controls relevant to Ransomware Readiness."""
    return [c for c in IBM_CLOUD_CIS_CONTROLS if c.get("rr_relevant")]


def get_ibm_cloud_controls_by_service_area(service_area: str) -> list[dict]:
    """Return controls filtered by service area."""
    return [c for c in IBM_CLOUD_CIS_CONTROLS if c["service_area"] == service_area]


def get_ibm_cloud_controls_by_severity(severity: str) -> list[dict]:
    """Return controls filtered by severity."""
    return [c for c in IBM_CLOUD_CIS_CONTROLS if c["severity"] == severity]
