"""CIS Google Cloud Platform Foundation Benchmark v4.0.0 — Complete Control Registry.

Auto-generated from the unified CIS controls library.
Contains ALL 84 controls (72 automated, 12 manual).
Each control includes full metadata, audit procedures, detection commands,
remediation guidance, and DSPM/Ransomware Readiness mapping.

Reference: CIS Google Cloud Platform Foundation Benchmark v4.0.0 (2025)
Source: CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf

Total controls: 84 (72 automated, 12 manual)
"""

import json as _json


# Control registry — 84 controls
GCP_CIS_CONTROLS: list[dict] = _json.loads(r"""
[
  {
    "cis_id": "1.1",
    "title": "Ensure that Corporate Login Credentials are Used",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "description": "Use corporate login credentials instead of consumer accounts, such as Gmail accounts.",
    "rationale": "It is recommended fully-managed corporate Google accounts be used for increased\nvisibility, auditing, and controlling access to Cloud Platform resources. Email accounts\nbased outside of the user's organization, such as consumer accounts, should not be\nused for business purposes.",
    "impact": "There will be increased overhead as maintaining accounts will now be required. For\nsmaller organizations, this will not be an issue, but will balloon with size.",
    "audit": "For each Google Cloud Platform project, list the accounts that have been granted\naccess to that project:\nFrom Google Cloud CLI\ngcloud projects get-iam-policy PROJECT_ID\nAlso list the accounts added on each folder:\ngcloud resource-manager folders get-iam-policy FOLDER_ID\nAnd list your organization's IAM policy:\ngcloud organizations get-iam-policy ORGANIZATION_ID\nNo email accounts outside the organization domain should be granted permissions in\nthe IAM policies. This excludes Google-owned service accounts.",
    "expected_response": "No email accounts outside the organization domain should be granted permissions in",
    "remediation": "Remove all consumer Google accounts from IAM policies. Follow the documentation\nand setup corporate login accounts.\nPrevention:\nTo ensure that no email addresses outside the organization can be granted IAM\npermissions to its Google Cloud projects, folders or organization, turn on the\nOrganization Policy for Domain Restricted Sharing. Learn more at:\nhttps://cloud.google.com/resource-manager/docs/organization-policy/restricting-\ndomains",
    "default_value": "By default, no email addresses outside the organization's domain have access to its\nGoogle Cloud deployments, but any user email account can be added to the IAM policy\nfor Google Cloud Platform projects, folders, or organizations.",
    "detection_commands": [
      "gcloud projects get-iam-policy PROJECT_ID",
      "gcloud resource-manager folders get-iam-policy FOLDER_ID",
      "gcloud organizations get-iam-policy ORGANIZATION_ID"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://support.google.com/work/android/answer/6371476",
      "2. https://cloud.google.com/sdk/gcloud/reference/projects/get-iam-policy",
      "3. https://cloud.google.com/sdk/gcloud/reference/resource-manager/folders/get-",
      "iam-policy",
      "4. https://cloud.google.com/sdk/gcloud/reference/organizations/get-iam-policy",
      "5. https://cloud.google.com/resource-manager/docs/organization-policy/restricting-",
      "domains",
      "6. https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-",
      "constraints"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 19,
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
    "cis_id": "1.2",
    "title": "Ensure that Multi-Factor Authentication is 'Enabled' for All Non-Service Accounts",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Configure Centralized Point of Authentication",
    "description": "Setup multi-factor authentication for Google Cloud Platform accounts.",
    "rationale": "Multi-factor authentication requires more than one mechanism to authenticate a user.\nThis secures user logins from attackers exploiting stolen or weak credentials.",
    "audit": "From Google Cloud Console\nFor each Google Cloud Platform project, folder, or organization:\n1. Identify non-service accounts.\n2. Manually verify that multi-factor authentication for each account is set.",
    "remediation": "From Google Cloud Console\nFor each Google Cloud Platform project:\n1. Identify non-service accounts.\n2. Setup multi-factor authentication for each account.",
    "default_value": "By default, multi-factor authentication is not set.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.google.com/solutions/securing-gcp-account-u2f",
      "2. https://support.google.com/accounts/answer/185839"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 21,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1"
    ]
  },
  {
    "cis_id": "1.3",
    "title": "Ensure that Security Key Enforcement is Enabled for All Admin Accounts",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Require Multi-factor Authentication",
    "description": "Setup Security Key Enforcement for Google Cloud Platform admin accounts.",
    "rationale": "Google Cloud Platform users with Organization Administrator roles have the highest\nlevel of privilege in the organization. These accounts should be protected with the\nstrongest form of two-factor authentication: Security Key Enforcement. Ensure that\nadmins use Security Keys to log in instead of weaker second factors like SMS or one-\ntime passwords (OTP). Security Keys are actual physical keys used to access Google\nOrganization Administrator Accounts. They send an encrypted signature rather than a\ncode, ensuring that logins cannot be phished.",
    "impact": "If an organization administrator loses access to their security key, the user could lose\naccess to their account. For this reason, it is important to set up backup security keys.",
    "audit": "1. Identify users with Organization Administrator privileges:\ngcloud organizations get-iam-policy ORGANIZATION_ID\nLook for members granted the role \"roles/resourcemanager.organizationAdmin\".\n2. Manually verify that Security Key Enforcement has been enabled for each\naccount.",
    "remediation": "1. Identify users with the Organization Administrator role.\n2. Setup Security Key Enforcement for each account. Learn more at:\nhttps://cloud.google.com/security-key/",
    "default_value": "By default, Security Key Enforcement is not enabled for Organization Administrators.",
    "detection_commands": [
      "gcloud organizations get-iam-policy ORGANIZATION_ID"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.google.com/security-key/",
      "2. https://gsuite.google.com/learn-",
      "more/key_for_working_smarter_faster_and_more_securely.html"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 23,
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
    "cis_id": "1.4",
    "title": "Ensure That There Are Only GCP-Managed Service Account Keys for Each Service Account",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Require Multi-factor Authentication",
    "description": "User-managed service accounts should not have user-managed keys.",
    "rationale": "Anyone who has access to the keys will be able to access resources through the\nservice account. GCP-managed keys are used by Cloud Platform services such as App\nEngine and Compute Engine. These keys cannot be downloaded. Google will keep the\nkeys and automatically rotate them on an approximately weekly basis. User-managed\nkeys are created, downloadable, and managed by users. They expire 10 years from\ncreation.\nFor user-managed keys, the user has to take ownership of key management activities\nwhich include:\n• Key storage\n• Key distribution\n• Key revocation\n• Key rotation\n• Protecting the keys from unauthorized users\n• Key recovery\nEven with key owner precautions, keys can be easily leaked by common development\nmalpractices like checking keys into the source code or leaving them in the Downloads\ndirectory, or accidentally leaving them on support blogs/channels.\nIt is recommended to prevent user-managed service account keys.",
    "impact": "Deleting user-managed service account keys may break communication with the\napplications using the corresponding keys.",
    "audit": "From Google Cloud Console\n1. Go to the IAM page in the GCP Console using\nhttps://console.cloud.google.com/iam-admin/iam\n2. In the left navigation pane, click Service accounts. All service accounts and\ntheir corresponding keys are listed.\n3. Click the service accounts and check if keys exist.\nFrom Google Cloud CLI\nList All the service accounts:\ngcloud iam service-accounts list\nIdentify user-managed service accounts which have an account EMAIL ending with\niam.gserviceaccount.com\nFor each user-managed service account, list the keys managed by the user:\ngcloud iam service-accounts keys list --iam-account=<Service Account> --\nmanaged-by=user\nNo keys should be listed.",
    "expected_response": "No keys should be listed.",
    "remediation": "From Google Cloud Console\n1. Go to the IAM page in the GCP Console using\nhttps://console.cloud.google.com/iam-admin/iam\n2. In the left navigation pane, click Service accounts. All service accounts and\ntheir corresponding keys are listed.\n3. Click the service account.\n4. Click the edit and delete the keys.\nFrom Google Cloud CLI\nTo delete a user managed Service Account Key,\ngcloud iam service-accounts keys delete --iam-account=<user-managed-service-\naccount-EMAIL> <KEY-ID>\nPrevention:\nYou can disable service account key creation through the Disable service account\nkey creation Organization policy by visiting https://console.cloud.google.com/iam-\nadmin/orgpolicies/iam-disableServiceAccountKeyCreation. Learn more at:\nhttps://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-\naccounts\nIn addition, if you do not need to have service accounts in your project, you can also\nprevent the creation of service accounts through the Disable service account\ncreation Organization policy: https://console.cloud.google.com/iam-\nadmin/orgpolicies/iam-disableServiceAccountCreation.",
    "default_value": "By default, there are no user-managed keys created for user-managed service\naccounts.",
    "additional_information": "A user-managed key cannot be created on GCP-Managed Service Accounts.",
    "detection_commands": [
      "gcloud iam service-accounts list",
      "gcloud iam service-accounts keys list --iam-account=<Service Account> --"
    ],
    "remediation_commands": [
      "gcloud iam service-accounts keys delete --iam-account=<user-managed-service-"
    ],
    "references": [
      "1. https://cloud.google.com/iam/docs/understanding-service-",
      "accounts#managing_service_account_keys",
      "2. https://cloud.google.com/resource-manager/docs/organization-policy/restricting-",
      "service-accounts"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 25,
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
    "cis_id": "1.5",
    "title": "Ensure That Service Account Has No Admin Privileges",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Require Multi-factor Authentication",
    "description": "A service account is a special Google account that belongs to an application or a VM,\ninstead of to an individual end-user. The application uses the service account to call the\nservice's Google API so that users aren't directly involved. It's recommended not to use\nadmin access for ServiceAccount.",
    "rationale": "Service accounts represent service-level security of the Resources (application or a\nVM) which can be determined by the roles assigned to it. Enrolling ServiceAccount with\nAdmin rights gives full access to an assigned application or a VM. A ServiceAccount\nAccess holder can perform critical actions like delete, update change settings, etc.\nwithout user intervention. For this reason, it's recommended that service accounts not\nhave Admin rights.",
    "impact": "Removing *Admin or *admin or Editor or Owner role assignments from service\naccounts may break functionality that uses impacted service accounts. Required role(s)\nshould be assigned to impacted service accounts in order to restore broken\nfunctionalities.",
    "audit": "From Google Cloud Console\n1. Go to IAM & admin/IAM using https://console.cloud.google.com/iam-\nadmin/iam\n2. Under the IAM Tab look for VIEW BY PRINCIPALS\n3. Filter PRINCIPALS using type : Service account\n4. Look for the Service Account with the nomenclature:\nSERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com\n5. Ensure that there are no such Service Accounts with roles containing *Admin or\n*admin or role matching Editor or role matching Owner under Role column.\nFrom Google Cloud CLI\n1. Get the policy that you want to modify, and write it to a JSON file:\ngcloud projects get-iam-policy PROJECT_ID --format json > iam.json\n2. The contents of the JSON file will look similar to the following. Note that role of\nmembers group associated with each serviceaccount does not contain *Admin\nor *admin or does not match roles/editor or does not match roles/owner.\nThis recommendation is only applicable to User-Managed user-created service\naccounts. These accounts have the nomenclature:\nSERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com. Note that some\nGoogle-managed, Google-created service accounts have the same naming format, and\nshould be excluded (e.g., appsdev-apps-dev-script-\nauth@system.gserviceaccount.com which needs the Owner role).\nSample Json output:\n{\n\"bindings\": [\n{\n\"members\": [\n\"serviceAccount:our-project-123@appspot.gserviceaccount.com\",\n],\n\"role\": \"roles/appengine.appAdmin\"\n},\n{\n\"members\": [\n\"user:email1@gmail.com\"\n],\n\"role\": \"roles/owner\"\n},\n{\n\"members\": [\n\"serviceAccount:our-project-123@appspot.gserviceaccount.com\",\n\"serviceAccount:123456789012-compute@developer.gserviceaccount.com\"\n],\n\"role\": \"roles/editor\"\n}\n],\n\"etag\": \"BwUjMhCsNvY=\",\n\"version\": 1\n}",
    "expected_response": "5. Ensure that there are no such Service Accounts with roles containing *Admin or\nshould be excluded (e.g., appsdev-apps-dev-script-\nSample Json output:",
    "remediation": "From Google Cloud Console\n1. Go to IAM & admin/IAM using https://console.cloud.google.com/iam-\nadmin/iam\n2. Under the IAM Tab look for VIEW BY PRINCIPALS\n3. Filter PRINCIPALS using type : Service account\n4. Look for the Service Account with the Principal nomenclature:\nSERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com\n5. Identify User-Managed user created service account with roles containing\n*Admin or *admin or role matching Editor or role matching Owner under Role\nColumn.\n6. Click on Edit (Pencil Icon) for the Service Account, it will open all the roles\nwhich are assigned to the Service Account.\n7. Click the Delete bin icon to remove the role from the Principal (service account\nin this case)\nFrom Google Cloud CLI\ngcloud projects get-iam-policy PROJECT_ID --format json > iam.json\n1. Using a text editor, Remove Role which contains roles/*Admin or\nroles/*admin or matched roles/editor or matches 'roles/owner`. Add a role\nto the bindings array that defines the group members and the role for those\nmembers.\nFor example, to grant the role roles/appengine.appViewer to the ServiceAccount\nwhich is roles/editor, you would change the example shown below as follows:\n{\n\"bindings\": [\n{\n\"members\": [\n\"serviceAccount:our-project-123@appspot.gserviceaccount.com\",\n],\n\"role\": \"roles/appengine.appViewer\"\n},\n{\n\"members\": [\n\"user:email1@gmail.com\"\n],\n\"role\": \"roles/owner\"\n},\n{\n\"members\": [\n\"serviceAccount:our-project-123@appspot.gserviceaccount.com\",\n\"serviceAccount:123456789012-compute@developer.gserviceaccount.com\"\n],\n\"role\": \"roles/editor\"\n}\n],\n\"etag\": \"BwUjMhCsNvY=\"\n}\n2. Update the project's IAM policy:\ngcloud projects set-iam-policy PROJECT_ID iam.json",
    "default_value": "User Managed (and not user-created) default service accounts have the Editor\n(roles/editor) role assigned to them to support GCP services they offer.\nBy default, there are no roles assigned to User Managed User created service\naccounts.",
    "additional_information": "Default (user-managed but not user-created) service accounts have the Editor\n(roles/editor) role assigned to them to support GCP services they offer. Such\nService accounts are: PROJECT_NUMBER-compute@developer.gserviceaccount.com,\nPROJECT_ID@appspot.gserviceaccount.com.",
    "detection_commands": [
      "gcloud projects get-iam-policy PROJECT_ID --format json > iam.json"
    ],
    "remediation_commands": [
      "gcloud projects get-iam-policy PROJECT_ID --format json > iam.json",
      "gcloud projects set-iam-policy PROJECT_ID iam.json"
    ],
    "references": [
      "1. https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/",
      "2. https://cloud.google.com/iam/docs/understanding-roles",
      "3. https://cloud.google.com/iam/docs/understanding-service-accounts"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 28,
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
    "cis_id": "1.6",
    "title": "Ensure That IAM Users Are Not Assigned the Service Account User or Service Account Token Creator Roles at Project Level",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Ensure the Use of Dedicated Administrative Accounts",
    "description": "It is recommended to assign the Service Account User\n(iam.serviceAccountUser) and Service Account Token Creator\n(iam.serviceAccountTokenCreator) roles to a user for a specific service account\nrather than assigning the role to a user at project level.",
    "rationale": "A service account is a special Google account that belongs to an application or a virtual\nmachine (VM), instead of to an individual end-user. Application/VM-Instance uses the\nservice account to call the service's Google API so that users aren't directly involved. In\naddition to being an identity, a service account is a resource that has IAM policies\nattached to it. These policies determine who can use the service account.\nUsers with IAM roles to update the App Engine and Compute Engine instances (such as\nApp Engine Deployer or Compute Instance Admin) can effectively run code as the\nservice accounts used to run these instances, and indirectly gain access to all the\nresources for which the service accounts have access. Similarly, SSH access to a\nCompute Engine instance may also provide the ability to execute code as that\ninstance/Service account.\nBased on business needs, there could be multiple user-managed service accounts\nconfigured for a project. Granting the iam.serviceAccountUser or\niam.serviceAccountTokenCreator roles to a user for a project gives the user access\nto all service accounts in the project, including service accounts that may be created in\nthe future. This can result in elevation of privileges by using service accounts and\ncorresponding Compute Engine instances.\nIn order to implement least privileges best practices, IAM users should not be\nassigned the Service Account User or Service Account Token Creator roles at\nthe project level. Instead, these roles should be assigned to a user for a specific service\naccount, giving that user access to the service account. The Service Account User\nallows a user to bind a service account to a long-running job service, whereas the\nService Account Token Creator role allows a user to directly impersonate (or\nassert) the identity of a service account.",
    "impact": "After revoking Service Account User or Service Account Token Creator roles at\nthe project level from all impacted user account(s), these roles should be assigned to a\nuser(s) for specific service account(s) according to business needs.",
    "audit": "From Google Cloud Console\n1. Go to the IAM page in the GCP Console by visiting\nhttps://console.cloud.google.com/iam-admin/iam\n2. Click on the filter table text bar, Type Role: Service Account User.\n3. Ensure no user is listed as a result of the filter.\n4. Click on the filter table text bar, Type Role: Service Account Token\nCreator.\n5. Ensure no user is listed as a result of the filter.\nFrom Google Cloud CLI\nTo ensure IAM users are not assigned Service Account User role at the project level:\ngcloud projects get-iam-policy PROJECT_ID --format json | jq\n'.bindings[].role' | grep \"roles/iam.serviceAccountUser\"\ngcloud projects get-iam-policy PROJECT_ID --format json | jq\n'.bindings[].role' | grep \"roles/iam.serviceAccountTokenCreator\"\nThese commands should not return any output.",
    "expected_response": "3. Ensure no user is listed as a result of the filter.\n5. Ensure no user is listed as a result of the filter.\nTo ensure IAM users are not assigned Service Account User role at the project level:\nThese commands should not return any output.",
    "remediation": "From Google Cloud Console\n1. Go to the IAM page in the GCP Console by visiting:\nhttps://console.cloud.google.com/iam-admin/iam.\n2. Click on the filter table text bar. Type Role: Service Account User\n3. Click the Delete Bin icon in front of the role Service Account User for every\nuser listed as a result of a filter.\n4. Click on the filter table text bar. Type Role: Service Account Token Creator\n5. Click the Delete Bin icon in front of the role Service Account Token\nCreator for every user listed as a result of a filter.\nFrom Google Cloud CLI\n1. Using a text editor, remove the bindings with the\nroles/iam.serviceAccountUser or\nroles/iam.serviceAccountTokenCreator.\nFor example, you can use the iam.json file shown below as follows:\n{\n\"bindings\": [\n{\n\"members\": [\n\"serviceAccount:our-project-123@appspot.gserviceaccount.com\",\n],\n\"role\": \"roles/appengine.appViewer\"\n},\n{\n\"members\": [\n\"user:email1@gmail.com\"\n],\n\"role\": \"roles/owner\"\n},\n{\n\"members\": [\n\"serviceAccount:our-project-123@appspot.gserviceaccount.com\",\n\"serviceAccount:123456789012-compute@developer.gserviceaccount.com\"\n],\n\"role\": \"roles/editor\"\n}\n],\n\"etag\": \"BwUjMhCsNvY=\"\n}\n2. Update the project's IAM policy:\ngcloud projects set-iam-policy PROJECT_ID iam.json",
    "default_value": "By default, users do not have the Service Account User or Service Account Token\nCreator role assigned at project level.",
    "additional_information": "To assign the role roles/iam.serviceAccountUser or\nroles/iam.serviceAccountTokenCreator to a user role on a service account instead\nof a project:\n1. Go to https://console.cloud.google.com/projectselector/iam-\nadmin/serviceaccounts\n2. Select Target Project\n3. Select target service account. Click Permissions on the top bar. It will open\npermission pane on right side of the page\n4. Add desired members with Service Account User or Service Account\nToken Creator role.",
    "detection_commands": [
      "gcloud projects get-iam-policy PROJECT_ID --format json | jq '.bindings[].role' | grep \"roles/iam.serviceAccountUser\" gcloud projects get-iam-policy PROJECT_ID --format json | jq '.bindings[].role' | grep \"roles/iam.serviceAccountTokenCreator\""
    ],
    "remediation_commands": [
      "gcloud projects set-iam-policy PROJECT_ID iam.json"
    ],
    "references": [
      "1. https://cloud.google.com/iam/docs/service-accounts",
      "2. https://cloud.google.com/iam/docs/granting-roles-to-service-accounts",
      "3. https://cloud.google.com/iam/docs/understanding-roles",
      "4. https://cloud.google.com/iam/docs/granting-changing-revoking-access",
      "5. https://console.cloud.google.com/iam-admin/iam"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 32,
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
    "title": "Ensure User-Managed/External Keys for Service Accounts Are Rotated Every 90 Days or Fewer",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "iam",
    "domain": "Identity and Access Management",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Service Account keys consist of a key ID (Private_key_Id) and Private key, which are\nused to sign programmatic requests users make to Google cloud services accessible to\nthat particular service account. It is recommended that all Service Account keys are\nregularly rotated.",
    "rationale": "Rotating Service Account keys will reduce the window of opportunity for an access key\nthat is associated with a compromised or terminated account to be used. Service\nAccount keys should be rotated to ensure that data cannot be accessed with an old key\nthat might have been lost, cracked, or stolen.\nEach service account is associated with a key pair managed by Google Cloud Platform\n(GCP). It is used for service-to-service authentication within GCP. Google rotates the\nkeys daily.\nGCP provides the option to create one or more user-managed (also called external key\npairs) key pairs for use from outside GCP (for example, for use with Application Default\nCredentials). When a new key pair is created, the user is required to download the\nprivate key (which is not retained by Google). With external keys, users are responsible\nfor keeping the private key secure and other management operations such as key\nrotation. External keys can be managed by the IAM API, gcloud command-line tool, or\nthe Service Accounts page in the Google Cloud Platform Console. GCP facilitates up to\n10 external service account keys per service account to facilitate key rotation.",
    "impact": "Rotating service account keys will break communication for dependent applications.\nDependent applications need to be configured manually with the new key ID displayed\nin the Service account keys section and the private key downloaded by the user.",
    "audit": "From Google Cloud Console\n1. Go to APIs & Services\\Credentials using\nhttps://console.cloud.google.com/apis/credentials\n2. In the section Service Account Keys, for every External (user-managed)\nservice account key listed ensure the creation date is within the past 90 days.\nFrom Google Cloud CLI\n1. List all Service accounts from a project.\ngcloud iam service-accounts list\n2. For every service account list service account keys.\ngcloud iam service-accounts keys list --iam-account\n[Service_Account_Email_Id] --format=json\n3. Ensure every service account key for a service account has a\n\"validAfterTime\" value within the past 90 days.",
    "expected_response": "service account key listed ensure the creation date is within the past 90 days.\n3. Ensure every service account key for a service account has a",
    "remediation": "From Google Cloud Console\nDelete any external (user-managed) Service Account Key older than 90 days:\n1. Go to APIs & Services\\Credentials using\nhttps://console.cloud.google.com/apis/credentials\n2. In the Section Service Account Keys, for every external (user-managed)\nservice account key where creation date is greater than or equal to the past\n90 days, click Delete Bin Icon to Delete Service Account key\nCreate a new external (user-managed) Service Account Key for a Service\nAccount:\n1. Go to APIs & Services\\Credentials using\nhttps://console.cloud.google.com/apis/credentials\n2. Click Create Credentials and Select Service Account Key.\n3. Choose the service account in the drop-down list for which an External (user-\nmanaged) Service Account key needs to be created.\n4. Select the desired key type format among JSON or P12.\n5. Click Create. It will download the private key. Keep it safe.\n6. Click Close if prompted.\n7. The site will redirect to the APIs & Services\\Credentials page. Make a note\nof the new ID displayed in the Service account keys section.",
    "default_value": "GCP does not provide an automation option for External (user-managed) Service key\nrotation.",
    "additional_information": "For user-managed Service Account key(s), key management is entirely the user's\nresponsibility.",
    "detection_commands": [
      "gcloud iam service-accounts list",
      "gcloud iam service-accounts keys list --iam-account"
    ],
    "remediation_commands": [
      "Create a new external (user-managed) Service Account Key for a Service"
    ],
    "references": [
      "1. https://cloud.google.com/iam/docs/understanding-service-",
      "accounts#managing_service_account_keys",
      "2. https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/keys/list",
      "3. https://cloud.google.com/iam/docs/service-accounts"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 36,
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
    "title": "Ensure That Separation of Duties Is Enforced While Assigning Service Account Related Roles to Users",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days_click_delete_bin_icon_to_delete_service_account_key",
    "domain": "days, click Delete Bin Icon to Delete Service Account key",
    "description": "It is recommended that the principle of 'Separation of Duties' is enforced while assigning\nservice-account related roles to users.",
    "rationale": "The built-in/predefined IAM role Service Account admin allows the user/identity to\ncreate, delete, and manage service account(s). The built-in/predefined IAM role\nService Account User allows the user/identity (with adequate privileges on Compute\nand App Engine) to assign service account(s) to Apps/Compute Instances.\nSeparation of duties is the concept of ensuring that one individual does not have all\nnecessary permissions to be able to complete a malicious action. In Cloud IAM - service\naccounts, this could be an action such as using a service account to access resources\nthat user should not normally have access to.\nSeparation of duties is a business control typically used in larger organizations, meant\nto help avoid security or privacy incidents and errors. It is considered best practice.\nNo user should have Service Account Admin and Service Account User roles\nassigned at the same time.",
    "impact": "The removed role should be assigned to a different user based on business needs.",
    "audit": "From Google Cloud Console\n1. Go to IAM & Admin/IAM using https://console.cloud.google.com/iam-\nadmin/iam.\n2. Ensure no member has the roles Service Account Admin and Service\naccount User assigned together.\nFrom Google Cloud CLI\n1. List all users and role assignments:\ngcloud projects get-iam-policy [Project_ID] --format json | \\\njq -r '[\n([\"Service_Account_Admin_and_User\"] | (., map(length*\"-\"))),\n(\n[\n.bindings[] |\nselect(.role == \"roles/iam.serviceAccountAdmin\" or .role ==\n\"roles/iam.serviceAccountUser\").members[]\n] |\ngroup_by(.) |\nmap({User: ., Count: length}) |\n.[] |\nselect(.Count == 2).User |\nunique\n)\n] |\n.[] |\n@tsv'\n2. All common users listed under Service_Account_Admin_and_User are\nassigned both the roles/iam.serviceAccountAdmin and\nroles/iam.serviceAccountUser roles.",
    "expected_response": "2. Ensure no member has the roles Service Account Admin and Service",
    "remediation": "From Google Cloud Console\n1. Go to IAM & Admin/IAM using https://console.cloud.google.com/iam-\nadmin/iam.\n2. For any member having both Service Account Admin and Service account\nUser roles granted/assigned, click the Delete Bin icon to remove either role\nfrom the member.\nRemoval of a role should be done based on the business requirements.",
    "additional_information": "Users granted with Owner (roles/owner) and Editor (roles/editor) have privileges\nequivalent to Service Account Admin and Service Account User. To avoid the\nmisuse, Owner and Editor roles should be granted to very limited users and Use of\nthese primitive privileges should be minimal. These requirements are addressed in\nseparate recommendations.",
    "detection_commands": [
      "gcloud projects get-iam-policy [Project_ID] --format json |",
      "select(.role == \"roles/iam.serviceAccountAdmin\" or .role == \"roles/iam.serviceAccountUser\").members[]",
      "select(.Count == 2).User |"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.google.com/iam/docs/service-accounts",
      "2. https://cloud.google.com/iam/docs/understanding-roles",
      "3. https://cloud.google.com/iam/docs/granting-roles-to-service-accounts"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 39,
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
    "cis_id": "1.9",
    "title": "Ensure That Cloud KMS Cryptokeys Are Not Anonymously or Publicly Accessible",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "days_click_delete_bin_icon_to_delete_service_account_key",
    "domain": "days, click Delete Bin Icon to Delete Service Account key",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "It is recommended that the IAM policy on Cloud KMS cryptokeys should restrict\nanonymous and/or public access.",
    "rationale": "Granting permissions to allUsers or allAuthenticatedUsers allows anyone to\naccess the dataset. Such access might not be desirable if sensitive data is stored at the\nlocation. In this case, ensure that anonymous and/or public access to a Cloud KMS\ncryptokey is not allowed.",
    "impact": "Removing the binding for allUsers and allAuthenticatedUsers members denies\naccessing cryptokeys to anonymous or public users.",
    "audit": "From Google Cloud CLI\n1. List all Cloud KMS Cryptokeys.\ngcloud kms keys list --keyring=[key_ring_name] --location=global --\nformat=json | jq '.[].name'\n2. Ensure the below command's output does not contain allUsers or\nallAuthenticatedUsers.\ngcloud kms keys get-iam-policy [key_name] --keyring=[key_ring_name] --\nlocation=global --format=json | jq '.bindings[].members[]'",
    "expected_response": "2. Ensure the below command's output does not contain allUsers or",
    "remediation": "From Google Cloud CLI\n1. List all Cloud KMS Cryptokeys.\ngcloud kms keys list --keyring=[key_ring_name] --location=global --\nformat=json | jq '.[].name'\n2. Remove IAM policy binding for a KMS key to remove access to allUsers and\nallAuthenticatedUsers using the below command.\ngcloud kms keys remove-iam-policy-binding [key_name] --\nkeyring=[key_ring_name] --location=global --member='allAuthenticatedUsers' --\nrole='[role]'\ngcloud kms keys remove-iam-policy-binding [key_name] --\nkeyring=[key_ring_name] --location=global --member='allUsers' --role='[role]'",
    "default_value": "By default Cloud KMS does not allow access to allUsers or allAuthenticatedUsers.",
    "additional_information": "[key_ring_name] : Is the resource ID of the key ring, which is the fully-qualified Key ring\nname. This value is case-sensitive and in the form:\nprojects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING\nYou can retrieve the key ring resource ID using the Cloud Console:\n1. Open the Cryptographic Keys page in the Cloud Console.\n2. For the key ring whose resource ID you are retrieving, click the More icon (3\nvertical dots).\n3. Click Copy Resource ID. The resource ID for the key ring is copied to your\nclipboard.\n[key_name] : Is the resource ID of the key, which is the fully-qualified CryptoKey name.\nThis value is case-sensitive and in the form:\nprojects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY\nYou can retrieve the key resource ID using the Cloud Console:\n1. Open the Cryptographic Keys page in the Cloud Console.\n2. Click the name of the key ring that contains the key.\n3. For the key whose resource ID you are retrieving, click the More icon (3\nvertical dots).\n4. Click Copy Resource ID. The resource ID for the key is copied to your\nclipboard.\n[role] : The role to remove the member from.",
    "detection_commands": [
      "gcloud kms keys list --keyring=[key_ring_name] --location=global --",
      "gcloud kms keys get-iam-policy [key_name] --keyring=[key_ring_name] --"
    ],
    "remediation_commands": [
      "gcloud kms keys list --keyring=[key_ring_name] --location=global --",
      "gcloud kms keys remove-iam-policy-binding [key_name] --"
    ],
    "references": [
      "1. https://cloud.google.com/sdk/gcloud/reference/kms/keys/remove-iam-policy-",
      "binding",
      "2. https://cloud.google.com/sdk/gcloud/reference/kms/keys/set-iam-policy",
      "3. https://cloud.google.com/sdk/gcloud/reference/kms/keys/get-iam-policy",
      "4. https://cloud.google.com/kms/docs/object-hierarchy#key_resource_id"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 42,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D4"
    ]
  },
  {
    "cis_id": "1.10",
    "title": "Ensure KMS Encryption Keys Are Rotated Within a Period of 90 Days",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "days_click_delete_bin_icon_to_delete_service_account_key",
    "domain": "days, click Delete Bin Icon to Delete Service Account key",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Google Cloud Key Management Service stores cryptographic keys in a hierarchical\nstructure designed for useful and elegant access control management.\nThe format for the rotation schedule depends on the client library that is used. For the\ngcloud command-line tool, the next rotation time must be in ISO or RFC3339 format, and\nthe rotation period must be in the form INTEGER[UNIT], where units can be one of\nseconds (s), minutes (m), hours (h) or days (d).",
    "rationale": "Set a key rotation period and starting time. A key can be created with a specified\nrotation period, which is the time between when new key versions are generated\nautomatically. A key can also be created with a specified next rotation time. A key is a\nnamed object representing a cryptographic key used for a specific purpose. The key\nmaterial, the actual bits used for encryption, can change over time as new key\nversions are created.\nA key is used to protect some corpus of data. A collection of files could be encrypted\nwith the same key and people with decrypt permissions on that key would be able to\ndecrypt those files. Therefore, it's necessary to make sure the rotation period is set\nto a specific time.",
    "impact": "After a successful key rotation, the older key version is required in order to decrypt the\ndata encrypted by that previous key version.",
    "audit": "From Google Cloud Console\n1. Go to Cryptographic Keys by visiting:\nhttps://console.cloud.google.com/security/kms.\n2. Click on each key ring, then ensure each key in the keyring has Next Rotation\nset for less than 90 days from the current date.\nFrom Google Cloud CLI\n1. Ensure rotation is scheduled by ROTATION_PERIOD and NEXT_ROTATION_TIME\nfor each key :\ngcloud kms keys list --keyring=<KEY_RING> --location=<LOCATION> --\nformat=json'(rotationPeriod)'\nEnsure outcome values for rotationPeriod and nextRotationTime satisfy the below\ncriteria:\nrotationPeriod is <= 129600m\nrotationPeriod is <= 7776000s\nrotationPeriod is <= 2160h\nrotationPeriod is <= 90d\nnextRotationTime is <= 90days from current DATE",
    "expected_response": "2. Click on each key ring, then ensure each key in the keyring has Next Rotation\n1. Ensure rotation is scheduled by ROTATION_PERIOD and NEXT_ROTATION_TIME\nEnsure outcome values for rotationPeriod and nextRotationTime satisfy the below",
    "remediation": "From Google Cloud Console\n1. Go to Cryptographic Keys by visiting:\nhttps://console.cloud.google.com/security/kms.\n2. Click on the specific key ring\n3. From the list of keys, choose the specific key and Click on Right side pop up\nthe blade (3 dots).\n4. Click on Edit rotation period.\n5. On the pop-up window, Select a new rotation period in days which should\nbe less than 90 and then choose Starting on date (date from which the rotation\nperiod begins).\nFrom Google Cloud CLI\n1. Update and schedule rotation by ROTATION_PERIOD and NEXT_ROTATION_TIME\nfor each key:\ngcloud kms keys update new --keyring=KEY_RING --location=LOCATION --next-\nrotation-time=NEXT_ROTATION_TIME --rotation-period=ROTATION_PERIOD",
    "default_value": "By default, KMS encryption keys are rotated every 90 days.",
    "additional_information": "• Key rotation does NOT re-encrypt already encrypted data with the newly\ngenerated key version. If you suspect unauthorized use of a key, you should re-\nencrypt the data protected by that key and then disable or schedule destruction\nof the prior key version.\n• It is not recommended to rely solely on irregular rotation, but rather to use\nirregular rotation if needed in conjunction with a regular rotation schedule.",
    "detection_commands": [
      "gcloud kms keys list --keyring=<KEY_RING> --location=<LOCATION> --"
    ],
    "remediation_commands": [
      "gcloud kms keys update new --keyring=KEY_RING --location=LOCATION --next-"
    ],
    "references": [
      "1. https://cloud.google.com/kms/docs/key-rotation#frequency_of_key_rotation",
      "2. https://cloud.google.com/kms/docs/re-encrypt-data"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 45,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "key_management"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D5"
    ]
  },
  {
    "cis_id": "1.11",
    "title": "Ensure That Separation of Duties Is Enforced While Assigning KMS Related Roles to Users",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days_automated",
    "domain": "Days (Automated)",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "It is recommended that the principle of 'Separation of Duties' is enforced while assigning\nKMS related roles to users.",
    "rationale": "The built-in/predefined IAM role Cloud KMS Admin allows the user/identity to create,\ndelete, and manage service account(s). The built-in/predefined IAM role Cloud KMS\nCryptoKey Encrypter/Decrypter allows the user/identity (with adequate privileges\non concerned resources) to encrypt and decrypt data at rest using an encryption key(s).\nThe built-in/predefined IAM role Cloud KMS CryptoKey Encrypter allows the\nuser/identity (with adequate privileges on concerned resources) to encrypt data at rest\nusing an encryption key(s). The built-in/predefined IAM role Cloud KMS CryptoKey\nDecrypter allows the user/identity (with adequate privileges on concerned resources)\nto decrypt data at rest using an encryption key(s).\nSeparation of duties is the concept of ensuring that one individual does not have all\nnecessary permissions to be able to complete a malicious action. In Cloud KMS, this\ncould be an action such as using a key to access and decrypt data a user should not\nnormally have access to. Separation of duties is a business control typically used in\nlarger organizations, meant to help avoid security or privacy incidents and errors. It is\nconsidered best practice.\nNo user(s) should have Cloud KMS Admin and any of the Cloud KMS CryptoKey\nEncrypter/Decrypter, Cloud KMS CryptoKey Encrypter, Cloud KMS CryptoKey\nDecrypter roles assigned at the same time.",
    "impact": "Removed roles should be assigned to another user based on business needs.",
    "audit": "From Google Cloud Console\n1. Go to IAM & Admin/IAM by visiting: https://console.cloud.google.com/iam-\nadmin/iam\n2. Ensure no member has the roles Cloud KMS Admin and any of the Cloud KMS\nCryptoKey Encrypter/Decrypter, Cloud KMS CryptoKey Encrypter, Cloud\nKMS CryptoKey Decrypter assigned.\nFrom Google Cloud CLI\n1. List all users and role assignments:\ngcloud projects get-iam-policy PROJECT_ID\n2. Ensure that there are no common users found in the member section for roles\ncloudkms.admin and any one of Cloud KMS CryptoKey\nEncrypter/Decrypter, Cloud KMS CryptoKey Encrypter, Cloud KMS\nCryptoKey Decrypter",
    "expected_response": "2. Ensure no member has the roles Cloud KMS Admin and any of the Cloud KMS\n2. Ensure that there are no common users found in the member section for roles",
    "remediation": "From Google Cloud Console\n1. Go to IAM & Admin/IAM using https://console.cloud.google.com/iam-\nadmin/iam\n2. For any member having Cloud KMS Admin and any of the Cloud KMS\nCryptoKey Encrypter/Decrypter, Cloud KMS CryptoKey Encrypter, Cloud\nKMS CryptoKey Decrypter roles granted/assigned, click the Delete Bin icon\nto remove the role from the member.\nNote: Removing a role should be done based on the business requirement.",
    "additional_information": "Users granted with Owner (roles/owner) and Editor (roles/editor) have privileges\nequivalent to Cloud KMS Admin and Cloud KMS CryptoKey Encrypter/Decrypter.\nTo avoid misuse, Owner and Editor roles should be granted to a very limited group of\nusers. Use of these primitive privileges should be minimal.",
    "detection_commands": [
      "gcloud projects get-iam-policy PROJECT_ID"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.google.com/kms/docs/separation-of-duties"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 48,
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
    "cis_id": "1.12",
    "title": "Ensure API Keys Only Exist for Active Services",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days_automated",
    "domain": "Days (Automated)",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "API Keys should only be used for services in cases where other authentication methods\nare unavailable. Unused keys with their permissions in tact may still exist within a\nproject. Keys are insecure because they can be viewed publicly, such as from within a\nbrowser, or they can be accessed on a device where the key resides. It is\nrecommended to use standard authentication flow instead.",
    "rationale": "To avoid the security risk in using API keys, it is recommended to use standard\nauthentication flow instead. Security risks involved in using API-Keys appear below:\n• API keys are simple encrypted strings\n• API keys do not identify the user or the application making the API request\n• API keys are typically accessible to clients, making it easy to discover and steal\nan API key",
    "impact": "Deleting an API key will break dependent applications (if any).",
    "audit": "From Console:\n1. From within the Project you wish to audit Go to APIs &\nServices\\Credentials.\n2. In the section API Keys, no API key should be listed.\nFrom Google Cloud Command Line\n1. Run the following from within the project you wish to audit\ngcloud services api-keys list --filter\n1. There should be no keys listed at the project level.",
    "expected_response": "2. In the section API Keys, no API key should be listed.\n1. There should be no keys listed at the project level.",
    "remediation": "From Console:\n1. Go to APIs & Services\\Credentials using\nhttps://console.cloud.google.com/apis/credentials.\n2. In the section API Keys, to delete API Keys: Click the Delete Bin Icon in front\nof every API Key Name.\nFrom Google Cloud Command Line\n1. Run the following from within the project you wish to audit\ngcloud services api-keys list --filter\n1. Run the following command, providing the ID of the key or fully qualified identifier\nfor the key for <key_id>:\ngcloud services api-keys delete <key_id>",
    "default_value": "By default, API keys are not created for a project.",
    "additional_information": "Google recommends using the standard authentication flow instead of using API keys.\nHowever, there are limited cases where API keys are more appropriate. For example, if\nthere is a mobile application that needs to use the Google Cloud Translation API, but\ndoesn't otherwise need a backend server, API keys are the simplest way to authenticate\nto that API.\nIf a business requires API keys to be used, then the API keys should be secured\nproperly.",
    "detection_commands": [
      "gcloud services api-keys list --filter"
    ],
    "remediation_commands": [
      "gcloud services api-keys list --filter",
      "gcloud services api-keys delete <key_id>"
    ],
    "references": [
      "1. https://cloud.google.com/docs/authentication/api-keys",
      "2. https://cloud.google.com/sdk/gcloud/reference/services/api-keys/list",
      "3. https://cloud.google.com/docs/authentication",
      "4. https://cloud.google.com/sdk/gcloud/reference/services/api-keys/delete"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 51,
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
    "cis_id": "1.13",
    "title": "Ensure API Keys Are Restricted To Use by Only Specified Hosts and Apps",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "days_automated",
    "domain": "Days (Automated)",
    "subdomain": "Disable Any Unassociated Accounts",
    "description": "API Keys should only be used for services in cases where other authentication methods\nare unavailable. In this case, unrestricted keys are insecure because they can be\nviewed publicly, such as from within a browser, or they can be accessed on a device\nwhere the key resides. It is recommended to restrict API key usage to trusted hosts,\nHTTP referrers and apps. It is recommended to use the more secure standard\nauthentication flow instead.",
    "rationale": "Security risks involved in using API-Keys appear below:\n• API keys are simple encrypted strings\n• API keys do not identify the user or the application making the API request\n• API keys are typically accessible to clients, making it easy to discover and steal\nan API key\nIn light of these potential risks, Google recommends using the standard authentication\nflow instead of API keys. However, there are limited cases where API keys are more\nappropriate. For example, if there is a mobile application that needs to use the Google\nCloud Translation API, but doesn't otherwise need a backend server, API keys are the\nsimplest way to authenticate to that API.\nIn order to reduce attack vectors, API-Keys can be restricted only to trusted hosts,\nHTTP referrers and applications.",
    "impact": "Setting Application Restrictions may break existing application functioning, if not\ndone carefully.",
    "audit": "From Google Cloud Console\n1. Go to APIs & Services\\Credentials using\nhttps://console.cloud.google.com/apis/credentials\n2. In the section API Keys, Click the API Key Name. The API Key properties\ndisplay on a new page.\n3. For every API Key, ensure the section Key restrictions parameter\nApplication restrictions is not set to None.\nOr,\n1. Ensure Application restrictions is set to HTTP referrers and the referrer\nis not set to wild-cards (* or *.[TLD] or *.[TLD]/*) allowing access to\nany/wide HTTP referrer(s)\nOr,\n1. Ensure Application restrictions is set to IP addresses and referrer is not\nset to any host (0.0.0.0 or 0.0.0.0/0 or ::0)\nFrom Google Cloud Command Line\n1. Run the following from within the project you wish to audit\ngcloud services api-keys list --filter=\"-restrictions:*\" --\nformat=\"table[box](displayName:label='Key With No Restrictions')",
    "expected_response": "3. For every API Key, ensure the section Key restrictions parameter\n1. Ensure Application restrictions is set to HTTP referrers and the referrer\n1. Ensure Application restrictions is set to IP addresses and referrer is not",
    "remediation": "From Google Cloud Console\nLeaving Keys in Place\n1. Go to APIs & Services\\Credentials using\nhttps://console.cloud.google.com/apis/credentials\n2. In the section API Keys, Click the API Key Name. The API Key properties\ndisplay on a new page.\n3. In the Key restrictions section, set the application restrictions to any of HTTP\nreferrers, IP addresses, Android apps, iOS apps.\n4. Click Save.\n5. Repeat steps 2,3,4 for every unrestricted API key.\nNote: Do not set HTTP referrers to wild-cards (* or *.[TLD] or .[TLD]/) allowing\naccess to any/wide HTTP referrer(s)\nDo not set IP addresses and referrer to any host (0.0.0.0 or 0.0.0.0/0\nor ::0)\nRemoving Keys\nAnother option is to remove the keys entirely.\n1. Go to APIs & Services\\Credentials using\nhttps://console.cloud.google.com/apis/credentials\n2. In the section API Keys, select the checkbox next to each key you wish to\nremove\n3. Select Delete and confirm.",
    "default_value": "By default, Application Restrictions are set to None.",
    "detection_commands": [
      "gcloud services api-keys list --filter=\"-restrictions:*\" --"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.google.com/docs/authentication/api-keys",
      "2. https://cloud.google.com/sdk/gcloud/reference/services/api-keys/list",
      "3. https://cloud.google.com/sdk/gcloud/reference/services/api-keys/update"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 54,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D4"
    ]
  },
  {
    "cis_id": "1.14",
    "title": "Ensure API Keys Are Restricted to Only APIs That Application Needs Access",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days_automated",
    "domain": "Days (Automated)",
    "subdomain": "Apply Secure Design Principles in Application",
    "description": "API Keys should only be used for services in cases where other authentication methods\nare unavailable. API keys are always at risk because they can be viewed publicly, such\nas from within a browser, or they can be accessed on a device where the key resides. It\nis recommended to restrict API keys to use (call) only APIs required by an application.",
    "rationale": "Security risks involved in using API-Keys are below:\n• API keys are simple encrypted strings\n• API keys do not identify the user or the application making the API request\n• API keys are typically accessible to clients, making it easy to discover and steal\nan API key\nIn light of these potential risks, Google recommends using the standard authentication\nflow instead of API-Keys. However, there are limited cases where API keys are more\nappropriate. For example, if there is a mobile application that needs to use the Google\nCloud Translation API, but doesn't otherwise need a backend server, API keys are the\nsimplest way to authenticate to that API.\nIn order to reduce attack surfaces by providing least privileges, API-Keys can be\nrestricted to use (call) only APIs required by an application.",
    "impact": "Setting API restrictions may break existing application functioning, if not done\ncarefully.",
    "audit": "From Console:\n1. Go to APIs & Services\\Credentials using\nhttps://console.cloud.google.com/apis/credentials\n2. In the section API Keys, Click the API Key Name. The API Key properties\ndisplay on a new page.\n3. For every API Key, ensure the section Key restrictions parameter API\nrestrictions is not set to None.\nOr,\nEnsure API restrictions is not set to Google Cloud APIs\nNote: Google Cloud APIs represents the API collection of all cloud services/APIs\noffered by Google cloud.\nFrom Google Cloud CLI\n1. List all API Keys.\ngcloud services api-keys list\nEach key should have a line that says restrictions: followed by varying parameters\nand NOT have a line saying - service: cloudapis.googleapis.com as shown here\nrestrictions:\napiTargets:\n- service: cloudapis.googleapis.com",
    "expected_response": "3. For every API Key, ensure the section Key restrictions parameter API\nEnsure API restrictions is not set to Google Cloud APIs\nEach key should have a line that says restrictions: followed by varying parameters",
    "remediation": "From Console:\n1. Go to APIs & Services\\Credentials using\nhttps://console.cloud.google.com/apis/credentials\n2. In the section API Keys, Click the API Key Name. The API Key properties\ndisplay on a new page.\n3. In the Key restrictions section go to API restrictions.\n4. Click the Select API drop-down to choose an API.\n5. Click Save.\n6. Repeat steps 2,3,4,5 for every unrestricted API key\nNote: Do not set API restrictions to Google Cloud APIs, as this option allows\naccess to all services offered by Google cloud.\nFrom Google Cloud CLI\n1. List all API keys.\ngcloud services api-keys list\n2. Note the UID of the key to add restrictions to.\n3. Run the update command with the appropriate API target service or flags file with\nAPI target services and methods to add the required restrictions.\nCommand with appropriate API target service:\ngcloud services api-keys update <UID> --api-target=service=<service>\nCommand with flags file:\ngcloud services api-keys update <UID> --flags-file=<flags_file>.yaml\nContent of flags file:\n- --api-target:\nservice: \"foo.service.com\"\n- --api-target:\nservice: \"bar.service.com\"\nmethods:\n- \"foomethod\"\n- \"barmethod\"\nNote: Flags can be found by running:\ngcloud services api-keys update --help\nNote: Services can be found by running:\ngcloud services list\nor in this documentation\nhttps://cloud.google.com/sdk/gcloud/reference/services/api-keys/update",
    "default_value": "By default, API restrictions are set to None.",
    "detection_commands": [
      "gcloud services api-keys list"
    ],
    "remediation_commands": [
      "gcloud services api-keys list",
      "gcloud services api-keys update <UID> --api-target=service=<service>",
      "gcloud services api-keys update <UID> --flags-file=<flags_file>.yaml",
      "gcloud services api-keys update --help",
      "gcloud services list"
    ],
    "references": [
      "1. https://cloud.google.com/docs/authentication/api-keys",
      "2. https://cloud.google.com/apis/docs/overview"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 57,
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
    "cis_id": "1.15",
    "title": "Ensure API Keys Are Rotated Every 90 Days",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "days_automated",
    "domain": "Days (Automated)",
    "subdomain": "Apply Secure Design Principles in Application",
    "description": "API Keys should only be used for services in cases where other authentication methods\nare unavailable. If they are in use it is recommended to rotate API keys every 90 days.",
    "rationale": "Security risks involved in using API-Keys are listed below:\n• API keys are simple encrypted strings\n• API keys do not identify the user or the application making the API request\n• API keys are typically accessible to clients, making it easy to discover and steal\nan API key\nBecause of these potential risks, Google recommends using the standard authentication\nflow instead of API Keys. However, there are limited cases where API keys are more\nappropriate. For example, if there is a mobile application that needs to use the Google\nCloud Translation API, but doesn't otherwise need a backend server, API keys are the\nsimplest way to authenticate to that API.\nOnce a key is stolen, it has no expiration, meaning it may be used indefinitely unless the\nproject owner revokes or regenerates the key. Rotating API keys will reduce the window\nof opportunity for an access key that is associated with a compromised or terminated\naccount to be used.\nAPI keys should be rotated to ensure that data cannot be accessed with an old key that\nmight have been lost, cracked, or stolen.",
    "impact": "Regenerating Key may break existing client connectivity as the client will try to\nconnect with older API keys they have stored on devices.",
    "audit": "From Google Cloud Console\n1. Go to APIs & Services\\Credentials using\nhttps://console.cloud.google.com/apis/credentials\n2. In the section API Keys, for every key ensure the creation date is less than\n90 days.\nFrom Google Cloud CLI\nTo list keys, use the command\ngcloud services api-keys list\nEnsure the date in createTime is within 90 days.",
    "expected_response": "2. In the section API Keys, for every key ensure the creation date is less than\nEnsure the date in createTime is within 90 days.",
    "remediation": "From Google Cloud Console\n1. Go to APIs & Services\\Credentials using\nhttps://console.cloud.google.com/apis/credentials\n2. In the section API Keys, Click the API Key Name. The API Key properties\ndisplay on a new page.\n3. Click REGENERATE KEY to rotate API key.\n4. Click Save.\n5. Repeat steps 2,3,4 for every API key that has not been rotated in the last 90\ndays.\nNote: Do not set HTTP referrers to wild-cards (* or *.[TLD] or .[TLD]/) allowing access\nto any/wide HTTP referrer(s)\nDo not set IP addresses and referrer to any host (0.0.0.0 or 0.0.0.0/0 or\n::0)\nFrom Google Cloud CLI\nThere is not currently a way to regenerate and API key using gcloud commands. To\n'regenerate' a key you will need to create a new one, duplicate the restrictions from the\nkey being rotated, and delete the old key.\n1. List existing keys.\ngcloud services api-keys list\n2. Note the UID and restrictions of the key to regenerate.\n3. Run this command to create a new API key. <key_name> is the display name of\nthe new key.\ngcloud services api-keys create --display-name=\"<key_name>\"\nNote the UID of the newly created key\n4. Run the update command to add required restrictions.\nNote - the restriction may vary for each key. Refer to this documentation for the\nappropriate flags.\nhttps://cloud.google.com/sdk/gcloud/reference/services/api-keys/update\ngcloud services api-keys update <UID of new key>\n5. Delete the old key.\ngcloud services api-keys delete <UID of old key>",
    "additional_information": "There is no option to automatically regenerate (rotate) API keys periodically.",
    "detection_commands": [
      "gcloud services api-keys list"
    ],
    "remediation_commands": [
      "gcloud services api-keys list",
      "gcloud services api-keys create --display-name=\"<key_name>\"",
      "gcloud services api-keys update <UID of new key>",
      "gcloud services api-keys delete <UID of old key>"
    ],
    "references": [
      "1. https://developers.google.com/maps/api-security-best-practices#regenerate-",
      "apikey",
      "2. https://cloud.google.com/sdk/gcloud/reference/services/api-keys/update"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 60,
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
    "cis_id": "1.16",
    "title": "Ensure Essential Contacts is Configured for Organization",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Apply Secure Design Principles in Application",
    "description": "It is recommended that Essential Contacts is configured to designate email addresses\nfor Google Cloud services to notify of important technical or security information.",
    "rationale": "Many Google Cloud services, such as Cloud Billing, send out notifications to share\nimportant information with Google Cloud users. By default, these notifications are sent\nto members with certain Identity and Access Management (IAM) roles. With Essential\nContacts, you can customize who receives notifications by providing your own list of\ncontacts.",
    "impact": "There is no charge for Essential Contacts except for the 'Technical Incidents' category\nthat is only available to premium support customers.",
    "audit": "From Google Cloud Console\n1. Go to Essential Contacts by visiting https://console.cloud.google.com/iam-\nadmin/essential-contacts\n2. Make sure the organization appears in the resource selector at the top of the\npage. The resource selector tells you what project, folder, or organization you are\ncurrently managing contacts for.\n3. Ensure that appropriate email addresses are configured for each of the following\nnotification categories:\n• Legal\n• Security\n• Suspension\n• Technical\nAlternatively, appropriate email addresses can be configured for the All notification\ncategory to receive all possible important notifications.\nFrom Google Cloud CLI\n1. To list all configured organization Essential Contacts run a command:\ngcloud essential-contacts list --organization=<ORGANIZATION_ID>\n2. Ensure at least one appropriate email address is configured for each of the\nfollowing notification categories:\n• LEGAL\n• SECURITY\n• SUSPENSION\n• TECHNICAL\nAlternatively, appropriate email addresses can be configured for the ALL notification\ncategory to receive all possible important notifications.",
    "expected_response": "3. Ensure that appropriate email addresses are configured for each of the following\n2. Ensure at least one appropriate email address is configured for each of the",
    "remediation": "From Google Cloud Console\n1. Go to Essential Contacts by visiting https://console.cloud.google.com/iam-\nadmin/essential-contacts\n2. Make sure the organization appears in the resource selector at the top of the\npage. The resource selector tells you what project, folder, or organization you are\ncurrently managing contacts for.\n3. Click +Add contact\n4. In the Email and Confirm Email fields, enter the email address of the contact.\n5. From the Notification categories drop-down menu, select the notification\ncategories that you want the contact to receive communications for.\n6. Click Save\nFrom Google Cloud CLI\n1. To add an organization Essential Contacts run a command:\ngcloud essential-contacts create --email=\"<EMAIL>\" \\\n--notification-categories=\"<NOTIFICATION_CATEGORIES>\" \\\n--organization=<ORGANIZATION_ID>",
    "default_value": "By default, there are no Essential Contacts configured.\nIn the absence of an Essential Contact, the following IAM roles are used to identify\nusers to notify for the following categories:\n• Legal: roles/billing.admin\n• Security: roles/resourcemanager.organizationAdmin\n• Suspension: roles/owner\n• Technical: roles/owner\n• Technical Incidents: roles/owner",
    "detection_commands": [
      "gcloud essential-contacts list --organization=<ORGANIZATION_ID>"
    ],
    "remediation_commands": [
      "gcloud essential-contacts create --email=\"<EMAIL>\" --notification-categories=\"<NOTIFICATION_CATEGORIES>\" --organization=<ORGANIZATION_ID>"
    ],
    "references": [
      "1. https://cloud.google.com/resource-manager/docs/managing-notification-contacts"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 63,
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
    "cis_id": "1.17",
    "title": "Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "days",
    "domain": "days",
    "subdomain": "Maintain Contact Information For Reporting Security",
    "description": "Google Cloud Functions allow you to host serverless code that is executed when an\nevent is triggered, without the requiring the management a host operating system.\nThese functions can also store environment variables to be used by the code that may\ncontain authentication or other information that needs to remain confidential.",
    "rationale": "It is recommended to use the Secret Manager, because environment variables are\nstored unencrypted, and accessible for all users who have access to the code.",
    "impact": "There should be no impact on the Cloud Function. There are minor costs after 10,000\nrequests a month to the Secret Manager API as well for a high use of other functions.\nModifying the Cloud Function to use the Secret Manager may prevent it running to\ncompletion.",
    "audit": "Determine if Confidential Information is Stored in your Functions in Cleartext\nFrom Google Cloud Console\n1. Within the project you wish to audit, select the Navigation hamburger menu in the\ntop left. Scroll down to under the heading 'Serverless', then select 'Cloud\nFunctions'\n2. Click on a function name from the list\n3. Open the Variables tab and you will see both buildEnvironmentVariables and\nenvironmentVariables\n4. Review the variables whether they are secrets\n5. Repeat step 3-5 until all functions are reviewed\nFrom Google Cloud CLI\n1. To view a list of your cloud functions run\ngcloud functions list\n2. For each cloud function in the list run the following command.\ngcloud functions describe <function_name>\n3. Review the settings of the buildEnvironmentVariables and environmentVariables.\nDetermine if this is data that should not be publicly accessible.\nDetermine if Secret Manager API is 'Enabled' for your Project\nFrom Google Cloud Console\n1. Within the project you wish to audit, select the Navigation hamburger menu in the\ntop left. Hover over 'APIs & Services' to under the heading 'Serverless', then\nselect 'Enabled APIs & Services' in the menu that opens up.\n2. Click the button '+ Enable APIS and Services'\n3. In the Search bar, search for 'Secret Manager API' and select it.\n4. If it is enabled, the blue box that normally says 'Enable' will instead say 'Manage'.\nFrom Google Cloud CLI\n1. Within the project you wish to audit, run the following command.\ngcloud services list\n2. If 'Secret Manager API' is in the list, it is enabled.",
    "expected_response": "Determine if this is data that should not be publicly accessible.\n4. If it is enabled, the blue box that normally says 'Enable' will instead say 'Manage'.\n2. If 'Secret Manager API' is in the list, it is enabled.",
    "remediation": "Enable Secret Manager API for your Project\nFrom Google Cloud Console\n1. Within the project you wish to enable, select the Navigation hamburger menu in\nthe top left. Hover over 'APIs & Services' to under the heading 'Serverless', then\nselect 'Enabled APIs & Services' in the menu that opens up.\n2. Click the button '+ Enable APIS and Services'\n3. In the Search bar, search for 'Secret Manager API' and select it.\n4. Click the blue box that says 'Enable'.\nFrom Google Cloud CLI\n1. Within the project you wish to enable the API in, run the following command.\ngcloud services enable Secret Manager API\nReviewing Environment Variables That Should Be Migrated to Secret Manager\nFrom Google Cloud Console\n1. Log in to the Google Cloud Web Portal (https://console.cloud.google.com/)\n2. Go to Cloud Functions\n3. Click on a function name from the list\n4. Click on Edit and review the Runtime environment for variables that should be\nsecrets. Leave this list open for the next step.\nFrom Google Cloud CLI\n1. To view a list of your cloud functions run\ngcloud functions list\n2. For each cloud function run the following command.\ngcloud functions describe <function_name>\n3. Review the settings of the buildEnvironmentVariables and environmentVariables.\nKeep this information for the next step.\nMigrating Environment Variables to Secrets within the Secret Manager\nFrom Google Cloud Console\n1. Go to the Secret Manager page in the Cloud Console.\n2. On the Secret Manager page, click Create Secret.\n3. On the Create secret page, under Name, enter the name of the Environment\nVariable you are replacing. This will then be the Secret Variable you will\nreference in your code.\n4. You will also need to add a version. This is the actual value of the variable that\nwill be referenced from the code. To add a secret version when creating the initial\nsecret, in the Secret value field, enter the value from the Environment Variable\nyou are replacing.\n5. Leave the Regions section unchanged.\n6. Click the Create secret button.\n7. Repeat for all Environment Variables\nFrom Google Cloud CLI\n1. Run the following command with the Environment Variable name you are\nreplacing in the <secret-id>. It is most secure to point this command to a file\nwith the Environment Variable value located in it, as if you entered it via\ncommand line it would show up in your shell’s command history.\ngcloud secrets create <secret-id> --data-file=\"/path/to/file.txt\"\nGranting your Runtime's Service Account Access to Secrets\nFrom Google Cloud Console\n1. Within the project containing your runtime login with account that has the\n'roles/secretmanager.secretAccessor' permission.\n2. Select the Navigation hamburger menu in the top left. Hover over 'Security' to\nunder the then select 'Secret Manager' in the menu that opens up.\n3. Click the name of a secret listed in this screen.\n4. If it is not already open, click Show Info Panel in this screen to open the panel.\n5.In the info panel, click Add principal.\n6.In the New principals field, enter the service account your function uses for its\nidentity. (If you need help locating or updating your runtime's service account,\nplease see the 'docs/securing/function-identity#runtime_service_account'\nreference.)\n5. In the Select a role dropdown, choose Secret Manager and then Secret Manager\nSecret Accessor.\nFrom Google Cloud CLI\nAs of the time of writing, using Google CLI to list Runtime variables is only in beta.\nBecause this is likely to change we are not including it here.\nModifying the Code to use the Secrets in Secret Manager\nFrom Google Cloud Console\nThis depends heavily on which language your runtime is in. For the sake of the brevity\nof this recommendation, please see the '/docs/creating-and-accessing-secrets#access'\nreference for language specific instructions.\nFrom Google Cloud CLI\nThis depends heavily on which language your runtime is in. For the sake of the brevity\nof this recommendation, please see the' /docs/creating-and-accessing-secrets#access'\nreference for language specific instructions.\nDeleting the Insecure Environment Variables\nBe certain to do this step last. Removing variables from code actively referencing\nthem will prevent it from completing successfully.\nFrom Google Cloud Console\n1. Select the Navigation hamburger menu in the top left. Hover over 'Security' then\nselect 'Secret Manager' in the menu that opens up.\n2. Click the name of a function. Click Edit.\n3. Click Runtime, build and connections settings to expand the advanced\nconfiguration options.\n4. Click 'Security’. Hover over the secret you want to remove, then click 'Delete'.\n5. Click Next. Click Deploy. The latest version of the runtime will now reference the\nsecrets in Secret Manager.\nFrom Google Cloud CLI\ngcloud functions deploy <Function name>--remove-env-vars <env vars>\nIf you need to find the env vars to remove, they are from the step where ‘gcloud\nfunctions describe <function_name>’ was run.",
    "default_value": "By default Secret Manager is not enabled.",
    "additional_information": "There are slight additional costs to using the Secret Manager API. Review the\ndocumentation to determine your organizations' needs.",
    "detection_commands": [
      "gcloud functions list",
      "gcloud functions describe <function_name>",
      "select 'Enabled APIs & Services' in the menu that opens up.",
      "gcloud services list"
    ],
    "remediation_commands": [
      "select 'Enabled APIs & Services' in the menu that opens up.",
      "gcloud services enable Secret Manager API",
      "gcloud functions list",
      "gcloud functions describe <function_name>",
      "gcloud secrets create <secret-id> --data-file=\"/path/to/file.txt\"",
      "select 'Secret Manager' in the menu that opens up.",
      "gcloud functions deploy <Function name>--remove-env-vars <env vars>"
    ],
    "references": [
      "1. https://cloud.google.com/functions/docs/configuring/env-var#managing_secrets",
      "2. https://cloud.google.com/secret-manager/docs/overview"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 66,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
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
    "cis_id": "2.1",
    "title": "Ensure That Cloud Audit Logging Is Configured Properly",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "description": "It is recommended that Cloud Audit Logging is configured to track all admin activities\nand read, write access to user data.",
    "rationale": "Cloud Audit Logging maintains two audit logs for each project, folder, and organization:\nAdmin Activity and Data Access.\n1. Admin Activity logs contain log entries for API calls or other administrative\nactions that modify the configuration or metadata of resources. Admin Activity\naudit logs are enabled for all services and cannot be configured.\n2. Data Access audit logs record API calls that create, modify, or read user-\nprovided data. These are disabled by default and should be enabled.\nThere are three kinds of Data Access audit log information:\no Admin read: Records operations that read metadata or configuration\ninformation. Admin Activity audit logs record writes of metadata and\nconfiguration information that cannot be disabled.\no Data read: Records operations that read user-provided data.\no Data write: Records operations that write user-provided data.\nIt is recommended to have an effective default audit config configured in such a way\nthat:\n1. logtype is set to DATA_READ (to log user activity tracking) and DATA_WRITES\n(to log changes/tampering to user data).\n2. audit config is enabled for all the services supported by the Data Access audit\nlogs feature.\n3. Logs should be captured for all users, i.e., there are no exempted users in any of\nthe audit config sections. This will ensure overriding the audit config will not\ncontradict the requirement.",
    "impact": "There is no charge for Admin Activity audit logs. Enabling the Data Access audit logs\nmight result in your project being charged for the additional logs usage.",
    "audit": "From Google Cloud Console\n1. Go to Audit Logs by visiting https://console.cloud.google.com/iam-admin/audit.\n2. Ensure that Admin Read, Data Write, and Data Read are enabled for all Google\nCloud services and that no exemptions are allowed.\nFrom Google Cloud CLI\n1. List the Identity and Access Management (IAM) policies for the project, folder, or\norganization:\ngcloud organizations get-iam-policy ORGANIZATION_ID\ngcloud resource-manager folders get-iam-policy FOLDER_ID\ngcloud projects get-iam-policy PROJECT_ID\n2. Policy should have a default auditConfigs section which has the logtype set to\nDATA_WRITES and DATA_READ for all services. Note that projects inherit\nsettings from folders, which in turn inherit settings from the organization. When\ncalled, projects get-iam-policy, the result shows only the policies set in the\nproject, not the policies inherited from the parent folder or organization.\nNevertheless, if the parent folder has Cloud Audit Logging enabled, the project\ndoes as well.\nSample output for default audit configs may look like this:\nauditConfigs:\n- auditLogConfigs:\n- logType: ADMIN_READ\n- logType: DATA_WRITE\n- logType: DATA_READ\nservice: allServices\n3. Any of the auditConfigs sections should not have parameter\n\"exemptedMembers:\" set, which will ensure that Logging is enabled for all users\nand no user is exempted.",
    "expected_response": "2. Ensure that Admin Read, Data Write, and Data Read are enabled for all Google\n2. Policy should have a default auditConfigs section which has the logtype set to\nSample output for default audit configs may look like this:\n3. Any of the auditConfigs sections should not have parameter\n\"exemptedMembers:\" set, which will ensure that Logging is enabled for all users",
    "remediation": "From Google Cloud Console\n1. Go to Audit Logs by visiting https://console.cloud.google.com/iam-admin/audit.\n2. Follow the steps at https://cloud.google.com/logging/docs/audit/configure-data-\naccess to enable audit logs for all Google Cloud services. Ensure that no\nexemptions are allowed.\nFrom Google Cloud CLI\n1. To read the project's IAM policy and store it in a file run a command:\ngcloud projects get-iam-policy PROJECT_ID > /tmp/project_policy.yaml\nAlternatively, the policy can be set at the organization or folder level. If setting the policy\nat the organization level, it is not necessary to also set it for each folder or project.\ngcloud organizations get-iam-policy ORGANIZATION_ID > /tmp/org_policy.yaml\ngcloud resource-manager folders get-iam-policy FOLDER_ID >\n/tmp/folder_policy.yaml\n2. Edit policy in /tmp/policy.yaml, adding or changing only the audit logs\nconfiguration to:\nNote: Admin Activity Logs are enabled by default, and cannot be disabled.\nSo they are not listed in these configuration changes.\nauditConfigs:\n- auditLogConfigs:\n- logType: DATA_WRITE\n- logType: DATA_READ\nservice: allServices\nNote: exemptedMembers: is not set as audit logging should be enabled for all the users\n3. To write new IAM policy run command:\ngcloud organizations set-iam-policy ORGANIZATION_ID /tmp/org_policy.yaml\ngcloud resource-manager folders set-iam-policy FOLDER_ID\n/tmp/folder_policy.yaml\ngcloud projects set-iam-policy PROJECT_ID /tmp/project_policy.yaml\nIf the preceding command reports a conflict with another change, then repeat these\nsteps, starting with the first step.",
    "default_value": "Admin Activity logs are always enabled. They cannot be disabled. Data Access audit\nlogs are disabled by default because they can be quite large.",
    "additional_information": "• Log type DATA_READ is equally important to that of DATA_WRITE to track detailed\nuser activities.\n• BigQuery Data Access logs are handled differently from other data access logs.\nBigQuery logs are enabled by default and cannot be disabled. They do not count\nagainst logs allotment and cannot result in extra logs charges.",
    "detection_commands": [
      "gcloud organizations get-iam-policy ORGANIZATION_ID gcloud resource-manager folders get-iam-policy FOLDER_ID gcloud projects get-iam-policy PROJECT_ID"
    ],
    "remediation_commands": [
      "gcloud projects get-iam-policy PROJECT_ID > /tmp/project_policy.yaml",
      "gcloud organizations get-iam-policy ORGANIZATION_ID > /tmp/org_policy.yaml gcloud resource-manager folders get-iam-policy FOLDER_ID >",
      "gcloud organizations set-iam-policy ORGANIZATION_ID /tmp/org_policy.yaml gcloud resource-manager folders set-iam-policy FOLDER_ID",
      "gcloud projects set-iam-policy PROJECT_ID /tmp/project_policy.yaml"
    ],
    "references": [
      "1. https://cloud.google.com/logging/docs/audit/",
      "2. https://cloud.google.com/logging/docs/audit/configure-data-access"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 72,
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
    "cis_id": "2.2",
    "title": "Ensure That Sinks Are Configured for All Log Entries",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Activate audit logging",
    "description": "It is recommended to create a sink that will export copies of all the log entries. This can\nhelp aggregate logs from multiple projects and export them to a Security Information\nand Event Management (SIEM).",
    "rationale": "Log entries are held in Cloud Logging. To aggregate logs, export them to a SIEM. To\nkeep them longer, it is recommended to set up a log sink. Exporting involves writing a\nfilter that selects the log entries to export, and choosing a destination in Cloud Storage,\nBigQuery, or Cloud Pub/Sub. The filter and destination are held in an object called a\nsink. To ensure all log entries are exported to sinks, ensure that there is no filter\nconfigured for a sink. Sinks can be created in projects, organizations, folders, and billing\naccounts.",
    "impact": "There are no costs or limitations in Cloud Logging for exporting logs, but the export\ndestinations charge for storing or transmitting the log data.",
    "audit": "From Google Cloud Console\n1. Go to Logs Router by visiting https://console.cloud.google.com/logs/router.\n2. For every sink, click the 3-dot button for Menu options and select View sink\ndetails.\n3. Ensure there is at least one sink with an empty Inclusion filter.\n4. Additionally, ensure that the resource configured as Destination exists.\nFrom Google Cloud CLI\n1. Ensure that a sink with an empty filter exists. List the sinks for the project,\nfolder or organization. If sinks are configured at a folder or organization level,\nthey do not need to be configured for each project:\ngcloud logging sinks list --folder=FOLDER_ID | --organization=ORGANIZATION_ID\n| --project=PROJECT_ID\nThe output should list at least one sink with an empty filter.\n2. Additionally, ensure that the resource configured as Destination exists.\nSee https://cloud.google.com/sdk/gcloud/reference/beta/logging/sinks/list for more\ninformation.",
    "expected_response": "3. Ensure there is at least one sink with an empty Inclusion filter.\n4. Additionally, ensure that the resource configured as Destination exists.\n1. Ensure that a sink with an empty filter exists. List the sinks for the project,\nThe output should list at least one sink with an empty filter.\n2. Additionally, ensure that the resource configured as Destination exists.",
    "remediation": "From Google Cloud Console\n1. Go to Logs Router by visiting https://console.cloud.google.com/logs/router.\n2. Click on the arrow symbol with CREATE SINK text.\n3. Fill out the fields for Sink details.\n4. Choose Cloud Logging bucket in the Select sink destination drop down menu.\n5. Choose a log bucket in the next drop down menu.\n6. If an inclusion filter is not provided for this sink, all ingested logs will be routed to\nthe destination provided above. This may result in higher than expected resource\nusage.\n7. Click Create Sink.\nFor more information, see\nhttps://cloud.google.com/logging/docs/export/configure_export_v2#dest-create.\nFrom Google Cloud CLI\nTo create a sink to export all log entries in a Google Cloud Storage bucket:\ngcloud logging sinks create <sink-name>\nstorage.googleapis.com/DESTINATION_BUCKET_NAME\nSinks can be created for a folder or organization, which will include all projects.\ngcloud logging sinks create <sink-name>\nstorage.googleapis.com/DESTINATION_BUCKET_NAME --include-children --\nfolder=FOLDER_ID | --organization=ORGANIZATION_ID\nNote:\n1. A sink created by the command-line above will export logs in storage buckets.\nHowever, sinks can be configured to export logs into BigQuery, or Cloud\nPub/Sub, or Custom Destination.\n2. While creating a sink, the sink option --log-filter is not used to ensure the\nsink exports all log entries.\n3. A sink can be created at a folder or organization level that collects the logs of all\nthe projects underneath bypassing the option --include-children in the\ngcloud command.",
    "default_value": "By default, there are no sinks configured.",
    "additional_information": "For Command-Line Audit and Remediation, the sink destination of type Cloud Storage\nBucket is considered. However, the destination could be configured to Cloud Storage\nBucket or BigQuery or Cloud Pub\\Sub or Custom Destination. Command Line\nInterface commands would change accordingly.",
    "detection_commands": [
      "gcloud logging sinks list --folder=FOLDER_ID | --organization=ORGANIZATION_ID | --project=PROJECT_ID"
    ],
    "remediation_commands": [
      "gcloud logging sinks create <sink-name>",
      "gcloud command."
    ],
    "references": [
      "1. https://cloud.google.com/logging/docs/reference/tools/gcloud-logging",
      "2. https://cloud.google.com/logging/quotas",
      "3. https://cloud.google.com/logging/docs/routing/overview",
      "4. https://cloud.google.com/logging/docs/export/using_exported_logs",
      "5. https://cloud.google.com/logging/docs/export/configure_export_v2",
      "6. https://cloud.google.com/logging/docs/export/aggregated_exports",
      "7. https://cloud.google.com/sdk/gcloud/reference/beta/logging/sinks/list"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 76,
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
    "cis_id": "2.3",
    "title": "Ensure That Retention Policies on Cloud Storage Buckets Used for Exporting Logs Are Configured Using Bucket Lock",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Ensure adequate storage for logs",
    "description": "Enabling retention policies on log buckets will protect logs stored in cloud storage\nbuckets from being overwritten or accidentally deleted. It is recommended to set up\nretention policies and configure Bucket Lock on all storage buckets that are used as log\nsinks.",
    "rationale": "Logs can be exported by creating one or more sinks that include a log filter and a\ndestination. As Cloud Logging receives new log entries, they are compared against\neach sink. If a log entry matches a sink's filter, then a copy of the log entry is written to\nthe destination.\nSinks can be configured to export logs in storage buckets. It is recommended to\nconfigure a data retention policy for these cloud storage buckets and to lock the data\nretention policy; thus permanently preventing the policy from being reduced or removed.\nThis way, if the system is ever compromised by an attacker or a malicious insider who\nwants to cover their tracks, the activity logs are definitely preserved for forensics and\nsecurity investigations.",
    "impact": "Locking a bucket is an irreversible action. Once you lock a bucket, you cannot remove\nthe retention policy from the bucket or decrease the retention period for the policy. You\nwill then have to wait for the retention period for all items within the bucket before you\ncan delete them, and then the bucket.",
    "audit": "From Google Cloud Console\n1. Open the Cloud Storage browser in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/storage/browser.\n2. In the Column display options menu, make sure Retention policy is checked.\n3. In the list of buckets, the retention period of each bucket is found in the\nRetention policy column. If the retention policy is locked, an image of a lock\nappears directly to the left of the retention period.\nFrom Google Cloud CLI\n1. To list all sinks destined to storage buckets:\ngcloud logging sinks list --folder=FOLDER_ID | --organization=ORGANIZATION_ID\n| --project=PROJECT_ID\n2. For every storage bucket listed above, verify that retention policies and Bucket\nLock are enabled:\ngsutil retention get gs://BUCKET_NAME\nFor more information, see https://cloud.google.com/storage/docs/using-bucket-\nlock#view-policy.",
    "remediation": "From Google Cloud Console\n1. If sinks are not configured, first follow the instructions in the recommendation:\nEnsure that sinks are configured for all Log entries.\n2. For each storage bucket configured as a sink, go to the Cloud Storage browser\nat https://console.cloud.google.com/storage/browser/<BUCKET_NAME>.\n3. Select the Bucket Lock tab near the top of the page.\n4. In the Retention policy entry, click the Add Duration link. The Set a retention\npolicy dialog box appears.\n5. Enter the desired length of time for the retention period and click Save policy.\n6. Set the Lock status for this retention policy to Locked.\nFrom Google Cloud CLI\n1. To list all sinks destined to storage buckets:\ngcloud logging sinks list --folder=FOLDER_ID | --organization=ORGANIZATION_ID\n| --project=PROJECT_ID\n2. For each storage bucket listed above, set a retention policy and lock it:\ngsutil retention set [TIME_DURATION] gs://[BUCKET_NAME]\ngsutil retention lock gs://[BUCKET_NAME]\nFor more information, visit https://cloud.google.com/storage/docs/using-bucket-lock#set-\npolicy.",
    "default_value": "By default, storage buckets used as log sinks do not have retention policies and Bucket\nLock configured.",
    "additional_information": "Caution: Locking a retention policy is an irreversible action. Once locked, you must\ndelete the entire bucket in order to \"remove\" the bucket's retention policy. However,\nbefore you can delete the bucket, you must be able to delete all the objects in the\nbucket, which itself is only possible if all the objects have reached the retention period\nset by the retention policy.",
    "detection_commands": [
      "gcloud logging sinks list --folder=FOLDER_ID | --organization=ORGANIZATION_ID | --project=PROJECT_ID",
      "gsutil retention get gs://BUCKET_NAME"
    ],
    "remediation_commands": [
      "gcloud logging sinks list --folder=FOLDER_ID | --organization=ORGANIZATION_ID | --project=PROJECT_ID",
      "gsutil retention set [TIME_DURATION] gs://[BUCKET_NAME] gsutil retention lock gs://[BUCKET_NAME]"
    ],
    "references": [
      "1. https://cloud.google.com/storage/docs/bucket-lock",
      "2. https://cloud.google.com/storage/docs/using-bucket-lock",
      "3. https://cloud.google.com/storage/docs/bucket-lock"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 79,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "retention",
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
    "title": "Ensure Log Metric Filter and Alerts Exist for Project Ownership Assignments/Changes",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "In order to prevent unnecessary project ownership assignments to users/service-\naccounts and further misuses of projects and resources, all roles/Owner assignments\nshould be monitored.\nMembers (users/Service-Accounts) with a role assignment to primitive role\nroles/Owner are project owners.\nThe project owner has all the privileges on the project the role belongs to. These are\nsummarized below:\n• All viewer permissions on all GCP Services within the project\n• Permissions for actions that modify the state of all GCP services within the\nproject\n• Manage roles and permissions for a project and all resources within the project\n• Set up billing for a project\nGranting the owner role to a member (user/Service-Account) will allow that member to\nmodify the Identity and Access Management (IAM) policy. Therefore, grant the owner\nrole only if the member has a legitimate purpose to manage the IAM policy. This is\nbecause the project IAM policy contains sensitive access control data. Having a minimal\nset of users allowed to manage IAM policy will simplify any auditing that may be\nnecessary.",
    "rationale": "Project ownership has the highest level of privileges on a project. To avoid misuse of\nproject resources, the project ownership assignment/change actions mentioned above\nshould be monitored and alerted to concerned recipients.\n• Sending project ownership invites\n• Acceptance/Rejection of project ownership invite by user\n• Adding role\\Owner to a user/service-account\n• Removing a user/Service account from role\\Owner",
    "impact": "Enabling of logging may result in your project being charged for the additional logs\nusage.",
    "audit": "From Google Cloud Console\nEnsure that the prescribed log metric is present:\n1. Go to Logging/Log-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics.\n2. In the User-defined Metrics section, ensure that at least one metric\n<Log_Metric_Name> is present with filter text:\n(protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\")\nAND (ProjectOwnership OR projectOwnerInvitee)\nOR (protoPayload.serviceData.policyDelta.bindingDeltas.action=\"REMOVE\"\nAND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\")\nOR (protoPayload.serviceData.policyDelta.bindingDeltas.action=\"ADD\"\nAND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\")\nEnsure that the prescribed Alerting Policy is present:\n3. Go to Alerting by visiting https://console.cloud.google.com/monitoring/alerting.\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\ncondition. For example, Violates when: Any\nlogging.googleapis.com/user/<Log Metric Name> stream is above a\nthreshold of zero(0) for greater than zero(0) seconds means that\nthe alert will trigger for any new owner change. Verify that the chosen alerting\nthresholds make sense for your organization.\n5. Ensure that the appropriate notifications channels have been set up.\nFrom Google Cloud CLI\nEnsure that the prescribed log metric is present:\n1. List the log metrics:\ngcloud logging metrics list --format json\n2. Ensure that the output contains at least one metric with filter set to:\n(protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\")\nAND (ProjectOwnership OR projectOwnerInvitee)\nOR (protoPayload.serviceData.policyDelta.bindingDeltas.action=\"REMOVE\"\nAND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\")\nOR (protoPayload.serviceData.policyDelta.bindingDeltas.action=\"ADD\"\nAND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\")\n3. Note the value of the property metricDescriptor.type for the identified metric,\nin the format logging.googleapis.com/user/<Log Metric Name>.\nEnsure that the prescribed alerting policy is present:\n4. List the alerting policies:\ngcloud alpha monitoring policies list --format json\n5. Ensure that the output contains an least one alert policy where:\n• conditions.conditionThreshold.filter is set to\nmetric.type=\\\"logging.googleapis.com/user/<Log Metric Name>\\\"\n• AND enabled is set to true",
    "expected_response": "Ensure that the prescribed log metric is present:\n2. In the User-defined Metrics section, ensure that at least one metric\n<Log_Metric_Name> is present with filter text:\nEnsure that the prescribed Alerting Policy is present:\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\n5. Ensure that the appropriate notifications channels have been set up.\n2. Ensure that the output contains at least one metric with filter set to:\nEnsure that the prescribed alerting policy is present:\n5. Ensure that the output contains an least one alert policy where:\n• conditions.conditionThreshold.filter is set to\n• AND enabled is set to true",
    "remediation": "From Google Cloud Console\nCreate the prescribed log metric:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics and click \"CREATE METRIC\".\n2. Click the down arrow symbol on the Filter Bar at the rightmost corner and\nselect Convert to Advanced Filter.\n3. Clear any text and add:\n(protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\")\nAND (ProjectOwnership OR projectOwnerInvitee)\nOR (protoPayload.serviceData.policyDelta.bindingDeltas.action=\"REMOVE\"\nAND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\")\nOR (protoPayload.serviceData.policyDelta.bindingDeltas.action=\"ADD\"\nAND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\")\n4. Click Submit Filter. The logs display based on the filter text entered by the\nuser.\n5. In the Metric Editor menu on the right, fill out the name field. Set Units to 1\n(default) and the Type to Counter. This ensures that the log metric counts the\nnumber of log entries matching the advanced logs query.\n6. Click Create Metric.\nCreate the display prescribed Alert Policy:\n1. Identify the newly created metric under the section User-defined Metrics at\nhttps://console.cloud.google.com/logs/metrics.\n2. Click the 3-dot icon in the rightmost column for the desired metric and select\nCreate alert from Metric. A new page opens.\n3. Fill out the alert policy configuration and click Save. Choose the alerting threshold\nand configuration that makes sense for the user's organization. For example, a\nthreshold of zero(0) for the most recent value will ensure that a notification is\ntriggered for every owner change in the project:\nSet `Aggregator` to `Count`\nSet `Configuration`:\n- Condition: above\n- Threshold: 0\n- For: most recent value\n4. Configure the desired notifications channels in the section Notifications.\n5. Name the policy and click Save.\nFrom Google Cloud CLI\nCreate a prescribed Log Metric:\n• Use the command: gcloud beta logging metrics create\n• Reference for Command Usage:\nhttps://cloud.google.com/sdk/gcloud/reference/beta/logging/metrics/create\nCreate prescribed Alert Policy\n• Use the command: gcloud alpha monitoring policies create\n• Reference for Command Usage:\nhttps://cloud.google.com/sdk/gcloud/reference/alpha/monitoring/policies/create",
    "additional_information": "1. Project ownership assignments for a user cannot be done using the gcloud utility\nas assigning project ownership to a user requires sending, and the user\naccepting, an invitation.\n2. Project Ownership assignment to a service account does not send any invites.\nSetIAMPolicy to role/owneris directly performed on service accounts.",
    "detection_commands": [
      "gcloud logging metrics list --format json",
      "gcloud alpha monitoring policies list --format json"
    ],
    "remediation_commands": [
      "Create the prescribed log metric:",
      "select Convert to Advanced Filter.",
      "Create the display prescribed Alert Policy:",
      "Create alert from Metric. A new page opens.",
      "Create a prescribed Log Metric:",
      "Create prescribed Alert Policy"
    ],
    "references": [
      "1. https://cloud.google.com/logging/docs/logs-based-metrics/",
      "2. https://cloud.google.com/monitoring/custom-metrics/",
      "3. https://cloud.google.com/monitoring/alerts/",
      "4. https://cloud.google.com/logging/docs/reference/tools/gcloud-logging"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 82,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access",
      "classification",
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
    "cis_id": "2.5",
    "title": "Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Activate audit logging",
    "description": "Google Cloud Platform (GCP) services write audit log entries to the Admin Activity and\nData Access logs to help answer the questions of, \"who did what, where, and when?\"\nwithin GCP projects.\nCloud audit logging records information includes the identity of the API caller, the time\nof the API call, the source IP address of the API caller, the request parameters, and the\nresponse elements returned by GCP services. Cloud audit logging provides a history of\nGCP API calls for an account, including API calls made via the console, SDKs,\ncommand-line tools, and other GCP services.",
    "rationale": "Admin activity and data access logs produced by cloud audit logging enable security\nanalysis, resource change tracking, and compliance auditing.\nConfiguring the metric filter and alerts for audit configuration changes ensures the\nrecommended state of audit configuration is maintained so that all activities in the\nproject are audit-able at any point in time.",
    "impact": "Enabling of logging may result in your project being charged for the additional logs\nusage.",
    "audit": "From Google Cloud Console\nEnsure the prescribed log metric is present:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics.\n2. In the User-defined Metrics section, ensure that at least one metric\n<Log_Metric_Name> is present with the filter text:\nprotoPayload.methodName=\"SetIamPolicy\" AND\nprotoPayload.serviceData.policyDelta.auditConfigDeltas:*\nEnsure that the prescribed alerting policy is present:\n3. Go to Alerting by visiting https://console.cloud.google.com/monitoring/alerting.\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\ncondition. For example, Violates when: Any\nlogging.googleapis.com/user/<Log Metric Name> stream is above a\nthreshold of 0 for greater than zero(0) seconds, means that the alert\nwill trigger for any new owner change. Verify that the chosen alerting thresholds\nmake sense for the user's organization.\n5. Ensure that appropriate notifications channels have been set up.\nFrom Google Cloud CLI\nEnsure that the prescribed log metric is present:\n1. List the log metrics:\ngcloud beta logging metrics list --format json\n2. Ensure that the output contains at least one metric with the filter set to:\nprotoPayload.methodName=\"SetIamPolicy\" AND\nprotoPayload.serviceData.policyDelta.auditConfigDeltas:*\n3. Note the value of the property metricDescriptor.type for the identified metric,\nin the format logging.googleapis.com/user/<Log Metric Name>.\nEnsure that the prescribed alerting policy is present:\n4. List the alerting policies:\ngcloud alpha monitoring policies list --format json\n5. Ensure that the output contains at least one alert policy where:\n• conditions.conditionThreshold.filter is set to\nmetric.type=\\\"logging.googleapis.com/user/<Log Metric Name>\\\"\n• AND enabled is set to true",
    "expected_response": "Ensure the prescribed log metric is present:\n2. In the User-defined Metrics section, ensure that at least one metric\n<Log_Metric_Name> is present with the filter text:\nEnsure that the prescribed alerting policy is present:\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\n5. Ensure that appropriate notifications channels have been set up.\nEnsure that the prescribed log metric is present:\n2. Ensure that the output contains at least one metric with the filter set to:\n5. Ensure that the output contains at least one alert policy where:\n• conditions.conditionThreshold.filter is set to\n• AND enabled is set to true",
    "remediation": "From Google Cloud Console\nCreate the prescribed log metric:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics and click \"CREATE METRIC\".\n2. Click the down arrow symbol on the Filter Bar at the rightmost corner and\nselect Convert to Advanced Filter.\n3. Clear any text and add:\nprotoPayload.methodName=\"SetIamPolicy\" AND\nprotoPayload.serviceData.policyDelta.auditConfigDeltas:*\n4. Click Submit Filter. Display logs appear based on the filter text entered by the\nuser.\n5. In the Metric Editor menu on the right, fill out the name field. Set Units to 1\n(default) and Type to Counter. This will ensure that the log metric counts the\nnumber of log entries matching the user's advanced logs query.\n6. Click Create Metric.\nCreate a prescribed Alert Policy:\n1. Identify the new metric the user just created, under the section User-defined\nMetrics at https://console.cloud.google.com/logs/metrics.\n2. Click the 3-dot icon in the rightmost column for the new metric and select Create\nalert from Metric. A new page opens.\n3. Fill out the alert policy configuration and click Save. Choose the alerting threshold\nand configuration that makes sense for the organization. For example, a\nthreshold of zero(0) for the most recent value will ensure that a notification is\ntriggered for every owner change in the project:\nSet `Aggregator` to `Count`\nSet `Configuration`:\n- Condition: above\n- Threshold: 0\n- For: most recent value\n4. Configure the desired notifications channels in the section Notifications.\n5. Name the policy and click Save.\nFrom Google Cloud CLI\nCreate a prescribed Log Metric:\n• Use the command: gcloud beta logging metrics create\n• Reference for command usage:\nhttps://cloud.google.com/sdk/gcloud/reference/beta/logging/metrics/create\nCreate prescribed Alert Policy\n• Use the command: gcloud alpha monitoring policies create\n• Reference for command usage:\nhttps://cloud.google.com/sdk/gcloud/reference/alpha/monitoring/policies/create",
    "detection_commands": [
      "gcloud beta logging metrics list --format json",
      "gcloud alpha monitoring policies list --format json"
    ],
    "remediation_commands": [
      "Create the prescribed log metric:",
      "select Convert to Advanced Filter.",
      "Create a prescribed Alert Policy:",
      "Create a prescribed Log Metric:",
      "Create prescribed Alert Policy"
    ],
    "references": [
      "1. https://cloud.google.com/logging/docs/logs-based-metrics/",
      "2. https://cloud.google.com/monitoring/custom-metrics/",
      "3. https://cloud.google.com/monitoring/alerts/",
      "4. https://cloud.google.com/logging/docs/reference/tools/gcloud-logging",
      "5. https://cloud.google.com/logging/docs/audit/configure-data-access#getiampolicy-",
      "setiampolicy"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 87,
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
    "cis_id": "2.6",
    "title": "Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Enable Detailed Logging",
    "description": "It is recommended that a metric filter and alarm be established for changes to Identity\nand Access Management (IAM) role creation, deletion and updating activities.",
    "rationale": "Google Cloud IAM provides predefined roles that give granular access to specific\nGoogle Cloud Platform resources and prevent unwanted access to other resources.\nHowever, to cater to organization-specific needs, Cloud IAM also provides the ability to\ncreate custom roles. Project owners and administrators with the Organization Role\nAdministrator role or the IAM Role Administrator role can create custom roles.\nMonitoring role creation, deletion and updating activities will help in identifying any over-\nprivileged role at early stages.",
    "impact": "Enabling of logging may result in your project being charged for the additional logs\nusage.",
    "audit": "From Console:\nEnsure that the prescribed log metric is present:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics.\n2. In the User-defined Metrics section, ensure that at least one metric\n<Log_Metric_Name> is present with filter text:\nresource.type=\"iam_role\"\nAND (protoPayload.methodName=\"google.iam.admin.v1.CreateRole\"\nOR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\"\nOR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\"\nOR protoPayload.methodName=\"google.iam.admin.v1.UndeleteRole\")\nEnsure that the prescribed alerting policy is present:\n3. Go to Alerting by visiting https://console.cloud.google.com/monitoring/alerting.\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\ncondition. For example, Violates when: Any\nlogging.googleapis.com/user/<Log Metric Name> stream is above a\nthreshold of zero(0) for greater than zero(0) seconds means that\nthe alert will trigger for any new owner change. Verify that the chosen alerting\nthresholds make sense for the user's organization.\n5. Ensure that the appropriate notifications channels have been set up.\nFrom Google Cloud CLI\nEnsure that the prescribed log metric is present:\n1. List the log metrics:\ngcloud logging metrics list --format json\n2. Ensure that the output contains at least one metric with the filter set to:\nresource.type=\"iam_role\"\nAND (protoPayload.methodName = \"google.iam.admin.v1.CreateRole\" OR\nprotoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR\nprotoPayload.methodName=\"google.iam.admin.v1.UpdateRole OR\nprotoPayload.methodName=\"google.iam.admin.v1.UndeleteRole\")\n3. Note the value of the property metricDescriptor.type for the identified metric,\nin the format logging.googleapis.com/user/<Log Metric Name>.\nEnsure that the prescribed alerting policy is present:\n4. List the alerting policies:\ngcloud alpha monitoring policies list --format json\n5. Ensure that the output contains an least one alert policy where:\n• conditions.conditionThreshold.filter is set to\nmetric.type=\\\"logging.googleapis.com/user/<Log Metric Name>\\\"\n• AND enabled is set to true.",
    "expected_response": "Ensure that the prescribed log metric is present:\n2. In the User-defined Metrics section, ensure that at least one metric\n<Log_Metric_Name> is present with filter text:\nEnsure that the prescribed alerting policy is present:\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\n5. Ensure that the appropriate notifications channels have been set up.\n2. Ensure that the output contains at least one metric with the filter set to:\n5. Ensure that the output contains an least one alert policy where:\n• conditions.conditionThreshold.filter is set to\n• AND enabled is set to true.",
    "remediation": "From Console:\nCreate the prescribed log metric:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics and click \"CREATE METRIC\".\n2. Click the down arrow symbol on the Filter Bar at the rightmost corner and\nselect Convert to Advanced Filter.\n3. Clear any text and add:\nresource.type=\"iam_role\"\nAND (protoPayload.methodName =  \"google.iam.admin.v1.CreateRole\"\nOR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\"\nOR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\"\nOR protoPayload.methodName=\"google.iam.admin.v1.UndeleteRole\")\n1. Click Submit Filter. Display logs appear based on the filter text entered by the\nuser.\n2. In the Metric Editor menu on the right, fill out the name field. Set Units to 1\n(default) and Type to Counter. This ensures that the log metric counts the\nnumber of log entries matching the advanced logs query.\n3. Click Create Metric.\nCreate a prescribed Alert Policy:\n1. Identify the new metric that was just created under the section User-defined\nMetrics at https://console.cloud.google.com/logs/metrics.\n2. Click the 3-dot icon in the rightmost column for the metric and select Create\nalert from Metric. A new page displays.\n3. Fill out the alert policy configuration and click Save. Choose the alerting threshold\nand configuration that makes sense for the user's organization. For example, a\nthreshold of zero(0) for the most recent value ensures that a notification is\ntriggered for every owner change in the project:\nSet `Aggregator` to `Count`\nSet `Configuration`:\n- Condition: above\n- Threshold: 0\n- For: most recent value\n1. Configure the desired notification channels in the section Notifications.\n2. Name the policy and click Save.\nFrom Google Cloud CLI\nCreate the prescribed Log Metric:\n• Use the command: gcloud logging metrics create\nCreate the prescribed Alert Policy:\n• Use the command: gcloud alpha monitoring policies create",
    "detection_commands": [
      "gcloud logging metrics list --format json",
      "gcloud alpha monitoring policies list --format json"
    ],
    "remediation_commands": [
      "Create the prescribed log metric:",
      "select Convert to Advanced Filter.",
      "Create a prescribed Alert Policy:",
      "Create the prescribed Log Metric:",
      "Create the prescribed Alert Policy:"
    ],
    "references": [
      "1. https://cloud.google.com/logging/docs/logs-based-metrics/",
      "2. https://cloud.google.com/monitoring/custom-metrics/",
      "3. https://cloud.google.com/monitoring/alerts/",
      "4. https://cloud.google.com/logging/docs/reference/tools/gcloud-logging",
      "5. https://cloud.google.com/iam/docs/understanding-custom-roles"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 91,
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
    "cis_id": "2.7",
    "title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Firewall Rule Changes",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Enable Detailed Logging",
    "description": "It is recommended that a metric filter and alarm be established for Virtual Private Cloud\n(VPC) Network Firewall rule changes.",
    "rationale": "Monitoring for Create or Update Firewall rule events gives insight to network access\nchanges and may reduce the time it takes to detect suspicious activity.",
    "impact": "Enabling of logging may result in your project being charged for the additional logs\nusage. These charges could be significant depending on the size of the organization.",
    "audit": "From Google Cloud Console\nEnsure that the prescribed log metric is present:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics.\n2. In the User-defined Metrics section, ensure at least one metric\n<Log_Metric_Name> is present with this filter text:\nresource.type=\"gce_firewall_rule\"\nAND (protoPayload.methodName:\"compute.firewalls.patch\"\nOR protoPayload.methodName:\"compute.firewalls.insert\"\nOR protoPayload.methodName:\"compute.firewalls.delete\")\nEnsure that the prescribed alerting policy is present:\n3. Go to Alerting by visiting https://console.cloud.google.com/monitoring/alerting.\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\ncondition. For example, Violates when: Any\nlogging.googleapis.com/user/<Log Metric Name> stream is above a\nthreshold of zero(0) for greater than zero(0) seconds means that\nthe alert will trigger for any new owner change. Verify that the chosen alerting\nthresholds make sense for the user's organization.\n5. Ensure that appropriate notification channels have been set up.\nFrom Google Cloud CLI\nEnsure that the prescribed log metric is present:\n1. List the log metrics:\ngcloud logging metrics list --format json\n2. Ensure that the output contains at least one metric with the filter set to:\nresource.type=\"gce_firewall_rule\"\nAND (protoPayload.methodName:\"compute.firewalls.patch\"\nOR protoPayload.methodName:\"compute.firewalls.insert\"\nOR protoPayload.methodName:\"compute.firewalls.delete\")\n3. Note the value of the property metricDescriptor.type for the identified metric,\nin the format logging.googleapis.com/user/<Log Metric Name>.\nEnsure that the prescribed alerting policy is present:\n4. List the alerting policies:\ngcloud alpha monitoring policies list --format json\n5. Ensure that the output contains an least one alert policy where:\n• conditions.conditionThreshold.filter is set to\nmetric.type=\\\"logging.googleapis.com/user/<Log Metric Name>\\\"\n• AND enabled is set to true",
    "expected_response": "Ensure that the prescribed log metric is present:\n2. In the User-defined Metrics section, ensure at least one metric\n<Log_Metric_Name> is present with this filter text:\nEnsure that the prescribed alerting policy is present:\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\n5. Ensure that appropriate notification channels have been set up.\n2. Ensure that the output contains at least one metric with the filter set to:\n5. Ensure that the output contains an least one alert policy where:\n• conditions.conditionThreshold.filter is set to\n• AND enabled is set to true",
    "remediation": "From Google Cloud Console\nCreate the prescribed log metric:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics and click \"CREATE METRIC\".\n2. Click the down arrow symbol on the Filter Bar at the rightmost corner and\nselect Convert to Advanced Filter.\n3. Clear any text and add:\nresource.type=\"gce_firewall_rule\"\nAND (protoPayload.methodName:\"compute.firewalls.patch\"\nOR protoPayload.methodName:\"compute.firewalls.insert\"\nOR protoPayload.methodName:\"compute.firewalls.delete\")\n4. Click Submit Filter. Display logs appear based on the filter text entered by the\nuser.\n5. In the Metric Editor menu on the right, fill out the name field. Set Units to 1\n(default) and Type to Counter. This ensures that the log metric counts the\nnumber of log entries matching the advanced logs query.\n6. Click Create Metric.\nCreate the prescribed Alert Policy:\n1. Identify the newly created metric under the section User-defined Metrics at\nhttps://console.cloud.google.com/logs/metrics.\n2. Click the 3-dot icon in the rightmost column for the new metric and select Create\nalert from Metric. A new page displays.\n3. Fill out the alert policy configuration and click Save. Choose the alerting threshold\nand configuration that makes sense for the user's organization. For example, a\nthreshold of zero(0) for the most recent value ensures that a notification is\ntriggered for every owner change in the project:\nSet `Aggregator` to `Count`\nSet `Configuration`:\n- Condition: above\n- Threshold: 0\n- For: most recent value\n4. Configure the desired notifications channels in the section Notifications.\n5. Name the policy and click Save.\nFrom Google Cloud CLI\nCreate the prescribed Log Metric\n• Use the command: gcloud logging metrics create\nCreate the prescribed alert policy:\n• Use the command: gcloud alpha monitoring policies create",
    "detection_commands": [
      "gcloud logging metrics list --format json",
      "gcloud alpha monitoring policies list --format json"
    ],
    "remediation_commands": [
      "Create the prescribed log metric:",
      "select Convert to Advanced Filter.",
      "Create the prescribed Alert Policy:",
      "Create the prescribed Log Metric",
      "Create the prescribed alert policy:"
    ],
    "references": [
      "1. https://cloud.google.com/logging/docs/logs-based-metrics/",
      "2. https://cloud.google.com/monitoring/custom-metrics/",
      "3. https://cloud.google.com/monitoring/alerts/",
      "4. https://cloud.google.com/logging/docs/reference/tools/gcloud-logging",
      "5. https://cloud.google.com/vpc/docs/firewalls"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 95,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
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
    "cis_id": "2.8",
    "title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Route Changes",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Enable Detailed Logging",
    "description": "It is recommended that a metric filter and alarm be established for Virtual Private Cloud\n(VPC) network route changes.",
    "rationale": "Google Cloud Platform (GCP) routes define the paths network traffic takes from a VM\ninstance to another destination. The other destination can be inside the organization\nVPC network (such as another VM) or outside of it. Every route consists of a destination\nand a next hop. Traffic whose destination IP is within the destination range is sent to the\nnext hop for delivery.\nMonitoring changes to route tables will help ensure that all VPC traffic flows through an\nexpected path.",
    "impact": "Enabling of logging may result in your project being charged for the additional logs\nusage. These charges could be significant depending on the size of the organization.",
    "audit": "From Google Cloud Console\nEnsure that the prescribed Log metric is present:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics.\n2. In the User-defined Metrics section, ensure that at least one metric\n<Log_Metric_Name> is present with the filter text:\nresource.type=\"gce_route\"\nAND (protoPayload.methodName:\"compute.routes.delete\"\nOR protoPayload.methodName:\"compute.routes.insert\")\nEnsure the prescribed alerting policy is present:\n3. Go to Alerting by visiting: https://console.cloud.google.com/monitoring/alerting.\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\ncondition. For example, Violates when: Any\nlogging.googleapis.com/user/<Log Metric Name> stream is above a\nthreshold of 0 for greater than zero(0) seconds means that the alert\nwill trigger for any new owner change. Verify that the chosen alert thresholds\nmake sense for the user's organization.\n5. Ensure that the appropriate notification channels have been set up.\nFrom Google Cloud CLI\nEnsure the prescribed log metric is present:\n1. List the log metrics:\ngcloud logging metrics list --format json\n2. Ensure that the output contains at least one metric with the filter set to:\nresource.type=\"gce_route\"\nAND (protoPayload.methodName:\"compute.routes.delete\"\nOR protoPayload.methodName:\"compute.routes.insert\")\n3. Note the value of the property metricDescriptor.type for the identified metric,\nin the format logging.googleapis.com/user/<Log Metric Name>.\nEnsure that the prescribed alerting policy is present:\n4. List the alerting policies:\ngcloud alpha monitoring policies list --format json\n5. Ensure that the output contains an least one alert policy where:\n• conditions.conditionThreshold.filter is set to\nmetric.type=\\\"logging.googleapis.com/user/<Log Metric Name>\\\"\n• AND enabled is set to true",
    "expected_response": "Ensure that the prescribed Log metric is present:\n2. In the User-defined Metrics section, ensure that at least one metric\n<Log_Metric_Name> is present with the filter text:\nEnsure the prescribed alerting policy is present:\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\n5. Ensure that the appropriate notification channels have been set up.\nEnsure the prescribed log metric is present:\n2. Ensure that the output contains at least one metric with the filter set to:\nEnsure that the prescribed alerting policy is present:\n5. Ensure that the output contains an least one alert policy where:\n• conditions.conditionThreshold.filter is set to\n• AND enabled is set to true",
    "remediation": "From Google Cloud Console\nCreate the prescribed Log Metric:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics and click \"CREATE METRIC\".\n2. Click the down arrow symbol on the Filter Bar at the rightmost corner and\nselect Convert to Advanced Filter\n3. Clear any text and add:\nresource.type=\"gce_route\"\nAND (protoPayload.methodName:\"compute.routes.delete\"\nOR protoPayload.methodName:\"compute.routes.insert\")\n4. Click Submit Filter. Display logs appear based on the filter text entered by the\nuser.\n5. In the Metric Editor menu on the right, fill out the name field. Set Units to 1\n(default) and Type to Counter. This ensures that the log metric counts the\nnumber of log entries matching the user's advanced logs query.\n6. Click Create Metric.\nCreate the prescribed alert policy:\n1. Identify the newly created metric under the section User-defined Metrics at\nhttps://console.cloud.google.com/logs/metrics.\n2. Click the 3-dot icon in the rightmost column for the new metric and select Create\nalert from Metric. A new page displays.\n3. Fill out the alert policy configuration and click Save. Choose the alerting threshold\nand configuration that makes sense for the user's organization. For example, a\nthreshold of zero(0) for the most recent value ensures that a notification is\ntriggered for every owner change in the project:\nSet `Aggregator` to `Count`\nSet `Configuration`:\n- Condition: above\n- Threshold: 0\n- For: most recent value\n4. Configure the desired notification channels in the section Notifications.\n5. Name the policy and click Save.\nFrom Google Cloud CLI\nCreate the prescribed Log Metric:\n• Use the command: gcloud logging metrics create\nCreate the prescribed the alert policy:\n• Use the command: gcloud alpha monitoring policies create",
    "detection_commands": [
      "gcloud logging metrics list --format json",
      "gcloud alpha monitoring policies list --format json"
    ],
    "remediation_commands": [
      "Create the prescribed Log Metric:",
      "select Convert to Advanced Filter",
      "Create the prescribed alert policy:",
      "Create the prescribed the alert policy:"
    ],
    "references": [
      "1. https://cloud.google.com/logging/docs/logs-based-metrics/",
      "2. https://cloud.google.com/monitoring/custom-metrics/",
      "3. https://cloud.google.com/monitoring/alerts/",
      "4. https://cloud.google.com/logging/docs/reference/tools/gcloud-logging",
      "5. https://cloud.google.com/storage/docs/access-control/iam",
      "6. https://cloud.google.com/sdk/gcloud/reference/beta/logging/metrics/create",
      "7. https://cloud.google.com/sdk/gcloud/reference/alpha/monitoring/policies/create"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 99,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
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
    "cis_id": "2.9",
    "title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Changes",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Enable Detailed Logging",
    "description": "It is recommended that a metric filter and alarm be established for Virtual Private Cloud\n(VPC) network changes.",
    "rationale": "It is possible to have more than one VPC within a project. In addition, it is also possible\nto create a peer connection between two VPCs enabling network traffic to route\nbetween VPCs.\nMonitoring changes to a VPC will help ensure VPC traffic flow is not getting impacted.",
    "impact": "Enabling of logging may result in your project being charged for the additional logs\nusage. These charges could be significant depending on the size of the organization.",
    "audit": "From Google Cloud Console\nEnsure the prescribed log metric is present:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics.\n2. In the User-defined Metrics section, ensure at least one metric\n<Log_Metric_Name> is present with filter text:\nresource.type=\"gce_network\"\nAND (protoPayload.methodName:\"compute.networks.insert\"\nOR protoPayload.methodName:\"compute.networks.patch\"\nOR protoPayload.methodName:\"compute.networks.delete\"\nOR protoPayload.methodName:\"compute.networks.removePeering\"\nOR protoPayload.methodName:\"compute.networks.addPeering\")\nEnsure the prescribed alerting policy is present:\n3. Go to Alerting by visiting https://console.cloud.google.com/monitoring/alerting.\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\ncondition. For example, Violates when: Any\nlogging.googleapis.com/user/<Log Metric Name> stream is above a\nthreshold of 0 for greater than 0 seconds means that the alert will\ntrigger for any new owner change. Verify that the chosen alerting thresholds\nmake sense for the user's organization.\n5. Ensure that appropriate notification channels have been set up.\nFrom Google Cloud CLI\nEnsure the log metric is present:\n1. List the log metrics:\ngcloud logging metrics list --format json\n2. Ensure that the output contains at least one metric with filter set to:\nresource.type=\"gce_network\"\nAND protoPayload.methodName=\"beta.compute.networks.insert\"\nOR protoPayload.methodName=\"beta.compute.networks.patch\"\nOR protoPayload.methodName=\"v1.compute.networks.delete\"\nOR protoPayload.methodName=\"v1.compute.networks.removePeering\"\nOR protoPayload.methodName=\"v1.compute.networks.addPeering\"\n3. Note the value of the property metricDescriptor.type for the identified metric,\nin the format logging.googleapis.com/user/<Log Metric Name>.\nEnsure the prescribed alerting policy is present:\n4. List the alerting policies:\ngcloud alpha monitoring policies list --format json\n5. Ensure that the output contains at least one alert policy where:\n• conditions.conditionThreshold.filter is set to\nmetric.type=\\\"logging.googleapis.com/user/<Log Metric Name>\\\"\n• AND enabled is set to true",
    "expected_response": "Ensure the prescribed log metric is present:\n2. In the User-defined Metrics section, ensure at least one metric\n<Log_Metric_Name> is present with filter text:\nEnsure the prescribed alerting policy is present:\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\n5. Ensure that appropriate notification channels have been set up.\nEnsure the log metric is present:\n2. Ensure that the output contains at least one metric with filter set to:\n5. Ensure that the output contains at least one alert policy where:\n• conditions.conditionThreshold.filter is set to\n• AND enabled is set to true",
    "remediation": "From Google Cloud Console\nCreate the prescribed log metric:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics and click \"CREATE METRIC\".\n2. Click the down arrow symbol on Filter Bar at the rightmost corner and select\nConvert to Advanced Filter.\n3. Clear any text and add:\nresource.type=\"gce_network\"\nAND (protoPayload.methodName:\"compute.networks.insert\"\nOR protoPayload.methodName:\"compute.networks.patch\"\nOR protoPayload.methodName:\"compute.networks.delete\"\nOR protoPayload.methodName:\"compute.networks.removePeering\"\nOR protoPayload.methodName:\"compute.networks.addPeering\")\n4. Click Submit Filter. Display logs appear based on the filter text entered by the\nuser.\n5. In the Metric Editor menu on the right, fill out the name field. Set Units to 1\n(default) and Type to Counter. This ensures that the log metric counts the\nnumber of log entries matching the user's advanced logs query.\n6. Click Create Metric.\nCreate the prescribed alert policy:\n1. Identify the newly created metric under the section User-defined Metrics at\nhttps://console.cloud.google.com/logs/metrics.\n2. Click the 3-dot icon in the rightmost column for the new metric and select Create\nalert from Metric. A new page appears.\n3. Fill out the alert policy configuration and click Save. Choose the alerting threshold\nand configuration that makes sense for the user's organization. For example, a\nthreshold of 0 for the most recent value will ensure that a notification is triggered\nfor every owner change in the project:\nSet `Aggregator` to `Count`\nSet `Configuration`:\n- Condition: above\n- Threshold: 0\n- For: most recent value\n4. Configure the desired notification channels in the section Notifications.\n5. Name the policy and click Save.\nFrom Google Cloud CLI\nCreate the prescribed Log Metric:\n• Use the command: gcloud logging metrics create\nCreate the prescribed alert policy:\n• Use the command: gcloud alpha monitoring policies create",
    "detection_commands": [
      "gcloud logging metrics list --format json",
      "gcloud alpha monitoring policies list --format json"
    ],
    "remediation_commands": [
      "Create the prescribed log metric:",
      "Create the prescribed alert policy:",
      "Create the prescribed Log Metric:"
    ],
    "references": [
      "1. https://cloud.google.com/logging/docs/logs-based-metrics/",
      "2. https://cloud.google.com/monitoring/custom-metrics/",
      "3. https://cloud.google.com/monitoring/alerts/",
      "4. https://cloud.google.com/logging/docs/reference/tools/gcloud-logging",
      "5. https://cloud.google.com/vpc/docs/overview"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 103,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
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
    "cis_id": "2.10",
    "title": "Ensure That the Log Metric Filter and Alerts Exist for Cloud Storage IAM Permission Changes",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Enable Detailed Logging",
    "description": "It is recommended that a metric filter and alarm be established for Cloud Storage\nBucket IAM changes.",
    "rationale": "Monitoring changes to cloud storage bucket permissions may reduce the time needed\nto detect and correct permissions on sensitive cloud storage buckets and objects inside\nthe bucket.",
    "impact": "Enabling of logging may result in your project being charged for the additional logs\nusage. These charges could be significant depending on the size of the organization.",
    "audit": "From Google Cloud Console\nEnsure the prescribed log metric is present:\n1. For each project that contains cloud storage buckets, go to Logging/Logs-\nbased Metrics by visiting https://console.cloud.google.com/logs/metrics.\n2. In the User-defined Metrics section, ensure at least one metric\n<Log_Metric_Name> is present with the filter text:\nresource.type=\"gcs_bucket\"\nAND protoPayload.methodName=\"storage.setIamPermissions\"\nEnsure that the prescribed alerting policy is present:\n3. Go to Alerting by visiting https://console.cloud.google.com/monitoring/alerting.\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\ncondition. For example, Violates when: Any\nlogging.googleapis.com/user/<Log Metric Name> stream is above a\nthreshold of 0 for greater than 0 seconds means that the alert will\ntrigger for any new owner change. Verify that the chosen alerting thresholds\nmake sense for the user's organization.\n5. Ensure that the appropriate notifications channels have been set up.\nFrom Google Cloud CLI\nEnsure that the prescribed log metric is present:\n1. List the log metrics:\ngcloud logging metrics list --format json\n2. Ensure that the output contains at least one metric with the filter set to:\nresource.type=gcs_bucket\nAND protoPayload.methodName=\"storage.setIamPermissions\"\n3. Note the value of the property metricDescriptor.type for the identified metric,\nin the format logging.googleapis.com/user/<Log Metric Name>.\nEnsure the prescribed alerting policy is present:\n4. List the alerting policies:\ngcloud alpha monitoring policies list --format json\n5. Ensure that the output contains an least one alert policy where:\n• conditions.conditionThreshold.filter is set to\nmetric.type=\\\"logging.googleapis.com/user/<Log Metric Name>\\\"\n• AND enabled is set to true",
    "expected_response": "Ensure the prescribed log metric is present:\n2. In the User-defined Metrics section, ensure at least one metric\n<Log_Metric_Name> is present with the filter text:\nEnsure that the prescribed alerting policy is present:\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\n5. Ensure that the appropriate notifications channels have been set up.\nEnsure that the prescribed log metric is present:\n2. Ensure that the output contains at least one metric with the filter set to:\nEnsure the prescribed alerting policy is present:\n5. Ensure that the output contains an least one alert policy where:\n• conditions.conditionThreshold.filter is set to\n• AND enabled is set to true",
    "remediation": "From Google Cloud Console\nCreate the prescribed log metric:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics and click \"CREATE METRIC\".\n2. Click the down arrow symbol on the Filter Bar at the rightmost corner and\nselect Convert to Advanced Filter.\n3. Clear any text and add:\nresource.type=\"gcs_bucket\"\nAND protoPayload.methodName=\"storage.setIamPermissions\"\n4. Click Submit Filter. Display logs appear based on the filter text entered by the\nuser.\n5. In the Metric Editor menu on right, fill out the name field. Set Units to 1\n(default) and Type to Counter. This ensures that the log metric counts the\nnumber of log entries matching the user's advanced logs query.\n6. Click Create Metric.\nCreate the prescribed Alert Policy:\n1. Identify the newly created metric under the section User-defined Metrics at\nhttps://console.cloud.google.com/logs/metrics.\n2. Click the 3-dot icon in the rightmost column for the new metric and select Create\nalert from Metric. A new page appears.\n3. Fill out the alert policy configuration and click Save. Choose the alerting threshold\nand configuration that makes sense for the user's organization. For example, a\nthreshold of zero(0) for the most recent value will ensure that a notification is\ntriggered for every owner change in the project:\nSet `Aggregator` to `Count`\nSet `Configuration`:\n- Condition: above\n- Threshold: 0\n- For: most recent value\n4. Configure the desired notifications channels in the section Notifications.\n5. Name the policy and click Save.\nFrom Google Cloud CLI\nCreate the prescribed Log Metric:\n• Use the command: gcloud beta logging metrics create\nCreate the prescribed alert policy:\n• Use the command: gcloud alpha monitoring policies create",
    "detection_commands": [
      "gcloud logging metrics list --format json",
      "gcloud alpha monitoring policies list --format json"
    ],
    "remediation_commands": [
      "Create the prescribed log metric:",
      "select Convert to Advanced Filter.",
      "Create the prescribed Alert Policy:",
      "Create the prescribed Log Metric:",
      "Create the prescribed alert policy:"
    ],
    "references": [
      "1. https://cloud.google.com/logging/docs/logs-based-metrics/",
      "2. https://cloud.google.com/monitoring/custom-metrics/",
      "3. https://cloud.google.com/monitoring/alerts/",
      "4. https://cloud.google.com/logging/docs/reference/tools/gcloud-logging",
      "5. https://cloud.google.com/storage/docs/overview",
      "6. https://cloud.google.com/storage/docs/access-control/iam-roles"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 107,
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
    "cis_id": "2.11",
    "title": "Ensure That the Log Metric Filter and Alerts Exist for SQL Instance Configuration Changes",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Enable Detailed Logging",
    "description": "It is recommended that a metric filter and alarm be established for SQL instance\nconfiguration changes.",
    "rationale": "Monitoring changes to SQL instance configuration changes may reduce the time\nneeded to detect and correct misconfigurations done on the SQL server.\nBelow are a few of the configurable options which may the impact security posture of an\nSQL instance:\n• Enable auto backups and high availability: Misconfiguration may adversely\nimpact business continuity, disaster recovery, and high availability\n• Authorize networks: Misconfiguration may increase exposure to untrusted\nnetworks",
    "impact": "Enabling of logging may result in your project being charged for the additional logs\nusage. These charges could be significant depending on the size of the organization.",
    "audit": "From Google Cloud Console\nEnsure the prescribed log metric is present:\n1. For each project that contains Cloud SQL instances, go to Logging/Logs-based\nMetrics by visiting https://console.cloud.google.com/logs/metrics.\n2. In the User-defined Metrics section, ensure that at least one metric\n<Log_Metric_Name> is present with the filter text:\nprotoPayload.methodName=\"cloudsql.instances.update\"\nEnsure that the prescribed alerting policy is present:\n3. Go to Alerting by visiting https://console.cloud.google.com/monitoring/alerting.\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\ncondition. For example, Violates when: Any\nlogging.googleapis.com/user/<Log Metric Name> stream is above a\nthreshold of zero(0) for greater than zero(0) seconds means that\nthe alert will trigger for any new owner change. Verify that the chosen alerting\nthresholds make sense for the user's organization.\n5. Ensure that the appropriate notifications channels have been set up.\nFrom Google Cloud CLI\nEnsure that the prescribed log metric is present:\n1. List the log metrics:\ngcloud logging metrics list --format json\n2. Ensure that the output contains at least one metric with the filter set to\nprotoPayload.methodName=\"cloudsql.instances.update\"\n3. Note the value of the property metricDescriptor.type for the identified metric,\nin the format logging.googleapis.com/user/<Log Metric Name>.\nEnsure that the prescribed alerting policy is present:\n4. List the alerting policies:\ngcloud alpha monitoring policies list --format json\n5. Ensure that the output contains at least one alert policy where:\n• conditions.conditionThreshold.filter is set to\nmetric.type=\\\"logging.googleapis.com/user/<Log Metric Name>\\\"\n• AND enabled is set to true",
    "expected_response": "Ensure the prescribed log metric is present:\n2. In the User-defined Metrics section, ensure that at least one metric\n<Log_Metric_Name> is present with the filter text:\nEnsure that the prescribed alerting policy is present:\n4. Under the Policies section, ensure that at least one alert policy exists for the\nlog metric above. Clicking on the policy should show that it is configured with a\n5. Ensure that the appropriate notifications channels have been set up.\nEnsure that the prescribed log metric is present:\n2. Ensure that the output contains at least one metric with the filter set to\n5. Ensure that the output contains at least one alert policy where:\n• conditions.conditionThreshold.filter is set to\n• AND enabled is set to true",
    "remediation": "From Google Cloud Console\nCreate the prescribed Log Metric:\n1. Go to Logging/Logs-based Metrics by visiting\nhttps://console.cloud.google.com/logs/metrics and click \"CREATE METRIC\".\n2. Click the down arrow symbol on the Filter Bar at the rightmost corner and\nselect Convert to Advanced Filter.\n3. Clear any text and add:\nprotoPayload.methodName=\"cloudsql.instances.update\"\n4. Click Submit Filter. Display logs appear based on the filter text entered by the\nuser.\n5. In the Metric Editor menu on right, fill out the name field. Set Units to 1\n(default) and Type to Counter. This ensures that the log metric counts the\nnumber of log entries matching the user's advanced logs query.\n6. Click Create Metric.\nCreate the prescribed alert policy:\n1. Identify the newly created metric under the section User-defined Metrics at\nhttps://console.cloud.google.com/logs/metrics.\n2. Click the 3-dot icon in the rightmost column for the new metric and select Create\nalert from Metric. A new page appears.\n3. Fill out the alert policy configuration and click Save. Choose the alerting threshold\nand configuration that makes sense for the user's organization. For example, a\nthreshold of zero(0) for the most recent value will ensure that a notification is\ntriggered for every owner change in the user's project:\nSet `Aggregator` to `Count`\nSet `Configuration`:\n- Condition: above\n- Threshold: 0\n- For: most recent value\n4. Configure the desired notification channels in the section Notifications.\n5. Name the policy and click Save.\nFrom Google Cloud CLI\nCreate the prescribed log metric:\n• Use the command: gcloud logging metrics create\nCreate the prescribed alert policy:\n• Use the command: gcloud alpha monitoring policies create\n• Reference for command usage:\nhttps://cloud.google.com/sdk/gcloud/reference/alpha/monitoring/policies/create",
    "detection_commands": [
      "gcloud logging metrics list --format json",
      "gcloud alpha monitoring policies list --format json"
    ],
    "remediation_commands": [
      "Create the prescribed Log Metric:",
      "select Convert to Advanced Filter.",
      "Create the prescribed alert policy:",
      "Create the prescribed log metric:"
    ],
    "references": [
      "1. https://cloud.google.com/logging/docs/logs-based-metrics/",
      "2. https://cloud.google.com/monitoring/custom-metrics/",
      "3. https://cloud.google.com/monitoring/alerts/",
      "4. https://cloud.google.com/logging/docs/reference/tools/gcloud-logging",
      "5. https://cloud.google.com/storage/docs/overview",
      "6. https://cloud.google.com/sql/docs/",
      "7. https://cloud.google.com/sql/docs/mysql/",
      "8. https://cloud.google.com/sql/docs/postgres/"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 111,
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
    "cis_id": "2.12",
    "title": "Ensure That Cloud DNS Logging Is Enabled for All VPC Networks",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Enable Detailed Logging",
    "description": "Cloud DNS logging records the queries from the name servers within your VPC to\nStackdriver. Logged queries can come from Compute Engine VMs, GKE containers, or\nother GCP resources provisioned within the VPC.",
    "rationale": "Security monitoring and forensics cannot depend solely on IP addresses from VPC flow\nlogs, especially when considering the dynamic IP usage of cloud resources, HTTP\nvirtual host routing, and other technology that can obscure the DNS name used by a\nclient from the IP address. Monitoring of Cloud DNS logs provides visibility to DNS\nnames requested by the clients within the VPC. These logs can be monitored for\nanomalous domain names, evaluated against threat intelligence, and\nNote: For full capture of DNS, firewall must block egress UDP/53 (DNS) and TCP/443\n(DNS over HTTPS) to prevent client from using external DNS name server for\nresolution.",
    "impact": "Enabling of Cloud DNS logging might result in your project being charged for the\nadditional logs usage.",
    "audit": "From Google Cloud CLI\n1. List all VPCs networks in a project:\ngcloud compute networks list --format=\"table[box,title='All VPC\nNetworks'](name:label='VPC Network Name')\"\n2. List all DNS policies, logging enablement, and associated VPC networks:\ngcloud dns policies list --flatten=\"networks[]\" --\nformat=\"table[box,title='All DNS Policies By VPC Network'](name:label='Policy\nName',enableLogging:label='Logging\nEnabled':align=center,networks.networkUrl.basename():label='VPC Network\nName')\"\nEach VPC Network should be associated with a DNS policy with logging enabled.",
    "expected_response": "Each VPC Network should be associated with a DNS policy with logging enabled.",
    "remediation": "From Google Cloud CLI\nAdd New DNS Policy With Logging Enabled\nFor each VPC network that needs a DNS policy with logging enabled:\ngcloud dns policies create enable-dns-logging --enable-logging --\ndescription=\"Enable DNS Logging\" --networks=VPC_NETWORK_NAME\nThe VPC_NETWORK_NAME can be one or more networks in comma-separated list\nEnable Logging for Existing DNS Policy\nFor each VPC network that has an existing DNS policy that needs logging enabled:\ngcloud dns policies update POLICY_NAME --enable-logging --\nnetworks=VPC_NETWORK_NAME\nThe VPC_NETWORK_NAME can be one or more networks in comma-separated list",
    "default_value": "Cloud DNS logging is disabled by default on each network.",
    "additional_information": "Additional Info\n• Only queries that reach a name server are logged. Cloud DNS resolvers cache\nresponses, queries answered from caches, or direct queries to an external DNS\nresolver outside the VPC are not logged.",
    "detection_commands": [
      "gcloud compute networks list --format=\"table[box,title='All VPC",
      "gcloud dns policies list --flatten=\"networks[]\" --"
    ],
    "remediation_commands": [
      "gcloud dns policies create enable-dns-logging --enable-logging --",
      "gcloud dns policies update POLICY_NAME --enable-logging --"
    ],
    "references": [
      "1. https://cloud.google.com/dns/docs/monitoring"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 115,
    "dspm_relevant": true,
    "dspm_categories": [
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
    "cis_id": "2.13",
    "title": "Ensure Cloud Asset Inventory Is Enabled",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Enable DNS Query Logging",
    "description": "GCP Cloud Asset Inventory is services that provides a historical view of GCP resources\nand IAM policies through a time-series database. The information recorded includes\nmetadata on Google Cloud resources, metadata on policies set on Google Cloud\nprojects or resources, and runtime information gathered within a Google Cloud\nresource.\nCloud Asset Inventory Service (CAIS) API enablement is not required for operation of\nthe service, but rather enables the mechanism for searching/exporting CAIS asset data\ndirectly.",
    "rationale": "The GCP resources and IAM policies captured by GCP Cloud Asset Inventory enables\nsecurity analysis, resource change tracking, and compliance auditing.\nIt is recommended GCP Cloud Asset Inventory be enabled for all GCP projects.",
    "audit": "From Google Cloud Console\nEnsure that the Cloud Asset API is enabled:\n1. Go to API & Services/Library by visiting\nhttps://console.cloud.google.com/apis/library\n2. Search for Cloud Asset API and select the result for Cloud Asset API\n3. Ensure that API Enabled is displayed.\nFrom Google Cloud CLI\nEnsure that the Cloud Asset API is enabled:\n1. Query enabled services:\ngcloud services list --enabled --filter=name:cloudasset.googleapis.com\nIf the API is listed, then it is enabled. If the response is Listed 0 items the API is not\nenabled.",
    "expected_response": "Ensure that the Cloud Asset API is enabled:\n3. Ensure that API Enabled is displayed.\nIf the API is listed, then it is enabled. If the response is Listed 0 items the API is not",
    "remediation": "From Google Cloud Console\nEnable the Cloud Asset API:\n1. Go to API & Services/Library by visiting\nhttps://console.cloud.google.com/apis/library\n2. Search for Cloud Asset API and select the result for Cloud Asset API\n3. Click the ENABLE button.\nFrom Google Cloud CLI\nEnable the Cloud Asset API:\n1. Enable the Cloud Asset API through the services interface:\ngcloud services enable cloudasset.googleapis.com",
    "default_value": "The Cloud Asset Inventory API is disabled by default in each project.",
    "additional_information": "Additional info\n• Cloud Asset Inventory only keeps a five-week history of Google Cloud asset\nmetadata. If a longer history is desired, automation to export the history to Cloud\nStorage or BigQuery should be evaluated.\nUsers need not enable CAI API if they don't have any plans to export.",
    "detection_commands": [
      "gcloud services list --enabled --filter=name:cloudasset.googleapis.com"
    ],
    "remediation_commands": [
      "gcloud services enable cloudasset.googleapis.com"
    ],
    "references": [
      "1. https://cloud.google.com/asset-inventory/docs"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 118,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "logging"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D2",
      "D6"
    ]
  },
  {
    "cis_id": "2.14",
    "title": "Ensure 'Access Transparency' is 'Enabled'",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Maintain an Inventory of Authentication Systems",
    "description": "GCP Access Transparency provides audit logs for all actions that Google personnel\ntake in your Google Cloud resources.",
    "rationale": "Controlling access to your information is one of the foundations of information security.\nGiven that Google Employees do have access to your organizations' projects for\nsupport reasons, you should have logging in place to view who, when, and why your\ninformation is being accessed.",
    "impact": "To use Access Transparency your organization will need to have at one of the following\nsupport level: Premium, Enterprise, Platinum, or Gold. There will be subscription costs\nassociated with support, as well as increased storage costs for storing the logs. You will\nalso not be able to turn Access Transparency off yourself, and you will need to submit a\nservice request to Google Cloud Support.",
    "audit": "From Google Cloud Console\nDetermine if Access Transparency is Enabled\n1. From the Google Cloud Home, click on the Navigation hamburger menu in the\ntop left. Hover over the IAM & Admin Menu. Select settings in the middle of the\ncolumn that opens.\n2. The status will be under the heading Access Transparency. Status should be\nEnabled",
    "expected_response": "Determine if Access Transparency is Enabled\n2. The status will be under the heading Access Transparency. Status should be",
    "remediation": "From Google Cloud Console\nAdd privileges to enable Access Transparency\n1. From the Google Cloud Home, within the project you wish to check, click on the\nNavigation hamburger menu in the top left. Hover over the 'IAM and Admin'.\nSelect IAM in the top of the column that opens.\n2. Click the blue button the says +add at the top of the screen.\n3. In the principals field, select a user or group by typing in their associated email\naddress.\n4. Click on the role field to expand it. In the filter field enter Access Transparency\nAdmin and select it.\n5. Click save.\nVerify that the Google Cloud project is associated with a billing account\n1. From the Google Cloud Home, click on the Navigation hamburger menu in the\ntop left. Select Billing.\n2. If you see This project is not associated with a billing account you\nwill need to enter billing information or switch to a project with a billing account.\nEnable Access Transparency\n1. From the Google Cloud Home, click on the Navigation hamburger menu in the\ntop left. Hover over the IAM & Admin Menu. Select settings in the middle of the\ncolumn that opens.\n2. Click the blue button labeled Enable Access Transparency for\nOrganization",
    "default_value": "By default Access Transparency is not enabled.",
    "additional_information": "To enable Access Transparency for your Google Cloud organization, your Google\nCloud organization must have one of the following customer support levels: Premium,\nEnterprise, Platinum, or Gold.",
    "detection_commands": [],
    "remediation_commands": [
      "Select IAM in the top of the column that opens."
    ],
    "references": [
      "1. https://cloud.google.com/cloud-provider-access-management/access-",
      "transparency/docs/overview",
      "2. https://cloud.google.com/cloud-provider-access-management/access-",
      "transparency/docs/enable",
      "3. https://cloud.google.com/cloud-provider-access-management/access-",
      "transparency/docs/reading-logs",
      "4. https://cloud.google.com/cloud-provider-access-management/access-",
      "transparency/docs/reading-logs#justification_reason_codes",
      "5. https://cloud.google.com/cloud-provider-access-management/access-",
      "transparency/docs/supported-services"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 121,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D6"
    ]
  },
  {
    "cis_id": "2.15",
    "title": "Ensure 'Access Approval' is 'Enabled'",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Enable Detailed Logging",
    "description": "GCP Access Approval enables you to require your organizations' explicit approval\nwhenever Google support try to access your projects. You can then select users within\nyour organization who can approve these requests through giving them a security role\nin IAM. All access requests display which Google Employee requested them in an email\nor Pub/Sub message that you can choose to Approve. This adds an additional control\nand logging of who in your organization approved/denied these requests.",
    "rationale": "Controlling access to your information is one of the foundations of information security.\nGoogle Employees do have access to your organizations' projects for support reasons.\nWith Access Approval, organizations can then be certain that their information is\naccessed by only approved Google Personnel.",
    "impact": "To use Access Approval your organization will need have enabled Access\nTransparency and have at one of the following support level: Enhanced or Premium.\nThere will be subscription costs associated with these support levels, as well as\nincreased storage costs for storing the logs. You will also not be able to turn the Access\nTransparency which Access Approval depends on, off yourself. To do so you will need\nto submit a service request to Google Cloud Support. There will also be additional\noverhead in managing user permissions. There may also be a potential delay in support\ntimes as Google Personnel will have to wait for their access to be approved.",
    "audit": "From Google Cloud Console\nDetermine if Access Transparency is Enabled as it is a Dependency\n1. From the Google Cloud Home inside the project you wish to audit, click on the\nNavigation hamburger menu in the top left. Hover over the IAM & Admin Menu.\nSelect settings in the middle of the column that opens.\n2. The status should be \"Enabled' under the heading Access Transparency\nDetermine if Access Approval is Enabled\n1. From the Google Cloud Home, within the project you wish to check, click on the\nNavigation hamburger menu in the top left. Hover over the Security Menu.\nSelect Access Approval in the middle of the column that opens.\n2. The status will be displayed here. If you see a screen saying you need to enroll in\nAccess Approval, it is not enabled.\nFrom Google Cloud CLI\nDetermine if Access Approval is Enabled\n1. From within the project you wish to audit, run the following command.\ngcloud access-approval settings get\n2. The status will be displayed in the output.\nIF Access Approval is not enabled you should get this output:\nAPI [accessapproval.googleapis.com] not enabled on project [-----]. Would you\nlike to enable and retry (this will take a few minutes)? (y/N)?\nAfter entering Y if you get the following output, it means that Access Transparency is\nnot enabled:\nERROR: (gcloud.access-approval.settings.get) FAILED_PRECONDITION:\nPrecondition check failed.",
    "expected_response": "Determine if Access Transparency is Enabled as it is a Dependency\n2. The status should be \"Enabled' under the heading Access Transparency\nDetermine if Access Approval is Enabled\n2. The status will be displayed in the output.\nIF Access Approval is not enabled you should get this output:\nAfter entering Y if you get the following output, it means that Access Transparency is",
    "remediation": "From Google Cloud Console\n1. From the Google Cloud Home, within the project you wish to enable, click on the\nNavigation hamburger menu in the top left. Hover over the Security Menu.\nSelect Access Approval in the middle of the column that opens.\n2. The status will be displayed here. On this screen, there is an option to click\nEnroll. If it is greyed out and you see an error bar at the top of the screen that\nsays Access Transparency is not enabled please view the corresponding\nreference within this section to enable it.\n3. In the second screen click Enroll.\nGrant an IAM Group or User the role with permissions to Add Users to be Access\nApproval message Recipients\n1. From the Google Cloud Home, within the project you wish to enable, click on the\nNavigation hamburger menu in the top left. Hover over the IAM and Admin.\nSelect IAM in the middle of the column that opens.\n2. Click the blue button the says + ADD at the top of the screen.\n3. In the principals field, select a user or group by typing in their associated email\naddress.\n4. Click on the role field to expand it. In the filter field enter Access Approval\nApprover and select it.\n5. Click save.\nAdd a Group or User as an Approver for Access Approval Requests\n1. As a user with the Access Approval Approver permission, within the project\nwhere you wish to add an email address to which request will be sent, click on\nthe Navigation hamburger menu in the top left. Hover over the Security Menu.\nSelect Access Approval in the middle of the column that opens.\n2. Click Manage Settings\n3. Under Set up approval notifications, enter the email address associated\nwith a Google Cloud User or Group you wish to send Access Approval requests\nto. All future access approvals will be sent as emails to this address.\nFrom Google Cloud CLI\n1. To update all services in an entire project, run the following command from an\naccount that has permissions as an 'Approver for Access Approval Requests'\ngcloud access-approval settings update --project=<project name> --\nenrolled_services=all --notification_emails='<email recipient for access\napproval requests>@<domain name>'",
    "default_value": "By default Access Approval and its dependency of Access Transparency are not\nenabled.",
    "additional_information": "The recipients of Access Requests will also need to be logged into a Google Cloud\naccount associated with an email address in this list. To approve requests they can click\napprove within the email. Or they can view requests at the the Access Approval page\nwithin the Security submenu.",
    "detection_commands": [
      "Select settings in the middle of the column that opens.",
      "Select Access Approval in the middle of the column that opens.",
      "gcloud access-approval settings get"
    ],
    "remediation_commands": [
      "Select Access Approval in the middle of the column that opens.",
      "Grant an IAM Group or User the role with permissions to Add Users to be Access",
      "Select IAM in the middle of the column that opens.",
      "gcloud access-approval settings update --project=<project name> --"
    ],
    "references": [
      "1. https://cloud.google.com/cloud-provider-access-management/access-",
      "approval/docs",
      "2. https://cloud.google.com/cloud-provider-access-management/access-",
      "approval/docs/overview",
      "3. https://cloud.google.com/cloud-provider-access-management/access-",
      "approval/docs/quickstart-custom-key",
      "4. https://cloud.google.com/cloud-provider-access-management/access-",
      "approval/docs/supported-services",
      "5. https://cloud.google.com/cloud-provider-access-management/access-",
      "approval/docs/view-historical-requests"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 124,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D1",
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "2.16",
    "title": "Ensure Logging is enabled for HTTP(S) Load Balancer",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "logging_monitoring",
    "domain": "Logging and Monitoring",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "Logging enabled on a HTTPS Load Balancer will show all network traffic and its\ndestination.",
    "rationale": "Logging will allow you to view HTTPS network traffic to your web applications.",
    "impact": "On high use systems with a high percentage sample rate, the logging file may grow to\nhigh capacity in a short amount of time. Ensure that the sample rate is set appropriately\nso that storage costs are not exorbitant.",
    "audit": "From Google Cloud Console\n1. From Google Cloud home open the Navigation Menu in the top left.\n2. Under the Networking heading select Network services.\n3. Select the HTTPS load-balancer you wish to audit.\n4. Select Edit then Backend Configuration.\n5. Select Edit on the corresponding backend service.\n6. Ensure that Enable Logging is selected. Also ensure that Sample Rate is set to\nan appropriate level for your needs.\nFrom Google Cloud CLI\n1. Run the following command\ngcloud compute backend-services describe <serviceName>\n1. Ensure that enable-logging is enabled and sample rate is set to your desired\nlevel.",
    "expected_response": "6. Ensure that Enable Logging is selected. Also ensure that Sample Rate is set to\n1. Ensure that enable-logging is enabled and sample rate is set to your desired",
    "remediation": "From Google Cloud Console\n1. From Google Cloud home open the Navigation Menu in the top left.\n2. Under the Networking heading select Network services.\n3. Select the HTTPS load-balancer you wish to audit.\n4. Select Edit then Backend Configuration.\n5. Select Edit on the corresponding backend service.\n6. Click Enable Logging.\n7. Set Sample Rate to a desired value. This is a percentage as a decimal point. 1.0\nis 100%.\nFrom Google Cloud CLI\n1. Run the following command\ngcloud compute backend-services update <serviceName> --region=REGION --\nenable-logging --logging-sample-rate=<percentageAsADecimal>",
    "default_value": "By default logging for https load balancing is disabled. When logging is enabled it sets\nthe default sample rate as 1.0 or 100%. Ensure this value fits the need of your\norganization to avoid high storage costs.",
    "detection_commands": [
      "gcloud compute backend-services describe <serviceName>"
    ],
    "remediation_commands": [
      "gcloud compute backend-services update <serviceName> --region=REGION --"
    ],
    "references": [
      "1. https://cloud.google.com/load-balancing/",
      "2. https://cloud.google.com/load-balancing/docs/https/https-logging-",
      "monitoring#gcloud:-global-mode",
      "3. https://cloud.google.com/sdk/gcloud/reference/compute/backend-services/"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 128,
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
    "cis_id": "3.1",
    "title": "Ensure That the Default Network Does Not Exist in a Project",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "networking",
    "domain": "Networking",
    "description": "To prevent use of default network, a project should not have a default network.",
    "rationale": "The default network has a preconfigured network configuration and automatically\ngenerates the following insecure firewall rules:\n• default-allow-internal: Allows ingress connections for all protocols and ports\namong instances in the network.\n• default-allow-ssh: Allows ingress connections on TCP port 22(SSH) from any\nsource to any instance in the network.\n• default-allow-rdp: Allows ingress connections on TCP port 3389(RDP) from any\nsource to any instance in the network.\n• default-allow-icmp: Allows ingress ICMP traffic from any source to any instance\nin the network.\nThese automatically created firewall rules do not get audit logged by default.\nFurthermore, the default network is an auto mode network, which means that its\nsubnets use the same predefined range of IP addresses, and as a result, it's not\npossible to use Cloud VPN or VPC Network Peering with the default network.\nBased on organization security and networking requirements, the organization should\ncreate a new network and delete the default network.",
    "impact": "When an organization deletes the default network, it will need to remove all asests from\nthat network and migrate them to a new network.",
    "audit": "From Google Cloud Console\n1. Go to the VPC networks page by visiting:\nhttps://console.cloud.google.com/networking/networks/list.\n2. Ensure that a network with the name default is not present.\nFrom Google Cloud CLI\n1. Set the project name in the Google Cloud Shell:\ngcloud config set project PROJECT_ID\n2. List the networks configured in that project:\ngcloud compute networks list\nIt should not list default as one of the available networks in that project.",
    "expected_response": "2. Ensure that a network with the name default is not present.\nIt should not list default as one of the available networks in that project.",
    "remediation": "From Google Cloud Console\n1. Go to the VPC networks page by visiting:\nhttps://console.cloud.google.com/networking/networks/list.\n2. Click the network named default.\n3. On the network detail page, click EDIT.\n4. Click DELETE VPC NETWORK.\n5. If needed, create a new network to replace the default network.\nFrom Google Cloud CLI\nFor each Google Cloud Platform project,\n1. Delete the default network:\ngcloud compute networks delete default\n2. If needed, create a new network to replace it:\ngcloud compute networks create NETWORK_NAME\nPrevention:\nThe user can prevent the default network and its insecure default firewall rules from\nbeing created by setting up an Organization Policy to Skip default network\ncreation at https://console.cloud.google.com/iam-admin/orgpolicies/compute-\nskipDefaultNetworkCreation.",
    "default_value": "By default, for each project, a default network is created.",
    "detection_commands": [
      "gcloud config set project PROJECT_ID",
      "gcloud compute networks list"
    ],
    "remediation_commands": [
      "gcloud compute networks delete default",
      "gcloud compute networks create NETWORK_NAME"
    ],
    "references": [
      "1. https://cloud.google.com/compute/docs/networking#firewall_rules",
      "2. https://cloud.google.com/compute/docs/reference/latest/networks/insert",
      "3. https://cloud.google.com/compute/docs/reference/latest/networks/delete",
      "4. https://cloud.google.com/vpc/docs/firewall-rules-logging",
      "5. https://cloud.google.com/vpc/docs/vpc#default-network",
      "6. https://cloud.google.com/sdk/gcloud/reference/compute/networks/delete"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 131,
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
    "cis_id": "3.2",
    "title": "Ensure Legacy Networks Do Not Exist for Older Projects",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Maintain Standard Security Configurations for",
    "description": "In order to prevent use of legacy networks, a project should not have a legacy network\nconfigured. As of now, Legacy Networks are gradually being phased out, and you can\nno longer create projects with them. This recommendation is to check older projects to\nensure that they are not using Legacy Networks.",
    "rationale": "Legacy networks have a single network IPv4 prefix range and a single gateway IP\naddress for the whole network. The network is global in scope and spans all cloud\nregions. Subnetworks cannot be created in a legacy network and are unable to switch\nfrom legacy to auto or custom subnet networks. Legacy networks can have an impact\nfor high network traffic projects and are subject to a single point of contention or failure.",
    "impact": "None.",
    "audit": "From Google Cloud CLI\nFor each Google Cloud Platform project,\n1. Set the project name in the Google Cloud Shell:\ngcloud config set project <Project-ID>\n2. List the networks configured in that project:\ngcloud compute networks list\nNone of the listed networks should be in the legacy mode.",
    "expected_response": "None of the listed networks should be in the legacy mode.",
    "remediation": "From Google Cloud CLI\nFor each Google Cloud Platform project,\n1. Follow the documentation and create a non-legacy network suitable for the\norganization's requirements.\n2. Follow the documentation and delete the networks in the legacy mode.",
    "default_value": "By default, networks are not created in the legacy mode.",
    "detection_commands": [
      "gcloud config set project <Project-ID>",
      "gcloud compute networks list"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.google.com/vpc/docs/using-legacy#creating_a_legacy_network",
      "2. https://cloud.google.com/vpc/docs/using-legacy#deleting_a_legacy_network"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 134,
    "dspm_relevant": false,
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "3.3",
    "title": "Ensure That DNSSEC Is Enabled for Cloud DNS",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Maintain Standard Security Configurations for",
    "description": "Cloud Domain Name System (DNS) is a fast, reliable and cost-effective domain name\nsystem that powers millions of domains on the internet. Domain Name System Security\nExtensions (DNSSEC) in Cloud DNS enables domain owners to take easy steps to\nprotect their domains against DNS hijacking and man-in-the-middle and other attacks.",
    "rationale": "Domain Name System Security Extensions (DNSSEC) adds security to the DNS\nprotocol by enabling DNS responses to be validated. Having a trustworthy DNS that\ntranslates a domain name like www.example.com into its associated IP address is an\nincreasingly important building block of today’s web-based applications. Attackers can\nhijack this process of domain/IP lookup and redirect users to a malicious site through\nDNS hijacking and man-in-the-middle attacks. DNSSEC helps mitigate the risk of such\nattacks by cryptographically signing DNS records. As a result, it prevents attackers from\nissuing fake DNS responses that may misdirect browsers to nefarious websites.",
    "audit": "From Google Cloud Console\n1. Go to Cloud DNS by visiting https://console.cloud.google.com/net-\nservices/dns/zones.\n2. For each zone of Type Public, ensure that DNSSEC is set to On.\nFrom Google Cloud CLI\n1. List all the Managed Zones in a project:\ngcloud dns managed-zones list\n2. For each zone of VISIBILITY public, get its metadata:\ngcloud dns managed-zones describe ZONE_NAME\n3. Ensure that dnssecConfig.state property is on.",
    "expected_response": "2. For each zone of Type Public, ensure that DNSSEC is set to On.\n3. Ensure that dnssecConfig.state property is on.",
    "remediation": "From Google Cloud Console\n1. Go to Cloud DNS by visiting https://console.cloud.google.com/net-\nservices/dns/zones.\n2. For each zone of Type Public, set DNSSEC to On.\nFrom Google Cloud CLI\nUse the below command to enable DNSSEC for Cloud DNS Zone Name.\ngcloud dns managed-zones update ZONE_NAME --dnssec-state on",
    "default_value": "By default DNSSEC is not enabled.",
    "detection_commands": [
      "gcloud dns managed-zones list",
      "gcloud dns managed-zones describe ZONE_NAME"
    ],
    "remediation_commands": [
      "Use the below command to enable DNSSEC for Cloud DNS Zone Name. gcloud dns managed-zones update ZONE_NAME --dnssec-state on"
    ],
    "references": [
      "1. https://cloudplatform.googleblog.com/2017/11/DNSSEC-now-available-in-Cloud-",
      "DNS.html",
      "2. https://cloud.google.com/dns/dnssec-config#enabling",
      "3. https://cloud.google.com/dns/dnssec"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 136,
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
    "cis_id": "3.4",
    "title": "Ensure That RSASHA1 Is Not Used for the Key-Signing Key in Cloud DNS DNSSEC",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Maintain Standard Security Configurations for",
    "description": "NOTE: Currently, the SHA1 algorithm has been removed from general use by Google,\nand, if being used, needs to be whitelisted on a project basis by Google and will also,\ntherefore, require a Google Cloud support contract.\nDNSSEC algorithm numbers in this registry may be used in CERT RRs. Zone signing\n(DNSSEC) and transaction security mechanisms (SIG(0) and TSIG) make use of\nparticular subsets of these algorithms. The algorithm used for key signing should be a\nrecommended one and it should be strong.",
    "rationale": "Domain Name System Security Extensions (DNSSEC) algorithm numbers in this\nregistry may be used in CERT RRs. Zonesigning (DNSSEC) and transaction security\nmechanisms (SIG(0) and TSIG) make use of particular subsets of these algorithms.\nThe algorithm used for key signing should be a recommended one and it should be\nstrong. When enabling DNSSEC for a managed zone, or creating a managed zone with\nDNSSEC, the user can select the DNSSEC signing algorithms and the denial-of-\nexistence type. Changing the DNSSEC settings is only effective for a managed zone if\nDNSSEC is not already enabled. If there is a need to change the settings for a\nmanaged zone where it has been enabled, turn DNSSEC off and then re-enable it with\ndifferent settings.",
    "audit": "From Google Cloud CLI\nEnsure the property algorithm for keyType keySigning is not using RSASHA1.\ngcloud dns managed-zones describe ZONENAME --\nformat=\"json(dnsName,dnssecConfig.state,dnssecConfig.defaultKeySpecs)\"",
    "expected_response": "Ensure the property algorithm for keyType keySigning is not using RSASHA1.",
    "remediation": "From Google Cloud CLI\n1. If it is necessary to change the settings for a managed zone where it has been\nenabled, DNSSEC must be turned off and re-enabled with different settings. To\nturn off DNSSEC, run the following command:\ngcloud dns managed-zones update ZONE_NAME --dnssec-state off\n2. To update key-signing for a reported managed DNS Zone, run the following\ncommand:\ngcloud dns managed-zones update ZONE_NAME --dnssec-state on --ksk-algorithm\nKSK_ALGORITHM --ksk-key-length KSK_KEY_LENGTH --zsk-algorithm ZSK_ALGORITHM -\n-zsk-key-length ZSK_KEY_LENGTH --denial-of-existence DENIAL_OF_EXISTENCE\nSupported algorithm options and key lengths are as follows.\nAlgorithm                        KSK Length               ZSK Length\n---------                        ----------               ----------\nRSASHA1                          1024,2048                1024,2048\nRSASHA256                        1024,2048                1024,2048\nRSASHA512                        1024,2048                1024,2048\nECDSAP256SHA256                  256                      256\nECDSAP384SHA384                  384                      384",
    "additional_information": "1. RSASHA1 key-signing support may be required for compatibility reasons.\n2. Remediation CLI works well with gcloud-cli version 221.0.0 and later.",
    "detection_commands": [
      "gcloud dns managed-zones describe ZONENAME --"
    ],
    "remediation_commands": [
      "gcloud dns managed-zones update ZONE_NAME --dnssec-state off",
      "gcloud dns managed-zones update ZONE_NAME --dnssec-state on --ksk-algorithm"
    ],
    "references": [
      "1. https://cloud.google.com/dns/dnssec-advanced#advanced_signing_options"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 138,
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
    "cis_id": "3.5",
    "title": "Ensure That RSASHA1 Is Not Used for the Zone-Signing Key in Cloud DNS DNSSEC",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Maintain Standard Security Configurations for",
    "description": "NOTE: Currently, the SHA1 algorithm has been removed from general use by Google,\nand, if being used, needs to be whitelisted on a project basis by Google and will also,\ntherefore, require a Google Cloud support contract.\nDNSSEC algorithm numbers in this registry may be used in CERT RRs. Zone signing\n(DNSSEC) and transaction security mechanisms (SIG(0) and TSIG) make use of\nparticular subsets of these algorithms. The algorithm used for key signing should be a\nrecommended one and it should be strong.",
    "rationale": "DNSSEC algorithm numbers in this registry may be used in CERT RRs. Zone signing\n(DNSSEC) and transaction security mechanisms (SIG(0) and TSIG) make use of\nparticular subsets of these algorithms.\nThe algorithm used for key signing should be a recommended one and it should be\nstrong. When enabling DNSSEC for a managed zone, or creating a managed zone with\nDNSSEC, the DNSSEC signing algorithms and the denial-of-existence type can be\nselected. Changing the DNSSEC settings is only effective for a managed zone if\nDNSSEC is not already enabled. If the need exists to change the settings for a\nmanaged zone where it has been enabled, turn DNSSEC off and then re-enable it with\ndifferent settings.",
    "audit": "From Google Cloud CLI\nEnsure the property algorithm for keyType zone signing is not using RSASHA1.\ngcloud dns managed-zones describe --\nformat=\"json(dnsName,dnssecConfig.state,dnssecConfig.defaultKeySpecs)\"",
    "expected_response": "Ensure the property algorithm for keyType zone signing is not using RSASHA1.",
    "remediation": "From Google Cloud CLI\n1. If the need exists to change the settings for a managed zone where it has been\nenabled, DNSSEC must be turned off and then re-enabled with different settings.\nTo turn off DNSSEC, run following command:\ngcloud dns managed-zones update ZONE_NAME --dnssec-state off\n2. To update zone-signing for a reported managed DNS Zone, run the following\ncommand:\ngcloud dns managed-zones update ZONE_NAME --dnssec-state on --ksk-algorithm\nKSK_ALGORITHM --ksk-key-length KSK_KEY_LENGTH --zsk-algorithm ZSK_ALGORITHM -\n-zsk-key-length ZSK_KEY_LENGTH --denial-of-existence DENIAL_OF_EXISTENCE\nSupported algorithm options and key lengths are as follows.\nAlgorithm                 KSK Length            ZSK Length\n---------                 ----------            ----------\nRSASHA1                   1024,2048             1024,2048\nRSASHA256                 1024,2048             1024,2048\nRSASHA512                 1024,2048             1024,2048\nECDSAP256SHA256           256                   384\nECDSAP384SHA384           384                   384",
    "additional_information": "1. RSASHA1 zone-signing support may be required for compatibility reasons.\n2. The remediation CLI works well with gcloud-cli version 221.0.0 and later.",
    "detection_commands": [
      "gcloud dns managed-zones describe --"
    ],
    "remediation_commands": [
      "gcloud dns managed-zones update ZONE_NAME --dnssec-state off",
      "gcloud dns managed-zones update ZONE_NAME --dnssec-state on --ksk-algorithm"
    ],
    "references": [
      "1. https://cloud.google.com/dns/dnssec-advanced#advanced_signing_options"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 140,
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
    "cis_id": "3.6",
    "title": "Ensure That SSH Access Is Restricted From the Internet",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Maintain Standard Security Configurations for",
    "description": "GCP Firewall Rules are specific to a VPC Network. Each rule either allows or\ndenies traffic when its conditions are met. Its conditions allow the user to specify the\ntype of traffic, such as ports and protocols, and the source or destination of the traffic,\nincluding IP addresses, subnets, and instances.\nFirewall rules are defined at the VPC network level and are specific to the network in\nwhich they are defined. The rules themselves cannot be shared among networks.\nFirewall rules only support IPv4 traffic. When specifying a source for an ingress rule or a\ndestination for an egress rule by address, only an IPv4 address or IPv4 block in\nCIDR notation can be used. Generic (0.0.0.0/0) incoming traffic from the internet to\nVPC or VM instance using SSH on Port 22 can be avoided.",
    "rationale": "GCP Firewall Rules within a VPC Network apply to outgoing (egress) traffic from\ninstances and incoming (ingress) traffic to instances in the network. Egress and ingress\ntraffic flows are controlled even if the traffic stays within the network (for example,\ninstance-to-instance communication). For an instance to have outgoing Internet access,\nthe network must have a valid Internet gateway route or custom route whose destination\nIP is specified. This route simply defines the path to the Internet, to avoid the most\ngeneral (0.0.0.0/0) destination IP Range specified from the Internet through SSH with\nthe default Port 22. Generic access from the Internet to a specific IP Range needs to\nbe restricted.",
    "impact": "All Secure Shell (SSH) connections from outside of the network to the concerned\nVPC(s) will be blocked. There could be a business need where SSH access is required\nfrom outside of the network to access resources associated with the VPC. In that case,\nspecific source IP(s) should be mentioned in firewall rules to white-list access to SSH\nport for the concerned VPC(s).",
    "audit": "From Google Cloud Console\n1. Go to VPC network.\n2. Go to the Firewall Rules.\n3. Ensure that Port is not equal to 22 and Action is not set to Allow.\n4. Ensure IP Ranges is not equal to 0.0.0.0/0 under Source filters.\nFrom Google Cloud CLI\ngcloud compute firewall-rules list --\nformat=table'(name,direction,sourceRanges,allowed)'\nEnsure that there is no rule matching the below criteria:\n• SOURCE_RANGES is 0.0.0.0/0\n• AND DIRECTION is INGRESS\n• AND IPProtocol is tcp or ALL\n• AND PORTS is set to 22 or range containing 22 or Null (not set)\nNote:\n• When ALL TCP ports are allowed in a rule, PORT does not have any value set\n(NULL)\n• When ALL Protocols are allowed in a rule, PORT does not have any value set\n(NULL)",
    "expected_response": "3. Ensure that Port is not equal to 22 and Action is not set to Allow.\n4. Ensure IP Ranges is not equal to 0.0.0.0/0 under Source filters.\nEnsure that there is no rule matching the below criteria:\n• AND PORTS is set to 22 or range containing 22 or Null (not set)",
    "remediation": "From Google Cloud Console\n1. Go to VPC Network.\n2. Go to the Firewall Rules.\n3. Click the Firewall Rule you want to modify.\n4. Click Edit.\n5. Modify Source IP ranges to specific IP.\n6. Click Save.\nFrom Google Cloud CLI\n1.Update the Firewall rule with the new SOURCE_RANGE from the below command:\ngcloud compute firewall-rules update FirewallName --allow=[PROTOCOL[:PORT[-\nPORT]],...] --source-ranges=[CIDR_RANGE,...]",
    "additional_information": "Currently, GCP VPC only supports IPV4; however, Google is already working on adding\nIPV6 support for VPC. In that case along with source IP range 0.0.0.0, the rule should\nbe checked for IPv6 equivalent ::/0 as well.",
    "detection_commands": [
      "gcloud compute firewall-rules list --"
    ],
    "remediation_commands": [
      "gcloud compute firewall-rules update FirewallName --allow=[PROTOCOL[:PORT[-"
    ],
    "references": [
      "1. https://cloud.google.com/vpc/docs/firewalls#blockedtraffic",
      "2. https://cloud.google.com/blog/products/identity-security/cloud-iap-enables-",
      "context-aware-access-to-vms-via-ssh-and-rdp-without-bastion-hosts"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 142,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "3.7",
    "title": "Ensure That RDP Access Is Restricted From the Internet",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Deny Communication over Unauthorized Ports",
    "description": "GCP Firewall Rules are specific to a VPC Network. Each rule either allows or\ndenies traffic when its conditions are met. Its conditions allow users to specify the type\nof traffic, such as ports and protocols, and the source or destination of the traffic,\nincluding IP addresses, subnets, and instances.\nFirewall rules are defined at the VPC network level and are specific to the network in\nwhich they are defined. The rules themselves cannot be shared among networks.\nFirewall rules only support IPv4 traffic. When specifying a source for an ingress rule or a\ndestination for an egress rule by address, an IPv4 address or IPv4 block in CIDR\nnotation can be used. Generic (0.0.0.0/0) incoming traffic from the Internet to a VPC\nor VM instance using RDP on Port 3389 can be avoided.",
    "rationale": "GCP Firewall Rules within a VPC Network. These rules apply to outgoing (egress)\ntraffic from instances and incoming (ingress) traffic to instances in the network. Egress\nand ingress traffic flows are controlled even if the traffic stays within the network (for\nexample, instance-to-instance communication). For an instance to have outgoing\nInternet access, the network must have a valid Internet gateway route or custom route\nwhose destination IP is specified. This route simply defines the path to the Internet, to\navoid the most general (0.0.0.0/0) destination IP Range specified from the Internet\nthrough RDP with the default Port 3389. Generic access from the Internet to a specific\nIP Range should be restricted.",
    "impact": "All Remote Desktop Protocol (RDP) connections from outside of the network to the\nconcerned VPC(s) will be blocked. There could be a business need where secure shell\naccess is required from outside of the network to access resources associated with the\nVPC. In that case, specific source IP(s) should be mentioned in firewall rules to white-\nlist access to RDP port for the concerned VPC(s).",
    "audit": "From Google Cloud Console\n1. Go to VPC network.\n2. Go to the Firewall Rules.\n3. Ensure Port is not equal to 3389 and Action is not Allow.\n4. Ensure IP Ranges is not equal to 0.0.0.0/0 under Source filters.\nFrom Google Cloud CLI\ngcloud compute firewall-rules list --\nformat=table'(name,direction,sourceRanges,allowed)'\nEnsure that there is no rule matching the below criteria:\n• SOURCE_RANGES is 0.0.0.0/0\n• AND DIRECTION is INGRESS\n• AND IPProtocol is TCP or ALL\n• AND PORTS is set to 3389 or range containing 3389 or Null (not set)\nNote:\n• When ALL TCP ports are allowed in a rule, PORT does not have any value set\n(NULL)\n• When ALL Protocols are allowed in a rule, PORT does not have any value set\n(NULL)",
    "expected_response": "3. Ensure Port is not equal to 3389 and Action is not Allow.\n4. Ensure IP Ranges is not equal to 0.0.0.0/0 under Source filters.\nEnsure that there is no rule matching the below criteria:\n• AND PORTS is set to 3389 or range containing 3389 or Null (not set)",
    "remediation": "From Google Cloud Console\n1. Go to VPC Network.\n2. Go to the Firewall Rules.\n3. Click the Firewall Rule to be modified.\n4. Click Edit.\n5. Modify Source IP ranges to specific IP.\n6. Click Save.\nFrom Google Cloud CLI\n1.Update RDP Firewall rule with new SOURCE_RANGE from the below command:\ngcloud compute firewall-rules update FirewallName --allow=[PROTOCOL[:PORT[-\nPORT]],...] --source-ranges=[CIDR_RANGE,...]",
    "additional_information": "Currently, GCP VPC only supports IPV4; however, Google is already working on adding\nIPV6 support for VPC. In that case along with source IP range 0.0.0.0, the rule should\nbe checked for IPv6 equivalent ::/0 as well.",
    "detection_commands": [
      "gcloud compute firewall-rules list --"
    ],
    "remediation_commands": [
      "gcloud compute firewall-rules update FirewallName --allow=[PROTOCOL[:PORT[-"
    ],
    "references": [
      "1. https://cloud.google.com/vpc/docs/firewalls#blockedtraffic",
      "2. https://cloud.google.com/blog/products/identity-security/cloud-iap-enables-",
      "context-aware-access-to-vms-via-ssh-and-rdp-without-bastion-hosts"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 145,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D2",
      "D4",
      "D5"
    ]
  },
  {
    "cis_id": "3.8",
    "title": "Ensure that VPC Flow Logs is Enabled for Every Subnet in a VPC Network",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Deny Communication over Unauthorized Ports",
    "description": "Flow Logs is a feature that enables users to capture information about the IP traffic\ngoing to and from network interfaces in the organization's VPC Subnets. Once a flow\nlog is created, the user can view and retrieve its data in Stackdriver Logging. It is\nrecommended that Flow Logs be enabled for every business-critical VPC subnet.",
    "rationale": "VPC networks and subnetworks not reserved for internal HTTP(S) load balancing\nprovide logically isolated and secure network partitions where GCP resources can be\nlaunched. When Flow Logs are enabled for a subnet, VMs within that subnet start\nreporting on all Transmission Control Protocol (TCP) and User Datagram Protocol\n(UDP) flows. Each VM samples the TCP and UDP flows it sees, inbound and outbound,\nwhether the flow is to or from another VM, a host in the on-premises datacenter, a\nGoogle service, or a host on the Internet. If two GCP VMs are communicating, and both\nare in subnets that have VPC Flow Logs enabled, both VMs report the flows.\nFlow Logs supports the following use cases:\n• Network monitoring\n• Understanding network usage and optimizing network traffic expenses\n• Network forensics\n• Real-time security analysis\nFlow Logs provide visibility into network traffic for each VM inside the subnet and can be\nused to detect anomalous traffic or provide insight during security workflows.\nThe Flow Logs must be configured such that all network traffic is logged, the interval of\nlogging is granular to provide detailed information on the connections, no logs are\nfiltered, and metadata to facilitate investigations are included.\nNote: Subnets reserved for use by internal HTTP(S) load balancers do not support VPC\nflow logs.",
    "impact": "Standard pricing for Stackdriver Logging, BigQuery, or Cloud Pub/Sub applies. VPC\nFlow Logs generation will be charged starting in GA as described in reference:\nhttps://cloud.google.com/vpc/",
    "audit": "From Google Cloud Console\n1. Go to the VPC network GCP Console visiting\nhttps://console.cloud.google.com/networking/networks/list\n2. From the list of network subnets, make sure for each subnet:\n• Flow Logs is set to On\n• Aggregation Interval is set to 5 sec\n• Include metadata checkbox is checked\n• Sample rate is set to 100%\nNote: It is not possible to determine if a Log filter has been defined from the console.\nFrom Google Cloud CLI\ngcloud compute networks subnets list --format json | \\\njq -r\n'([\"Subnet\",\"Purpose\",\"Flow_Logs\",\"Aggregation_Interval\",\"Flow_Sampling\",\"Met\nadata\",\"Logs_Filtered\"] | (., map(length*\"-\"))),\n(.[] |\n[\n.name,\n.purpose,\n(if has(\"enableFlowLogs\") and .enableFlowLogs == true then\n\"Enabled\" else \"Disabled\" end),\n(if has(\"logConfig\") then .logConfig.aggregationInterval else\n\"N/A\" end),\n(if has(\"logConfig\") then .logConfig.flowSampling else \"N/A\"\nend),\n(if has(\"logConfig\") then .logConfig.metadata else \"N/A\" end),\n(if has(\"logConfig\") then (.logConfig | has(\"filterExpr\")) else\n\"N/A\" end)\n]\n) |\n@tsv' | \\\ncolumn -t\nThe output of the above command will list:\n• each subnet\n• the subnet's purpose\n• a Enabled or Disabled value if Flow Logs are enabled\n• the value for Aggregation Interval or N/A if disabled, the value for Flow\nSampling or N/A if disabled\n• the value for Metadata or N/A if disabled\n• 'true' or 'false' if a Logging Filter is configured or 'N/A' if disabled.\nIf the subnet's purpose is PRIVATE then Flow Logs should be Enabled.\nIf Flow Logs is enabled then:\n• Aggregation_Interval should be INTERVAL_5_SEC\n• Flow_Sampling should be 1\n• Metadata should be INCLUDE_ALL_METADATA\n• Logs_Filtered should be false.",
    "expected_response": "• Flow Logs is set to On\n• Aggregation Interval is set to 5 sec\n• Sample rate is set to 100%\nThe output of the above command will list:\n• 'true' or 'false' if a Logging Filter is configured or 'N/A' if disabled.\nIf the subnet's purpose is PRIVATE then Flow Logs should be Enabled.\nIf Flow Logs is enabled then:\n• Aggregation_Interval should be INTERVAL_5_SEC\n• Flow_Sampling should be 1\n• Metadata should be INCLUDE_ALL_METADATA\n• Logs_Filtered should be false.",
    "remediation": "From Google Cloud Console\n1. Go to the VPC network GCP Console visiting\nhttps://console.cloud.google.com/networking/networks/list\n2. Click the name of a subnet, The Subnet details page displays.\n3. Click the EDIT button.\n4. Set Flow Logs to On.\n5. Expand the Configure Logs section.\n6. Set Aggregation Interval to 5 SEC.\n7. Check the box beside Include metadata.\n8. Set Sample rate to 100.\n9. Click Save.\nNote: It is not possible to configure a Log filter from the console.\nFrom Google Cloud CLI\nTo enable VPC Flow Logs for a network subnet, run the following command:\ngcloud compute networks subnets update [SUBNET_NAME] --region [REGION] --\nenable-flow-logs --logging-aggregation-interval=interval-5-sec --logging-\nflow-sampling=1 --logging-metadata=include-all",
    "default_value": "By default, Flow Logs is set to Off when a new VPC network subnet is created.",
    "detection_commands": [
      "gcloud compute networks subnets list --format json |"
    ],
    "remediation_commands": [
      "gcloud compute networks subnets update [SUBNET_NAME] --region [REGION] --"
    ],
    "references": [
      "1. https://cloud.google.com/vpc/docs/using-flow-logs#enabling_vpc_flow_logging",
      "2. https://cloud.google.com/vpc/"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 148,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
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
    "cis_id": "3.9",
    "title": "Ensure No HTTPS or SSL Proxy Load Balancers Permit SSL Policies With Weak Cipher Suites",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Deploy NetFlow Collection on Networking",
    "description": "Secure Sockets Layer (SSL) policies determine what port Transport Layer Security\n(TLS) features clients are permitted to use when connecting to load balancers. To\nprevent usage of insecure features, SSL policies should use (a) at least TLS 1.2 with\nthe MODERN profile; or (b) the RESTRICTED profile, because it effectively requires\nclients to use TLS 1.2 regardless of the chosen minimum TLS version; or (3) a\nCUSTOM profile that does not support any of the following features:\nTLS_RSA_WITH_AES_128_GCM_SHA256\nTLS_RSA_WITH_AES_256_GCM_SHA384\nTLS_RSA_WITH_AES_128_CBC_SHA\nTLS_RSA_WITH_AES_256_CBC_SHA\nTLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "rationale": "Load balancers are used to efficiently distribute traffic across multiple servers. Both SSL\nproxy and HTTPS load balancers are external load balancers, meaning they distribute\ntraffic from the Internet to a GCP network. GCP customers can configure load balancer\nSSL policies with a minimum TLS version (1.0, 1.1, or 1.2) that clients can use to\nestablish a connection, along with a profile (Compatible, Modern, Restricted, or Custom)\nthat specifies permissible cipher suites. To comply with users using outdated protocols,\nGCP load balancers can be configured to permit insecure cipher suites. In fact, the GCP\ndefault SSL policy uses a minimum TLS version of 1.0 and a Compatible profile, which\nallows the widest range of insecure cipher suites. As a result, it is easy for customers to\nconfigure a load balancer without even knowing that they are permitting outdated cipher\nsuites.",
    "impact": "Creating more secure SSL policies can prevent clients using older TLS versions from\nestablishing a connection.",
    "audit": "From Google Cloud Console\n1. See all load balancers by visiting https://console.cloud.google.com/net-\nservices/loadbalancing/loadBalancers/list.\n2. For each load balancer for SSL (Proxy) or HTTPS, click on its name to go the\nLoad balancer details page.\n3. Ensure that each target proxy entry in the Frontend table has an SSL Policy\nconfigured.\n4. Click on each SSL policy to go to its SSL policy details page.\n5. Ensure that the SSL policy satisfies one of the following conditions:\n• has a Min TLS set to TLS 1.2 and Profile set to Modern profile, or\n• has Profile set to Restricted. Note that a Restricted profile effectively\nrequires clients to use TLS 1.2 regardless of the chosen minimum TLS version,\nor\n• has Profile set to Custom and the following features are all disabled:\nTLS_RSA_WITH_AES_128_GCM_SHA256\nTLS_RSA_WITH_AES_256_GCM_SHA384\nTLS_RSA_WITH_AES_128_CBC_SHA\nTLS_RSA_WITH_AES_256_CBC_SHA\nTLS_RSA_WITH_3DES_EDE_CBC_SHA\nFrom Google Cloud CLI\n1. List all TargetHttpsProxies and TargetSslProxies.\ngcloud compute target-https-proxies list\ngcloud compute target-ssl-proxies list\n2. For each target proxy, list its properties:\ngcloud compute target-https-proxies describe TARGET_HTTPS_PROXY_NAME\ngcloud compute target-ssl-proxies describe TARGET_SSL_PROXY_NAME\n3. Ensure that the sslPolicy field is present and identifies the name of the SSL\npolicy:\nsslPolicy:\nhttps://www.googleapis.com/compute/v1/projects/PROJECT_ID/global/sslPolicies/\nSSL_POLICY_NAME\nIf the sslPolicy field is missing from the configuration, it means that the GCP default\npolicy is used, which is insecure.\n4. Describe the SSL policy:\ngcloud compute ssl-policies describe SSL_POLICY_NAME\n5. Ensure that the policy satisfies one of the following conditions:\n• has Profile set to Modern and minTlsVersion set to TLS_1_2, or\n• has Profile set to Restricted, or\n• has Profile set to Custom and  enabledFeatures does not contain any of the\nfollowing values:\nTLS_RSA_WITH_AES_128_GCM_SHA256\nTLS_RSA_WITH_AES_256_GCM_SHA384\nTLS_RSA_WITH_AES_128_CBC_SHA\nTLS_RSA_WITH_AES_256_CBC_SHA\nTLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "expected_response": "3. Ensure that each target proxy entry in the Frontend table has an SSL Policy\n5. Ensure that the SSL policy satisfies one of the following conditions:\n3. Ensure that the sslPolicy field is present and identifies the name of the SSL\n5. Ensure that the policy satisfies one of the following conditions:",
    "remediation": "From Google Cloud Console\nIf the TargetSSLProxy or TargetHttpsProxy does not have an SSL policy configured,\ncreate a new SSL policy. Otherwise, modify the existing insecure policy.\n1. Navigate to the SSL Policies page by visiting:\nhttps://console.cloud.google.com/net-security/sslpolicies\n2. Click on the name of the insecure policy to go to its SSL policy details page.\n3. Click EDIT.\n4. Set Minimum TLS version to TLS 1.2.\n5. Set Profile to Modern or Restricted.\n6. Alternatively, if teh user selects the profile Custom, make sure that the following\nfeatures are disabled:\nTLS_RSA_WITH_AES_128_GCM_SHA256\nTLS_RSA_WITH_AES_256_GCM_SHA384\nTLS_RSA_WITH_AES_128_CBC_SHA\nTLS_RSA_WITH_AES_256_CBC_SHA\nTLS_RSA_WITH_3DES_EDE_CBC_SHA\nFrom Google Cloud CLI\n1. For each insecure SSL policy, update it to use secure cyphers:\ngcloud compute ssl-policies update NAME [--profile\nCOMPATIBLE|MODERN|RESTRICTED|CUSTOM] --min-tls-version 1.2 [--custom-features\nFEATURES]\n2. If the target proxy has a GCP default SSL policy, use the following command\ncorresponding to the proxy type to update it.\ngcloud compute target-ssl-proxies update TARGET_SSL_PROXY_NAME --ssl-policy\nSSL_POLICY_NAME\ngcloud compute target-https-proxies update TARGET_HTTPS_POLICY_NAME --ssl-\npolicy SSL_POLICY_NAME",
    "default_value": "The GCP default SSL policy is the least secure setting: Min TLS 1.0 and Compatible\nprofile",
    "detection_commands": [
      "gcloud compute target-https-proxies list gcloud compute target-ssl-proxies list",
      "gcloud compute target-https-proxies describe TARGET_HTTPS_PROXY_NAME gcloud compute target-ssl-proxies describe TARGET_SSL_PROXY_NAME",
      "gcloud compute ssl-policies describe SSL_POLICY_NAME"
    ],
    "remediation_commands": [
      "create a new SSL policy. Otherwise, modify the existing insecure policy.",
      "gcloud compute ssl-policies update NAME [--profile",
      "gcloud compute target-ssl-proxies update TARGET_SSL_PROXY_NAME --ssl-policy",
      "gcloud compute target-https-proxies update TARGET_HTTPS_POLICY_NAME --ssl-"
    ],
    "references": [
      "1. https://cloud.google.com/load-balancing/docs/use-ssl-policies",
      "2. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 152,
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
    "cis_id": "3.10",
    "title": "Use Identity Aware Proxy (IAP) to Ensure Only Traffic From Google IP Addresses are 'Allowed'",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "networking",
    "domain": "Networking",
    "subdomain": "Encrypt Sensitive Data in Transit",
    "description": "IAP authenticates the user requests to your apps via a Google single sign in. You can\nthen manage these users with permissions to control access. It is recommended to use\nboth IAP permissions and firewalls to restrict this access to your apps with sensitive\ninformation.",
    "rationale": "IAP ensure that access to VMs is controlled by authenticating incoming requests.\nAccess to your apps and the VMs should be restricted by firewall rules that allow only\nthe proxy IAP IP addresses contained in the 35.235.240.0/20 subnet. Otherwise,\nunauthenticated requests can be made to your apps. To ensure that load balancing\nworks correctly health checks should also be allowed.",
    "impact": "If firewall rules are not configured correctly, legitimate business services could be\nnegatively impacted. It is recommended to make these changes during a time of low\nusage.",
    "audit": "From Google Cloud Console\n1. For each of your apps that have IAP enabled go to the Cloud Console VPC\nnetwork > Firewall rules.\n2. Verify that the only rules correspond to the following values:\no Targets: All instances in the network\no Source IP ranges:\n▪ IAP Proxy Addresses 35.235.240.0/20\n▪ Google Health Check 130.211.0.0/22\n▪ Google Health Check 35.191.0.0/16\no Protocols and ports:\n- Specified protocols and ports required for access and management of\nyour app. For example most health check connection protocols would be\ncovered by;\n▪ tcp:80 (Default HTTP Health Check port)\n▪ tcp:443 (Default HTTPS Health Check port)\nNote: if you have custom ports used by your load balancers, you will need to list\nthem here",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud Console VPC network > Firewall rules.\n2. Select the checkbox next to the following rules:\no default-allow-http\no default-allow-https\no default-allow-internal\n3. Click Delete.\n4. Click Create firewall rule and set the following values:\no Name: allow-iap-traffic\no Targets: All instances in the network\no Source IP ranges (press Enter after you paste each value in the box, copy\neach full CIDR IP address):\n▪ IAP Proxy Addresses 35.235.240.0/20\n▪ Google Health Check 130.211.0.0/22\n▪ Google Health Check 35.191.0.0/16\no Protocols and ports:\n▪ Specified protocols and ports required for access and management\nof your app. For example most health check connection protocols\nwould be covered by;\n▪ tcp:80 (Default HTTP Health Check port)\n▪ tcp:443 (Default HTTPS Health Check port)\nNote: if you have custom ports used by your load balancers,\nyou will need to list them here\n5. When you're finished updating values, click Create.",
    "default_value": "By default all traffic is allowed.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.google.com/iap/docs/concepts-overview",
      "2. https://cloud.google.com/iap/docs/load-balancer-howto",
      "3. https://cloud.google.com/load-balancing/docs/health-checks",
      "4. https://cloud.google.com/blog/products/identity-security/cloud-iap-enables-",
      "context-aware-access-to-vms-via-ssh-and-rdp-without-bastion-hosts"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 156,
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
      "D4"
    ]
  },
  {
    "cis_id": "4.1",
    "title": "Ensure That Instances Are Not Configured To Use the Default Service Account",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "description": "It is recommended to configure your instance to not use the default Compute Engine\nservice account because it has the Editor role on the project.",
    "rationale": "When a default Compute Engine service account is created, it is automatically granted\nthe Editor role (roles/editor) on your project which allows read and write access to most\nGoogle Cloud Services. This role includes a very large number of permissions. To\ndefend against privilege escalations if your VM is compromised and prevent an attacker\nfrom gaining access to all of your project, you should either revoke the Editor role from\nthe default Compute Engine service account or create a new service account and\nassign only the permissions needed by your instance. To mitigate this at scale, we\nstrongly recommend that you disable the automatic role grant by adding a constraint to\nyour organization policy.\nThe default Compute Engine service account is named [PROJECT_NUMBER]-\ncompute@developer.gserviceaccount.com.",
    "audit": "From Google Cloud Console\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. Click on each instance name to go to its VM instance details page.\n3. Under the section API and identity management, ensure that the default\nCompute Engine service account is not used. This account is named\n[PROJECT_NUMBER]-compute@developer.gserviceaccount.com.\nFrom Google Cloud CLI\n1. List the instances in your project and get details on each instance:\ngcloud compute instances list --format=json | jq -r '. | \"SA:\n\\(.[].serviceAccounts[].email) Name: \\(.[].name)\"'\n2. Ensure that the service account section has an email that does not match the\npattern [PROJECT_NUMBER]-compute@developer.gserviceaccount.com.\nException:\nVMs created by GKE should be excluded. These VMs have names that start with gke-\nand are labeled goog-gke-node.",
    "expected_response": "3. Under the section API and identity management, ensure that the default\n2. Ensure that the service account section has an email that does not match the\nVMs created by GKE should be excluded. These VMs have names that start with gke-",
    "remediation": "From Google Cloud Console\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. Click on the instance name to go to its VM instance details page.\n3. Click STOP and then click EDIT.\n4. Under the section API and identity management, select a service account\nother than the default Compute Engine service account. You may first need to\ncreate a new service account.\n5. Click Save and then click START.\nFrom Google Cloud CLI\n1. Stop the instance:\ngcloud compute instances stop <INSTANCE_NAME>\n2. Update the instance:\ngcloud compute instances set-service-account <INSTANCE_NAME> --service-\naccount=<SERVICE_ACCOUNT>\n3. Restart the instance:\ngcloud compute instances start <INSTANCE_NAME>",
    "default_value": "By default, Compute instances are configured to use the default Compute Engine\nservice account.",
    "detection_commands": [
      "gcloud compute instances list --format=json | jq -r '. | \"SA:"
    ],
    "remediation_commands": [
      "create a new service account.",
      "gcloud compute instances stop <INSTANCE_NAME>",
      "gcloud compute instances set-service-account <INSTANCE_NAME> --service-",
      "gcloud compute instances start <INSTANCE_NAME>"
    ],
    "references": [
      "1. https://cloud.google.com/compute/docs/access/service-accounts",
      "2. https://cloud.google.com/compute/docs/access/create-enable-service-accounts-",
      "for-instances",
      "3. https://cloud.google.com/sdk/gcloud/reference/compute/instances/set-service-",
      "account"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 160,
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
    "title": "Ensure That Instances Are Not Configured To Use the Default Service Account With Full Access to All Cloud APIs",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Limit Access to Script Tools",
    "description": "To support principle of least privileges and prevent potential privilege escalation it is\nrecommended that instances are not assigned to default service account Compute\nEngine default service account with Scope Allow full access to all Cloud\nAPIs.",
    "rationale": "Along with ability to optionally create, manage and use user managed custom service\naccounts, Google Compute Engine provides default service account Compute Engine\ndefault service account for an instances to access necessary cloud services.\nProject Editor role is assigned to Compute Engine default service account\nhence, This service account has almost all capabilities over all cloud services except\nbilling. However, when Compute Engine default service account assigned to an\ninstance it can operate in 3 scopes.\n1. Allow default access: Allows only minimum access required to run an\nInstance (Least Privileges)\n2. Allow full access to all Cloud APIs: Allow full access to all the cloud\nAPIs/Services (Too much access)\n3. Set access for each API: Allows Instance administrator to choose only\nthose APIs that are needed to perform specific business functionality\nexpected by instance\nWhen an instance is configured with Compute Engine default service account\nwith Scope Allow full access to all Cloud APIs, based on IAM roles assigned to\nthe user(s) accessing Instance, it may allow user to perform cloud operations/API calls\nthat user is not supposed to perform leading to successful privilege escalation.",
    "impact": "In order to change service account or scope for an instance, it needs to be stopped.",
    "audit": "From Google Cloud Console\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. Click on each instance name to go to its VM instance details page.\n3. Under the API and identity management, ensure that Cloud API access\nscopes is not set to Allow full access to all Cloud APIs.\nFrom Google Cloud CLI\n1. List the instances in your project and get details on each instance:\ngcloud compute instances list --format=json | jq -r '. | \"SA Scopes:\n\\(.[].serviceAccounts[].scopes) Name: \\(.[].name) Email:\n\\(.[].serviceAccounts[].email)\"'\n2. Ensure that the service account section has an email that does not match the\npattern [PROJECT_NUMBER]-compute@developer.gserviceaccount.com.\nException:\nVMs created by GKE should be excluded. These VMs have names that start with gke-\nand are labeled `goog-gke-node",
    "expected_response": "3. Under the API and identity management, ensure that Cloud API access\n2. Ensure that the service account section has an email that does not match the\nVMs created by GKE should be excluded. These VMs have names that start with gke-",
    "remediation": "From Google Cloud Console\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. Click on the impacted VM instance.\n3. If the instance is not stopped, click the Stop button. Wait for the instance to be\nstopped.\n4. Next, click the Edit button.\n5. Scroll down to the Service Account section.\n6. Select a different service account or ensure that Allow full access to all\nCloud APIs is not selected.\n7. Click the Save button to save your changes and then click START.\nFrom Google Cloud CLI\n1. Stop the instance:\ngcloud compute instances stop <INSTANCE_NAME>\n2. Update the instance:\ngcloud compute instances set-service-account <INSTANCE_NAME> --service-\naccount=<SERVICE_ACCOUNT> --scopes [SCOPE1, SCOPE2...]\n3. Restart the instance:\ngcloud compute instances start <INSTANCE_NAME>",
    "default_value": "While creating an VM instance, default service account is used with scope Allow\ndefault access.",
    "additional_information": "• User IAM roles will override service account scope but configuring minimal scope\nensures defense in depth\n• Non-default service accounts do not offer selection of access scopes like default\nservice account. IAM roles with non-default service accounts should be used to\ncontrol VM access.",
    "detection_commands": [
      "gcloud compute instances list --format=json | jq -r '. | \"SA Scopes:"
    ],
    "remediation_commands": [
      "gcloud compute instances stop <INSTANCE_NAME>",
      "gcloud compute instances set-service-account <INSTANCE_NAME> --service-",
      "gcloud compute instances start <INSTANCE_NAME>"
    ],
    "references": [
      "1. https://cloud.google.com/compute/docs/access/create-enable-service-accounts-",
      "for-instances",
      "2. https://cloud.google.com/compute/docs/access/service-accounts"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
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
    "cis_id": "4.3",
    "title": "Ensure “Block Project-Wide SSH Keys” Is Enabled for VM Instances",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Limit Access to Script Tools",
    "description": "It is recommended to use Instance specific SSH key(s) instead of using common/shared\nproject-wide SSH key(s) to access Instances.",
    "rationale": "Project-wide SSH keys are stored in Compute/Project-meta-data. Project wide SSH\nkeys can be used to login into all the instances within project. Using project-wide SSH\nkeys eases the SSH key management but if compromised, poses the security risk which\ncan impact all the instances within project. It is recommended to use Instance specific\nSSH keys which can limit the attack surface if the SSH keys are compromised.",
    "impact": "Users already having Project-wide ssh key pairs and using third party SSH clients will\nlose access to the impacted Instances. For Project users using gcloud or GCP Console\nbased SSH option, no manual key creation and distribution is required and will be\nhandled by GCE (Google Compute Engine) itself. To access Instance using third party\nSSH clients Instance specific SSH key pairs need to be created and distributed to the\nrequired users.",
    "audit": "From Google Cloud Console\n1. Go to the VM instances page by visiting\nhttps://console.cloud.google.com/compute/instances. It will list all the instances in\nyour project.\n2. For every instance, click on the name of the instance.\n3. Under SSH Keys, ensure Block project-wide SSH keys is selected.\nFrom Google Cloud CLI\n1. List the instances in your project and get details on each instance:\ngcloud compute instances list --format=json\n2. Ensure key: block-project-ssh-keys is set to value: 'true'.",
    "expected_response": "3. Under SSH Keys, ensure Block project-wide SSH keys is selected.\n2. Ensure key: block-project-ssh-keys is set to value: 'true'.",
    "remediation": "From Google Cloud Console\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances. It will list all the instances in\nyour project.\n2. Click on the name of the Impacted instance\n3. Click Edit in the toolbar\n4. Under SSH Keys, go to the Block project-wide SSH keys checkbox\n5. To block users with project-wide SSH keys from connecting to this instance,\nselect Block project-wide SSH keys\n6. Click Save at the bottom of the page\n7. Repeat steps for every impacted Instance\nFrom Google Cloud CLI\nTo block project-wide public SSH keys, set the metadata value to TRUE:\ngcloud compute instances add-metadata <INSTANCE_NAME> --metadata block-\nproject-ssh-keys=TRUE",
    "default_value": "By Default Block Project-wide SSH keys is not enabled.",
    "additional_information": "If OS Login is enabled, SSH keys in instance metadata are ignored, and therefore\nblocking project-wide SSH keys is not necessary.",
    "detection_commands": [
      "gcloud compute instances list --format=json"
    ],
    "remediation_commands": [
      "select Block project-wide SSH keys",
      "gcloud compute instances add-metadata <INSTANCE_NAME> --metadata block-"
    ],
    "references": [
      "1. https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys",
      "2. https://cloud.google.com/sdk/gcloud/reference/topic/formats"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 166,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": false
  },
  {
    "cis_id": "4.4",
    "title": "Ensure Oslogin Is Enabled for a Project",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Encrypt Transmittal of Username and Authentication",
    "description": "Enabling OS login binds SSH certificates to IAM users and facilitates effective SSH\ncertificate management.",
    "rationale": "Enabling osLogin ensures that SSH keys used to connect to instances are mapped with\nIAM users. Revoking access to IAM user will revoke all the SSH keys associated with\nthat particular user. It facilitates centralized and automated SSH key pair management\nwhich is useful in handling cases like response to compromised SSH key pairs and/or\nrevocation of external/third-party/Vendor users.",
    "impact": "Enabling OS Login on project disables metadata-based SSH key configurations on all\ninstances from a project. Disabling OS Login restores SSH keys that you have\nconfigured in project or instance meta-data.",
    "audit": "From Google Cloud Console\n1. Go to the VM compute metadata page by visiting\nhttps://console.cloud.google.com/compute/metadata.\n2. Ensure that key enable-oslogin is present with value set to TRUE.\n3. Because instances can override project settings, ensure that no instance has\ncustom metadata with key enable-oslogin and value FALSE.\nFrom Google Cloud CLI\n1. List the instances in your project and get details on each instance:\ngcloud compute instances list --format=json\n2. Verify that the section commonInstanceMetadata has a key enable-oslogin\nset to value TRUE.\nException:\nVMs created by GKE should be excluded. These VMs have names that start with\ngke- and are labeled goog-gke-node",
    "expected_response": "2. Ensure that key enable-oslogin is present with value set to TRUE.\n3. Because instances can override project settings, ensure that no instance has\nVMs created by GKE should be excluded. These VMs have names that start with",
    "remediation": "From Google Cloud Console\n1. Go to the VM compute metadata page by visiting:\nhttps://console.cloud.google.com/compute/metadata.\n2. Click Edit.\n3. Add a metadata entry where the key is enable-oslogin and the value is TRUE.\n4. Click Save to apply the changes.\n5. For every instance that overrides the project setting, go to the VM Instances\npage at https://console.cloud.google.com/compute/instances.\n6. Click the name of the instance on which you want to remove the metadata value.\n7. At the top of the instance details page, click Edit to edit the instance settings.\n8. Under Custom metadata, remove any entry with key enable-oslogin and the\nvalue is FALSE\n9. At the bottom of the instance details page, click Save to apply your changes to\nthe instance.\nFrom Google Cloud CLI\n1. Configure oslogin on the project:\ngcloud compute project-info add-metadata --metadata enable-oslogin=TRUE\n2. Remove instance metadata that overrides the project setting.\ngcloud compute instances remove-metadata <INSTANCE_NAME> --keys=enable-\noslogin\nOptionally, you can enable two factor authentication for OS login. For more information,\nsee: https://cloud.google.com/compute/docs/oslogin/setup-two-factor-authentication.",
    "default_value": "By default, parameter enable-oslogin is not set, which is equivalent to setting it to\nFALSE.",
    "additional_information": "1. In order to use osLogin, instance using Custom Images must have the latest\nversion of the Linux Guest Environment installed. The following image families do\nnot yet support OS Login:\nProject cos-cloud (Container-Optimized OS) image family cos-stable.\nAll project coreos-cloud (CoreOS) image families\nProject suse-cloud (SLES) image family sles-11\nAll Windows Server and SQL Server image families\n2. Project enable-oslogin can be over-ridden by setting enable-oslogin parameter to\nan instance metadata individually.",
    "detection_commands": [
      "gcloud compute instances list --format=json"
    ],
    "remediation_commands": [
      "gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE",
      "gcloud compute instances remove-metadata <INSTANCE_NAME> --keys=enable-"
    ],
    "references": [
      "1. https://cloud.google.com/compute/docs/instances/managing-instance-access",
      "2. https://cloud.google.com/compute/docs/instances/managing-instance-",
      "access#enable_oslogin",
      "3. https://cloud.google.com/sdk/gcloud/reference/compute/instances/remove-",
      "metadata",
      "4. https://cloud.google.com/compute/docs/oslogin/setup-two-factor-authentication"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 169,
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
    "cis_id": "4.5",
    "title": "Ensure ‘Enable Connecting to Serial Ports’ Is Not Enabled for VM Instance",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Configure Centralized Point of Authentication",
    "description": "Interacting with a serial port is often referred to as the serial console, which is similar to\nusing a terminal window, in that input and output is entirely in text mode and there is no\ngraphical interface or mouse support.\nIf you enable the interactive serial console on an instance, clients can attempt to\nconnect to that instance from any IP address. Therefore interactive serial console\nsupport should be disabled.",
    "rationale": "A virtual machine instance has four virtual serial ports. Interacting with a serial port is\nsimilar to using a terminal window, in that input and output is entirely in text mode and\nthere is no graphical interface or mouse support. The instance's operating system,\nBIOS, and other system-level entities often write output to the serial ports, and can\naccept input such as commands or answers to prompts. Typically, these system-level\nentities use the first serial port (port 1) and serial port 1 is often referred to as the serial\nconsole.\nThe interactive serial console does not support IP-based access restrictions such as IP\nwhitelists. If you enable the interactive serial console on an instance, clients can attempt\nto connect to that instance from any IP address. This allows anybody to connect to that\ninstance if they know the correct SSH key, username, project ID, zone, and instance\nname.\nTherefore interactive serial console support should be disabled.",
    "audit": "From Google Cloud Console\n1. Login to Google Cloud console\n2. Go to Compute Engine\n3. Go to VM instances\n4. Click on the Specific VM\n5. Ensure the statement Connecting to serial serial ports is disabled is\ndisplayed at the top of the details tab, just below the Connect to serial\nconsole drop-down..\nFrom Google Cloud CLI\nEnsure the below command's output shows null:\ngcloud compute instances describe <vmName> --zone=<region> --\nformat=\"json(metadata.items[].key,metadata.items[].value)\"\nor key and value properties from below command's json response are equal to\nserial-port-enable and 0 or false respectively.\n{\n\"metadata\": {\n\"items\": [\n{\n\"key\": \"serial-port-enable\",\n\"value\": \"0\"\n}\n]\n}\n}",
    "expected_response": "5. Ensure the statement Connecting to serial serial ports is disabled is\nEnsure the below command's output shows null:\nor key and value properties from below command's json response are equal to",
    "remediation": "From Google Cloud Console\n1. Login to Google Cloud console\n2. Go to Computer Engine\n3. Go to VM instances\n4. Click on the Specific VM\n5. Click EDIT\n6. Unselect Enable connecting to serial ports below Remote access block.\n7. Click Save\nFrom Google Cloud CLI\nUse the below command to disable\ngcloud compute instances add-metadata <INSTANCE_NAME> --zone=<ZONE> --\nmetadata=serial-port-enable=false\nor\ngcloud compute instances add-metadata <INSTANCE_NAME> --zone=<ZONE> --\nmetadata=serial-port-enable=0\nPrevention:\nYou can prevent VMs from having serial port access enable by Disable VM serial\nport access organization policy:\nhttps://console.cloud.google.com/iam-admin/orgpolicies/compute-\ndisableSerialPortAccess.",
    "default_value": "By default, connecting to serial ports is not enabled.",
    "detection_commands": [
      "gcloud compute instances describe <vmName> --zone=<region> --"
    ],
    "remediation_commands": [
      "Use the below command to disable gcloud compute instances add-metadata <INSTANCE_NAME> --zone=<ZONE> --",
      "gcloud compute instances add-metadata <INSTANCE_NAME> --zone=<ZONE> --"
    ],
    "references": [
      "1. https://cloud.google.com/compute/docs/instances/interacting-with-serial-console"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 172,
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
    "cis_id": "4.6",
    "title": "Ensure That IP Forwarding Is Not Enabled on Instances",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "Compute Engine instance cannot forward a packet unless the source IP address of the\npacket matches the IP address of the instance. Similarly, GCP won't deliver a packet\nwhose destination IP address is different than the IP address of the instance receiving\nthe packet. However, both capabilities are required if you want to use instances to help\nroute packets.\nForwarding of data packets should be disabled to prevent data loss or information\ndisclosure.",
    "rationale": "Compute Engine instance cannot forward a packet unless the source IP address of the\npacket matches the IP address of the instance. Similarly, GCP won't deliver a packet\nwhose destination IP address is different than the IP address of the instance receiving\nthe packet. However, both capabilities are required if you want to use instances to help\nroute packets. To enable this source and destination IP check, disable the\ncanIpForward field, which allows an instance to send and receive packets with non-\nmatching destination or source IPs.",
    "audit": "From Google Cloud Console\n1. Go to the VM Instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. For every instance, click on its name to go to the VM instance details page.\n3. Under the Network interfaces section, ensure that IP forwarding is set to\nOff for every network interface.\nFrom Google Cloud CLI\n1. List all instances:\ngcloud compute instances list --format='table(name,canIpForward)'\n2. Ensure that CAN_IP_FORWARD column in the output of above command does not\ncontain True for any VM instance.\nException:\nInstances created by GKE should be excluded because they need to have IP forwarding\nenabled and cannot be changed. Instances created by GKE have names that start with\n\"gke-\".",
    "expected_response": "3. Under the Network interfaces section, ensure that IP forwarding is set to\n2. Ensure that CAN_IP_FORWARD column in the output of above command does not\nInstances created by GKE should be excluded because they need to have IP forwarding",
    "remediation": "You only edit the canIpForward setting at instance creation or using CLI.\nFrom Google Cloud CLI\n1. Use the instances export command to export the existing instance properties:\ngcloud compute instances export <INSTANCE_NAME> \\\n--project <PROJECT_ID> \\\n--zone <ZONE> \\\n--destination=<FILE_PATH>\nNoteReplace the following:\nINSTANCE_NAME the name for the instance that you want to export.\nPROJECT_ID: the project ID for this request.\nZONE: the zone for this instance.\nFILE_PATH: the output path where you want to save the instance configuration file on\nyour local workstation.\n2. Use a text editor to modify this file\nReplace\ncanIpForward: true\nwith\ncanIpForward: false\n3. Run this command to import the file you just modified\ngcloud compute instances update-from-file INSTANCE_NAME \\\n--project PROJECT_ID \\\n--zone ZONE \\\n--source=FILE_PATH \\\n--most-disruptive-allowed-action=REFRESH\nIf the update request is valid and the required resources are available, the instance\nupdate process begins. You can monitor the status of this operation by viewing the audit\nlogs.\nThis update requires only a REFRESH not a full restart.",
    "default_value": "By default, instances are not configured to allow IP forwarding.",
    "additional_information": "You can only set the canIpForward field at instance creation time or using CLI.",
    "detection_commands": [
      "gcloud compute instances list --format='table(name,canIpForward)'"
    ],
    "remediation_commands": [
      "gcloud compute instances export <INSTANCE_NAME> --project <PROJECT_ID> --zone <ZONE> --destination=<FILE_PATH>",
      "gcloud compute instances update-from-file INSTANCE_NAME --project PROJECT_ID --zone ZONE --source=FILE_PATH --most-disruptive-allowed-action=REFRESH"
    ],
    "references": [
      "1. https://cloud.google.com/vpc/docs/using-routes#canipforward",
      "2. https://cloud.google.com/compute/docs/instances/update-instance-properties"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 175,
    "dspm_relevant": true,
    "dspm_categories": [],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "4.7",
    "title": "Ensure VM Disks for Critical VMs Are Encrypted With Customer-Supplied Encryption Keys (CSEK)",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Document Traffic Configuration Rules",
    "description": "Customer-Supplied Encryption Keys (CSEK) are a feature in Google Cloud Storage and\nGoogle Compute Engine. If you supply your own encryption keys, Google uses your key\nto protect the Google-generated keys used to encrypt and decrypt your data. By default,\nGoogle Compute Engine encrypts all data at rest. Compute Engine handles and\nmanages this encryption for you without any additional actions on your part. However, if\nyou wanted to control and manage this encryption yourself, you can provide your own\nencryption keys.",
    "rationale": "By default, Google Compute Engine encrypts all data at rest. Compute Engine handles\nand manages this encryption for you without any additional actions on your part.\nHowever, if you wanted to control and manage this encryption yourself, you can provide\nyour own encryption keys.\nIf you provide your own encryption keys, Compute Engine uses your key to protect the\nGoogle-generated keys used to encrypt and decrypt your data. Only users who can\nprovide the correct key can use resources protected by a customer-supplied encryption\nkey.\nGoogle does not store your keys on its servers and cannot access your protected data\nunless you provide the key. This also means that if you forget or lose your key, there is\nno way for Google to recover the key or to recover any data encrypted with the lost key.\nAt least business critical VMs should have VM disks encrypted with CSEK.",
    "impact": "If you lose your encryption key, you will not be able to recover the data.",
    "audit": "From Google Cloud Console\n1. Go to Compute Engine Disks by visiting:\nhttps://console.cloud.google.com/compute/disks.\n2. Click on the disk for your critical VMs to see its configuration details.\n3. Ensure that Encryption type is set to Customer supplied.\nFrom Google Cloud CLI\nEnsure diskEncryptionKey property in the below command's response is not null, and\ncontains key sha256 with corresponding value\ngcloud compute disks describe <DISK_NAME> --zone <ZONE> --\nformat=\"json(diskEncryptionKey,name)\"",
    "expected_response": "3. Ensure that Encryption type is set to Customer supplied.\nEnsure diskEncryptionKey property in the below command's response is not null, and",
    "remediation": "Currently there is no way to update the encryption of an existing disk. Therefore you\nshould create a new disk with Encryption set to Customer supplied.\nFrom Google Cloud Console\n1. Go to Compute Engine Disks by visiting:\nhttps://console.cloud.google.com/compute/disks.\n2. Click CREATE DISK.\n3. Set Encryption type to Customer supplied,\n4. Provide the Key in the box.\n5. Select Wrapped key.\n6. Click Create.\nFrom Google Cloud CLI\nIn the gcloud compute tool, encrypt a disk using the --csek-key-file flag during instance\ncreation. If you are using an RSA-wrapped key, use the gcloud beta component:\ngcloud compute instances create <INSTANCE_NAME> --csek-key-file <example-\nfile.json>\nTo encrypt a standalone persistent disk:\ngcloud compute disks create <DISK_NAME> --csek-key-file <example-file.json>",
    "default_value": "By default, VM disks are encrypted with Google-managed keys. They are not encrypted\nwith Customer-Supplied Encryption Keys.",
    "additional_information": "Note 1: When you delete a persistent disk, Google discards the cipher keys, rendering\nthe data irretrievable. This process is irreversible.\nNote 2: It is up to you to generate and manage your key. You must provide a key that\nis a 256-bit string encoded in RFC 4648 standard base64 to Compute Engine.\nNote 3: An example key file looks like this.\n[\n{\n\"uri\": \"https://www.googleapis.com/compute/v1/projects/myproject/zones/us-\ncentral1-a/disks/example-disk\",\n\"key\": \"acXTX3rxrKAFTF0tYVLvydU1riRZTvUNC4g5I11NY-c=\",\n\"key-type\": \"raw\"\n},\n{\n\"uri\":\n\"https://www.googleapis.com/compute/v1/projects/myproject/global/snapshots/my\n-private-snapshot\",\n\"key\":\n\"ieCx/NcW06PcT7Ep1X6LUTc/hLvUDYyzSZPPVCVPTVEohpeHASqC8uw5TzyO9U+Fka9JFHz0mBib\nXUInrC/jEk014kCK/NPjYgEMOyssZ4ZINPKxlUh2zn1bV+MCaTICrdmuSBTWlUUiFoDD6PYznLwh8\nZNdaheCeZ8ewEXgFQ8V+sDroLaN3Xs3MDTXQEMMoNUXMCZEIpg9Vtp9x2oeQ5lAbtt7bYAAHf5l+g\nJWw3sUfs0/Glw5fpdjT8Uggrr+RMZezGrltJEF293rvTIjWOEB3z5OHyHwQkvdrPDFcTqsLfh+8Hr\n8g+mf+7zVPEC8nEbqpdl3GPv3A7AwpFp7MA==\"\n\"key-type\": \"rsa-encrypted\"\n}\n]",
    "detection_commands": [
      "gcloud compute disks describe <DISK_NAME> --zone <ZONE> --"
    ],
    "remediation_commands": [
      "gcloud compute instances create <INSTANCE_NAME> --csek-key-file <example-",
      "gcloud compute disks create <DISK_NAME> --csek-key-file <example-file.json>"
    ],
    "references": [
      "1. https://cloud.google.com/compute/docs/disks/customer-supplied-",
      "encryption#encrypt_a_new_persistent_disk_with_your_own_keys",
      "2. https://cloud.google.com/compute/docs/reference/rest/v1/disks/get",
      "3. https://cloud.google.com/compute/docs/disks/customer-supplied-",
      "encryption#key_file"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 178,
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
    "cis_id": "4.8",
    "title": "Ensure Compute Instances Are Launched With Shielded VM Enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "To defend against advanced threats and ensure that the boot loader and firmware on\nyour VMs are signed and untampered, it is recommended that Compute instances are\nlaunched with Shielded VM enabled.",
    "rationale": "Shielded VMs are virtual machines (VMs) on Google Cloud Platform hardened by a set\nof security controls that help defend against rootkits and bootkits.\nShielded VM offers verifiable integrity of your Compute Engine VM instances, so you\ncan be confident your instances haven't been compromised by boot- or kernel-level\nmalware or rootkits. Shielded VM's verifiable integrity is achieved through the use of\nSecure Boot, virtual trusted platform module (vTPM)-enabled Measured Boot, and\nintegrity monitoring.\nShielded VM instances run firmware which is signed and verified using Google's\nCertificate Authority, ensuring that the instance's firmware is unmodified and\nestablishing the root of trust for Secure Boot.\nIntegrity monitoring helps you understand and make decisions about the state of your\nVM instances and the Shielded VM vTPM enables Measured Boot by performing the\nmeasurements needed to create a known good boot baseline, called the integrity policy\nbaseline. The integrity policy baseline is used for comparison with measurements from\nsubsequent VM boots to determine if anything has changed.\nSecure Boot helps ensure that the system only runs authentic software by verifying the\ndigital signature of all boot components, and halting the boot process if signature\nverification fails.",
    "audit": "From Google Cloud Console\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. Click on the instance name to see its VM instance details page.\n3. Under the section Shielded VM, ensure that vTPM and Integrity Monitoring\nare on.\nFrom Google Cloud CLI\n1. For each instance in your project, get its metadata:\ngcloud compute instances list --format=json | jq -r '. | \"vTPM:\n\\(.[].shieldedInstanceConfig.enableVtpm) IntegrityMonitoring:\n\\(.[].shieldedInstanceConfig.enableIntegrityMonitoring) Name: \\(.[].name)\"'\n2. Ensure that there is a shieldedInstanceConfig configuration and that\nconfiguration has the enableIntegrityMonitoring and enableVtpm set to\ntrue. If the VM is not a Shield VM image, you will not see a\nshieldedInstanceConfig` in the output.",
    "expected_response": "3. Under the section Shielded VM, ensure that vTPM and Integrity Monitoring\n2. Ensure that there is a shieldedInstanceConfig configuration and that\nshieldedInstanceConfig` in the output.",
    "remediation": "To be able turn on Shielded VM on an instance, your instance must use an image with\nShielded VM support.\nFrom Google Cloud Console\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. Click on the instance name to see its VM instance details page.\n3. Click STOP to stop the instance.\n4. When the instance has stopped, click EDIT.\n5. In the Shielded VM section, select Turn on vTPM and Turn on Integrity\nMonitoring.\n6. Optionally, if you do not use any custom or unsigned drivers on the instance, also\nselect Turn on Secure Boot.\n7. Click the Save button to modify the instance and then click START to restart it.\nFrom Google Cloud CLI\nYou can only enable Shielded VM options on instances that have Shielded VM support.\nFor a list of Shielded VM public images, run the gcloud compute images list command\nwith the following flags:\ngcloud compute images list --project gce-uefi-images --no-standard-images\n1. Stop the instance:\ngcloud compute instances stop <INSTANCE_NAME>\n2. Update the instance:\ngcloud compute instances update <INSTANCE_NAME> --shielded-vtpm --shielded-\nvm-integrity-monitoring\n3. Optionally, if you do not use any custom or unsigned drivers on the instance, also\nturn on secure boot.\ngcloud compute instances update <INSTANCE_NAME> --shielded-vm-secure-boot\n4. Restart the instance:\ngcloud compute instances start <INSTANCE_NAME>\nPrevention:\nYou can ensure that all new VMs will be created with Shielded VM enabled by setting\nup an Organization Policy to for Shielded VM at https://console.cloud.google.com/iam-\nadmin/orgpolicies/compute-requireShieldedVm. Learn more at:\nhttps://cloud.google.com/security/shielded-cloud/shielded-vm#organization-policy-\nconstraint.",
    "default_value": "By default, Compute Instances do not have Shielded VM enabled.",
    "additional_information": "If you do use custom or unsigned drivers on the instance, enabling Secure Boot will\ncause the machine to no longer boot. Turn on Secure Boot only on instances that have\nbeen verified to not have any custom drivers installed.",
    "detection_commands": [
      "gcloud compute instances list --format=json | jq -r '. | \"vTPM:"
    ],
    "remediation_commands": [
      "select Turn on Secure Boot.",
      "gcloud compute images list --project gce-uefi-images --no-standard-images",
      "gcloud compute instances stop <INSTANCE_NAME>",
      "gcloud compute instances update <INSTANCE_NAME> --shielded-vtpm --shielded-",
      "gcloud compute instances update <INSTANCE_NAME> --shielded-vm-secure-boot",
      "gcloud compute instances start <INSTANCE_NAME>"
    ],
    "references": [
      "1. https://cloud.google.com/compute/docs/instances/modifying-shielded-vm",
      "2. https://cloud.google.com/shielded-vm",
      "3. https://cloud.google.com/security/shielded-cloud/shielded-vm#organization-",
      "policy-constraint"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 181,
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
    "cis_id": "4.9",
    "title": "Ensure That Compute Instances Do Not Have Public IP Addresses",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Maintain Secure Images",
    "description": "Compute instances should not be configured to have external IP addresses.",
    "rationale": "To reduce your attack surface, Compute instances should not have public IP addresses.\nInstead, instances should be configured behind load balancers, to minimize the\ninstance's exposure to the internet.",
    "impact": "Removing the external IP address from your Compute instance may cause some\napplications to stop working.",
    "audit": "From Google Cloud Console\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. For every VM, ensure that there is no External IP configured.\nFrom Google Cloud CLI\ngcloud compute instances list --format=json\n1. The output should not contain an accessConfigs section under\nnetworkInterfaces. Note that the natIP value is present only for instances that\nare running or for instances that are stopped but have a static IP address. For\ninstances that are stopped and are configured to have an ephemeral public IP\naddress, the natIP field will not be present. Example output:\nnetworkInterfaces:\n- accessConfigs:\n- kind: compute#accessConfig\nname: External NAT\nnetworkTier: STANDARD\ntype: ONE_TO_ONE_NAT\nException:\nInstances created by GKE should be excluded because some of them have external IP\naddresses and cannot be changed by editing the instance settings. Instances created\nby GKE should be excluded. These instances have names that start with \"gke-\" and are\nlabeled \"goog-gke-node\".",
    "expected_response": "2. For every VM, ensure that there is no External IP configured.\n1. The output should not contain an accessConfigs section under\nnetworkInterfaces. Note that the natIP value is present only for instances that\naddress, the natIP field will not be present. Example output:\nInstances created by GKE should be excluded because some of them have external IP\nby GKE should be excluded. These instances have names that start with \"gke-\" and are",
    "remediation": "From Google Cloud Console\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. Click on the instance name to go the the Instance detail page.\n3. Click Edit.\n4. For each Network interface, ensure that External IP is set to None.\n5. Click Done and then click Save.\nFrom Google Cloud CLI\n1. Describe the instance properties:\ngcloud compute instances describe <INSTANCE_NAME> --zone=<ZONE>\n2. Identify the access config name that contains the external IP address. This\naccess config appears in the following format:\nnetworkInterfaces:\n- accessConfigs:\n- kind: compute#accessConfig\nname: External NAT\nnatIP: 130.211.181.55\ntype: ONE_TO_ONE_NAT\n3. Delete the access config.\ngcloud compute instances delete-access-config <INSTANCE_NAME> --zone=<ZONE> -\n-access-config-name <ACCESS_CONFIG_NAME>\nIn the above example, the ACCESS_CONFIG_NAME is External NAT. The name of your\naccess config might be different.\nPrevention:\nYou can configure the Define allowed external IPs for VM instances\nOrganization Policy to prevent VMs from being configured with public IP addresses.\nLearn more at: https://console.cloud.google.com/orgpolicies/compute-\nvmExternalIpAccess",
    "default_value": "By default, Compute instances have a public IP address.",
    "additional_information": "You can connect to Linux VMs that do not have public IP addresses by using Identity-\nAware Proxy for TCP forwarding. Learn more at\nhttps://cloud.google.com/compute/docs/instances/connecting-\nadvanced#sshbetweeninstances\nFor Windows VMs, see https://cloud.google.com/compute/docs/instances/connecting-\nto-instance.",
    "detection_commands": [
      "gcloud compute instances list --format=json"
    ],
    "remediation_commands": [
      "gcloud compute instances describe <INSTANCE_NAME> --zone=<ZONE>",
      "gcloud compute instances delete-access-config <INSTANCE_NAME> --zone=<ZONE> -"
    ],
    "references": [
      "1. https://cloud.google.com/load-balancing/docs/backend-",
      "service#backends_and_external_ip_addresses",
      "2. https://cloud.google.com/compute/docs/instances/connecting-",
      "advanced#sshbetweeninstances",
      "3. https://cloud.google.com/compute/docs/instances/connecting-to-instance",
      "4. https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-",
      "address#unassign_ip",
      "5. https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-",
      "constraints"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 184,
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
    "cis_id": "4.10",
    "title": "Ensure That App Engine Applications Enforce HTTPS Connections",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "high",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "In order to maintain the highest level of security all connections to an application should\nbe secure by default.",
    "rationale": "Insecure HTTP connections maybe subject to eavesdropping which can expose\nsensitive data.",
    "impact": "All connections to appengine will automatically be redirected to the HTTPS endpoint\nensuring that all connections are secured by TLS.",
    "audit": "Verify that the app.yaml file controlling the application contains a line which enforces\nsecure connections. For example\nhandlers:\n- url: /.*\nsecure: always\nredirect_http_response_code: 301\nscript: auto\nhttps://cloud.google.com/appengine/docs/standard/python3/config/appref",
    "remediation": "Add a line to the app.yaml file controlling the application which enforces secure\nconnections. For example\nhandlers:\n- url: /.*\n**secure: always**\nredirect_http_response_code: 301\nscript: auto\n[https://cloud.google.com/appengine/docs/standard/python3/config/appref]",
    "default_value": "By default both HTTP and HTTP are supported",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.google.com/appengine/docs/standard/python3/config/appref",
      "2. https://cloud.google.com/appengine/docs/flexible/nodejs/configuring-your-app-",
      "with-app-yaml"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 187,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "4.11",
    "title": "Ensure That Compute Instances Have Confidential Computing Enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Use Only Standardized and Extensively Reviewed",
    "description": "Google Cloud encrypts data at-rest and in-transit, but customer data must be decrypted\nfor processing. Confidential Computing is a breakthrough technology that encrypts data\nin-use while it is being processed. Confidential Computing environments keep data\nencrypted in memory and elsewhere outside the central processing unit (CPU).\nConfidential VMs leverage hardware-based memory encryption technologies, such as\nAMD Secure Encrypted Virtualization (SEV), AMD SEV-SNP, and Intel Trust Domain\nExtensions (TDX), depending on the chosen machine type and CPU platform. Customer\ndata will stay encrypted while it is used, indexed, queried, or trained on. Encryption keys\nare generated by and reside solely in dedicated hardware and are not exportable,\nenhancing isolation and security. Built-in hardware optimizations ensure Confidential\nComputing workloads experience minimal to no significant performance penalties.",
    "rationale": "Confidential Computing enables customers' sensitive code and other data encrypted in\nmemory during processing. Google does not have access to the encryption keys.\nConfidential VM can help alleviate concerns about risk related to either dependency on\nGoogle infrastructure or Google insiders' access to customer data in the clear.",
    "impact": "• Confidential Computing for Compute instances does not support live migration.\nUnlike regular Compute instances, Confidential VMs experience disruptions\nduring maintenance events like a software or hardware update.\n• Additional charges may be incurred when enabling this security feature. See\nhttps://cloud.google.com/compute/confidential-vm/pricing for more info.",
    "audit": "Note: Confidential Computing is currently only supported on limited VM configurations.\nTo learn more about VM configurations supported by Confidential Computing, visit\nhttps://cloud.google.com/confidential-computing/confidential-vm/docs/supported-\nconfigurations\nFrom Google Cloud Console\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. Click on the instance name to see its VM instance details page.\n3. Ensure that Confidential VM service is Enabled.\nFrom Google Cloud CLI\n1. List the instances in your project and get details on each instance:\ngcloud compute instances list --format=json\n2. Ensure that enableConfidentialCompute is set to true for all instances with\nmachine type starting with \"n2d-\".\nconfidentialInstanceConfig:\nenableConfidentialCompute: true",
    "expected_response": "3. Ensure that Confidential VM service is Enabled.\n2. Ensure that enableConfidentialCompute is set to true for all instances with",
    "remediation": "Confidential Computing can only be enabled when an instance is created. You must\ndelete the current instance and create a new one.\nFrom Google Cloud Console\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. Click CREATE INSTANCE.\n3. Fill out the desired configuration for your instance.\n4. Under the Confidential VM service section, check the option Enable the\nConfidential Computing service on this VM instance.\n5. Click Create.\nFrom Google Cloud CLI\nCreate a new instance with Confidential Compute enabled.\ngcloud compute instances create <INSTANCE_NAME>   --zone <ZONE>   --\nconfidential-compute  --maintenance-policy=TERMINATE",
    "default_value": "By default, Confidential Computing is disabled for Compute instances.",
    "detection_commands": [
      "gcloud compute instances list --format=json"
    ],
    "remediation_commands": [
      "Create a new instance with Confidential Compute enabled. gcloud compute instances create <INSTANCE_NAME> --zone <ZONE> --"
    ],
    "references": [
      "1. https://cloud.google.com/compute/confidential-vm/docs/creating-cvm-instance",
      "2. https://cloud.google.com/compute/confidential-vm/docs/about-cvm",
      "3. https://cloud.google.com/confidential-computing",
      "4. https://cloud.google.com/blog/products/identity-security/introducing-google-cloud-",
      "confidential-computing-with-confidential-vms"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 189,
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
    "cis_id": "4.12",
    "title": "Ensure the Latest Operating System Updates Are Installed On Your Virtual Machines in All Projects",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "virtual_machines",
    "domain": "Virtual Machines",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "Google Cloud Virtual Machines have the ability via an OS Config agent API to\nperiodically (about every 10 minutes) report OS inventory data. A patch compliance API\nperiodically reads this data, and cross references metadata to determine if the latest\nupdates are installed.\nThis is not the only Patch Management solution available to your organization and you\nshould weigh your needs before committing to using this method.",
    "rationale": "Keeping virtual machine operating systems up to date is a security best practice. Using\nthis service will simplify this process.",
    "impact": "Most Operating Systems require a restart or changing critical resources to apply the\nupdates. Using the Google Cloud VM manager for its OS Patch management will incur\nadditional costs for each VM managed by it. Please view the VM manager pricing\nreference for further information.",
    "audit": "From Google Cloud Console\nDetermine if OS Config API is Enabled for the Project\n1. Navigate into a project. In the expanded navigation menu located at the top left of\nthe screen hover over APIs & Services. Then in the menu right of that select\nAPI Libraries\n2. Search for \"VM Manager (OS Config API) or scroll down in the left hand column\nand select the filter labeled \"Compute\" where it is the last listed. Open this API.\n3. Verify the blue button at the top is enabled.\nDetermine if VM Instances have correct metadata tags for OSConfig parsing\n1. From the main Google Cloud console, open the hamburger menu in the top left.\nMouse over Computer Engine to expand the menu next to it.\n2. Under the \"Settings\" heading, select \"Metadata\".\n3. In this view there will be a list of the project wide metadata tags for VMs.\nDetermine if the tag \"enable-osconfig\" is set to \"true\".\nDetermine if the Operating System of VM Instances have the local OS-Config\nAgent running\nThere is no way to determine this from the Google Cloud console. The only way is to\nrun operating specific commands locally inside the operating system via remote\nconnection. For the sake of brevity of this recommendation please view the\ndocs/troubleshooting/vm-manager/verify-setup reference at the bottom of the page. If\nyou initialized your VM instance with a Google Supplied OS Image with a build date of\nlater than v20200114 it will have the service installed. You should still determine its\nstatus for proper operation.\nVerify the service account you have setup for the project in Recommendation 4.1\nis running\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. Click on each instance name to go to its VM instance details page.\n3. Under the section Service Account, take note of the service account\n4. Run the commands locally for your operating system that are located at the\ndocs/troubleshooting/vm-manager/verify-setup#service-account-enabled\nreference located at the bottom of this page. They should return the name of your\nservice account.\nDetermine if Instances can connect to public update hosting\nEach type of operating system has its own update process. You will need to determine\non each operating system that it can reach the update servers via its network\nconnection. The VM Manager doesn't host the updates, it will only allow you to centrally\nissue a command to each VM to update.\nDetermine if OS Config API is Enabled for the Project\n1. In each project you wish to enable run the following command\ngcloud services list\n2. If osconfig.googleapis.com is in the left hand column it is enabled for this project.\nDetermine if VM Manager is Enabled for the Project\n1. Within the project run the following command:\ngcloud compute instances os-inventory describe VM-NAME \\\n--zone=ZONE\nThe output will look like\nINSTANCE_ID          INSTANCE_NAME  OS\nOSCONFIG_AGENT_VERSION       UPDATE_TIME\n29255009728795105    centos7        CentOS Linux 7 (Core)\n20210217.00-g1.el7           2021-04-12T22:19:36.559Z\n5138980234596718741  rhel-8         Red Hat Enterprise Linux 8.3 (Ootpa)\n20210316.00-g1.el8           2021-09-16T17:19:24Z\n7127836223366142250  windows        Microsoft Windows Server 2019 Datacenter\n20210316.00.0+win@1          2021-09-16T17:13:18Z\nDetermine if VM Instances have correct metadata tags for OSConfig parsing\n1. Select the project you want to view tagging in.\nFrom Google Cloud Console\n1. From the main Google Cloud console, open the hamburger menu in the top left.\nMouse over Computer Engine to expand the menu next to it.\n2. Under the \"Settings\" heading, select \"Metadata\".\n3. In this view there will be a list of the project wide metadata tags for Vms. Verify a\ntag of ‘enable-osconfig’ is in this list and it is set to ‘true’.\nFrom Command Line\nRun the following command to view instance data\ngcloud compute instances list --format=\"table(name,status,tags.list())\"\nOn each instance it should have a tag of ‘enable-osconfig’ set to ‘true’\nDetermine if the Operating System of VM Instances have the local OS-Config\nAgent running\nThere is no way to determine this from the Google Cloud CLI. The best way is to run the\nthe commands inside the operating system located at 'Check OS-Config agent is\ninstalled and running' at the /docs/troubleshooting/vm-manager/verify-setup reference at\nthe bottom of the page. If you initialized your VM instance with a Google Supplied OS\nImage with a build date of later than v20200114 it will have the service installed. You\nshould still determine its status.\nVerify the service account you have setup for the project in Recommendation 4.1\nis running\n1. Go to the VM instances page by visiting:\nhttps://console.cloud.google.com/compute/instances.\n2. Click on each instance name to go to its VM instance details page.\n3. Under the section Service Account, take note of the service account\n4. View the compute/docs/troubleshooting/vm-manager/verify-setup#service-\naccount-enabled resource at the bottom of the page for operating system specific\ncommands to run locally.\nDetermine if Instances can connect to public update hosting\nLinux\nDebian Based Operating Systems\nsudo apt update\nThe output should have a numbered list of lines with Hit: URL of updates.\nRedhat Based Operating Systems\nyum check-update\nThe output should show a list of packages that have updates available.\nWindows\nping http://windowsupdate.microsoft.com/\nThe ping should successfully be delivered and received.",
    "expected_response": "Determine if OS Config API is Enabled for the Project\n3. Verify the blue button at the top is enabled.\nDetermine if the tag \"enable-osconfig\" is set to \"true\".\nlater than v20200114 it will have the service installed. You should still determine its\nreference located at the bottom of this page. They should return the name of your\n2. If osconfig.googleapis.com is in the left hand column it is enabled for this project.\nDetermine if VM Manager is Enabled for the Project\nThe output will look like\ntag of ‘enable-osconfig’ is in this list and it is set to ‘true’.\nOn each instance it should have a tag of ‘enable-osconfig’ set to ‘true’\nshould still determine its status.\nThe output should have a numbered list of lines with Hit: URL of updates.\nThe output should show a list of packages that have updates available.\nThe ping should successfully be delivered and received.",
    "remediation": "From Google Cloud Console\nEnabling OS Patch Management on a Project by Project Basis\nInstall OS Config API for the Project\n1. Navigate into a project. In the expanded portal menu located at the top left of the\nscreen hover over \"APIs & Services\". Then in the menu right of that select \"API\nLibraries\"\n2. Search for \"VM Manager (OS Config API) or scroll down in the left hand column\nand select the filter labeled \"Compute\" where it is the last listed. Open this API.\n3. Click the blue 'Enable' button.\nAdd MetaData Tags for OSConfig Parsing\n1. From the main Google Cloud console, open the portal menu in the top left.\nMouse over Computer Engine to expand the menu next to it.\n2. Under the \"Settings\" heading, select \"Metadata\".\n3. In this view there will be a list of the project wide metadata tags for VMs. Click\nedit and 'add item' in the key column type 'enable-osconfig' and in the value\ncolumn set it to 'true'.\nFrom Command Line\n1. For project wide tagging, run the following command\ngcloud compute project-info add-metadata \\\n--project <PROJECT_ID>\\\n--metadata=enable-osconfig=TRUE\nPlease see the reference /compute/docs/troubleshooting/vm-manager/verify-\nsetup#metadata-enabled at the bottom for more options like instance specific tagging.\nNote: Adding a new tag via commandline may overwrite existing tags. You will need to\ndo this at a time of low usage for the least impact.\nInstall and Start the Local OSConfig for Data Parsing\nThere is no way to centrally manage or start the Local OSConfig agent. Please view the\nreference of manage-os#agent-install to view specific operating system commands.\nSetup a project wide Service Account\nPlease view Recommendation 4.1 to view how to setup a service account. Rerun the\naudit procedure to test if it has taken effect.\nEnable NAT or Configure Private Google Access to allow Access to Public Update\nHosting\nFor the sake of brevity, please see the attached resources to enable NAT or Private\nGoogle Access. Rerun the audit procedure to test if it has taken effect.\nFrom Command Line:\nInstall OS Config API for the Project\n1. In each project you wish to audit run gcloud services enable\nosconfig.googleapis.com\nInstall and Start the Local OSConfig for Data Parsing\nPlease view the reference of manage-os#agent-install to view specific operating system\ncommands.\nSetup a project wide Service Account\nPlease view Recommendation 4.1 to view how to setup a service account. Rerun the\naudit procedure to test if it has taken effect.\nEnable NAT or Configure Private Google Access to allow Access to Public Update\nHosting\nFor the sake of brevity, please see the attached resources to enable NAT or Private\nGoogle Access. Rerun the audit procedure to test if it has taken effect.\nDetermine if Instances can connect to public update hosting\nLinux\nDebian Based Operating Systems\nsudo apt update\nThe output should have a numbered list of lines with Hit: URL of updates.\nRedhat Based Operating Systems\nyum check-update\nThe output should show a list of packages that have updates available.\nWindows\nping http://windowsupdate.microsoft.com/\nThe ping should successfully be delivered and received.",
    "default_value": "By default most operating systems and programs do not update themselves. The\nGoogle Cloud VM Manager which is a dependency of the OS Patch management\nfeature is installed on Google Built OS images with a build date of v20200114 or later.\nThe VM manager is not enabled in a project by default and will need to be setup.",
    "additional_information": "This is not your only solution to handle updates. This is a Google Cloud specific\nrecommendation to leverage a resource to solve the need for comprehensive update\nprocedures and policy. If you have a solution already in place you do not need to make\nthe switch.\nThere are also further resources that would be out of the scope of this recommendation.\nIf you need to allow your VMs to access public hosted updates, please see the\nreference to setup NAT or Private Google Access.",
    "detection_commands": [
      "gcloud services list",
      "gcloud compute instances os-inventory describe VM-NAME --zone=ZONE",
      "gcloud compute instances list --format=\"table(name,status,tags.list())\""
    ],
    "remediation_commands": [
      "gcloud compute project-info add-metadata --project <PROJECT_ID> --metadata=enable-osconfig=TRUE"
    ],
    "references": [
      "1. https://cloud.google.com/compute/docs/manage-os",
      "2. https://cloud.google.com/compute/docs/os-patch-management",
      "3. https://cloud.google.com/compute/docs/vm-manager",
      "4. https://cloud.google.com/compute/docs/images/os-details#vm-manager",
      "5. https://cloud.google.com/compute/docs/vm-manager#pricing",
      "6. https://cloud.google.com/compute/docs/troubleshooting/vm-manager/verify-setup",
      "7. https://cloud.google.com/compute/docs/instances/view-os-details#view-data-",
      "tools",
      "8. https://cloud.google.com/compute/docs/os-patch-management/create-patch-job",
      "9. https://cloud.google.com/nat/docs/set-up-network-address-translation",
      "10. https://cloud.google.com/vpc/docs/configure-private-google-access",
      "11. https://workbench.cisecurity.org/sections/811638/recommendations/1334335",
      "12. https://cloud.google.com/compute/docs/manage-os#agent-install",
      "13. https://cloud.google.com/compute/docs/troubleshooting/vm-manager/verify-",
      "setup#service-account-enabled",
      "14. https://cloud.google.com/compute/docs/os-patch-management#use-dashboard",
      "15. https://cloud.google.com/compute/docs/troubleshooting/vm-manager/verify-",
      "setup#metadata-enabled"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 192,
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
    "cis_id": "5.1",
    "title": "Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "storage",
    "domain": "Storage",
    "description": "It is recommended that IAM policy on Cloud Storage bucket does not allows anonymous\nor public access.",
    "rationale": "Allowing anonymous or public access grants permissions to anyone to access bucket\ncontent. Such access might not be desired if you are storing any sensitive data. Hence,\nensure that anonymous or public access to a bucket is not allowed.",
    "impact": "No storage buckets would be publicly accessible. You would have to explicitly\nadminister bucket access.",
    "audit": "From Google Cloud Console\n1. Go to Storage browser by visiting\nhttps://console.cloud.google.com/storage/browser.\n2. Click on each bucket name to go to its Bucket details page.\n3. Click on the Permissions tab.\n4. Ensure that allUsers and allAuthenticatedUsers are not in the Members list.\nFrom Google Cloud CLI\n1. List all buckets in a project\ngsutil ls\n2. Check the IAM Policy for each bucket:\ngsutil iam get gs://BUCKET_NAME\nNo role should contain allUsers and/or allAuthenticatedUsers as a member.\nUsing Rest API\n1. List all buckets in a project\nGet https://www.googleapis.com/storage/v1/b?project=<ProjectName>\n2. Check the IAM Policy for each bucket\nGET https://www.googleapis.com/storage/v1/b/<bucketName>/iam\nNo role should contain allUsers and/or allAuthenticatedUsers as a member.",
    "expected_response": "4. Ensure that allUsers and allAuthenticatedUsers are not in the Members list.\nNo role should contain allUsers and/or allAuthenticatedUsers as a member.",
    "remediation": "From Google Cloud Console\n1. Go to Storage browser by visiting\nhttps://console.cloud.google.com/storage/browser.\n2. Click on the bucket name to go to its Bucket details page.\n3. Click on the Permissions tab.\n4. Click Delete button in front of allUsers and allAuthenticatedUsers to\nremove that particular role assignment.\nFrom Google Cloud CLI\nRemove allUsers and allAuthenticatedUsers access.\ngsutil iam ch -d allUsers gs://BUCKET_NAME\ngsutil iam ch -d allAuthenticatedUsers gs://BUCKET_NAME\nPrevention:\nYou can prevent Storage buckets from becoming publicly accessible by setting up the\nDomain restricted sharing organization policy at:\nhttps://console.cloud.google.com/iam-admin/orgpolicies/iam-\nallowedPolicyMemberDomains .",
    "default_value": "By Default, Storage buckets are not publicly shared.",
    "additional_information": "To implement Access restrictions on buckets, configuring Bucket IAM is preferred way\nthan configuring Bucket ACL. On GCP console, \"Edit Permissions\" for bucket exposes\nIAM configurations only. Bucket ACLs are configured automatically as per need in order\nto implement/support User enforced Bucket IAM policy. In-case administrator changes\nbucket ACL using command-line(gsutils)/API bucket IAM also gets updated\nautomatically.",
    "detection_commands": [
      "gsutil ls",
      "gsutil iam get gs://BUCKET_NAME"
    ],
    "remediation_commands": [
      "gsutil iam ch -d allUsers gs://BUCKET_NAME gsutil iam ch -d allAuthenticatedUsers gs://BUCKET_NAME"
    ],
    "references": [
      "1. https://cloud.google.com/storage/docs/access-control/iam-reference",
      "2. https://cloud.google.com/storage/docs/access-control/making-data-public",
      "3. https://cloud.google.com/storage/docs/gsutil/commands/iam"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 200,
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
    "cis_id": "5.2",
    "title": "Ensure That Cloud Storage Buckets Have Uniform Bucket- Level Access Enabled",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "storage",
    "domain": "Storage",
    "subdomain": "Deny Communication over Unauthorized Ports",
    "description": "It is recommended that uniform bucket-level access is enabled on Cloud Storage\nbuckets.",
    "rationale": "It is recommended to use uniform bucket-level access to unify and simplify how you\ngrant access to your Cloud Storage resources.\nCloud Storage offers two systems for granting users permission to access your buckets\nand objects: Cloud Identity and Access Management (Cloud IAM) and Access Control\nLists (ACLs). These systems act in parallel - in order for a user to access a Cloud\nStorage resource, only one of the systems needs to grant the user permission. Cloud\nIAM is used throughout Google Cloud and allows you to grant a variety of permissions\nat the bucket and project levels. ACLs are used only by Cloud Storage and have limited\npermission options, but they allow you to grant permissions on a per-object basis.\nIn order to support a uniform permissioning system, Cloud Storage has uniform bucket-\nlevel access. Using this feature disables ACLs for all Cloud Storage resources: access\nto Cloud Storage resources then is granted exclusively through Cloud IAM. Enabling\nuniform bucket-level access guarantees that if a Storage bucket is not publicly\naccessible, no object in the bucket is publicly accessible either.",
    "impact": "If you enable uniform bucket-level access, you revoke access from users who gain their\naccess solely through object ACLs.\nCertain Google Cloud services, such as Stackdriver, Cloud Audit Logs, and Datastore,\ncannot export to Cloud Storage buckets that have uniform bucket-level access enabled.",
    "audit": "From Google Cloud Console\n1. Open the Cloud Storage browser in the Google Cloud Console by visiting:\nhttps://console.cloud.google.com/storage/browser\n2. For each bucket, make sure that Access control column has the value\nUniform.\nFrom Google Cloud CLI\n1. List all buckets in a project\ngsutil ls\n2. For each bucket, verify that uniform bucket-level access is enabled.\ngsutil uniformbucketlevelaccess get gs://BUCKET_NAME/\nIf uniform bucket-level access is enabled, the response looks like:\nUniform bucket-level access setting for gs://BUCKET_NAME/:\nEnabled: True\nLockedTime: LOCK_DATE",
    "expected_response": "2. For each bucket, verify that uniform bucket-level access is enabled.\nIf uniform bucket-level access is enabled, the response looks like:",
    "remediation": "From Google Cloud Console\n1. Open the Cloud Storage browser in the Google Cloud Console by visiting:\nhttps://console.cloud.google.com/storage/browser\n2. In the list of buckets, click on the name of the desired bucket.\n3. Select the Permissions tab near the top of the page.\n4. In the text box that starts with This bucket uses fine-grained access\ncontrol..., click Edit.\n5. In the pop-up menu that appears, select Uniform.\n6. Click Save.\nFrom Google Cloud CLI\nUse the on option in a uniformbucketlevelaccess set command:\ngsutil uniformbucketlevelaccess set on gs://BUCKET_NAME/\nPrevention\nYou can set up an Organization Policy to enforce that any new bucket has uniform\nbucket level access enabled. Learn more at:\nhttps://cloud.google.com/storage/docs/setting-org-policies#uniform-bucket",
    "default_value": "By default, Cloud Storage buckets do not have uniform bucket-level access enabled.",
    "additional_information": "Uniform bucket-level access can no longer be disabled if it has been active on a bucket\nfor 90 consecutive days.",
    "detection_commands": [
      "gsutil ls",
      "gsutil uniformbucketlevelaccess get gs://BUCKET_NAME/"
    ],
    "remediation_commands": [
      "Use the on option in a uniformbucketlevelaccess set command: gsutil uniformbucketlevelaccess set on gs://BUCKET_NAME/"
    ],
    "references": [
      "1. https://cloud.google.com/storage/docs/uniform-bucket-level-access",
      "2. https://cloud.google.com/storage/docs/using-uniform-bucket-level-access",
      "3. https://cloud.google.com/storage/docs/setting-org-policies#uniform-bucket"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 203,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "access"
    ],
    "rr_relevant": false
  },
  {
    "cis_id": "6.1.1",
    "title": "Ensure That a MySQL Instance Does Not Allow Anyone To Connect With Administrative Privileges",
    "cis_level": "L1",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "critical",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "MySQL Database",
    "description": "It is recommended to set a password for the administrative user (root by default) to\nprevent unauthorized access to the SQL database instances.\nThis recommendation is applicable only for MySQL Instances. PostgreSQL does not\noffer any setting for No Password from the cloud console.",
    "rationale": "At the time of MySQL Instance creation, not providing an administrative password\nallows anyone to connect to the SQL database instance with administrative privileges.\nThe root password should be set to ensure only authorized users have these privileges.",
    "impact": "Connection strings for administrative clients need to be reconfigured to use a password.",
    "audit": "From Google Cloud CLI\n1. List All SQL database instances of type MySQL:\ngcloud sql instances list --filter='DATABASE_VERSION:MYSQL*' --project\n<project_id> --format=\"(NAME,PRIMARY_ADDRESS)\"\n2. For every MySQL instance try to connect using the PRIMARY_ADDRESS, if\navailable:\nmysql -u root -h <mysql_instance_ip_address>\nThe command should return either an error message or a password prompt.\nSample Error message:\nERROR 1045 (28000): Access denied for user 'root'@'<Instance_IP>' (using\npassword: NO)\nIf a command produces the mysql> prompt, the MySQL instance allows anyone to\nconnect with administrative privileges without needing a password.\nNote: The No Password setting is exposed only at the time of MySQL instance\ncreation. Once the instance is created, the Google Cloud Platform Console does not\nexpose the set to confirm whether a password for an administrative user is set to a\nMySQL instance.",
    "expected_response": "The command should return either an error message or a password prompt.\nexpose the set to confirm whether a password for an administrative user is set to a",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Platform Console\nusing https://console.cloud.google.com/sql/\n2. Select the instance to open its Overview page.\n3. Select Access Control > Users.\n4. Click the More actions icon for the user to be updated.\n5. Select Change password, specify a New password, and click OK.\nFrom Google Cloud CLI\n1. Set a password to a MySql instance:\ngcloud sql users set-password root --host=<host> --instance=<instance_name> -\n-prompt-for-password\n2. A prompt will appear, requiring the user to enter a password:\nInstance Password:\n3. With a successful password configured, the following message should be seen:\nUpdating Cloud SQL user...done.",
    "default_value": "From the Google Cloud Platform Console, the Create Instance workflow enforces the\nrule to enter the root password unless the option No Password is selected explicitly.",
    "detection_commands": [
      "gcloud sql instances list --filter='DATABASE_VERSION:MYSQL*' --project"
    ],
    "remediation_commands": [
      "gcloud sql users set-password root --host=<host> --instance=<instance_name> -"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/mysql/create-manage-users",
      "2. https://cloud.google.com/sql/docs/mysql/create-instance"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
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
    "cis_id": "6.1.2",
    "title": "Ensure ‘Skip_show_database’ Database Flag for Cloud SQL MySQL Instance Is Set to ‘On’",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Change Default Passwords",
    "description": "It is recommended to set skip_show_database database flag for Cloud SQL Mysql\ninstance to on",
    "rationale": "skip_show_database database flag prevents people from using the SHOW\nDATABASES statement if they do not have the SHOW DATABASES privilege. This can\nimprove security if you have concerns about users being able to see databases\nbelonging to other users. Its effect depends on the SHOW DATABASES privilege: If the\nvariable value is ON, the SHOW DATABASES statement is permitted only to users who\nhave the SHOW DATABASES privilege, and the statement displays all database\nnames. If the value is OFF, SHOW DATABASES is permitted to all users, but displays\nthe names of only those databases for which the user has the SHOW DATABASES or\nother privilege. This recommendation is applicable to Mysql database instances.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page\n3. Ensure the database flag skip_show_database that has been set is listed under\nthe Database flags section.\nFrom Google Cloud CLI\n1. List all Cloud SQL database Instances\ngcloud sql instances list\n2. Ensure the below command returns on for every Cloud SQL Mysql database\ninstance\ngcloud sql instances describe <INSTANCE_NAME> --format=json | jq\n'.settings.databaseFlags[] | select(.name==\"skip_show_database\")|.value'",
    "expected_response": "3. Ensure the database flag skip_show_database that has been set is listed under\n2. Ensure the below command returns on for every Cloud SQL Mysql database",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the Mysql instance for which you want to enable to database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add a Database\nFlag, choose the flag skip_show_database from the drop-down menu, and set\nits value to on.\n6. Click Save to save your changes.\n7. Confirm your changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. List all Cloud SQL database Instances\ngcloud sql instances list\n2. Configure the skip_show_database database flag for every Cloud SQL Mysql\ndatabase instance using the below command.\ngcloud sql instances patch <INSTANCE_NAME> --database-flags\nskip_show_database=on\nNote:\nThis command will overwrite all database flags previously set. To keep those and add\nnew ones, include the values for all flags you want set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/mysql/flags - to see if your instance will be restarted\nwhen this patch is submitted.\nNote: some database flag settings can affect instance availability or stability, and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\"\nNote: Configuring the above flag restarts the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances list",
      "gcloud sql instances describe <INSTANCE_NAME> --format=json | jq '.settings.databaseFlags[] | select(.name==\"skip_show_database\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances list",
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/mysql/flags",
      "2. https://dev.mysql.com/doc/refman/5.7/en/server-system-",
      "variables.html#sysvar_skip_show_database"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 211,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "6.1.3",
    "title": "Ensure That the ‘Local_infile’ Database Flag for a Cloud SQL MySQL Instance Is Set to ‘Off’",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "It is recommended to set the local_infile database flag for a Cloud SQL MySQL\ninstance to off.",
    "rationale": "The local_infile flag controls the server-side LOCAL capability for LOAD DATA\nstatements. Depending on the local_infile setting, the server refuses or permits\nlocal data loading by clients that have LOCAL enabled on the client side.\nTo explicitly cause the server to refuse LOAD DATA LOCAL statements (regardless of\nhow client programs and libraries are configured at build time or runtime), start mysqld\nwith local_infile disabled. local_infile can also be set at runtime.\nDue to security issues associated with the local_infile flag, it is recommended to\ndisable it. This recommendation is applicable to MySQL database instances.",
    "impact": "Disabling local_infile makes the server refuse local data loading by clients that have\nLOCAL enabled on the client side.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page\n3. Ensure the database flag local_infile that has been set is listed under the\nDatabase flags section.\nFrom Google Cloud CLI\n1. List all Cloud SQL database instances:\ngcloud sql instances list\n2. Ensure the below command returns off for every Cloud SQL MySQL database\ninstance.\ngcloud sql instances describe <INSTANCE_NAME> --format=json | jq\n'.settings.databaseFlags[] | select(.name==\"local_infile\")|.value'",
    "expected_response": "3. Ensure the database flag local_infile that has been set is listed under the\n2. Ensure the below command returns off for every Cloud SQL MySQL database",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the MySQL instance where the database flag needs to be enabled.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add a Database\nFlag, choose the flag local_infile from the drop-down menu, and set its value\nto off.\n6. Click Save.\n7. Confirm the changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. List all Cloud SQL database instances using the following command:\ngcloud sql instances list\n2. Configure the local_infile database flag for every Cloud SQL Mysql database\ninstance using the below command:\ngcloud sql instances patch <INSTANCE_NAME> --database-flags local_infile=off\nNote:\nThis command will overwrite all database flags that were previously set. To keep those\nand add new ones, include the values for all flags to be set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "By default local_infile is on.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require the instance to\nbe restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/mysql/flags - to see if your instance will be restarted\nwhen this patch is submitted.\nNote: some database flag settings can affect instance availability or stability, and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\"",
    "detection_commands": [
      "gcloud sql instances list",
      "gcloud sql instances describe <INSTANCE_NAME> --format=json | jq '.settings.databaseFlags[] | select(.name==\"local_infile\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances list",
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags local_infile=off"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/mysql/flags",
      "2. https://dev.mysql.com/doc/refman/5.7/en/server-system-",
      "variables.html#sysvar_local_infile",
      "3. https://dev.mysql.com/doc/refman/5.7/en/load-data-local.html"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 214,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "6.2.1",
    "title": "Ensure ‘Log_error_verbosity’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘DEFAULT’ or Stricter",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "PostgreSQL Database",
    "description": "The log_error_verbosity flag controls the verbosity/details of messages logged.\nValid values are:\n• TERSE\n• DEFAULT\n• VERBOSE\nTERSE excludes the logging of DETAIL, HINT, QUERY, and CONTEXT error information.\nVERBOSE output includes the SQLSTATE error code, source code file name, function\nname, and line number that generated the error.\nEnsure an appropriate value is set to 'DEFAULT' or stricter.",
    "rationale": "Auditing helps in troubleshooting operational problems and also permits forensic\nanalysis. If log_error_verbosity is not set to the correct value, too many details or\ntoo few details may be logged. This flag should be configured with a value of\n'DEFAULT' or stricter. This recommendation is applicable to PostgreSQL database\ninstances.",
    "impact": "Turning on logging will increase the required storage over time. Mismanaged logs may\ncause your storage costs to increase. Setting custom flags via command line on certain\ninstances will cause all omitted flags to be reset to defaults. This may cause you to lose\ncustom flags and could result in unforeseen complications or instance restarts. Because\nof this, it is recommended you apply these flags changes during a period of low usage.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page\n3. Go to Configuration card\n4. Under Database flags, check the value of log_error_verbosity flag is set to\n'DEFAULT' or stricter.\nFrom Google Cloud CLI\n1. Use the below command for every Cloud SQL PostgreSQL database instance to\nverify the value of log_error_verbosity\ngcloud sql instances describe [INSTANCE_NAME] --format=json | jq\n'.settings.databaseFlags[] | select(.name==\"log_error_verbosity\")|.value'\nIn the output, database flags are listed under the settings as the collection\ndatabaseFlags.",
    "expected_response": "4. Under Database flags, check the value of log_error_verbosity flag is set to\nIn the output, database flags are listed under the settings as the collection",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the PostgreSQL instance for which you want to enable the database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add a Database\nFlag, choose the flag log_error_verbosity from the drop-down menu and set\nappropriate value.\n6. Click Save to save your changes.\n7. Confirm your changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. Configure the log_error_verbosity database flag for every Cloud SQL PosgreSQL\ndatabase instance using the below command.\ngcloud sql instances patch INSTANCE_NAME --database-flags\nlog_error_verbosity=<TERSE|DEFAULT|VERBOSE>\nNote: This command will overwrite all database flags previously set. To keep those and\nadd new ones, include the values for all flags you want set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "By default log_error_verbosity is DEFAULT.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/postgres/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: some database flag settings can affect instance availability or stability and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\nNote: Configuring the above flag does not require restarting the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances describe [INSTANCE_NAME] --format=json | jq '.settings.databaseFlags[] | select(.name==\"log_error_verbosity\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances patch INSTANCE_NAME --database-flags"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/postgres/flags",
      "2. https://www.postgresql.org/docs/current/runtime-config-logging.html#GUC-LOG-",
      "ERROR-VERBOSITY"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 218,
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
    "cis_id": "6.2.2",
    "title": "Ensure That the ‘Log_connections’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘On’",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Enable Detailed Logging",
    "description": "Enabling the log_connections setting causes each attempted connection to the server\nto be logged, along with successful completion of client authentication. This parameter\ncannot be changed after the session starts.",
    "rationale": "PostgreSQL does not log attempted connections by default. Enabling the\nlog_connections setting will create log entries for each attempted connection as well\nas successful completion of client authentication which can be useful in troubleshooting\nissues and to determine any unusual connection attempts to the server. This\nrecommendation is applicable to PostgreSQL database instances.",
    "impact": "Turning on logging will increase the required storage over time. Mismanaged logs may\ncause your storage costs to increase. Setting custom flags via command line on certain\ninstances will cause all omitted flags to be reset to defaults. This may cause you to lose\ncustom flags and could result in unforeseen complications or instance restarts. Because\nof this, it is recommended you apply these flags changes during a period of low usage.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page.\n3. Go to the Configuration card.\n4. Under Database flags, check the value of log_connections flag to determine\nif it is configured as expected.\nFrom Google Cloud CLI\n1. Ensure the below command returns on for every Cloud SQL PostgreSQL\ndatabase instance:\ngcloud sql instances describe [INSTANCE_NAME] --format=json | jq\n'.settings.databaseFlags[] | select(.name==\"log_connections\")|.value'\nIn the output, database flags are listed under the settings as the collection\ndatabaseFlags.",
    "expected_response": "if it is configured as expected.\n1. Ensure the below command returns on for every Cloud SQL PostgreSQL\nIn the output, database flags are listed under the settings as the collection",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the PostgreSQL instance for which you want to enable the database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add a Database\nFlag, choose the flag log_connections from the drop-down menu and set the\nvalue as on.\n6. Click Save.\n7. Confirm the changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. Configure the log_connections database flag for every Cloud SQL PosgreSQL\ndatabase instance using the below command.\ngcloud sql instances patch <INSTANCE_NAME> --database-flags\n\"log_connections\"=on\nNote:\nThis command will overwrite all previously set database flags. To keep those and add\nnew ones, include the values for all flags to be set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "By default log_connections is off.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/postgres/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: some database flag settings can affect instance availability or stability and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nthe Operational Guidelines.\nNote: Configuring the above flag does not require restarting the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances describe [INSTANCE_NAME] --format=json | jq '.settings.databaseFlags[] | select(.name==\"log_connections\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags \"log_connections\"=on"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/postgres/flags",
      "2. https://www.postgresql.org/docs/current/runtime-config-logging.html#GUC-LOG-",
      "CONNECTIONS"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 221,
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
    "cis_id": "6.2.3",
    "title": "Ensure That the ‘Log_disconnections’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘On’",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Enable Detailed Logging",
    "description": "Enabling the log_disconnections setting logs the end of each session, including the\nsession duration.",
    "rationale": "PostgreSQL does not log session details such as duration and session end by default.\nEnabling the log_disconnections setting will create log entries at the end of each\nsession which can be useful in troubleshooting issues and determine any unusual\nactivity across a time period. The log_disconnections and log_connections work\nhand in hand and generally, the pair would be enabled/disabled together. This\nrecommendation is applicable to PostgreSQL database instances.",
    "impact": "Turning on logging will increase the required storage over time. Mismanaged logs may\ncause your storage costs to increase. Setting custom flags via command line on certain\ninstances will cause all omitted flags to be reset to defaults. This may cause you to lose\ncustom flags and could result in unforeseen complications or instance restarts. Because\nof this, it is recommended you apply these flags changes during a period of low usage.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page\n3. Go to the Configuration card.\n4. Under Database flags, check the value of log_disconnections flag is\nconfigured as expected.\nFrom Google Cloud CLI\n1. Ensure the below command returns on for every Cloud SQL PostgreSQL\ndatabase instance:\ngcloud sql instances list --format=json | jq '.[].settings.databaseFlags[] |\nselect(.name==\"log_disconnections\")|.value'",
    "expected_response": "1. Ensure the below command returns on for every Cloud SQL PostgreSQL",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the PostgreSQL instance where the database flag needs to be enabled.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add a Database\nFlag, choose the flag log_disconnections from the drop-down menu and set\nthe value as on.\n6. Click Save.\n7. Confirm the changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. Configure the log_disconnections database flag for every Cloud SQL\nPosgreSQL database instance using the below command:\ngcloud sql instances patch <INSTANCE_NAME> --database-flags\nlog_disconnections=on\nNote: This command will overwrite all previously set database flags. To keep those and\nadd new ones, include the values for all flags to be set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "By default log_disconnections is off.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/postgres/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: some database flag settings can affect instance availability or stability and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\nNote: Configuring the above flag does not require restarting the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances list --format=json | jq '.[].settings.databaseFlags[] | select(.name==\"log_disconnections\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/postgres/flags",
      "2. https://www.postgresql.org/docs/current/runtime-config-logging.html#GUC-LOG-",
      "DISCONNECTIONS"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 224,
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
    "cis_id": "6.2.4",
    "title": "Ensure ‘Log_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set Appropriately",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Enable Detailed Logging",
    "description": "The value of log_statement flag determined the SQL statements that are logged. Valid\nvalues are:\n• none\n• ddl\n• mod\n• all\nThe value ddl logs all data definition statements. The value mod logs all ddl statements,\nplus data-modifying statements.\nThe statements are logged after a basic parsing is done and statement type is\ndetermined, thus this does not logs statements with errors. When using extended query\nprotocol, logging occurs after an Execute message is received and values of the Bind\nparameters are included.\nA value of 'ddl' is recommended unless otherwise directed by your organization's\nlogging policy.",
    "rationale": "Auditing helps in forensic analysis. If log_statement is not set to the correct value, too\nmany statements may be logged leading to issues in finding the relevant information\nfrom the logs, or too few statements may be logged with relevant information missing\nfrom the logs. Setting log_statement to align with your organization's security and\nlogging policies facilitates later auditing and review of database activities. This\nrecommendation is applicable to PostgreSQL database instances.",
    "impact": "Turning on logging will increase the required storage over time. Mismanaged logs may\ncause your storage costs to increase. Setting custom flags via command line on certain\ninstances will cause all omitted flags to be reset to defaults. This may cause you to lose\ncustom flags and could result in unforeseen complications or instance restarts. Because\nof this, it is recommended you apply these flags changes during a period of low usage.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page\n3. Go to Configuration card\n4. Under Database flags, check the value of log_statement flag is set to\nappropriately.\nFrom Google Cloud CLI\n1. Use the below command for every Cloud SQL PostgreSQL database instance to\nverify the value of log_statement\ngcloud sql instances list --format=json | jq '.[].settings.databaseFlags[] |\nselect(.name==\"log_statement\")|.value'",
    "expected_response": "4. Under Database flags, check the value of log_statement flag is set to",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the PostgreSQL instance for which you want to enable the database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add a Database\nFlag, choose the flag log_statement from the drop-down menu and set\nappropriate value.\n6. Click Save to save your changes.\n7. Confirm your changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. Configure the log_statement database flag for every Cloud SQL PosgreSQL\ndatabase instance using the below command.\ngcloud sql instances patch <INSTANCE_NAME> --database-flags\nlog_statement=<ddl|mod|all|none>\nNote: This command will overwrite all database flags previously set. To keep those and\nadd new ones, include the values for all flags you want set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "none",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/postgres/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: some database flag settings can affect instance availability or stability and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\nNote: Configuring the above flag does not require restarting the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances list --format=json | jq '.[].settings.databaseFlags[] | select(.name==\"log_statement\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/postgres/flags",
      "2. https://www.postgresql.org/docs/current/runtime-config-logging.html#GUC-LOG-",
      "STATEMENT"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 227,
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
    "cis_id": "6.2.5",
    "title": "Ensure that the ‘Log_min_messages’ Flag for a Cloud SQL PostgreSQL Instance is set at minimum to 'Warning'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Enable Detailed Logging",
    "description": "The log_min_messages flag defines the minimum message severity level that is\nconsidered as an error statement. Messages for error statements are logged with the\nSQL statement. Valid values include (from lowest to highest severity) DEBUG5, DEBUG4,\nDEBUG3, DEBUG2, DEBUG1, INFO, NOTICE, WARNING, ERROR, LOG, FATAL, and PANIC. Each\nseverity level includes the subsequent levels mentioned above. ERROR is considered\nthe best practice setting. Changes should only be made in accordance with the\norganization's logging policy.",
    "rationale": "Auditing helps in troubleshooting operational problems and also permits forensic\nanalysis. If log_min_messages is not set to the correct value, messages may not be\nclassified as error messages appropriately. Setting the threshold to 'Warning' will log\nmessages for the most needed error messages.\nThis recommendation is applicable to PostgreSQL database instances.",
    "impact": "Setting the threshold too low will might result in increased log storage size and length,\nmaking it difficult to find actual errors. Higher severity levels may cause errors needed\nto troubleshoot to not be logged. An organization will need to decide their own threshold\nfor logging log_min_messages flag.\nNote: To effectively turn off logging failing statements, set this parameter to PANIC.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page.\n3. Go to the Configuration card.\n4. Under Database flags, check the value of log_min_messages flag is set to\nwarning or higher (WARNING|ERROR|LOG|FATAL|PANIC).\nFrom Google Cloud CLI\n1. Use the below command for every Cloud SQL PostgreSQL database instance to\nverify that the value of log_min_messages is set to warning or higher .\ngcloud sql instances describe [INSTANCE_NAME] --format=json | jq\n'.settings.databaseFlags[] | select(.name==\"log_min_messages\")|.value'",
    "expected_response": "4. Under Database flags, check the value of log_min_messages flag is set to\nverify that the value of log_min_messages is set to warning or higher .",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances\n2. Select the PostgreSQL instance for which you want to enable the database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add a Database\nFlag, choose the flag log_min_messages from the drop-down menu and set\nappropriate value.\n6. Click Save to save the changes.\n7. Confirm the changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. Configure the log_min_messages database flag for every Cloud SQL\nPosgreSQL database instance using the below command.\ngcloud sql instances patch <INSTANCE_NAME> --database-flags\nlog_min_messages=<DEBUG5|DEBUG4|DEBUG3|DEBUG2|DEBUG1|INFO|NOTICE|WARNING|ERRO\nR|LOG|FATAL|PANIC>\nNote: This command will overwrite all database flags previously set. To keep those and\nadd new ones, include the values for all flags to be set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "By default log_min_messages is ERROR.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/postgres/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: Some database flag settings can affect instance availability or stability and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\nNote: Configuring the above flag does not require restarting the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances describe [INSTANCE_NAME] --format=json | jq '.settings.databaseFlags[] | select(.name==\"log_min_messages\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/postgres/flags",
      "2. https://www.postgresql.org/docs/current/runtime-config-logging.html#GUC-LOG-",
      "MIN-MESSAGES"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 230,
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
    "cis_id": "6.2.6",
    "title": "Ensure ‘Log_min_error_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘Error’ or Stricter",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Enable Detailed Logging",
    "description": "The log_min_error_statement flag defines the minimum message severity level that\nare considered as an error statement. Messages for error statements are logged with\nthe SQL statement. Valid values include (from lowest to highest severity) DEBUG5,\nDEBUG4, DEBUG3, DEBUG2, DEBUG1, INFO, NOTICE, WARNING, ERROR, LOG, FATAL, and\nPANIC. Each severity level includes the subsequent levels mentioned above. Ensure a\nvalue of ERROR or stricter is set.",
    "rationale": "Auditing helps in troubleshooting operational problems and also permits forensic\nanalysis. If log_min_error_statement is not set to the correct value, messages may\nnot be classified as error messages appropriately. Considering general log messages\nas error messages would make is difficult to find actual errors and considering only\nstricter severity levels as error messages may skip actual errors to log their SQL\nstatements. The log_min_error_statement flag should be set to ERROR or stricter.\nThis recommendation is applicable to PostgreSQL database instances.",
    "impact": "Turning on logging will increase the required storage over time. Mismanaged logs may\ncause your storage costs to increase. Setting custom flags via command line on certain\ninstances will cause all omitted flags to be reset to defaults. This may cause you to lose\ncustom flags and could result in unforeseen complications or instance restarts. Because\nof this, it is recommended you apply these flags changes during a period of low usage.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page\n3. Go to Configuration card\n4. Under Database flags, check the value of log_min_error_statement flag is\nconfigured as to ERROR or stricter.\nFrom Google Cloud CLI\n1. Use the below command for every Cloud SQL PostgreSQL database instance to\nverify the value of log_min_error_statement is set to ERROR or stricter.\ngcloud sql instances describe <INSTANCE_NAME> --format=json | jq\n'.[].settings.databaseFlags[] |\nselect(.name==\"log_min_error_statement\")|.value'\nIn the output, database flags are listed under the settings as the collection\ndatabaseFlags.",
    "expected_response": "verify the value of log_min_error_statement is set to ERROR or stricter.\nIn the output, database flags are listed under the settings as the collection",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the PostgreSQL instance for which you want to enable the database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add item,\nchoose the flag log_min_error_statement from the drop-down menu and set\nappropriate value.\n6. Click Save to save your changes.\n7. Confirm your changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. Configure the log_min_error_statement database flag for every Cloud SQL\nPosgreSQL database instance using the below command.\ngcloud sql instances patch <INSTANCE_NAME> --database-flags\nlog_min_error_statement=<DEBUG5|DEBUG4|DEBUG3|DEBUG2|DEBUG1|INFO|NOTICE|WARNI\nNG|ERROR>\nNote: This command will overwrite all database flags previously set. To keep those and\nadd new ones, include the values for all flags you want set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "By default log_min_error_statement is ERROR.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/postgres/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: some database flag settings can affect instance availability or stability and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\nNote: Configuring the above flag does not require restarting the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances describe <INSTANCE_NAME> --format=json | jq '.[].settings.databaseFlags[] | select(.name==\"log_min_error_statement\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/postgres/flags",
      "2. https://www.postgresql.org/docs/current/runtime-config-logging.html#GUC-LOG-",
      "MIN-ERROR-STATEMENT"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 233,
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
    "cis_id": "6.2.7",
    "title": "Ensure That the ‘Log_min_duration_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to '-1' (Disabled)",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Enable Detailed Logging",
    "description": "The log_min_duration_statement flag defines the minimum amount of execution\ntime of a statement in milliseconds where the total duration of the statement is logged.\nEnsure that log_min_duration_statement is disabled, i.e., a value of -1 is set.",
    "rationale": "Logging SQL statements may include sensitive information that should not be recorded\nin logs. This recommendation is applicable to PostgreSQL database instances.",
    "impact": "Turning on logging will increase the required storage over time. Mismanaged logs may\ncause your storage costs to increase. Setting custom flags via command line on certain\ninstances will cause all omitted flags to be reset to defaults. This may cause you to lose\ncustom flags and could result in unforeseen complications or instance restarts. Because\nof this, it is recommended you apply these flags changes during a period of low usage.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page.\n3. Go to the Configuration card.\n4. Under Database flags, check that the value of log_min_duration_statement\nflag is set to -1.\nFrom Google Cloud CLI\n1. Use the below command for every Cloud SQL PostgreSQL database instance to\nverify the value of log_min_duration_statement is set to -1.\ngcloud sql instances describe <INSTANCE_NAME> --format=json| jq\n'.settings.databaseFlags[] |\nselect(.name==\"log_min_duration_statement\")|.value'\nIn the output, database flags are listed under the settings as the collection\ndatabaseFlags.",
    "expected_response": "flag is set to -1.\nverify the value of log_min_duration_statement is set to -1.\nIn the output, database flags are listed under the settings as the collection",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the PostgreSQL instance where the database flag needs to be enabled.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add item,\nchoose the flag log_min_duration_statement from the drop-down menu and\nset a value of -1.\n6. Click Save.\n7. Confirm the changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. List all Cloud SQL database instances using the following command:\ngcloud sql instances list\n2. Configure the log_min_duration_statement flag for every Cloud SQL\nPosgreSQL database instance using the below command:\ngcloud sql instances patch <INSTANCE_NAME> --database-flags\nlog_min_duration_statement=-1\nNote: This command will overwrite all database flags previously set. To keep those and\nadd new ones, include the values for all flags to be set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "By default log_min_duration_statement is -1.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/postgres/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: Some database flag settings can affect instance availability or stability and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\nNote: Configuring the above flag does not require restarting the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances describe <INSTANCE_NAME> --format=json| jq '.settings.databaseFlags[] | select(.name==\"log_min_duration_statement\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances list",
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/postgres/flags",
      "2. https://www.postgresql.org/docs/current/runtime-config-logging.html#GUC-LOG-",
      "MIN-DURATION-STATEMENT"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 236,
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
    "cis_id": "6.2.8",
    "title": "Ensure That 'cloudsql.enable_pgaudit' Database Flag for each Cloud Sql Postgresql Instance Is Set to 'on' For Centralized Logging",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Enable Detailed Logging",
    "description": "Ensure cloudsql.enable_pgaudit database flag for Cloud SQL PostgreSQL instance\nis set to on to allow for centralized logging.",
    "rationale": "As numerous other recommendations in this section consist of turning on flags for\nlogging purposes, your organization will need a way to manage these logs. You may\nhave a solution already in place. If you do not, consider installing and enabling the open\nsource pgaudit extension within PostgreSQL and enabling its corresponding flag of\ncloudsql.enable_pgaudit. This flag and installing the extension enables database\nauditing in PostgreSQL through the open-source pgAudit extension. This extension\nprovides detailed session and object logging to comply with government, financial, &\nISO standards and provides auditing capabilities to mitigate threats by monitoring\nsecurity events on the instance. Enabling the flag and settings later in this\nrecommendation will send these logs to Google Logs Explorer so that you can access\nthem in a central location. to This recommendation is applicable only to PostgreSQL\ndatabase instances.",
    "impact": "Enabling the pgAudit extension can lead to increased data storage requirements and to\nensure durability of pgAudit log records in the event of unexpected storage issues, it is\nrecommended to enable the Enable automatic storage increases setting on the\ninstance. Enabling flags via the command line will also overwrite all existing flags, so\nyou should apply all needed flags in the CLI command. Also flags may require a restart\nof the server to be implemented or will break existing functionality so update your\nservers at a time of low usage.",
    "audit": "Determining if the pgAudit Flag is set to 'on'\nFrom Google Cloud Console\n1. Go to https://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Overview page.\n3. Click Edit.\n4. Scroll down and expand Flags.\n5. Ensure that cloudsql.enable_pgaudit flag is set to on.\nFrom Google Cloud CLI\nRun the command by providing <INSTANCE_NAME>. Ensure the value of the flag is on.\ngcloud sql instances describe <INSTANCE_NAME> --format=\"json\" | jq\n'.settings|.|.databaseFlags[]|select(.name==\"cloudsql.enable_pgaudit\")|.value\n'\nDetermine if the pgAudit extension is installed\n1. Connect to the the server running PostgreSQL or through a SQL client of your\nchoice.\n2. Run the following command\nSELECT *\nFROM pg_extension;\n3. If pgAudit is in this list. If so, it is installed.\nDetermine if Data Access Audit logs are enabled for your project and have\nsufficient privileges\n1. From the homepage open the hamburger menu in the top left.\n2. Scroll down to IAM & Adminand hover over it.\n3. In the menu that opens up, select Audit Logs\n4. In the middle of the page, in the search box next to filter search for Cloud\nComposer API\n5. Select it, and ensure that both 'Admin Read' and 'Data Read' are checked.\nDetermine if logs are being sent to Logs Explorer\n1. From the Google Console home page, open the hamburger menu in the top left.\n2. In the menu that pops open, scroll down to Logs Explorer under Operations.\n3. In the query box, paste the following and search\nresource.type=\"cloudsql_database\"\nlogName=\"projects/<your-project-\nname>/logs/cloudaudit.googleapis.com%2Fdata_access\"\nprotoPayload.request.@type=\"type.googleapis.com/google.cloud.sql.audit.v1.PgA\nuditEntry\"\n4. If it returns any log sources, they are correctly setup.",
    "expected_response": "Determining if the pgAudit Flag is set to 'on'\n5. Ensure that cloudsql.enable_pgaudit flag is set to on.\nRun the command by providing <INSTANCE_NAME>. Ensure the value of the flag is on.\n5. Select it, and ensure that both 'Admin Read' and 'Data Read' are checked.\n4. If it returns any log sources, they are correctly setup.",
    "remediation": "Initialize the pgAudit flag\nFrom Google Cloud Console\n1. Go to https://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Overview page.\n3. Click Edit.\n4. Scroll down and expand Flags.\n5. To set a flag that has not been set on the instance before, click Add item.\n6. Enter cloudsql.enable_pgaudit for the flag name and set the flag to on.\n7. Click Done.\n8. Click Save to update the configuration.\n9. Confirm your changes under Flags on the Overview page.\nFrom Google Cloud CLI\nRun the below command by providing <INSTANCE_NAME> to enable\ncloudsql.enable_pgaudit flag.\ngcloud sql instances patch <INSTANCE_NAME> --database-flags\ncloudsql.enable_pgaudit=on\nNote: RESTART is required to get this configuration in effect.\nCreating the extension\n1. Connect to the the server running PostgreSQL or through a SQL client of your\nchoice.\n2. Run the following command as a superuser.\nCREATE EXTENSION pgaudit;\nUpdating the previously created pgaudit.log flag for your Logging Needs\nFrom Console:\nNote: there are multiple options here. This command will enable logging for all\ndatabases on a server. Please see the customizing database audit logging reference for\nmore flag options.\n1. Go to https://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Overview page.\n3. Click Edit.\n4. Scroll down and expand Flags.\n5. To set a flag that has not been set on the instance before, click Add item.\n6. Enter pgaudit.log=all for the flag name and set the flag to on.\n7. Click Done.\n8. Click Save to update the configuration.\n9. Confirm your changes under Flags on the Overview page.\nFrom Command Line:\nRun the command\ngcloud sql instances patch <INSTANCE_NAME> --database-flags \\\ncloudsql.enable_pgaudit=on,pgaudit.log=all\nDetermine if logs are being sent to Logs Explorer\n1. From the Google Console home page, open the hamburger menu in the top left.\n2. In the menu that pops open, scroll down to Logs Explorer under Operations.\n3. In the query box, paste the following and search\nresource.type=\"cloudsql_database\"\nlogName=\"projects/<your-project-\nname>/logs/cloudaudit.googleapis.com%2Fdata_access\"\nprotoPayload.request.@type=\"type.googleapis.com/google.cloud.sql.audit.v1.PgA\nuditEntry\"\nIf it returns any log sources, they are correctly setup.",
    "default_value": "By default cloudsql.enable_pgaudit database flag is set to off and the extension is\nnot enabled.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/postgres/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: Configuring the 'cloudsql.enable_pgaudit' database flag requires restarting the\nCloud SQL PostgreSQL instance.",
    "detection_commands": [
      "gcloud sql instances describe <INSTANCE_NAME> --format=\"json\" | jq '.settings|.|.databaseFlags[]|select(.name==\"cloudsql.enable_pgaudit\")|.value '",
      "SELECT *"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags",
      "CREATE EXTENSION pgaudit;"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/postgres/flags#list-flags-postgres",
      "2. https://cloud.google.com/sql/docs/postgres/pg-audit#enable-auditing-flag",
      "3. https://cloud.google.com/sql/docs/postgres/pg-audit#customizing-database-audit-",
      "logging",
      "4. https://cloud.google.com/logging/docs/audit/configure-data-access#config-",
      "console-enable"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 239,
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
    "cis_id": "6.3.1",
    "title": "Ensure 'external scripts enabled' Database Flag for Cloud SQL SQL Server Instance Is Set to 'off'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "SQL Server",
    "description": "It is recommended to set external scripts enabled database flag for Cloud SQL\nSQL Server instance to off",
    "rationale": "external scripts enabled enable the execution of scripts with certain remote\nlanguage extensions. This property is OFF by default. When Advanced Analytics\nServices is installed, setup can optionally set this property to true. As the External\nScripts Enabled feature allows scripts external to SQL such as files located in an R\nlibrary to be executed, which could adversely affect the security of the system, hence\nthis should be disabled. This recommendation is applicable to SQL Server database\ninstances.",
    "impact": "Setting custom flags via command line on certain instances will cause all omitted flags\nto be reset to defaults. This may cause you to lose custom flags and could result in\nunforeseen complications or instance restarts. Because of this, it is recommended you\napply these flags changes during a period of low usage.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page\n3. Ensure the database flag external scripts enabled that has been set is\nlisted under the Database flags section.\nFrom Google Cloud CLI\n1. Ensure the below command returns off for every Cloud SQL SQL Server\ndatabase instance\ngcloud sql instances describe <INSTANCE_NAME> --format=json | jq\n'.settings.databaseFlags[] | select(.name==\"external scripts\nenabled\")|.value'\nIn the output, database flags are listed under the settings as the collection\ndatabaseFlags.",
    "expected_response": "3. Ensure the database flag external scripts enabled that has been set is\n1. Ensure the below command returns off for every Cloud SQL SQL Server\nIn the output, database flags are listed under the settings as the collection",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the SQL Server instance for which you want to enable to database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add item,\nchoose the flag external scripts enabled from the drop-down menu, and set\nits value to off.\n6. Click Save to save your changes.\n7. Confirm your changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. Configure the external scripts enabled database flag for every Cloud SQL\nSQL Server database instance using the below command.\ngcloud sql instances patch <INSTANCE_NAME> --database-flags \"external scripts\nenabled\"=off\nNote:\nThis command will overwrite all database flags previously set. To keep those and add\nnew ones, include the values for all flags you want set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "By default external scripts enabled is off",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/sqlserver/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: some database flag settings can affect instance availability or stability, and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\"\nNote: Configuring the above flag restarts the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances describe <INSTANCE_NAME> --format=json | jq '.settings.databaseFlags[] | select(.name==\"external scripts"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags \"external scripts"
    ],
    "references": [
      "1. https://docs.microsoft.com/en-us/sql/database-engine/configure-",
      "windows/external-scripts-enabled-server-configuration-option?view=sql-server-",
      "ver15",
      "2. https://cloud.google.com/sql/docs/sqlserver/flags",
      "3. https://docs.microsoft.com/en-us/sql/advanced-",
      "analytics/concepts/security?view=sql-server-ver15",
      "4. https://www.stigviewer.com/stig/ms_sql_server_2016_instance/2018-03-",
      "09/finding/V-79347"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 245,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "6.3.2",
    "title": "Ensure 'cross db ownership chaining' Database Flag for Cloud SQL SQL Server Instance Is Set to 'off'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Implement Application Whitelisting of Scripts",
    "description": "It is recommended to set cross db ownership chaining database flag for Cloud SQL\nSQL Server instance to off.\nThis flag is deprecated for all SQL Server versions in CGP. Going forward, you can't set\nits value to on. However, if you have this flag enabled, we strongly recommend that you\neither remove the flag from your database or set it to off. For cross-database access,\nuse the Microsoft tutorial for signing stored procedures with a certificate.",
    "rationale": "Use the cross db ownership for chaining option to configure cross-database\nownership chaining for an instance of Microsoft SQL Server. This server option allows\nyou to control cross-database ownership chaining at the database level or to allow\ncross-database ownership chaining for all databases. Enabling cross db ownership is\nnot recommended unless all of the databases hosted by the instance of SQL Server\nmust participate in cross-database ownership chaining and you are aware of the\nsecurity implications of this setting. This recommendation is applicable to SQL Server\ndatabase instances.",
    "impact": "Updating flags may cause the database to restart. This may cause it to unavailable for a\nshort amount of time, so this is best done at a time of low usage. You should also\ndetermine if the tables in your databases reference another table without using\ncredentials for that database, as turning off cross database ownership will break this\nrelationship.",
    "audit": "NOTE: This flag is deprecated for all SQL Server versions. Going forward, you can't set\nits value to on. However, if you have this flag enabled it should be removed from your\ndatabase or set to off.\nFrom Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console.\n2. Select the instance to open its Instance Overview page\n3. Ensure the database flag cross db ownership chaining that has been set is\nlisted under the Database flags section.\nFrom Google Cloud CLI\n1. Ensure the below command returns off for every Cloud SQL SQL Server\ndatabase instance:\ngcloud sql instances describe <INSTANCE_NAME> --format=json | jq\n'.settings.databaseFlags[] | select(.name==\"cross db ownership\nchaining\")|.value'\nIn the output, database flags are listed under the settings as the collection\ndatabaseFlags.",
    "expected_response": "its value to on. However, if you have this flag enabled it should be removed from your\n3. Ensure the database flag cross db ownership chaining that has been set is\n1. Ensure the below command returns off for every Cloud SQL SQL Server\nIn the output, database flags are listed under the settings as the collection",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the SQL Server instance for which you want to enable to database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add item,\nchoose the flag cross db ownership chaining from the drop-down menu, and\nset its value to off.\n6. Click Save.\n7. Confirm the changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. Configure the cross db ownership chaining database flag for every Cloud\nSQL SQL Server database instance using the below command:\ngcloud sql instances patch <INSTANCE_NAME> --database-flags \"cross db\nownership chaining\"=off\nNote:\nThis command will overwrite all database flags previously set. To keep those and add\nnew ones, include the values for all flags to be set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "This flag is deprecated for all SQL Server versions. Going forward, you can't set its\nvalue to on.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/sqlserver/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: Some database flag settings can affect instance availability or stability, and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\nNote: Configuring the above flag does not restart the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances describe <INSTANCE_NAME> --format=json | jq '.settings.databaseFlags[] | select(.name==\"cross db ownership"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags \"cross db"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/sqlserver/flags",
      "2. https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/cross-",
      "db-ownership-chaining-server-configuration-option?view=sql-server-ver15"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 248,
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
    "cis_id": "6.3.3",
    "title": "Ensure 'user Connections' Database Flag for Cloud SQL SQL Server Instance Is Set to a Non-limiting Value",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "It is recommended to check the user connections for a Cloud SQL SQL Server\ninstance to ensure that it is not artificially limiting connections.",
    "rationale": "The user connections option specifies the maximum number of simultaneous user\nconnections that are allowed on an instance of SQL Server. The actual number of user\nconnections allowed also depends on the version of SQL Server that you are using, and\nalso the limits of your application or applications and hardware. SQL Server allows a\nmaximum of 32,767 user connections. Because user connections is by default a self-\nconfiguring value, with SQL Server adjusting the maximum number of user connections\nautomatically as needed, up to the maximum value allowable. For example, if only 10\nusers are logged in, 10 user connection objects are allocated. In most cases, you do not\nhave to change the value for this option. The default is 0, which means that the\nmaximum (32,767) user connections are allowed. However if there is a number defined\nhere that limits connections, SQL Server will not allow anymore above this limit. If the\nconnections are at the limit, any new requests will be dropped, potentially causing lost\ndata or outages for those using the database.",
    "impact": "Setting custom flags via command line on certain instances will cause all omitted flags\nto be reset to defaults. This may cause you to lose custom flags and could result in\nunforeseen complications or instance restarts. Because of this, it is recommended you\napply these flags changes during a period of low usage.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page\n3. Ensure the database flag user connections listed under the Database flags\nsection is 0.\nFrom Google Cloud CLI\n1. Ensure the below command returns a value of 0, for every Cloud SQL SQL\nServer database instance.\ngcloud sql instances describe <INSTANCE_NAME> --format=json | jq\n'.settings.databaseFlags[] | select(.name==\"user connections\")|.value'",
    "expected_response": "3. Ensure the database flag user connections listed under the Database flags\n1. Ensure the below command returns a value of 0, for every Cloud SQL SQL",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the SQL Server instance for which you want to enable to database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add item,\nchoose the flag user connections from the drop-down menu, and set its value\nto your organization recommended value.\n6. Click Save to save your changes.\n7. Confirm your changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. Configure the user connections database flag for every Cloud SQL SQL\nServer database instance using the below command.\ngcloud sql instances patch <INSTANCE_NAME> --database-flags \"user\nconnections=[0-32,767]\"\nNote:\nThis command will overwrite all database flags previously set. To keep those and add\nnew ones, include the values for all flags you want set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "By default user connections is set to '0' which does not limit the number of\nconnections, giving the server free reign to facilitate a max of 32,767 connections.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/sqlserver/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: some database flag settings can affect instance availability or stability, and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\nNote: Configuring the above flag restarts the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances describe <INSTANCE_NAME> --format=json | jq '.settings.databaseFlags[] | select(.name==\"user connections\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags \"user"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/sqlserver/flags",
      "2. https://docs.microsoft.com/en-us/sql/database-engine/configure-",
      "windows/configure-the-user-connections-server-configuration-option?view=sql-",
      "server-ver15",
      "3. https://www.stigviewer.com/stig/ms_sql_server_2016_instance/2018-03-",
      "09/finding/V-79119"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 251,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "6.3.4",
    "title": "Ensure 'user options' Database Flag for Cloud SQL SQL Server Instance Is Not Configured",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Establish Secure Configurations",
    "description": "The user options option specifies global defaults for all users. A list of default query\nprocessing options is established for the duration of a user's work session. The user\noptions option allows you to change the default values of the SET options (if the server's\ndefault settings are not appropriate).\nA user can override these defaults by using the SET statement. You can configure user\noptions dynamically for new logins. After you change the setting of user options, new\nlogin sessions use the new setting; current login sessions are not affected. This\nrecommendation is applicable to SQL Server database instances.",
    "rationale": "It is recommended that, user options database flag for Cloud SQL SQL Server\ninstance should not be configured.\nA user can override these defaults set with user options by using the SET statement.\nSome of these features/options could adversely affect the security of the system if\nenabled.",
    "impact": "Setting custom flags via command line on certain instances will cause all omitted flags\nto be reset to defaults. This may cause you to lose custom flags and could result in\nunforeseen complications or instance restarts. Because of this, it is recommended you\napply these flags changes during a period of low usage.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page\n3. Ensure the database flag user options that has been set is not listed under the\nDatabase flags section.\nFrom Google Cloud CLI\n1. Ensure the below command returns empty result for every Cloud SQL SQL\nServer database instance\ngcloud sql instances describe <INSTANCE_NAME> --format=json | jq\n'.settings.databaseFlags[] | select(.name==\"user options\")|.value'\nIn the output, database flags are listed under the settings as the collection\ndatabaseFlags.",
    "expected_response": "3. Ensure the database flag user options that has been set is not listed under the\n1. Ensure the below command returns empty result for every Cloud SQL SQL\nIn the output, database flags are listed under the settings as the collection",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the SQL Server instance for which you want to enable to database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. Click the X next user options flag shown\n6. Click Save to save your changes.\n7. Confirm your changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. List all Cloud SQL database Instances\ngcloud sql instances list\n2. Clear the user options database flag for every Cloud SQL SQL Server\ndatabase instance using either of the below commands.\nClearing all flags to their default value\ngcloud sql instances patch <INSTANCE_NAME> --clear-database-flags\nOR\nTo clear only user options database flag, configure the database flag by overriding\nthe user options. Exclude user options flag and its value, and keep all other flags\nyou want to configure.\ngcloud sql instances patch <INSTANCE_NAME> --database-flags\n[FLAG1=VALUE1,FLAG2=VALUE2]\nNote:\nThis command will overwrite all database flags previously set. To keep those and add\nnew ones, include the values for all flags you want set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "By default 'user options' is not configured.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/sqlserver/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: some database flag settings can affect instance availability or stability, and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\nNote: Configuring the above flag does not restart the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances describe <INSTANCE_NAME> --format=json | jq '.settings.databaseFlags[] | select(.name==\"user options\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances list",
      "gcloud sql instances patch <INSTANCE_NAME> --clear-database-flags",
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/sqlserver/flags",
      "2. https://docs.microsoft.com/en-us/sql/database-engine/configure-",
      "windows/configure-the-user-options-server-configuration-option?view=sql-server-",
      "ver15",
      "3. https://www.stigviewer.com/stig/ms_sql_server_2016_instance/2018-03-",
      "09/finding/V-79335"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 254,
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
    "cis_id": "6.3.5",
    "title": "Ensure 'remote access' Database Flag for Cloud SQL SQL Server Instance Is Set to 'off'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Establish Secure Configurations",
    "description": "It is recommended to set remote access database flag for Cloud SQL SQL Server\ninstance to off.",
    "rationale": "The remote access option controls the execution of stored procedures from local or\nremote servers on which instances of SQL Server are running. This default value for\nthis option is 1. This grants permission to run local stored procedures from remote\nservers or remote stored procedures from the local server. To prevent local stored\nprocedures from being run from a remote server or remote stored procedures from\nbeing run on the local server, this must be disabled. The Remote Access option controls\nthe execution of local stored procedures on remote servers or remote stored procedures\non local server. 'Remote access' functionality can be abused to launch a Denial-of-\nService (DoS) attack on remote servers by off-loading query processing to a target,\nhence this should be disabled. This recommendation is applicable to SQL Server\ndatabase instances.",
    "impact": "Setting custom flags via command line on certain instances will cause all omitted flags\nto be reset to defaults. This may cause you to lose custom flags and could result in\nunforeseen complications or instance restarts. Because of this, it is recommended you\napply these flags changes during a period of low usage.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page\n3. Ensure the database flag remote access that has been set is listed under the\nDatabase flags section.\nFrom Google Cloud CLI\n1. Ensure the below command returns off for every Cloud SQL SQL Server\ndatabase instance\ngcloud sql instances describe <INSTANCE_NAME> --format=json | jq\n'.settings.databaseFlags[] | select(.name==\"remote access\")|.value'\nIn the output, database flags are listed under the settings as the collection\ndatabaseFlags.",
    "expected_response": "3. Ensure the database flag remote access that has been set is listed under the\n1. Ensure the below command returns off for every Cloud SQL SQL Server\nIn the output, database flags are listed under the settings as the collection",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the SQL Server instance for which you want to enable to database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add item,\nchoose the flag remote access from the drop-down menu, and set its value to\noff.\n6. Click Save to save your changes.\n7. Confirm your changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. Configure the remote access database flag for every Cloud SQL SQL Server\ndatabase instance using the below command\ngcloud sql instances patch <INSTANCE_NAME> --database-flags \"remote\naccess\"=off\nNote:\nThis command will overwrite all database flags previously set. To keep those and add\nnew ones, include the values for all flags you want set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "By default 'remote access' is 'on'.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/sqlserver/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: some database flag settings can affect instance availability or stability, and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\nNote: Configuring the above flag restarts the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances describe <INSTANCE_NAME> --format=json | jq '.settings.databaseFlags[] | select(.name==\"remote access\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags \"remote"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/sqlserver/flags",
      "2. https://docs.microsoft.com/en-us/sql/database-engine/configure-",
      "windows/configure-the-remote-access-server-configuration-option?view=sql-",
      "server-ver15",
      "3. https://www.stigviewer.com/stig/ms_sql_server_2016_instance/2018-03-",
      "09/finding/V-79337"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 257,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "6.3.6",
    "title": "Ensure '3625 (trace flag)' Database Flag for all Cloud SQL SQL Server Instances Is Set to 'on'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Ensure Only Approved Ports, Protocols and Services",
    "description": "It is recommended to set 3625 (trace flag) database flag for Cloud SQL SQL Server\ninstance to on.",
    "rationale": "Microsoft SQL Trace Flags are frequently used to diagnose performance issues or to\ndebug stored procedures or complex computer systems, but they may also be\nrecommended by Microsoft Support to address behavior that is negatively impacting a\nspecific workload. All documented trace flags and those recommended by Microsoft\nSupport are fully supported in a production environment when used as directed.\n3625(trace log) Limits the amount of information returned to users who are not\nmembers of the sysadmin fixed server role, by masking the parameters of some error\nmessages using '******'. Setting this in a Google Cloud flag for the instance allows for\nsecurity through obscurity and prevents the disclosure of sensitive information, hence\nthis is recommended to set this flag globally to on to prevent the flag having been left\noff, or changed by bad actors. This recommendation is applicable to SQL Server\ndatabase instances.",
    "impact": "Changing flags on a database may cause it to be restarted. The best time to do this is at\na time where there is low usage.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page\n3. Ensure the database flag 3625 that has been set is listed under the Database\nflags section.\nFrom Google Cloud CLI\n1. Ensure the below command returns on for every Cloud SQL SQL Server\ndatabase instance\ngcloud sql instances describe <INSTANCE_NAME> --format=json | jq\n'.settings.databaseFlags[] | select(.name==\"3625\")|.value'",
    "expected_response": "3. Ensure the database flag 3625 that has been set is listed under the Database\n1. Ensure the below command returns on for every Cloud SQL SQL Server",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the SQL Server instance for which you want to enable to database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. To set a flag that has not been set on the instance before, click Add item,\nchoose the flag 3625 from the drop-down menu, and set its value to on.\n6. Click Save to save your changes.\n7. Confirm your changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. Configure the 3625 database flag for every Cloud SQL SQL Server database\ninstance using the below command.\ngcloud sql instances patch <INSTANCE_NAME> --database-flags \"3625=on\"\nNote:\nThis command will overwrite all database flags previously set. To keep those and add\nnew ones, include the values for all flags you want set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "default_value": "MS SQL Server implementations by default have trace flags, including the '3625' flag,\nturned off, as they are used for logging purposes.",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/sqlserver/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: some database flag settings can affect instance availability or stability, and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\nNote: Configuring the above flag restarts the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances describe <INSTANCE_NAME> --format=json | jq '.settings.databaseFlags[] | select(.name==\"3625\")|.value'"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags \"3625=on\""
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/sqlserver/flags",
      "2. https://docs.microsoft.com/en-us/sql/t-sql/database-console-commands/dbcc-",
      "traceon-trace-flags-transact-sql?view=sql-server-ver15#trace-flags",
      "3. https://github.com/ktaranov/sqlserver-",
      "kit/blob/master/SQL%20Server%20Trace%20Flag.md"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 260,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5"
    ]
  },
  {
    "cis_id": "6.3.7",
    "title": "Ensure 'contained database authentication' Database Flag for Cloud SQL SQL Server Instance Is Set to 'off'",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Establish Secure Configurations",
    "description": "A contained database includes all database settings and metadata required to define\nthe database and has no configuration dependencies on the instance of the Database\nEngine where the database is installed. Users can connect to the database without\nauthenticating a login at the Database Engine level. Isolating the database from the\nDatabase Engine makes it possible to easily move the database to another instance of\nSQL Server. Contained databases have some unique threats that should be understood\nand mitigated by SQL Server Database Engine administrators. Most of the threats are\nrelated to the USER WITH PASSWORD authentication process, which moves the\nauthentication boundary from the Database Engine level to the database level, hence\nthis is recommended not to enable this flag. This recommendation is applicable to SQL\nServer database instances.",
    "rationale": "When contained databases are enabled, database users with the ALTER ANY USER\npermission, such as members of the db_owner and db_accessadmin database roles,\ncan grant access to databases and by doing so, grant access to the instance of SQL\nServer. This means that control over access to the server is no longer limited to\nmembers of the sysadmin and securityadmin fixed server role, and logins with the\nserver level CONTROL SERVER and ALTER ANY LOGIN permission.\nIt is recommended to set contained database authentication database flag for\nCloud SQL on the SQL Server instance to off.",
    "impact": "When contained database authentication is off (0) for the instance, contained\ndatabases cannot be created, or attached to the Database Engine. Setting custom flags\nvia command line on certain instances will cause all omitted flags to be reset to defaults.\nThis may cause you to lose custom flags and could result in unforeseen complications\nor instance restarts. Because of this, it is recommended you apply these flags changes\nduring a period of low usage.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance to open its Instance Overview page\n3. Under the 'Database flags' section, if the database flag contained database\nauthentication is present, then ensure that it is set to 'off'.\nFrom Google Cloud CLI\n1. Ensure the below command returns off for any Cloud SQL for SQL Server\ndatabase instance.\ngcloud sql instances describe <INSTANCE_NAME> --format=json | jq\n'.settings.databaseFlags[] | select(.name==\"contained database\nauthentication\")|.value'",
    "expected_response": "authentication is present, then ensure that it is set to 'off'.\n1. Ensure the below command returns off for any Cloud SQL for SQL Server",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the SQL Server instance for which you want to enable to database flag.\n3. Click Edit.\n4. Scroll down to the Flags section.\n5. If the flag contained database authentication is present and its value is set\nto 'on', then change it to 'off'.\n6. Click Save.\n7. Confirm the changes under Flags on the Overview page.\nFrom Google Cloud CLI\n1. If any Cloud SQL for SQL Server instance has the database flag contained\ndatabase authentication set to 'on', then change it to 'off' using the below\ncommand:\ngcloud sql instances patch <INSTANCE_NAME> --database-flags \"contained\ndatabase authentication=off\"\nNote:\nThis command will overwrite all database flags previously set. To keep those and add\nnew ones, include the values for all flags to be set on the instance; any flag not\nspecifically included is set to its default value. For flags that do not take a value, specify\nthe flag name followed by an equals sign (\"=\").",
    "additional_information": "WARNING: This patch modifies database flag values, which may require your instance\nto be restarted. Check the list of supported flags -\nhttps://cloud.google.com/sql/docs/sqlserver/flags - to see if your instance will be\nrestarted when this patch is submitted.\nNote: Some database flag settings can affect instance availability or stability, and\nremove the instance from the Cloud SQL SLA. For information about these flags, see\nOperational Guidelines.\nNote: Configuring the above flag does not restart the Cloud SQL instance.",
    "detection_commands": [
      "gcloud sql instances describe <INSTANCE_NAME> --format=json | jq '.settings.databaseFlags[] | select(.name==\"contained database"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --database-flags \"contained"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/sqlserver/flags",
      "2. https://docs.microsoft.com/en-us/sql/database-engine/configure-",
      "windows/contained-database-authentication-server-configuration-",
      "option?view=sql-server-ver15",
      "3. https://docs.microsoft.com/en-us/sql/relational-databases/databases/security-",
      "best-practices-with-contained-databases?view=sql-server-ver15"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 263,
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
    "cis_id": "6.4",
    "title": "Ensure That the Cloud SQL Database Instance Requires All Incoming Connections To Use SSL",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "benchmarks_we_nevertheless_include_them_here_as_well_the_remediation",
    "domain": "Benchmarks. We, nevertheless, include them here as well, the remediation",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "It is recommended to enforce all incoming connections to SQL database instance to use\nSSL.",
    "rationale": "SQL database connections if successfully trapped (MITM); can reveal sensitive data like\ncredentials, database queries, query outputs etc. For security, it is recommended to\nalways use SSL encryption when connecting to your instance. This recommendation is\napplicable for Postgresql, MySql generation 1, MySql generation 2 and SQL Server\n2017 instances.",
    "impact": "After enforcing SSL requirement for connections, existing client will not be able to\ncommunicate with Cloud SQL database instance unless they use SSL encrypted\nconnections to communicate to Cloud SQL database instance.",
    "audit": "From Google Cloud Console\n1. Go to https://console.cloud.google.com/sql/instances.\n2. Click on an instance name to see its configuration overview.\n3. In the left-side panel, select Connections.\n4. In the Security section, ensure that Allow only SSL connections option is\nselected.\nFrom Google Cloud CLI\n1. Get the detailed configuration for every SQL database instance using the\nfollowing command:\ngcloud sql instances list --format=json\nEnsure that section settings: ipConfiguration has the parameter sslMode set to\nENCRYPTED_ONLY .",
    "expected_response": "4. In the Security section, ensure that Allow only SSL connections option is\nEnsure that section settings: ipConfiguration has the parameter sslMode set to",
    "remediation": "From Google Cloud Console\n1. Go to https://console.cloud.google.com/sql/instances.\n2. Click on an instance name to see its configuration overview.\n3. In the left-side panel, select Connections.\n4. In the security section, select SSL mode as Allow only SSL connections.\n5. Under Configure SSL server certificates click Create new certificate\nand save the setting\nFrom Google Cloud CLI\nTo enforce SSL encryption for an instance run the command:\ngcloud sql instances patch INSTANCE_NAME --ssl-mode= ENCRYPTED_ONLY\nNote:\nRESTART is required for type MySQL Generation 1 Instances (backendType:\nFIRST_GEN) to get this configuration in effect.",
    "default_value": "By default parameter settings: ipConfiguration: sslMode is not set which is\nequivalent to sslMode:ALLOW_UNENCRYPTED_AND_ENCRYPTED.",
    "additional_information": "By default Settings: ipConfiguration has no authorizedNetworks set/configured.\nIn that case even if by default sslMode is not set, which is equivalent to\nsslMode:ALLOW_UNENCRYPTED_AND_ENCRYPTED there is no risk as instance cannot be\naccessed outside of the network unless authorizedNetworks are configured.\nHowever, If default for sslMode is not updated to ENCRYPTED_ONLY any\nauthorizedNetworks created later on will not enforce SSL only connection.",
    "detection_commands": [
      "gcloud sql instances list --format=json"
    ],
    "remediation_commands": [
      "gcloud sql instances patch INSTANCE_NAME --ssl-mode= ENCRYPTED_ONLY"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/postgres/configure-ssl-instance/"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 266,
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
    "cis_id": "6.5",
    "title": "Ensure That Cloud SQL Database Instances Do Not Implicitly Whitelist All Public IP Addresses",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "instances",
    "domain": "instances",
    "subdomain": "Encrypt Transmittal of Username and",
    "description": "Database Server should accept connections only from trusted Network(s)/IP(s) and\nrestrict access from public IP addresses.",
    "rationale": "To minimize attack surface on a Database server instance, only trusted/known and\nrequired IP(s) should be white-listed to connect to it.\nAn authorized network should not have IPs/networks configured to 0.0.0.0/0 which\nwill allow access to the instance from anywhere in the world. Note that authorized\nnetworks apply only to instances with public IPs.",
    "impact": "The Cloud SQL database instance would not be available to public IP addresses.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Click the instance name to open its Instance details page.\n3. Under the Configuration section click Edit configurations\n4. Under Configuration options expand the Connectivity section.\n5. Ensure that no authorized network is configured to allow 0.0.0.0/0.\nFrom Google Cloud CLI\n1. Get detailed configuration for every Cloud SQL database instance.\ngcloud sql instances list --format=json\nEnsure that the section settings: ipConfiguration : authorizedNetworks does\nnot have any parameter value containing 0.0.0.0/0.",
    "expected_response": "5. Ensure that no authorized network is configured to allow 0.0.0.0/0.\nEnsure that the section settings: ipConfiguration : authorizedNetworks does",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Click the instance name to open its Instance details page.\n3. Under the Configuration section click Edit configurations\n4. Under Configuration options expand the Connectivity section.\n5. Click the delete icon for the authorized network 0.0.0.0/0.\n6. Click Save to update the instance.\nFrom Google Cloud CLI\nUpdate the authorized network list by dropping off any addresses.\ngcloud sql instances patch <INSTANCE_NAME> --authorized-\nnetworks=IP_ADDR1,IP_ADDR2...\nPrevention:\nTo prevent new SQL instances from being configured to accept incoming connections\nfrom any IP addresses, set up a Restrict Authorized Networks on Cloud SQL\ninstances Organization Policy at: https://console.cloud.google.com/iam-\nadmin/orgpolicies/sql-restrictAuthorizedNetworks.",
    "default_value": "By default, authorized networks are not configured. Remote connection to Cloud SQL\ndatabase instance is not possible unless authorized networks are configured.",
    "additional_information": "There is no IPv6 configuration found for Google cloud SQL server services.",
    "detection_commands": [
      "gcloud sql instances list --format=json"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --authorized-"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/mysql/configure-ip",
      "2. https://console.cloud.google.com/iam-admin/orgpolicies/sql-",
      "restrictAuthorizedNetworks",
      "3. https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-",
      "constraints",
      "4. https://cloud.google.com/sql/docs/mysql/connection-org-policy"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 269,
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
    "cis_id": "6.6",
    "title": "Ensure That Cloud SQL Database Instances Do Not Have Public IPs",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "medium",
    "service_area": "instances",
    "domain": "instances",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "It is recommended to configure Second Generation Sql instance to use private IPs\ninstead of public IPs.",
    "rationale": "To lower the organization's attack surface, Cloud SQL databases should not have public\nIPs. Private IPs provide improved network security and lower latency for your\napplication.",
    "impact": "Removing the public IP address on SQL instances may break some applications that\nrelied on it for database connectivity.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console:\nhttps://console.cloud.google.com/sql/instances\n2. Ensure that every instance has a private IP address and no public IP address\nconfigured.\nFrom Google Cloud CLI\n1. List all Cloud SQL database instances using the following command:\ngcloud sql instances list\n2. For every instance of type instanceType: CLOUD_SQL_INSTANCE with\nbackendType: SECOND_GEN, get detailed configuration. Ignore instances of type\nREAD_REPLICA_INSTANCE because these instances inherit their settings from the\nprimary instance. Also, note that first generation instances cannot be configured\nto have a private IP address.\ngcloud sql instances describe <INSTANCE_NAME>\n3. Ensure that the setting ipAddresses has an IP address configured of type:\nPRIVATE and has no IP address of type: PRIMARY. PRIMARY IP addresses are\npublic addresses. An instance can have both a private and public address at the\nsame time. Note also that you cannot use private IP with First Generation\ninstances.",
    "expected_response": "2. Ensure that every instance has a private IP address and no public IP address\n3. Ensure that the setting ipAddresses has an IP address configured of type:",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console:\nhttps://console.cloud.google.com/sql/instances\n2. Click the instance name to open its Instance details page.\n3. Select the Connections tab.\n4. Deselect the Public IP checkbox.\n5. Click Save to update the instance.\nFrom Google Cloud CLI\n1. For every instance remove its public IP and assign a private IP instead:\ngcloud sql instances patch <INSTANCE_NAME> --network=<VPC_NETWORK_NAME> --no-\nassign-ip\n2. Confirm the changes using the following command::\ngcloud sql instances describe <INSTANCE_NAME>\nPrevention:\nTo prevent new SQL instances from getting configured with public IP addresses, set up\na Restrict Public IP access on Cloud SQL instances Organization policy at:\nhttps://console.cloud.google.com/iam-admin/orgpolicies/sql-restrictPublicIp.",
    "default_value": "By default, Cloud Sql instances have a public IP.",
    "additional_information": "Replicas inherit their private IP status from their primary instance. You cannot configure\na private IP directly on a replica.",
    "detection_commands": [
      "gcloud sql instances list",
      "gcloud sql instances describe <INSTANCE_NAME>"
    ],
    "remediation_commands": [
      "gcloud sql instances patch <INSTANCE_NAME> --network=<VPC_NETWORK_NAME> --no-",
      "gcloud sql instances describe <INSTANCE_NAME>"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/mysql/configure-private-ip",
      "2. https://cloud.google.com/sql/docs/mysql/private-ip",
      "3. https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-",
      "constraints",
      "4. https://console.cloud.google.com/iam-admin/orgpolicies/sql-restrictPublicIp"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 272,
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
    "cis_id": "6.7",
    "title": "Ensure That Cloud SQL Database Instances Are Configured With Automated Backups",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "instances",
    "domain": "instances",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "It is recommended to have all SQL database instances set to enable automated\nbackups.",
    "rationale": "Backups provide a way to restore a Cloud SQL instance to recover lost data or recover\nfrom a problem with that instance. Automated backups need to be set for any instance\nthat contains data that should be protected from loss or damage. This recommendation\nis applicable for SQL Server, PostgreSql, MySql generation 1 and MySql generation 2\ninstances.",
    "impact": "Automated Backups will increase required size of storage and costs associated with it.",
    "audit": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Click the instance name to open its instance details page.\n3. Go to the Backups menu.\n4. Ensure that Automated backups is set to Enabled and Backup time is\nmentioned.\nFrom Google Cloud CLI\n1. List all Cloud SQL database instances using the following command:\ngcloud sql instances list --format=json | jq '. | map(select(.instanceType !=\n\"READ_REPLICA_INSTANCE\")) | .[].name'\nNOTE: gcloud command has been added with the filter to exclude read-replicas\ninstances, as GCP do not provide Automated Backups for read-replica instances.\n2. Ensure that the below command returns True for every Cloud SQL database\ninstance.\ngcloud sql instances describe <INSTANCE_NAME> --\nformat=\"value('Enabled':settings.backupConfiguration.enabled)\"",
    "expected_response": "4. Ensure that Automated backups is set to Enabled and Backup time is\n2. Ensure that the below command returns True for every Cloud SQL database",
    "remediation": "From Google Cloud Console\n1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting\nhttps://console.cloud.google.com/sql/instances.\n2. Select the instance where the backups need to be configured.\n3. Click Edit.\n4. In the Backups section, check `Enable automated backups', and choose a\nbackup window.\n5. Click Save.\nFrom Google Cloud CLI\n1. List all Cloud SQL database instances using the following command:\ngcloud sql instances list --format=json | jq '. | map(select(.instanceType !=\n\"READ_REPLICA_INSTANCE\")) | .[].name'\nNOTE: gcloud command has been added with the filter to exclude read-replicas\ninstances, as GCP do not provide Automated Backups for read-replica instances.\n2. Enable Automated backups for every Cloud SQL database instance using the\nbelow command:\ngcloud sql instances patch <INSTANCE_NAME> --backup-start-time <[HH:MM]>\nThe backup-start-time parameter is specified in 24-hour time, in the UTC±00 time\nzone, and specifies the start of a 4-hour backup window. Backups can start any time\nduring the backup window.",
    "default_value": "By default, automated backups are not configured for Cloud SQL instances.",
    "detection_commands": [
      "gcloud sql instances list --format=json | jq '. | map(select(.instanceType != \"READ_REPLICA_INSTANCE\")) | .[].name'",
      "gcloud sql instances describe <INSTANCE_NAME> --"
    ],
    "remediation_commands": [
      "gcloud sql instances list --format=json | jq '. | map(select(.instanceType != \"READ_REPLICA_INSTANCE\")) | .[].name'",
      "gcloud sql instances patch <INSTANCE_NAME> --backup-start-time <[HH:MM]>"
    ],
    "references": [
      "1. https://cloud.google.com/sql/docs/mysql/backup-recovery/backups",
      "2. https://cloud.google.com/sql/docs/postgres/backup-recovery/backups",
      "3. https://cloud.google.com/sql/docs/sqlserver/backup-recovery/backups",
      "4. https://cloud.google.com/sql/docs/mysql/backup-recovery/backing-up",
      "5. https://cloud.google.com/sql/docs/postgres/backup-recovery/backing-up",
      "6. https://cloud.google.com/sql/docs/sqlserver/backup-recovery/backing-up"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 275,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "backup"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D3",
      "D5"
    ]
  },
  {
    "cis_id": "7.1",
    "title": "Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible",
    "cis_level": "L1",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "critical",
    "service_area": "bigquery",
    "domain": "BigQuery",
    "description": "It is recommended that the IAM policy on BigQuery datasets does not allow anonymous\nand/or public access.",
    "rationale": "Granting permissions to allUsers or allAuthenticatedUsers allows anyone to\naccess the dataset. Such access might not be desirable if sensitive data is being stored\nin the dataset. Therefore, ensure that anonymous and/or public access to a dataset is\nnot allowed.",
    "impact": "The dataset is not publicly accessible. Explicit modification of IAM privileges would be\nnecessary to make them publicly accessible.",
    "audit": "From Google Cloud Console\n1. Go to BigQuery by visiting: https://console.cloud.google.com/bigquery.\n2. Select a dataset from Resources.\n3. Click SHARING near the right side of the window and select Permissions.\n4. Validate that none of the attached roles contain allUsers or\nallAuthenticatedUsers.\nFrom Google Cloud CLI\nList the name of all datasets.\nbq ls\nRetrieve each dataset details using the following command:\nbq show PROJECT_ID:DATASET_NAME\nEnsure that allUsers and allAuthenticatedUsers have not been granted access to\nthe dataset.",
    "expected_response": "Ensure that allUsers and allAuthenticatedUsers have not been granted access to",
    "remediation": "From Google Cloud Console\n1. Go to BigQuery by visiting: https://console.cloud.google.com/bigquery.\n2. Select the dataset from 'Resources'.\n3. Click SHARING near the right side of the window and select Permissions.\n4. Review each attached role.\n5. Click the delete icon for each member allUsers or allAuthenticatedUsers.\nOn the popup click Remove.\nFrom Google Cloud CLI\nList the name of all datasets.\nbq ls\nRetrieve the data set details:\nbq show --format=prettyjson PROJECT_ID:DATASET_NAME > PATH_TO_FILE\nIn the access section of the JSON file, update the dataset information to remove all\nroles containing allUsers or allAuthenticatedUsers.\nUpdate the dataset:\nbq update --source PATH_TO_FILE PROJECT_ID:DATASET_NAME\nPrevention:\nYou can prevent Bigquery dataset from becoming publicly accessible by setting up the\nDomain restricted sharing organization policy at:\nhttps://console.cloud.google.com/iam-admin/orgpolicies/iam-\nallowedPolicyMemberDomains .",
    "default_value": "By default, BigQuery datasets are not publicly accessible.",
    "detection_commands": [
      "bq ls",
      "bq show PROJECT_ID:DATASET_NAME"
    ],
    "remediation_commands": [
      "bq ls",
      "bq show --format=prettyjson PROJECT_ID:DATASET_NAME > PATH_TO_FILE",
      "bq update --source PATH_TO_FILE PROJECT_ID:DATASET_NAME"
    ],
    "references": [
      "1. https://cloud.google.com/bigquery/docs/dataset-access-controls"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 279,
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
    "cis_id": "7.2",
    "title": "Ensure That All BigQuery Tables Are Encrypted With Customer-Managed Encryption Key (CMEK)",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "bigquery",
    "domain": "BigQuery",
    "subdomain": "Protect Information through Access Control Lists",
    "description": "BigQuery by default encrypts the data as rest by employing Envelope Encryption\nusing Google managed cryptographic keys. The data is encrypted using the data\nencryption keys and data encryption keys themselves are further encrypted using\nkey encryption keys. This is seamless and do not require any additional input from\nthe user. However, if you want to have greater control, Customer-managed encryption\nkeys (CMEK) can be used as encryption key management solution for BigQuery Data\nSets. If CMEK is used, the CMEK is used to encrypt the data encryption keys instead of\nusing google-managed encryption keys.",
    "rationale": "BigQuery by default encrypts the data as rest by employing Envelope Encryption\nusing Google managed cryptographic keys. This is seamless and does not require any\nadditional input from the user.\nFor greater control over the encryption, customer-managed encryption keys (CMEK)\ncan be used as encryption key management solution for BigQuery tables. The CMEK is\nused to encrypt the data encryption keys instead of using google-managed encryption\nkeys. BigQuery stores the table and CMEK association and the encryption/decryption is\ndone automatically.\nApplying the Default Customer-managed keys on BigQuery data sets ensures that all\nthe new tables created in the future will be encrypted using CMEK but existing tables\nneed to be updated to use CMEK individually.\nNote: Google does not store your keys on its servers and cannot access your\nprotected data unless you provide the key. This also means that if you forget\nor lose your key, there is no way for Google to recover the key or to recover\nany data encrypted with the lost key.",
    "impact": "Using Customer-managed encryption keys (CMEK) will incur additional labor-hour\ninvestment to create, protect, and manage the keys.",
    "audit": "From Google Cloud Console\n1. Go to Analytics\n2. Go to BigQuery\n3. Under SQL Workspace, select the project\n4. Select Data Set, select the table\n5. Go to Details tab\n6. Under Table info, verify Customer-managed key is present.\n7. Repeat for each table in all data sets for all projects.\nFrom Google Cloud CLI\nList all dataset names\nbq ls\nUse the following command to view the table details. Verify the kmsKeyName is present.\nbq show <table_object>",
    "expected_response": "6. Under Table info, verify Customer-managed key is present.\nUse the following command to view the table details. Verify the kmsKeyName is present.",
    "remediation": "From Google Cloud CLI\nUse the following command to copy the data. The source and the destination needs to\nbe same in case copying to the original table.\nbq cp --destination_kms_key <customer_managed_key>\nsource_dataset.source_table destination_dataset.destination_table",
    "default_value": "Google Managed keys are used as key encryption keys.",
    "detection_commands": [
      "bq ls Use the following command to view the table details. Verify the kmsKeyName is present. bq show <table_object>"
    ],
    "remediation_commands": [
      "Use the following command to copy the data. The source and the destination needs to",
      "bq cp --destination_kms_key <customer_managed_key>"
    ],
    "references": [
      "1. https://cloud.google.com/bigquery/docs/customer-managed-encryption"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 281,
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
    "cis_id": "7.3",
    "title": "Ensure That a Default Customer-Managed Encryption Key (CMEK) Is Specified for All BigQuery Data Sets",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "bigquery",
    "domain": "BigQuery",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "BigQuery by default encrypts the data as rest by employing Envelope Encryption\nusing Google managed cryptographic keys. The data is encrypted using the data\nencryption keys and data encryption keys themselves are further encrypted using\nkey encryption keys. This is seamless and do not require any additional input from\nthe user. However, if you want to have greater control, Customer-managed encryption\nkeys (CMEK) can be used as encryption key management solution for BigQuery Data\nSets.",
    "rationale": "BigQuery by default encrypts the data as rest by employing Envelope Encryption\nusing Google managed cryptographic keys. This is seamless and does not require any\nadditional input from the user.\nFor greater control over the encryption, customer-managed encryption keys (CMEK)\ncan be used as encryption key management solution for BigQuery Data Sets. Setting a\nDefault Customer-managed encryption key (CMEK) for a data set ensure any tables\ncreated in future will use the specified CMEK if none other is provided.\nNote: Google does not store your keys on its servers and cannot access your\nprotected data unless you provide the key. This also means that if you forget\nor lose your key, there is no way for Google to recover the key or to recover\nany data encrypted with the lost key.",
    "impact": "Using Customer-managed encryption keys (CMEK) will incur additional labor-hour\ninvestment to create, protect, and manage the keys.",
    "audit": "From Google Cloud Console\n1. Go to Analytics\n2. Go to BigQuery\n3. Under Analysis click on SQL Workspaces, select the project\n4. Select Data Set\n5. Ensure Customer-managed key is present under Dataset info section.\n6. Repeat for each data set in all projects.\nFrom Google Cloud CLI\nList all dataset names\nbq ls\nUse the following command to view each dataset details.\nbq show <data_set_object>\nVerify the kmsKeyName is present.",
    "expected_response": "5. Ensure Customer-managed key is present under Dataset info section.\nVerify the kmsKeyName is present.",
    "remediation": "From Google Cloud CLI\nThe default CMEK for existing data sets can be updated by specifying the default key in\nthe EncryptionConfiguration.kmsKeyName field when calling the datasets.insert\nor datasets.patch methods",
    "default_value": "Google Managed keys are used as key encryption keys.",
    "detection_commands": [
      "bq ls Use the following command to view each dataset details. bq show <data_set_object>"
    ],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.google.com/bigquery/docs/customer-managed-encryption"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 283,
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
    "cis_id": "7.4",
    "title": "Ensure all data in BigQuery has been classified",
    "cis_level": "L2",
    "assessment_type": "manual",
    "automatable": false,
    "severity": "medium",
    "service_area": "bigquery",
    "domain": "BigQuery",
    "subdomain": "Encrypt Sensitive Information at Rest",
    "description": "BigQuery tables can contain sensitive data that for security purposes should be\ndiscovered, monitored, classified, and protected. Google Cloud's Sensitive Data\nProtection tools can automatically provide data classification of all BigQuery data across\nan organization.",
    "rationale": "Using a cloud service or 3rd party software to continuously monitor and automate the\nprocess of data discovery and classification for BigQuery tables is an important part of\nprotecting the data.\nSensitive Data Protection is a fully managed data protection and data privacy platform\nthat uses machine learning and pattern matching to discover and classify sensitive data\nin Google Cloud.",
    "impact": "There is a cost associated with using Sensitive Data Protection. There is also typically a\ncost associated with 3rd party tools that perform similar processes and protection.",
    "audit": "1. Go to Cloud DLP by visiting\nhttps://console.cloud.google.com/dlp/landing/dataProfiles/configurations.\n2. Verify there is a discovery scan configuration either for the organization or\nproject.",
    "remediation": "Enable profiling:\n1. Go to Cloud DLP by visiting\nhttps://console.cloud.google.com/dlp/landing/dataProfiles/configurations\n2. Click \"Create Configuration\"\n3. For projects follow https://cloud.google.com/dlp/docs/profile-project. For\norganizations or folders follow https://cloud.google.com/dlp/docs/profile-org-folder\nReview findings:\n• Columns or tables with high data risk have evidence of sensitive information\nwithout additional protections. To lower the data risk score, consider doing the\nfollowing:\n• For columns containing sensitive data, apply a BigQuery policy tag to restrict\naccess to accounts with specific access rights.\n• De-identify the raw sensitive data using de-identification techniques like masking\nand tokenization.\nIncorporate findings into your security and governance operations:\n• Enable sending findings into your security and posture services. You can publish\ndata profiles to Security Command Center and Chronicle.\n• Automate remediation or enable alerting of new or changed data risk with\nPub/Sub.",
    "detection_commands": [],
    "remediation_commands": [],
    "references": [
      "1. https://cloud.google.com/dlp/docs/data-profiles",
      "2. https://cloud.google.com/dlp/docs/analyze-data-profiles",
      "3. https://cloud.google.com/dlp/docs/data-profiles-remediation",
      "4. https://cloud.google.com/dlp/docs/send-profiles-to-scc",
      "5. https://cloud.google.com/dlp/docs/profile-org-folder#chronicle",
      "6. https://cloud.google.com/dlp/docs/profile-org-folder#publish-pubsub"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 285,
    "dspm_relevant": true,
    "dspm_categories": [
      "encryption",
      "classification"
    ],
    "rr_relevant": true,
    "rr_domains": [
      "D5",
      "D6"
    ]
  },
  {
    "cis_id": "8.1",
    "title": "Ensure that Dataproc Cluster is encrypted using Customer- Managed Encryption Key",
    "cis_level": "L2",
    "assessment_type": "automated",
    "automatable": true,
    "severity": "high",
    "service_area": "dataproc",
    "domain": "Dataproc",
    "description": "When you use Dataproc, cluster and job data is stored on Persistent Disks (PDs)\nassociated with the Compute Engine VMs in your cluster and in a Cloud Storage\nstaging bucket. This PD and bucket data is encrypted using a Google-generated data\nencryption key (DEK) and key encryption key (KEK). The CMEK feature allows you to\ncreate, use, and revoke the key encryption key (KEK). Google still controls the data\nencryption key (DEK).",
    "rationale": "\"Cloud services offer the ability to protect data related to those services using\nencryption keys managed by the customer within Cloud KMS. These encryption keys\nare called customer-managed encryption keys (CMEK). When you protect data in\nGoogle Cloud services with CMEK, the CMEK key is within your control.",
    "impact": "Using Customer Managed Keys involves additional overhead in maintenance by\nadministrators.",
    "audit": "From Google Cloud Console\n1. Login to the GCP Console and navigate to the Dataproc Cluster page by visiting\nhttps://console.cloud.google.com/dataproc/clusters.\n2. Select the project from the project dropdown list.\n3. On the Dataproc Clusters page, select the cluster and click on the Name\nattribute value that you want to examine.\n4. On the details page, select the Configurations tab.\n5. On the Configurations tab, check the Encryption type configuration attribute\nvalue. If the value is set to Google-managed key, then Dataproc Cluster is not\nencrypted with Customer managed encryption keys.\nRepeat step no. 3 - 5 for other Dataproc Clusters available in the selected project.\n6. Change the project from the project dropdown list and repeat the audit procedure\nfor other projects.\nFrom Google Cloud CLI\n1. Run clusters list command to list all the Dataproc Clusters available in the region:\ngcloud dataproc clusters list --region='us-central1'\n2. Run clusters describe command to get the key details of the selected cluster:\ngcloud dataproc clusters describe <cluster_name> --region=us-central1 --\nflatten=config.encryptionConfig.gcePdKmsKeyName\n3. If the above command output return \"null\", then the selected cluster is not\nencrypted with Customer managed encryption keys.\n4. Repeat step no. 2 and 3 for other Dataproc Clusters available in the selected\nregion. Change the region by updating --region and repeat step no. 2 for other\nclusters available in the project. Change the project by running the below\ncommand and repeat the audit procedure for other Dataproc clusters available in\nother projects:\ngcloud config set project <project_ID>\"",
    "expected_response": "value. If the value is set to Google-managed key, then Dataproc Cluster is not\n3. If the above command output return \"null\", then the selected cluster is not",
    "remediation": "From Google Cloud Console\n1. Login to the GCP Console and navigate to the Dataproc Cluster page by visiting\nhttps://console.cloud.google.com/dataproc/clusters.\n2. Select the project from the projects dropdown list.\n3. On the Dataproc Cluster page, click on the Create Cluster to create a new\ncluster with Customer managed encryption keys.\n4. On Create a cluster page, perform below steps:\n• Inside Set up cluster section perform below steps:\n-In the Name textbox, provide a name for your cluster.\no From Location select the location in which you want to deploy a cluster.\no Configure other configurations as per your requirements.\n• Inside Configure Nodes and Customize cluster section configure the settings\nas per your requirements.\n• Inside Manage security section, perform below steps:\no From Encryption, select Customer-managed key.\no Select a customer-managed key from dropdown list.\no Ensure that the selected KMS Key have Cloud KMS CryptoKey\nEncrypter/Decrypter role assign to Dataproc Cluster service account\n(\"serviceAccount:service-<project_number>@compute-\nsystem.iam.gserviceaccount.com\").\no Click on Create to create a cluster.\n• Once the cluster is created migrate all your workloads from the older cluster to\nthe new cluster and delete the old cluster by performing the below steps:\no On the Clusters page, select the old cluster and click on Delete\ncluster.\no On the Confirm deletion window, click on Confirm to delete the cluster.\no Repeat step above for other Dataproc clusters available in the selected\nproject.\n• Change the project from the project dropdown list and repeat the remediation\nprocedure for other Dataproc clusters available in other projects.\nFrom Google Cloud CLI\nBefore creating cluster ensure that the selected KMS Key have Cloud KMS CryptoKey\nEncrypter/Decrypter role assign to Dataproc Cluster service account\n(\"serviceAccount:service-<project_number>@compute-\nsystem.iam.gserviceaccount.com\").\nRun clusters create command to create new cluster with customer-managed key:\ngcloud dataproc clusters create <cluster_name> --region=us-central1 --gce-pd-\nkms-key=<key_resource_name>\nThe above command will create a new cluster in the selected region.\nOnce the cluster is created migrate all your workloads from the older cluster to the new\ncluster and Run clusters delete command to delete cluster:\ngcloud dataproc clusters delete <cluster_name> --region=us-central1\nRepeat step no. 1 to create a new Dataproc cluster.\nChange the project by running the below command and repeat the remediation\nprocedure for other projects:\ngcloud config set project <project_ID>\"",
    "detection_commands": [
      "gcloud dataproc clusters list --region='us-central1'",
      "gcloud dataproc clusters describe <cluster_name> --region=us-central1 --",
      "gcloud config set project <project_ID>\""
    ],
    "remediation_commands": [
      "gcloud dataproc clusters create <cluster_name> --region=us-central1 --gce-pd-",
      "gcloud dataproc clusters delete <cluster_name> --region=us-central1",
      "gcloud config set project <project_ID>\""
    ],
    "references": [
      "1. https://cloud.google.com/docs/security/encryption/default-encryption"
    ],
    "source_pdf": "CIS_Google_Cloud_Platform_Foundation_Benchmark_v4.0.0.pdf",
    "page": 288,
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
  }
]
""")


def get_gcp_cis_registry() -> list[dict]:
    """Return the complete CIS control registry as a list of dicts."""
    return GCP_CIS_CONTROLS


def get_gcp_control_count() -> int:
    """Return total number of CIS controls."""
    return len(GCP_CIS_CONTROLS)


def get_gcp_automated_count() -> int:
    """Return count of automated controls."""
    return sum(1 for c in GCP_CIS_CONTROLS if c["assessment_type"] == "automated")


def get_gcp_manual_count() -> int:
    """Return count of manual controls."""
    return sum(1 for c in GCP_CIS_CONTROLS if c["assessment_type"] == "manual")


def get_gcp_dspm_controls() -> list[dict]:
    """Return controls relevant to DSPM (Data Security Posture Management)."""
    return [c for c in GCP_CIS_CONTROLS if c.get("dspm_relevant")]


def get_gcp_rr_controls() -> list[dict]:
    """Return controls relevant to Ransomware Readiness."""
    return [c for c in GCP_CIS_CONTROLS if c.get("rr_relevant")]


def get_gcp_controls_by_service_area(service_area: str) -> list[dict]:
    """Return controls filtered by service area."""
    return [c for c in GCP_CIS_CONTROLS if c["service_area"] == service_area]


def get_gcp_controls_by_severity(severity: str) -> list[dict]:
    """Return controls filtered by severity."""
    return [c for c in GCP_CIS_CONTROLS if c["severity"] == severity]
