"""MITRE ATT&CK mapping for cloud security checks.

Maps security check results to MITRE ATT&CK Enterprise techniques, providing
threat context for findings across AWS, Azure, and GCP environments.
"""

# ---------------------------------------------------------------------------
# 1. MITRE_TECHNIQUES - Cloud-relevant Enterprise ATT&CK techniques
# ---------------------------------------------------------------------------
MITRE_TECHNIQUES: dict[str, dict] = {
    # -- Initial Access --
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts "
            "as a means of gaining Initial Access, Persistence, Privilege "
            "Escalation, or Defense Evasion. Compromised credentials may be "
            "used to bypass access controls placed on various resources."
        ),
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1078.004": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may obtain and abuse credentials of a cloud account "
            "as a means of gaining Initial Access, Persistence, Privilege "
            "Escalation, or Defense Evasion. Cloud accounts may be federated "
            "with on-premises identity providers or have unique credentials."
        ),
        "url": "https://attack.mitre.org/techniques/T1078/004/",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may attempt to exploit a weakness in an "
            "Internet-facing host or service using software, data, or "
            "commands in order to cause unintended or unanticipated behavior. "
            "Public-facing applications include websites, databases, and "
            "standard services such as SSH and SMB."
        ),
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1199": {
        "name": "Trusted Relationship",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may breach or otherwise leverage organizations who "
            "have access to intended victims. Access through trusted third "
            "party relationships abuses an existing connection that may not "
            "be protected or receives less scrutiny than standard mechanisms."
        ),
        "url": "https://attack.mitre.org/techniques/T1199/",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may send phishing messages to gain access to victim "
            "systems. All forms of phishing are electronically delivered "
            "social engineering. Phishing can be targeted (spearphishing) or "
            "non-targeted, and may involve attachments or malicious links."
        ),
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    # -- Execution --
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and script interpreters to execute "
            "commands, scripts, or binaries. These interfaces and languages "
            "provide ways of interacting with computer systems and are a "
            "common feature across many platforms."
        ),
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "description": (
            "An adversary may rely upon specific actions by a user in order "
            "to gain execution. Users may be subjected to social engineering "
            "to get them to execute malicious code, such as opening a "
            "malicious document or clicking a malicious link."
        ),
        "url": "https://attack.mitre.org/techniques/T1204/",
    },
    "T1648": {
        "name": "Serverless Execution",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse serverless computing, integration, and "
            "automation services to execute arbitrary code in cloud "
            "environments. Many cloud providers offer serverless solutions "
            "such as AWS Lambda, Azure Functions, and Google Cloud Functions."
        ),
        "url": "https://attack.mitre.org/techniques/T1648/",
    },
    # -- Persistence --
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": (
            "Adversaries may manipulate accounts to maintain and/or elevate "
            "access to victim systems. Account manipulation may consist of "
            "any action that preserves or modifies adversary access to a "
            "compromised account, such as modifying credentials or "
            "permission groups."
        ),
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "Persistence",
        "description": (
            "Adversaries may create an account to maintain access to victim "
            "systems. With a sufficient level of access, creating such "
            "accounts may be used to establish secondary credentialed access "
            "that do not require persistent remote access tools."
        ),
        "url": "https://attack.mitre.org/techniques/T1136/",
    },
    "T1136.003": {
        "name": "Create Account: Cloud Account",
        "tactic": "Persistence",
        "description": (
            "Adversaries may create a cloud account to maintain access to "
            "victim systems. With a sufficient level of access, such "
            "accounts may be used to establish secondary credentialed access "
            "that does not require persistent remote access tools."
        ),
        "url": "https://attack.mitre.org/techniques/T1136/003/",
    },
    "T1525": {
        "name": "Implant Internal Image",
        "tactic": "Persistence",
        "description": (
            "Adversaries may implant cloud or container images with "
            "malicious code to establish persistence after gaining access "
            "to an environment. Unlike Upload Malware, this technique "
            "focuses on adversaries implanting an image in a registry "
            "within a victim's environment."
        ),
        "url": "https://attack.mitre.org/techniques/T1525/",
    },
    "T1556": {
        "name": "Modify Authentication Process",
        "tactic": "Persistence",
        "description": (
            "Adversaries may modify authentication mechanisms and processes "
            "to access user credentials or enable otherwise unwarranted "
            "access to accounts. By compromising the MFA or password "
            "validation process an adversary can bypass access controls."
        ),
        "url": "https://attack.mitre.org/techniques/T1556/",
    },
    # -- Privilege Escalation --
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": (
            "Adversaries may circumvent mechanisms designed to control "
            "elevated privileges to gain higher-level permissions. Most "
            "modern systems contain native elevation control mechanisms "
            "that are intended to limit privileges that a user can perform."
        ),
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
    "T1484": {
        "name": "Domain or Tenant Policy Modification",
        "tactic": "Privilege Escalation",
        "description": (
            "Adversaries may modify the configuration settings of a domain "
            "or identity tenant to evade defenses and/or escalate "
            "privileges in domain or cloud environments. Domains and tenants "
            "provide a centralized means of managing access to resources."
        ),
        "url": "https://attack.mitre.org/techniques/T1484/",
    },
    # -- Defense Evasion --
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may maliciously modify components of a victim "
            "environment in order to hinder or disable defensive mechanisms. "
            "This includes disabling security tools, modifying firewall "
            "rules, and impairing log aggregation."
        ),
        "url": "https://attack.mitre.org/techniques/T1562/",
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may modify and/or disable security tools to avoid "
            "possible detection of their malware and activities. This can "
            "take many forms such as killing security software processes, "
            "modifying registry keys or configuration files, or other "
            "methods to interfere with security tools scanning or reporting."
        ),
        "url": "https://attack.mitre.org/techniques/T1562/001/",
    },
    "T1562.008": {
        "name": "Impair Defenses: Disable or Modify Cloud Logs",
        "tactic": "Defense Evasion",
        "description": (
            "An adversary may disable or modify cloud logging capabilities "
            "and integrations to limit what data is collected on their "
            "activities and avoid detection. Cloud environments allow for "
            "collection and analysis of audit and application logs."
        ),
        "url": "https://attack.mitre.org/techniques/T1562/008/",
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may delete or modify artifacts generated within "
            "systems to remove evidence of their presence or hinder "
            "defenses. Various artifacts may be created by an adversary or "
            "something that can be attributed to an adversary's actions."
        ),
        "url": "https://attack.mitre.org/techniques/T1070/",
    },
    "T1578": {
        "name": "Modify Cloud Compute Infrastructure",
        "tactic": "Defense Evasion",
        "description": (
            "An adversary may attempt to modify a cloud account's compute "
            "service infrastructure to evade defenses. A modification to "
            "the compute service infrastructure can include the creation, "
            "deletion, or modification of one or more components such as "
            "compute instances, virtual machines, and snapshots."
        ),
        "url": "https://attack.mitre.org/techniques/T1578/",
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may use alternate authentication material, such as "
            "password hashes, Kerberos tickets, and application access "
            "tokens, in order to move laterally within an environment and "
            "bypass normal system access controls."
        ),
        "url": "https://attack.mitre.org/techniques/T1550/",
    },
    # -- Credential Access --
    "T1528": {
        "name": "Steal Application Access Token",
        "tactic": "Credential Access",
        "description": (
            "Adversaries can steal application access tokens as a means of "
            "acquiring credentials to access remote systems and resources. "
            "Application access tokens are used to make authorized API "
            "requests on behalf of a user or service."
        ),
        "url": "https://attack.mitre.org/techniques/T1528/",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may search compromised systems to find and obtain "
            "insecurely stored credentials. These credentials can be stored "
            "and/or misplaced in many locations on a system, including "
            "plaintext files, environment variables, or cloud metadata APIs."
        ),
        "url": "https://attack.mitre.org/techniques/T1552/",
    },
    "T1552.005": {
        "name": "Unsecured Credentials: Cloud Instance Metadata API",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to access the Cloud Instance Metadata "
            "API to collect credentials and other sensitive data. Most cloud "
            "service providers support a Cloud Instance Metadata API that "
            "is accessible to instances running within the cloud environment."
        ),
        "url": "https://attack.mitre.org/techniques/T1552/005/",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain access to "
            "accounts when passwords are unknown or when password hashes "
            "are obtained. Without knowledge of the password for an account "
            "or a set of accounts, an adversary may systematically guess "
            "the password."
        ),
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1621": {
        "name": "Multi-Factor Authentication Request Generation",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to bypass multi-factor authentication "
            "(MFA) mechanisms and gain access to accounts by generating MFA "
            "requests sent to users. Adversaries in possession of "
            "credentials that are missing the MFA factor may attempt to "
            "cycle through MFA options to bypass MFA requirements."
        ),
        "url": "https://attack.mitre.org/techniques/T1621/",
    },
    # -- Discovery --
    "T1580": {
        "name": "Cloud Infrastructure Discovery",
        "tactic": "Discovery",
        "description": (
            "An adversary may attempt to discover infrastructure and "
            "resources that are available within an infrastructure-as-a-"
            "service (IaaS) environment. This includes compute service "
            "resources such as instances, virtual machines, and snapshots, "
            "as well as storage and database services."
        ),
        "url": "https://attack.mitre.org/techniques/T1580/",
    },
    "T1526": {
        "name": "Cloud Service Discovery",
        "tactic": "Discovery",
        "description": (
            "An adversary may attempt to enumerate the cloud services "
            "running on a system after gaining access. These methods can "
            "differ from platform-as-a-service (PaaS), infrastructure-as-a-"
            "service (IaaS), or software-as-a-service (SaaS)."
        ),
        "url": "https://attack.mitre.org/techniques/T1526/",
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to discover group and permission "
            "settings. This information can help adversaries determine "
            "which user accounts and groups are available, the membership "
            "of users in particular groups, and which users and groups "
            "have elevated permissions."
        ),
        "url": "https://attack.mitre.org/techniques/T1069/",
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of valid accounts, "
            "usernames, or email addresses on a system or within a "
            "compromised environment. This information can help adversaries "
            "determine which accounts exist which may aid in follow-on "
            "behavior."
        ),
        "url": "https://attack.mitre.org/techniques/T1087/",
    },
    # -- Lateral Movement --
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use valid accounts to log into a service "
            "specifically designed to accept remote connections, such as "
            "SSH, RDP, telnet, and VNC. The adversary may then perform "
            "actions as the logged-on user."
        ),
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    "T1021.004": {
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use valid accounts to log into remote machines "
            "using Secure Shell (SSH). The adversary may then perform "
            "actions as the logged-on user. SSH is a protocol that allows "
            "authorized users to open remote shells on other computers."
        ),
        "url": "https://attack.mitre.org/techniques/T1021/004/",
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use valid accounts to log into a computer "
            "using the Remote Desktop Protocol (RDP). The adversary may "
            "then perform actions as the logged-on user. RDP is a common "
            "feature of operating systems and allows a user to log into an "
            "interactive session with a system desktop graphical user "
            "interface on a remote system."
        ),
        "url": "https://attack.mitre.org/techniques/T1021/001/",
    },
    "T1563": {
        "name": "Remote Service Session Hijacking",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may take control of preexisting sessions with "
            "remote services to move laterally in an environment. Users "
            "may use valid credentials to log into a service specifically "
            "designed to accept remote connections."
        ),
        "url": "https://attack.mitre.org/techniques/T1563/",
    },
    # -- Collection --
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "description": (
            "Adversaries may access data from cloud storage. Many IaaS "
            "providers offer solutions for online data object storage such "
            "as Amazon S3, Azure Storage, and Google Cloud Storage. "
            "Adversaries can collect sensitive data from these sources."
        ),
        "url": "https://attack.mitre.org/techniques/T1530/",
    },
    "T1213": {
        "name": "Data from Information Repositories",
        "tactic": "Collection",
        "description": (
            "Adversaries may leverage information repositories to mine "
            "valuable information. Information repositories are tools that "
            "allow for storage of information, typically to facilitate "
            "collaboration or information sharing between users."
        ),
        "url": "https://attack.mitre.org/techniques/T1213/",
    },
    # -- Exfiltration --
    "T1537": {
        "name": "Transfer Data to Cloud Account",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may exfiltrate data by transferring the data, "
            "including backups of cloud environments, to another cloud "
            "account they control on the same service to avoid typical "
            "file transfers/downloads and network-based exfiltration "
            "detection."
        ),
        "url": "https://attack.mitre.org/techniques/T1537/",
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may use an existing, legitimate external Web "
            "service to exfiltrate data rather than their primary command "
            "and control channel. Popular Web services acting as an "
            "exfiltration mechanism may give a significant amount of cover."
        ),
        "url": "https://attack.mitre.org/techniques/T1567/",
    },
    # -- Impact --
    "T1485": {
        "name": "Data Destruction",
        "tactic": "Impact",
        "description": (
            "Adversaries may destroy data and files on specific systems or "
            "in large numbers on a network to interrupt availability to "
            "systems, services, and network resources. Data destruction is "
            "likely to render stored data irrecoverable by forensic "
            "techniques through overwriting files or data on local and "
            "remote drives."
        ),
        "url": "https://attack.mitre.org/techniques/T1485/",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": (
            "Adversaries may encrypt data on target systems or on large "
            "numbers of systems in a network to interrupt availability to "
            "system and network resources. They can attempt to render "
            "stored data inaccessible by encrypting files or data on local "
            "and remote drives and withholding access to a decryption key."
        ),
        "url": "https://attack.mitre.org/techniques/T1486/",
    },
    "T1496": {
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "description": (
            "Adversaries may leverage the resources of co-opted systems to "
            "complete resource-intensive tasks, which may impact system "
            "and/or hosted service availability. One common purpose for "
            "Resource Hijacking is to validate transactions of "
            "cryptocurrency networks and earn virtual currency."
        ),
        "url": "https://attack.mitre.org/techniques/T1496/",
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": (
            "Adversaries may perform Network Denial of Service (DoS) "
            "attacks to degrade or block the availability of targeted "
            "resources to users. Network DoS can be performed by "
            "exhausting the network bandwidth services rely on."
        ),
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
    "T1531": {
        "name": "Account Access Removal",
        "tactic": "Impact",
        "description": (
            "Adversaries may interrupt availability of system and network "
            "resources by inhibiting access to accounts utilized by "
            "legitimate users. Accounts may be deleted, locked, or "
            "manipulated (modified credentials) to remove access to "
            "accounts."
        ),
        "url": "https://attack.mitre.org/techniques/T1531/",
    },
}


# ---------------------------------------------------------------------------
# 2. CHECK_TO_MITRE - Maps check_ids to relevant MITRE technique IDs
# ---------------------------------------------------------------------------
CHECK_TO_MITRE: dict[str, list[str]] = {
    # -----------------------------------------------------------------------
    # AWS checks
    # -----------------------------------------------------------------------
    "iam_root_mfa_enabled": [
        "T1078", "T1078.004", "T1556", "T1621",
    ],
    "iam_password_policy_strong": [
        "T1110", "T1078", "T1078.004",
    ],
    "iam_password_policy_rotation": [
        "T1110", "T1078", "T1078.004",
    ],
    "iam_user_mfa_enabled": [
        "T1078", "T1078.004", "T1556", "T1621",
    ],
    "iam_access_key_rotation": [
        "T1528", "T1552", "T1078.004",
    ],
    "s3_bucket_public_access_blocked": [
        "T1530", "T1190", "T1537",
    ],
    "s3_bucket_encryption_enabled": [
        "T1530", "T1213",
    ],
    "s3_bucket_logging_enabled": [
        "T1562.008", "T1070",
    ],
    "s3_bucket_versioning_enabled": [
        "T1485", "T1486", "T1537",
    ],
    "ec2_sg_open_port_22": [
        "T1021.004", "T1190", "T1563",
    ],
    "ec2_sg_open_port_3389": [
        "T1021.001", "T1190", "T1563",
    ],
    "ec2_ebs_volume_encrypted": [
        "T1530", "T1213", "T1486",
    ],
    "ec2_imdsv2_required": [
        "T1552.005", "T1528", "T1078.004",
    ],
    "rds_encryption_enabled": [
        "T1530", "T1213", "T1486",
    ],
    "rds_public_access_disabled": [
        "T1190", "T1110", "T1530",
    ],
    "rds_multi_az_enabled": [
        "T1485", "T1498",
    ],
    "rds_backup_enabled": [
        "T1485", "T1486",
    ],
    "cloudtrail_multiregion": [
        "T1562.008", "T1070", "T1526",
    ],
    "cloudtrail_log_validation": [
        "T1070", "T1562.008",
    ],
    "cloudtrail_encrypted": [
        "T1530", "T1070",
    ],
    "kms_key_rotation_enabled": [
        "T1552", "T1486",
    ],
    "vpc_flow_logs_enabled": [
        "T1562.008", "T1070", "T1021",
    ],
    "guardduty_enabled": [
        "T1562.001", "T1562.008", "T1580",
    ],
    "config_recorder_enabled": [
        "T1562.001", "T1562.008", "T1578",
    ],
    "eks_cluster_logging": [
        "T1562.008", "T1070", "T1525",
    ],
    "eks_endpoint_public_access": [
        "T1190", "T1078.004", "T1525",
    ],
    "lambda_function_public_access": [
        "T1190", "T1648", "T1059",
    ],
    "ecs_task_definition_no_root": [
        "T1548", "T1525", "T1059",
    ],
    "sns_topic_encrypted": [
        "T1530", "T1213",
    ],
    "sqs_queue_encrypted": [
        "T1530", "T1213",
    ],
    "secretsmanager_rotation_enabled": [
        "T1552", "T1528", "T1078.004",
    ],
    "elasticsearch_encrypted_at_rest": [
        "T1530", "T1213", "T1486",
    ],
    "cloudwatch_log_group_retention": [
        "T1562.008", "T1070",
    ],
    "dynamodb_table_encrypted_kms": [
        "T1530", "T1213", "T1486",
    ],
    "dynamodb_pitr_enabled": [
        "T1485", "T1486",
    ],
    "efs_encryption_enabled": [
        "T1530", "T1213", "T1486",
    ],
    "elasticache_encryption_in_transit": [
        "T1530", "T1550",
    ],
    # -----------------------------------------------------------------------
    # Azure checks
    # -----------------------------------------------------------------------
    "azure_iam_owner_count": [
        "T1078.004", "T1098", "T1484",
    ],
    "azure_storage_https_only": [
        "T1530", "T1550",
    ],
    "azure_storage_tls_12": [
        "T1530", "T1550",
    ],
    "azure_storage_no_public_access": [
        "T1530", "T1190", "T1537",
    ],
    "azure_nsg_open_port_22": [
        "T1021.004", "T1190", "T1563",
    ],
    "azure_nsg_open_port_3389": [
        "T1021.001", "T1190", "T1563",
    ],
    "azure_network_watcher_enabled": [
        "T1562.008", "T1070", "T1021",
    ],
    "azure_vm_disk_encryption": [
        "T1530", "T1213", "T1486",
    ],
    "azure_sql_auditing_enabled": [
        "T1562.008", "T1070", "T1190",
    ],
    "azure_sql_tls_12": [
        "T1530", "T1550", "T1190",
    ],
    "azure_keyvault_soft_delete": [
        "T1485", "T1531",
    ],
    "azure_keyvault_purge_protection": [
        "T1485", "T1531",
    ],
    "azure_monitor_log_profile": [
        "T1562.008", "T1070",
    ],
    "azure_appservice_https_only": [
        "T1530", "T1550", "T1190",
    ],
    "azure_appservice_tls_12": [
        "T1530", "T1550", "T1190",
    ],
    # -----------------------------------------------------------------------
    # GCP checks
    # -----------------------------------------------------------------------
    "gcp_iam_no_public_access": [
        "T1078.004", "T1190", "T1098",
    ],
    "gcp_compute_no_external_ip": [
        "T1190", "T1021", "T1580",
    ],
    "gcp_compute_os_login": [
        "T1078.004", "T1136.003", "T1098",
    ],
    "gcp_storage_uniform_access": [
        "T1530", "T1098", "T1190",
    ],
    "gcp_sql_no_public_ip": [
        "T1190", "T1110", "T1530",
    ],
    "gcp_sql_ssl_required": [
        "T1530", "T1550", "T1190",
    ],
    "gcp_kms_key_rotation": [
        "T1552", "T1486",
    ],
    "gcp_gke_private_cluster": [
        "T1190", "T1525", "T1021",
    ],
    "gcp_gke_network_policy": [
        "T1021", "T1563", "T1525",
    ],
    "gcp_firewall_open_22": [
        "T1021.004", "T1190", "T1563",
    ],
    "gcp_firewall_open_3389": [
        "T1021.001", "T1190", "T1563",
    ],
}


# ---------------------------------------------------------------------------
# 3. CHECK_DESCRIPTIONS - Security-meaningful descriptions of FAIL results
# ---------------------------------------------------------------------------
CHECK_DESCRIPTIONS: dict[str, str] = {
    # -----------------------------------------------------------------------
    # AWS checks
    # -----------------------------------------------------------------------
    "iam_root_mfa_enabled": (
        "The AWS root account does not have multi-factor authentication "
        "enabled. An attacker who obtains the root credentials through "
        "phishing, credential stuffing, or a data breach can gain "
        "unrestricted access to every resource in the AWS account. Without "
        "MFA, there is no second factor to prevent unauthorized access even "
        "after credential compromise."
    ),
    "iam_password_policy_strong": (
        "The IAM password policy does not enforce sufficient complexity "
        "requirements such as minimum length, uppercase, lowercase, numeric, "
        "and symbol characters. Weak passwords are susceptible to brute-force "
        "and dictionary attacks, allowing adversaries to compromise IAM user "
        "accounts. A strong password policy is a fundamental control against "
        "credential-based attacks."
    ),
    "iam_password_policy_rotation": (
        "The IAM password policy does not enforce periodic password rotation "
        "within 90 days. Long-lived passwords increase the window of "
        "opportunity for attackers who have obtained credentials through any "
        "means, including past breaches or shoulder-surfing. Regular rotation "
        "limits the useful lifespan of compromised credentials."
    ),
    "iam_user_mfa_enabled": (
        "One or more IAM users do not have multi-factor authentication "
        "enabled. Compromised user credentials without MFA allow adversaries "
        "to authenticate directly to AWS services, move laterally, and "
        "escalate privileges. MFA provides a critical second factor that "
        "blocks credential-only attacks."
    ),
    "iam_access_key_rotation": (
        "One or more IAM access keys have not been rotated within 90 days. "
        "Static, long-lived access keys are a high-value target for "
        "adversaries because they provide programmatic access to AWS APIs. "
        "If keys are leaked through code repositories, logs, or compromised "
        "developer workstations, an attacker can use them indefinitely until "
        "they are rotated."
    ),
    "s3_bucket_public_access_blocked": (
        "An S3 bucket does not have all public access block settings enabled. "
        "Publicly accessible buckets can expose sensitive data, internal "
        "documents, database backups, and credentials to the internet. "
        "Adversaries routinely scan for open S3 buckets to harvest data for "
        "extortion, competitive intelligence, or further attacks."
    ),
    "s3_bucket_encryption_enabled": (
        "An S3 bucket does not have default server-side encryption enabled. "
        "Data stored without encryption is vulnerable to exposure if an "
        "attacker gains access to the underlying storage layer or if bucket "
        "objects are accidentally shared. Encryption at rest protects data "
        "confidentiality even when access controls are bypassed."
    ),
    "s3_bucket_logging_enabled": (
        "An S3 bucket does not have server access logging enabled. Without "
        "access logs, there is no audit trail to detect unauthorized data "
        "access, exfiltration attempts, or configuration changes. An "
        "adversary who accesses the bucket can operate undetected, and "
        "incident response teams lack the forensic data needed to scope a "
        "breach."
    ),
    "s3_bucket_versioning_enabled": (
        "An S3 bucket does not have versioning enabled. Without versioning, "
        "overwritten or deleted objects cannot be recovered. Adversaries who "
        "gain write access can permanently destroy or replace data, and "
        "ransomware-style attacks can render bucket contents unrecoverable."
    ),
    "ec2_sg_open_port_22": (
        "A security group allows unrestricted inbound SSH access (port 22) "
        "from 0.0.0.0/0. This exposes instances to brute-force attacks, "
        "exploitation of SSH vulnerabilities, and unauthorized remote access "
        "from any IP address on the internet. Adversaries can use this to "
        "establish an initial foothold and move laterally within the network."
    ),
    "ec2_sg_open_port_3389": (
        "A security group allows unrestricted inbound RDP access (port 3389) "
        "from 0.0.0.0/0. RDP is a frequent target for brute-force attacks "
        "and exploitation of vulnerabilities such as BlueKeep. Open RDP "
        "access enables adversaries to remotely control Windows instances, "
        "deploy ransomware, or establish persistent access."
    ),
    "ec2_ebs_volume_encrypted": (
        "An EBS volume is not encrypted. Unencrypted volumes expose data at "
        "rest to unauthorized access if snapshots are shared, the underlying "
        "hardware is compromised, or volumes are accessed through stolen "
        "credentials. Encryption is a critical defense-in-depth control for "
        "protecting sensitive data stored on compute infrastructure."
    ),
    "ec2_imdsv2_required": (
        "An EC2 instance does not require IMDSv2 (Instance Metadata Service "
        "version 2). IMDSv1 is vulnerable to Server-Side Request Forgery "
        "(SSRF) attacks that allow adversaries to steal the instance's IAM "
        "role credentials directly from the metadata endpoint. These stolen "
        "credentials can then be used to access other AWS services and "
        "escalate privileges."
    ),
    "rds_encryption_enabled": (
        "An RDS instance does not have storage encryption enabled. Database "
        "contents including application data, user records, and potentially "
        "sensitive PII are stored in plaintext. An attacker who gains access "
        "to snapshots, backups, or the underlying storage can read all data "
        "without additional barriers."
    ),
    "rds_public_access_disabled": (
        "An RDS instance is publicly accessible from the internet. This "
        "exposes the database to brute-force attacks on database "
        "credentials, exploitation of database engine vulnerabilities, and "
        "direct data exfiltration. Databases should only be reachable from "
        "trusted private network segments."
    ),
    "rds_multi_az_enabled": (
        "An RDS instance does not have Multi-AZ deployment enabled. Without "
        "a standby replica in a different Availability Zone, the database is "
        "vulnerable to outages from infrastructure failures, including those "
        "caused by denial-of-service attacks or destructive actions by a "
        "compromised account."
    ),
    "rds_backup_enabled": (
        "An RDS instance does not have automated backups enabled with "
        "sufficient retention. Without backups, data destroyed by "
        "ransomware, accidental deletion, or a malicious insider cannot be "
        "recovered. Backups are a critical control for resilience against "
        "data destruction attacks."
    ),
    "cloudtrail_multiregion": (
        "CloudTrail is not configured as a multi-region trail. API activity "
        "in regions without CloudTrail coverage goes unrecorded, providing "
        "adversaries a blind spot where they can provision resources, "
        "exfiltrate data, or establish persistence without generating audit "
        "logs."
    ),
    "cloudtrail_log_validation": (
        "CloudTrail log file validation is not enabled. Without digest files "
        "for integrity verification, an adversary who gains access to the "
        "log storage bucket can modify or delete log entries to cover their "
        "tracks. Log validation ensures tamper evidence through "
        "cryptographic hashing."
    ),
    "cloudtrail_encrypted": (
        "CloudTrail logs are not encrypted with a KMS key. Unencrypted logs "
        "stored in S3 can be accessed by anyone with bucket read permissions, "
        "potentially revealing sensitive API call details including "
        "resource names, IP addresses, and user identities used during an "
        "attack."
    ),
    "kms_key_rotation_enabled": (
        "A customer-managed KMS key does not have automatic rotation "
        "enabled. Without rotation, the same key material is used "
        "indefinitely, increasing the risk that it could be compromised "
        "through cryptanalysis or key material leakage. Regular rotation "
        "limits the blast radius of a compromised encryption key."
    ),
    "vpc_flow_logs_enabled": (
        "A VPC does not have flow logs enabled. Without network flow data, "
        "security teams cannot detect suspicious traffic patterns such as "
        "lateral movement, port scanning, data exfiltration, or "
        "communication with known malicious IP addresses. Flow logs are "
        "essential for network-level threat detection and incident response."
    ),
    "guardduty_enabled": (
        "Amazon GuardDuty is not enabled in this region. GuardDuty provides "
        "continuous threat detection by analyzing CloudTrail, VPC Flow Logs, "
        "and DNS logs for malicious activity. Without it, the environment "
        "lacks automated detection of reconnaissance, instance compromise, "
        "and account compromise indicators."
    ),
    "config_recorder_enabled": (
        "AWS Config recorder is not enabled in this region. Without Config, "
        "there is no continuous record of resource configuration changes. "
        "Adversaries can modify security groups, IAM policies, or other "
        "resource configurations without any change-tracking audit trail, "
        "making unauthorized modifications difficult to detect."
    ),
    "eks_cluster_logging": (
        "An EKS cluster does not have control plane logging enabled. Without "
        "API server, audit, authenticator, and controller manager logs, "
        "malicious activities within the Kubernetes cluster such as "
        "unauthorized pod deployments, privilege escalation, or container "
        "escapes go undetected."
    ),
    "eks_endpoint_public_access": (
        "An EKS cluster API endpoint is publicly accessible. This allows "
        "anyone on the internet to attempt authentication against the "
        "Kubernetes API server, enabling brute-force attacks on cluster "
        "credentials and exploitation of any API server vulnerabilities. "
        "Public endpoints significantly increase the cluster's attack "
        "surface."
    ),
    "lambda_function_public_access": (
        "A Lambda function's resource-based policy allows invocation from "
        "any AWS account or principal. This can permit adversaries to trigger "
        "function execution with crafted payloads, potentially leading to "
        "data exfiltration, code execution within the function's IAM role "
        "context, or abuse of the function as a pivot point into the "
        "internal network."
    ),
    "ecs_task_definition_no_root": (
        "An ECS task definition is configured to run containers as the root "
        "user. Running containers as root grants unnecessary privileges and "
        "increases the impact of container escape vulnerabilities. An "
        "attacker who exploits an application vulnerability can gain root "
        "access within the container and potentially break out to the "
        "host system."
    ),
    "sns_topic_encrypted": (
        "An SNS topic is not encrypted with a KMS key. Messages published "
        "to unencrypted topics, which may contain sensitive notifications, "
        "alerts, or application data, are stored in plaintext. An adversary "
        "with access to the topic can read message contents without needing "
        "to decrypt them."
    ),
    "sqs_queue_encrypted": (
        "An SQS queue is not encrypted. Messages in transit and at rest in "
        "the queue can contain sensitive application data, API payloads, or "
        "credentials. Without encryption, an adversary who gains access to "
        "the queue or its backing storage can read all message contents."
    ),
    "secretsmanager_rotation_enabled": (
        "A Secrets Manager secret does not have automatic rotation enabled. "
        "Static secrets that are never rotated remain valid indefinitely, "
        "giving adversaries an unlimited exploitation window if the secret "
        "is leaked. Automatic rotation limits the lifespan of compromised "
        "credentials and reduces the risk of long-term unauthorized access."
    ),
    "elasticsearch_encrypted_at_rest": (
        "An Elasticsearch/OpenSearch domain does not have encryption at rest "
        "enabled. The domain may contain indexed application logs, user "
        "data, and analytics records that are stored in plaintext. An "
        "adversary who accesses the underlying storage or snapshots can "
        "read all data without additional barriers."
    ),
    "cloudwatch_log_group_retention": (
        "A CloudWatch log group does not have a retention policy configured. "
        "Without retention limits, logs accumulate indefinitely, increasing "
        "storage costs. Conversely, if the default behavior is to retain "
        "forever, there is no lifecycle management, and if logs are deleted "
        "manually by an adversary, the lack of defined policy complicates "
        "compliance evidence collection."
    ),
    "dynamodb_table_encrypted_kms": (
        "A DynamoDB table is not encrypted with a customer-managed KMS key. "
        "While DynamoDB encrypts data with AWS-owned keys by default, "
        "customer-managed keys provide granular access control through key "
        "policies. Without a CMK, the organization cannot independently "
        "revoke access to the encrypted data or audit key usage."
    ),
    "dynamodb_pitr_enabled": (
        "A DynamoDB table does not have Point-in-Time Recovery enabled. "
        "Without PITR, accidental or malicious data deletion or corruption "
        "cannot be recovered beyond the standard backup window. Ransomware "
        "or destructive attacks against the table would result in permanent "
        "data loss."
    ),
    "efs_encryption_enabled": (
        "An EFS file system does not have encryption at rest enabled. Files "
        "stored on unencrypted EFS volumes are accessible in plaintext if "
        "the underlying storage is compromised or if mount targets are "
        "misconfigured. Encryption protects file contents even when network "
        "or IAM controls are bypassed."
    ),
    "elasticache_encryption_in_transit": (
        "An ElastiCache cluster does not have encryption in transit enabled. "
        "Data flowing between application servers and the cache, which may "
        "include session tokens, cached credentials, and sensitive "
        "application data, can be intercepted by an adversary with network "
        "access. Without TLS, all cache traffic is transmitted in plaintext."
    ),
    # -----------------------------------------------------------------------
    # Azure checks
    # -----------------------------------------------------------------------
    "azure_iam_owner_count": (
        "The Azure subscription has more than three accounts with the Owner "
        "role. An excessive number of owners increases the attack surface "
        "because each owner account becomes a high-value target for "
        "credential theft. Compromising any single owner account grants full "
        "control over all subscription resources."
    ),
    "azure_storage_https_only": (
        "An Azure Storage account does not enforce HTTPS-only access. When "
        "HTTP traffic is permitted, data in transit including storage "
        "account keys, SAS tokens, and blob contents can be intercepted by "
        "network-level adversaries through man-in-the-middle attacks."
    ),
    "azure_storage_tls_12": (
        "An Azure Storage account allows TLS versions older than 1.2. "
        "Older TLS versions (1.0 and 1.1) have known cryptographic "
        "weaknesses that can be exploited to decrypt traffic. Enforcing "
        "TLS 1.2 ensures that all client connections use modern, secure "
        "cipher suites."
    ),
    "azure_storage_no_public_access": (
        "An Azure Storage account allows public blob access. Publicly "
        "accessible blobs can expose sensitive data including database "
        "backups, application configurations, and user data to anyone on "
        "the internet. Adversaries actively scan for open storage accounts "
        "to harvest exposed data."
    ),
    "azure_nsg_open_port_22": (
        "A Network Security Group allows unrestricted inbound access on "
        "port 22 (SSH) from the internet. This exposes virtual machines to "
        "brute-force attacks and SSH exploitation attempts from any global "
        "IP address. Adversaries can use compromised SSH access to install "
        "malware, pivot to internal networks, or exfiltrate data."
    ),
    "azure_nsg_open_port_3389": (
        "A Network Security Group allows unrestricted inbound access on "
        "port 3389 (RDP) from the internet. RDP is one of the most "
        "commonly exploited remote access protocols, and open RDP exposure "
        "is a leading vector for ransomware deployment. Attackers use "
        "credential spraying and vulnerability exploits against exposed "
        "RDP endpoints."
    ),
    "azure_network_watcher_enabled": (
        "Azure Network Watcher is not enabled. Without Network Watcher, "
        "there is no capability to capture network packets, analyze NSG "
        "flow logs, or diagnose connectivity issues. This creates blind "
        "spots in network monitoring that adversaries can exploit to "
        "move laterally or exfiltrate data undetected."
    ),
    "azure_vm_disk_encryption": (
        "An Azure virtual machine does not have disk encryption enabled. "
        "Unencrypted VM disks expose operating system data, application "
        "data, and potentially cached credentials to unauthorized access "
        "through disk snapshots, shared images, or compromised storage "
        "accounts."
    ),
    "azure_sql_auditing_enabled": (
        "An Azure SQL Server does not have auditing enabled. Without "
        "auditing, database operations including data access, schema "
        "changes, and authentication failures are not logged. Adversaries "
        "can query, modify, or exfiltrate data without leaving an audit "
        "trail for detection or forensic analysis."
    ),
    "azure_sql_tls_12": (
        "An Azure SQL Server does not enforce TLS 1.2 as the minimum "
        "protocol version. Connections using TLS 1.0 or 1.1 are vulnerable "
        "to protocol downgrade attacks and known cryptographic weaknesses. "
        "Enforcing TLS 1.2 prevents interception of database traffic "
        "including queries and result sets."
    ),
    "azure_keyvault_soft_delete": (
        "An Azure Key Vault does not have soft delete enabled. Without "
        "soft delete, keys, secrets, and certificates that are deleted "
        "are permanently removed immediately. A malicious actor or "
        "compromised account can irreversibly destroy cryptographic keys, "
        "rendering encrypted data permanently inaccessible."
    ),
    "azure_keyvault_purge_protection": (
        "An Azure Key Vault does not have purge protection enabled. Even "
        "with soft delete, a privileged adversary can purge deleted items "
        "before the retention period expires. Purge protection ensures that "
        "deleted keys and secrets cannot be permanently removed during the "
        "retention window, providing a recovery safety net."
    ),
    "azure_monitor_log_profile": (
        "No Azure Monitor activity log profile is configured for the "
        "subscription. Without a log profile, administrative activity and "
        "security events are not exported to long-term storage. Adversaries "
        "can perform privileged actions, modify configurations, or delete "
        "resources without centralized log collection for detection."
    ),
    "azure_appservice_https_only": (
        "An Azure App Service does not enforce HTTPS-only access. When HTTP "
        "is permitted, web application traffic including authentication "
        "cookies, session tokens, and form data can be intercepted by "
        "network adversaries through man-in-the-middle attacks."
    ),
    "azure_appservice_tls_12": (
        "An Azure App Service does not enforce TLS 1.2 as the minimum "
        "protocol version. Older TLS versions have known vulnerabilities "
        "such as POODLE and BEAST that allow traffic decryption. Clients "
        "connecting with weak TLS versions expose sensitive web application "
        "data to interception."
    ),
    # -----------------------------------------------------------------------
    # GCP checks
    # -----------------------------------------------------------------------
    "gcp_iam_no_public_access": (
        "A GCP project IAM policy grants access to allUsers or "
        "allAuthenticatedUsers. This effectively makes project resources "
        "accessible to anyone on the internet or any Google-authenticated "
        "user. Adversaries do not need stolen credentials to access "
        "resources, making this one of the most critical misconfigurations."
    ),
    "gcp_compute_no_external_ip": (
        "A Compute Engine instance has an external IP address assigned. "
        "Instances with public IP addresses are directly exposed to "
        "internet-based attacks including port scanning, vulnerability "
        "exploitation, and brute-force attacks. External IPs should be "
        "avoided for instances that do not require direct internet access."
    ),
    "gcp_compute_os_login": (
        "A Compute Engine instance does not have OS Login enabled. Without "
        "OS Login, SSH keys are managed through instance or project metadata, "
        "making centralized access control and key revocation difficult. "
        "Adversaries who inject SSH keys through metadata can maintain "
        "persistent access that is hard to detect and revoke."
    ),
    "gcp_storage_uniform_access": (
        "A Cloud Storage bucket does not use uniform bucket-level access. "
        "When uniform access is not enabled, individual object ACLs can "
        "grant public or overly broad access that conflicts with bucket-"
        "level policies. This complexity increases the risk of accidental "
        "data exposure through misconfigured ACLs."
    ),
    "gcp_sql_no_public_ip": (
        "A Cloud SQL instance has a public IP address. This exposes the "
        "database directly to the internet, enabling brute-force attacks on "
        "database credentials and exploitation of database engine "
        "vulnerabilities. Database instances should use private IPs and be "
        "accessible only from authorized VPC networks."
    ),
    "gcp_sql_ssl_required": (
        "A Cloud SQL instance does not require SSL/TLS for connections. "
        "Without enforced SSL, database traffic including queries, result "
        "sets, and authentication credentials can be intercepted in "
        "plaintext. Network-level adversaries can capture sensitive data "
        "or perform man-in-the-middle attacks on database connections."
    ),
    "gcp_kms_key_rotation": (
        "A Cloud KMS key does not have automatic rotation configured within "
        "90 days. Without rotation, the same cryptographic key material is "
        "used indefinitely, increasing exposure if the key is compromised. "
        "Regular rotation limits the amount of data encrypted under any "
        "single key version."
    ),
    "gcp_gke_private_cluster": (
        "A GKE cluster does not use private nodes. Nodes with public IP "
        "addresses are exposed to internet-based attacks and increase the "
        "risk of container escape vulnerabilities being exploited remotely. "
        "Private clusters ensure that node traffic stays within the VPC "
        "network, reducing the attack surface."
    ),
    "gcp_gke_network_policy": (
        "A GKE cluster does not have network policy enforcement enabled. "
        "Without network policies, all pods can communicate with each other "
        "freely across namespaces. An adversary who compromises a single "
        "pod can pivot to any other pod in the cluster, access internal "
        "services, and exfiltrate data without network-level restrictions."
    ),
    "gcp_firewall_open_22": (
        "A VPC firewall rule allows unrestricted inbound access on port 22 "
        "(SSH) from 0.0.0.0/0. This exposes all instances in the target "
        "network to SSH brute-force attacks and exploitation of SSH "
        "vulnerabilities from any internet source. Adversaries use open SSH "
        "ports as an initial entry point for cloud infrastructure compromise."
    ),
    "gcp_firewall_open_3389": (
        "A VPC firewall rule allows unrestricted inbound access on port "
        "3389 (RDP) from 0.0.0.0/0. Open RDP is a primary attack vector "
        "for ransomware groups who use brute-force or purchased credentials "
        "to access Windows instances. Once inside, attackers deploy "
        "ransomware, steal data, or establish persistent backdoors."
    ),
}


# ---------------------------------------------------------------------------
# 4. CHECK_EVIDENCE - API call and logic description for each check
# ---------------------------------------------------------------------------
CHECK_EVIDENCE: dict[str, str] = {
    # -----------------------------------------------------------------------
    # AWS checks
    # -----------------------------------------------------------------------
    "iam_root_mfa_enabled": (
        "AWS IAM GetAccountSummary API. Checks if AccountMFAEnabled == 1 "
        "in the SummaryMap response."
    ),
    "iam_password_policy_strong": (
        "AWS IAM GetAccountPasswordPolicy API. Verifies that "
        "MinimumPasswordLength >= 14 and that RequireUppercaseCharacters, "
        "RequireLowercaseCharacters, RequireNumbers, and RequireSymbols are "
        "all True."
    ),
    "iam_password_policy_rotation": (
        "AWS IAM GetAccountPasswordPolicy API. Checks that MaxPasswordAge "
        "is set and is <= 90 days."
    ),
    "iam_user_mfa_enabled": (
        "AWS IAM ListUsers API followed by ListMFADevices for each user. "
        "Checks that at least one MFA device is associated with each IAM "
        "user."
    ),
    "iam_access_key_rotation": (
        "AWS IAM ListUsers API followed by ListAccessKeys for each user. "
        "Calculates the age of each active access key by comparing "
        "CreateDate to the current date. Fails if any key is older than "
        "90 days."
    ),
    "s3_bucket_public_access_blocked": (
        "AWS S3 ListBuckets API followed by GetPublicAccessBlock for each "
        "bucket. Verifies that all four settings (BlockPublicAcls, "
        "IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) are "
        "set to True."
    ),
    "s3_bucket_encryption_enabled": (
        "AWS S3 ListBuckets API followed by GetBucketEncryption for each "
        "bucket. Checks that a ServerSideEncryptionConfiguration is present. "
        "A ClientError (ServerSideEncryptionConfigurationNotFoundError) "
        "indicates encryption is not configured."
    ),
    "s3_bucket_logging_enabled": (
        "AWS S3 ListBuckets API followed by GetBucketLogging for each "
        "bucket. Checks that the LoggingEnabled key is present in the "
        "response."
    ),
    "s3_bucket_versioning_enabled": (
        "AWS S3 ListBuckets API followed by GetBucketVersioning for each "
        "bucket. Checks that Status == 'Enabled' in the versioning "
        "configuration."
    ),
    "ec2_sg_open_port_22": (
        "AWS EC2 DescribeSecurityGroups API. Iterates through "
        "IpPermissions and checks for IpRanges containing CidrIp "
        "0.0.0.0/0 where FromPort is 22."
    ),
    "ec2_sg_open_port_3389": (
        "AWS EC2 DescribeSecurityGroups API. Iterates through "
        "IpPermissions and checks for IpRanges containing CidrIp "
        "0.0.0.0/0 where FromPort is 3389."
    ),
    "ec2_ebs_volume_encrypted": (
        "AWS EC2 DescribeVolumes API. Checks the Encrypted field for each "
        "EBS volume. Fails if Encrypted is False."
    ),
    "ec2_imdsv2_required": (
        "AWS EC2 DescribeInstances API. Inspects the MetadataOptions "
        "object for each instance and checks that HttpTokens == 'required' "
        "(meaning IMDSv2 is enforced)."
    ),
    "rds_encryption_enabled": (
        "AWS RDS DescribeDBInstances API. Checks the StorageEncrypted "
        "field for each RDS instance. Fails if StorageEncrypted is False."
    ),
    "rds_public_access_disabled": (
        "AWS RDS DescribeDBInstances API. Checks the PubliclyAccessible "
        "field for each RDS instance. Fails if PubliclyAccessible is True."
    ),
    "rds_multi_az_enabled": (
        "AWS RDS DescribeDBInstances API. Checks the MultiAZ field for "
        "each RDS instance. Fails if MultiAZ is False."
    ),
    "rds_backup_enabled": (
        "AWS RDS DescribeDBInstances API. Checks BackupRetentionPeriod "
        "for each instance. Fails if the retention period is less than "
        "7 days."
    ),
    "cloudtrail_multiregion": (
        "AWS CloudTrail DescribeTrails API. Checks the "
        "IsMultiRegionTrail field for each trail. Fails if no trail has "
        "multi-region enabled."
    ),
    "cloudtrail_log_validation": (
        "AWS CloudTrail DescribeTrails API. Checks the "
        "LogFileValidationEnabled field for each trail. Fails if log file "
        "validation is not enabled."
    ),
    "cloudtrail_encrypted": (
        "AWS CloudTrail DescribeTrails API. Checks whether the KmsKeyId "
        "field is set for each trail. Fails if KmsKeyId is None, meaning "
        "logs are not encrypted with a customer-managed KMS key."
    ),
    "kms_key_rotation_enabled": (
        "AWS KMS ListKeys API followed by DescribeKey and "
        "GetKeyRotationStatus for each customer-managed key. Checks that "
        "KeyRotationEnabled is True."
    ),
    "vpc_flow_logs_enabled": (
        "AWS EC2 DescribeVpcs API followed by DescribeFlowLogs filtered by "
        "resource-id for each VPC. Fails if no flow logs are associated "
        "with the VPC."
    ),
    "guardduty_enabled": (
        "AWS GuardDuty ListDetectors API. Checks that at least one "
        "detector ID exists in the response. An empty DetectorIds list "
        "indicates GuardDuty is not enabled."
    ),
    "config_recorder_enabled": (
        "AWS Config DescribeConfigurationRecorders API. Checks that at "
        "least one configuration recorder exists in the response."
    ),
    "eks_cluster_logging": (
        "AWS EKS ListClusters API followed by DescribeCluster for each "
        "cluster. Inspects the logging.clusterLogging array and checks "
        "that the 'api' log type has enabled == True."
    ),
    "eks_endpoint_public_access": (
        "AWS EKS ListClusters API followed by DescribeCluster for each "
        "cluster. Checks resourcesVpcConfig.endpointPublicAccess. Fails if "
        "endpointPublicAccess is True."
    ),
    "lambda_function_public_access": (
        "AWS Lambda ListFunctions API followed by GetPolicy for each "
        "function. Parses the resource-based policy and checks for "
        "principals set to '*' or conditions that allow cross-account "
        "invocation without restrictions."
    ),
    "ecs_task_definition_no_root": (
        "AWS ECS ListTaskDefinitions API followed by DescribeTaskDefinition "
        "for each active task definition. Inspects containerDefinitions and "
        "checks that the 'user' field is not set to 'root' or '0', and "
        "that the privileged flag is not set to True."
    ),
    "sns_topic_encrypted": (
        "AWS SNS ListTopics API followed by GetTopicAttributes for each "
        "topic. Checks that the KmsMasterKeyId attribute is set."
    ),
    "sqs_queue_encrypted": (
        "AWS SQS ListQueues API followed by GetQueueAttributes for each "
        "queue. Checks that KmsMasterKeyId is set or "
        "SqsManagedSseEnabled == 'true'."
    ),
    "secretsmanager_rotation_enabled": (
        "AWS SecretsManager ListSecrets API. Checks the RotationEnabled "
        "field for each secret in the SecretList response. Fails if "
        "RotationEnabled is False."
    ),
    "elasticsearch_encrypted_at_rest": (
        "AWS Elasticsearch ListDomainNames API followed by "
        "DescribeElasticsearchDomain for each domain. Checks "
        "EncryptionAtRestOptions.Enabled. Fails if Enabled is False."
    ),
    "cloudwatch_log_group_retention": (
        "AWS CloudWatch Logs DescribeLogGroups API. Checks the "
        "retentionInDays field for each log group. Fails if "
        "retentionInDays is not set (None), meaning logs are retained "
        "indefinitely without a defined policy."
    ),
    "dynamodb_table_encrypted_kms": (
        "AWS DynamoDB ListTables API followed by DescribeTable for each "
        "table. Checks SSEDescription.Status == 'ENABLED' to verify "
        "customer-managed KMS encryption is active."
    ),
    "dynamodb_pitr_enabled": (
        "AWS DynamoDB ListTables API followed by "
        "DescribeContinuousBackups for each table. Checks "
        "PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == "
        "'ENABLED'."
    ),
    "efs_encryption_enabled": (
        "AWS EFS DescribeFileSystems API. Checks the Encrypted field for "
        "each file system. Fails if Encrypted is False."
    ),
    "elasticache_encryption_in_transit": (
        "AWS ElastiCache DescribeCacheClusters API. Checks the "
        "TransitEncryptionEnabled field for each cluster. Fails if "
        "TransitEncryptionEnabled is False."
    ),
    # -----------------------------------------------------------------------
    # Azure checks
    # -----------------------------------------------------------------------
    "azure_iam_owner_count": (
        "Azure Authorization RoleAssignments.List API. Counts the number "
        "of role assignments where the role definition ID contains 'Owner'. "
        "Fails if the owner count exceeds 3."
    ),
    "azure_storage_https_only": (
        "Azure Storage StorageAccounts.List API. Checks the "
        "enableHttpsTrafficOnly property for each storage account. Fails "
        "if the property is False."
    ),
    "azure_storage_tls_12": (
        "Azure Storage StorageAccounts.List API. Checks the "
        "minimumTlsVersion property for each storage account. Fails if "
        "the value is not 'TLS1_2'."
    ),
    "azure_storage_no_public_access": (
        "Azure Storage StorageAccounts.List API. Checks the "
        "allowBlobPublicAccess property for each storage account. Fails "
        "if the property is True."
    ),
    "azure_nsg_open_port_22": (
        "Azure Network NetworkSecurityGroups.ListAll API. Iterates through "
        "security rules for each NSG and checks for inbound Allow rules "
        "where sourceAddressPrefix is *, 0.0.0.0/0, or Internet and "
        "destinationPortRange includes 22."
    ),
    "azure_nsg_open_port_3389": (
        "Azure Network NetworkSecurityGroups.ListAll API. Iterates through "
        "security rules for each NSG and checks for inbound Allow rules "
        "where sourceAddressPrefix is *, 0.0.0.0/0, or Internet and "
        "destinationPortRange includes 3389."
    ),
    "azure_network_watcher_enabled": (
        "Azure Network NetworkWatchers.ListAll API. Checks that at least "
        "one Network Watcher instance exists. An empty list indicates "
        "Network Watcher is not enabled."
    ),
    "azure_vm_disk_encryption": (
        "Azure Compute VirtualMachines.ListAll API. For each VM, inspects "
        "storageProfile.osDisk.managedDisk.diskEncryptionSet. Fails if "
        "the disk encryption set reference is not configured."
    ),
    "azure_sql_auditing_enabled": (
        "Azure SQL Servers.List API followed by "
        "ServerBlobAuditingPolicies.Get for each server. Checks that "
        "the auditing state is 'Enabled'."
    ),
    "azure_sql_tls_12": (
        "Azure SQL Servers.List API. Checks the minimalTlsVersion "
        "property for each SQL Server. Fails if the value is not '1.2'."
    ),
    "azure_keyvault_soft_delete": (
        "Azure Key Vault Vaults.List API. Checks the "
        "properties.enableSoftDelete field for each vault. Fails if "
        "soft delete is not enabled."
    ),
    "azure_keyvault_purge_protection": (
        "Azure Key Vault Vaults.List API. Checks the "
        "properties.enablePurgeProtection field for each vault. Fails if "
        "purge protection is not enabled."
    ),
    "azure_monitor_log_profile": (
        "Azure Monitor LogProfiles.List API. Checks that at least one "
        "activity log profile exists for the subscription. An empty list "
        "indicates no log profile is configured."
    ),
    "azure_appservice_https_only": (
        "Azure Web WebApps.List API. Checks the httpsOnly property for "
        "each App Service. Fails if httpsOnly is False."
    ),
    "azure_appservice_tls_12": (
        "Azure Web WebApps.List API. Inspects siteConfig.minTlsVersion "
        "for each App Service. Fails if the value is not '1.2'."
    ),
    # -----------------------------------------------------------------------
    # GCP checks
    # -----------------------------------------------------------------------
    "gcp_iam_no_public_access": (
        "GCP Resource Manager Projects.GetIamPolicy API. Iterates through "
        "all IAM bindings and checks if any member is 'allUsers' or "
        "'allAuthenticatedUsers'."
    ),
    "gcp_compute_no_external_ip": (
        "GCP Compute Instances.AggregatedList API. For each instance, "
        "inspects networkInterfaces[].accessConfigs[].natIP. Fails if any "
        "access config has a NAT IP assigned (indicating an external IP)."
    ),
    "gcp_compute_os_login": (
        "GCP Compute Instances.AggregatedList API. Checks instance "
        "metadata items for the key 'enable-oslogin' with value 'true'. "
        "Fails if OS Login is not enabled."
    ),
    "gcp_storage_uniform_access": (
        "GCP Cloud Storage Buckets.List API. Checks the "
        "iamConfiguration.uniformBucketLevelAccess.enabled property for "
        "each bucket. Fails if uniform access is not enabled."
    ),
    "gcp_sql_no_public_ip": (
        "GCP Cloud SQL Instances.List API. Checks "
        "settings.ipConfiguration.ipv4Enabled for each instance. Fails if "
        "ipv4Enabled is True, indicating a public IP is assigned."
    ),
    "gcp_sql_ssl_required": (
        "GCP Cloud SQL Instances.List API. Checks "
        "settings.ipConfiguration.requireSsl for each instance. Fails if "
        "requireSsl is not True."
    ),
    "gcp_kms_key_rotation": (
        "GCP Cloud KMS ListKeyRings and ListCryptoKeys APIs. Checks the "
        "rotationPeriod for each key. Fails if the rotation period exceeds "
        "90 days (7,776,000 seconds) or is not set."
    ),
    "gcp_gke_private_cluster": (
        "GCP GKE Clusters.List API. Checks "
        "privateClusterConfig.enablePrivateNodes for each cluster. Fails "
        "if private nodes are not enabled."
    ),
    "gcp_gke_network_policy": (
        "GCP GKE Clusters.List API. Checks networkPolicy.enabled for each "
        "cluster. Fails if network policy enforcement is not enabled."
    ),
    "gcp_firewall_open_22": (
        "GCP Compute Firewalls.List API. Iterates through ingress firewall "
        "rules and checks for rules where sourceRanges includes 0.0.0.0/0 "
        "and allowed[].ports includes port 22."
    ),
    "gcp_firewall_open_3389": (
        "GCP Compute Firewalls.List API. Iterates through ingress firewall "
        "rules and checks for rules where sourceRanges includes 0.0.0.0/0 "
        "and allowed[].ports includes port 3389."
    ),
}
