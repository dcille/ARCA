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
    "T1610": {
        "name": "Deploy Container",
        "tactic": "Execution",
        "description": (
            "Adversaries may deploy containers to execute malicious code, "
            "evade defenses, or facilitate persistence. In cloud "
            "environments, attackers can deploy rogue containers in "
            "Kubernetes clusters, ECS, GKE, OKE, or ACK to run crypto "
            "miners, backdoors, or lateral movement tools."
        ),
        "url": "https://attack.mitre.org/techniques/T1610/",
    },
    "T1611": {
        "name": "Escape to Host",
        "tactic": "Privilege Escalation",
        "description": (
            "Adversaries may escape container boundaries to gain access to "
            "the underlying host. By exploiting misconfigurations like "
            "privileged pods, hostPID, hostNetwork, or container runtime "
            "vulnerabilities, attackers can break out and access the node "
            "filesystem, credentials, and other containers."
        ),
        "url": "https://attack.mitre.org/techniques/T1611/",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may scan for running services on remote hosts to "
            "identify targets for lateral movement. In cloud environments, "
            "compromised pods or instances can scan VPC subnets, discovering "
            "databases, APIs, and internal services not exposed to the "
            "internet."
        ),
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials in Files",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may search local filesystems, configuration files, "
            "environment variables, and container mounts for stored "
            "credentials. In Kubernetes, secrets mounted as env vars or "
            "files are easily extractable from compromised pods."
        ),
        "url": "https://attack.mitre.org/techniques/T1552/001/",
    },
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may intercept network traffic between systems to "
            "steal credentials or manipulate data. In cloud environments, "
            "services communicating without TLS or using self-signed "
            "certificates are vulnerable to MITM attacks within the VPC."
        ),
        "url": "https://attack.mitre.org/techniques/T1557/",
    },
    "T1534": {
        "name": "Internal Spearphishing",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use internal email or messaging platforms to "
            "phish other users within the organization. Compromised M365 or "
            "Google Workspace accounts can send internal phishing emails "
            "that bypass external email security controls."
        ),
        "url": "https://attack.mitre.org/techniques/T1534/",
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may compromise supply chain components to gain "
            "access to victim environments. In cloud, this includes "
            "poisoned container images in registries, malicious GitHub "
            "Actions workflows, compromised Terraform modules, or "
            "backdoored AMIs."
        ),
        "url": "https://attack.mitre.org/techniques/T1195/",
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may manipulate access tokens to operate under a "
            "different security context. In cloud environments, this "
            "includes forging or stealing OAuth tokens, SAML assertions, "
            "or cloud provider session tokens to assume different "
            "identities."
        ),
        "url": "https://attack.mitre.org/techniques/T1134/",
    },
    "T1542": {
        "name": "Pre-OS Boot",
        "tactic": "Persistence",
        "description": (
            "Adversaries may abuse pre-OS boot mechanisms to establish "
            "persistence. In cloud, this relates to compromising boot "
            "integrity through disabled Secure Boot on instances, modified "
            "boot volumes, or tampered VM images."
        ),
        "url": "https://attack.mitre.org/techniques/T1542/",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": (
            "Adversaries may delete or disable system recovery features to "
            "prevent restoration after destructive actions. In cloud, "
            "attackers delete snapshots, disable backup policies, remove "
            "cross-region replicas, and purge versioned objects before "
            "deploying ransomware."
        ),
        "url": "https://attack.mitre.org/techniques/T1490/",
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": (
            "Adversaries may consume resources to prevent availability of "
            "services. In cloud, this includes resource exhaustion via "
            "auto-scaling abuse, storage quota exhaustion, API rate limit "
            "abuse, or compute resource hijacking."
        ),
        "url": "https://attack.mitre.org/techniques/T1499/",
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
    "gcp_iam_no_primitive_roles": [
        "T1078.004", "T1098",
    ],
    "gcp_iam_no_sa_admin_key": [
        "T1078.004", "T1552",
    ],
    "gcp_iam_sa_key_rotation": [
        "T1552", "T1078.004",
    ],
    "gcp_iam_separation_of_duties": [
        "T1098", "T1078.004",
    ],
    "gcp_iam_no_user_managed_sa_keys": [
        "T1552", "T1078.004",
    ],
    "gcp_iam_api_keys_restricted": [
        "T1552", "T1190",
    ],
    "gcp_iam_corp_login_required": [
        "T1078.004", "T1566",
    ],
    "gcp_iam_sa_user_role": [
        "T1078.004", "T1098",
    ],
    "gcp_iam_sa_token_creator_role": [
        "T1078.004", "T1134",
    ],
    "gcp_iam_kms_separation_of_duties": [
        "T1098", "T1486",
    ],
    "gcp_iam_api_keys_exist": [
        "T1552",
    ],
    "gcp_iam_api_keys_rotated": [
        "T1552", "T1078.004",
    ],
    "gcp_iam_essential_contacts": [
        "T1562.008",
    ],
    "gcp_iam_secrets_in_functions": [
        "T1552.001", "T1648",
    ],
    "gcp_compute_shielded_vm": [
        "T1542", "T1195",
    ],
    "gcp_compute_disk_encryption_cmek": [
        "T1530", "T1486",
    ],
    "gcp_compute_no_default_sa": [
        "T1078.004", "T1098",
    ],
    "gcp_compute_serial_port_disabled": [
        "T1021", "T1059",
    ],
    "gcp_compute_ip_forwarding_disabled": [
        "T1557", "T1021",
    ],
    "gcp_compute_confidential_computing": [
        "T1530",
    ],
    "gcp_compute_no_full_api_access": [
        "T1078.004", "T1098",
    ],
    "gcp_compute_block_project_ssh": [
        "T1021.004", "T1098",
    ],
    "gcp_storage_no_public_access": [
        "T1530", "T1190",
    ],
    "gcp_storage_versioning": [
        "T1485", "T1530",
    ],
    "gcp_storage_logging_enabled": [
        "T1562.008", "T1070",
    ],
    "gcp_storage_retention_policy": [
        "T1485",
    ],
    "gcp_storage_cmek_encryption": [
        "T1530", "T1486",
    ],
    "gcp_sql_backup_enabled": [
        "T1485", "T1490",
    ],
    "gcp_sql_pitr_enabled": [
        "T1485", "T1490",
    ],
    "gcp_sql_no_public_networks": [
        "T1190", "T1110",
    ],
    "gcp_sql_cmek_encryption": [
        "T1530", "T1486",
    ],
    "gcp_sql_audit_logging": [
        "T1562.008", "T1070",
    ],
    "gcp_sql_auto_storage_increase": [
        "T1499",
    ],
    "gcp_logging_sinks_configured": [
        "T1562.008",
    ],
    "gcp_logging_audit_logs_enabled": [
        "T1562.008", "T1070",
    ],
    "gcp_logging_metric_filters": [
        "T1562.008",
    ],
    "gcp_logging_bucket_retention": [
        "T1070", "T1562.008",
    ],
    "gcp_logging_vpc_flow_logs": [
        "T1562.008", "T1021",
    ],
    "gcp_logging_dns_logging": [
        "T1071", "T1562.008",
    ],
    "gcp_logging_ownership_changes": [
        "T1098", "T1562.008",
    ],
    "gcp_logging_audit_config_changes": [
        "T1562.008", "T1070",
    ],
    "gcp_logging_custom_role_changes": [
        "T1098", "T1078.004",
    ],
    "gcp_logging_firewall_changes": [
        "T1562.004", "T1562.008",
    ],
    "gcp_logging_route_changes": [
        "T1557", "T1562.008",
    ],
    "gcp_logging_vpc_changes": [
        "T1562.008", "T1021",
    ],
    "gcp_logging_storage_iam_changes": [
        "T1530", "T1562.008",
    ],
    "gcp_logging_sql_config_changes": [
        "T1562.008", "T1530",
    ],
    "gcp_logging_cloud_asset_inventory": [
        "T1580", "T1562.008",
    ],
    "gcp_logging_lb_logging": [
        "T1562.008", "T1190",
    ],
    "gcp_kms_no_public_access": [
        "T1552", "T1190",
    ],
    "gcp_kms_hsm_protection": [
        "T1552", "T1486",
    ],
    "gcp_gke_master_auth_networks": [
        "T1190", "T1021",
    ],
    "gcp_gke_pod_security_policy": [
        "T1525", "T1611",
    ],
    "gcp_gke_shielded_nodes": [
        "T1542", "T1525",
    ],
    "gcp_gke_workload_identity": [
        "T1078.004", "T1552",
    ],
    "gcp_gke_binary_auth": [
        "T1525", "T1195",
    ],
    "gcp_gke_cluster_logging": [
        "T1562.008",
    ],
    "gcp_firewall_no_default_allow": [
        "T1190", "T1021",
    ],
    "gcp_network_dns_sec": [
        "T1071", "T1557",
    ],
    "gcp_network_private_google_access": [
        "T1530", "T1021",
    ],
    "gcp_network_flow_logs_enabled": [
        "T1562.008", "T1021",
    ],
    "gcp_network_no_default_network": [
        "T1190", "T1021",
    ],
    "gcp_network_no_legacy_network": [
        "T1190",
    ],
    "gcp_network_ssl_policy": [
        "T1530", "T1557",
    ],
    "gcp_bigquery_dataset_no_public": [
        "T1530", "T1190",
    ],
    "gcp_bigquery_cmek_encryption": [
        "T1530", "T1486",
    ],
    "gcp_bigquery_table_encrypted": [
        "T1530", "T1486",
    ],
    "gcp_bigquery_audit_logging": [
        "T1562.008", "T1070",
    ],
    "gcp_bigquery_classification": [
        "T1530",
    ],
    "gcp_pubsub_no_public_access": [
        "T1530", "T1190",
    ],
    "gcp_pubsub_encrypted": [
        "T1530",
    ],
    "gcp_dns_dnssec_enabled": [
        "T1071", "T1557",
    ],
    "gcp_dns_rsasha1_disabled": [
        "T1557",
    ],
    "gcp_dataproc_encrypted": [
        "T1530",
    ],
    "gcp_dataproc_private": [
        "T1190", "T1021",
    ],
    # -----------------------------------------------------------------------
    # OCI checks
    # -----------------------------------------------------------------------
    "oci_iam_user_mfa_enabled": [
        "T1078", "T1078.004", "T1556", "T1621",
    ],
    "oci_iam_api_key_rotation": [
        "T1528", "T1552", "T1078.004",
    ],
    "oci_iam_policy_no_wildcard": [
        "T1078.004", "T1098", "T1548",
    ],
    "oci_iam_admin_group_empty": [
        "T1078.004", "T1098",
    ],
    "oci_network_sl_no_ssh_open": [
        "T1021.004", "T1190", "T1563",
    ],
    "oci_network_sl_no_rdp_open": [
        "T1021.001", "T1190", "T1563",
    ],
    "oci_network_sl_no_unrestricted_ingress": [
        "T1190", "T1046",
    ],
    "oci_objectstorage_bucket_public_access": [
        "T1530", "T1190", "T1537",
    ],
    "oci_objectstorage_bucket_cmk_encryption": [
        "T1530", "T1213",
    ],
    "oci_objectstorage_versioning_enabled": [
        "T1485", "T1490",
    ],
    "oci_compute_secure_boot": [
        "T1542", "T1195",
    ],
    "oci_compute_imds_v2": [
        "T1552.005", "T1528", "T1078.004",
    ],
    "oci_vault_key_rotation": [
        "T1552", "T1486",
    ],
    "oci_cloud_guard_enabled": [
        "T1562.001", "T1562.008", "T1580",
    ],
    "oci_logging_audit_retention": [
        "T1562.008", "T1070",
    ],
    "oci_db_autonomous_private_endpoint": [
        "T1190", "T1110", "T1530",
    ],
    "oci_oke_cluster_public_endpoint": [
        "T1190", "T1078.004", "T1525",
    ],
    "oci_waf_enabled": [
        "T1190", "T1498",
    ],
    # -----------------------------------------------------------------------
    # Alibaba Cloud checks
    # -----------------------------------------------------------------------
    "ali_ram_mfa_enabled": [
        "T1078", "T1078.004", "T1556", "T1621",
    ],
    "ali_ram_access_key_rotation": [
        "T1528", "T1552", "T1078.004",
    ],
    "ali_ram_no_wildcard_policy": [
        "T1078.004", "T1098", "T1548",
    ],
    "ali_ram_unused_users": [
        "T1078", "T1078.004",
    ],
    "ali_ram_policies_groups_only": [
        "T1078.004", "T1098",
    ],
    "ali_ecs_no_public_ip": [
        "T1190", "T1021", "T1580",
    ],
    "ali_ecs_sg_no_ssh_open": [
        "T1021.004", "T1190", "T1563",
    ],
    "ali_ecs_sg_no_rdp_open": [
        "T1021.001", "T1190", "T1563",
    ],
    "ali_ecs_sg_no_public_ingress": [
        "T1190", "T1046",
    ],
    "ali_oss_no_public_access": [
        "T1530", "T1190", "T1537",
    ],
    "ali_oss_encryption_enabled": [
        "T1530", "T1213",
    ],
    "ali_oss_versioning_enabled": [
        "T1485", "T1490",
    ],
    "ali_actiontrail_enabled": [
        "T1562.008", "T1070", "T1526",
    ],
    "ali_actiontrail_multi_region": [
        "T1562.008", "T1070",
    ],
    "ali_sls_retention_365": [
        "T1562.008", "T1070",
    ],
    "ali_security_center_enabled": [
        "T1562.001", "T1562.008", "T1580",
    ],
    "ali_sas_agents_installed": [
        "T1562.001", "T1580",
    ],
    "ali_rds_no_public_access": [
        "T1190", "T1110", "T1530",
    ],
    "ali_rds_encryption_enabled": [
        "T1530", "T1213",
    ],
    "ali_kms_key_rotation": [
        "T1552", "T1486",
    ],
    "ali_ack_private_cluster": [
        "T1190", "T1525", "T1021",
    ],
    "ali_waf_enabled": [
        "T1190", "T1498",
    ],
    "ali_vpc_flow_logs": [
        "T1562.008", "T1046",
    ],
    # -----------------------------------------------------------------------
    # Kubernetes checks
    # -----------------------------------------------------------------------
    "k8s_rbac_no_wildcard_cluster_admin": [
        "T1078.004", "T1098", "T1548",
    ],
    "k8s_no_pods_in_default": [
        "T1525", "T1059", "T1610",
    ],
    "k8s_namespace_network_policy": [
        "T1021", "T1563", "T1046",
    ],
    "k8s_admission_pod_security": [
        "T1611", "T1525",
    ],
    "k8s_secrets_encrypted_etcd": [
        "T1552", "T1530",
    ],
    "k8s_secrets_no_env_vars": [
        "T1552", "T1552.001",
    ],
    "k8s_api_audit_logging": [
        "T1562.008", "T1070",
    ],
    "k8s_rbac_no_default_sa_token": [
        "T1528", "T1078.004",
    ],
    "k8s_no_privileged_containers": [
        "T1611", "T1610",
    ],
    "k8s_no_host_pid": [
        "T1611",
    ],
    "k8s_no_host_network": [
        "T1611", "T1046",
    ],
    "k8s_image_pull_policy_always": [
        "T1525", "T1195",
    ],
    "k8s_resource_limits_set": [
        "T1499", "T1496",
    ],
    "k8s_no_automount_sa_token": [
        "T1528", "T1552.001",
    ],
    # -----------------------------------------------------------------------
    # SaaS checks
    # -----------------------------------------------------------------------
    # ServiceNow
    "servicenow_users_mfa_enabled": [
        "T1078", "T1556", "T1621",
    ],
    "servicenow_ac_acl_active": [
        "T1078", "T1098",
    ],
    "servicenow_iv_escape_script": [
        "T1059", "T1190",
    ],
    "servicenow_encryption_at_rest": [
        "T1530", "T1213",
    ],
    "servicenow_session_timeout": [
        "T1550", "T1528",
    ],
    # Microsoft 365
    "m365_user_mfa_registered": [
        "T1078", "T1556", "T1621",
    ],
    "m365_ca_block_legacy_auth": [
        "T1078", "T1550", "T1110",
    ],
    "m365_admin_mfa_enforced": [
        "T1078", "T1078.004", "T1556",
    ],
    "m365_defender_sensor_active": [
        "T1562.001",
    ],
    "m365_safe_attachments_enabled": [
        "T1566", "T1204",
    ],
    "m365_safe_links_enabled": [
        "T1566", "T1204",
    ],
    "m365_dlp_policies_configured": [
        "T1530", "T1567",
    ],
    "m365_external_sharing_restricted": [
        "T1537", "T1567",
    ],
    "m365_audit_log_enabled": [
        "T1562.008", "T1070",
    ],
    # Salesforce
    "salesforce_user_mfa_enabled": [
        "T1078", "T1556",
    ],
    "salesforce_encryption_at_rest": [
        "T1530", "T1213",
    ],
    "salesforce_field_level_security": [
        "T1530", "T1213",
    ],
    "salesforce_session_timeout": [
        "T1550", "T1528",
    ],
    "salesforce_login_ip_ranges": [
        "T1078", "T1190",
    ],
    # Snowflake
    "snowflake_user_mfa_enabled": [
        "T1078", "T1556", "T1621",
    ],
    "snowflake_network_policy_set": [
        "T1078", "T1190",
    ],
    "snowflake_column_masking_policies": [
        "T1530", "T1213",
    ],
    "snowflake_query_audit_enabled": [
        "T1562.008", "T1070",
    ],
    # GitHub
    "github_org_2fa_required": [
        "T1078", "T1556",
    ],
    "github_repo_secret_scanning": [
        "T1552", "T1552.001",
    ],
    "github_repo_branch_protection": [
        "T1195", "T1525",
    ],
    "github_actions_restricted": [
        "T1059", "T1648",
    ],
    "github_repo_vulnerability_alerts": [
        "T1195", "T1190",
    ],
    # Cloudflare
    "cloudflare_tls_full_strict": [
        "T1557", "T1550",
    ],
    "cloudflare_waf_managed_rules": [
        "T1190", "T1498",
    ],
    "cloudflare_bot_management": [
        "T1110", "T1498",
    ],
    # Google Workspace
    "gws_user_2fa_enrolled": [
        "T1078", "T1556", "T1621",
    ],
    "gws_admin_2fa_enforced": [
        "T1078", "T1078.004", "T1556",
    ],
    "gws_email_dmarc_configured": [
        "T1566", "T1534",
    ],
    "gws_email_spf_configured": [
        "T1566",
    ],
    "gws_drive_sharing_restricted": [
        "T1537", "T1567",
    ],
    # OpenStack
    "openstack_identity_admin_mfa": [
        "T1078", "T1556", "T1621",
    ],
    "openstack_storage_volume_encryption": [
        "T1530", "T1213", "T1486",
    ],
    "openstack_network_sg_no_ssh_open": [
        "T1021.004", "T1190",
    ],
    "openstack_identity_token_expiry": [
        "T1550", "T1134",
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
    # ── OCI checks ──
    "oci_iam_user_mfa_enabled": (
        "OCI IAM users lack multi-factor authentication. An attacker who "
        "obtains credentials through phishing or credential stuffing gains "
        "unrestricted access to cloud resources. Without MFA, a single "
        "compromised password enables full account takeover across the OCI tenancy."
    ),
    "oci_iam_api_key_rotation": (
        "OCI API signing keys are not being rotated regularly. Long-lived API "
        "keys increase the window of opportunity for attackers who obtain them "
        "through code repositories, logs, or insider access. Stale keys allow "
        "persistent unauthorized access that is difficult to detect."
    ),
    "oci_iam_policy_no_wildcard": (
        "OCI IAM policies contain wildcard permissions granting overly broad "
        "access. An attacker who compromises any identity with these policies "
        "gains administrative-level access across all OCI services, enabling "
        "data exfiltration, resource manipulation, and lateral movement."
    ),
    "oci_iam_admin_group_empty": (
        "OCI administrator group contains users who may not need elevated "
        "privileges. Excessive admin membership widens the attack surface — "
        "compromising any admin user grants full control over the tenancy."
    ),
    "oci_network_sl_no_ssh_open": (
        "OCI security list allows SSH (port 22) from the internet. Exposed SSH "
        "enables brute-force attacks and exploitation of SSH vulnerabilities. "
        "Attackers who gain SSH access can pivot to internal networks and access "
        "instance metadata credentials."
    ),
    "oci_network_sl_no_rdp_open": (
        "OCI security list allows RDP (port 3389) from the internet. Open RDP "
        "is a primary vector for ransomware groups who use credential attacks "
        "to access Windows instances and deploy malicious payloads."
    ),
    "oci_network_sl_no_unrestricted_ingress": (
        "OCI security lists allow unrestricted inbound access from 0.0.0.0/0. "
        "This exposes all services on the subnet to the internet, enabling "
        "attackers to discover and exploit any vulnerable service."
    ),
    "oci_objectstorage_bucket_public_access": (
        "OCI Object Storage buckets are publicly accessible. Exposed buckets "
        "can leak sensitive data, backups, and credentials. Adversaries "
        "routinely scan for open cloud storage to harvest data for extortion."
    ),
    "oci_objectstorage_bucket_cmk_encryption": (
        "OCI Object Storage buckets are not encrypted with customer-managed "
        "keys. Without CMK encryption, data at rest is protected only by "
        "default encryption, limiting the organization's control over key "
        "lifecycle and access policies."
    ),
    "oci_objectstorage_versioning_enabled": (
        "OCI Object Storage buckets do not have versioning enabled. Without "
        "versioning, deleted or overwritten objects cannot be recovered, making "
        "the environment vulnerable to ransomware that destroys backup data."
    ),
    "oci_compute_secure_boot": (
        "OCI compute instances do not have Secure Boot enabled. Attackers can "
        "modify boot volumes or implant rootkits that persist across reboots, "
        "gaining persistent access that evades standard security controls."
    ),
    "oci_compute_imds_v2": (
        "OCI compute instances use IMDSv1 which is vulnerable to SSRF attacks. "
        "An attacker exploiting an SSRF vulnerability in a web application can "
        "query the metadata service to steal instance credentials and API keys."
    ),
    "oci_vault_key_rotation": (
        "OCI Vault encryption keys are not being rotated. Long-lived encryption "
        "keys increase the risk of key compromise, potentially exposing all "
        "data encrypted with the stale key material."
    ),
    "oci_cloud_guard_enabled": (
        "OCI Cloud Guard is not enabled. Without Cloud Guard, security "
        "misconfigurations, threats, and anomalous activity go undetected, "
        "giving attackers freedom to operate without triggering alerts."
    ),
    "oci_logging_audit_retention": (
        "OCI audit log retention is insufficient. Short retention periods mean "
        "forensic evidence is lost before an incident is discovered, preventing "
        "proper investigation and attacker attribution."
    ),
    "oci_db_autonomous_private_endpoint": (
        "OCI Autonomous Database is not using a private endpoint. Public "
        "database endpoints expose the service to brute-force attacks and "
        "exploitation of database vulnerabilities from the internet."
    ),
    "oci_oke_cluster_public_endpoint": (
        "OCI Kubernetes Engine cluster has a public API endpoint. Exposed "
        "Kubernetes API servers are targeted by attackers for credential "
        "brute-force, misconfig exploitation, and container escape attacks."
    ),
    "oci_waf_enabled": (
        "OCI Web Application Firewall is not enabled. Without WAF, web "
        "applications are exposed to OWASP top 10 attacks including SQL "
        "injection, XSS, and command injection that enable initial access."
    ),
    # ── Alibaba Cloud checks ──
    "ali_ram_mfa_enabled": (
        "Alibaba Cloud RAM users lack multi-factor authentication. Compromised "
        "credentials allow direct access to cloud resources without additional "
        "verification. Attackers can deploy resources, exfiltrate data from OSS "
        "buckets, and establish persistence through new RAM users."
    ),
    "ali_ram_access_key_rotation": (
        "Alibaba Cloud RAM access keys are not rotated regularly. Long-lived "
        "access keys discovered in code repositories or logs provide persistent "
        "programmatic access to all authorized Alibaba Cloud APIs."
    ),
    "ali_ram_no_wildcard_policy": (
        "Alibaba Cloud RAM policies contain wildcard permissions. A compromised "
        "identity with wildcard policies gains administrative access to all "
        "services, enabling data theft, resource destruction, and account takeover."
    ),
    "ali_ram_unused_users": (
        "Alibaba Cloud RAM has unused user accounts that have not been accessed "
        "recently. Dormant accounts are attractive targets because their "
        "compromise is less likely to be noticed by the legitimate user."
    ),
    "ali_ram_policies_groups_only": (
        "Alibaba Cloud RAM policies are attached directly to users instead of "
        "groups. This makes permission management error-prone and increases the "
        "risk of overly permissive access through inconsistent policy assignment."
    ),
    "ali_ecs_no_public_ip": (
        "Alibaba Cloud ECS instances have public IP addresses assigned. Direct "
        "internet exposure enables attackers to scan, enumerate, and exploit "
        "services running on these instances."
    ),
    "ali_ecs_sg_no_ssh_open": (
        "Alibaba ECS security groups allow SSH access from the internet. This "
        "exposes instances to brute-force attacks and SSH vulnerability "
        "exploitation. Attackers who gain SSH access can pivot to internal "
        "networks and access ECS metadata credentials."
    ),
    "ali_ecs_sg_no_rdp_open": (
        "Alibaba ECS security groups allow RDP access from the internet. Open "
        "RDP is a primary entry point for ransomware operators who use credential "
        "attacks to access Windows instances."
    ),
    "ali_ecs_sg_no_public_ingress": (
        "Alibaba ECS security groups allow unrestricted inbound access from "
        "0.0.0.0/0. This exposes all services on the instance to internet-based "
        "attacks, including service exploitation and network scanning."
    ),
    "ali_oss_no_public_access": (
        "Alibaba Cloud OSS buckets are publicly accessible. Exposed object "
        "storage can leak sensitive data, customer records, and internal "
        "documents. Attackers systematically scan for open cloud storage."
    ),
    "ali_oss_encryption_enabled": (
        "Alibaba Cloud OSS buckets are not encrypted. Unencrypted data at rest "
        "is exposed if storage access controls are bypassed, increasing the "
        "impact of any data breach or insider threat."
    ),
    "ali_oss_versioning_enabled": (
        "Alibaba Cloud OSS buckets do not have versioning enabled. Without "
        "versioning, ransomware operators can permanently destroy data by "
        "overwriting or deleting objects with no recovery path."
    ),
    "ali_actiontrail_enabled": (
        "Alibaba Cloud ActionTrail is not enabled. Without audit logging, "
        "attacker actions such as privilege escalation, data access, and "
        "configuration changes go unrecorded, preventing detection and forensics."
    ),
    "ali_actiontrail_multi_region": (
        "Alibaba Cloud ActionTrail is not configured for multi-region logging. "
        "Attackers can operate in unmonitored regions to evade detection while "
        "accessing resources across the account."
    ),
    "ali_sls_retention_365": (
        "Alibaba Cloud SLS log retention is less than 365 days. Insufficient "
        "retention means forensic evidence may be lost before sophisticated "
        "attacks with long dwell times are discovered."
    ),
    "ali_security_center_enabled": (
        "Alibaba Cloud Security Center is not enabled. Without centralized "
        "threat detection, malware, intrusions, and misconfigurations go "
        "undetected across the cloud environment."
    ),
    "ali_sas_agents_installed": (
        "Alibaba Cloud Security Center agents are not installed on instances. "
        "Without host-level agents, runtime threats such as cryptominers, "
        "backdoors, and lateral movement tools are invisible to security teams."
    ),
    "ali_rds_no_public_access": (
        "Alibaba Cloud RDS instances are publicly accessible. Internet-exposed "
        "databases are subject to brute-force attacks, SQL injection via "
        "exposed management ports, and data exfiltration."
    ),
    "ali_rds_encryption_enabled": (
        "Alibaba Cloud RDS instances do not have encryption enabled. "
        "Unencrypted database storage exposes data if access controls are "
        "bypassed or storage volumes are accessed through the cloud API."
    ),
    "ali_kms_key_rotation": (
        "Alibaba Cloud KMS keys are not being rotated. Long-lived encryption "
        "keys increase the blast radius of key compromise and reduce "
        "cryptographic agility for the organization."
    ),
    "ali_ack_private_cluster": (
        "Alibaba Cloud ACK Kubernetes cluster has a public API endpoint. "
        "Exposed Kubernetes API servers enable attackers to attempt credential "
        "attacks and exploit cluster misconfigurations remotely."
    ),
    "ali_waf_enabled": (
        "Alibaba Cloud WAF is not enabled. Web applications are exposed to "
        "injection attacks, cross-site scripting, and other OWASP top 10 "
        "vulnerabilities that enable initial access and data theft."
    ),
    "ali_vpc_flow_logs": (
        "Alibaba Cloud VPC flow logs are not enabled. Without network flow "
        "visibility, lateral movement, data exfiltration, and command-and-control "
        "traffic cannot be detected or investigated."
    ),
    # ── Kubernetes checks ──
    "k8s_rbac_no_wildcard_cluster_admin": (
        "Kubernetes RBAC roles grant wildcard cluster-admin permissions. An "
        "attacker who compromises any pod bound to these roles gains full "
        "control over the cluster, including ability to deploy malicious "
        "containers, read all secrets, and escape to underlying nodes."
    ),
    "k8s_no_pods_in_default": (
        "Workloads running in the Kubernetes default namespace bypass "
        "namespace-level security policies. Attackers who compromise these "
        "pods may inherit overly permissive default service accounts and "
        "network access, facilitating lateral movement."
    ),
    "k8s_namespace_network_policy": (
        "Kubernetes namespaces lack network policies. Without network "
        "segmentation, a compromised pod can communicate freely with all "
        "other pods and services in the cluster, enabling unrestricted "
        "lateral movement and service discovery."
    ),
    "k8s_admission_pod_security": (
        "Kubernetes does not enforce Pod Security Standards via admission "
        "control. Without these controls, attackers can deploy privileged "
        "containers that mount host filesystems and escape to the node."
    ),
    "k8s_secrets_encrypted_etcd": (
        "Kubernetes secrets are not encrypted at rest in etcd. An attacker "
        "with access to etcd data can read all secrets including database "
        "credentials, API keys, and TLS certificates in plaintext."
    ),
    "k8s_secrets_no_env_vars": (
        "Kubernetes secrets are exposed as environment variables in pods. "
        "Environment variables are visible in process listings and crash "
        "dumps, making credential extraction trivial for attackers who gain "
        "any level of pod access."
    ),
    "k8s_api_audit_logging": (
        "Kubernetes API audit logging is not enabled. Without audit logs, "
        "attacker actions such as secret reads, role binding changes, and "
        "container deployments go unrecorded, preventing incident detection "
        "and forensic investigation."
    ),
    "k8s_rbac_no_default_sa_token": (
        "Kubernetes default service account tokens are auto-mounted to pods. "
        "Attackers who compromise a pod can use the service account token to "
        "authenticate to the Kubernetes API and enumerate cluster resources."
    ),
    "k8s_no_privileged_containers": (
        "Kubernetes allows privileged containers. Privileged containers have "
        "unrestricted access to the host OS, enabling attackers to escape "
        "the container boundary and compromise the underlying node."
    ),
    "k8s_no_host_pid": (
        "Kubernetes pods can access the host PID namespace. This allows "
        "attackers to see and signal host processes, enabling process "
        "injection, credential harvesting, and container escape."
    ),
    "k8s_no_host_network": (
        "Kubernetes pods can use the host network namespace. This bypasses "
        "network policies and allows attackers to sniff traffic, access "
        "services bound to localhost, and perform network-level attacks."
    ),
    "k8s_image_pull_policy_always": (
        "Kubernetes image pull policy is not set to Always. Cached images "
        "may contain known vulnerabilities or be tampered with. Attackers "
        "can exploit stale images to deploy containers with known exploits."
    ),
    "k8s_resource_limits_set": (
        "Kubernetes pods do not have resource limits configured. Without "
        "limits, a compromised pod can consume all node resources, causing "
        "denial of service to co-located workloads and enabling cryptomining."
    ),
    "k8s_no_automount_sa_token": (
        "Kubernetes service account tokens are auto-mounted to pods that "
        "don't need API access. Unnecessary token exposure increases the "
        "attack surface for credential theft and API abuse."
    ),
    # ── SaaS checks ──
    "servicenow_users_mfa_enabled": (
        "ServiceNow users are not required to use multi-factor authentication. "
        "An attacker who compromises ServiceNow credentials gains access to IT "
        "service management data, change records, and potentially stored cloud "
        "credentials in custom fields or integrations."
    ),
    "servicenow_ac_acl_active": (
        "ServiceNow access control lists are not properly enforced. Without "
        "ACL enforcement, users may access records beyond their authorization, "
        "enabling data theft and privilege escalation within the ITSM platform."
    ),
    "servicenow_iv_escape_script": (
        "ServiceNow input validation does not properly escape scripts. This "
        "exposes the platform to cross-site scripting (XSS) and script "
        "injection attacks that can steal session tokens and credentials."
    ),
    "servicenow_encryption_at_rest": (
        "ServiceNow data is not encrypted at rest. Sensitive ITSM data "
        "including passwords, configurations, and cloud credentials stored in "
        "custom fields are exposed if the underlying storage is compromised."
    ),
    "servicenow_session_timeout": (
        "ServiceNow session timeout is too long or not configured. Abandoned "
        "sessions on shared computers allow attackers to hijack authenticated "
        "sessions and access ITSM data without credentials."
    ),
    "m365_user_mfa_registered": (
        "Microsoft 365 users have not registered for multi-factor "
        "authentication. Without MFA, compromised credentials from phishing or "
        "credential stuffing provide direct access to email, OneDrive, "
        "SharePoint, and Teams data."
    ),
    "m365_ca_block_legacy_auth": (
        "Microsoft 365 allows legacy authentication protocols that do not "
        "support MFA. Attackers can use password spray attacks against IMAP, "
        "POP3, and SMTP to bypass conditional access policies and gain access "
        "to mailboxes and cloud resources."
    ),
    "m365_admin_mfa_enforced": (
        "Microsoft 365 administrator accounts do not have MFA enforced. "
        "Compromised admin credentials grant full control over the tenant, "
        "including user management, data access, and Azure AD configuration."
    ),
    "m365_defender_sensor_active": (
        "Microsoft Defender sensors are not active. Without endpoint "
        "detection, malware, suspicious processes, and attacker tools "
        "running on managed devices go undetected."
    ),
    "m365_safe_attachments_enabled": (
        "Microsoft 365 Safe Attachments is not enabled. Email attachments "
        "with malware bypass security scanning, allowing phishing campaigns "
        "to deliver ransomware, trojans, and other malicious payloads."
    ),
    "m365_safe_links_enabled": (
        "Microsoft 365 Safe Links is not enabled. Malicious URLs in email "
        "messages are not scanned at click time, allowing phishing links "
        "to redirect users to credential harvesting or malware download sites."
    ),
    "m365_dlp_policies_configured": (
        "Microsoft 365 Data Loss Prevention policies are not configured. "
        "Without DLP, sensitive data such as credit card numbers, SSNs, and "
        "confidential documents can be shared externally without detection."
    ),
    "m365_external_sharing_restricted": (
        "Microsoft 365 external sharing is unrestricted. Users can share "
        "documents and data with external parties without controls, enabling "
        "both intentional insider exfiltration and accidental data exposure."
    ),
    "m365_audit_log_enabled": (
        "Microsoft 365 unified audit logging is not enabled. Without audit "
        "logs, user activities, admin changes, and data access events are "
        "not recorded, preventing breach detection and forensic investigation."
    ),
    "salesforce_user_mfa_enabled": (
        "Salesforce users do not have MFA enabled. Compromised Salesforce "
        "credentials grant access to CRM data including customer records, "
        "contracts, revenue data, and potentially integrated cloud resources."
    ),
    "salesforce_encryption_at_rest": (
        "Salesforce Shield Platform Encryption is not enabled. Sensitive CRM "
        "data including customer PII, financial records, and credentials "
        "stored in custom fields are not protected at the storage layer."
    ),
    "salesforce_field_level_security": (
        "Salesforce field-level security is not properly configured. Users "
        "can access sensitive fields beyond their role requirements, enabling "
        "unauthorized data harvesting and increasing insider threat risk."
    ),
    "salesforce_session_timeout": (
        "Salesforce session timeout is not configured appropriately. Long "
        "sessions on shared or compromised devices allow session hijacking "
        "and unauthorized access to CRM data."
    ),
    "salesforce_login_ip_ranges": (
        "Salesforce does not restrict login IP ranges. Attackers can "
        "authenticate from any location using stolen credentials, making "
        "unauthorized access harder to distinguish from legitimate use."
    ),
    "snowflake_user_mfa_enabled": (
        "Snowflake users do not have MFA enabled. Compromised data warehouse "
        "credentials grant access to analytical data, customer datasets, and "
        "potentially sensitive financial and PII data stored in Snowflake."
    ),
    "snowflake_network_policy_set": (
        "Snowflake does not have a network policy restricting access by IP. "
        "Attackers can connect from any network location using stolen "
        "credentials, bypassing network-level access controls."
    ),
    "snowflake_column_masking_policies": (
        "Snowflake does not enforce column-level masking policies. Users and "
        "compromised accounts can view sensitive data fields (SSN, credit "
        "cards, etc.) in plaintext, enabling bulk data exfiltration."
    ),
    "snowflake_query_audit_enabled": (
        "Snowflake query auditing is not enabled. Without audit logs, "
        "unusual data access patterns such as bulk exports and sensitive "
        "column queries go undetected."
    ),
    "github_org_2fa_required": (
        "GitHub organization does not require two-factor authentication. "
        "Compromised developer credentials grant access to source code, "
        "CI/CD pipelines, secrets, and the ability to inject malicious code."
    ),
    "github_repo_secret_scanning": (
        "GitHub repositories do not have secret scanning enabled. Developers "
        "may accidentally commit API keys, cloud credentials, and tokens to "
        "code. Attackers who discover these secrets can access cloud "
        "infrastructure, databases, and third-party services."
    ),
    "github_repo_branch_protection": (
        "GitHub branch protection rules are not configured. Without branch "
        "protection, attackers who compromise a developer account can push "
        "malicious code directly to production branches without review."
    ),
    "github_actions_restricted": (
        "GitHub Actions are not restricted to approved workflows. Attackers "
        "can create or modify workflows to exfiltrate secrets, mine "
        "cryptocurrency, or inject malicious code into the CI/CD pipeline."
    ),
    "github_repo_vulnerability_alerts": (
        "GitHub repository vulnerability alerts are not enabled. Known "
        "vulnerabilities in dependencies go unnoticed, allowing attackers "
        "to exploit published CVEs in the software supply chain."
    ),
    "cloudflare_tls_full_strict": (
        "Cloudflare TLS mode is not set to Full Strict. Without strict TLS, "
        "connections between Cloudflare and the origin server may be "
        "vulnerable to man-in-the-middle attacks and certificate spoofing."
    ),
    "cloudflare_waf_managed_rules": (
        "Cloudflare WAF managed rules are not enabled. Web applications are "
        "exposed to common attacks including SQL injection, XSS, and remote "
        "code execution that enable initial access and data theft."
    ),
    "cloudflare_bot_management": (
        "Cloudflare bot management is not enabled. Automated credential "
        "stuffing, brute-force attacks, and scraping can be conducted at "
        "scale without detection or mitigation."
    ),
    "gws_user_2fa_enrolled": (
        "Google Workspace users have not enrolled in two-factor "
        "authentication. Compromised credentials grant access to Gmail, "
        "Drive, Calendar, and other Workspace services containing sensitive "
        "business communications and documents."
    ),
    "gws_admin_2fa_enforced": (
        "Google Workspace admin accounts do not have 2FA enforced. "
        "Compromised admin credentials grant full control over the "
        "organization's Workspace tenant, user management, and data."
    ),
    "gws_email_dmarc_configured": (
        "Google Workspace DMARC is not configured. Without DMARC, attackers "
        "can spoof the organization's email domain for phishing campaigns "
        "targeting employees, customers, and partners."
    ),
    "gws_email_spf_configured": (
        "Google Workspace SPF records are not configured. Without SPF, "
        "attackers can send emails appearing to come from the organization's "
        "domain, enabling phishing and business email compromise."
    ),
    "gws_drive_sharing_restricted": (
        "Google Workspace Drive sharing is not restricted. Users can share "
        "documents externally without controls, enabling data exfiltration "
        "through legitimate sharing mechanisms."
    ),
    "openstack_identity_admin_mfa": (
        "OpenStack Keystone admin accounts lack MFA. Compromised admin "
        "credentials grant full control over the private cloud infrastructure "
        "including compute, storage, and networking resources."
    ),
    "openstack_storage_volume_encryption": (
        "OpenStack Cinder volumes are not encrypted. Unencrypted block "
        "storage volumes expose data if access controls are bypassed or "
        "physical media is compromised."
    ),
    "openstack_network_sg_no_ssh_open": (
        "OpenStack security groups allow SSH from the internet. Exposed SSH "
        "on private cloud instances enables brute-force attacks and provides "
        "an entry point for lateral movement within the infrastructure."
    ),
    "openstack_identity_token_expiry": (
        "OpenStack Keystone token expiry is too long. Long-lived tokens "
        "increase the window for token theft and replay attacks, allowing "
        "attackers to maintain access after credential rotation."
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
    # ── OCI checks ──
    "oci_iam_user_mfa_enabled": (
        "OCI Identity ListUsers API followed by ListMfaTotpDevices per user. "
        "Checks at least one TOTP device in ACTIVE state. Fails if any "
        "console-enabled user has zero active MFA devices."
    ),
    "oci_iam_api_key_rotation": (
        "OCI Identity ListApiKeys API per user. Checks timeCreated for each "
        "API signing key. Fails if any key is older than 90 days."
    ),
    "oci_iam_policy_no_wildcard": (
        "OCI Identity ListPolicies API. Parses policy statements and checks "
        "for 'allow * to manage all-resources'. Fails if wildcard statements found."
    ),
    "oci_iam_admin_group_empty": (
        "OCI Identity GetGroup API for Administrators group. Lists members "
        "via ListUserGroupMemberships. Fails if non-essential users are members."
    ),
    "oci_network_sl_no_ssh_open": (
        "OCI VCN ListSecurityLists API. Checks ingressSecurityRules for "
        "rules where source is 0.0.0.0/0 and tcpOptions.destinationPortRange "
        "includes port 22."
    ),
    "oci_network_sl_no_rdp_open": (
        "OCI VCN ListSecurityLists API. Checks ingressSecurityRules for "
        "rules where source is 0.0.0.0/0 and tcpOptions.destinationPortRange "
        "includes port 3389."
    ),
    "oci_network_sl_no_unrestricted_ingress": (
        "OCI VCN ListSecurityLists API. Checks ingressSecurityRules for "
        "any rule with source 0.0.0.0/0 and protocol ALL."
    ),
    "oci_objectstorage_bucket_public_access": (
        "OCI ObjectStorage GetBucket API. Checks publicAccessType field. "
        "Fails if value is not NoPublicAccess."
    ),
    "oci_objectstorage_bucket_cmk_encryption": (
        "OCI ObjectStorage GetBucket API. Checks kmsKeyId field. Fails if "
        "bucket uses Oracle-managed keys instead of customer-managed KMS key."
    ),
    "oci_objectstorage_versioning_enabled": (
        "OCI ObjectStorage GetBucket API. Checks versioning field. Fails if "
        "versioning is not Enabled."
    ),
    "oci_compute_secure_boot": (
        "OCI Compute GetInstance API. Checks launchOptions.isSecureBootEnabled "
        "field. Fails if Secure Boot is not enabled on the instance."
    ),
    "oci_compute_imds_v2": (
        "OCI Compute GetInstance API. Checks instanceOptions."
        "areLegacyImdsEndpointsDisabled. Fails if legacy IMDSv1 endpoint is enabled."
    ),
    "oci_vault_key_rotation": (
        "OCI KMS ListKeys API. Checks timeOfLastRotation for each key. Fails "
        "if any key has not been rotated within 365 days."
    ),
    "oci_cloud_guard_enabled": (
        "OCI CloudGuard GetConfiguration API for the tenancy. Checks status "
        "field. Fails if Cloud Guard is not ENABLED."
    ),
    "oci_logging_audit_retention": (
        "OCI Logging GetLog API for audit log. Checks retentionDuration. "
        "Fails if retention is less than 365 days."
    ),
    "oci_db_autonomous_private_endpoint": (
        "OCI Database GetAutonomousDatabase API. Checks "
        "privateEndpointLabel and isAccessControlEnabled. Fails if database "
        "is accessible from public internet."
    ),
    "oci_oke_cluster_public_endpoint": (
        "OCI ContainerEngine GetCluster API. Checks "
        "endpointConfig.isPublicIpEnabled. Fails if Kubernetes API endpoint "
        "has a public IP."
    ),
    "oci_waf_enabled": (
        "OCI Waas ListWebAppFirewalls API. Checks if WAF policies are "
        "configured and active for public-facing services. Fails if no "
        "active WAF policy exists."
    ),
    # ── Alibaba Cloud checks ──
    "ali_ram_mfa_enabled": (
        "Alibaba Cloud RAM GetUser API per user. Checks MFABindRequired and "
        "ListVirtualMFADevices for active devices. Fails if any user with "
        "console access has no bound MFA device."
    ),
    "ali_ram_access_key_rotation": (
        "Alibaba Cloud RAM ListAccessKeys API per user. Checks CreateDate "
        "for each key. Fails if any active key is older than 90 days."
    ),
    "ali_ram_no_wildcard_policy": (
        "Alibaba Cloud RAM ListPolicies and GetPolicy API. Parses policy "
        "document for Action: '*' and Resource: '*'. Fails if wildcard found."
    ),
    "ali_ram_unused_users": (
        "Alibaba Cloud RAM GetUser API. Checks LastLoginDate for each user. "
        "Fails if any user has not logged in within 90 days."
    ),
    "ali_ram_policies_groups_only": (
        "Alibaba Cloud RAM ListPoliciesForUser API. Checks if policies are "
        "attached directly to users. Fails if any user has directly attached "
        "policies instead of group-based assignment."
    ),
    "ali_ecs_no_public_ip": (
        "Alibaba Cloud ECS DescribeInstances API. Checks PublicIpAddress "
        "field. Fails if any instance has a public IP assigned."
    ),
    "ali_ecs_sg_no_ssh_open": (
        "Alibaba Cloud ECS DescribeSecurityGroupAttribute API. Checks "
        "permissions for rules with SourceCidrIp 0.0.0.0/0 and PortRange "
        "22/22. Fails if open SSH rule found."
    ),
    "ali_ecs_sg_no_rdp_open": (
        "Alibaba Cloud ECS DescribeSecurityGroupAttribute API. Checks "
        "permissions for rules with SourceCidrIp 0.0.0.0/0 and PortRange "
        "3389/3389. Fails if open RDP rule found."
    ),
    "ali_ecs_sg_no_public_ingress": (
        "Alibaba Cloud ECS DescribeSecurityGroupAttribute API. Checks for "
        "any ingress rule with SourceCidrIp 0.0.0.0/0 and Policy Accept."
    ),
    "ali_oss_no_public_access": (
        "Alibaba Cloud OSS GetBucketAcl API. Checks ACL grant for public "
        "access. Fails if ACL is public-read or public-read-write."
    ),
    "ali_oss_encryption_enabled": (
        "Alibaba Cloud OSS GetBucketEncryption API. Checks if server-side "
        "encryption rule is configured. Fails if SSEAlgorithm is not set."
    ),
    "ali_oss_versioning_enabled": (
        "Alibaba Cloud OSS GetBucketVersioning API. Checks VersioningStatus. "
        "Fails if versioning is not Enabled."
    ),
    "ali_actiontrail_enabled": (
        "Alibaba Cloud ActionTrail DescribeTrails API. Checks for at least "
        "one active trail. Fails if no trails are configured or all are stopped."
    ),
    "ali_actiontrail_multi_region": (
        "Alibaba Cloud ActionTrail DescribeTrails API. Checks IsMultiRegion "
        "field for each trail. Fails if no trail covers all regions."
    ),
    "ali_sls_retention_365": (
        "Alibaba Cloud SLS GetLogstore API. Checks ttl (retention days). "
        "Fails if retention is less than 365 days."
    ),
    "ali_security_center_enabled": (
        "Alibaba Cloud Security Center DescribeVersionConfig API. Checks "
        "if Security Center is activated. Fails if not enabled."
    ),
    "ali_sas_agents_installed": (
        "Alibaba Cloud Security Center DescribeCloudCenterInstances API. "
        "Checks agent status per instance. Fails if agents not installed."
    ),
    "ali_rds_no_public_access": (
        "Alibaba Cloud RDS DescribeDBInstanceNetInfo API. Checks for public "
        "connection strings. Fails if any public endpoint is configured."
    ),
    "ali_rds_encryption_enabled": (
        "Alibaba Cloud RDS DescribeDBInstanceAttribute API. Checks "
        "EncryptionKey field. Fails if TDE or disk encryption not enabled."
    ),
    "ali_kms_key_rotation": (
        "Alibaba Cloud KMS DescribeKey API per key. Checks "
        "AutomaticRotation and LastRotationDate. Fails if rotation disabled "
        "or last rotation exceeds 365 days."
    ),
    "ali_ack_private_cluster": (
        "Alibaba Cloud ACK DescribeClusterDetail API. Checks "
        "masterUrl for public endpoint. Fails if public API endpoint exists."
    ),
    "ali_waf_enabled": (
        "Alibaba Cloud WAF DescribeInstanceInfo API. Checks if WAF instance "
        "is active. Fails if no active WAF instance for public domains."
    ),
    "ali_vpc_flow_logs": (
        "Alibaba Cloud VPC DescribeFlowLogs API. Checks for active flow "
        "logs per VPC. Fails if VPC has no flow log configured."
    ),
    # ── Kubernetes checks ──
    "k8s_rbac_no_wildcard_cluster_admin": (
        "Kubernetes RBAC API list ClusterRoleBindings and ClusterRoles. "
        "Checks rules[].resources and rules[].verbs for wildcard '*'. "
        "Fails if non-system ClusterRole has wildcard permissions."
    ),
    "k8s_no_pods_in_default": (
        "Kubernetes Core API list pods in default namespace. Fails if any "
        "non-system pods are running in the default namespace."
    ),
    "k8s_namespace_network_policy": (
        "Kubernetes Networking API list NetworkPolicies per namespace. "
        "Fails if any active namespace has zero network policies defined."
    ),
    "k8s_admission_pod_security": (
        "Kubernetes API check namespace labels for pod-security.kubernetes.io "
        "enforcement. Fails if Pod Security Standards not enforced."
    ),
    "k8s_secrets_encrypted_etcd": (
        "Kubernetes API server --encryption-provider-config flag. Checks "
        "EncryptionConfiguration for aescbc or secretbox providers. Fails "
        "if secrets stored in identity (plaintext) provider."
    ),
    "k8s_secrets_no_env_vars": (
        "Kubernetes Core API list Pods. Checks containers[].env and "
        "containers[].envFrom for secretKeyRef. Fails if secrets exposed "
        "as environment variables instead of volume mounts."
    ),
    "k8s_api_audit_logging": (
        "Kubernetes API server --audit-policy-file flag. Checks if audit "
        "policy is configured and active. Fails if no audit policy defined."
    ),
    "k8s_rbac_no_default_sa_token": (
        "Kubernetes Core API get ServiceAccount 'default' per namespace. "
        "Checks automountServiceAccountToken field. Fails if set to true."
    ),
    "k8s_no_privileged_containers": (
        "Kubernetes Core API list Pods. Checks containers[].securityContext."
        "privileged. Fails if any container runs in privileged mode."
    ),
    "k8s_no_host_pid": (
        "Kubernetes Core API list Pods. Checks spec.hostPID field. "
        "Fails if any pod has hostPID set to true."
    ),
    "k8s_no_host_network": (
        "Kubernetes Core API list Pods. Checks spec.hostNetwork field. "
        "Fails if any pod has hostNetwork set to true."
    ),
    "k8s_image_pull_policy_always": (
        "Kubernetes Core API list Pods. Checks containers[].imagePullPolicy. "
        "Fails if policy is not Always for non-pinned image tags."
    ),
    "k8s_resource_limits_set": (
        "Kubernetes Core API list Pods. Checks containers[].resources.limits "
        "for cpu and memory. Fails if any container lacks resource limits."
    ),
    "k8s_no_automount_sa_token": (
        "Kubernetes Core API list Pods. Checks spec."
        "automountServiceAccountToken. Fails if token auto-mounted on pods "
        "that don't need API access."
    ),
    # ── SaaS checks ──
    "servicenow_users_mfa_enabled": (
        "ServiceNow sys_properties API. Fetches glide.authenticate.multifactor "
        "property. Cross-checks with sys_user table for active users. Fails "
        "if MFA not enforced for all active users."
    ),
    "servicenow_ac_acl_active": (
        "ServiceNow sys_security_acl API. Lists ACL rules and checks active "
        "flag. Fails if critical ACLs are inactive or bypassed."
    ),
    "servicenow_iv_escape_script": (
        "ServiceNow sys_properties API. Checks glide.ui.escape_all_script "
        "property. Fails if script escaping is not enabled."
    ),
    "servicenow_encryption_at_rest": (
        "ServiceNow sys_properties API. Checks encryption configuration "
        "properties. Fails if column-level encryption not active."
    ),
    "servicenow_session_timeout": (
        "ServiceNow sys_properties API. Checks glide.ui.session_timeout "
        "property value. Fails if timeout exceeds 30 minutes."
    ),
    "m365_user_mfa_registered": (
        "Microsoft Graph API /reports/credentialUserRegistrationDetails. "
        "Checks isMfaRegistered for each user. Fails if any active user "
        "has not registered for MFA."
    ),
    "m365_ca_block_legacy_auth": (
        "Microsoft Graph API /identity/conditionalAccess/policies. Checks "
        "for a policy with conditions.clientAppTypes including "
        "exchangeActiveSync and other. Fails if no blocking policy exists."
    ),
    "m365_admin_mfa_enforced": (
        "Microsoft Graph API /directoryRoles and /users. Checks MFA "
        "registration status for users with admin roles. Fails if any "
        "admin lacks MFA enforcement."
    ),
    "m365_defender_sensor_active": (
        "Microsoft Graph Security API /security/alerts. Checks Defender "
        "sensor status via device management API. Fails if sensors inactive."
    ),
    "m365_safe_attachments_enabled": (
        "Microsoft Graph API /security/threatManagement/policies. Checks "
        "Safe Attachments policy configuration. Fails if not enabled for "
        "all mailboxes."
    ),
    "m365_safe_links_enabled": (
        "Microsoft Graph API /security/threatManagement/policies. Checks "
        "Safe Links policy for URL scanning on click. Fails if disabled."
    ),
    "m365_dlp_policies_configured": (
        "Microsoft Compliance API /dlp/policies. Lists DLP policies. "
        "Fails if no DLP policies are configured or all are disabled."
    ),
    "m365_external_sharing_restricted": (
        "Microsoft Graph API SharePoint admin settings. Checks "
        "sharingCapability. Fails if set to ExternalUserAndGuestSharing "
        "without domain restrictions."
    ),
    "m365_audit_log_enabled": (
        "Microsoft Graph API /security/auditLogs. Checks unified audit "
        "log status. Fails if audit logging is not enabled."
    ),
    "salesforce_user_mfa_enabled": (
        "Salesforce REST API /sobjects/User. Checks UserPreferencesHasMfa "
        "and SessionSecurityLevel settings. Fails if MFA not required."
    ),
    "salesforce_encryption_at_rest": (
        "Salesforce Shield API /services/data/encryption. Checks Platform "
        "Encryption status and tenant secret. Fails if not configured."
    ),
    "salesforce_field_level_security": (
        "Salesforce REST API /sobjects/FieldPermissions. Checks field "
        "accessibility per profile. Fails if sensitive fields lack FLS."
    ),
    "salesforce_session_timeout": (
        "Salesforce REST API /sobjects/SecuritySettings. Checks "
        "sessionTimeout value. Fails if timeout exceeds 2 hours."
    ),
    "salesforce_login_ip_ranges": (
        "Salesforce REST API /sobjects/Profile. Checks loginIpRanges per "
        "profile. Fails if no IP restrictions configured for admin profiles."
    ),
    "snowflake_user_mfa_enabled": (
        "Snowflake SHOW USERS query. Checks ext_authn_duo column and "
        "has_mfa property. Fails if MFA not enabled for active users."
    ),
    "snowflake_network_policy_set": (
        "Snowflake SHOW NETWORK POLICIES query. Checks for active "
        "policies with allowed_ip_list. Fails if no network policy set."
    ),
    "snowflake_column_masking_policies": (
        "Snowflake SHOW MASKING POLICIES query. Checks policy assignments "
        "on sensitive columns. Fails if no masking policies configured."
    ),
    "snowflake_query_audit_enabled": (
        "Snowflake ACCOUNT_USAGE.QUERY_HISTORY view. Checks if access "
        "history tracking is active. Fails if not available."
    ),
    "github_org_2fa_required": (
        "GitHub API GET /orgs/{org}. Checks two_factor_requirement_enabled "
        "field. Fails if 2FA not required for organization members."
    ),
    "github_repo_secret_scanning": (
        "GitHub API GET /repos/{owner}/{repo}. Checks "
        "security_and_analysis.secret_scanning.status. Fails if disabled."
    ),
    "github_repo_branch_protection": (
        "GitHub API GET /repos/{owner}/{repo}/branches/{branch}/protection. "
        "Checks required_pull_request_reviews and required_status_checks. "
        "Fails if protection rules not configured on default branch."
    ),
    "github_actions_restricted": (
        "GitHub API GET /orgs/{org}/actions/permissions. Checks "
        "allowed_actions policy. Fails if set to 'all' without restrictions."
    ),
    "github_repo_vulnerability_alerts": (
        "GitHub API GET /repos/{owner}/{repo}/vulnerability-alerts. "
        "Checks if Dependabot alerts are enabled. Fails if disabled."
    ),
    "cloudflare_tls_full_strict": (
        "Cloudflare API GET /zones/{id}/settings/ssl. Checks value field. "
        "Fails if TLS mode is not 'strict' (Full Strict)."
    ),
    "cloudflare_waf_managed_rules": (
        "Cloudflare API GET /zones/{id}/firewall/waf/packages. Checks for "
        "active managed ruleset. Fails if WAF not enabled."
    ),
    "cloudflare_bot_management": (
        "Cloudflare API GET /zones/{id}/bot_management. Checks if bot "
        "management is enabled and configured. Fails if disabled."
    ),
    "gws_user_2fa_enrolled": (
        "Google Workspace Admin SDK Directory API users.list. Checks "
        "isEnrolledIn2Sv for each user. Fails if not enrolled."
    ),
    "gws_admin_2fa_enforced": (
        "Google Workspace Admin SDK Directory API users.list filtered by "
        "isAdmin=true. Checks isEnforcedIn2Sv. Fails if not enforced."
    ),
    "gws_email_dmarc_configured": (
        "DNS TXT record lookup for _dmarc.{domain}. Checks for valid DMARC "
        "record with p=reject or p=quarantine. Fails if missing or p=none."
    ),
    "gws_email_spf_configured": (
        "DNS TXT record lookup for {domain}. Checks for valid SPF record "
        "with -all or ~all mechanism. Fails if missing."
    ),
    "gws_drive_sharing_restricted": (
        "Google Workspace Admin SDK Settings API. Checks Drive sharing "
        "settings for external sharing restrictions. Fails if unrestricted."
    ),
    "openstack_identity_admin_mfa": (
        "OpenStack Keystone GET /v3/users?is_admin=true. Cross-checks "
        "with credential API for TOTP credentials. Fails if admin users "
        "lack MFA credentials."
    ),
    "openstack_storage_volume_encryption": (
        "OpenStack Cinder GET /volumes/detail. Checks encrypted field "
        "for each volume. Fails if any volume is not encrypted."
    ),
    "openstack_network_sg_no_ssh_open": (
        "OpenStack Neutron GET /security-group-rules. Checks for rules "
        "with remote_ip_prefix 0.0.0.0/0 and port_range_min 22. Fails "
        "if open SSH rule exists."
    ),
    "openstack_identity_token_expiry": (
        "OpenStack Keystone configuration check for token expiration. "
        "Checks [token].expiration in keystone.conf. Fails if greater "
        "than 3600 seconds (1 hour)."
    ),
}
