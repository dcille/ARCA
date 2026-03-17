"""MITRE ATT&CK mapping for cloud security checks.

Maps security check IDs to MITRE ATT&CK techniques, provides technique metadata,
check descriptions (security impact of failures), and evidence descriptions.
"""

# Cloud-relevant MITRE ATT&CK techniques
MITRE_TECHNIQUES = {
    # Initial Access
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "initial-access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls and grant access to remote systems and services.",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1078.004": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "initial-access",
        "description": "Adversaries may obtain and abuse credentials of a cloud account to gain initial access. Cloud accounts may be compromised through phishing, credential stuffing, or exploitation of weak credentials.",
        "url": "https://attack.mitre.org/techniques/T1078/004/",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "description": "Adversaries may attempt to exploit vulnerabilities in internet-facing services, including cloud management consoles, APIs, and deployed applications with unpatched or misconfigured security settings.",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1199": {
        "name": "Trusted Relationship",
        "tactic": "initial-access",
        "description": "Adversaries may breach or leverage organizations who have access to intended victims through trusted third-party relationships, such as cross-account IAM roles or federated identity providers.",
        "url": "https://attack.mitre.org/techniques/T1199/",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "initial-access",
        "description": "Adversaries may send phishing messages to gain access to victim systems, including cloud console credentials. MFA is a key defense against phished credentials being used for unauthorized access.",
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    # Execution
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands. In cloud environments, this includes abusing cloud CLI tools, Lambda functions, or Azure Functions.",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "execution",
        "description": "Adversaries may rely upon specific user actions to gain execution, such as running malicious code through cloud function invocations or container deployments.",
        "url": "https://attack.mitre.org/techniques/T1204/",
    },
    "T1648": {
        "name": "Serverless Execution",
        "tactic": "execution",
        "description": "Adversaries may abuse serverless computing services (Lambda, Azure Functions, Cloud Functions) to execute malicious code without managing the underlying infrastructure.",
        "url": "https://attack.mitre.org/techniques/T1648/",
    },
    # Persistence
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "persistence",
        "description": "Adversaries may manipulate accounts to maintain access. This includes adding credentials to cloud accounts, modifying IAM policies, or creating new access keys for persistence.",
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "persistence",
        "description": "Adversaries may create accounts in cloud environments to maintain persistent access. Without proper IAM monitoring and logging, rogue accounts can go undetected.",
        "url": "https://attack.mitre.org/techniques/T1136/",
    },
    "T1136.003": {
        "name": "Create Account: Cloud Account",
        "tactic": "persistence",
        "description": "Adversaries may create new cloud accounts to maintain access. CloudTrail and equivalent logging services are essential for detecting unauthorized account creation.",
        "url": "https://attack.mitre.org/techniques/T1136/003/",
    },
    "T1525": {
        "name": "Implant Internal Image",
        "tactic": "persistence",
        "description": "Adversaries may implant backdoors in cloud container images or VM images, allowing persistence whenever the image is deployed.",
        "url": "https://attack.mitre.org/techniques/T1525/",
    },
    "T1556": {
        "name": "Modify Authentication Process",
        "tactic": "persistence",
        "description": "Adversaries may modify authentication mechanisms to access user credentials or enable unauthorized access, such as weakening password policies or disabling MFA requirements.",
        "url": "https://attack.mitre.org/techniques/T1556/",
    },
    # Privilege Escalation
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "privilege-escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevated privileges. In cloud, this includes exploiting overly permissive IAM roles or privilege escalation paths.",
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
    "T1484": {
        "name": "Domain Policy Modification",
        "tactic": "privilege-escalation",
        "description": "Adversaries may modify cloud policies to escalate privileges, including IAM policies, security group rules, or organizational policies.",
        "url": "https://attack.mitre.org/techniques/T1484/",
    },
    # Defense Evasion
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "defense-evasion",
        "description": "Adversaries may maliciously modify components of cloud security tools (CloudTrail, GuardDuty, Security Center) to prevent detection of their activities.",
        "url": "https://attack.mitre.org/techniques/T1562/",
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "defense-evasion",
        "description": "Adversaries may disable or modify security monitoring tools such as GuardDuty, CloudTrail, or Azure Monitor to evade detection.",
        "url": "https://attack.mitre.org/techniques/T1562/001/",
    },
    "T1562.008": {
        "name": "Impair Defenses: Disable Cloud Logs",
        "tactic": "defense-evasion",
        "description": "Adversaries may disable cloud logging capabilities (CloudTrail, VPC Flow Logs, Activity Logs) to prevent the collection of audit data that could be used to detect their activity.",
        "url": "https://attack.mitre.org/techniques/T1562/008/",
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "defense-evasion",
        "description": "Adversaries may delete or modify artifacts (logs, events) to remove evidence of their intrusion. Log integrity validation and immutable storage are key defenses.",
        "url": "https://attack.mitre.org/techniques/T1070/",
    },
    "T1578": {
        "name": "Modify Cloud Compute Infrastructure",
        "tactic": "defense-evasion",
        "description": "Adversaries may modify cloud compute infrastructure (snapshots, images, instances) to evade defenses or establish persistence.",
        "url": "https://attack.mitre.org/techniques/T1578/",
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic": "defense-evasion",
        "description": "Adversaries may use alternate authentication material such as API keys, session tokens, or SAS tokens to move laterally or bypass normal authentication.",
        "url": "https://attack.mitre.org/techniques/T1550/",
    },
    # Credential Access
    "T1528": {
        "name": "Steal Application Access Token",
        "tactic": "credential-access",
        "description": "Adversaries can steal application access tokens (OAuth, JWT, API keys) to assume the identity of applications and access cloud resources.",
        "url": "https://attack.mitre.org/techniques/T1528/",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "credential-access",
        "description": "Adversaries may search compromised systems for insecurely stored credentials, including AWS access keys, Azure service principal credentials, or GCP service account keys.",
        "url": "https://attack.mitre.org/techniques/T1552/",
    },
    "T1552.005": {
        "name": "Unsecured Credentials: Cloud Instance Metadata API",
        "tactic": "credential-access",
        "description": "Adversaries may attempt to access the Cloud Instance Metadata API (IMDS) to collect credentials and sensitive data. IMDSv2 helps mitigate SSRF-based credential theft.",
        "url": "https://attack.mitre.org/techniques/T1552/005/",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "credential-access",
        "description": "Adversaries may use brute force techniques to attempt access to cloud accounts. Strong password policies and MFA are key defenses against credential brute-forcing.",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1621": {
        "name": "Multi-Factor Authentication Request Generation",
        "tactic": "credential-access",
        "description": "Adversaries may attempt to bypass MFA by generating repeated MFA requests (MFA fatigue/bombing). Proper MFA configuration is essential.",
        "url": "https://attack.mitre.org/techniques/T1621/",
    },
    # Discovery
    "T1580": {
        "name": "Cloud Infrastructure Discovery",
        "tactic": "discovery",
        "description": "Adversaries may enumerate cloud infrastructure (instances, storage, networks) after gaining access. Reducing public exposure limits discovery opportunities.",
        "url": "https://attack.mitre.org/techniques/T1580/",
    },
    "T1526": {
        "name": "Cloud Service Discovery",
        "tactic": "discovery",
        "description": "Adversaries may attempt to discover cloud services running on systems after gaining access, including storage services, databases, and compute instances.",
        "url": "https://attack.mitre.org/techniques/T1526/",
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "tactic": "discovery",
        "description": "Adversaries may attempt to discover cloud IAM groups and their permissions to understand access levels and identify escalation paths.",
        "url": "https://attack.mitre.org/techniques/T1069/",
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "discovery",
        "description": "Adversaries may attempt to enumerate cloud accounts and their attributes. VPC flow logs and audit logs help detect unauthorized enumeration.",
        "url": "https://attack.mitre.org/techniques/T1087/",
    },
    # Lateral Movement
    "T1021": {
        "name": "Remote Services",
        "tactic": "lateral-movement",
        "description": "Adversaries may use remote services (SSH, RDP) to access cloud instances. Open security group ports increase the attack surface for lateral movement.",
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    "T1563": {
        "name": "Remote Service Session Hijacking",
        "tactic": "lateral-movement",
        "description": "Adversaries may hijack existing remote service sessions to move laterally within cloud environments using stolen session tokens or cookies.",
        "url": "https://attack.mitre.org/techniques/T1563/",
    },
    # Collection
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "collection",
        "description": "Adversaries may access data from cloud storage buckets (S3, Blob, GCS). Publicly accessible buckets without encryption are prime targets for data theft.",
        "url": "https://attack.mitre.org/techniques/T1530/",
    },
    "T1213": {
        "name": "Data from Information Repositories",
        "tactic": "collection",
        "description": "Adversaries may collect data from cloud databases, data lakes, and repositories. Encryption and access controls protect data at rest.",
        "url": "https://attack.mitre.org/techniques/T1213/",
    },
    # Exfiltration
    "T1537": {
        "name": "Transfer Data to Cloud Account",
        "tactic": "exfiltration",
        "description": "Adversaries may exfiltrate data by transferring it to another cloud account they control, using services like S3 cross-account access or snapshots.",
        "url": "https://attack.mitre.org/techniques/T1537/",
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "exfiltration",
        "description": "Adversaries may use legitimate cloud web services to exfiltrate data, making detection difficult. Network monitoring and DLP controls are key defenses.",
        "url": "https://attack.mitre.org/techniques/T1567/",
    },
    # Impact
    "T1485": {
        "name": "Data Destruction",
        "tactic": "impact",
        "description": "Adversaries may destroy data in cloud storage, databases, and backups. Versioning, backups, and deletion protection are critical defenses.",
        "url": "https://attack.mitre.org/techniques/T1485/",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "impact",
        "description": "Adversaries may encrypt data on cloud resources (ransomware). KMS key management and backup/DR strategies help mitigate ransomware impact.",
        "url": "https://attack.mitre.org/techniques/T1486/",
    },
    "T1496": {
        "name": "Resource Hijacking",
        "tactic": "impact",
        "description": "Adversaries may leverage compromised cloud resources for cryptomining or other resource-intensive operations. Monitoring and cost alerts help detect hijacking.",
        "url": "https://attack.mitre.org/techniques/T1496/",
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "impact",
        "description": "Adversaries may launch denial of service attacks against cloud infrastructure. Network security groups and WAF rules help mitigate exposure.",
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
    "T1531": {
        "name": "Account Access Removal",
        "tactic": "impact",
        "description": "Adversaries may interrupt availability by disabling accounts, deleting IAM resources, or modifying permissions to lock out legitimate users.",
        "url": "https://attack.mitre.org/techniques/T1531/",
    },
}

# Mapping: check_id -> list of MITRE technique IDs
CHECK_TO_MITRE = {
    # AWS IAM
    "iam_root_mfa_enabled": ["T1078", "T1078.004", "T1566", "T1110"],
    "iam_password_policy_strong": ["T1110", "T1078", "T1556"],
    "iam_password_policy_rotation": ["T1078", "T1110", "T1552"],
    "iam_user_mfa_enabled": ["T1078", "T1078.004", "T1566", "T1621"],
    "iam_access_key_rotation": ["T1552", "T1528", "T1098"],
    # AWS S3
    "s3_bucket_public_access_blocked": ["T1530", "T1190", "T1537"],
    "s3_bucket_encryption_enabled": ["T1530", "T1213"],
    "s3_bucket_logging_enabled": ["T1562.008", "T1070"],
    "s3_bucket_versioning_enabled": ["T1485", "T1486"],
    # AWS EC2
    "ec2_sg_open_port_22": ["T1021", "T1190", "T1498"],
    "ec2_sg_open_port_3389": ["T1021", "T1190", "T1498"],
    "ec2_ebs_volume_encrypted": ["T1213", "T1530"],
    "ec2_imdsv2_required": ["T1552.005", "T1528"],
    # AWS RDS
    "rds_encryption_enabled": ["T1213", "T1530"],
    "rds_public_access_disabled": ["T1190", "T1580"],
    "rds_multi_az_enabled": ["T1485", "T1498"],
    "rds_backup_enabled": ["T1485", "T1486"],
    # AWS CloudTrail
    "cloudtrail_multiregion": ["T1562.008", "T1070", "T1562"],
    "cloudtrail_log_validation": ["T1070", "T1562.008"],
    "cloudtrail_encrypted": ["T1070", "T1530"],
    # AWS KMS
    "kms_key_rotation_enabled": ["T1486", "T1552"],
    # AWS VPC
    "vpc_flow_logs_enabled": ["T1562.008", "T1070", "T1580"],
    # AWS GuardDuty / Config
    "guardduty_enabled": ["T1562.001", "T1580", "T1526"],
    "config_recorder_enabled": ["T1562.001", "T1578"],
    # AWS EKS
    "eks_cluster_logging": ["T1562.008", "T1070"],
    "eks_endpoint_public_access": ["T1190", "T1580"],
    # AWS Lambda
    "lambda_function_public_access": ["T1190", "T1648"],
    # AWS ECS
    "ecs_task_definition_no_root": ["T1548", "T1525"],
    # AWS Encryption
    "sns_topic_encrypted": ["T1213", "T1530"],
    "sqs_queue_encrypted": ["T1213", "T1530"],
    "efs_encryption_enabled": ["T1213", "T1530"],
    "dynamodb_table_encrypted_kms": ["T1213", "T1530"],
    "dynamodb_pitr_enabled": ["T1485", "T1486"],
    "elasticache_encryption_in_transit": ["T1557", "T1040"],
    "elasticsearch_encrypted_at_rest": ["T1213", "T1530"],
    # AWS Secrets / Logs
    "secretsmanager_rotation_enabled": ["T1552", "T1528"],
    "cloudwatch_log_group_retention": ["T1562.008", "T1070"],
    # Azure
    "azure_iam_owner_count": ["T1078", "T1548", "T1484"],
    "azure_storage_https_only": ["T1557", "T1040"],
    "azure_storage_tls_12": ["T1557", "T1040"],
    "azure_storage_no_public_access": ["T1530", "T1190"],
    "azure_nsg_open_port_22": ["T1021", "T1190", "T1498"],
    "azure_nsg_open_port_3389": ["T1021", "T1190", "T1498"],
    "azure_network_watcher_enabled": ["T1562.008", "T1580"],
    "azure_vm_disk_encryption": ["T1213", "T1530"],
    "azure_sql_auditing_enabled": ["T1562.008", "T1070"],
    "azure_sql_tls_12": ["T1557", "T1040"],
    "azure_keyvault_soft_delete": ["T1485", "T1531"],
    "azure_keyvault_purge_protection": ["T1485", "T1531"],
    "azure_monitor_log_profile": ["T1562.008", "T1070"],
    "azure_appservice_https_only": ["T1557", "T1040"],
    "azure_appservice_tls_12": ["T1557", "T1040"],
    # GCP
    "gcp_iam_no_public_access": ["T1078", "T1190", "T1548"],
    "gcp_compute_no_external_ip": ["T1190", "T1580", "T1021"],
    "gcp_compute_os_login": ["T1078", "T1136"],
    "gcp_storage_uniform_access": ["T1530", "T1548"],
    "gcp_sql_no_public_ip": ["T1190", "T1580"],
    "gcp_sql_ssl_required": ["T1557", "T1040"],
    "gcp_kms_key_rotation": ["T1486", "T1552"],
    "gcp_gke_private_cluster": ["T1190", "T1580"],
    "gcp_gke_network_policy": ["T1021", "T1498"],
    "gcp_firewall_open_22": ["T1021", "T1190"],
    "gcp_firewall_open_3389": ["T1021", "T1190"],
    # OCI
    "oci_iam_user_mfa_enabled": ["T1078", "T1566", "T1621"],
    "oci_iam_admin_mfa_enabled": ["T1078", "T1566"],
    "oci_network_sl_no_ssh_open": ["T1021", "T1190"],
    "oci_network_sl_no_rdp_open": ["T1021", "T1190"],
    "oci_network_vcn_flow_logs": ["T1562.008", "T1070"],
    "oci_objectstorage_bucket_public_access": ["T1530", "T1190"],
    "oci_objectstorage_bucket_cmk_encryption": ["T1213", "T1530"],
    "oci_cloud_guard_enabled": ["T1562.001", "T1580"],
    # Alibaba
    "alibaba_iam_ram_root_mfa_enabled": ["T1078", "T1566", "T1110"],
    "alibaba_iam_ram_user_mfa_enabled": ["T1078", "T1566", "T1621"],
    "alibaba_network_sg_no_ssh_open": ["T1021", "T1190"],
    "alibaba_network_sg_no_rdp_open": ["T1021", "T1190"],
    "alibaba_storage_oss_public_access_blocked": ["T1530", "T1190"],
    "alibaba_storage_oss_encryption_enabled": ["T1213", "T1530"],
    "alibaba_logging_actiontrail_enabled": ["T1562.008", "T1070"],
}

# Human-readable security impact descriptions for when a check FAILS
CHECK_DESCRIPTIONS = {
    # AWS IAM
    "iam_root_mfa_enabled": "The root account lacks multi-factor authentication. An attacker who compromises root credentials gains unrestricted access to the entire AWS account, including billing, all services, and the ability to create/delete any resource. This is the highest-impact single point of failure.",
    "iam_password_policy_strong": "Weak password policy allows users to set easily guessable passwords. Attackers can use brute-force or credential-stuffing attacks to compromise IAM user accounts and gain persistent access to cloud resources.",
    "iam_password_policy_rotation": "Without password rotation, compromised credentials remain valid indefinitely. Long-lived passwords increase the window of opportunity for attackers who have stolen credentials through phishing or data breaches.",
    "iam_user_mfa_enabled": "IAM users without MFA are vulnerable to credential theft via phishing, keyloggers, or credential stuffing. A single compromised password grants the attacker full access to that user's permissions without any second verification factor.",
    "iam_access_key_rotation": "Long-lived access keys that are not rotated increase the risk of credential compromise. If an old key is leaked (e.g., in code repos, logs, or backups), attackers can use it for programmatic access to AWS services.",
    # AWS S3
    "s3_bucket_public_access_blocked": "Publicly accessible S3 buckets expose sensitive data to the internet. Attackers routinely scan for open buckets to steal PII, credentials, backups, and intellectual property. This is one of the most common causes of cloud data breaches.",
    "s3_bucket_encryption_enabled": "Unencrypted S3 data is vulnerable if the underlying storage is compromised or if bucket access controls are misconfigured. Server-side encryption provides a last line of defense against unauthorized data access.",
    "s3_bucket_logging_enabled": "Without access logging, unauthorized reads, writes, and deletes to S3 objects go undetected. Attackers can exfiltrate or tamper with data without leaving an audit trail, hindering incident response and forensics.",
    "s3_bucket_versioning_enabled": "Without versioning, deleted or overwritten objects cannot be recovered. Ransomware attacks and accidental deletions result in permanent data loss. Versioning enables recovery from both malicious and accidental modifications.",
    # AWS EC2
    "ec2_sg_open_port_22": "SSH (port 22) open to the internet allows brute-force login attempts from any IP address. Automated botnets continuously scan for open SSH ports to deploy cryptominers, backdoors, and ransomware on compromised instances.",
    "ec2_sg_open_port_3389": "RDP (port 3389) open to the internet is a high-risk exposure. RDP is among the most exploited remote access protocols; exposed instances are targeted by ransomware operators and credential-spraying attacks within minutes.",
    "ec2_ebs_volume_encrypted": "Unencrypted EBS volumes expose data if snapshots are shared, volumes are detached, or if the underlying hardware is decommissioned. Encryption at rest protects against physical theft and unauthorized snapshot access.",
    "ec2_imdsv2_required": "IMDSv1 is vulnerable to Server-Side Request Forgery (SSRF) attacks that allow attackers to steal IAM role credentials from the instance metadata service. IMDSv2 requires session tokens that mitigate this class of attacks.",
    # AWS RDS
    "rds_encryption_enabled": "Unencrypted databases expose sensitive data (PII, credentials, financial records) if snapshots are shared or backup media is compromised. Encryption at rest is a fundamental data protection control required by most compliance frameworks.",
    "rds_public_access_disabled": "Publicly accessible databases are directly attackable from the internet. SQL injection, brute-force authentication, and exploitation of known database vulnerabilities can lead to full data breach and system compromise.",
    "rds_multi_az_enabled": "Single-AZ deployments have no automatic failover. An AZ outage or instance failure results in database downtime, potentially causing service disruption and data loss for dependent applications.",
    "rds_backup_enabled": "Without automated backups, database data cannot be recovered after accidental deletion, corruption, or ransomware attacks. Backups are the primary recovery mechanism for destructive incidents.",
    # AWS CloudTrail
    "cloudtrail_multiregion": "CloudTrail limited to a single region leaves activity in other regions completely unmonitored. Attackers deliberately operate in unmonitored regions to avoid detection while performing reconnaissance and data exfiltration.",
    "cloudtrail_log_validation": "Without log file validation, attackers can modify or delete CloudTrail logs to cover their tracks. Integrity validation detects tampering with audit logs, which is critical for forensic investigations.",
    "cloudtrail_encrypted": "Unencrypted CloudTrail logs may expose sensitive API activity details if the S3 bucket is compromised. Encrypted logs protect the confidentiality of audit data including API parameters and caller identities.",
    # AWS KMS
    "kms_key_rotation_enabled": "Without automatic key rotation, a compromised encryption key remains valid indefinitely. Regular rotation limits the blast radius of a key compromise and aligns with cryptographic best practices.",
    # AWS VPC
    "vpc_flow_logs_enabled": "Without VPC Flow Logs, network traffic patterns are invisible. Attackers can perform lateral movement, data exfiltration, and port scanning without leaving network-layer evidence for security teams to investigate.",
    # AWS GuardDuty / Config
    "guardduty_enabled": "Without GuardDuty, the account lacks automated threat detection for compromised instances, unauthorized access patterns, and malicious activity. Attackers can operate freely without triggering security alerts.",
    "config_recorder_enabled": "Without AWS Config, configuration changes to resources go untracked. Attackers can modify security groups, IAM policies, and other resources without generating a configuration change audit trail.",
    # AWS EKS
    "eks_cluster_logging": "Without EKS control plane logging, API server activity, authentication events, and scheduler decisions are not recorded. This makes it impossible to investigate unauthorized container deployments or cluster compromises.",
    "eks_endpoint_public_access": "A publicly accessible EKS API endpoint allows attackers to attempt authentication and exploit Kubernetes API vulnerabilities from the internet, increasing the cluster's attack surface.",
    # AWS Lambda / ECS
    "lambda_function_public_access": "Publicly invocable Lambda functions can be triggered by any attacker, potentially leading to data exfiltration, resource abuse, or injection attacks through function input parameters.",
    "ecs_task_definition_no_root": "Containers running as root can escape container isolation and compromise the host. An attacker who exploits a vulnerability in a root container can gain full control of the underlying EC2 instance.",
    # AWS Encryption services
    "sns_topic_encrypted": "Unencrypted SNS topics may expose notification contents including sensitive alerts, PII, and system events to unauthorized parties if topic access controls are misconfigured.",
    "sqs_queue_encrypted": "Unencrypted SQS messages can be read by anyone with queue access. Messages often contain sensitive application data, credentials, and PII that should be protected at rest.",
    "efs_encryption_enabled": "Unencrypted EFS file systems expose shared data if mount targets are improperly secured or if the underlying storage is compromised. Many compliance frameworks require encryption of shared file systems.",
    "dynamodb_table_encrypted_kms": "DynamoDB tables without customer-managed KMS encryption use default AWS-managed keys, providing less control over key lifecycle and access policies. CMK encryption enables granular access control.",
    "dynamodb_pitr_enabled": "Without Point-in-Time Recovery, DynamoDB table data cannot be restored to a specific moment. Accidental deletions, application bugs, or ransomware result in permanent data loss.",
    "elasticache_encryption_in_transit": "Unencrypted ElastiCache traffic is vulnerable to network sniffing and man-in-the-middle attacks. Session data, cached credentials, and application state transmitted in cleartext can be intercepted.",
    "elasticsearch_encrypted_at_rest": "Unencrypted Elasticsearch domains expose indexed data (logs, application data, PII) if the underlying storage is compromised or domain access policies are misconfigured.",
    "secretsmanager_rotation_enabled": "Secrets without automatic rotation remain valid indefinitely. If a secret is leaked or compromised, the extended validity window gives attackers prolonged access to protected resources.",
    "cloudwatch_log_group_retention": "Log groups without defined retention may either lose logs prematurely or accumulate excessive costs. Proper retention ensures logs are available for incident investigation while managing storage costs.",
    # Azure
    "azure_iam_owner_count": "Excessive Owner-role assignments increase the blast radius of a single compromised account. Each Owner can modify all resources, delete data, and grant access to others, making privilege minimization critical.",
    "azure_storage_https_only": "Allowing HTTP traffic to storage accounts exposes data to interception in transit. Attackers on the network path can capture authentication tokens and stored data through man-in-the-middle attacks.",
    "azure_storage_tls_12": "Older TLS versions (1.0, 1.1) have known vulnerabilities that allow attackers to decrypt traffic. Enforcing TLS 1.2+ ensures data in transit is protected by modern cryptographic standards.",
    "azure_storage_no_public_access": "Publicly accessible storage containers expose blobs to the internet. Attackers scan for open containers to steal backups, database exports, and application data, leading to data breaches.",
    "azure_nsg_open_port_22": "SSH open to the internet on Azure VMs allows brute-force attacks from any source. Automated scanners continuously probe for weak SSH credentials to deploy malware.",
    "azure_nsg_open_port_3389": "RDP open to the internet is the most common entry point for ransomware in cloud environments. Attackers use stolen or brute-forced credentials to gain interactive access to Windows VMs.",
    "azure_network_watcher_enabled": "Without Network Watcher, network diagnostic data and flow logs are unavailable. Security teams cannot investigate traffic patterns, connection issues, or lateral movement attempts.",
    "azure_vm_disk_encryption": "Unencrypted VM disks expose the operating system, application data, and cached credentials if disk snapshots are shared or the underlying storage is compromised.",
    "azure_sql_auditing_enabled": "Without SQL auditing, database queries and administrative actions go unlogged. Attackers can exfiltrate data, modify records, or escalate privileges without detection.",
    "azure_sql_tls_12": "SQL connections over older TLS versions are vulnerable to decryption attacks. Sensitive query data and credentials transmitted in transit can be intercepted by network-positioned attackers.",
    "azure_keyvault_soft_delete": "Without soft delete, accidentally or maliciously deleted secrets, keys, and certificates are permanently lost. Soft delete provides a recovery window for deleted Key Vault objects.",
    "azure_keyvault_purge_protection": "Without purge protection, even soft-deleted Key Vault objects can be permanently purged. This protects against insider threats and accidental permanent deletion of critical cryptographic material.",
    "azure_monitor_log_profile": "Without an activity log profile, Azure management plane events are not exported for long-term retention. Critical audit data may be lost after the default retention period.",
    "azure_appservice_https_only": "App Services accepting HTTP traffic expose session cookies, authentication tokens, and application data to network-level interception and manipulation.",
    "azure_appservice_tls_12": "App Services using older TLS versions are vulnerable to known protocol attacks. Enforcing TLS 1.2+ protects web application traffic from decryption and tampering.",
    # GCP
    "gcp_iam_no_public_access": "IAM bindings with allUsers or allAuthenticatedUsers grant access to anyone on the internet. This can expose sensitive resources, APIs, and data to unauthorized parties.",
    "gcp_compute_no_external_ip": "VMs with external IPs are directly accessible from the internet. This increases the attack surface and enables direct exploitation of any vulnerabilities on the instance.",
    "gcp_compute_os_login": "Without OS Login, SSH key management is decentralized and error-prone. OS Login integrates with Cloud IAM for centralized, auditable access control to VM instances.",
    "gcp_storage_uniform_access": "Without uniform bucket-level access, per-object ACLs create complex and hard-to-audit permission structures. Uniform access simplifies security and reduces the risk of overly permissive object ACLs.",
    "gcp_sql_no_public_ip": "Cloud SQL instances with public IPs are directly attackable from the internet. Database exploitation can lead to full data breach and lateral movement into connected applications.",
    "gcp_sql_ssl_required": "Database connections without SSL/TLS encryption transmit query data and credentials in cleartext. Network-positioned attackers can intercept and steal database contents.",
    "gcp_kms_key_rotation": "Without automatic key rotation, compromised encryption keys remain valid indefinitely. Regular rotation limits cryptographic exposure and is required by many compliance frameworks.",
    "gcp_gke_private_cluster": "Public GKE cluster endpoints allow Kubernetes API access from the internet. Attackers can attempt API authentication and exploit cluster vulnerabilities remotely.",
    "gcp_gke_network_policy": "Without network policies, all pods can communicate freely within the cluster. A compromised pod can reach any other workload, enabling rapid lateral movement.",
    "gcp_firewall_open_22": "SSH open to the internet on GCP VMs allows brute-force attacks. Automated botnets target SSH continuously to compromise instances for cryptomining and botnet recruitment.",
    "gcp_firewall_open_3389": "RDP open to the internet on GCP VMs enables remote desktop attacks. This is a primary vector for ransomware deployment and interactive attacker sessions.",
}

# API evidence descriptions for each check
CHECK_EVIDENCE = {
    # AWS IAM
    "iam_root_mfa_enabled": '{"api_call": "AWS IAM: GetAccountSummary", "response": "Checks SummaryMap.AccountMFAEnabled == 1. Returns 0 if root MFA is not enabled."}',
    "iam_password_policy_strong": '{"api_call": "AWS IAM: GetAccountPasswordPolicy", "response": "Evaluates MinimumPasswordLength >= 14, RequireSymbols, RequireNumbers, RequireUppercaseCharacters, RequireLowercaseCharacters."}',
    "iam_password_policy_rotation": '{"api_call": "AWS IAM: GetAccountPasswordPolicy", "response": "Checks MaxPasswordAge <= 90 days. If no rotation policy is set, the check fails."}',
    "iam_user_mfa_enabled": '{"api_call": "AWS IAM: ListUsers + ListMFADevices", "response": "For each IAM user with console access, checks if at least one MFA device is assigned via ListMFADevices."}',
    "iam_access_key_rotation": '{"api_call": "AWS IAM: ListAccessKeys", "response": "For each active access key, checks if CreateDate is within the last 90 days. Old keys indicate lack of rotation."}',
    # AWS S3
    "s3_bucket_public_access_blocked": '{"api_call": "AWS S3: GetPublicAccessBlock", "response": "Checks BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets are all True."}',
    "s3_bucket_encryption_enabled": '{"api_call": "AWS S3: GetBucketEncryption", "response": "Checks for ServerSideEncryptionConfiguration. FAIL if no encryption rule is defined on the bucket."}',
    "s3_bucket_logging_enabled": '{"api_call": "AWS S3: GetBucketLogging", "response": "Checks if LoggingEnabled is present with a TargetBucket configured for access log delivery."}',
    "s3_bucket_versioning_enabled": '{"api_call": "AWS S3: GetBucketVersioning", "response": "Checks if Status == Enabled. Suspended or absent versioning configuration results in FAIL."}',
    # AWS EC2
    "ec2_sg_open_port_22": '{"api_call": "AWS EC2: DescribeSecurityGroups", "response": "Checks inbound rules for port 22 with source 0.0.0.0/0 or ::/0. Any match results in FAIL."}',
    "ec2_sg_open_port_3389": '{"api_call": "AWS EC2: DescribeSecurityGroups", "response": "Checks inbound rules for port 3389 with source 0.0.0.0/0 or ::/0. Any match results in FAIL."}',
    "ec2_ebs_volume_encrypted": '{"api_call": "AWS EC2: DescribeVolumes", "response": "Checks Volume.Encrypted == True for each EBS volume. Unencrypted volumes result in FAIL."}',
    "ec2_imdsv2_required": '{"api_call": "AWS EC2: DescribeInstances", "response": "Checks MetadataOptions.HttpTokens == required. If set to optional, IMDSv1 is still accessible (FAIL)."}',
    # AWS RDS
    "rds_encryption_enabled": '{"api_call": "AWS RDS: DescribeDBInstances", "response": "Checks StorageEncrypted == True. Unencrypted DB instances result in FAIL."}',
    "rds_public_access_disabled": '{"api_call": "AWS RDS: DescribeDBInstances", "response": "Checks PubliclyAccessible == False. Publicly accessible instances result in FAIL."}',
    "rds_multi_az_enabled": '{"api_call": "AWS RDS: DescribeDBInstances", "response": "Checks MultiAZ == True for production database instances."}',
    "rds_backup_enabled": '{"api_call": "AWS RDS: DescribeDBInstances", "response": "Checks BackupRetentionPeriod > 0. Zero retention means no automated backups (FAIL)."}',
    # AWS CloudTrail
    "cloudtrail_multiregion": '{"api_call": "AWS CloudTrail: DescribeTrails", "response": "Checks IsMultiRegionTrail == True and trail is logging (IsLogging == True)."}',
    "cloudtrail_log_validation": '{"api_call": "AWS CloudTrail: DescribeTrails", "response": "Checks LogFileValidationEnabled == True. Disabled validation means log integrity cannot be verified."}',
    "cloudtrail_encrypted": '{"api_call": "AWS CloudTrail: DescribeTrails", "response": "Checks KmsKeyId is set. Trails without KMS encryption store logs in plaintext."}',
    # AWS KMS
    "kms_key_rotation_enabled": '{"api_call": "AWS KMS: GetKeyRotationStatus", "response": "Checks KeyRotationEnabled == True for each customer-managed CMK."}',
    # AWS VPC
    "vpc_flow_logs_enabled": '{"api_call": "AWS EC2: DescribeFlowLogs + DescribeVpcs", "response": "For each VPC, checks if at least one active flow log exists."}',
    # AWS GuardDuty / Config
    "guardduty_enabled": '{"api_call": "AWS GuardDuty: ListDetectors", "response": "Checks if at least one GuardDuty detector exists and is enabled."}',
    "config_recorder_enabled": '{"api_call": "AWS Config: DescribeConfigurationRecorders + DescribeConfigurationRecorderStatus", "response": "Checks recording == True and lastStatus == SUCCESS."}',
    # AWS EKS
    "eks_cluster_logging": '{"api_call": "AWS EKS: DescribeCluster", "response": "Checks cluster.logging.clusterLogging for enabled log types (api, audit, authenticator)."}',
    "eks_endpoint_public_access": '{"api_call": "AWS EKS: DescribeCluster", "response": "Checks resourcesVpcConfig.endpointPublicAccess == False. Public endpoints increase attack surface."}',
    # Azure
    "azure_iam_owner_count": '{"api_call": "Azure RBAC: List Role Assignments (filter: Owner role)", "response": "Counts users with Owner role at subscription level. More than 3 owners results in FAIL."}',
    "azure_storage_https_only": '{"api_call": "Azure Storage: Get Storage Account Properties", "response": "Checks supportsHttpsTrafficOnly == True. HTTP-enabled accounts result in FAIL."}',
    "azure_storage_tls_12": '{"api_call": "Azure Storage: Get Storage Account Properties", "response": "Checks minimumTlsVersion == TLS1_2. Lower versions result in FAIL."}',
    "azure_storage_no_public_access": '{"api_call": "Azure Storage: Get Storage Account Properties", "response": "Checks allowBlobPublicAccess == False. Public blob access enabled results in FAIL."}',
    "azure_nsg_open_port_22": '{"api_call": "Azure Network: List NSG Security Rules", "response": "Checks for Allow rules on port 22 with source 0.0.0.0/0 or *. Any match results in FAIL."}',
    "azure_nsg_open_port_3389": '{"api_call": "Azure Network: List NSG Security Rules", "response": "Checks for Allow rules on port 3389 with source 0.0.0.0/0 or *. Any match results in FAIL."}',
    "azure_network_watcher_enabled": '{"api_call": "Azure Network: List Network Watchers", "response": "Checks if Network Watcher exists and is enabled in each active region."}',
    "azure_vm_disk_encryption": '{"api_call": "Azure Compute: Get Disk Encryption Status", "response": "Checks encryptionSettings.enabled == True for OS and data disks."}',
    "azure_sql_auditing_enabled": '{"api_call": "Azure SQL: Get Server Auditing Policy", "response": "Checks state == Enabled for the server-level auditing policy."}',
    "azure_sql_tls_12": '{"api_call": "Azure SQL: Get Server Properties", "response": "Checks minimalTlsVersion == 1.2. Lower versions result in FAIL."}',
    "azure_keyvault_soft_delete": '{"api_call": "Azure Key Vault: Get Vault Properties", "response": "Checks enableSoftDelete == True (default since 2020 but can be disabled on old vaults)."}',
    "azure_keyvault_purge_protection": '{"api_call": "Azure Key Vault: Get Vault Properties", "response": "Checks enablePurgeProtection == True. Without it, soft-deleted objects can be permanently purged."}',
    "azure_monitor_log_profile": '{"api_call": "Azure Monitor: List Log Profiles", "response": "Checks if at least one log profile exists for exporting Activity Log events."}',
    "azure_appservice_https_only": '{"api_call": "Azure App Service: Get Web App Configuration", "response": "Checks httpsOnly == True. HTTP-accessible apps expose traffic to interception."}',
    "azure_appservice_tls_12": '{"api_call": "Azure App Service: Get Web App Configuration", "response": "Checks minTlsVersion == 1.2. Lower versions result in FAIL."}',
    # GCP
    "gcp_iam_no_public_access": '{"api_call": "GCP IAM: GetIamPolicy", "response": "Checks for bindings containing allUsers or allAuthenticatedUsers members. Any match results in FAIL."}',
    "gcp_compute_no_external_ip": '{"api_call": "GCP Compute: instances.list", "response": "Checks networkInterfaces[].accessConfigs for external IP assignments. Any external IP results in FAIL."}',
    "gcp_compute_os_login": '{"api_call": "GCP Compute: projects.get", "response": "Checks commonInstanceMetadata for enable-oslogin == TRUE at project level."}',
    "gcp_storage_uniform_access": '{"api_call": "GCP Storage: buckets.get", "response": "Checks iamConfiguration.uniformBucketLevelAccess.enabled == True."}',
    "gcp_sql_no_public_ip": '{"api_call": "GCP SQL: instances.list", "response": "Checks settings.ipConfiguration.ipv4Enabled == False and no authorizedNetworks with 0.0.0.0/0."}',
    "gcp_sql_ssl_required": '{"api_call": "GCP SQL: instances.list", "response": "Checks settings.ipConfiguration.requireSsl == True."}',
    "gcp_kms_key_rotation": '{"api_call": "GCP KMS: cryptoKeys.get", "response": "Checks rotationPeriod is set and nextRotationTime is in the future (rotation period <= 365 days)."}',
    "gcp_gke_private_cluster": '{"api_call": "GCP GKE: clusters.get", "response": "Checks privateClusterConfig.enablePrivateNodes == True and masterIpv4CidrBlock is set."}',
    "gcp_gke_network_policy": '{"api_call": "GCP GKE: clusters.get", "response": "Checks networkPolicy.enabled == True or datapath == ADVANCED_DATAPATH."}',
    "gcp_firewall_open_22": '{"api_call": "GCP Compute: firewalls.list", "response": "Checks for ALLOW rules on tcp:22 with source 0.0.0.0/0. Any match results in FAIL."}',
    "gcp_firewall_open_3389": '{"api_call": "GCP Compute: firewalls.list", "response": "Checks for ALLOW rules on tcp:3389 with source 0.0.0.0/0. Any match results in FAIL."}',
}
