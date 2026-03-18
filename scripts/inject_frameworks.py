#!/usr/bin/env python3
"""Inject missing compliance frameworks into frameworks.py."""
import sys

FRAMEWORKS_FILE = "scanner/compliance/frameworks.py"

NEW_FRAMEWORKS = r'''
    # ═══════════════════════════════════════════════════════════════════
    # CIS AWS Foundations Benchmark v3.0
    # ═══════════════════════════════════════════════════════════════════
    "CIS-AWS-3.0": {
        "name": "CIS Amazon Web Services Foundations Benchmark v3.0",
        "description": "CIS Benchmark for AWS providing prescriptive guidance for configuring security options, aligned with CIS Controls v8.",
        "category": "cis",
        "controls": [
            {
                "id": "1.1",
                "title": "Maintain current contact details",
                "description": "Ensure contact email and security contacts are current for AWS account.",
                "checks": {"aws": ["iam_root_mfa_enabled"]},
            },
            {
                "id": "1.4",
                "title": "Ensure no root user access key exists",
                "description": "The root user is the most privileged user. Remove all access keys associated with the root user.",
                "checks": {"aws": ["iam_no_root_access_key", "iam_root_mfa_enabled"]},
            },
            {
                "id": "1.5",
                "title": "Ensure MFA is enabled for the root user account",
                "description": "Enable hardware or virtual MFA for the root user to add an extra layer of protection.",
                "checks": {"aws": ["iam_root_mfa_enabled"]},
            },
            {
                "id": "1.8",
                "title": "Ensure IAM password policy requires minimum length of 14 or greater",
                "description": "Set the password policy to require at least 14 characters.",
                "checks": {"aws": ["iam_password_policy_strong", "iam_password_policy_exists"]},
            },
            {
                "id": "1.10",
                "title": "Ensure multi-factor authentication (MFA) is enabled for all IAM users",
                "description": "Enable MFA for all IAM users that have a console password.",
                "checks": {"aws": ["iam_user_mfa_enabled"]},
            },
            {
                "id": "1.12",
                "title": "Ensure credentials unused for 45 days or greater are disabled",
                "description": "Disable credentials that have not been used within 45 days.",
                "checks": {"aws": ["iam_user_unused_credentials_45days"]},
            },
            {
                "id": "1.14",
                "title": "Ensure access keys are rotated every 90 days or less",
                "description": "Rotate access keys regularly to reduce risk of compromised keys.",
                "checks": {"aws": ["iam_access_key_rotation"]},
            },
            {
                "id": "1.15",
                "title": "Ensure IAM Users Receive Permissions Only Through Groups",
                "description": "Do not attach policies directly to users; use groups instead.",
                "checks": {"aws": ["iam_user_no_inline_policies", "iam_group_no_inline_policies"]},
            },
            {
                "id": "1.16",
                "title": "Ensure IAM policies that allow full administrative privileges are not attached",
                "description": "Do not create IAM policies with Statement Effect Allow and Action * on Resource *.",
                "checks": {"aws": ["iam_no_star_policies"]},
            },
            {
                "id": "1.17",
                "title": "Ensure a support role has been created to manage incidents with AWS Support",
                "description": "Create an IAM role for managing incidents with AWS Support.",
                "checks": {"aws": ["iam_support_role_created"]},
            },
            {
                "id": "1.20",
                "title": "Ensure that IAM Access Analyzer is enabled for all regions",
                "description": "Enable IAM Access Analyzer to identify resources shared with external entities.",
                "checks": {"aws": ["iam_access_analyzer_enabled"]},
            },
            {
                "id": "2.1.1",
                "title": "Ensure S3 Bucket Policy is set to deny HTTP requests",
                "description": "At the S3 bucket level, configure a bucket policy to deny any HTTP requests.",
                "checks": {"aws": ["s3_bucket_ssl_required", "s3_bucket_encryption_enabled"]},
            },
            {
                "id": "2.1.2",
                "title": "Ensure MFA Delete is enabled on S3 buckets",
                "description": "Enable MFA Delete to add an additional layer of security for S3 bucket versioning.",
                "checks": {"aws": ["s3_bucket_mfa_delete"]},
            },
            {
                "id": "2.1.4",
                "title": "Ensure S3 buckets have block public access enabled",
                "description": "Block all public access to S3 buckets by default.",
                "checks": {"aws": ["s3_bucket_public_access_blocked"]},
            },
            {
                "id": "2.1.5",
                "title": "Ensure S3 buckets have Object Lock enabled",
                "description": "Enable Object Lock on S3 buckets for WORM compliance.",
                "checks": {"aws": ["s3_bucket_object_lock"]},
            },
            {
                "id": "2.2.1",
                "title": "Ensure EBS Volume Encryption is Enabled in all Regions",
                "description": "Enable default EBS encryption to ensure all new EBS volumes are encrypted.",
                "checks": {"aws": ["ec2_ebs_default_encryption", "ec2_ebs_volume_encrypted"]},
            },
            {
                "id": "2.3.1",
                "title": "Ensure RDS instances are encrypted at rest",
                "description": "Ensure all RDS instances have encryption at rest enabled.",
                "checks": {"aws": ["rds_encryption_enabled", "rds_public_access_disabled"]},
            },
            {
                "id": "2.4.1",
                "title": "Ensure EFS is encrypted at rest",
                "description": "EFS file systems should be encrypted at rest.",
                "checks": {"aws": ["efs_encryption_enabled"]},
            },
            {
                "id": "3.1",
                "title": "Ensure CloudTrail is enabled in all regions",
                "description": "Enable CloudTrail across all regions and ensure log file validation.",
                "checks": {"aws": ["cloudtrail_multiregion", "cloudtrail_enabled", "cloudtrail_log_validation"]},
            },
            {
                "id": "3.2",
                "title": "Ensure CloudTrail log file validation is enabled",
                "description": "Enable log file validation to detect unauthorized modification of log files.",
                "checks": {"aws": ["cloudtrail_log_validation"]},
            },
            {
                "id": "3.4",
                "title": "Ensure CloudTrail trails are integrated with CloudWatch Logs",
                "description": "Send CloudTrail logs to CloudWatch for real-time monitoring.",
                "checks": {"aws": ["cloudtrail_integrated_cloudwatch"]},
            },
            {
                "id": "3.5",
                "title": "Ensure AWS Config is enabled in all regions",
                "description": "Enable AWS Config to record configuration changes across all regions.",
                "checks": {"aws": ["config_recorder_enabled"]},
            },
            {
                "id": "3.6",
                "title": "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
                "description": "Enable server access logging on the S3 bucket that stores CloudTrail logs.",
                "checks": {"aws": ["cloudtrail_s3_bucket_logging"]},
            },
            {
                "id": "3.7",
                "title": "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
                "description": "Configure CloudTrail to use SSE-KMS encryption for log files.",
                "checks": {"aws": ["cloudtrail_encrypted", "kms_key_rotation_enabled"]},
            },
            {
                "id": "3.8",
                "title": "Ensure rotation for customer-created symmetric CMKs is enabled",
                "description": "Enable automatic annual rotation for customer-managed symmetric KMS keys.",
                "checks": {"aws": ["kms_key_rotation_enabled"]},
            },
            {
                "id": "3.9",
                "title": "Ensure VPC flow logging is enabled in all VPCs",
                "description": "Enable VPC flow logs to capture information about IP traffic.",
                "checks": {"aws": ["vpc_flow_logs_enabled"]},
            },
            {
                "id": "4.1",
                "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
                "description": "Remove inbound rules that allow unrestricted SSH access.",
                "checks": {"aws": ["ec2_default_sg_no_traffic", "ec2_sg_no_wide_open_ports"]},
            },
            {
                "id": "4.2",
                "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
                "description": "Remove inbound rules that allow unrestricted RDP access.",
                "checks": {"aws": ["ec2_default_sg_no_traffic", "ec2_sg_no_wide_open_ports"]},
            },
            {
                "id": "4.3",
                "title": "Ensure the default security group of every VPC restricts all traffic",
                "description": "Configure the default security group to restrict all traffic.",
                "checks": {"aws": ["vpc_default_sg_restricts_all", "ec2_default_sg_no_traffic"]},
            },
            {
                "id": "5.1",
                "title": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to all ports",
                "description": "Remove unrestricted inbound rules from Network ACLs.",
                "checks": {"aws": ["vpc_no_unrestricted_nacl"]},
            },
            {
                "id": "5.2",
                "title": "Ensure EC2 instances do not have public IP addresses",
                "description": "Launch EC2 instances without public IP addresses unless necessary.",
                "checks": {"aws": ["ec2_instance_no_public_ip"]},
            },
            {
                "id": "5.6",
                "title": "Ensure IMDSv2 is enabled on all EC2 instances",
                "description": "Require IMDSv2 on all EC2 instances to mitigate SSRF attacks.",
                "checks": {"aws": ["ec2_imdsv2_required"]},
            },
        ],
    },
    # ═══════════════════════════════════════════════════════════════════
    # CIS GCP Foundations Benchmark v3.0
    # ═══════════════════════════════════════════════════════════════════
    "CIS-GCP-3.0": {
        "name": "CIS Google Cloud Platform Foundation Benchmark v3.0",
        "description": "CIS Benchmark for GCP providing prescriptive guidance for configuring security options, aligned with CIS Controls v8.",
        "category": "cis",
        "controls": [
            {
                "id": "1.1",
                "title": "Ensure that corporate login credentials are used",
                "description": "Use corporate login credentials instead of personal accounts.",
                "checks": {"gcp": ["gcp_iam_corp_login_required"]},
            },
            {
                "id": "1.4",
                "title": "Ensure that there are only GCP-managed service account keys",
                "description": "Eliminate user-managed service account keys where possible.",
                "checks": {"gcp": ["gcp_iam_no_user_managed_sa_keys", "gcp_iam_sa_key_rotation"]},
            },
            {
                "id": "1.5",
                "title": "Ensure that Service Account has no admin privileges",
                "description": "Service accounts should not have admin or owner-level privileges.",
                "checks": {"gcp": ["gcp_iam_no_sa_admin_key", "gcp_iam_no_primitive_roles"]},
            },
            {
                "id": "1.6",
                "title": "Ensure IAM users are not assigned the Service Account User or Token Creator roles at project level",
                "description": "Restrict Service Account User and Token Creator roles.",
                "checks": {"gcp": ["gcp_iam_separation_of_duties"]},
            },
            {
                "id": "1.8",
                "title": "Ensure that Separation of Duties is enforced",
                "description": "No user should have both Service Account Admin and Service Account User roles.",
                "checks": {"gcp": ["gcp_iam_separation_of_duties"]},
            },
            {
                "id": "1.10",
                "title": "Ensure KMS encryption keys are rotated within a period of 90 days",
                "description": "Set a key rotation period of 90 days or less for KMS keys.",
                "checks": {"gcp": ["gcp_kms_key_rotation"]},
            },
            {
                "id": "1.11",
                "title": "Ensure that Separation of Duties is enforced while assigning KMS related roles",
                "description": "No user should have both KMS Admin and any CryptoKey role.",
                "checks": {"gcp": ["gcp_kms_no_public_access"]},
            },
            {
                "id": "1.15",
                "title": "Ensure API Keys are restricted to only APIs that application needs access",
                "description": "Restrict API keys to limit their use to specific APIs.",
                "checks": {"gcp": ["gcp_iam_api_keys_restricted"]},
            },
            {
                "id": "2.1",
                "title": "Ensure that Cloud Audit Logging is configured properly",
                "description": "Enable Data Access audit logs for all services and all users.",
                "checks": {"gcp": ["gcp_logging_audit_logs_enabled", "gcp_logging_sinks_configured"]},
            },
            {
                "id": "2.2",
                "title": "Ensure that sinks are configured for all log entries",
                "description": "Create a sink that captures all activity logs.",
                "checks": {"gcp": ["gcp_logging_sinks_configured"]},
            },
            {
                "id": "2.5",
                "title": "Ensure that Logging is enabled for Cloud Storage buckets",
                "description": "Enable access logging and storage logging on Cloud Storage buckets.",
                "checks": {"gcp": ["gcp_storage_logging_enabled"]},
            },
            {
                "id": "2.6",
                "title": "Ensure that retention policies on Cloud Storage buckets are configured using Bucket Lock",
                "description": "Set retention policies with Bucket Lock on storage buckets.",
                "checks": {"gcp": ["gcp_logging_bucket_retention", "gcp_storage_retention_policy"]},
            },
            {
                "id": "2.12",
                "title": "Ensure that Cloud DNS logging is enabled for all VPC networks",
                "description": "Enable DNS logging for each VPC to record DNS queries.",
                "checks": {"gcp": ["gcp_logging_dns_logging"]},
            },
            {
                "id": "3.1",
                "title": "Ensure that the default network does not exist in a project",
                "description": "Delete the default network to enforce intentional network architecture.",
                "checks": {"gcp": ["gcp_firewall_no_default_allow"]},
            },
            {
                "id": "3.6",
                "title": "Ensure SSH access is restricted from the internet",
                "description": "GCP firewall rules should not allow SSH from 0.0.0.0/0.",
                "checks": {"gcp": ["gcp_firewall_open_22"]},
            },
            {
                "id": "3.7",
                "title": "Ensure RDP access is restricted from the internet",
                "description": "GCP firewall rules should not allow RDP from 0.0.0.0/0.",
                "checks": {"gcp": ["gcp_firewall_open_3389"]},
            },
            {
                "id": "3.8",
                "title": "Ensure VPC Flow logs are enabled for every subnet",
                "description": "Enable VPC Flow Logs on every VPC subnet for network monitoring.",
                "checks": {"gcp": ["gcp_logging_vpc_flow_logs", "gcp_network_flow_logs_enabled"]},
            },
            {
                "id": "3.9",
                "title": "Ensure Private Google Access is enabled for all VPC subnets",
                "description": "Enable Private Google Access for subnets with private instances.",
                "checks": {"gcp": ["gcp_network_private_google_access"]},
            },
            {
                "id": "4.1",
                "title": "Ensure that instances are not configured to use default service accounts",
                "description": "Do not use the default Compute Engine service account for VM instances.",
                "checks": {"gcp": ["gcp_compute_no_default_sa"]},
            },
            {
                "id": "4.3",
                "title": "Ensure Compute instances do not have public IP addresses",
                "description": "Launch instances without external IP addresses unless necessary.",
                "checks": {"gcp": ["gcp_compute_no_external_ip"]},
            },
            {
                "id": "4.4",
                "title": "Ensure Shielded VM is enabled on Compute instances",
                "description": "Enable Shielded VM features (Secure Boot, vTPM, Integrity Monitoring).",
                "checks": {"gcp": ["gcp_compute_shielded_vm"]},
            },
            {
                "id": "4.5",
                "title": "Ensure OS Login is enabled for all Compute instances",
                "description": "Use OS Login to manage SSH access using IAM roles.",
                "checks": {"gcp": ["gcp_compute_os_login"]},
            },
            {
                "id": "4.6",
                "title": "Ensure serial port connection is disabled for Compute instances",
                "description": "Disable serial port access to prevent interactive console access.",
                "checks": {"gcp": ["gcp_compute_serial_port_disabled"]},
            },
            {
                "id": "4.8",
                "title": "Ensure Compute instances are launched with Confidential Computing",
                "description": "Enable Confidential Computing for memory encryption on VMs.",
                "checks": {"gcp": ["gcp_compute_confidential_computing"]},
            },
            {
                "id": "4.11",
                "title": "Ensure that Compute instances have IP forwarding disabled",
                "description": "Disable IP forwarding unless the instance is used as a router.",
                "checks": {"gcp": ["gcp_compute_ip_forwarding_disabled"]},
            },
            {
                "id": "5.1",
                "title": "Ensure uniform bucket-level access is enabled on Cloud Storage",
                "description": "Use uniform bucket-level access for consistent permissions.",
                "checks": {"gcp": ["gcp_storage_uniform_access"]},
            },
            {
                "id": "5.2",
                "title": "Ensure Cloud Storage buckets are not anonymously or publicly accessible",
                "description": "Remove public access from Cloud Storage buckets.",
                "checks": {"gcp": ["gcp_storage_no_public_access"]},
            },
            {
                "id": "6.1",
                "title": "Ensure Cloud SQL instances require all incoming connections to use SSL",
                "description": "Configure Cloud SQL to require SSL/TLS for all connections.",
                "checks": {"gcp": ["gcp_sql_ssl_required"]},
            },
            {
                "id": "6.2",
                "title": "Ensure Cloud SQL database instances do not have public IPs",
                "description": "Configure Cloud SQL instances with private IPs only.",
                "checks": {"gcp": ["gcp_sql_no_public_ip", "gcp_sql_no_public_networks"]},
            },
            {
                "id": "6.3",
                "title": "Ensure automated backups are configured for Cloud SQL",
                "description": "Enable automated backups and PITR for Cloud SQL instances.",
                "checks": {"gcp": ["gcp_sql_backup_enabled", "gcp_sql_pitr_enabled"]},
            },
            {
                "id": "7.1",
                "title": "Ensure GKE clusters have Stackdriver Logging enabled",
                "description": "Enable Stackdriver Logging for GKE clusters.",
                "checks": {"gcp": ["gcp_gke_cluster_logging"]},
            },
            {
                "id": "7.3",
                "title": "Ensure private cluster is enabled for GKE",
                "description": "Enable private cluster to restrict public access to the API server.",
                "checks": {"gcp": ["gcp_gke_private_cluster"]},
            },
            {
                "id": "7.4",
                "title": "Ensure Master Authorized Networks is enabled",
                "description": "Restrict access to the GKE cluster master endpoint.",
                "checks": {"gcp": ["gcp_gke_master_auth_networks"]},
            },
            {
                "id": "7.5",
                "title": "Ensure Network Policy is enabled on GKE",
                "description": "Enable Network Policy to control pod-to-pod communication.",
                "checks": {"gcp": ["gcp_gke_network_policy"]},
            },
            {
                "id": "7.7",
                "title": "Ensure Workload Identity is enabled for GKE",
                "description": "Use Workload Identity for secure IAM authentication from pods.",
                "checks": {"gcp": ["gcp_gke_workload_identity"]},
            },
            {
                "id": "7.8",
                "title": "Ensure Shielded GKE Nodes are enabled",
                "description": "Enable Shielded GKE Nodes for integrity verification.",
                "checks": {"gcp": ["gcp_gke_shielded_nodes"]},
            },
            {
                "id": "7.10",
                "title": "Ensure Binary Authorization is configured for GKE",
                "description": "Enable Binary Authorization to deploy only trusted container images.",
                "checks": {"gcp": ["gcp_gke_binary_auth"]},
            },
        ],
    },
    # ═══════════════════════════════════════════════════════════════════
    # CIS Kubernetes Benchmark v1.8
    # ═══════════════════════════════════════════════════════════════════
    "CIS-K8s-1.8": {
        "name": "CIS Kubernetes Benchmark v1.8",
        "description": "CIS Benchmark for Kubernetes providing configuration guidelines for securing Kubernetes clusters.",
        "category": "cis",
        "controls": [
            {
                "id": "1.2.1",
                "title": "Ensure audit logging is enabled",
                "description": "Enable audit logging for the API server to record all requests.",
                "checks": {"kubernetes": ["k8s_api_audit_logging"]},
            },
            {
                "id": "1.2.6",
                "title": "Ensure the API server TLS certificates are valid",
                "description": "Use valid TLS certificates for API server communication.",
                "checks": {"kubernetes": ["k8s_api_tls_enabled"]},
            },
            {
                "id": "4.1.1",
                "title": "Ensure RBAC is properly configured",
                "description": "Do not grant cluster-admin to non-admin subjects. Avoid wildcards.",
                "checks": {"kubernetes": ["k8s_rbac_no_wildcard_cluster_admin", "k8s_rbac_no_wildcard_verbs"]},
            },
            {
                "id": "4.1.5",
                "title": "Ensure default service account tokens are not automounted",
                "description": "Disable automatic mounting of default service account tokens.",
                "checks": {"kubernetes": ["k8s_rbac_no_default_sa_token"]},
            },
            {
                "id": "4.1.8",
                "title": "Limit access to Secrets",
                "description": "Restrict access to the secrets resource to only authorized subjects.",
                "checks": {"kubernetes": ["k8s_rbac_limit_secrets_access"]},
            },
            {
                "id": "5.1.1",
                "title": "Ensure pods do not run in the default namespace",
                "description": "Create namespaces for workloads to isolate and manage resources.",
                "checks": {"kubernetes": ["k8s_no_pods_in_default"]},
            },
            {
                "id": "5.1.3",
                "title": "Ensure namespaces have network policies defined",
                "description": "Define network policies per namespace to control pod traffic.",
                "checks": {"kubernetes": ["k8s_namespace_network_policy", "k8s_network_deny_all_default"]},
            },
            {
                "id": "5.1.4",
                "title": "Ensure resource quotas and limit ranges are set per namespace",
                "description": "Set resource quotas and limit ranges to prevent resource exhaustion.",
                "checks": {"kubernetes": ["k8s_namespace_resource_quotas", "k8s_namespace_limit_ranges"]},
            },
            {
                "id": "5.2.1",
                "title": "Ensure Pod Security Admission is configured",
                "description": "Configure Pod Security Admission to enforce pod security standards.",
                "checks": {"kubernetes": ["k8s_admission_pod_security"]},
            },
            {
                "id": "5.4.1",
                "title": "Ensure Secrets are encrypted at rest in etcd",
                "description": "Configure encryption providers to encrypt Secrets stored in etcd.",
                "checks": {"kubernetes": ["k8s_secrets_encrypted_etcd"]},
            },
            {
                "id": "5.4.2",
                "title": "Ensure Secrets are not stored as environment variables",
                "description": "Use volume mounts for Secrets instead of environment variables.",
                "checks": {"kubernetes": ["k8s_secrets_no_env_vars"]},
            },
            {
                "id": "5.7.1",
                "title": "Ensure Services of type LoadBalancer are not exposed publicly",
                "description": "Restrict LoadBalancer Services to internal use or use ingress controllers.",
                "checks": {"kubernetes": ["k8s_service_no_loadbalancer_public"]},
            },
            {
                "id": "5.7.2",
                "title": "Ensure Services of type NodePort are avoided",
                "description": "Avoid NodePort services; use ClusterIP and Ingress instead.",
                "checks": {"kubernetes": ["k8s_service_no_nodeport"]},
            },
            {
                "id": "5.7.4",
                "title": "Ensure Network Policies define ingress rules",
                "description": "Ensure all network policies have explicit ingress rules.",
                "checks": {"kubernetes": ["k8s_network_ingress_rules"]},
            },
        ],
    },
    # ═══════════════════════════════════════════════════════════════════
    # CIS Microsoft 365 Foundations Benchmark v3.0
    # ═══════════════════════════════════════════════════════════════════
    "CIS-M365-3.0": {
        "name": "CIS Microsoft 365 Foundations Benchmark v3.0",
        "description": "CIS Benchmark for Microsoft 365 tenant security covering identity, data protection, email security, and collaboration settings.",
        "category": "cis",
        "controls": [
            {
                "id": "1.1.1",
                "title": "Ensure Administrative Accounts Use MFA",
                "description": "All admin accounts should have MFA enabled.",
                "checks": {"m365": ["m365_admin_mfa_enforced", "m365_user_mfa_registered"]},
            },
            {
                "id": "1.1.3",
                "title": "Ensure Security Defaults are enabled or Conditional Access policies are configured",
                "description": "Enable Security Defaults or equivalent Conditional Access policies.",
                "checks": {"m365": ["m365_security_defaults_enabled", "m365_ca_policies_configured"]},
            },
            {
                "id": "1.1.4",
                "title": "Ensure Conditional Access policies are configured to require MFA",
                "description": "Require MFA via Conditional Access policies for all users.",
                "checks": {"m365": ["m365_ca_require_mfa", "m365_ca_sign_in_risk"]},
            },
            {
                "id": "1.1.6",
                "title": "Ensure that legacy authentication is blocked via Conditional Access",
                "description": "Block legacy authentication protocols that cannot enforce MFA.",
                "checks": {"m365": ["m365_ca_block_legacy_auth", "m365_legacy_auth_blocked"]},
            },
            {
                "id": "1.2.1",
                "title": "Ensure the admin portal is restricted to admins",
                "description": "Limit the number of users with admin privileges.",
                "checks": {"m365": ["m365_privileged_accounts_limited"]},
            },
            {
                "id": "1.3.1",
                "title": "Ensure password policies do not expire",
                "description": "Set passwords to never expire (rely on MFA and breach detection instead).",
                "checks": {"m365": ["m365_password_never_expire_disabled"]},
            },
            {
                "id": "1.3.3",
                "title": "Ensure Self-Service Password Reset is enabled",
                "description": "Enable SSPR to reduce helpdesk calls and improve security.",
                "checks": {"m365": ["m365_self_service_password_reset"]},
            },
            {
                "id": "2.1.1",
                "title": "Ensure Microsoft Defender for Endpoint is enabled",
                "description": "Enable Defender for Endpoint for threat detection.",
                "checks": {"m365": ["m365_defender_sensor_active"]},
            },
            {
                "id": "2.1.4",
                "title": "Ensure Safe Attachments policy is enabled",
                "description": "Enable Safe Attachments in Exchange Online Protection.",
                "checks": {"m365": ["m365_safe_attachments_enabled"]},
            },
            {
                "id": "2.1.5",
                "title": "Ensure Safe Links policy is enabled",
                "description": "Enable Safe Links to protect users from malicious URLs.",
                "checks": {"m365": ["m365_safe_links_enabled"]},
            },
            {
                "id": "2.1.6",
                "title": "Ensure anti-phishing policy is configured",
                "description": "Configure anti-phishing policies with impersonation protection.",
                "checks": {"m365": ["m365_anti_phishing_policy"]},
            },
            {
                "id": "3.1.1",
                "title": "Ensure DLP policies are configured",
                "description": "Configure Data Loss Prevention policies for sensitive data.",
                "checks": {"m365": ["m365_dlp_policies_configured"]},
            },
            {
                "id": "3.2.1",
                "title": "Ensure sensitivity labels are published and in use",
                "description": "Publish sensitivity labels for document and email classification.",
                "checks": {"m365": ["m365_sensitivity_labels_enabled"]},
            },
            {
                "id": "3.2.2",
                "title": "Ensure Azure Information Protection encryption is enabled",
                "description": "Enable AIP encryption for sensitive content protection.",
                "checks": {"m365": ["m365_aip_encryption_enabled"]},
            },
            {
                "id": "4.1.1",
                "title": "Ensure SPF records are configured",
                "description": "Configure SPF records to prevent email spoofing.",
                "checks": {"m365": ["m365_spf_configured"]},
            },
            {
                "id": "4.1.2",
                "title": "Ensure DKIM is configured for all domains",
                "description": "Enable DKIM signing for email authentication.",
                "checks": {"m365": ["m365_dkim_configured"]},
            },
            {
                "id": "4.1.3",
                "title": "Ensure DMARC is configured for all domains",
                "description": "Configure DMARC records for email authentication and reporting.",
                "checks": {"m365": ["m365_dmarc_configured"]},
            },
            {
                "id": "5.1.1",
                "title": "Ensure external sharing in SharePoint is restricted",
                "description": "Restrict external sharing in SharePoint and OneDrive.",
                "checks": {"m365": ["m365_sharepoint_sharing_restricted", "m365_external_sharing_restricted"]},
            },
            {
                "id": "5.2.1",
                "title": "Ensure Teams external access is restricted",
                "description": "Restrict external access in Microsoft Teams.",
                "checks": {"m365": ["m365_teams_external_access_restricted"]},
            },
            {
                "id": "5.2.2",
                "title": "Ensure guest access in Teams is restricted",
                "description": "Limit guest access capabilities in Microsoft Teams.",
                "checks": {"m365": ["m365_guest_access_restricted"]},
            },
            {
                "id": "5.3.1",
                "title": "Ensure OneDrive sync is restricted",
                "description": "Restrict OneDrive sync to managed devices.",
                "checks": {"m365": ["m365_onedrive_sync_restricted"]},
            },
        ],
    },
    # ═══════════════════════════════════════════════════════════════════
    # CSA Cloud Controls Matrix (CCM) v4.1
    # ═══════════════════════════════════════════════════════════════════
    "CCM-4.1": {
        "name": "CSA Cloud Controls Matrix v4.1",
        "description": "Cloud Security Alliance Cloud Controls Matrix - a cybersecurity control framework for cloud computing aligned with CSA best practices, ISO 27001/27002, NIST, PCI-DSS and AICPA TSC.",
        "category": "industry",
        "controls": [
            {
                "id": "AIS-01",
                "domain": "Application & Interface Security",
                "title": "Application Security",
                "description": "Establish policies and procedures for application security including secure SDLC, code review, and API protection.",
                "checks": {
                    "aws": ["lambda_runtime_supported", "lambda_vpc_configured", "apigateway_rest_api_logging", "apigateway_waf_enabled"],
                    "gcp": ["gcp_gke_binary_auth"],
                    "kubernetes": ["k8s_admission_pod_security"],
                },
            },
            {
                "id": "AIS-02",
                "domain": "Application & Interface Security",
                "title": "Application Security Testing",
                "description": "Perform application security testing (SAST, DAST) for all deployed applications.",
                "checks": {
                    "aws": ["ecr_image_scanning"],
                    "gcp": ["gcp_gke_binary_auth"],
                },
            },
            {
                "id": "AIS-04",
                "domain": "Application & Interface Security",
                "title": "Secure Application Design",
                "description": "Implement application security controls including input validation, output encoding, and error handling.",
                "checks": {
                    "aws": ["waf_web_acl_exists", "cloudfront_waf_enabled"],
                    "gcp": [],
                },
            },
            {
                "id": "BCR-01",
                "domain": "Business Continuity Management & Operational Resilience",
                "title": "Business Continuity Planning",
                "description": "Establish and maintain a business continuity plan to ensure operational resilience.",
                "checks": {
                    "aws": ["rds_multi_az_enabled", "rds_backup_enabled", "backup_plan_exists", "dynamodb_pitr_enabled"],
                    "gcp": ["gcp_sql_backup_enabled", "gcp_sql_pitr_enabled"],
                },
            },
            {
                "id": "BCR-03",
                "domain": "Business Continuity Management & Operational Resilience",
                "title": "Backup and Recovery",
                "description": "Perform periodic backup and restoration testing to ensure data recovery capabilities.",
                "checks": {
                    "aws": ["backup_plan_exists", "backup_vault_encrypted", "rds_backup_enabled", "s3_bucket_versioning_enabled"],
                    "gcp": ["gcp_sql_backup_enabled", "gcp_storage_versioning"],
                    "alibaba": ["ali_rds_backup_retention", "ali_oss_versioning_enabled"],
                    "snowflake": ["snowflake_data_retention_configured", "snowflake_failover_configured"],
                },
            },
            {
                "id": "CCC-01",
                "domain": "Change Control & Configuration Management",
                "title": "Change Management Policy",
                "description": "Establish change management policies and procedures for all IT infrastructure changes.",
                "checks": {
                    "aws": ["config_recorder_enabled"],
                    "gcp": ["gcp_logging_audit_logs_enabled"],
                    "servicenow": ["servicenow_change_management"],
                },
            },
            {
                "id": "CEK-01",
                "domain": "Cryptography, Encryption & Key Management",
                "title": "Encryption and Key Management Policy",
                "description": "Define cryptographic standards, approved algorithms, and key management procedures.",
                "checks": {
                    "aws": ["kms_key_rotation_enabled", "cloudtrail_encrypted", "s3_bucket_encryption_enabled"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_kms_hsm_protection"],
                    "alibaba": ["ali_kms_key_rotation", "ali_kms_cmk_enabled"],
                },
            },
            {
                "id": "CEK-03",
                "domain": "Cryptography, Encryption & Key Management",
                "title": "Data Encryption",
                "description": "Encrypt data at rest and in transit using approved encryption standards.",
                "checks": {
                    "aws": ["ec2_ebs_volume_encrypted", "ec2_ebs_default_encryption", "rds_encryption_enabled", "s3_bucket_encryption_enabled", "efs_encryption_enabled", "es_encryption_at_rest", "dynamodb_table_encrypted_kms", "sqs_queue_encrypted", "sns_topic_encrypted", "redshift_cluster_encrypted"],
                    "gcp": ["gcp_compute_disk_encryption_cmek", "gcp_storage_cmek_encryption", "gcp_sql_cmek_encryption", "gcp_bigquery_cmek_encryption"],
                    "alibaba": ["ali_ecs_disk_encryption", "ali_rds_encryption_enabled", "ali_oss_encryption_enabled"],
                    "kubernetes": ["k8s_secrets_encrypted_etcd"],
                    "snowflake": ["snowflake_stages_encrypted"],
                },
            },
            {
                "id": "CEK-04",
                "domain": "Cryptography, Encryption & Key Management",
                "title": "Encryption in Transit",
                "description": "Implement encryption for data in transit using TLS 1.2 or higher.",
                "checks": {
                    "aws": ["s3_bucket_ssl_required", "cloudfront_https_only", "es_node_to_node_encryption", "elasticache_encryption_transit"],
                    "gcp": ["gcp_sql_ssl_required"],
                    "alibaba": ["ali_rds_ssl_enabled", "ali_oss_https_only", "ali_slb_https_listener"],
                    "m365": ["m365_spf_configured", "m365_dkim_configured", "m365_dmarc_configured"],
                    "servicenow": ["servicenow_tls_enforced"],
                    "salesforce": ["salesforce_tls_enforced"],
                },
            },
            {
                "id": "CEK-05",
                "domain": "Cryptography, Encryption & Key Management",
                "title": "Key Rotation",
                "description": "Rotate encryption keys per defined cryptoperiods.",
                "checks": {
                    "aws": ["kms_key_rotation_enabled", "iam_access_key_rotation"],
                    "gcp": ["gcp_kms_key_rotation", "gcp_iam_sa_key_rotation"],
                    "alibaba": ["ali_kms_key_rotation", "ali_ram_access_key_rotation"],
                    "snowflake": ["snowflake_user_password_rotation"],
                },
            },
            {
                "id": "DSP-01",
                "domain": "Data Security & Privacy Lifecycle Management",
                "title": "Data Security Policy",
                "description": "Establish data classification, handling, and protection policies.",
                "checks": {
                    "aws": ["macie_enabled", "s3_bucket_public_access_blocked"],
                    "gcp": ["gcp_storage_no_public_access", "gcp_bigquery_dataset_no_public"],
                    "alibaba": ["ali_oss_no_public_access"],
                    "m365": ["m365_dlp_policies_configured", "m365_sensitivity_labels_enabled"],
                    "snowflake": ["snowflake_column_masking_policies", "snowflake_row_access_policies"],
                    "servicenow": ["servicenow_data_classification"],
                },
            },
            {
                "id": "DSP-04",
                "domain": "Data Security & Privacy Lifecycle Management",
                "title": "Data Access Control",
                "description": "Implement data access controls aligned with classification levels.",
                "checks": {
                    "aws": ["s3_bucket_public_access_blocked", "rds_public_access_disabled", "redshift_cluster_no_public"],
                    "gcp": ["gcp_storage_no_public_access", "gcp_sql_no_public_ip", "gcp_bigquery_dataset_no_public"],
                    "alibaba": ["ali_oss_no_public_access", "ali_rds_no_public_access"],
                    "salesforce": ["salesforce_field_level_security", "salesforce_sharing_rules_reviewed"],
                },
            },
            {
                "id": "GRC-01",
                "domain": "Governance, Risk & Compliance",
                "title": "Governance Program",
                "description": "Establish an information security governance program including policies and procedures.",
                "checks": {
                    "aws": ["config_recorder_enabled", "guardduty_enabled"],
                    "gcp": ["gcp_logging_audit_logs_enabled"],
                    "servicenow": ["servicenow_incident_management", "servicenow_change_management"],
                },
            },
            {
                "id": "HRS-04",
                "domain": "Human Resources",
                "title": "Security Awareness Training",
                "description": "Provide security awareness training to all personnel.",
                "checks": {},
            },
            {
                "id": "IAM-01",
                "domain": "Identity & Access Management",
                "title": "Identity and Access Management Policy",
                "description": "Establish identity and access management policies including least privilege and MFA.",
                "checks": {
                    "aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled", "iam_password_policy_strong"],
                    "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_no_public_access"],
                    "alibaba": ["ali_ram_mfa_enabled", "ali_ram_password_policy"],
                    "m365": ["m365_admin_mfa_enforced", "m365_ca_require_mfa", "m365_security_defaults_enabled"],
                    "salesforce": ["salesforce_user_mfa_enabled", "salesforce_sso_configured"],
                    "snowflake": ["snowflake_user_mfa_enabled", "snowflake_account_sso_configured"],
                    "servicenow": ["servicenow_users_mfa_enabled"],
                },
            },
            {
                "id": "IAM-02",
                "domain": "Identity & Access Management",
                "title": "Strong Authentication",
                "description": "Implement multi-factor authentication for all interactive access.",
                "checks": {
                    "aws": ["iam_root_mfa_enabled", "iam_user_mfa_enabled"],
                    "alibaba": ["ali_ram_mfa_enabled"],
                    "m365": ["m365_admin_mfa_enforced", "m365_user_mfa_registered", "m365_user_phishing_resistant_mfa"],
                    "salesforce": ["salesforce_user_mfa_enabled"],
                    "snowflake": ["snowflake_user_mfa_enabled"],
                    "servicenow": ["servicenow_users_mfa_enabled"],
                },
            },
            {
                "id": "IAM-04",
                "domain": "Identity & Access Management",
                "title": "Policies and Procedures",
                "description": "Implement least privilege access control with regular reviews.",
                "checks": {
                    "aws": ["iam_no_star_policies", "iam_user_no_inline_policies", "iam_group_no_inline_policies"],
                    "gcp": ["gcp_iam_no_primitive_roles", "gcp_iam_separation_of_duties"],
                    "kubernetes": ["k8s_rbac_no_wildcard_cluster_admin", "k8s_rbac_no_wildcard_verbs", "k8s_rbac_limit_secrets_access"],
                    "servicenow": ["servicenow_role_separation"],
                },
            },
            {
                "id": "IAM-07",
                "domain": "Identity & Access Management",
                "title": "User Access Review",
                "description": "Review user access rights regularly and remove unused credentials.",
                "checks": {
                    "aws": ["iam_user_unused_credentials_45days"],
                    "alibaba": ["ali_ram_unused_users"],
                    "snowflake": ["snowflake_user_not_inactive"],
                    "salesforce": ["salesforce_user_not_stale"],
                },
            },
            {
                "id": "IVS-01",
                "domain": "Infrastructure & Virtualization Security",
                "title": "Infrastructure Security Policy",
                "description": "Define infrastructure security controls including network segmentation and hardening.",
                "checks": {
                    "aws": ["vpc_flow_logs_enabled", "ec2_default_sg_no_traffic", "vpc_default_sg_restricts_all", "ec2_imdsv2_required"],
                    "gcp": ["gcp_compute_shielded_vm", "gcp_compute_os_login", "gcp_logging_vpc_flow_logs"],
                    "alibaba": ["ali_vpc_flow_logs", "ali_ecs_vpc_network"],
                    "kubernetes": ["k8s_namespace_network_policy", "k8s_network_deny_all_default"],
                },
            },
            {
                "id": "IVS-03",
                "domain": "Infrastructure & Virtualization Security",
                "title": "Network Security",
                "description": "Segment networks and restrict traffic to only required communication paths.",
                "checks": {
                    "aws": ["ec2_sg_no_wide_open_ports", "ec2_default_sg_no_traffic", "vpc_no_unrestricted_nacl", "ec2_instance_no_public_ip"],
                    "gcp": ["gcp_firewall_no_default_allow", "gcp_gke_network_policy", "gcp_gke_private_cluster"],
                    "alibaba": ["ali_ecs_no_public_ip", "ali_ecs_sg_no_public_ingress"],
                    "kubernetes": ["k8s_namespace_network_policy", "k8s_service_no_loadbalancer_public", "k8s_service_no_nodeport"],
                },
            },
            {
                "id": "IVS-09",
                "domain": "Infrastructure & Virtualization Security",
                "title": "Firewall and Network Protection",
                "description": "Implement firewall rules and WAF protection for internet-facing applications.",
                "checks": {
                    "aws": ["waf_web_acl_exists", "cloudfront_waf_enabled", "apigateway_waf_enabled"],
                    "alibaba": ["ali_waf_enabled", "ali_waf_domains_configured"],
                },
            },
            {
                "id": "LOG-01",
                "domain": "Logging & Monitoring",
                "title": "Logging and Monitoring Policy",
                "description": "Establish logging and monitoring policies. Collect and retain audit logs.",
                "checks": {
                    "aws": ["cloudtrail_multiregion", "cloudtrail_enabled", "cloudtrail_log_validation", "cloudwatch_log_group_retention"],
                    "gcp": ["gcp_logging_sinks_configured", "gcp_logging_audit_logs_enabled", "gcp_logging_bucket_retention"],
                    "alibaba": ["ali_actiontrail_enabled", "ali_actiontrail_multi_region", "ali_actiontrail_logging_active"],
                    "snowflake": ["snowflake_audit_logging_enabled", "snowflake_query_history_retention"],
                    "servicenow": ["servicenow_admin_audit_logging"],
                    "salesforce": ["salesforce_setup_audit_trail", "salesforce_event_monitoring"],
                },
            },
            {
                "id": "LOG-03",
                "domain": "Logging & Monitoring",
                "title": "Security Monitoring and Alerting",
                "description": "Implement security monitoring with automated alerting for anomalous activities.",
                "checks": {
                    "aws": ["guardduty_enabled", "cloudtrail_integrated_cloudwatch", "config_recorder_enabled"],
                    "gcp": ["gcp_logging_metric_filters"],
                    "alibaba": ["ali_security_center_enabled"],
                    "m365": ["m365_defender_sensor_active"],
                },
            },
            {
                "id": "SEF-02",
                "domain": "Security Incident Management",
                "title": "Incident Management",
                "description": "Establish incident management procedures with defined response and escalation processes.",
                "checks": {
                    "aws": ["guardduty_enabled", "iam_support_role_created"],
                    "servicenow": ["servicenow_incident_management"],
                },
            },
            {
                "id": "TVM-01",
                "domain": "Threat & Vulnerability Management",
                "title": "Threat and Vulnerability Management Policy",
                "description": "Establish processes for vulnerability identification, assessment, and remediation.",
                "checks": {
                    "aws": ["ecr_image_scanning", "guardduty_enabled", "rds_auto_minor_upgrade"],
                    "gcp": ["gcp_gke_binary_auth"],
                    "m365": ["m365_defender_low_risk", "m365_no_high_risk_users"],
                },
            },
            {
                "id": "TVM-04",
                "domain": "Threat & Vulnerability Management",
                "title": "Detection Updates",
                "description": "Keep threat detection signatures and rules up to date.",
                "checks": {
                    "aws": ["guardduty_enabled", "lambda_runtime_supported"],
                    "m365": ["m365_safe_attachments_enabled", "m365_safe_links_enabled", "m365_anti_phishing_policy"],
                },
            },
            {
                "id": "UEM-01",
                "domain": "Universal Endpoint Management",
                "title": "Endpoint Device Policy",
                "description": "Establish endpoint security policies including device compliance requirements.",
                "checks": {
                    "m365": ["m365_ca_require_compliant_device"],
                },
            },
        ],
    },
'''

# Insert before the closing "}" of FRAMEWORKS dict
with open(FRAMEWORKS_FILE, "r") as f:
    content = f.read()

# Find the marker: the closing of MCSB-Azure (last framework) then the dict closing "}"
# The structure ends with:    },\n}\n\n\n# ═══...
marker = "}\n\n\n# " + "═" * 67
if marker not in content:
    # Try alternative marker
    marker = "}\n\n\n# ═"

if marker not in content:
    print("ERROR: Could not find insertion point in frameworks.py")
    sys.exit(1)

# Insert before the closing } and helpers
# Find the position: we need to insert right before the final "}\n\n\n# ═"
idx = content.index(marker)
# The "}" at idx is the FRAMEWORKS dict closing brace. Insert before it.
new_content = content[:idx] + NEW_FRAMEWORKS + content[idx:]

with open(FRAMEWORKS_FILE, "w") as f:
    f.write(new_content)

print("Successfully injected 5 new frameworks into frameworks.py")
