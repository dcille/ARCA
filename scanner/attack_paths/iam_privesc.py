"""
IAM Privilege Escalation Discovery Engine.

Uses the IAM graph built by iam_graph.py to algorithmically discover:
1. Known privesc patterns (30+ AWS patterns based on Rhino Security research)
2. Shadow admins (non-admin principals that can escalate to admin)
3. Cross-account escalation via role chaining

Phase 3 of BAS 2.0 evolution.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from .models import PrivescPattern, ShadowAdmin, PathConfidence, PathSource
from .iam_graph import IAMGraphBuilder, IAMPrincipal

logger = logging.getLogger(__name__)


# ── AWS Privilege Escalation Patterns ─────────────────────────────────
# Based on Rhino Security Labs research and community contributions.
# Each pattern describes a set of permissions that, when held together,
# allow a non-admin to escalate to admin-equivalent access.

AWS_PRIVESC_PATTERNS: list[PrivescPattern] = [
    # ── IAM Policy Manipulation ───────────────────────────────────────
    PrivescPattern(
        id="aws-privesc-01",
        name="CreatePolicyVersion",
        required_perms=["iam:CreatePolicyVersion"],
        mitre_id="T1098.003",
        description="Can create a new version of an existing managed policy with admin permissions.",
    ),
    PrivescPattern(
        id="aws-privesc-02",
        name="SetDefaultPolicyVersion",
        required_perms=["iam:SetDefaultPolicyVersion"],
        mitre_id="T1098.003",
        description="Can set an older (more permissive) policy version as default.",
    ),
    PrivescPattern(
        id="aws-privesc-03",
        name="AttachUserPolicy",
        required_perms=["iam:AttachUserPolicy"],
        mitre_id="T1098.003",
        description="Can attach admin policy to own user.",
    ),
    PrivescPattern(
        id="aws-privesc-04",
        name="AttachGroupPolicy",
        required_perms=["iam:AttachGroupPolicy"],
        mitre_id="T1098.003",
        description="Can attach admin policy to a group they belong to.",
    ),
    PrivescPattern(
        id="aws-privesc-05",
        name="AttachRolePolicy",
        required_perms=["iam:AttachRolePolicy"],
        mitre_id="T1098.003",
        description="Can attach admin policy to a role they can assume.",
    ),
    PrivescPattern(
        id="aws-privesc-06",
        name="PutUserPolicy",
        required_perms=["iam:PutUserPolicy"],
        mitre_id="T1098.003",
        description="Can add inline admin policy to own user.",
    ),
    PrivescPattern(
        id="aws-privesc-07",
        name="PutGroupPolicy",
        required_perms=["iam:PutGroupPolicy"],
        mitre_id="T1098.003",
        description="Can add inline admin policy to a group they belong to.",
    ),
    PrivescPattern(
        id="aws-privesc-08",
        name="PutRolePolicy",
        required_perms=["iam:PutRolePolicy"],
        mitre_id="T1098.003",
        description="Can add inline admin policy to a role they can assume.",
    ),

    # ── Role Assumption + Policy ──────────────────────────────────────
    PrivescPattern(
        id="aws-privesc-09",
        name="CreateNewUser+LoginProfile",
        required_perms=["iam:CreateUser", "iam:CreateLoginProfile"],
        mitre_id="T1136.003",
        description="Can create a new IAM user with console access.",
    ),
    PrivescPattern(
        id="aws-privesc-10",
        name="CreateAccessKey",
        required_perms=["iam:CreateAccessKey"],
        mitre_id="T1098.001",
        description="Can create access keys for any user (including admins).",
    ),
    PrivescPattern(
        id="aws-privesc-11",
        name="CreateLoginProfile",
        required_perms=["iam:CreateLoginProfile"],
        mitre_id="T1098.001",
        description="Can create console login for users without one (including admins).",
    ),
    PrivescPattern(
        id="aws-privesc-12",
        name="UpdateLoginProfile",
        required_perms=["iam:UpdateLoginProfile"],
        mitre_id="T1098.001",
        description="Can reset passwords for other users (including admins).",
    ),

    # ── PassRole-based Escalation ─────────────────────────────────────
    PrivescPattern(
        id="aws-privesc-13",
        name="PassRole+EC2",
        required_perms=["iam:PassRole", "ec2:RunInstances"],
        mitre_id="T1078.004",
        description="Can launch EC2 with admin role attached.",
    ),
    PrivescPattern(
        id="aws-privesc-14",
        name="PassRole+Lambda",
        required_perms=["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        mitre_id="T1078.004",
        description="Can create Lambda with admin role and invoke it.",
    ),
    PrivescPattern(
        id="aws-privesc-15",
        name="PassRole+Lambda+ExistingTrigger",
        required_perms=["iam:PassRole", "lambda:CreateFunction"],
        mitre_id="T1078.004",
        description="Can create Lambda with admin role triggered by existing event.",
    ),
    PrivescPattern(
        id="aws-privesc-16",
        name="PassRole+Glue",
        required_perms=["iam:PassRole", "glue:CreateDevEndpoint"],
        mitre_id="T1078.004",
        description="Can create Glue dev endpoint with admin role.",
    ),
    PrivescPattern(
        id="aws-privesc-17",
        name="PassRole+CloudFormation",
        required_perms=["iam:PassRole", "cloudformation:CreateStack"],
        mitre_id="T1078.004",
        description="Can create CloudFormation stack with admin role.",
    ),
    PrivescPattern(
        id="aws-privesc-18",
        name="PassRole+DataPipeline",
        required_perms=["iam:PassRole", "datapipeline:CreatePipeline",
                        "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline"],
        mitre_id="T1078.004",
        description="Can create Data Pipeline with admin role.",
    ),
    PrivescPattern(
        id="aws-privesc-19",
        name="PassRole+SageMaker",
        required_perms=["iam:PassRole", "sagemaker:CreateNotebookInstance",
                        "sagemaker:CreatePresignedNotebookInstanceUrl"],
        mitre_id="T1078.004",
        description="Can create SageMaker notebook with admin role.",
    ),
    PrivescPattern(
        id="aws-privesc-20",
        name="PassRole+CodeBuild",
        required_perms=["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"],
        mitre_id="T1078.004",
        description="Can create CodeBuild project with admin role.",
    ),

    # ── Lambda Code Injection ─────────────────────────────────────────
    PrivescPattern(
        id="aws-privesc-21",
        name="UpdateExistingLambdaCode",
        required_perms=["lambda:UpdateFunctionCode"],
        mitre_id="T1525",
        description="Can modify code of existing Lambda running with elevated role.",
    ),
    PrivescPattern(
        id="aws-privesc-22",
        name="UpdateLambdaConfig+Env",
        required_perms=["lambda:UpdateFunctionConfiguration"],
        mitre_id="T1525",
        description="Can modify Lambda env vars/layers to inject code.",
    ),

    # ── STS and Federation ────────────────────────────────────────────
    PrivescPattern(
        id="aws-privesc-23",
        name="AssumeRole",
        required_perms=["sts:AssumeRole"],
        mitre_id="T1550.001",
        description="Can assume roles (check trust policies for exploitable targets).",
    ),

    # ── EC2 SSRF / Metadata ───────────────────────────────────────────
    PrivescPattern(
        id="aws-privesc-24",
        name="EC2+SSRF_Metadata",
        required_perms=["ec2:RunInstances", "ec2:DescribeInstances"],
        mitre_id="T1552.005",
        description="Can launch EC2 and access IMDS to steal instance role credentials.",
    ),

    # ── SSM-based Escalation ──────────────────────────────────────────
    PrivescPattern(
        id="aws-privesc-25",
        name="SSM_SendCommand",
        required_perms=["ssm:SendCommand"],
        mitre_id="T1059.004",
        description="Can execute commands on EC2 instances via SSM with their role.",
    ),
    PrivescPattern(
        id="aws-privesc-26",
        name="SSM_StartSession",
        required_perms=["ssm:StartSession"],
        mitre_id="T1059.004",
        description="Can start SSM session on EC2 to access instance role.",
    ),

    # ── Secrets / Parameter Store ─────────────────────────────────────
    PrivescPattern(
        id="aws-privesc-27",
        name="SecretsManager_GetSecret",
        required_perms=["secretsmanager:GetSecretValue"],
        mitre_id="T1552.004",
        description="Can read secrets that may contain credentials or API keys.",
    ),
    PrivescPattern(
        id="aws-privesc-28",
        name="SSM_GetParameter",
        required_perms=["ssm:GetParameter*"],
        mitre_id="T1552.004",
        description="Can read SSM parameters that may contain credentials.",
    ),

    # ── CloudFormation Manipulation ───────────────────────────────────
    PrivescPattern(
        id="aws-privesc-29",
        name="UpdateExistingStack",
        required_perms=["cloudformation:UpdateStack"],
        mitre_id="T1578",
        description="Can update existing CloudFormation stack to deploy admin resources.",
    ),

    # ── ECR / Container Image ─────────────────────────────────────────
    PrivescPattern(
        id="aws-privesc-30",
        name="ECR_PushImage",
        required_perms=["ecr:PutImage", "ecr:InitiateLayerUpload",
                        "ecr:UploadLayerPart", "ecr:CompleteLayerUpload"],
        mitre_id="T1525",
        description="Can push malicious container images to ECR repositories.",
    ),

    # ── Misc ──────────────────────────────────────────────────────────
    PrivescPattern(
        id="aws-privesc-31",
        name="DeletePermissionBoundary",
        required_perms=["iam:DeleteUserPermissionsBoundary"],
        mitre_id="T1098.003",
        description="Can remove permission boundary that restricts their own access.",
    ),
    PrivescPattern(
        id="aws-privesc-32",
        name="ModifyInstanceAttribute",
        required_perms=["ec2:ModifyInstanceAttribute"],
        mitre_id="T1078.004",
        description="Can modify EC2 instance user data to run commands on reboot.",
    ),
]


# ── Azure Privilege Escalation Patterns ──────────────────────────────
# Based on Azure AD / Entra ID and RBAC privilege escalation research.

AZURE_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="azure-privesc-01",
        name="UserAccessAdministrator",
        required_perms=["Microsoft.Authorization/roleAssignments/write"],
        mitre_id="T1098.003",
        description="Can assign any RBAC role, including Owner, to any principal.",
        provider="azure",
    ),
    PrivescPattern(
        id="azure-privesc-02",
        name="ServicePrincipalCredentialAdd",
        required_perms=["microsoft.directory/servicePrincipals/credentials/update"],
        mitre_id="T1098.001",
        description="Can add credentials to a service principal to impersonate it.",
        provider="azure",
    ),
    PrivescPattern(
        id="azure-privesc-03",
        name="ApplicationCredentialAdd",
        required_perms=["microsoft.directory/applications/credentials/update"],
        mitre_id="T1098.001",
        description="Can add credentials to an app registration to obtain its permissions.",
        provider="azure",
    ),
    PrivescPattern(
        id="azure-privesc-04",
        name="KeyVaultSecretAccess",
        required_perms=["Microsoft.KeyVault/vaults/secrets/getSecret/action"],
        mitre_id="T1552.004",
        description="Can read Key Vault secrets that may contain credentials or keys.",
        provider="azure",
    ),
    PrivescPattern(
        id="azure-privesc-05",
        name="GlobalAdminRoleActivation",
        required_perms=["microsoft.directory/roleAssignments/allProperties/allTasks"],
        mitre_id="T1098.003",
        description="Can activate Global Administrator role via PIM or direct assignment.",
        provider="azure",
    ),
    PrivescPattern(
        id="azure-privesc-06",
        name="AutomationRunAsAccount",
        required_perms=["Microsoft.Automation/automationAccounts/runbooks/write",
                        "Microsoft.Automation/automationAccounts/jobs/write"],
        mitre_id="T1078.004",
        description="Can create/run automation runbook using elevated RunAs account.",
        provider="azure",
    ),
    PrivescPattern(
        id="azure-privesc-07",
        name="VMRunCommand",
        required_perms=["Microsoft.Compute/virtualMachines/runCommand/action"],
        mitre_id="T1059.004",
        description="Can execute commands on VMs with their managed identity.",
        provider="azure",
    ),
    PrivescPattern(
        id="azure-privesc-08",
        name="ManagedIdentityTokenAccess",
        required_perms=["Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
                        "Microsoft.Compute/virtualMachines/write"],
        mitre_id="T1550.001",
        description="Can assign a managed identity to a VM to steal its token.",
        provider="azure",
    ),
    PrivescPattern(
        id="azure-privesc-09",
        name="CustomRoleEscalation",
        required_perms=["Microsoft.Authorization/roleDefinitions/write"],
        mitre_id="T1098.003",
        description="Can create or modify custom RBAC roles to grant elevated permissions.",
        provider="azure",
    ),
    PrivescPattern(
        id="azure-privesc-10",
        name="ConditionalAccessBypass",
        required_perms=["microsoft.directory/conditionalAccessPolicies/delete"],
        mitre_id="T1556",
        description="Can delete Conditional Access policies to weaken authentication controls.",
        provider="azure",
    ),
]


# ── GCP Privilege Escalation Patterns ────────────────────────────────
# Based on GCP IAM & service account escalation research.

GCP_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="gcp-privesc-01",
        name="SetIAMPolicy",
        required_perms=["resourcemanager.projects.setIamPolicy"],
        mitre_id="T1098.003",
        description="Can set IAM policy on a project, granting any role to any principal.",
        provider="gcp",
    ),
    PrivescPattern(
        id="gcp-privesc-02",
        name="ServiceAccountKeyCreate",
        required_perms=["iam.serviceAccountKeys.create"],
        mitre_id="T1098.001",
        description="Can create keys for any service account to impersonate it.",
        provider="gcp",
    ),
    PrivescPattern(
        id="gcp-privesc-03",
        name="ServiceAccountTokenCreator",
        required_perms=["iam.serviceAccounts.getAccessToken"],
        mitre_id="T1550.001",
        description="Can generate access tokens for service accounts.",
        provider="gcp",
    ),
    PrivescPattern(
        id="gcp-privesc-04",
        name="ServiceAccountImpersonation",
        required_perms=["iam.serviceAccounts.implicitDelegation"],
        mitre_id="T1550.001",
        description="Can impersonate a service account via delegation chain.",
        provider="gcp",
    ),
    PrivescPattern(
        id="gcp-privesc-05",
        name="CloudFunctionDeploy",
        required_perms=["cloudfunctions.functions.create", "cloudfunctions.functions.call",
                        "iam.serviceAccounts.actAs"],
        mitre_id="T1078.004",
        description="Can deploy Cloud Function with elevated service account.",
        provider="gcp",
    ),
    PrivescPattern(
        id="gcp-privesc-06",
        name="ComputeInstanceSA",
        required_perms=["compute.instances.create", "iam.serviceAccounts.actAs"],
        mitre_id="T1078.004",
        description="Can create compute instance with elevated service account.",
        provider="gcp",
    ),
    PrivescPattern(
        id="gcp-privesc-07",
        name="CustomRoleUpdate",
        required_perms=["iam.roles.update"],
        mitre_id="T1098.003",
        description="Can modify custom roles to add elevated permissions.",
        provider="gcp",
    ),
    PrivescPattern(
        id="gcp-privesc-08",
        name="ComputeSSH",
        required_perms=["compute.instances.setMetadata", "compute.projects.setCommonInstanceMetadata"],
        mitre_id="T1059.004",
        description="Can inject SSH keys via instance/project metadata.",
        provider="gcp",
    ),
    PrivescPattern(
        id="gcp-privesc-09",
        name="CloudBuildEditor",
        required_perms=["cloudbuild.builds.create"],
        mitre_id="T1078.004",
        description="Can create Cloud Build jobs that run as the Cloud Build service account.",
        provider="gcp",
    ),
    PrivescPattern(
        id="gcp-privesc-10",
        name="OrgPolicyBypass",
        required_perms=["orgpolicy.policy.set"],
        mitre_id="T1562.001",
        description="Can modify org policies to disable security guardrails.",
        provider="gcp",
    ),
]


# ── OCI Privilege Escalation Patterns ────────────────────────────────

OCI_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="oci-privesc-01",
        name="PolicyManipulation",
        required_perms=["manage policies in tenancy"],
        mitre_id="T1098.003",
        description="Can create or modify IAM policies to grant admin access.",
        provider="oci",
    ),
    PrivescPattern(
        id="oci-privesc-02",
        name="UserGroupManipulation",
        required_perms=["manage groups in tenancy", "manage users in tenancy"],
        mitre_id="T1098.003",
        description="Can add self to admin groups.",
        provider="oci",
    ),
    PrivescPattern(
        id="oci-privesc-03",
        name="APIKeyAdd",
        required_perms=["manage users in tenancy"],
        mitre_id="T1098.001",
        description="Can add API keys to other users to impersonate them.",
        provider="oci",
    ),
    PrivescPattern(
        id="oci-privesc-04",
        name="DynamicGroupManipulation",
        required_perms=["manage dynamic-groups in tenancy"],
        mitre_id="T1078.004",
        description="Can create dynamic group rules to include attacker-controlled instances.",
        provider="oci",
    ),
    PrivescPattern(
        id="oci-privesc-05",
        name="InstancePrincipalAbuse",
        required_perms=["manage instances in compartment"],
        mitre_id="T1078.004",
        description="Can launch instance matching admin dynamic group for elevated permissions.",
        provider="oci",
    ),
    PrivescPattern(
        id="oci-privesc-06",
        name="VaultSecretAccess",
        required_perms=["read secret-family in compartment"],
        mitre_id="T1552.004",
        description="Can read vault secrets containing credentials.",
        provider="oci",
    ),
]


# ── Alibaba Cloud Privilege Escalation Patterns ──────────────────────

ALIBABA_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="ali-privesc-01",
        name="RAMPolicyAttach",
        required_perms=["ram:AttachPolicyToUser", "ram:AttachPolicyToGroup"],
        mitre_id="T1098.003",
        description="Can attach AdministratorAccess policy to users or groups.",
        provider="alibaba",
    ),
    PrivescPattern(
        id="ali-privesc-02",
        name="RAMUserAccessKeyCreate",
        required_perms=["ram:CreateAccessKey"],
        mitre_id="T1098.001",
        description="Can create access keys for other RAM users.",
        provider="alibaba",
    ),
    PrivescPattern(
        id="ali-privesc-03",
        name="RAMRoleAssume",
        required_perms=["sts:AssumeRole"],
        mitre_id="T1550.001",
        description="Can assume RAM roles with elevated permissions.",
        provider="alibaba",
    ),
    PrivescPattern(
        id="ali-privesc-04",
        name="RAMPolicyUpdate",
        required_perms=["ram:CreatePolicyVersion", "ram:SetDefaultPolicyVersion"],
        mitre_id="T1098.003",
        description="Can create and set permissive policy versions.",
        provider="alibaba",
    ),
    PrivescPattern(
        id="ali-privesc-05",
        name="ECSInstanceRAMRole",
        required_perms=["ecs:AttachInstanceRamRole", "ecs:RunInstances"],
        mitre_id="T1078.004",
        description="Can launch ECS instance with admin RAM role.",
        provider="alibaba",
    ),
    PrivescPattern(
        id="ali-privesc-06",
        name="FunctionComputeEscalation",
        required_perms=["fc:CreateFunction", "fc:InvokeFunction", "ram:PassRole"],
        mitre_id="T1078.004",
        description="Can create Function Compute function with elevated service role.",
        provider="alibaba",
    ),
]


# ── IBM Cloud Privilege Escalation Patterns ──────────────────────────

IBM_CLOUD_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="ibm-privesc-01",
        name="IAMPolicyCreate",
        required_perms=["iam-identity.policy.create", "iam-identity.policy.update"],
        mitre_id="T1098.003",
        description="Can create or update IAM access policies to grant admin access.",
        provider="ibm_cloud",
    ),
    PrivescPattern(
        id="ibm-privesc-02",
        name="ServiceIDKeyCreate",
        required_perms=["iam-identity.apikey.create"],
        mitre_id="T1098.001",
        description="Can create API keys for service IDs with elevated permissions.",
        provider="ibm_cloud",
    ),
    PrivescPattern(
        id="ibm-privesc-03",
        name="AccessGroupManipulation",
        required_perms=["iam-groups.groups.update", "iam-groups.members.add"],
        mitre_id="T1098.003",
        description="Can add users/service IDs to access groups with admin policies.",
        provider="ibm_cloud",
    ),
    PrivescPattern(
        id="ibm-privesc-04",
        name="TrustedProfileAbuse",
        required_perms=["iam-identity.profile.create", "iam-identity.profile.linkToResource"],
        mitre_id="T1078.004",
        description="Can create trusted profiles linked to compute resources for token theft.",
        provider="ibm_cloud",
    ),
]


# ── Kubernetes Privilege Escalation Patterns ─────────────────────────
# Based on Kubernetes RBAC escalation research.

K8S_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="k8s-privesc-01",
        name="ClusterRoleBinding",
        required_perms=["rbac.authorization.k8s.io/clusterrolebindings:create"],
        mitre_id="T1098.003",
        description="Can bind cluster-admin ClusterRole to any subject.",
        provider="kubernetes",
    ),
    PrivescPattern(
        id="k8s-privesc-02",
        name="PodCreate+ServiceAccount",
        required_perms=["pods:create"],
        mitre_id="T1078.004",
        description="Can create pod mounting privileged service account token.",
        provider="kubernetes",
    ),
    PrivescPattern(
        id="k8s-privesc-03",
        name="PodExec",
        required_perms=["pods/exec:create"],
        mitre_id="T1059.004",
        description="Can exec into pods running with privileged service accounts.",
        provider="kubernetes",
    ),
    PrivescPattern(
        id="k8s-privesc-04",
        name="SecretRead",
        required_perms=["secrets:get", "secrets:list"],
        mitre_id="T1552.004",
        description="Can read all secrets including service account tokens.",
        provider="kubernetes",
    ),
    PrivescPattern(
        id="k8s-privesc-05",
        name="NodeProxy",
        required_perms=["nodes/proxy:create"],
        mitre_id="T1021",
        description="Can access the Kubelet API to execute commands in any pod on a node.",
        provider="kubernetes",
    ),
    PrivescPattern(
        id="k8s-privesc-06",
        name="ImpersonateUser",
        required_perms=["users:impersonate"],
        mitre_id="T1550.001",
        description="Can impersonate any user including cluster-admin.",
        provider="kubernetes",
    ),
    PrivescPattern(
        id="k8s-privesc-07",
        name="CSRApproval",
        required_perms=["certificatesigningrequests:create",
                        "certificatesigningrequests/approval:update"],
        mitre_id="T1098.001",
        description="Can create and approve CSRs to obtain certificates for any identity.",
        provider="kubernetes",
    ),
]


# ── SaaS Privilege Escalation Patterns ───────────────────────────────

M365_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="m365-privesc-01",
        name="ExchangeAdminRoleAssign",
        required_perms=["RoleManagement.ReadWrite.All"],
        mitre_id="T1098.003",
        description="Can assign Exchange admin or Global admin roles.",
        provider="m365",
    ),
    PrivescPattern(
        id="m365-privesc-02",
        name="MailboxDelegation",
        required_perms=["Mail.ReadWrite"],
        mitre_id="T1098.002",
        description="Can set mailbox delegation to read other users' email.",
        provider="m365",
    ),
    PrivescPattern(
        id="m365-privesc-03",
        name="AppConsentGrant",
        required_perms=["AppRoleAssignment.ReadWrite.All"],
        mitre_id="T1098.003",
        description="Can grant admin consent to OAuth apps with broad permissions.",
        provider="m365",
    ),
    PrivescPattern(
        id="m365-privesc-04",
        name="eDiscoveryExfiltration",
        required_perms=["eDiscovery.ReadWrite.All"],
        mitre_id="T1114.002",
        description="Can run eDiscovery searches across all mailboxes and SharePoint.",
        provider="m365",
    ),
]

GITHUB_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="gh-privesc-01",
        name="OrgOwnerPromotion",
        required_perms=["admin:org"],
        mitre_id="T1098.003",
        description="Can promote users to org owners, granting full repository access.",
        provider="github",
    ),
    PrivescPattern(
        id="gh-privesc-02",
        name="SecretsExfiltration",
        required_perms=["admin:org", "repo"],
        mitre_id="T1552.004",
        description="Can read org-level secrets via workflow dispatch.",
        provider="github",
    ),
    PrivescPattern(
        id="gh-privesc-03",
        name="WorkflowInjection",
        required_perms=["repo:write", "actions:write"],
        mitre_id="T1525",
        description="Can modify workflows to exfiltrate secrets via CI/CD pipeline.",
        provider="github",
    ),
    PrivescPattern(
        id="gh-privesc-04",
        name="DeployKeyCompromise",
        required_perms=["admin:repo_hook", "admin:public_key"],
        mitre_id="T1098.001",
        description="Can add deploy keys for persistent repo access.",
        provider="github",
    ),
]

GWS_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="gws-privesc-01",
        name="SuperAdminPromotion",
        required_perms=["admin.directory.users.update"],
        mitre_id="T1098.003",
        description="Can promote user to super admin role.",
        provider="google_workspace",
    ),
    PrivescPattern(
        id="gws-privesc-02",
        name="DomainWideDelgation",
        required_perms=["admin.directory.domainAliases", "iam.serviceAccountKeys.create"],
        mitre_id="T1550.001",
        description="Can configure domain-wide delegation for a service account.",
        provider="google_workspace",
    ),
    PrivescPattern(
        id="gws-privesc-03",
        name="OAuthAppApproval",
        required_perms=["admin.directory.oauthApps"],
        mitre_id="T1098.003",
        description="Can approve OAuth apps with broad Drive/Gmail scopes.",
        provider="google_workspace",
    ),
    PrivescPattern(
        id="gws-privesc-04",
        name="AdminAPITokenTheft",
        required_perms=["admin.directory.users.readonly"],
        mitre_id="T1528",
        description="Can enumerate users to target for phishing or credential stuffing.",
        provider="google_workspace",
    ),
]

SALESFORCE_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="sf-privesc-01",
        name="PermissionSetAssign",
        required_perms=["ManageUsers", "AssignPermissionSets"],
        mitre_id="T1098.003",
        description="Can assign System Administrator permission set to any user.",
        provider="salesforce",
    ),
    PrivescPattern(
        id="sf-privesc-02",
        name="ConnectedAppAbuse",
        required_perms=["ManageConnectedApps"],
        mitre_id="T1098.001",
        description="Can create connected apps with OAuth for persistent API access.",
        provider="salesforce",
    ),
    PrivescPattern(
        id="sf-privesc-03",
        name="ApexCodeExecution",
        required_perms=["AuthorApex"],
        mitre_id="T1059",
        description="Can execute arbitrary Apex code with system-level access.",
        provider="salesforce",
    ),
    PrivescPattern(
        id="sf-privesc-04",
        name="FieldLevelSecurityBypass",
        required_perms=["ManageProfilesPermissionsets", "CustomizeApplication"],
        mitre_id="T1548",
        description="Can modify field-level security to access restricted data.",
        provider="salesforce",
    ),
]

SERVICENOW_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="sn-privesc-01",
        name="AdminRoleGrant",
        required_perms=["admin", "user_admin"],
        mitre_id="T1098.003",
        description="Can assign admin role to any user.",
        provider="servicenow",
    ),
    PrivescPattern(
        id="sn-privesc-02",
        name="ACLBypass",
        required_perms=["admin", "security_admin"],
        mitre_id="T1548",
        description="Can modify ACL rules to bypass access controls on tables.",
        provider="servicenow",
    ),
    PrivescPattern(
        id="sn-privesc-03",
        name="ScriptExecution",
        required_perms=["admin", "script_execution"],
        mitre_id="T1059",
        description="Can execute background scripts with full system access.",
        provider="servicenow",
    ),
    PrivescPattern(
        id="sn-privesc-04",
        name="IntegrationCredentialAccess",
        required_perms=["admin", "credential_admin"],
        mitre_id="T1552.004",
        description="Can read integration credentials and connection aliases.",
        provider="servicenow",
    ),
]

SNOWFLAKE_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="snow-privesc-01",
        name="AccountAdminGrant",
        required_perms=["MANAGE GRANTS"],
        mitre_id="T1098.003",
        description="Can grant ACCOUNTADMIN role to any user.",
        provider="snowflake",
    ),
    PrivescPattern(
        id="snow-privesc-02",
        name="NetworkPolicyBypass",
        required_perms=["CREATE NETWORK POLICY", "APPLY NETWORK POLICY"],
        mitre_id="T1562.001",
        description="Can modify network policies to allow access from any IP.",
        provider="snowflake",
    ),
    PrivescPattern(
        id="snow-privesc-03",
        name="ExternalFunctionExec",
        required_perms=["CREATE EXTERNAL FUNCTION", "USAGE ON INTEGRATION"],
        mitre_id="T1059",
        description="Can create external functions to exfiltrate data via API calls.",
        provider="snowflake",
    ),
    PrivescPattern(
        id="snow-privesc-04",
        name="MaskingPolicyBypass",
        required_perms=["APPLY MASKING POLICY", "CREATE MASKING POLICY"],
        mitre_id="T1548",
        description="Can modify masking policies to reveal protected columns.",
        provider="snowflake",
    ),
]

CLOUDFLARE_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="cf-privesc-01",
        name="SuperAdminInvite",
        required_perms=["#member:edit"],
        mitre_id="T1098.003",
        description="Can invite users with Super Administrator role.",
        provider="cloudflare",
    ),
    PrivescPattern(
        id="cf-privesc-02",
        name="APITokenCreate",
        required_perms=["#api_tokens:edit"],
        mitre_id="T1098.001",
        description="Can create API tokens with elevated permissions.",
        provider="cloudflare",
    ),
    PrivescPattern(
        id="cf-privesc-03",
        name="WorkerScriptInject",
        required_perms=["#worker:edit"],
        mitre_id="T1525",
        description="Can deploy Workers to intercept/modify traffic or exfiltrate data.",
        provider="cloudflare",
    ),
    PrivescPattern(
        id="cf-privesc-04",
        name="DNSManipulation",
        required_perms=["#dns_records:edit"],
        mitre_id="T1584.002",
        description="Can modify DNS records to redirect traffic.",
        provider="cloudflare",
    ),
]

OPENSTACK_PRIVESC_PATTERNS: list[PrivescPattern] = [
    PrivescPattern(
        id="os-privesc-01",
        name="RoleAssignment",
        required_perms=["identity:create_grant"],
        mitre_id="T1098.003",
        description="Can assign admin role to any user on any project.",
        provider="openstack",
    ),
    PrivescPattern(
        id="os-privesc-02",
        name="TrustCreate",
        required_perms=["identity:create_trust"],
        mitre_id="T1550.001",
        description="Can create trusts to impersonate other users.",
        provider="openstack",
    ),
    PrivescPattern(
        id="os-privesc-03",
        name="CredentialCreate",
        required_perms=["identity:create_credential"],
        mitre_id="T1098.001",
        description="Can create EC2/application credentials for any user.",
        provider="openstack",
    ),
    PrivescPattern(
        id="os-privesc-04",
        name="PolicyFileOverride",
        required_perms=["compute:inject_network_info", "compute:create"],
        mitre_id="T1078.004",
        description="Can launch instances with metadata service access to steal tokens.",
        provider="openstack",
    ),
]


# ── Unified Pattern Registry ─────────────────────────────────────────

ALL_PRIVESC_PATTERNS: dict[str, list[PrivescPattern]] = {
    "aws": AWS_PRIVESC_PATTERNS,
    "azure": AZURE_PRIVESC_PATTERNS,
    "gcp": GCP_PRIVESC_PATTERNS,
    "oci": OCI_PRIVESC_PATTERNS,
    "alibaba": ALIBABA_PRIVESC_PATTERNS,
    "ibm_cloud": IBM_CLOUD_PRIVESC_PATTERNS,
    "kubernetes": K8S_PRIVESC_PATTERNS,
    "m365": M365_PRIVESC_PATTERNS,
    "github": GITHUB_PRIVESC_PATTERNS,
    "google_workspace": GWS_PRIVESC_PATTERNS,
    "salesforce": SALESFORCE_PRIVESC_PATTERNS,
    "servicenow": SERVICENOW_PRIVESC_PATTERNS,
    "snowflake": SNOWFLAKE_PRIVESC_PATTERNS,
    "cloudflare": CLOUDFLARE_PRIVESC_PATTERNS,
    "openstack": OPENSTACK_PRIVESC_PATTERNS,
}


def build_from_provider(provider: str) -> list[PrivescPattern]:
    """Factory: return the privesc patterns for a given cloud/SaaS provider."""
    return ALL_PRIVESC_PATTERNS.get(provider, [])


# ── Privesc Discovery Engine ──────────────────────────────────────────


@dataclass
class PrivescFinding:
    """A discovered privilege escalation path."""
    principal: IAMPrincipal
    pattern: PrivescPattern
    matched_perms: list[str]
    escalation_target: str  # e.g., "admin", "role:XYZ"
    steps: int
    via_roles: list[str] = field(default_factory=list)  # role chain


class IAMPrivescDiscovery:
    """
    Discovers privilege escalation paths in the IAM graph.

    Takes the IAM graph from IAMGraphBuilder and checks each non-admin
    principal against all known privesc patterns.
    """

    def __init__(
        self,
        iam_builder: IAMGraphBuilder,
        patterns: Optional[list[PrivescPattern]] = None,
        provider: Optional[str] = None,
    ):
        self.builder = iam_builder
        if patterns is not None:
            self.patterns = patterns
        elif provider is not None:
            self.patterns = build_from_provider(provider)
        else:
            self.patterns = AWS_PRIVESC_PATTERNS
        self.provider = provider or "aws"
        self.findings: list[PrivescFinding] = []
        self.shadow_admins: list[ShadowAdmin] = []

    def discover(self) -> list[PrivescFinding]:
        """
        Run privilege escalation discovery.
        Returns list of PrivescFinding sorted by severity.
        """
        self.findings = []
        self.shadow_admins = []

        principals = self.builder.get_all_principals()

        for principal in principals:
            if principal.principal_type == "group":
                continue  # Groups don't act directly
            if principal.is_admin():
                continue  # Already admin, no escalation needed

            # Get effective permissions (including via assumable roles)
            effective = self.builder.get_effective_permissions(principal)

            # Check direct permissions
            direct_findings = self._check_patterns(principal, effective, via_roles=[])

            # Check via role assumption chains
            role_chain_findings = self._check_role_chain_escalation(principal)

            all_findings = direct_findings + role_chain_findings
            self.findings.extend(all_findings)

            # If any finding leads to admin, this is a shadow admin
            if all_findings:
                self.shadow_admins.append(ShadowAdmin(
                    principal_id=principal.arn,
                    principal_name=principal.name,
                    principal_type=f"iam_{principal.principal_type}",
                    provider=self.provider,
                    escalation_paths=[f.pattern.id for f in all_findings],
                    shortest_path_steps=min(f.steps for f in all_findings),
                    blast_radius_estimate=self._estimate_blast_radius(principal, all_findings),
                ))

        logger.info(
            "Privesc discovery complete: %d findings, %d shadow admins",
            len(self.findings),
            len(self.shadow_admins),
        )
        return self.findings

    def _check_patterns(
        self,
        principal: IAMPrincipal,
        effective_perms: set[str],
        via_roles: list[str],
    ) -> list[PrivescFinding]:
        """Check all privesc patterns against a principal's effective permissions."""
        findings = []
        for pattern in self.patterns:
            if pattern.matches(effective_perms):
                matched = [
                    p for p in pattern.required_perms
                    if any(
                        self._perm_matches(p, ep)
                        for ep in effective_perms
                    )
                ]
                findings.append(PrivescFinding(
                    principal=principal,
                    pattern=pattern,
                    matched_perms=matched,
                    escalation_target="admin",
                    steps=1 + len(via_roles),
                    via_roles=via_roles,
                ))
        return findings

    def _check_role_chain_escalation(self, principal: IAMPrincipal) -> list[PrivescFinding]:
        """
        Check if a principal can escalate via role assumption chains.
        E.g., UserA → RoleB → RoleC (admin)
        """
        findings = []
        visited = set()

        def _dfs(current: IAMPrincipal, chain: list[str], depth: int):
            if depth > 4:  # Max chain depth
                return
            current_id = current.arn
            if current_id in visited:
                return
            visited.add(current_id)

            assumable = self.builder.get_assumable_roles(current)
            for role in assumable:
                role_chain = chain + [role.name]

                # Check if the role itself is admin
                if role.is_admin():
                    findings.append(PrivescFinding(
                        principal=principal,
                        pattern=PrivescPattern(
                            id=f"aws-privesc-chain-{len(role_chain)}",
                            name=f"RoleChain-{'->'.join(role_chain)}",
                            required_perms=["sts:AssumeRole"],
                            mitre_id="T1550.001",
                            description=f"Can escalate to admin via role chain: {' → '.join(role_chain)}",
                        ),
                        matched_perms=["sts:AssumeRole"],
                        escalation_target=f"role:{role.name}",
                        steps=len(role_chain),
                        via_roles=role_chain,
                    ))
                else:
                    # Check privesc patterns with the role's permissions
                    role_perms = set(role.effective_allows)
                    role_findings = self._check_patterns(principal, role_perms, via_roles=role_chain)
                    findings.extend(role_findings)

                    # Continue DFS
                    _dfs(role, role_chain, depth + 1)

        _dfs(principal, [], 0)
        return findings

    def _estimate_blast_radius(
        self,
        principal: IAMPrincipal,
        findings: list[PrivescFinding],
    ) -> int:
        """Estimate the blast radius if this principal escalates."""
        # If they can become admin, blast radius = all resources
        for f in findings:
            if f.escalation_target == "admin":
                return len(self.builder.graph.nodes)

        # Otherwise, count reachable nodes from the principal's position
        node_id = self.builder._node_id(principal)
        visited = set()
        queue = [node_id]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            for edge in self.builder.graph.adjacency.get(current, []):
                if edge.target not in visited:
                    queue.append(edge.target)
        return len(visited)

    @staticmethod
    def _perm_matches(required: str, effective: str) -> bool:
        """Check if an effective permission satisfies a required permission."""
        req = required.lower()
        eff = effective.lower()
        if eff == "*" or eff == "*:*":
            return True
        if req.endswith("*"):
            return eff.startswith(req[:-1])
        if eff.endswith("*"):
            req_parts = req.split(":")
            eff_parts = eff.split(":")
            if len(req_parts) == 2 and len(eff_parts) == 2:
                if req_parts[0] == eff_parts[0]:
                    return True
        return req == eff

    # ── Output Methods ────────────────────────────────────────────────

    def get_shadow_admins(self) -> list[ShadowAdmin]:
        """Get discovered shadow admins."""
        return sorted(self.shadow_admins, key=lambda s: s.shortest_path_steps)

    def get_findings_by_severity(self) -> dict[str, list[PrivescFinding]]:
        """Group findings by severity (based on steps to escalate)."""
        result: dict[str, list[PrivescFinding]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }
        for f in self.findings:
            if f.steps == 1:
                result["critical"].append(f)
            elif f.steps == 2:
                result["high"].append(f)
            elif f.steps <= 3:
                result["medium"].append(f)
            else:
                result["low"].append(f)
        return result

    def to_attack_paths(self) -> list[dict]:
        """
        Convert privesc findings to attack path dicts compatible with
        the graph_engine.AttackPath format for unified storage and display.
        """
        paths = []
        seen_patterns: set[str] = set()

        for finding in self.findings:
            # Deduplicate by principal + pattern
            key = f"{finding.principal.arn}:{finding.pattern.id}"
            if key in seen_patterns:
                continue
            seen_patterns.add(key)

            severity = "critical" if finding.steps == 1 else (
                "high" if finding.steps == 2 else "medium"
            )

            path = {
                "title": f"IAM Privesc: {finding.pattern.name} via {finding.principal.name}",
                "description": finding.pattern.description,
                "severity": severity,
                "category": "privilege_escalation",
                "entry_point": f"iam:{finding.principal.principal_type}:{finding.principal.name}",
                "target": finding.escalation_target,
                "techniques": [finding.pattern.mitre_id],
                "affected_resources": [finding.principal.arn] + [
                    f"role:{r}" for r in finding.via_roles
                ],
                "remediation": self._generate_remediation(finding),
                "confidence": PathConfidence.THEORETICAL.value,
                "source": PathSource.IAM_DISCOVERY.value,
                "nodes": self._build_path_nodes(finding),
                "edges": self._build_path_edges(finding),
            }
            paths.append(path)

        return paths

    def _generate_remediation(self, finding: PrivescFinding) -> list[str]:
        """Generate remediation steps for a privesc finding."""
        remediation = []
        pattern = finding.pattern

        if "PassRole" in pattern.name:
            remediation.append(
                f"Restrict iam:PassRole for {finding.principal.name} to specific role ARNs using resource conditions."
            )
        if "AttachUserPolicy" in pattern.name or "AttachRolePolicy" in pattern.name or "AttachGroupPolicy" in pattern.name:
            remediation.append(
                f"Remove {pattern.required_perms[0]} from {finding.principal.name} or restrict via conditions."
            )
        if "PutUserPolicy" in pattern.name or "PutRolePolicy" in pattern.name or "PutGroupPolicy" in pattern.name:
            remediation.append(
                f"Remove inline policy write permissions from {finding.principal.name}."
            )
        if "CreatePolicyVersion" in pattern.name:
            remediation.append(
                "Restrict iam:CreatePolicyVersion with conditions or use SCPs."
            )
        if "CreateAccessKey" in pattern.name:
            remediation.append(
                f"Restrict iam:CreateAccessKey for {finding.principal.name} to only their own user."
            )
        if "Lambda" in pattern.name:
            remediation.append(
                "Restrict Lambda function creation/modification to specific roles."
            )

        # Generic recommendations
        remediation.append(
            "Apply least-privilege: review and minimize permissions for this principal."
        )
        if not finding.principal.permission_boundary:
            remediation.append(
                "Add a permission boundary to restrict the maximum permissions this principal can have."
            )

        return remediation

    def _build_path_nodes(self, finding: PrivescFinding) -> list[dict]:
        """Build graph nodes for visualization of this privesc path."""
        nodes = [
            {
                "id": f"iam:{finding.principal.principal_type}:{finding.principal.name}",
                "node_type": "identity",
                "label": finding.principal.name,
                "service": f"IAM {finding.principal.principal_type}",
                "severity": "",
                "metadata": {"arn": finding.principal.arn},
            }
        ]

        for i, role_name in enumerate(finding.via_roles):
            nodes.append({
                "id": f"iam:role:{role_name}",
                "node_type": "identity",
                "label": role_name,
                "service": "IAM Role",
                "severity": "",
                "metadata": {"step": i + 1},
            })

        nodes.append({
            "id": f"target:{finding.escalation_target}",
            "node_type": "resource",
            "label": finding.escalation_target,
            "service": "Target",
            "severity": "critical",
            "metadata": {"pattern": finding.pattern.id},
        })

        return nodes

    def _build_path_edges(self, finding: PrivescFinding) -> list[dict]:
        """Build graph edges for visualization of this privesc path."""
        edges = []
        prev_id = f"iam:{finding.principal.principal_type}:{finding.principal.name}"

        for role_name in finding.via_roles:
            role_id = f"iam:role:{role_name}"
            edges.append({
                "source_id": prev_id,
                "target_id": role_id,
                "edge_type": "assumes_role",
                "label": "assumes role",
            })
            prev_id = role_id

        edges.append({
            "source_id": prev_id,
            "target_id": f"target:{finding.escalation_target}",
            "edge_type": "privilege_escalation",
            "label": finding.pattern.name,
        })

        return edges

    def to_summary(self) -> dict:
        """Summary for logging/display."""
        by_sev = self.get_findings_by_severity()
        return {
            "total_findings": len(self.findings),
            "shadow_admins": len(self.shadow_admins),
            "critical": len(by_sev["critical"]),
            "high": len(by_sev["high"]),
            "medium": len(by_sev["medium"]),
            "low": len(by_sev["low"]),
            "top_patterns": self._top_patterns(5),
            "shadow_admin_names": [s.principal_name for s in self.shadow_admins[:10]],
        }

    def _top_patterns(self, n: int) -> list[dict]:
        """Get the most common privesc patterns found."""
        pattern_count: dict[str, int] = {}
        for f in self.findings:
            pid = f.pattern.id
            pattern_count[pid] = pattern_count.get(pid, 0) + 1
        top = sorted(pattern_count.items(), key=lambda x: x[1], reverse=True)[:n]
        return [{"pattern_id": pid, "count": count} for pid, count in top]
