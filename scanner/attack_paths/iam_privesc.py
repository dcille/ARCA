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
    ):
        self.builder = iam_builder
        self.patterns = patterns or AWS_PRIVESC_PATTERNS
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
                    provider="aws",
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
