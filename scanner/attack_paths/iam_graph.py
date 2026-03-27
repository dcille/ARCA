"""
Multi-Cloud IAM Graph Builder.

Reads IAM configuration via read-only API calls and builds a directed graph
of principals → policies → permissions → resources.
This enables algorithmic discovery of privilege escalation paths, overprivileged
identities, and shadow-admin detection.

Supports: AWS, Azure, GCP (and extensible to any provider).

Phase 2 of BAS 2.0 evolution.
"""
from __future__ import annotations

import abc
import json
import fnmatch
import logging
from dataclasses import dataclass, field
from typing import Optional

from .graph import NodeType, EdgeType, Node, Edge, AttackGraph

logger = logging.getLogger(__name__)


# ── IAM-specific node/edge type extensions ────────────────────────────


class IAMNodeType:
    """Extended node types for IAM graph (supplement graph.py NodeType)."""
    # Provider-agnostic
    IAM_GROUP = "iam_group"
    IAM_MANAGED_POLICY = "iam_managed_policy"
    IAM_INLINE_POLICY = "iam_inline_policy"
    IAM_SERVICE_PRINCIPAL = "iam_service_principal"
    IAM_MANAGED_IDENTITY = "iam_managed_identity"
    IAM_SERVICE_ACCOUNT = "iam_service_account"
    RESOURCE = "resource"
    # Provider-specific (kept for backward compat)
    AWS_SERVICE = "aws_service"


class IAMEdgeType:
    """Extended edge types for IAM graph."""
    MEMBER_OF = "member_of"           # user → group
    HAS_INLINE_POLICY = "has_inline"  # principal → inline policy
    HAS_MANAGED_POLICY = "has_managed"  # principal → managed policy
    POLICY_GRANTS = "policy_grants"   # policy → resource (Allow action)
    CAN_ASSUME = "can_assume"         # principal → role (role assumption / impersonation)
    PERMISSION_BOUNDARY = "perm_boundary"  # principal → boundary policy
    SERVICE_LINKED = "service_linked"  # role → service
    HAS_ROLE_ASSIGNMENT = "has_role_assignment"  # principal → RBAC role (Azure)
    HAS_BINDING = "has_binding"       # principal → IAM binding (GCP)


# ── Data classes for parsed IAM ───────────────────────────────────────


@dataclass
class IAMStatement:
    """A single IAM policy statement (provider-agnostic)."""
    effect: str  # Allow | Deny
    actions: list[str]
    resources: list[str]
    conditions: dict = field(default_factory=dict)
    principals: list[str] = field(default_factory=list)

    @classmethod
    def from_aws_dict(cls, stmt: dict) -> IAMStatement:
        """Parse from AWS IAM policy statement format."""
        actions = stmt.get("Action", stmt.get("NotAction", []))
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", stmt.get("NotResource", ["*"]))
        if isinstance(resources, str):
            resources = [resources]
        principals = stmt.get("Principal", [])
        if isinstance(principals, str):
            principals = [principals]
        elif isinstance(principals, dict):
            # {"AWS": ["arn:..."]} or {"Service": "lambda.amazonaws.com"}
            p_list = []
            for k, v in principals.items():
                if isinstance(v, list):
                    p_list.extend(v)
                else:
                    p_list.append(v)
            principals = p_list
        return cls(
            effect=stmt.get("Effect", "Deny"),
            actions=actions,
            resources=resources,
            conditions=stmt.get("Condition", {}),
            principals=principals,
        )

    @classmethod
    def from_dict(cls, stmt: dict) -> IAMStatement:
        """Backward-compatible alias for from_aws_dict."""
        return cls.from_aws_dict(stmt)

    @classmethod
    def from_azure_dict(cls, role_def: dict, scope: str) -> IAMStatement:
        """Parse from Azure RBAC role definition format."""
        actions = role_def.get("permissions", [{}])[0].get("actions", []) if role_def.get("permissions") else []
        not_actions = role_def.get("permissions", [{}])[0].get("notActions", []) if role_def.get("permissions") else []
        data_actions = role_def.get("permissions", [{}])[0].get("dataActions", []) if role_def.get("permissions") else []
        all_actions = actions + data_actions
        return cls(
            effect="Allow",
            actions=all_actions,
            resources=[scope],
            conditions={},
            principals=[],
        )

    @classmethod
    def from_gcp_binding(cls, binding: dict) -> IAMStatement:
        """Parse from GCP IAM binding format."""
        role = binding.get("role", "")
        members = binding.get("members", [])
        condition = binding.get("condition", {})
        return cls(
            effect="Allow",
            actions=[role],  # In GCP, roles are the "actions"
            resources=["*"],  # Scope determined by where the binding is set
            conditions=condition,
            principals=members,
        )


@dataclass
class IAMPrincipal:
    """A resolved IAM principal with all its effective permissions (provider-agnostic)."""
    arn: str  # AWS ARN, Azure object ID, GCP member string
    name: str
    principal_type: str  # user | role | group | service_account | service_principal | managed_identity
    provider: str = "aws"  # aws | azure | gcp
    policies: list[dict] = field(default_factory=list)  # [{name, statements}]
    groups: list[str] = field(default_factory=list)  # group names
    permission_boundary: Optional[str] = None
    trust_policy: Optional[dict] = None  # AWS roles only
    tags: dict = field(default_factory=dict)
    # Azure-specific
    role_assignments: list[dict] = field(default_factory=list)
    # GCP-specific
    iam_bindings: list[dict] = field(default_factory=list)

    _effective_allows: Optional[set] = field(default=None, repr=False)
    _effective_denies: Optional[set] = field(default=None, repr=False)

    @property
    def effective_allows(self) -> set[str]:
        """Lazily compute effective allowed actions (across all attached policies)."""
        if self._effective_allows is None:
            self._resolve_effective()
        return self._effective_allows  # type: ignore

    @property
    def effective_denies(self) -> set[str]:
        if self._effective_denies is None:
            self._resolve_effective()
        return self._effective_denies  # type: ignore

    def _resolve_effective(self):
        allows: set[str] = set()
        denies: set[str] = set()
        for pol in self.policies:
            for stmt in pol.get("statements", []):
                s = IAMStatement.from_dict(stmt) if isinstance(stmt, dict) else stmt
                if s.effect == "Allow":
                    for action in s.actions:
                        allows.add(action.lower())
                elif s.effect == "Deny":
                    for action in s.actions:
                        denies.add(action.lower())
        # Also resolve from role_assignments (Azure)
        for ra in self.role_assignments:
            for action in ra.get("actions", []):
                allows.add(action.lower())
            for action in ra.get("not_actions", []):
                denies.add(action.lower())
        # Also resolve from iam_bindings (GCP)
        for binding in self.iam_bindings:
            role = binding.get("role", "")
            if role:
                allows.add(role.lower())
        self._effective_allows = allows
        self._effective_denies = denies

    def has_permission(self, action: str) -> bool:
        """Check if this principal has a specific permission (supports wildcards)."""
        action_lower = action.lower()
        # Explicit deny always wins
        for deny in self.effective_denies:
            if fnmatch.fnmatch(action_lower, deny):
                return False
        # Check allows
        for allow in self.effective_allows:
            if fnmatch.fnmatch(action_lower, allow):
                return True
        return False

    def has_any_permission(self, actions: list[str]) -> bool:
        return any(self.has_permission(a) for a in actions)

    def has_all_permissions(self, actions: list[str]) -> bool:
        return all(self.has_permission(a) for a in actions)

    def is_admin(self) -> bool:
        """Check if this principal has admin-level access."""
        # Universal check: wildcard in effective_allows
        if "*" in self.effective_allows or "*:*" in self.effective_allows:
            if not self.effective_denies:
                return True

        if self.provider == "aws":
            return self._is_admin_aws()
        elif self.provider == "azure":
            return self._is_admin_azure()
        elif self.provider == "gcp":
            return self._is_admin_gcp()
        elif self.provider == "oci":
            return self._is_admin_oci()
        elif self.provider in ("alibaba", "ibm_cloud", "kubernetes",
                               "m365", "github", "google_workspace",
                               "salesforce", "servicenow", "snowflake",
                               "cloudflare", "openstack"):
            return self._is_admin_generic()
        return False

    def _is_admin_aws(self) -> bool:
        admin_patterns = ["*", "*:*"]
        for allow in self.effective_allows:
            if allow in admin_patterns:
                if not self.effective_denies:
                    return True
        return self.has_permission("iam:*") and self.has_permission("sts:*")

    def _is_admin_azure(self) -> bool:
        admin_roles = {
            "owner", "/subscriptions/*/providers/microsoft.authorization/roledefinitions/owner",
            "global administrator", "company administrator",
        }
        for allow in self.effective_allows:
            if allow in admin_roles or allow == "*":
                return True
        for ra in self.role_assignments:
            role_name = ra.get("role_name", "").lower()
            if role_name in admin_roles:
                return True
        return False

    def _is_admin_gcp(self) -> bool:
        admin_roles = {
            "roles/owner", "roles/editor",
            "roles/iam.securityadmin", "roles/resourcemanager.organizationadmin",
        }
        for allow in self.effective_allows:
            if allow in admin_roles:
                return True
        for binding in self.iam_bindings:
            if binding.get("role", "").lower() in admin_roles:
                return True
        return False

    def _is_admin_oci(self) -> bool:
        """OCI: 'manage all-resources in tenancy' maps to '*' in actions."""
        return "*" in self.effective_allows

    def _is_admin_generic(self) -> bool:
        """Generic admin check for SaaS/K8s providers (wildcard = admin)."""
        return "*" in self.effective_allows


# ── Abstract Base IAM Graph Builder ──────────────────────────────────


class BaseIAMGraphBuilder(abc.ABC):
    """
    Abstract base class for IAM graph builders.

    Each cloud provider implements this to read IAM data via its own SDK
    and build a unified graph of principals → policies → permissions.
    """

    def __init__(self):
        self.graph = AttackGraph()
        self.principals: dict[str, IAMPrincipal] = {}

    @property
    @abc.abstractmethod
    def provider(self) -> str:
        """Return provider identifier: 'aws', 'azure', 'gcp', etc."""

    @abc.abstractmethod
    def build_from_sdk(self, session) -> AttackGraph:
        """Build IAM graph from a live SDK session/client."""

    @abc.abstractmethod
    def build_from_data(self, iam_data: dict) -> AttackGraph:
        """Build IAM graph from pre-collected data dict."""

    # ── Shared analysis helpers ──────────────────────────────────────

    def get_all_principals(self) -> list[IAMPrincipal]:
        """Get all discovered principals."""
        return list(self.principals.values())

    def get_admin_principals(self) -> list[IAMPrincipal]:
        """Get all principals with admin-level access."""
        return [p for p in self.principals.values() if p.is_admin()]

    def get_principals_with_permission(self, action: str) -> list[IAMPrincipal]:
        """Find all principals that have a specific permission."""
        return [p for p in self.principals.values() if p.has_permission(action)]

    def get_assumable_roles(self, principal: IAMPrincipal) -> list[IAMPrincipal]:
        """Get all roles/identities that a principal can assume (via graph traversal)."""
        node_id = self._node_id(principal)
        assumable = []
        for edge in self.graph.adjacency.get(node_id, []):
            if edge.edge_type == EdgeType.ASSUMES_ROLE:
                for p in self.principals.values():
                    if self._node_id(p) == edge.target:
                        assumable.append(p)
                        break
        return assumable

    def get_effective_permissions(self, principal: IAMPrincipal) -> set[str]:
        """
        Get the FULL effective permissions for a principal, including
        permissions from assumable roles (transitive).
        """
        effective = set(principal.effective_allows)
        visited = set()
        stack = [principal]
        while stack:
            current = stack.pop()
            current_id = current.arn
            if current_id in visited:
                continue
            visited.add(current_id)
            effective.update(current.effective_allows)
            for role in self.get_assumable_roles(current):
                if role.arn not in visited:
                    stack.append(role)
        return effective

    def get_graph(self) -> AttackGraph:
        """Return the built graph."""
        return self.graph

    def _add_principal_node(self, principal: IAMPrincipal):
        """Add a principal as a node in the graph."""
        node_type_map = {
            "user": NodeType.IAM_USER,
            "role": NodeType.IAM_ROLE,
            "group": NodeType.IAM_USER,
            "service_principal": NodeType.IAM_ROLE,
            "managed_identity": NodeType.IAM_ROLE,
            "service_account": NodeType.IAM_ROLE,
        }
        node_type = node_type_map.get(principal.principal_type, NodeType.IAM_USER)
        node_id = self._node_id(principal)

        props = {
            "arn": principal.arn,
            "principal_type": principal.principal_type,
            "provider": principal.provider,
            "policy_count": len(principal.policies),
            "is_admin": principal.is_admin(),
        }
        if principal.permission_boundary:
            props["permission_boundary"] = principal.permission_boundary
        if principal.groups:
            props["groups"] = principal.groups

        self.graph.add_node(Node(
            id=node_id,
            node_type=node_type,
            label=principal.name,
            properties=props,
        ))

        # Add policy nodes and edges
        for pol in principal.policies:
            pol_id = f"policy:{principal.name}:{pol['name']}"
            self.graph.add_node(Node(
                id=pol_id,
                node_type=NodeType.IAM_POLICY,
                label=pol["name"],
                properties={
                    "type": pol.get("type", "unknown"),
                    "arn": pol.get("arn", ""),
                    "statement_count": len(pol.get("statements", [])),
                },
            ))
            self.graph.add_edge(Edge(
                source=node_id,
                target=pol_id,
                edge_type=EdgeType.HAS_POLICY,
                label=pol.get("type", "policy"),
            ))

    def _node_id(self, principal: IAMPrincipal) -> str:
        """Generate stable node ID from principal."""
        return f"iam:{principal.provider}:{principal.principal_type}:{principal.name}"

    def _find_principal_by_name(self, name: str, ptype: str) -> Optional[IAMPrincipal]:
        for p in self.principals.values():
            if p.name == name and p.principal_type == ptype:
                return p
        return None

    # ── Multi-Provider Factory ──────────────────────────────────────────

    def build_from_provider(self, provider_type: str, credentials: dict) -> AttackGraph:
        """
        Factory method: build IAM graph for any provider.
        Delegates to the appropriate _build_<provider>() method.
        """
        builders = {
            "aws": self._build_aws,
            "azure": self._build_azure,
            "gcp": self._build_gcp,
            "oci": self._build_oci,
            "alibaba": self._build_alibaba,
            "ibm_cloud": self._build_ibm_cloud,
            "kubernetes": self._build_kubernetes,
            "m365": self._build_m365,
            "github": self._build_github,
            "google_workspace": self._build_google_workspace,
            "salesforce": self._build_salesforce,
            "servicenow": self._build_servicenow,
            "snowflake": self._build_snowflake,
            "cloudflare": self._build_cloudflare,
            "openstack": self._build_openstack,
        }
        builder = builders.get(provider_type)
        if not builder:
            logger.warning("No IAM graph builder for provider: %s", provider_type)
            return self.graph
        try:
            builder(credentials)
        except ImportError as e:
            logger.warning("SDK not installed for %s: %s", provider_type, e)
        except Exception as e:
            logger.warning("IAM graph build failed for %s: %s", provider_type, e)
        return self.graph

    def _build_aws(self, credentials: dict) -> None:
        """Build AWS IAM graph via boto3."""
        import boto3
        session = boto3.Session(**credentials)
        self.build_from_sdk(session)

    def _build_azure(self, credentials: dict) -> None:
        """Build IAM graph from Azure RBAC + Entra ID."""
        from azure.identity import ClientSecretCredential
        from azure.mgmt.authorization import AuthorizationManagementClient
        import httpx

        credential = ClientSecretCredential(
            tenant_id=credentials["tenant_id"],
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"],
        )
        subscription_id = credentials["subscription_id"]
        auth_client = AuthorizationManagementClient(credential, subscription_id)

        # 1. Role Definitions
        role_defs = {}
        for rd in auth_client.role_definitions.list(scope=f"/subscriptions/{subscription_id}"):
            actions = []
            for perm in rd.permissions:
                actions.extend(perm.actions or [])
                actions.extend(perm.data_actions or [])
            role_defs[rd.id] = {
                "name": rd.role_name,
                "actions": actions,
                "is_admin": "*" in actions or "*/write" in actions,
            }

        # 2. Role Assignments
        for ra in auth_client.role_assignments.list_for_subscription():
            principal_id = ra.principal_id
            role_def = role_defs.get(ra.role_definition_id, {})
            statements = [{"Effect": "Allow", "Action": role_def.get("actions", []),
                           "Resource": [ra.scope]}]
            arn = f"azure://{subscription_id}/principals/{principal_id}"
            if arn not in self.principals:
                self.principals[arn] = IAMPrincipal(
                    arn=arn,
                    name=f"{role_def.get('name', 'unknown')}:{principal_id[:8]}",
                    principal_type="user",
                    provider="azure",
                    policies=[{"name": role_def.get("name", ""), "type": "rbac",
                               "statements": statements}],
                    role_assignments=[{"role_name": role_def.get("name", ""),
                                      "actions": role_def.get("actions", []),
                                      "scope": ra.scope}],
                )
                self._add_principal_node(self.principals[arn])
            else:
                p = self.principals[arn]
                p.policies.append({"name": role_def.get("name", ""), "type": "rbac",
                                   "statements": statements})
                p.role_assignments.append({"role_name": role_def.get("name", ""),
                                           "actions": role_def.get("actions", []),
                                           "scope": ra.scope})
                p._effective_allows = None

        # 3. Entra ID Directory Roles (via MS Graph)
        try:
            token = credential.get_token("https://graph.microsoft.com/.default").token
            headers = {"Authorization": f"Bearer {token}"}
            roles_resp = httpx.get("https://graph.microsoft.com/v1.0/directoryRoles",
                                   headers=headers).json()
            for role in roles_resp.get("value", []):
                members = httpx.get(
                    f"https://graph.microsoft.com/v1.0/directoryRoles/{role['id']}/members",
                    headers=headers).json()
                for member in members.get("value", []):
                    member_arn = f"azure://{subscription_id}/principals/{member['id']}"
                    if member_arn in self.principals:
                        p = self.principals[member_arn]
                        p.policies.append({
                            "name": role["displayName"],
                            "type": "directory_role",
                            "statements": [{"Effect": "Allow",
                                            "Action": [f"directoryRole:{role['displayName']}"],
                                            "Resource": ["*"]}],
                        })
                        p._effective_allows = None
                        p._effective_denies = None
        except Exception as e:
            logger.warning("Failed to fetch Entra ID directory roles: %s", e)

        logger.info("Azure IAM graph built: %d principals", len(self.principals))

    def _build_gcp(self, credentials: dict) -> None:
        """Build IAM graph from GCP IAM bindings + Service Accounts."""
        from google.cloud import resourcemanager_v3, iam_admin_v1
        from google.oauth2 import service_account

        creds = service_account.Credentials.from_service_account_info(credentials)
        project_id = credentials["project_id"]

        # 1. Project IAM Policy
        crm = resourcemanager_v3.ProjectsClient(credentials=creds)
        policy = crm.get_iam_policy(resource=f"projects/{project_id}")
        for binding in policy.bindings:
            role_name = binding.role
            for member in binding.members:
                arn = f"gcp://{project_id}/{member}"
                ptype = "user" if member.startswith("user:") else \
                        "role" if member.startswith("serviceAccount:") else "group"
                if arn not in self.principals:
                    self.principals[arn] = IAMPrincipal(
                        arn=arn,
                        name=member.split(":")[-1] if ":" in member else member,
                        principal_type=ptype,
                        provider="gcp",
                        policies=[],
                        iam_bindings=[],
                    )
                    self._add_principal_node(self.principals[arn])
                self.principals[arn].policies.append({
                    "name": role_name,
                    "type": "binding",
                    "statements": [{"Effect": "Allow", "Action": [role_name], "Resource": ["*"]}],
                })
                self.principals[arn].iam_bindings.append({"role": role_name})
                self.principals[arn]._effective_allows = None

        # 2. Service Account impersonation edges
        try:
            iam = iam_admin_v1.IAMClient(credentials=creds)
            for sa in iam.list_service_accounts(name=f"projects/{project_id}"):
                sa_policy = iam.get_iam_policy(resource=sa.name)
                for binding in sa_policy.bindings:
                    if "iam.serviceAccountTokenCreator" in binding.role \
                       or "iam.serviceAccountUser" in binding.role:
                        for member in binding.members:
                            member_arn = f"gcp://{project_id}/{member}"
                            sa_arn = f"gcp://{project_id}/serviceAccount:{sa.email}"
                            if member_arn in self.principals and sa_arn in self.principals:
                                self.graph.add_edge(Edge(
                                    source=self._node_id(self.principals[member_arn]),
                                    target=self._node_id(self.principals[sa_arn]),
                                    edge_type=EdgeType.ASSUMES_ROLE,
                                    label="can impersonate SA",
                                ))
        except Exception as e:
            logger.warning("Failed to enumerate GCP SA impersonation: %s", e)

        logger.info("GCP IAM graph built: %d principals", len(self.principals))

    def _build_oci(self, credentials: dict) -> None:
        """Build IAM graph from OCI policies + compartments."""
        import re
        import oci as oci_sdk
        config = credentials if credentials else oci_sdk.config.from_file()
        identity = oci_sdk.identity.IdentityClient(config)
        tenancy_id = config.get("tenancy", "")

        # 1. Users + groups
        for user in identity.list_users(tenancy_id).data:
            memberships = identity.list_user_group_memberships(tenancy_id, user_id=user.id).data
            group_names = []
            for m in memberships:
                try:
                    group = identity.get_group(m.group_id).data
                    group_names.append(group.name)
                except Exception:
                    pass
            arn = f"oci://{tenancy_id}/users/{user.id}"
            self.principals[arn] = IAMPrincipal(
                arn=arn, name=user.name, principal_type="user",
                provider="oci", groups=group_names, policies=[],
            )
            self._add_principal_node(self.principals[arn])

        # 2. Policies (OCI natural language format)
        for policy in identity.list_policies(tenancy_id).data:
            for stmt_text in policy.statements:
                m = re.match(
                    r"Allow\s+(group|dynamic-group|any-user)\s+(\S+)\s+to\s+"
                    r"(manage|use|read|inspect)\s+(\S+)\s+in\s+(.+)",
                    stmt_text, re.IGNORECASE,
                )
                if m:
                    verb_to_actions = {"manage": ["*"], "use": ["read", "update"],
                                       "read": ["read"], "inspect": ["list"]}
                    subject_type = m.group(1).lower()
                    subject_name = m.group(2)
                    actions = verb_to_actions.get(m.group(3).lower(), [])
                    resource = m.group(4)

                    # Find matching principals by group name
                    for p in list(self.principals.values()):
                        if subject_type == "group" and subject_name in p.groups:
                            p.policies.append({
                                "name": f"policy:{resource}",
                                "type": "oci_policy",
                                "statements": [{"Effect": "Allow", "Action": actions,
                                                "Resource": [resource]}],
                            })
                            p._effective_allows = None

        # 3. Dynamic groups
        try:
            for dg in identity.list_dynamic_groups(tenancy_id).data:
                arn = f"oci://{tenancy_id}/dynamic-group/{dg.id}"
                self.principals[arn] = IAMPrincipal(
                    arn=arn, name=dg.name, principal_type="role",
                    provider="oci", policies=[],
                )
                self._add_principal_node(self.principals[arn])
        except Exception as e:
            logger.warning("Failed to enumerate OCI dynamic groups: %s", e)

        logger.info("OCI IAM graph built: %d principals", len(self.principals))

    def _build_alibaba(self, credentials: dict) -> None:
        """Build IAM graph from Alibaba Cloud RAM users, roles, policies."""
        from aliyunsdkcore.client import AcsClient
        from aliyunsdkram.request.v20150501 import (
            ListUsersRequest, ListRolesRequest, ListPoliciesForUserRequest,
        )

        client = AcsClient(
            credentials.get("access_key_id", ""),
            credentials.get("access_key_secret", ""),
            credentials.get("region_id", "cn-hangzhou"),
        )

        # 1. RAM Users
        req = ListUsersRequest.ListUsersRequest()
        resp = json.loads(client.do_action_with_exception(req))
        for user in resp.get("Users", {}).get("User", []):
            arn = f"alibaba://ram/users/{user['UserId']}"
            # Get user policies
            pol_req = ListPoliciesForUserRequest.ListPoliciesForUserRequest()
            pol_req.set_UserName(user["UserName"])
            try:
                pol_resp = json.loads(client.do_action_with_exception(pol_req))
                policies = []
                for pol in pol_resp.get("Policies", {}).get("Policy", []):
                    policies.append({
                        "name": pol["PolicyName"],
                        "type": pol.get("PolicyType", "custom"),
                        "statements": [{"Effect": "Allow",
                                        "Action": [f"ram:{pol['PolicyName']}"],
                                        "Resource": ["*"]}],
                    })
                    # Check for AdministratorAccess
                    if pol["PolicyName"] == "AdministratorAccess":
                        policies[-1]["statements"][0]["Action"] = ["*"]
            except Exception:
                policies = []

            self.principals[arn] = IAMPrincipal(
                arn=arn, name=user["UserName"], principal_type="user",
                provider="alibaba", policies=policies,
            )
            self._add_principal_node(self.principals[arn])

        # 2. RAM Roles (for role assumption)
        try:
            role_req = ListRolesRequest.ListRolesRequest()
            role_resp = json.loads(client.do_action_with_exception(role_req))
            for role in role_resp.get("Roles", {}).get("Role", []):
                arn = f"alibaba://ram/roles/{role['RoleId']}"
                trust = role.get("AssumeRolePolicyDocument", {})
                if isinstance(trust, str):
                    try:
                        trust = json.loads(trust)
                    except Exception:
                        trust = {}
                self.principals[arn] = IAMPrincipal(
                    arn=arn, name=role["RoleName"], principal_type="role",
                    provider="alibaba", trust_policy=trust, policies=[],
                )
                self._add_principal_node(self.principals[arn])
        except Exception as e:
            logger.warning("Failed to enumerate Alibaba RAM roles: %s", e)

        logger.info("Alibaba IAM graph built: %d principals", len(self.principals))

    def _build_ibm_cloud(self, credentials: dict) -> None:
        """Build IAM graph from IBM Cloud IAM policies + access groups."""
        from ibm_platform_services import IamPolicyManagementV1, IamAccessGroupsV2
        from ibm_cloud_sdk_core.authenticators import IAMAuthenticator

        authenticator = IAMAuthenticator(credentials.get("apikey", ""))
        account_id = credentials.get("account_id", "")

        # 1. IAM Policies
        policy_svc = IamPolicyManagementV1(authenticator=authenticator)
        policies_resp = policy_svc.list_policies(account_id=account_id).get_result()
        for policy in policies_resp.get("policies", []):
            subjects = policy.get("subjects", [])
            roles = [r.get("display_name", r.get("role_id", ""))
                     for r in policy.get("roles", [])]
            role_to_actions = {
                "Administrator": ["*"], "Editor": ["read", "write", "update"],
                "Operator": ["read", "update"], "Viewer": ["read"],
            }
            actions = []
            for r in roles:
                actions.extend(role_to_actions.get(r, [r]))

            for subj in subjects:
                for attr in subj.get("attributes", []):
                    if attr.get("name") == "iam_id":
                        iam_id = attr["value"]
                        arn = f"ibm://{account_id}/principals/{iam_id}"
                        if arn not in self.principals:
                            self.principals[arn] = IAMPrincipal(
                                arn=arn, name=iam_id, principal_type="user",
                                provider="ibm_cloud", policies=[],
                            )
                            self._add_principal_node(self.principals[arn])
                        self.principals[arn].policies.append({
                            "name": f"policy:{policy.get('id', '')}",
                            "type": "iam_policy",
                            "statements": [{"Effect": "Allow", "Action": actions,
                                            "Resource": ["*"]}],
                        })
                        self.principals[arn]._effective_allows = None

        # 2. Access Groups
        try:
            ag_svc = IamAccessGroupsV2(authenticator=authenticator)
            groups_resp = ag_svc.list_access_groups(account_id=account_id).get_result()
            for group in groups_resp.get("groups", []):
                members = ag_svc.list_access_group_members(
                    access_group_id=group["id"]).get_result()
                for member in members.get("members", []):
                    member_arn = f"ibm://{account_id}/principals/{member.get('iam_id', '')}"
                    if member_arn in self.principals:
                        self.principals[member_arn].groups.append(group.get("name", ""))
        except Exception as e:
            logger.warning("Failed to enumerate IBM access groups: %s", e)

        logger.info("IBM Cloud IAM graph built: %d principals", len(self.principals))

    def _build_kubernetes(self, credentials: dict) -> None:
        """Build IAM graph from Kubernetes RBAC."""
        from kubernetes import client as k8s_client, config as k8s_config

        if credentials.get("kubeconfig"):
            k8s_config.load_kube_config(config_file=credentials["kubeconfig"])
        elif credentials.get("in_cluster"):
            k8s_config.load_incluster_config()
        else:
            k8s_config.load_kube_config()

        rbac = k8s_client.RbacAuthorizationV1Api()
        core = k8s_client.CoreV1Api()

        # 1. ClusterRoleBindings -> map subjects to roles
        crbs = rbac.list_cluster_role_binding().items
        for crb in crbs:
            if not crb.subjects:
                continue
            role_ref = crb.role_ref
            role_name = role_ref.name
            # Resolve role permissions
            try:
                cr = rbac.read_cluster_role(role_name)
                actions = []
                for rule in (cr.rules or []):
                    verbs = rule.verbs or []
                    resources = rule.resources or []
                    for v in verbs:
                        for r in resources:
                            actions.append(f"{r}:{v}")
                    if "*" in verbs and "*" in resources:
                        actions = ["*"]
                        break
            except Exception:
                actions = [f"clusterrole:{role_name}"]

            for subject in crb.subjects:
                subj_name = subject.name
                subj_ns = subject.namespace or "cluster"
                arn = f"k8s://{subj_ns}/{subject.kind}/{subj_name}"
                ptype = "role" if subject.kind == "ServiceAccount" else "user"
                if arn not in self.principals:
                    self.principals[arn] = IAMPrincipal(
                        arn=arn, name=subj_name, principal_type=ptype,
                        provider="kubernetes", policies=[],
                    )
                    self._add_principal_node(self.principals[arn])
                self.principals[arn].policies.append({
                    "name": role_name,
                    "type": "cluster_role_binding",
                    "statements": [{"Effect": "Allow", "Action": actions, "Resource": ["*"]}],
                })
                self.principals[arn]._effective_allows = None

        # 2. Namespaced RoleBindings
        try:
            rbs = rbac.list_role_binding_for_all_namespaces().items
            for rb in rbs:
                if not rb.subjects:
                    continue
                ns = rb.metadata.namespace
                role_name = rb.role_ref.name
                try:
                    if rb.role_ref.kind == "ClusterRole":
                        r = rbac.read_cluster_role(role_name)
                    else:
                        r = rbac.read_namespaced_role(role_name, ns)
                    actions = []
                    for rule in (r.rules or []):
                        for v in (rule.verbs or []):
                            for res in (rule.resources or []):
                                actions.append(f"{res}:{v}")
                except Exception:
                    actions = [f"role:{role_name}"]

                for subject in rb.subjects:
                    subj_name = subject.name
                    subj_ns = subject.namespace or ns
                    arn = f"k8s://{subj_ns}/{subject.kind}/{subj_name}"
                    if arn not in self.principals:
                        ptype = "role" if subject.kind == "ServiceAccount" else "user"
                        self.principals[arn] = IAMPrincipal(
                            arn=arn, name=subj_name, principal_type=ptype,
                            provider="kubernetes", policies=[],
                        )
                        self._add_principal_node(self.principals[arn])
                    self.principals[arn].policies.append({
                        "name": f"{ns}/{role_name}",
                        "type": "role_binding",
                        "statements": [{"Effect": "Allow", "Action": actions,
                                        "Resource": [ns]}],
                    })
                    self.principals[arn]._effective_allows = None
        except Exception as e:
            logger.warning("Failed to enumerate K8s role bindings: %s", e)

        logger.info("Kubernetes IAM graph built: %d principals", len(self.principals))

    def _build_saas_generic(self, provider: str, users_with_roles: list[dict]) -> None:
        """Generic SaaS builder. Provider-specific builders generate users_with_roles."""
        for user in users_with_roles:
            org = user.get("org", "default")
            arn = f"{provider}://{org}/users/{user['id']}"
            actions = []
            for role in user.get("roles", []):
                actions.extend(self._saas_role_to_actions(provider, role))
            self.principals[arn] = IAMPrincipal(
                arn=arn, name=user.get("name", user["id"]),
                principal_type="user", provider=provider,
                policies=[{
                    "name": ",".join(user.get("roles", [])),
                    "type": "saas_role",
                    "statements": [{"Effect": "Allow", "Action": actions, "Resource": ["*"]}],
                }],
            )
            self._add_principal_node(self.principals[arn])

    def _saas_role_to_actions(self, provider: str, role: str) -> list[str]:
        """Map a SaaS role name to IAMPrincipal-compatible actions."""
        role_lower = role.lower()
        admin_roles = {
            "m365": ["global administrator", "company administrator"],
            "github": ["owner"],
            "google_workspace": ["super admin", "_seed_admin"],
            "salesforce": ["system administrator"],
            "servicenow": ["admin"],
            "snowflake": ["accountadmin"],
            "cloudflare": ["super administrator - all privileges"],
            "openstack": ["admin"],
        }
        if role_lower in [r.lower() for r in admin_roles.get(provider, [])]:
            return ["*"]
        return [f"{provider}:{role_lower}"]

    def _build_m365(self, credentials: dict) -> None:
        """Build IAM graph from Microsoft 365 via MS Graph API."""
        import httpx
        from azure.identity import ClientSecretCredential

        credential = ClientSecretCredential(
            tenant_id=credentials["tenant_id"],
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"],
        )
        token = credential.get_token("https://graph.microsoft.com/.default").token
        headers = {"Authorization": f"Bearer {token}"}

        # List directory role members
        roles = httpx.get("https://graph.microsoft.com/v1.0/directoryRoles",
                          headers=headers).json()
        users_with_roles: list[dict] = []
        seen: dict[str, dict] = {}

        for role in roles.get("value", []):
            members = httpx.get(
                f"https://graph.microsoft.com/v1.0/directoryRoles/{role['id']}/members",
                headers=headers).json()
            for member in members.get("value", []):
                mid = member.get("id", "")
                if mid not in seen:
                    seen[mid] = {"id": mid, "name": member.get("displayName", mid),
                                 "org": credentials.get("tenant_id", "default"), "roles": []}
                seen[mid]["roles"].append(role.get("displayName", ""))

        users_with_roles = list(seen.values())
        self._build_saas_generic("m365", users_with_roles)
        logger.info("M365 IAM graph built: %d principals", len(users_with_roles))

    def _build_github(self, credentials: dict) -> None:
        """Build IAM graph from GitHub org members."""
        import httpx

        token = credentials.get("token", "")
        org = credentials.get("org", "")
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}

        users_with_roles: list[dict] = []
        resp = httpx.get(f"https://api.github.com/orgs/{org}/members?role=all",
                         headers=headers).json()
        if isinstance(resp, list):
            for member in resp:
                # Get membership role
                try:
                    membership = httpx.get(
                        f"https://api.github.com/orgs/{org}/memberships/{member['login']}",
                        headers=headers).json()
                    role = membership.get("role", "member")
                except Exception:
                    role = "member"
                users_with_roles.append({
                    "id": str(member.get("id", "")),
                    "name": member.get("login", ""),
                    "org": org,
                    "roles": [role],
                })

        self._build_saas_generic("github", users_with_roles)
        logger.info("GitHub IAM graph built: %d principals", len(users_with_roles))

    def _build_google_workspace(self, credentials: dict) -> None:
        """Build IAM graph from Google Workspace Admin SDK."""
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        creds = service_account.Credentials.from_service_account_info(
            credentials, scopes=["https://www.googleapis.com/auth/admin.directory.user.readonly",
                                 "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly"],
        ).with_subject(credentials.get("admin_email", ""))

        service = build("admin", "directory_v1", credentials=creds)

        # List users
        users_with_roles: list[dict] = []
        results = service.users().list(customer="my_customer", maxResults=500).execute()
        for user in results.get("users", []):
            roles = []
            if user.get("isAdmin"):
                roles.append("Super Admin")
            if user.get("isDelegatedAdmin"):
                roles.append("Delegated Admin")
            if not roles:
                roles.append("User")
            users_with_roles.append({
                "id": user.get("id", ""),
                "name": user.get("primaryEmail", ""),
                "org": credentials.get("domain", "default"),
                "roles": roles,
            })

        self._build_saas_generic("google_workspace", users_with_roles)
        logger.info("Google Workspace IAM graph built: %d principals", len(users_with_roles))

    def _build_salesforce(self, credentials: dict) -> None:
        """Build IAM graph from Salesforce users + profiles."""
        import httpx

        instance_url = credentials.get("instance_url", "")
        token = credentials.get("access_token", "")
        headers = {"Authorization": f"Bearer {token}"}

        users_with_roles: list[dict] = []
        query = "SELECT Id, Username, Profile.Name, IsActive FROM User WHERE IsActive = true"
        resp = httpx.get(f"{instance_url}/services/data/v59.0/query",
                         params={"q": query}, headers=headers).json()
        for record in resp.get("records", []):
            profile = record.get("Profile", {}).get("Name", "Standard User")
            users_with_roles.append({
                "id": record.get("Id", ""),
                "name": record.get("Username", ""),
                "org": instance_url.split("//")[-1].split(".")[0],
                "roles": [profile],
            })

        self._build_saas_generic("salesforce", users_with_roles)
        logger.info("Salesforce IAM graph built: %d principals", len(users_with_roles))

    def _build_servicenow(self, credentials: dict) -> None:
        """Build IAM graph from ServiceNow user roles."""
        import httpx

        instance_url = credentials.get("instance_url", "")
        auth = (credentials.get("username", ""), credentials.get("password", ""))
        headers = {"Accept": "application/json"}

        users_with_roles: list[dict] = []
        resp = httpx.get(
            f"{instance_url}/api/now/table/sys_user_has_role",
            params={"sysparm_fields": "user.sys_id,user.user_name,role.name",
                    "sysparm_limit": 1000},
            auth=auth, headers=headers,
        ).json()

        seen: dict[str, dict] = {}
        for record in resp.get("result", []):
            uid = record.get("user.sys_id", "")
            if uid not in seen:
                seen[uid] = {"id": uid, "name": record.get("user.user_name", uid),
                             "org": instance_url.split("//")[-1].split(".")[0], "roles": []}
            seen[uid]["roles"].append(record.get("role.name", ""))

        users_with_roles = list(seen.values())
        self._build_saas_generic("servicenow", users_with_roles)
        logger.info("ServiceNow IAM graph built: %d principals", len(users_with_roles))

    def _build_snowflake(self, credentials: dict) -> None:
        """Build IAM graph from Snowflake user grants."""
        import snowflake.connector

        conn = snowflake.connector.connect(
            user=credentials.get("user", ""),
            password=credentials.get("password", ""),
            account=credentials.get("account", ""),
            warehouse=credentials.get("warehouse", ""),
        )
        cursor = conn.cursor()

        users_with_roles: list[dict] = []
        cursor.execute("SHOW USERS")
        for row in cursor.fetchall():
            username = row[0]
            cursor.execute(f"SHOW GRANTS TO USER \"{username}\"")
            roles = [grant[1] for grant in cursor.fetchall() if grant[1]]
            users_with_roles.append({
                "id": username,
                "name": username,
                "org": credentials.get("account", "default"),
                "roles": roles,
            })

        conn.close()
        self._build_saas_generic("snowflake", users_with_roles)
        logger.info("Snowflake IAM graph built: %d principals", len(users_with_roles))

    def _build_cloudflare(self, credentials: dict) -> None:
        """Build IAM graph from Cloudflare account members."""
        import httpx

        token = credentials.get("api_token", "")
        account_id = credentials.get("account_id", "")
        headers = {"Authorization": f"Bearer {token}"}

        users_with_roles: list[dict] = []
        resp = httpx.get(f"https://api.cloudflare.com/client/v4/accounts/{account_id}/members",
                         headers=headers).json()
        for member in resp.get("result", []):
            roles = [r.get("name", "") for r in member.get("roles", [])]
            users_with_roles.append({
                "id": member.get("id", ""),
                "name": member.get("user", {}).get("email", ""),
                "org": account_id,
                "roles": roles,
            })

        self._build_saas_generic("cloudflare", users_with_roles)
        logger.info("Cloudflare IAM graph built: %d principals", len(users_with_roles))

    def _build_openstack(self, credentials: dict) -> None:
        """Build IAM graph from OpenStack Keystone role assignments."""
        import httpx

        auth_url = credentials.get("auth_url", "")
        token = credentials.get("token", "")
        headers = {"X-Auth-Token": token}

        users_with_roles: list[dict] = []

        # List role assignments
        resp = httpx.get(f"{auth_url}/v3/role_assignments",
                         headers=headers).json()
        seen: dict[str, dict] = {}
        roles_cache: dict[str, str] = {}

        for ra in resp.get("role_assignments", []):
            user_id = ra.get("user", {}).get("id", "")
            role_id = ra.get("role", {}).get("id", "")
            if not user_id:
                continue
            # Resolve role name
            if role_id not in roles_cache:
                try:
                    role_resp = httpx.get(f"{auth_url}/v3/roles/{role_id}",
                                          headers=headers).json()
                    roles_cache[role_id] = role_resp.get("role", {}).get("name", role_id)
                except Exception:
                    roles_cache[role_id] = role_id
            if user_id not in seen:
                # Resolve user name
                try:
                    user_resp = httpx.get(f"{auth_url}/v3/users/{user_id}",
                                          headers=headers).json()
                    uname = user_resp.get("user", {}).get("name", user_id)
                except Exception:
                    uname = user_id
                seen[user_id] = {"id": user_id, "name": uname,
                                 "org": credentials.get("domain", "default"), "roles": []}
            seen[user_id]["roles"].append(roles_cache[role_id])

        users_with_roles = list(seen.values())
        self._build_saas_generic("openstack", users_with_roles)
        logger.info("OpenStack IAM graph built: %d principals", len(users_with_roles))

    def to_summary(self) -> dict:
        """Return a summary of the IAM graph for logging/display."""
        users = [p for p in self.principals.values() if p.principal_type in ("user",)]
        roles = [p for p in self.principals.values() if p.principal_type in ("role", "service_principal", "managed_identity", "service_account")]
        groups = [p for p in self.principals.values() if p.principal_type == "group"]
        admins = self.get_admin_principals()

        return {
            "provider": self.provider,
            "total_principals": len(self.principals),
            "users": len(users),
            "roles": len(roles),
            "groups": len(groups),
            "admin_principals": len(admins),
            "admin_names": [p.name for p in admins],
            "total_graph_nodes": len(self.graph.nodes),
            "total_graph_edges": sum(len(edges) for edges in self.graph.adjacency.values()),
        }


# ── AWS IAM Graph Builder ────────────────────────────────────────────


class AWSIAMGraphBuilder(BaseIAMGraphBuilder):
    """
    Builds an IAM-aware attack graph from AWS IAM data.

    Can be fed data from:
    1. Live boto3 API calls (read-only: iam:Get*, iam:List*)
    2. Pre-collected IAM data dicts (for testing or offline analysis)
    """

    def __init__(self):
        super().__init__()
        self._managed_policy_cache: dict[str, dict] = {}

    @property
    def provider(self) -> str:
        return "aws"

    def build_from_sdk(self, session) -> AttackGraph:
        """Build IAM graph from a live boto3 session."""
        return self.build_from_boto3(session)

    def build_from_boto3(self, session) -> AttackGraph:
        """
        Build IAM graph from a live boto3 session.
        Uses ONLY read-only IAM calls:
          - iam:ListUsers, iam:ListRoles, iam:ListGroups
          - iam:ListAttachedUserPolicies, iam:ListUserPolicies
          - iam:ListAttachedRolePolicies, iam:ListRolePolicies
          - iam:ListAttachedGroupPolicies, iam:ListGroupPolicies
          - iam:GetPolicy, iam:GetPolicyVersion
          - iam:GetUserPolicy, iam:GetRolePolicy, iam:GetGroupPolicy
          - iam:ListGroupsForUser
          - iam:GetRole (for trust policy)
        """
        iam = session.client("iam")

        # 1. Enumerate all users
        users = self._paginate(iam, "list_users", "Users")
        for user in users:
            self._process_user(iam, user)

        # 2. Enumerate all roles
        roles = self._paginate(iam, "list_roles", "Roles")
        for role in roles:
            self._process_role(iam, role)

        # 3. Enumerate all groups
        groups = self._paginate(iam, "list_groups", "Groups")
        for group in groups:
            self._process_group(iam, group)

        # 4. Link users to groups
        for user_arn, principal in self.principals.items():
            if principal.principal_type == "user":
                self._link_user_groups(iam, principal)

        # 5. Build trust relationships (role assumption edges)
        self._build_trust_edges()

        logger.info(
            "AWS IAM graph built: %d nodes, %d principals",
            len(self.graph.nodes),
            len(self.principals),
        )
        return self.graph

    def build_from_data(self, iam_data: dict) -> AttackGraph:
        """
        Build IAM graph from pre-collected data dict.

        Expected format:
        {
            "users": [{"UserName", "Arn", "UserId", "policies": [...], "groups": [...]}],
            "roles": [{"RoleName", "Arn", "RoleId", "AssumeRolePolicyDocument", "policies": [...]}],
            "groups": [{"GroupName", "Arn", "GroupId", "policies": [...]}],
        }
        """
        for user in iam_data.get("users", []):
            arn = user.get("Arn", f"arn:aws:iam::user/{user['UserName']}")
            principal = IAMPrincipal(
                arn=arn,
                name=user["UserName"],
                principal_type="user",
                provider="aws",
                policies=user.get("policies", []),
                groups=user.get("groups", []),
                permission_boundary=user.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn"),
                tags=user.get("Tags", {}),
            )
            self.principals[arn] = principal
            self._add_principal_node(principal)

        for role in iam_data.get("roles", []):
            arn = role.get("Arn", f"arn:aws:iam::role/{role['RoleName']}")
            trust = role.get("AssumeRolePolicyDocument", {})
            if isinstance(trust, str):
                try:
                    trust = json.loads(trust)
                except (json.JSONDecodeError, TypeError):
                    trust = {}
            principal = IAMPrincipal(
                arn=arn,
                name=role["RoleName"],
                principal_type="role",
                provider="aws",
                policies=role.get("policies", []),
                trust_policy=trust,
                tags=role.get("Tags", {}),
            )
            self.principals[arn] = principal
            self._add_principal_node(principal)

        for group in iam_data.get("groups", []):
            arn = group.get("Arn", f"arn:aws:iam::group/{group['GroupName']}")
            principal = IAMPrincipal(
                arn=arn,
                name=group["GroupName"],
                principal_type="group",
                provider="aws",
                policies=group.get("policies", []),
            )
            self.principals[arn] = principal
            self._add_principal_node(principal)

        # Link user → group membership
        for arn, principal in self.principals.items():
            if principal.principal_type == "user" and principal.groups:
                for group_name in principal.groups:
                    group_principal = self._find_principal_by_name(group_name, "group")
                    if group_principal:
                        principal.policies.extend(group_principal.policies)
                        self.graph.add_edge(Edge(
                            source=self._node_id(principal),
                            target=self._node_id(group_principal),
                            edge_type=EdgeType.HAS_POLICY,
                            label=f"member of {group_name}",
                        ))

        self._build_trust_edges()

        logger.info(
            "AWS IAM graph built from data: %d nodes, %d principals",
            len(self.graph.nodes),
            len(self.principals),
        )
        return self.graph

    # ── Principal Enumeration ────────────────────────────────────────

    def _process_user(self, iam, user: dict):
        arn = user["Arn"]
        name = user["UserName"]

        policies = self._get_all_policies(iam, "user", name)
        perm_boundary = user.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")

        principal = IAMPrincipal(
            arn=arn,
            name=name,
            principal_type="user",
            provider="aws",
            policies=policies,
            permission_boundary=perm_boundary,
            tags={t["Key"]: t["Value"] for t in user.get("Tags", [])},
        )
        self.principals[arn] = principal
        self._add_principal_node(principal)

    def _process_role(self, iam, role: dict):
        arn = role["Arn"]
        name = role["RoleName"]

        policies = self._get_all_policies(iam, "role", name)
        trust_doc = role.get("AssumeRolePolicyDocument", {})
        if isinstance(trust_doc, str):
            try:
                trust_doc = json.loads(trust_doc)
            except (json.JSONDecodeError, TypeError):
                trust_doc = {}

        principal = IAMPrincipal(
            arn=arn,
            name=name,
            principal_type="role",
            provider="aws",
            policies=policies,
            trust_policy=trust_doc,
            tags={t["Key"]: t["Value"] for t in role.get("Tags", [])},
        )
        self.principals[arn] = principal
        self._add_principal_node(principal)

    def _process_group(self, iam, group: dict):
        arn = group["Arn"]
        name = group["GroupName"]
        policies = self._get_all_policies(iam, "group", name)

        principal = IAMPrincipal(
            arn=arn,
            name=name,
            principal_type="group",
            provider="aws",
            policies=policies,
        )
        self.principals[arn] = principal
        self._add_principal_node(principal)

    def _link_user_groups(self, iam, user_principal: IAMPrincipal):
        """Link user to their groups and merge group policies."""
        try:
            groups = self._paginate(iam, "list_groups_for_user", "Groups",
                                     UserName=user_principal.name)
            for group in groups:
                group_arn = group["Arn"]
                user_principal.groups.append(group["GroupName"])
                group_principal = self.principals.get(group_arn)
                if group_principal:
                    user_principal.policies.extend(group_principal.policies)
                    self.graph.add_edge(Edge(
                        source=self._node_id(user_principal),
                        target=self._node_id(group_principal),
                        edge_type=EdgeType.HAS_POLICY,
                        label=f"member of {group['GroupName']}",
                    ))
        except Exception as e:
            logger.warning("Failed to get groups for user %s: %s", user_principal.name, e)

    # ── Policy Retrieval ──────────────────────────────────────────────

    def _get_all_policies(self, iam, entity_type: str, name: str) -> list[dict]:
        """Get all policies (inline + managed) for a user/role/group."""
        policies = []

        # Inline policies
        try:
            inline_names = self._paginate(
                iam,
                f"list_{entity_type}_policies",
                "PolicyNames",
                **{self._entity_param(entity_type): name},
            )
            for pol_name in inline_names:
                try:
                    response = getattr(iam, f"get_{entity_type}_policy")(
                        **{self._entity_param(entity_type): name, "PolicyName": pol_name},
                    )
                    doc = response.get("PolicyDocument", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    policies.append({
                        "name": pol_name,
                        "type": "inline",
                        "statements": doc.get("Statement", []),
                    })
                except Exception as e:
                    logger.debug("Failed to get inline policy %s: %s", pol_name, e)
        except Exception as e:
            logger.debug("Failed to list inline policies for %s/%s: %s", entity_type, name, e)

        # Managed policies
        try:
            managed = self._paginate(
                iam,
                f"list_attached_{entity_type}_policies",
                "AttachedPolicies",
                **{self._entity_param(entity_type): name},
            )
            for pol in managed:
                pol_arn = pol["PolicyArn"]
                doc = self._get_managed_policy_doc(iam, pol_arn)
                if doc:
                    policies.append({
                        "name": pol.get("PolicyName", pol_arn),
                        "type": "managed",
                        "arn": pol_arn,
                        "statements": doc.get("Statement", []),
                    })
        except Exception as e:
            logger.debug("Failed to list managed policies for %s/%s: %s", entity_type, name, e)

        return policies

    def _get_managed_policy_doc(self, iam, policy_arn: str) -> Optional[dict]:
        """Get the policy document for a managed policy (with caching)."""
        if policy_arn in self._managed_policy_cache:
            return self._managed_policy_cache[policy_arn]

        try:
            pol_meta = iam.get_policy(PolicyArn=policy_arn)
            version_id = pol_meta["Policy"]["DefaultVersionId"]
            version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            doc = version["PolicyVersion"]["Document"]
            if isinstance(doc, str):
                doc = json.loads(doc)
            self._managed_policy_cache[policy_arn] = doc
            return doc
        except Exception as e:
            logger.debug("Failed to get managed policy %s: %s", policy_arn, e)
            return None

    # ── Trust Relationship Edges ──────────────────────────────────────

    def _build_trust_edges(self):
        """Build CAN_ASSUME edges from role trust policies."""
        for arn, principal in self.principals.items():
            if principal.principal_type != "role" or not principal.trust_policy:
                continue

            statements = principal.trust_policy.get("Statement", [])
            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue

                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                assume_actions = {"sts:AssumeRole", "sts:AssumeRoleWithSAML",
                                  "sts:AssumeRoleWithWebIdentity"}
                if not any(a in assume_actions for a in actions):
                    continue

                trust_principals = stmt.get("Principal", {})
                if isinstance(trust_principals, str):
                    if trust_principals == "*":
                        trusted_arns = ["*"]
                    else:
                        trusted_arns = [trust_principals]
                elif isinstance(trust_principals, dict):
                    trusted_arns = []
                    for key, vals in trust_principals.items():
                        if key == "Service":
                            continue
                        if isinstance(vals, str):
                            trusted_arns.append(vals)
                        elif isinstance(vals, list):
                            trusted_arns.extend(vals)
                else:
                    continue

                role_node_id = self._node_id(principal)

                for trusted_arn in trusted_arns:
                    if trusted_arn == "*":
                        for other_arn, other in self.principals.items():
                            if other_arn != arn and other.principal_type != "group":
                                other_node = self._node_id(other)
                                self.graph.add_edge(Edge(
                                    source=other_node,
                                    target=role_node_id,
                                    edge_type=EdgeType.ASSUMES_ROLE,
                                    label="can assume (wildcard trust)",
                                ))
                    else:
                        if trusted_arn.endswith(":root"):
                            account_id = self._extract_account_id(trusted_arn)
                            for other_arn, other in self.principals.items():
                                if other_arn != arn and self._extract_account_id(other_arn) == account_id:
                                    if other.principal_type != "group":
                                        other_node = self._node_id(other)
                                        self.graph.add_edge(Edge(
                                            source=other_node,
                                            target=role_node_id,
                                            edge_type=EdgeType.ASSUMES_ROLE,
                                            label="can assume (account trust)",
                                        ))
                        else:
                            trusted = self.principals.get(trusted_arn)
                            if trusted:
                                self.graph.add_edge(Edge(
                                    source=self._node_id(trusted),
                                    target=role_node_id,
                                    edge_type=EdgeType.ASSUMES_ROLE,
                                    label="can assume",
                                ))

    # ── AWS-specific helpers ──────────────────────────────────────────

    @staticmethod
    def _extract_account_id(arn: str) -> str:
        """Extract AWS account ID from an ARN."""
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    @staticmethod
    def _entity_param(entity_type: str) -> str:
        """Get the boto3 parameter name for entity type."""
        return {"user": "UserName", "role": "RoleName", "group": "GroupName"}[entity_type]

    @staticmethod
    def _paginate(client, method: str, key: str, **kwargs) -> list:
        """Helper to paginate AWS API calls."""
        results = []
        try:
            paginator = client.get_paginator(method)
            for page in paginator.paginate(**kwargs):
                results.extend(page.get(key, []))
        except client.exceptions.NoSuchEntityException:
            pass
        except Exception:
            try:
                response = getattr(client, method)(**kwargs)
                results = response.get(key, [])
            except Exception as e:
                logger.warning("Failed to call %s: %s", method, e)
        return results


# Backward-compatible alias
IAMGraphBuilder = AWSIAMGraphBuilder
