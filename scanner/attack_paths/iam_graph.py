"""
IAM Graph Builder for AWS.

Reads IAM configuration via read-only API calls and builds a directed graph
of principals (users, roles, groups) → policies → permissions → resources.
This enables algorithmic discovery of privilege escalation paths, overprivileged
identities, and shadow-admin detection.

Phase 2 of BAS 2.0 evolution.
"""
from __future__ import annotations

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
    IAM_GROUP = "iam_group"
    IAM_MANAGED_POLICY = "iam_managed_policy"
    IAM_INLINE_POLICY = "iam_inline_policy"
    AWS_SERVICE = "aws_service"
    RESOURCE = "resource"


class IAMEdgeType:
    """Extended edge types for IAM graph."""
    MEMBER_OF = "member_of"           # user → group
    HAS_INLINE_POLICY = "has_inline"  # principal → inline policy
    HAS_MANAGED_POLICY = "has_managed"  # principal → managed policy
    POLICY_GRANTS = "policy_grants"   # policy → resource (Allow action)
    CAN_ASSUME = "can_assume"         # principal → role (sts:AssumeRole)
    PERMISSION_BOUNDARY = "perm_boundary"  # principal → boundary policy
    SERVICE_LINKED = "service_linked"  # role → AWS service


# ── Data classes for parsed IAM ───────────────────────────────────────


@dataclass
class IAMStatement:
    """A single IAM policy statement."""
    effect: str  # Allow | Deny
    actions: list[str]
    resources: list[str]
    conditions: dict = field(default_factory=dict)
    principals: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, stmt: dict) -> IAMStatement:
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


@dataclass
class IAMPrincipal:
    """A resolved IAM principal with all its effective permissions."""
    arn: str
    name: str
    principal_type: str  # user | role | group
    policies: list[dict] = field(default_factory=list)  # [{name, statements}]
    groups: list[str] = field(default_factory=list)  # group names
    permission_boundary: Optional[str] = None
    trust_policy: Optional[dict] = None  # roles only
    tags: dict = field(default_factory=dict)
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
        admin_patterns = ["*", "*:*"]
        for allow in self.effective_allows:
            if allow in admin_patterns:
                # Check no deny overrides
                if not self.effective_denies:
                    return True
        return self.has_permission("iam:*") and self.has_permission("sts:*")


# ── IAM Graph Builder ─────────────────────────────────────────────────


class IAMGraphBuilder:
    """
    Builds an IAM-aware attack graph from AWS IAM data.

    Can be fed data from:
    1. Live boto3 API calls (read-only: iam:Get*, iam:List*)
    2. Pre-collected IAM data dicts (for testing or offline analysis)
    """

    def __init__(self):
        self.graph = AttackGraph()
        self.principals: dict[str, IAMPrincipal] = {}
        self._managed_policy_cache: dict[str, dict] = {}

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
            "IAM graph built: %d nodes, %d principals",
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
                        # Merge group policies into user
                        principal.policies.extend(group_principal.policies)
                        self.graph.add_edge(Edge(
                            source=self._node_id(principal),
                            target=self._node_id(group_principal),
                            edge_type=EdgeType.HAS_POLICY,
                            label=f"member of {group_name}",
                        ))

        self._build_trust_edges()

        logger.info(
            "IAM graph built from data: %d nodes, %d principals",
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
                    # Merge group policies into user's effective policies
                    user_principal.policies.extend(group_principal.policies)
                    # Add graph edge
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

                # Only process sts:AssumeRole actions
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
                            # Service-linked roles
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
                        # Wildcard trust — any principal can assume this role
                        for other_arn, other in self.principals.items():
                            if other_arn != arn and other.principal_type != "group":
                                other_node = self._node_id(other)
                                self.graph.add_edge(Edge(
                                    source=other_node,
                                    target=role_node_id,
                                    edge_type=EdgeType.ASSUMES_ROLE,
                                    label=f"can assume (wildcard trust)",
                                ))
                    else:
                        # Specific ARN trust
                        # Could be an account root, specific user, or role
                        if trusted_arn.endswith(":root"):
                            # Account-level trust: all principals in that account can assume
                            account_id = self._extract_account_id(trusted_arn)
                            for other_arn, other in self.principals.items():
                                if other_arn != arn and self._extract_account_id(other_arn) == account_id:
                                    if other.principal_type != "group":
                                        other_node = self._node_id(other)
                                        self.graph.add_edge(Edge(
                                            source=other_node,
                                            target=role_node_id,
                                            edge_type=EdgeType.ASSUMES_ROLE,
                                            label=f"can assume (account trust)",
                                        ))
                        else:
                            # Specific principal trust
                            trusted = self.principals.get(trusted_arn)
                            if trusted:
                                self.graph.add_edge(Edge(
                                    source=self._node_id(trusted),
                                    target=role_node_id,
                                    edge_type=EdgeType.ASSUMES_ROLE,
                                    label="can assume",
                                ))

    # ── Graph Node Helpers ────────────────────────────────────────────

    def _add_principal_node(self, principal: IAMPrincipal):
        """Add a principal as a node in the graph."""
        node_type_map = {
            "user": NodeType.IAM_USER,
            "role": NodeType.IAM_ROLE,
            "group": NodeType.IAM_USER,  # reuse IAM_USER for groups
        }
        node_type = node_type_map.get(principal.principal_type, NodeType.IAM_USER)
        node_id = self._node_id(principal)

        props = {
            "arn": principal.arn,
            "principal_type": principal.principal_type,
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
            edge_type = EdgeType.HAS_POLICY
            self.graph.add_edge(Edge(
                source=node_id,
                target=pol_id,
                edge_type=edge_type,
                label=pol.get("type", "policy"),
            ))

    def _node_id(self, principal: IAMPrincipal) -> str:
        """Generate stable node ID from principal ARN."""
        return f"iam:{principal.principal_type}:{principal.name}"

    def _find_principal_by_name(self, name: str, ptype: str) -> Optional[IAMPrincipal]:
        for p in self.principals.values():
            if p.name == name and p.principal_type == ptype:
                return p
        return None

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
            # Fallback to single call
            try:
                response = getattr(client, method)(**kwargs)
                results = response.get(key, [])
            except Exception as e:
                logger.warning("Failed to call %s: %s", method, e)
        return results

    # ── Analysis Helpers ──────────────────────────────────────────────

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
        """Get all roles that a principal can assume (via graph traversal)."""
        node_id = self._node_id(principal)
        assumable = []
        for edge in self.graph.adjacency.get(node_id, []):
            if edge.edge_type == EdgeType.ASSUMES_ROLE:
                target_node = self.graph.nodes.get(edge.target)
                if target_node:
                    # Find the matching principal
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

        # Add permissions from roles this principal can assume
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

    def to_summary(self) -> dict:
        """Return a summary of the IAM graph for logging/display."""
        users = [p for p in self.principals.values() if p.principal_type == "user"]
        roles = [p for p in self.principals.values() if p.principal_type == "role"]
        groups = [p for p in self.principals.values() if p.principal_type == "group"]
        admins = self.get_admin_principals()

        return {
            "total_principals": len(self.principals),
            "users": len(users),
            "roles": len(roles),
            "groups": len(groups),
            "admin_principals": len(admins),
            "admin_names": [p.name for p in admins],
            "total_graph_nodes": len(self.graph.nodes),
            "total_graph_edges": sum(len(edges) for edges in self.graph.adjacency.values()),
        }
