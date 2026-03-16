"""
In-memory graph engine for attack path analysis.

Builds a directed graph of cloud resources, identities, network topology,
and security findings, then traverses it to discover multi-step attack chains.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class NodeType(str, Enum):
    INTERNET = "internet"
    VPC = "vpc"
    SUBNET = "subnet"
    SECURITY_GROUP = "security_group"
    EC2_INSTANCE = "ec2_instance"
    LAMBDA_FUNCTION = "lambda_function"
    S3_BUCKET = "s3_bucket"
    RDS_INSTANCE = "rds_instance"
    ECS_SERVICE = "ecs_service"
    EKS_CLUSTER = "eks_cluster"
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    KMS_KEY = "kms_key"
    SECRETS_MANAGER = "secrets_manager"
    DYNAMODB_TABLE = "dynamodb_table"
    SNS_TOPIC = "sns_topic"
    SQS_QUEUE = "sqs_queue"
    CLOUDTRAIL = "cloudtrail"
    FINDING = "finding"


class EdgeType(str, Enum):
    NETWORK_EXPOSURE = "network_exposure"
    NETWORK_FLOW = "network_flow"
    ASSUMES_ROLE = "assumes_role"
    HAS_POLICY = "has_policy"
    POLICY_ALLOWS = "policy_allows"
    PASS_ROLE = "pass_role"
    ATTACHED_TO = "attached_to"
    STORES_DATA = "stores_data"
    ENCRYPTS = "encrypts"
    HAS_FINDING = "has_finding"
    METADATA_ACCESS = "metadata_access"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Node:
    id: str
    node_type: NodeType
    label: str
    properties: dict = field(default_factory=dict)
    risk_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.node_type.value,
            "label": self.label,
            "properties": self.properties,
            "risk_score": self.risk_score,
        }


@dataclass
class Edge:
    source: str
    target: str
    edge_type: EdgeType
    label: str = ""
    weight: float = 1.0
    properties: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.edge_type.value,
            "label": self.label or self.edge_type.value.replace("_", " ").title(),
            "weight": self.weight,
            "properties": self.properties,
        }


@dataclass
class AttackPath:
    id: str
    title: str
    description: str
    risk_level: RiskLevel
    risk_score: float
    nodes: list[Node]
    edges: list[Edge]
    entry_point: str
    target: str
    steps: list[str]
    mitigations: list[str]
    affected_resources: list[str]
    category: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "entry_point": self.entry_point,
            "target": self.target,
            "steps": self.steps,
            "mitigations": self.mitigations,
            "affected_resources": self.affected_resources,
            "category": self.category,
        }


class AttackGraph:
    """Directed graph for modeling cloud resource relationships and attack paths."""

    def __init__(self):
        self.nodes: dict[str, Node] = {}
        self.adjacency: dict[str, list[Edge]] = {}
        self.reverse_adjacency: dict[str, list[Edge]] = {}

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node
        if node.id not in self.adjacency:
            self.adjacency[node.id] = []
        if node.id not in self.reverse_adjacency:
            self.reverse_adjacency[node.id] = []

    def add_edge(self, edge: Edge) -> None:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            return
        self.adjacency[edge.source].append(edge)
        self.reverse_adjacency[edge.target].append(edge)

    def get_neighbors(self, node_id: str) -> list[tuple[Edge, Node]]:
        result = []
        for edge in self.adjacency.get(node_id, []):
            if edge.target in self.nodes:
                result.append((edge, self.nodes[edge.target]))
        return result

    def find_paths(
        self,
        start: str,
        end: str,
        max_depth: int = 8,
    ) -> list[list[str]]:
        """BFS to find all paths from start to end within max_depth."""
        if start not in self.nodes or end not in self.nodes:
            return []

        paths = []
        queue: list[list[str]] = [[start]]

        while queue:
            path = queue.pop(0)
            current = path[-1]

            if current == end and len(path) > 1:
                paths.append(path)
                continue

            if len(path) >= max_depth:
                continue

            for edge, neighbor in self.get_neighbors(current):
                if neighbor.id not in path:
                    queue.append(path + [neighbor.id])

        return paths

    def find_attack_paths_from_entry(
        self,
        entry_node_id: str,
        high_value_types: set[NodeType] | None = None,
        max_depth: int = 8,
    ) -> list[list[str]]:
        """Find all paths from an entry point to high-value targets."""
        if high_value_types is None:
            high_value_types = {
                NodeType.S3_BUCKET,
                NodeType.RDS_INSTANCE,
                NodeType.DYNAMODB_TABLE,
                NodeType.SECRETS_MANAGER,
                NodeType.KMS_KEY,
                NodeType.IAM_ROLE,
            }

        targets = [
            nid for nid, n in self.nodes.items()
            if n.node_type in high_value_types and nid != entry_node_id
        ]

        all_paths = []
        for target in targets:
            paths = self.find_paths(entry_node_id, target, max_depth)
            all_paths.extend(paths)

        return all_paths

    def compute_centrality(self) -> dict[str, float]:
        """Simplified betweenness centrality to find choke points."""
        centrality = {nid: 0.0 for nid in self.nodes}

        node_ids = list(self.nodes.keys())
        for i, source in enumerate(node_ids):
            for target in node_ids[i + 1:]:
                paths = self.find_paths(source, target, max_depth=6)
                if not paths:
                    continue
                for path in paths:
                    for node_id in path[1:-1]:
                        centrality[node_id] += 1.0 / len(paths)

        max_c = max(centrality.values()) if centrality else 1.0
        if max_c > 0:
            centrality = {k: v / max_c for k, v in centrality.items()}

        return centrality

    def get_entry_points(self) -> list[str]:
        """Find nodes that represent external entry points."""
        entries = []
        for nid, node in self.nodes.items():
            if node.node_type == NodeType.INTERNET:
                entries.append(nid)
            elif node.properties.get("publicly_exposed"):
                entries.append(nid)
        return entries

    def get_graph_data(self) -> dict:
        """Export graph as JSON-serializable dict for the frontend."""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [
                e.to_dict()
                for edges in self.adjacency.values()
                for e in edges
            ],
        }
