"""
Blast Radius Calculator for attack paths.

Estimates the number and type of resources an attacker can reach from
an attack path's entry point. Works from the existing finding-based graph
without requiring IAM real-time data.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .graph_engine import AttackPath, AttackPathGraph, GraphNode, NodeType


@dataclass
class BlastRadius:
    """Blast radius assessment for a single attack path."""
    path_id: str
    path_title: str
    total_reachable: int
    data_stores: int
    compute_instances: int
    identities: int
    services: int
    network_nodes: int
    pii_exposure: bool
    backup_exposure: bool
    admin_escalation: bool
    severity: str  # critical, high, medium, low
    reachable_resources: list[dict]  # [{id, label, node_type, service, depth}]
    summary: str  # Human-readable blast radius summary

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "path_title": self.path_title,
            "total_reachable": self.total_reachable,
            "data_stores": self.data_stores,
            "compute_instances": self.compute_instances,
            "identities": self.identities,
            "services": self.services,
            "network_nodes": self.network_nodes,
            "pii_exposure": self.pii_exposure,
            "backup_exposure": self.backup_exposure,
            "admin_escalation": self.admin_escalation,
            "severity": self.severity,
            "reachable_resources": self.reachable_resources,
            "summary": self.summary,
        }


# Keywords that indicate PII-containing resources
PII_INDICATORS = {
    "user", "customer", "personal", "pii", "email", "patient",
    "health", "hipaa", "gdpr", "ssn", "credit_card", "payment",
}

# Keywords that indicate backup/DR resources
BACKUP_INDICATORS = {
    "backup", "snapshot", "replica", "versioning", "object_lock",
    "recovery", "archive", "vault", "dr-",
}

# Keywords that indicate admin/privileged roles
ADMIN_INDICATORS = {
    "admin", "administrator", "root", "owner", "superuser",
    "privilege", "cluster-admin", "org-admin", "management",
}


class BlastRadiusCalculator:
    """
    Calculates blast radius for attack paths using BFS on the path graph.

    This v1 implementation works entirely from existing findings/graph data.
    It does NOT require IAM real-time data — it estimates reachability from
    the resource graph built by the AttackPathAnalyzer.
    """

    def calculate(self, path: AttackPath, full_graph: Optional[AttackPathGraph] = None) -> BlastRadius:
        """
        Calculate blast radius for a single attack path.

        If full_graph is provided, uses BFS to find all reachable nodes
        from the path's entry point. Otherwise, uses only the nodes
        within the path itself as an approximation.
        """
        if full_graph:
            reachable = self._bfs_reachable(full_graph, path)
        else:
            reachable = self._path_nodes_as_reachable(path)

        # Classify reachable resources
        data_stores = [r for r in reachable if r["node_type"] == NodeType.DATA_STORE.value]
        compute = [r for r in reachable if r["node_type"] == NodeType.RESOURCE.value]
        identities = [r for r in reachable if r["node_type"] == NodeType.IDENTITY.value]
        services = [r for r in reachable if r["node_type"] == NodeType.SERVICE.value]
        network = [r for r in reachable if r["node_type"] == NodeType.NETWORK.value]

        # Check for PII, backup, admin exposure
        pii_exposure = self._has_indicator(reachable, PII_INDICATORS)
        backup_exposure = self._has_indicator(reachable, BACKUP_INDICATORS)
        admin_escalation = self._has_indicator(reachable, ADMIN_INDICATORS)

        severity = self._classify_severity(
            total=len(reachable),
            data_stores=len(data_stores),
            pii=pii_exposure,
            admin=admin_escalation,
            backup=backup_exposure,
        )

        summary = self._generate_summary(
            total=len(reachable),
            data_stores=len(data_stores),
            compute=len(compute),
            identities=len(identities),
            pii=pii_exposure,
            admin=admin_escalation,
            backup=backup_exposure,
        )

        return BlastRadius(
            path_id=path.id,
            path_title=path.title,
            total_reachable=len(reachable),
            data_stores=len(data_stores),
            compute_instances=len(compute),
            identities=len(identities),
            services=len(services),
            network_nodes=len(network),
            pii_exposure=pii_exposure,
            backup_exposure=backup_exposure,
            admin_escalation=admin_escalation,
            severity=severity,
            reachable_resources=reachable[:50],  # Cap at 50 for response size
            summary=summary,
        )

    def calculate_all(
        self, paths: list[AttackPath], full_graph: Optional[AttackPathGraph] = None
    ) -> list[BlastRadius]:
        """Calculate blast radius for all attack paths."""
        return [self.calculate(p, full_graph) for p in paths]

    def _bfs_reachable(self, graph: AttackPathGraph, path: AttackPath) -> list[dict]:
        """BFS from all nodes in the path to find reachable resources in the full graph."""
        visited: dict[str, int] = {}  # node_id -> depth
        queue: list[tuple[str, int]] = []

        # Seed from all nodes in the path (not just entry point)
        for node in path.nodes:
            if node.id not in visited:
                visited[node.id] = 0
                queue.append((node.id, 0))

        max_depth = 4

        while queue:
            current_id, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            for neighbor_id in graph.get_neighbors(current_id):
                if neighbor_id not in visited:
                    visited[neighbor_id] = depth + 1
                    queue.append((neighbor_id, depth + 1))

        # Convert to resource dicts, excluding Internet and Finding nodes
        reachable = []
        for nid, depth in visited.items():
            node = graph.nodes.get(nid)
            if not node:
                continue
            if node.node_type in (NodeType.INTERNET, NodeType.FINDING):
                continue
            reachable.append({
                "id": node.id,
                "label": node.label,
                "node_type": node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type),
                "service": node.service,
                "severity": node.severity,
                "depth": depth,
            })

        return reachable

    def _path_nodes_as_reachable(self, path: AttackPath) -> list[dict]:
        """Fallback: use path nodes + affected_resources as reachable estimate."""
        reachable = []
        seen = set()

        for node in path.nodes:
            if node.node_type in (NodeType.INTERNET, NodeType.FINDING):
                continue
            if node.id in seen:
                continue
            seen.add(node.id)
            reachable.append({
                "id": node.id,
                "label": node.label,
                "node_type": node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type),
                "service": node.service,
                "severity": getattr(node, "severity", ""),
                "depth": 0,
            })

        # Also count affected_resources that aren't already in nodes
        for res in path.affected_resources:
            res_str = str(res)
            if res_str not in seen:
                seen.add(res_str)
                reachable.append({
                    "id": res_str,
                    "label": res_str,
                    "node_type": "resource",
                    "service": "",
                    "severity": "",
                    "depth": 1,
                })

        return reachable

    @staticmethod
    def _has_indicator(resources: list[dict], indicators: set[str]) -> bool:
        """Check if any resource label/id contains indicator keywords."""
        for r in resources:
            text = (r.get("label", "") + " " + r.get("id", "") + " " + r.get("service", "")).lower()
            if any(ind in text for ind in indicators):
                return True
        return False

    @staticmethod
    def _classify_severity(
        total: int, data_stores: int, pii: bool, admin: bool, backup: bool
    ) -> str:
        if admin and (pii or data_stores >= 3):
            return "critical"
        if pii or (admin and total >= 10):
            return "critical"
        if backup and data_stores >= 2:
            return "high"
        if data_stores >= 3 or total >= 20:
            return "high"
        if data_stores >= 1 or total >= 10:
            return "medium"
        return "low"

    @staticmethod
    def _generate_summary(
        total: int, data_stores: int, compute: int, identities: int,
        pii: bool, admin: bool, backup: bool
    ) -> str:
        parts = [f"{total} resources reachable"]
        if data_stores:
            parts.append(f"{data_stores} data store{'s' if data_stores != 1 else ''}")
        if compute:
            parts.append(f"{compute} compute instance{'s' if compute != 1 else ''}")
        if identities:
            parts.append(f"{identities} identit{'ies' if identities != 1 else 'y'}")

        flags = []
        if pii:
            flags.append("PII exposure")
        if backup:
            flags.append("backup exposure")
        if admin:
            flags.append("admin escalation")

        summary = ": ".join([", ".join(parts)])
        if flags:
            summary += f". Risk flags: {', '.join(flags)}"
        return summary
