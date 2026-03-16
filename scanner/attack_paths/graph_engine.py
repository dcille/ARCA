"""
In-memory graph engine for attack path analysis.

Builds a directed graph from security findings and cloud resource relationships,
then traverses it to discover multi-step attack chains.
"""
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class NodeType(str, Enum):
    INTERNET = "internet"
    RESOURCE = "resource"
    IDENTITY = "identity"
    NETWORK = "network"
    DATA_STORE = "data_store"
    FINDING = "finding"
    SERVICE = "service"


class EdgeType(str, Enum):
    EXPOSES = "exposes"
    HAS_ACCESS = "has_access"
    ASSUMES_ROLE = "assumes_role"
    ATTACHED_TO = "attached_to"
    ROUTES_TO = "routes_to"
    STORES_DATA = "stores_data"
    HAS_FINDING = "has_finding"
    CAN_ESCALATE = "can_escalate"
    LATERAL_MOVE = "lateral_move"
    CREDENTIAL_ACCESS = "credential_access"


@dataclass
class GraphNode:
    id: str
    node_type: NodeType
    label: str
    service: str = ""
    resource_id: str = ""
    severity: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    edge_type: EdgeType
    label: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class AttackPath:
    id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low
    risk_score: float  # 0-100
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    entry_point: str
    target: str
    category: str  # privilege_escalation, lateral_movement, data_exfiltration, exposure
    techniques: list[str]
    affected_resources: list[str]
    remediation: list[str]


class AttackPathGraph:
    """In-memory directed graph for attack path analysis."""

    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self.adjacency: dict[str, list[str]] = {}

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.id] = node
        if node.id not in self.adjacency:
            self.adjacency[node.id] = []

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)
        if edge.source_id not in self.adjacency:
            self.adjacency[edge.source_id] = []
        self.adjacency[edge.source_id].append(edge.target_id)

    def get_neighbors(self, node_id: str) -> list[str]:
        return self.adjacency.get(node_id, [])

    def find_paths(self, start: str, end: str, max_depth: int = 8) -> list[list[str]]:
        """BFS to find all paths from start to end up to max_depth."""
        paths = []
        queue = [(start, [start])]
        while queue:
            current, path = queue.pop(0)
            if len(path) > max_depth:
                continue
            if current == end and len(path) > 1:
                paths.append(path)
                continue
            for neighbor in self.get_neighbors(current):
                if neighbor not in path:
                    queue.append((neighbor, path + [neighbor]))
        return paths

    def get_edge_between(self, source_id: str, target_id: str) -> Optional[GraphEdge]:
        for edge in self.edges:
            if edge.source_id == source_id and edge.target_id == target_id:
                return edge
        return None


def _make_id() -> str:
    return str(uuid.uuid4())[:8]


# ── Attack path scenario definitions ──────────────────────────────────

SCENARIO_TEMPLATES = [
    # ── AWS: External Exposure → Compute → Data ───────────────────
    {
        "match_services": {"ec2", "s3"},
        "match_checks": ["ec2_security_group", "s3_bucket_public", "ec2_ebs", "ec2_imds"],
        "category": "data_exfiltration",
        "builder": "_build_exposure_to_data_path",
    },
    # ── AWS: IAM Privilege Escalation ─────────────────────────────
    {
        "match_services": {"iam"},
        "match_checks": ["iam_policy_admin", "iam_user_policy", "iam_role_admin",
                          "iam_inline_policy", "iam_root_mfa", "iam_user_mfa",
                          "iam_access_key", "iam_password_policy"],
        "category": "privilege_escalation",
        "builder": "_build_iam_escalation_path",
    },
    # ── AWS: Credential Exposure → Lateral Movement ───────────────
    {
        "match_services": {"secretsmanager", "ssm", "lambda"},
        "match_checks": ["secretsmanager_rotation", "ssm_parameter", "lambda_env",
                          "lambda_runtime", "lambda_vpc"],
        "category": "lateral_movement",
        "builder": "_build_credential_lateral_path",
    },
    # ── AWS: Network Exposure Chain ───────────────────────────────
    {
        "match_services": {"vpc", "ec2", "rds"},
        "match_checks": ["vpc_flow_logs", "ec2_security_group", "rds_public",
                          "rds_encryption", "rds_multi_az"],
        "category": "exposure",
        "builder": "_build_network_exposure_path",
    },
    # ── AWS: Encryption Gap Chain ─────────────────────────────────
    {
        "match_services": {"s3", "rds", "ebs", "kms", "dynamodb", "efs", "elasticache"},
        "match_checks": ["s3_encryption", "rds_encryption", "ebs_encryption", "kms_rotation",
                          "dynamodb_table_encrypted", "efs_encryption", "elasticache_encryption"],
        "category": "data_exfiltration",
        "builder": "_build_encryption_gap_path",
    },
    # ── AWS: Logging Blindspot → Undetected Access ────────────────
    {
        "match_services": {"cloudtrail", "cloudwatch", "guardduty", "config"},
        "match_checks": ["cloudtrail_enabled", "guardduty_enabled", "config_enabled",
                          "cloudtrail_multiregion", "cloudwatch_log_group"],
        "category": "detection_evasion",
        "builder": "_build_logging_blindspot_path",
    },
    # ── AWS: Lambda/ECS Compute Escalation ────────────────────────
    {
        "match_services": {"lambda", "ecs", "eks"},
        "match_checks": ["lambda_", "ecs_", "eks_"],
        "category": "privilege_escalation",
        "builder": "_build_compute_escalation_path",
    },
    # ── Azure: Identity → KeyVault → Data ─────────────────────────
    {
        "match_services": {"identity", "keyvault", "database", "storage"},
        "match_checks": ["azure_iam", "azure_keyvault", "azure_storage", "azure_sql"],
        "category": "data_exfiltration",
        "builder": "_build_azure_exposure_path",
    },
    # ── Azure: Network Exposure ───────────────────────────────────
    {
        "match_services": {"network", "appservice", "compute", "database"},
        "match_checks": ["azure_network", "azure_nsg", "azure_appservice",
                          "azure_vm", "azure_sql"],
        "category": "exposure",
        "builder": "_build_azure_network_path",
    },
    # ── GCP: IAM & Compute Exposure ───────────────────────────────
    {
        "match_services": {"iam", "compute", "storage", "sql"},
        "match_checks": ["gcp_iam", "gcp_compute", "gcp_storage", "gcp_sql"],
        "category": "exposure",
        "builder": "_build_gcp_exposure_path",
    },
    # ── GCP: Network & Firewall Exposure ──────────────────────────
    {
        "match_services": {"networking", "compute", "gke", "sql"},
        "match_checks": ["gcp_firewall", "gcp_gke", "gcp_sql_no_public"],
        "category": "exposure",
        "builder": "_build_gcp_network_path",
    },
    # ── Kubernetes: RBAC & Pod Security ───────────────────────────
    {
        "match_services": {"pods", "rbac", "namespaces"},
        "match_checks": ["k8s_pod", "k8s_rbac", "k8s_namespace"],
        "category": "privilege_escalation",
        "builder": "_build_k8s_escalation_path",
    },
    # ── Kubernetes: Network & Container Exposure ──────────────────
    {
        "match_services": {"pods", "network", "namespaces"},
        "match_checks": ["k8s_pod_privileged", "k8s_pod_run_as_non_root",
                          "k8s_namespace_network_policy"],
        "category": "lateral_movement",
        "builder": "_build_k8s_lateral_path",
    },
    # ── OCI: IAM & Storage Exposure ───────────────────────────────
    {
        "match_services": {"iam", "objectstorage", "networking", "storage", "vault"},
        "match_checks": ["oci_iam", "oci_objectstorage", "oci_network", "oci_storage",
                          "oci_vault"],
        "category": "exposure",
        "builder": "_build_oci_exposure_path",
    },
    # ── OCI: Compute & Database ───────────────────────────────────
    {
        "match_services": {"compute", "database", "mysql", "kubernetesengine",
                           "functions", "containerinstances"},
        "match_checks": ["oci_compute", "oci_db", "oci_mysql", "oci_oke",
                          "oci_functions", "oci_container"],
        "category": "data_exfiltration",
        "builder": "_build_oci_compute_data_path",
    },
    # ── Cross-provider: Monitoring Blind Spots ────────────────────
    {
        "match_services": {"monitor", "logging", "cloudguard", "cloudtrail",
                           "cloudwatch", "guardduty", "config"},
        "match_checks": ["azure_monitor", "gcp_logging", "oci_cloudguard", "oci_logging",
                          "cloudtrail_", "guardduty_", "config_"],
        "category": "detection_evasion",
        "builder": "_build_monitoring_blindspot_path",
    },
    # ── Cross-provider: Encryption Gaps ───────────────────────────
    {
        "match_services": {"kms", "keyvault", "vault", "storage", "s3", "objectstorage",
                           "database", "rds", "sql", "mysql"},
        "match_checks": ["encrypt", "kms", "ssl", "tls", "cmk"],
        "category": "data_exfiltration",
        "builder": "_build_encryption_gap_path",
    },
]


class AttackPathAnalyzer:
    """Analyzes findings to discover attack paths."""

    def __init__(self, findings: list[dict]):
        self.findings = findings
        self.graph = AttackPathGraph()
        self.paths: list[AttackPath] = []

    def analyze(self) -> list[AttackPath]:
        """Run full analysis pipeline."""
        self._build_graph()
        self._detect_paths()
        self._score_paths()
        return sorted(self.paths, key=lambda p: p.risk_score, reverse=True)

    def _build_graph(self) -> None:
        """Build the resource graph from findings."""
        internet_node = GraphNode(
            id="internet",
            node_type=NodeType.INTERNET,
            label="Internet",
            service="external",
        )
        self.graph.add_node(internet_node)

        # Group findings by service
        by_service: dict[str, list[dict]] = {}
        for f in self.findings:
            svc = f.get("service", "unknown")
            by_service.setdefault(svc, []).append(f)

        # Create resource nodes from findings
        for f in self.findings:
            resource_node = GraphNode(
                id=f"resource-{f['id'][:8]}",
                node_type=self._classify_node_type(f["service"]),
                label=f.get("resource_name") or f.get("resource_id") or f["check_title"],
                service=f["service"],
                resource_id=f.get("resource_id", ""),
                severity=f["severity"],
                metadata={
                    "check_id": f["check_id"],
                    "check_title": f["check_title"],
                    "status": f["status"],
                    "region": f.get("region", ""),
                    "remediation": f.get("remediation", ""),
                    "finding_id": f["id"],
                },
            )
            self.graph.add_node(resource_node)

            # Finding node
            finding_node = GraphNode(
                id=f"finding-{f['id'][:8]}",
                node_type=NodeType.FINDING,
                label=f["check_title"],
                service=f["service"],
                severity=f["severity"],
                metadata={"status": f["status"]},
            )
            self.graph.add_node(finding_node)
            self.graph.add_edge(GraphEdge(
                source_id=resource_node.id,
                target_id=finding_node.id,
                edge_type=EdgeType.HAS_FINDING,
                label="has finding",
            ))

        # Build inter-resource edges based on service relationships
        self._build_service_edges(by_service)

    def _classify_node_type(self, service: str) -> NodeType:
        svc = service.lower()
        identity_services = {"iam", "identity", "aad", "rbac"}
        network_services = {"vpc", "network", "securitygroup", "subnet", "networking",
                            "vcn", "loadbalancer"}
        data_services = {"s3", "rds", "dynamodb", "storage", "cloudsql", "efs", "elasticsearch",
                         "database", "objectstorage", "blockstorage", "mysql", "sql",
                         "filestorage", "elasticache", "containerregistry"}
        compute_services = {"ec2", "lambda", "ecs", "compute", "gke", "eks", "oke", "functions",
                            "appservice", "containerinstances", "kubernetesengine", "pods"}

        if svc in identity_services:
            return NodeType.IDENTITY
        if svc in network_services:
            return NodeType.NETWORK
        if svc in data_services:
            return NodeType.DATA_STORE
        if svc in compute_services:
            return NodeType.RESOURCE
        return NodeType.SERVICE

    def _build_service_edges(self, by_service: dict[str, list[dict]]) -> None:
        """Create edges representing resource relationships."""
        resource_nodes = {
            nid: n for nid, n in self.graph.nodes.items()
            if n.node_type != NodeType.FINDING and n.node_type != NodeType.INTERNET
        }

        # Internet → publicly exposed resources
        for nid, node in resource_nodes.items():
            check_id = node.metadata.get("check_id", "")
            if any(kw in check_id for kw in ["public", "security_group_open", "ingress", "exposed"]):
                self.graph.add_edge(GraphEdge(
                    source_id="internet",
                    target_id=nid,
                    edge_type=EdgeType.EXPOSES,
                    label="publicly accessible",
                ))

        # IAM → other resources (permission relationships)
        iam_nodes = [n for n in resource_nodes.values() if n.service.lower() in ("iam", "identity")]
        compute_nodes = [n for n in resource_nodes.values()
                         if n.node_type == NodeType.RESOURCE]
        data_nodes = [n for n in resource_nodes.values()
                      if n.node_type == NodeType.DATA_STORE]

        for iam in iam_nodes:
            for compute in compute_nodes:
                self.graph.add_edge(GraphEdge(
                    source_id=iam.id,
                    target_id=compute.id,
                    edge_type=EdgeType.HAS_ACCESS,
                    label="has permissions",
                ))
            for data in data_nodes:
                self.graph.add_edge(GraphEdge(
                    source_id=iam.id,
                    target_id=data.id,
                    edge_type=EdgeType.HAS_ACCESS,
                    label="can access data",
                ))
            # IAM self-escalation
            for other_iam in iam_nodes:
                if iam.id != other_iam.id:
                    self.graph.add_edge(GraphEdge(
                        source_id=iam.id,
                        target_id=other_iam.id,
                        edge_type=EdgeType.CAN_ESCALATE,
                        label="can escalate via",
                    ))

        # Compute → Data (access patterns)
        for compute in compute_nodes:
            for data in data_nodes:
                self.graph.add_edge(GraphEdge(
                    source_id=compute.id,
                    target_id=data.id,
                    edge_type=EdgeType.HAS_ACCESS,
                    label="accesses data store",
                ))

        # Network → Compute (routing)
        network_nodes = [n for n in resource_nodes.values()
                         if n.node_type == NodeType.NETWORK]
        for net in network_nodes:
            for compute in compute_nodes:
                self.graph.add_edge(GraphEdge(
                    source_id=net.id,
                    target_id=compute.id,
                    edge_type=EdgeType.ROUTES_TO,
                    label="routes traffic to",
                ))

        # Credential stores → Lateral movement
        cred_nodes = [n for n in resource_nodes.values()
                      if n.service.lower() in ("secretsmanager", "ssm", "kms", "keyvault", "vault")]
        for cred in cred_nodes:
            for compute in compute_nodes:
                self.graph.add_edge(GraphEdge(
                    source_id=cred.id,
                    target_id=compute.id,
                    edge_type=EdgeType.CREDENTIAL_ACCESS,
                    label="credentials used by",
                ))

    def _detect_paths(self) -> None:
        """Detect attack path scenarios from the graph."""
        failed = [f for f in self.findings if f.get("status") == "FAIL"]
        if not failed:
            return

        # Normalize service names to lowercase for case-insensitive matching
        services = {f["service"] for f in failed}
        services_lower = {s.lower() for s in services}
        check_ids = {f["check_id"] for f in failed}

        for template in SCENARIO_TEMPLATES:
            template_services_lower = {s.lower() for s in template["match_services"]}
            matched_services = services_lower & template_services_lower
            matched_checks = [
                cid for cid in check_ids
                if any(mc.lower() in cid.lower() for mc in template["match_checks"])
            ]
            if matched_services and matched_checks:
                builder = getattr(self, template["builder"], None)
                if builder:
                    path = builder(failed, matched_services, matched_checks)
                    if path:
                        self.paths.append(path)

    def _build_exposure_to_data_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Internet → Exposed Service → Data Store path."""
        graph = AttackPathGraph()
        nodes, edges = [], []

        internet = GraphNode(id="internet", node_type=NodeType.INTERNET,
                             label="Internet", service="external")
        nodes.append(internet)
        graph.add_node(internet)

        exposed_findings = [f for f in findings
                            if any(k in f["check_id"] for k in ["public", "security_group", "ingress"])]
        data_findings = [f for f in findings
                         if f["service"].lower() in ("s3", "rds", "dynamodb", "efs", "elasticsearch")]

        if not exposed_findings or not data_findings:
            return None

        affected = []
        for ef in exposed_findings[:3]:
            n = GraphNode(id=f"exposed-{_make_id()}", node_type=NodeType.RESOURCE,
                          label=ef.get("resource_name") or ef["check_title"],
                          service=ef["service"], severity=ef["severity"],
                          metadata={"finding_id": ef["id"], "check_id": ef["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge("internet", n.id, EdgeType.EXPOSES, "publicly accessible"))
            affected.append(ef.get("resource_id") or ef["check_title"])

            for df in data_findings[:2]:
                dn = GraphNode(id=f"data-{_make_id()}", node_type=NodeType.DATA_STORE,
                               label=df.get("resource_name") or df["check_title"],
                               service=df["service"], severity=df["severity"],
                               metadata={"finding_id": df["id"], "check_id": df["check_id"]})
                nodes.append(dn)
                edges.append(GraphEdge(n.id, dn.id, EdgeType.HAS_ACCESS, "accesses"))
                affected.append(df.get("resource_id") or df["check_title"])

        max_sev = self._max_severity([f["severity"] for f in exposed_findings + data_findings])

        return AttackPath(
            id=_make_id(),
            title="External Exposure to Sensitive Data",
            description="Publicly accessible resources provide a path to sensitive data stores. "
                        "An attacker could exploit exposed services to access databases or storage buckets.",
            severity=max_sev,
            risk_score=0,
            nodes=nodes,
            edges=edges,
            entry_point="Internet",
            target="Data Stores",
            category="data_exfiltration",
            techniques=["Initial Access: Exploit Public-Facing Application",
                         "Collection: Data from Cloud Storage"],
            affected_resources=affected,
            remediation=[
                "Restrict security group inbound rules to known IPs",
                "Disable public access on S3 buckets and RDS instances",
                "Enable encryption at rest on all data stores",
                "Implement VPC endpoints for private access",
            ],
        )

    def _build_iam_escalation_path(self, findings, services, checks) -> Optional[AttackPath]:
        """IAM misconfiguration → privilege escalation path."""
        iam_findings = [f for f in findings if f["service"].lower() == "iam"
                        and any(k in f["check_id"] for k in ["admin", "policy", "inline", "role",
                                                              "mfa", "access_key", "password"])]
        if not iam_findings:
            return None

        nodes, edges, affected = [], [], []
        attacker = GraphNode(id="attacker", node_type=NodeType.IDENTITY,
                             label="Compromised User", service="IAM")
        nodes.append(attacker)

        for i, f in enumerate(iam_findings[:4]):
            n = GraphNode(id=f"iam-{_make_id()}", node_type=NodeType.IDENTITY,
                          label=f.get("resource_name") or f["check_title"],
                          service="IAM", severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            if i == 0:
                edges.append(GraphEdge("attacker", n.id, EdgeType.CAN_ESCALATE,
                                       "exploits misconfiguration"))
            else:
                edges.append(GraphEdge(nodes[-2].id, n.id, EdgeType.CAN_ESCALATE,
                                       "escalates to"))
            affected.append(f.get("resource_id") or f["check_title"])

        admin_node = GraphNode(id=f"admin-{_make_id()}", node_type=NodeType.IDENTITY,
                               label="Administrator Access", service="IAM", severity="critical")
        nodes.append(admin_node)
        edges.append(GraphEdge(nodes[-2].id, admin_node.id, EdgeType.CAN_ESCALATE, "gains admin"))

        max_sev = self._max_severity([f["severity"] for f in iam_findings])

        return AttackPath(
            id=_make_id(),
            title="IAM Privilege Escalation Chain",
            description="Overly permissive IAM policies create a chain that allows privilege escalation "
                        "from a low-privilege user to administrator access.",
            severity=max_sev,
            risk_score=0,
            nodes=nodes,
            edges=edges,
            entry_point="Compromised User",
            target="Administrator Access",
            category="privilege_escalation",
            techniques=["Privilege Escalation: IAM Policy Modification",
                         "Privilege Escalation: AssumeRole Abuse",
                         "Persistence: Create New IAM User"],
            affected_resources=affected,
            remediation=[
                "Apply least-privilege IAM policies",
                "Remove wildcard (*) permissions from IAM policies",
                "Enable IAM Access Analyzer to identify overly permissive policies",
                "Implement MFA for all IAM users with console access",
                "Use IAM roles with temporary credentials instead of long-lived access keys",
            ],
        )

    def _build_credential_lateral_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Credential exposure → lateral movement path."""
        cred_findings = [f for f in findings
                         if f["service"].lower() in ("secretsmanager", "ssm", "lambda")
                         and f.get("status") == "FAIL"]
        if not cred_findings:
            return None

        nodes, edges, affected = [], [], []
        entry = GraphNode(id="compromised-compute", node_type=NodeType.RESOURCE,
                          label="Compromised Instance", service="EC2")
        nodes.append(entry)

        for f in cred_findings[:3]:
            n = GraphNode(id=f"cred-{_make_id()}", node_type=NodeType.SERVICE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(entry.id, n.id, EdgeType.CREDENTIAL_ACCESS,
                                   "extracts credentials from"))
            affected.append(f.get("resource_id") or f["check_title"])

        target = GraphNode(id=f"target-{_make_id()}", node_type=NodeType.RESOURCE,
                           label="Other Cloud Resources", service="multi-service")
        nodes.append(target)
        for n in nodes[1:-1]:
            edges.append(GraphEdge(n.id, target.id, EdgeType.LATERAL_MOVE,
                                   "lateral movement via stolen credentials"))

        return AttackPath(
            id=_make_id(),
            title="Credential Exposure and Lateral Movement",
            description="Improperly managed secrets and credentials enable lateral movement "
                        "from a compromised instance to other cloud resources.",
            severity=self._max_severity([f["severity"] for f in cred_findings]),
            risk_score=0,
            nodes=nodes,
            edges=edges,
            entry_point="Compromised Compute Instance",
            target="Other Cloud Resources",
            category="lateral_movement",
            techniques=["Credential Access: Unsecured Credentials",
                         "Lateral Movement: Use Alternate Authentication Material"],
            affected_resources=affected,
            remediation=[
                "Enable automatic rotation for all secrets in Secrets Manager",
                "Use IAM roles instead of hardcoded credentials in Lambda environment variables",
                "Encrypt SSM parameters with customer-managed KMS keys",
                "Implement least-privilege access for credential stores",
            ],
        )

    def _build_network_exposure_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Network misconfiguration → database exposure path."""
        net_findings = [f for f in findings
                        if f["service"].lower() in ("vpc", "ec2", "rds")
                        and f.get("status") == "FAIL"]
        if not net_findings:
            return None

        nodes, edges, affected = [], [], []
        internet = GraphNode(id="internet-net", node_type=NodeType.INTERNET,
                             label="Internet", service="external")
        nodes.append(internet)

        net_layer = [f for f in net_findings if f["service"].lower() in ("vpc", "ec2")]
        db_layer = [f for f in net_findings if f["service"].lower() == "rds"]

        for f in net_layer[:2]:
            n = GraphNode(id=f"net-{_make_id()}", node_type=NodeType.NETWORK,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(internet.id, n.id, EdgeType.ROUTES_TO,
                                   "ingress through misconfigured network"))
            affected.append(f.get("resource_id") or f["check_title"])

        for f in db_layer[:2]:
            n = GraphNode(id=f"db-{_make_id()}", node_type=NodeType.DATA_STORE,
                          label=f.get("resource_name") or f["check_title"],
                          service="RDS", severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            for prev in nodes[1:]:
                if prev.node_type == NodeType.NETWORK:
                    edges.append(GraphEdge(prev.id, n.id, EdgeType.ROUTES_TO,
                                           "reaches database"))
            affected.append(f.get("resource_id") or f["check_title"])

        if len(nodes) < 3:
            return None

        return AttackPath(
            id=_make_id(),
            title="Network Exposure to Database",
            description="Misconfigured network controls allow internet traffic to reach "
                        "database instances through open security groups and VPC misconfigurations.",
            severity=self._max_severity([f["severity"] for f in net_findings]),
            risk_score=0,
            nodes=nodes,
            edges=edges,
            entry_point="Internet",
            target="Database Instances",
            category="exposure",
            techniques=["Initial Access: Exploit Public-Facing Application",
                         "Discovery: Cloud Service Dashboard"],
            affected_resources=affected,
            remediation=[
                "Enable VPC Flow Logs for network monitoring",
                "Restrict RDS instances to private subnets only",
                "Review and tighten security group inbound rules",
                "Use VPC endpoints instead of public internet access",
            ],
        )

    def _build_encryption_gap_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Missing encryption → data exposure path."""
        enc_findings = [f for f in findings
                        if any(k in f["check_id"] for k in ["encrypt", "kms", "ssl", "tls"])
                        and f.get("status") == "FAIL"]
        if not enc_findings:
            return None

        nodes, edges, affected = [], [], []
        attacker = GraphNode(id="insider-threat", node_type=NodeType.IDENTITY,
                             label="Insider / Compromised Account", service="IAM")
        nodes.append(attacker)

        for f in enc_findings[:4]:
            n = GraphNode(id=f"unenc-{_make_id()}", node_type=NodeType.DATA_STORE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(attacker.id, n.id, EdgeType.HAS_ACCESS,
                                   "accesses unencrypted data"))
            affected.append(f.get("resource_id") or f["check_title"])

        return AttackPath(
            id=_make_id(),
            title="Encryption Gaps Enabling Data Exposure",
            description="Missing encryption on data stores means that an attacker with access "
                        "can read sensitive data without additional barriers.",
            severity=self._max_severity([f["severity"] for f in enc_findings]),
            risk_score=0,
            nodes=nodes,
            edges=edges,
            entry_point="Insider / Compromised Account",
            target="Unencrypted Data Stores",
            category="data_exfiltration",
            techniques=["Collection: Data from Cloud Storage",
                         "Exfiltration: Transfer Data to Cloud Account"],
            affected_resources=affected,
            remediation=[
                "Enable server-side encryption on all S3 buckets",
                "Enable encryption at rest for RDS and DynamoDB",
                "Enable EBS volume encryption by default",
                "Implement KMS key rotation policies",
            ],
        )

    def _build_logging_blindspot_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Missing logging → undetected access path."""
        log_findings = [f for f in findings
                        if f["service"].lower() in ("cloudtrail", "cloudwatch", "guardduty", "config")
                        and f.get("status") == "FAIL"]
        if not log_findings:
            return None

        nodes, edges, affected = [], [], []
        attacker = GraphNode(id="stealthy-attacker", node_type=NodeType.IDENTITY,
                             label="Threat Actor", service="external")
        nodes.append(attacker)

        for f in log_findings[:4]:
            n = GraphNode(id=f"blind-{_make_id()}", node_type=NodeType.SERVICE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(attacker.id, n.id, EdgeType.LATERAL_MOVE,
                                   "undetected due to missing logging"))
            affected.append(f.get("resource_id") or f["check_title"])

        target = GraphNode(id=f"unmonitored-{_make_id()}", node_type=NodeType.RESOURCE,
                           label="Unmonitored Environment", service="multi-service")
        nodes.append(target)
        for n in nodes[1:-1]:
            edges.append(GraphEdge(n.id, target.id, EdgeType.LATERAL_MOVE,
                                   "blind spot enables undetected access"))

        return AttackPath(
            id=_make_id(),
            title="Logging Blind Spots Enable Undetected Access",
            description="Disabled or misconfigured logging and monitoring services create blind spots "
                        "where attacker activity cannot be detected or investigated.",
            severity=self._max_severity([f["severity"] for f in log_findings]),
            risk_score=0,
            nodes=nodes,
            edges=edges,
            entry_point="Threat Actor",
            target="Unmonitored Environment",
            category="detection_evasion",
            techniques=["Defense Evasion: Impair Defenses",
                         "Defense Evasion: Disable Cloud Logs"],
            affected_resources=affected,
            remediation=[
                "Enable CloudTrail in all regions with log file validation",
                "Enable GuardDuty for threat detection",
                "Enable AWS Config for resource change tracking",
                "Set up CloudWatch alarms for security-relevant events",
            ],
        )

    def _build_compute_escalation_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Lambda/ECS misconfiguration → privilege escalation."""
        compute_findings = [f for f in findings
                            if f["service"].lower() in ("lambda", "ecs", "eks")
                            and f.get("status") == "FAIL"]
        if not compute_findings:
            return None

        nodes, edges, affected = [], [], []
        entry = GraphNode(id="code-injection", node_type=NodeType.IDENTITY,
                          label="Code Injection / Supply Chain", service="external")
        nodes.append(entry)

        for f in compute_findings[:3]:
            n = GraphNode(id=f"compute-{_make_id()}", node_type=NodeType.RESOURCE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(entry.id if len(nodes) == 2 else nodes[-2].id,
                                   n.id, EdgeType.CAN_ESCALATE,
                                   "exploits misconfigured compute"))
            affected.append(f.get("resource_id") or f["check_title"])

        target = GraphNode(id=f"cloud-api-{_make_id()}", node_type=NodeType.SERVICE,
                           label="Cloud API (via Execution Role)", service="IAM")
        nodes.append(target)
        edges.append(GraphEdge(nodes[-2].id, target.id, EdgeType.ASSUMES_ROLE,
                               "assumes execution role"))

        return AttackPath(
            id=_make_id(),
            title="Compute Service Privilege Escalation",
            description="Misconfigured Lambda functions or ECS tasks can be exploited to "
                        "escalate privileges via overly permissive execution roles.",
            severity=self._max_severity([f["severity"] for f in compute_findings]),
            risk_score=0,
            nodes=nodes,
            edges=edges,
            entry_point="Code Injection / Supply Chain",
            target="Cloud API via Execution Role",
            category="privilege_escalation",
            techniques=["Execution: Serverless Function Abuse",
                         "Privilege Escalation: PassRole to Compute"],
            affected_resources=affected,
            remediation=[
                "Apply least-privilege execution roles to Lambda functions",
                "Remove sensitive environment variables from Lambda configuration",
                "Use VPC-attached Lambda functions for network isolation",
                "Enable ECS task-level IAM roles with minimal permissions",
            ],
        )

    def _build_multi_cloud_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Multi-cloud (Azure/GCP/OCI) exposure path."""
        # Accept any failed finding - this is a catch-all for cross-cloud scenarios
        multi_findings = [f for f in findings if f.get("status") == "FAIL"]
        if not multi_findings:
            return None

        nodes, edges, affected = [], [], []
        internet = GraphNode(id="internet-mc", node_type=NodeType.INTERNET,
                             label="Internet", service="external")
        nodes.append(internet)

        prev_id = internet.id
        for f in multi_findings[:5]:
            n = GraphNode(id=f"mc-{_make_id()}", node_type=self._classify_node_type(f["service"]),
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(prev_id, n.id, EdgeType.LATERAL_MOVE,
                                   "exploits misconfiguration"))
            prev_id = n.id
            affected.append(f.get("resource_id") or f["check_title"])

        return AttackPath(
            id=_make_id(),
            title="Multi-Cloud Resource Exposure Chain",
            description="A series of misconfigurations across cloud services creates an exploitable "
                        "chain from external exposure to sensitive internal resources.",
            severity=self._max_severity([f["severity"] for f in multi_findings]),
            risk_score=0,
            nodes=nodes,
            edges=edges,
            entry_point="Internet",
            target="Internal Resources",
            category="exposure",
            techniques=["Initial Access: Exploit Public-Facing Application",
                         "Lateral Movement: Cloud Service Exploitation"],
            affected_resources=affected,
            remediation=[
                "Review and restrict public access across all cloud services",
                "Implement network segmentation and private endpoints",
                "Enable cloud-native security monitoring",
                "Apply identity-based access controls with MFA",
            ],
        )

    def _build_azure_exposure_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Azure: Identity misconfiguration → KeyVault/Storage/Database exposure."""
        azure_findings = [f for f in findings
                          if f["service"].lower() in ("identity", "keyvault", "database", "storage")
                          and f.get("status") == "FAIL"]
        if len(azure_findings) < 2:
            return None

        nodes, edges, affected = [], [], []
        attacker = GraphNode(id="az-attacker", node_type=NodeType.IDENTITY,
                             label="Compromised Azure Identity", service="identity")
        nodes.append(attacker)

        prev_id = attacker.id
        for f in azure_findings[:5]:
            n = GraphNode(id=f"az-{_make_id()}", node_type=self._classify_node_type(f["service"]),
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edge_type = EdgeType.HAS_ACCESS if n.node_type == NodeType.DATA_STORE else EdgeType.CAN_ESCALATE
            edges.append(GraphEdge(prev_id, n.id, edge_type, "exploits misconfiguration"))
            prev_id = n.id
            affected.append(f.get("resource_id") or f["check_title"])

        return AttackPath(
            id=_make_id(),
            title="Azure Identity to Data Exposure Chain",
            description="Misconfigured Azure identity and access controls create a path from "
                        "compromised credentials to sensitive data in storage, databases, or Key Vault.",
            severity=self._max_severity([f["severity"] for f in azure_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Compromised Azure Identity",
            target="Sensitive Data Stores",
            category="data_exfiltration",
            techniques=["Initial Access: Valid Accounts",
                         "Credential Access: Unsecured Credentials in Key Vault",
                         "Collection: Data from Cloud Storage"],
            affected_resources=affected,
            remediation=[
                "Enforce MFA for all Azure AD users",
                "Apply RBAC with least-privilege across subscriptions",
                "Enable Key Vault soft-delete and purge protection",
                "Enable encryption with customer-managed keys on storage accounts",
                "Enable Azure Defender for real-time threat detection",
            ],
        )

    def _build_azure_network_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Azure: Network exposure → App Service / Compute / Database."""
        net_findings = [f for f in findings
                        if f["service"].lower() in ("network", "appservice", "compute", "database")
                        and f.get("status") == "FAIL"]
        if len(net_findings) < 2:
            return None

        nodes, edges, affected = [], [], []
        internet = GraphNode(id="az-internet", node_type=NodeType.INTERNET,
                             label="Internet", service="external")
        nodes.append(internet)

        net_layer = [f for f in net_findings if f["service"].lower() in ("network", "appservice")]
        data_layer = [f for f in net_findings if f["service"].lower() in ("compute", "database")]

        for f in net_layer[:3]:
            n = GraphNode(id=f"az-net-{_make_id()}", node_type=self._classify_node_type(f["service"]),
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(internet.id, n.id, EdgeType.EXPOSES, "publicly accessible"))
            affected.append(f.get("resource_id") or f["check_title"])

        for f in data_layer[:3]:
            n = GraphNode(id=f"az-data-{_make_id()}", node_type=self._classify_node_type(f["service"]),
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            for prev in nodes[1:]:
                if prev.node_type in (NodeType.NETWORK, NodeType.RESOURCE) and prev.id != n.id:
                    edges.append(GraphEdge(prev.id, n.id, EdgeType.ROUTES_TO, "reaches backend"))
                    break
            affected.append(f.get("resource_id") or f["check_title"])

        if len(nodes) < 3:
            return None

        return AttackPath(
            id=_make_id(),
            title="Azure Network Exposure to Backend Services",
            description="Misconfigured NSGs and publicly exposed App Services allow internet "
                        "traffic to reach compute instances and databases.",
            severity=self._max_severity([f["severity"] for f in net_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Internet",
            target="Backend Compute & Databases",
            category="exposure",
            techniques=["Initial Access: Exploit Public-Facing Application",
                         "Discovery: Cloud Service Dashboard"],
            affected_resources=affected,
            remediation=[
                "Restrict NSG inbound rules to required IPs and ports",
                "Disable public access on Azure SQL databases",
                "Use Azure Private Link for service connectivity",
                "Enable App Service access restrictions",
                "Deploy Azure WAF on public-facing endpoints",
            ],
        )

    def _build_monitoring_blindspot_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Azure/GCP/OCI: Missing monitoring and logging."""
        monitor_findings = [f for f in findings
                            if f["service"].lower() in ("monitor", "logging", "cloudguard",
                                                        "cloudtrail", "cloudwatch", "guardduty", "config")
                            and f.get("status") == "FAIL"]
        if not monitor_findings:
            return None

        nodes, edges, affected = [], [], []
        attacker = GraphNode(id="stealth-actor", node_type=NodeType.IDENTITY,
                             label="Threat Actor", service="external")
        nodes.append(attacker)

        for f in monitor_findings[:4]:
            n = GraphNode(id=f"monitor-{_make_id()}", node_type=NodeType.SERVICE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(attacker.id, n.id, EdgeType.LATERAL_MOVE,
                                   "undetected due to disabled monitoring"))
            affected.append(f.get("resource_id") or f["check_title"])

        target = GraphNode(id=f"unmonitored-env-{_make_id()}", node_type=NodeType.RESOURCE,
                           label="Unmonitored Environment", service="multi-service")
        nodes.append(target)
        for n in nodes[1:-1]:
            edges.append(GraphEdge(n.id, target.id, EdgeType.LATERAL_MOVE,
                                   "blind spot enables undetected access"))

        return AttackPath(
            id=_make_id(),
            title="Monitoring Blind Spots Enable Undetected Activity",
            description="Disabled or misconfigured monitoring and logging creates blind spots "
                        "where attacker activity goes undetected across the cloud environment.",
            severity=self._max_severity([f["severity"] for f in monitor_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Threat Actor",
            target="Unmonitored Environment",
            category="detection_evasion",
            techniques=["Defense Evasion: Impair Defenses",
                         "Defense Evasion: Disable Cloud Logs"],
            affected_resources=affected,
            remediation=[
                "Enable activity logging across all cloud services",
                "Configure security monitoring and alerting",
                "Enable cloud-native threat detection services",
                "Set up centralized log collection and SIEM integration",
            ],
        )

    def _build_gcp_exposure_path(self, findings, services, checks) -> Optional[AttackPath]:
        """GCP: IAM/Compute/Storage/SQL exposure chain."""
        gcp_findings = [f for f in findings
                        if f["service"].lower() in ("iam", "compute", "storage", "sql")
                        and f.get("status") == "FAIL"]
        if len(gcp_findings) < 2:
            return None

        nodes, edges, affected = [], [], []
        attacker = GraphNode(id="gcp-attacker", node_type=NodeType.IDENTITY,
                             label="Compromised GCP Identity", service="iam")
        nodes.append(attacker)

        prev_id = attacker.id
        for f in gcp_findings[:5]:
            n = GraphNode(id=f"gcp-{_make_id()}", node_type=self._classify_node_type(f["service"]),
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edge_type = EdgeType.HAS_ACCESS if n.node_type == NodeType.DATA_STORE else EdgeType.CAN_ESCALATE
            edges.append(GraphEdge(prev_id, n.id, edge_type, "exploits misconfiguration"))
            prev_id = n.id
            affected.append(f.get("resource_id") or f["check_title"])

        return AttackPath(
            id=_make_id(),
            title="GCP Identity to Data Exposure Chain",
            description="Misconfigured GCP IAM bindings and public resource access create a path "
                        "from compromised credentials to sensitive data in Cloud Storage and Cloud SQL.",
            severity=self._max_severity([f["severity"] for f in gcp_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Compromised GCP Identity",
            target="Sensitive Data Stores",
            category="exposure",
            techniques=["Initial Access: Valid Accounts (Cloud)",
                         "Collection: Data from Cloud Storage",
                         "Privilege Escalation: IAM Policy Misconfiguration"],
            affected_resources=affected,
            remediation=[
                "Remove public IAM bindings (allUsers/allAuthenticatedUsers)",
                "Enforce uniform bucket-level access on Cloud Storage",
                "Disable public IPs on Cloud SQL instances",
                "Enable OS Login on Compute Engine instances",
                "Implement VPC Service Controls for data exfiltration protection",
            ],
        )

    def _build_gcp_network_path(self, findings, services, checks) -> Optional[AttackPath]:
        """GCP: Firewall/networking → GKE/SQL exposure."""
        net_findings = [f for f in findings
                        if f["service"].lower() in ("networking", "compute", "gke", "sql")
                        and f.get("status") == "FAIL"]
        if len(net_findings) < 2:
            return None

        nodes, edges, affected = [], [], []
        internet = GraphNode(id="gcp-internet", node_type=NodeType.INTERNET,
                             label="Internet", service="external")
        nodes.append(internet)

        net_layer = [f for f in net_findings if f["service"].lower() in ("networking", "compute")]
        backend_layer = [f for f in net_findings if f["service"].lower() in ("gke", "sql")]

        for f in net_layer[:3]:
            n = GraphNode(id=f"gcp-net-{_make_id()}", node_type=self._classify_node_type(f["service"]),
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(internet.id, n.id, EdgeType.EXPOSES, "open firewall rule"))
            affected.append(f.get("resource_id") or f["check_title"])

        for f in backend_layer[:3]:
            n = GraphNode(id=f"gcp-back-{_make_id()}", node_type=self._classify_node_type(f["service"]),
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            for prev in nodes[1:]:
                if prev.node_type in (NodeType.NETWORK, NodeType.RESOURCE) and prev.id != n.id:
                    edges.append(GraphEdge(prev.id, n.id, EdgeType.ROUTES_TO, "reaches backend"))
                    break
            affected.append(f.get("resource_id") or f["check_title"])

        if len(nodes) < 3:
            return None

        return AttackPath(
            id=_make_id(),
            title="GCP Network Exposure to Backend Services",
            description="Open firewall rules and public compute instances expose GKE clusters "
                        "and Cloud SQL databases to internet-originating attacks.",
            severity=self._max_severity([f["severity"] for f in net_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Internet",
            target="GKE Clusters & Cloud SQL",
            category="exposure",
            techniques=["Initial Access: Exploit Public-Facing Application",
                         "Discovery: Cloud Infrastructure Discovery"],
            affected_resources=affected,
            remediation=[
                "Restrict firewall rules to specific source IP ranges",
                "Use private GKE clusters with authorized networks",
                "Disable public IP on Cloud SQL instances",
                "Enable GKE network policies for pod-level segmentation",
                "Remove external IPs from Compute Engine instances",
            ],
        )

    def _build_k8s_escalation_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Kubernetes: RBAC & Pod security → privilege escalation."""
        k8s_findings = [f for f in findings
                        if f["service"].lower() in ("pods", "rbac", "namespaces")
                        and f.get("status") == "FAIL"]
        if not k8s_findings:
            return None

        nodes, edges, affected = [], [], []
        attacker = GraphNode(id="k8s-attacker", node_type=NodeType.IDENTITY,
                             label="Compromised Pod / Service Account", service="pods")
        nodes.append(attacker)

        rbac_findings = [f for f in k8s_findings if f["service"].lower() == "rbac"]
        pod_findings = [f for f in k8s_findings if f["service"].lower() == "pods"]

        for f in pod_findings[:3]:
            n = GraphNode(id=f"k8s-pod-{_make_id()}", node_type=NodeType.RESOURCE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(attacker.id, n.id, EdgeType.CAN_ESCALATE,
                                   "exploits insecure pod config"))
            affected.append(f.get("resource_id") or f["check_title"])

        for f in rbac_findings[:2]:
            n = GraphNode(id=f"k8s-rbac-{_make_id()}", node_type=NodeType.IDENTITY,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            src = nodes[-2].id if len(nodes) > 2 else attacker.id
            edges.append(GraphEdge(src, n.id, EdgeType.CAN_ESCALATE,
                                   "RBAC wildcard escalation"))
            affected.append(f.get("resource_id") or f["check_title"])

        cluster_admin = GraphNode(id=f"k8s-admin-{_make_id()}", node_type=NodeType.IDENTITY,
                                  label="Cluster Admin Access", service="rbac",
                                  severity="critical")
        nodes.append(cluster_admin)
        edges.append(GraphEdge(nodes[-2].id, cluster_admin.id, EdgeType.CAN_ESCALATE,
                               "gains cluster-admin"))

        return AttackPath(
            id=_make_id(),
            title="Kubernetes Privilege Escalation Chain",
            description="Privileged pods and overly permissive RBAC roles create a path from "
                        "a compromised container to cluster-admin privileges.",
            severity=self._max_severity([f["severity"] for f in k8s_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Compromised Pod",
            target="Cluster Admin Access",
            category="privilege_escalation",
            techniques=["Privilege Escalation: Privileged Container",
                         "Privilege Escalation: Cluster-Admin Binding",
                         "Execution: Container Escape"],
            affected_resources=affected,
            remediation=[
                "Disable privileged mode on all pods",
                "Enforce runAsNonRoot in pod security standards",
                "Remove wildcard RBAC permissions from cluster roles",
                "Set read-only root filesystem on containers",
                "Enforce resource limits on all pods",
            ],
        )

    def _build_k8s_lateral_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Kubernetes: Missing network policies → lateral movement."""
        k8s_findings = [f for f in findings
                        if f["service"].lower() in ("pods", "network", "namespaces")
                        and f.get("status") == "FAIL"]
        if not k8s_findings:
            return None

        nodes, edges, affected = [], [], []
        compromised = GraphNode(id="k8s-compromised", node_type=NodeType.RESOURCE,
                                label="Compromised Container", service="pods")
        nodes.append(compromised)

        for f in k8s_findings[:4]:
            n = GraphNode(id=f"k8s-lat-{_make_id()}", node_type=self._classify_node_type(f["service"]),
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(compromised.id, n.id, EdgeType.LATERAL_MOVE,
                                   "no network policy restriction"))
            affected.append(f.get("resource_id") or f["check_title"])

        target = GraphNode(id=f"k8s-sensitive-{_make_id()}", node_type=NodeType.DATA_STORE,
                           label="Sensitive Workloads & Secrets", service="namespaces")
        nodes.append(target)
        for n in nodes[1:-1]:
            edges.append(GraphEdge(n.id, target.id, EdgeType.LATERAL_MOVE,
                                   "unrestricted lateral access"))

        return AttackPath(
            id=_make_id(),
            title="Kubernetes Lateral Movement via Missing Network Policies",
            description="Absent network policies and pods in the default namespace allow "
                        "unrestricted lateral movement between workloads.",
            severity=self._max_severity([f["severity"] for f in k8s_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Compromised Container",
            target="Sensitive Workloads",
            category="lateral_movement",
            techniques=["Lateral Movement: Container-to-Container",
                         "Discovery: Kubernetes API Enumeration"],
            affected_resources=affected,
            remediation=[
                "Apply network policies to all namespaces",
                "Move workloads out of the default namespace",
                "Implement pod-to-pod encryption with service mesh",
                "Use namespace-level resource quotas and limits",
            ],
        )

    def _build_oci_exposure_path(self, findings, services, checks) -> Optional[AttackPath]:
        """OCI: IAM/Networking/Storage exposure chain."""
        oci_findings = [f for f in findings
                        if f["service"].lower() in ("iam", "objectstorage", "networking",
                                                     "storage", "vault", "loadbalancer")
                        and f.get("status") == "FAIL"]
        if len(oci_findings) < 2:
            return None

        nodes, edges, affected = [], [], []
        attacker = GraphNode(id="oci-attacker", node_type=NodeType.IDENTITY,
                             label="Compromised OCI Identity", service="IAM")
        nodes.append(attacker)

        prev_id = attacker.id
        for f in oci_findings[:5]:
            n = GraphNode(id=f"oci-{_make_id()}", node_type=self._classify_node_type(f["service"]),
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edge_type = EdgeType.HAS_ACCESS if n.node_type == NodeType.DATA_STORE else EdgeType.CAN_ESCALATE
            edges.append(GraphEdge(prev_id, n.id, edge_type, "exploits misconfiguration"))
            prev_id = n.id
            affected.append(f.get("resource_id") or f["check_title"])

        return AttackPath(
            id=_make_id(),
            title="OCI Identity to Resource Exposure Chain",
            description="Misconfigured OCI IAM policies and unrestricted network security groups "
                        "create a path from compromised credentials to object storage and vault secrets.",
            severity=self._max_severity([f["severity"] for f in oci_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Compromised OCI Identity",
            target="Object Storage & Vault",
            category="exposure",
            techniques=["Initial Access: Valid Accounts (Cloud)",
                         "Collection: Data from Cloud Storage",
                         "Credential Access: Unsecured Vault Credentials"],
            affected_resources=affected,
            remediation=[
                "Enforce MFA for all OCI users",
                "Remove wildcard IAM policies",
                "Enable API key rotation for IAM users",
                "Block public access on Object Storage buckets",
                "Restrict VCN security list ingress to required ports",
                "Enable Vault key rotation",
            ],
        )

    def _build_oci_compute_data_path(self, findings, services, checks) -> Optional[AttackPath]:
        """OCI: Compute/Database/Container exposure chain."""
        oci_findings = [f for f in findings
                        if f["service"].lower() in ("compute", "database", "mysql",
                                                     "kubernetesengine", "functions",
                                                     "containerinstances", "filestorage")
                        and f.get("status") == "FAIL"]
        if len(oci_findings) < 2:
            return None

        nodes, edges, affected = [], [], []
        internet = GraphNode(id="oci-internet", node_type=NodeType.INTERNET,
                             label="Internet", service="external")
        nodes.append(internet)

        compute_layer = [f for f in oci_findings
                         if f["service"].lower() in ("compute", "kubernetesengine",
                                                      "functions", "containerinstances")]
        data_layer = [f for f in oci_findings
                      if f["service"].lower() in ("database", "mysql", "filestorage")]

        for f in compute_layer[:3]:
            n = GraphNode(id=f"oci-comp-{_make_id()}", node_type=self._classify_node_type(f["service"]),
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(internet.id, n.id, EdgeType.EXPOSES,
                                   "publicly exposed compute"))
            affected.append(f.get("resource_id") or f["check_title"])

        for f in data_layer[:3]:
            n = GraphNode(id=f"oci-data-{_make_id()}", node_type=self._classify_node_type(f["service"]),
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            for prev in nodes[1:]:
                if prev.node_type == NodeType.RESOURCE and prev.id != n.id:
                    edges.append(GraphEdge(prev.id, n.id, EdgeType.HAS_ACCESS,
                                           "accesses database"))
                    break
            affected.append(f.get("resource_id") or f["check_title"])

        if len(nodes) < 3:
            return None

        return AttackPath(
            id=_make_id(),
            title="OCI Compute to Database Exposure",
            description="Misconfigured OCI compute instances, OKE clusters, or serverless functions "
                        "expose a path to reach databases and file storage services.",
            severity=self._max_severity([f["severity"] for f in oci_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Internet",
            target="OCI Databases & File Storage",
            category="data_exfiltration",
            techniques=["Initial Access: Exploit Public-Facing Application",
                         "Collection: Data from Cloud Database"],
            affected_resources=affected,
            remediation=[
                "Enable secure boot and IMDSv2 on compute instances",
                "Use private endpoints for OKE clusters",
                "Assign NSGs to Functions applications",
                "Enable backup and deletion protection on MySQL databases",
                "Enable CMK encryption on databases and file storage",
                "Use private endpoints for Autonomous Databases",
            ],
        )

    def _score_paths(self) -> None:
        """Assign risk scores to discovered attack paths."""
        severity_weights = {
            "critical": 40, "high": 30, "medium": 20, "low": 10, "informational": 5
        }
        category_weights = {
            "privilege_escalation": 1.3,
            "data_exfiltration": 1.2,
            "lateral_movement": 1.1,
            "exposure": 1.0,
            "detection_evasion": 0.9,
        }

        for path in self.paths:
            # Base score from severity
            base = severity_weights.get(path.severity, 10)
            # Multiply by number of steps (longer paths = more complex but higher impact)
            step_factor = min(len(path.nodes) / 3, 2.0)
            # Category weight
            cat_weight = category_weights.get(path.category, 1.0)
            # Affected resources factor
            resource_factor = min(len(path.affected_resources) / 2, 2.0)

            score = base * step_factor * cat_weight * resource_factor
            path.risk_score = round(min(score, 100), 1)

    @staticmethod
    def _max_severity(severities: list[str]) -> str:
        order = ["critical", "high", "medium", "low", "informational"]
        for s in order:
            if s in severities:
                return s
        return "medium"
