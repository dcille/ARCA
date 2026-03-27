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
    # BAS 2.0 fields (optional, backward compatible)
    blast_radius: Optional[dict] = None
    detection_coverage: Optional[dict] = None
    confidence: str = "template"   # template | theoretical | confirmed
    source: str = "scenario"       # scenario | iam_discovery | combined


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
    # ── Data Exfiltration: Public Data Store Access ────────────────
    {
        "match_services": {"s3", "storage", "bigquery", "rds", "sql", "dynamodb",
                           "objectstorage", "database", "gcs", "cloudsql"},
        "match_checks": ["public", "no_public", "bucket_public", "dataset_no_public",
                          "blob_public", "objectstorage_public"],
        "category": "data_exfiltration",
        "builder": "_build_data_public_exposure_path",
    },
    # ── Data Security: Unencrypted Data Stores ─────────────────────
    {
        "match_services": {"s3", "rds", "dynamodb", "storage", "sql", "bigquery",
                           "efs", "elasticache", "objectstorage", "database",
                           "gcs", "cloudsql", "kms", "keyvault", "dataproc"},
        "match_checks": ["encrypt", "cmek", "cmk", "tde", "kms", "ssl_required"],
        "category": "data_exfiltration",
        "builder": "_build_data_encryption_weakness_path",
    },
    # ── Data Security: Missing Data Access Logging ─────────────────
    {
        "match_services": {"s3", "rds", "storage", "sql", "bigquery", "database",
                           "objectstorage", "keyvault", "cloudsql", "gcs"},
        "match_checks": ["logging", "audit", "access_log"],
        "category": "detection_evasion",
        "builder": "_build_data_logging_gap_path",
    },
    # ── Alibaba Cloud scenarios ──────────────────────────────────
    {
        "id": "alibaba_ram_escalation",
        "title": "Alibaba RAM Privilege Escalation",
        "description": "Compromised RAM user with weak MFA and wildcard policies escalates to administrator access across all Alibaba Cloud services.",
        "category": "privilege_escalation",
        "severity": "critical",
        "match_services": {"ram"},
        "match_checks": ["ali_ram_no_wildcard_policy", "ali_ram_mfa_enabled", "ali_ram_access_key_rotation", "ali_ram_unused_users", "ali_ram_policies_groups_only"],
        "min_matches": 2,
        "techniques": ["T1078.004", "T1098", "T1548"],
        "builder": "_build_alibaba_ram_escalation_path",
    },
    {
        "id": "alibaba_ecs_oss_exposure",
        "title": "Alibaba ECS/OSS Public Data Exposure",
        "description": "Internet-facing ECS instance with open security groups provides pivot to publicly accessible unencrypted OSS buckets, enabling mass data exfiltration.",
        "category": "data_exfiltration",
        "severity": "critical",
        "match_services": {"ecs", "oss"},
        "match_checks": ["ali_ecs_no_public_ip", "ali_ecs_sg_no_public_ingress", "ali_oss_no_public_access", "ali_oss_encryption_enabled"],
        "min_matches": 2,
        "techniques": ["T1190", "T1530", "T1537"],
        "builder": "_build_alibaba_ecs_oss_exposure_path",
    },
    {
        "id": "alibaba_network_chain",
        "title": "Alibaba Network/SLB to Database Chain",
        "description": "HTTP listener on SLB combined with open SSH on ECS, missing VPC flow logs, and publicly accessible RDS creates a network-based attack chain to sensitive databases.",
        "category": "exposure",
        "severity": "high",
        "match_services": {"vpc", "ecs", "slb", "rds"},
        "match_checks": ["ali_vpc_flow_logs", "ali_ecs_sg_no_ssh_open", "ali_slb_https_listener", "ali_rds_no_public_access"],
        "min_matches": 2,
        "techniques": ["T1190", "T1021.004", "T1046"],
        "builder": "_build_alibaba_network_chain_path",
    },
    {
        "id": "alibaba_monitoring_blindspot",
        "title": "Alibaba Monitoring Blindspot",
        "description": "Disabled ActionTrail, missing SLS alerts, and absent Security Center agents create a monitoring dead zone where attacker activity goes undetected.",
        "category": "detection_evasion",
        "severity": "high",
        "match_services": {"actiontrail", "sls", "security_center"},
        "match_checks": ["ali_actiontrail_enabled", "ali_actiontrail_multi_region", "ali_sls_retention_365", "ali_security_center_enabled", "ali_sas_agents_installed"],
        "min_matches": 2,
        "techniques": ["T1562.008", "T1070", "T1562.001"],
        "builder": "_build_alibaba_monitoring_blindspot_path",
    },
    # ── Cross-SaaS-to-Cloud scenarios ────────────────────────────
    {
        "id": "github_secrets_to_cloud",
        "title": "GitHub Secrets Exposure to Cloud Access",
        "description": "Repositories without secret scanning leak cloud credentials. Combined with unrotated access keys, attackers gain persistent cloud infrastructure access via committed secrets.",
        "category": "credential_access",
        "severity": "critical",
        "match_services": {"github", "iam", "ram", "azure_iam"},
        "match_checks": ["github_repo_secret_scanning", "iam_access_key_rotation", "ali_ram_access_key_rotation", "azure_iam_custom_role_admin"],
        "min_matches": 2,
        "techniques": ["T1552", "T1552.001", "T1078.004"],
        "builder": "_build_github_secrets_cloud_path",
    },
    {
        "id": "m365_identity_to_azure",
        "title": "M365 Identity Compromise to Azure Resources",
        "description": "Legacy authentication and weak MFA in Microsoft 365 allow credential phishing that pivots to Azure subscription resources via shared Azure AD identity.",
        "category": "privilege_escalation",
        "severity": "critical",
        "match_services": {"m365", "azure_iam", "azure_security"},
        "match_checks": ["m365_ca_block_legacy_auth", "m365_admin_mfa_enforced", "azure_iam_owner_count"],
        "min_matches": 2,
        "techniques": ["T1566", "T1078.004", "T1484"],
        "builder": "_build_m365_identity_azure_path",
    },
    {
        "id": "saas_credential_theft_to_cloud",
        "title": "SaaS Platform Credential Theft to Cloud",
        "description": "Compromised SaaS platform (ServiceNow/Salesforce) without encryption at rest exposes stored cloud credentials in custom fields, providing unauthorized cloud infrastructure access.",
        "category": "credential_access",
        "severity": "high",
        "match_services": {"servicenow", "salesforce", "iam", "azure_iam"},
        "match_checks": ["servicenow_encryption_at_rest", "servicenow_ac_acl_active", "salesforce_encryption_at_rest", "iam_access_key_rotation"],
        "min_matches": 2,
        "techniques": ["T1552", "T1078.004", "T1213"],
        "builder": "_build_saas_credential_cloud_path",
    },
    # ── Advanced scenarios ────────────────────────────────────────
    {
        "id": "supply_chain_container_registry",
        "title": "Supply Chain via Container Registry",
        "description": "Container registries without image scanning allow malicious or vulnerable images to deploy into production clusters, achieving code execution with task role permissions.",
        "category": "supply_chain",
        "severity": "critical",
        "match_services": {"ecr", "ecs", "eks", "gke", "oke", "ack", "containerregistry"},
        "match_checks": ["ecr_image_scanning_enabled", "ecr_lifecycle_policy_configured", "gcp_gke_binary_authorization", "k8s_image_pull_policy_always"],
        "min_matches": 1,
        "techniques": ["T1525", "T1195", "T1610"],
        "builder": "_build_supply_chain_container_path",
    },
    {
        "id": "ransomware_kill_chain",
        "title": "Ransomware Kill Chain",
        "description": "Complete ransomware attack chain: internet-facing RDP/SSH without MFA enables initial access, followed by logging disablement, backup destruction, and data encryption for impact.",
        "category": "ransomware",
        "severity": "critical",
        "match_services": {"iam", "ec2", "vpc", "s3", "cloudtrail", "backup", "rds", "ebs"},
        "match_checks": ["ec2_sg_open_port_22", "ec2_sg_open_port_3389", "iam_user_mfa_enabled", "cloudtrail_multiregion", "s3_bucket_versioning_enabled", "s3_bucket_object_lock", "rds_automated_backups_enabled"],
        "min_matches": 3,
        "techniques": ["T1190", "T1110", "T1078", "T1562.008", "T1490", "T1486", "T1485"],
        "builder": "_build_ransomware_kill_chain_path",
    },
    {
        "id": "insider_data_exfiltration_saas",
        "title": "Insider Data Exfiltration via SaaS Channels",
        "description": "Malicious insider leverages unmasked data in Snowflake, unrestricted Salesforce exports, and M365 external sharing without DLP to exfiltrate sensitive data through SaaS channels.",
        "category": "data_exfiltration",
        "severity": "high",
        "match_services": {"m365", "salesforce", "snowflake"},
        "match_checks": ["m365_external_sharing_restricted", "m365_dlp_policies_configured", "salesforce_field_level_security", "snowflake_column_masking_policies"],
        "min_matches": 2,
        "techniques": ["T1530", "T1567", "T1537"],
        "builder": "_build_insider_exfiltration_saas_path",
    },
    {
        "id": "multi_cloud_lateral_movement",
        "title": "Multi-Cloud Lateral Movement",
        "description": "IAM misconfigurations across multiple cloud providers allow attackers to pivot from the weakest environment to all connected cloud accounts via cross-cloud service accounts and federation.",
        "category": "lateral_movement",
        "severity": "critical",
        "match_services": {"iam", "azure_iam", "gcp_iam", "ram"},
        "match_checks": ["iam_user_mfa_enabled", "azure_iam_owner_count", "gcp_iam_no_public_access", "ali_ram_mfa_enabled"],
        "min_matches": 3,
        "techniques": ["T1078.004", "T1021", "T1563", "T1550"],
        "builder": "_build_multi_cloud_lateral_path",
    },
]


class AttackPathAnalyzer:
    """Analyzes findings to discover attack paths."""

    def __init__(self, findings: list[dict], all_findings: Optional[list[dict]] = None,
                 cloud_credentials: Optional[dict] = None):
        """
        Args:
            findings: FAIL findings used to build attack paths (backward compatible).
            all_findings: ALL findings (PASS + FAIL) for detection coverage analysis.
                         If None, only findings (FAIL) are used.
            cloud_credentials: Cloud credentials for IAM graph building (Phase 2+).
                              If None, IAM analysis is skipped.
        """
        self.findings = findings
        self.all_findings = all_findings or findings
        self.cloud_credentials = cloud_credentials
        self.graph = AttackPathGraph()
        self.paths: list[AttackPath] = []

    def analyze(self) -> list[AttackPath]:
        """Run full analysis pipeline."""
        # ── EXISTING: Template-based discovery (unchanged) ──
        self._build_graph()
        self._detect_paths()
        self._score_paths()

        # ── BAS 2.0: Enrichment with blast radius + detection coverage ──
        # These work from existing data, no cloud API calls needed.
        self._calculate_blast_radius()
        self._evaluate_detection_coverage()

        # Re-score with enrichment data
        self._enhanced_score_paths()

        return sorted(self.paths, key=lambda p: p.risk_score, reverse=True)

    def _calculate_blast_radius(self) -> None:
        """Calculate blast radius for each discovered path."""
        try:
            from .blast_radius import BlastRadiusCalculator
            calculator = BlastRadiusCalculator()
            for path in self.paths:
                br = calculator.calculate(path, self.graph)
                path.blast_radius = br.to_dict()
        except Exception:
            pass  # Don't fail the whole pipeline if blast radius fails

    def _evaluate_detection_coverage(self) -> None:
        """Evaluate detection coverage for each discovered path."""
        try:
            from .detection import DetectionCoverageAnalyzer
            analyzer = DetectionCoverageAnalyzer(self.all_findings)
            for path in self.paths:
                report = analyzer.analyze_path(path)
                path.detection_coverage = {
                    "coverage_pct": report.coverage_pct,
                    "detected_steps": report.detected_steps,
                    "undetected_steps": report.undetected_steps,
                    "total_steps": report.total_steps,
                    "verdict": report.verdict,
                    "blind_spot_summary": report.blind_spot_summary,
                }
        except Exception:
            pass  # Don't fail the whole pipeline if detection analysis fails

    def _enhanced_score_paths(self) -> None:
        """Re-score paths using BAS 2.0 enrichment data (blast radius + detection gaps)."""
        from .scoring import score_path as enhanced_score
        from .models import CATEGORY_WEIGHTS, SEVERITY_WEIGHTS

        for path in self.paths:
            path_dict = {
                'severity': path.severity,
                'category': path.category,
                'nodes': [{'id': n.id} for n in path.nodes],
                'edges': [{'source_id': e.source_id, 'target_id': e.target_id} for e in path.edges],
                'techniques': path.techniques,
                'affected_resources': path.affected_resources,
                'entry_point': path.entry_point,
            }
            result = enhanced_score(
                path_dict,
                blast_radius=path.blast_radius,
                detection_coverage=path.detection_coverage,
            )
            path.risk_score = result['risk_score']

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

    def _build_data_public_exposure_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Public data stores → data exfiltration path (DSPM-specific)."""
        data_services = {"s3", "storage", "bigquery", "rds", "sql", "dynamodb",
                         "objectstorage", "database", "gcs", "cloudsql",
                         "azure_blob", "azure_sql", "cosmosdb"}
        data_findings = [f for f in findings
                         if f["service"].lower() in data_services
                         and any(k in f["check_id"].lower() for k in ["public", "no_public"])
                         and f.get("status") == "FAIL"]
        if not data_findings:
            return None

        nodes, edges, affected = [], [], []
        internet = GraphNode(id="data-internet", node_type=NodeType.INTERNET,
                             label="Internet / Anonymous User", service="external")
        nodes.append(internet)

        for f in data_findings[:5]:
            n = GraphNode(id=f"pub-data-{_make_id()}", node_type=NodeType.DATA_STORE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(internet.id, n.id, EdgeType.EXPOSES,
                                   "publicly accessible data store"))
            affected.append(f.get("resource_id") or f["check_title"])

        exfil = GraphNode(id=f"exfil-{_make_id()}", node_type=NodeType.SERVICE,
                          label="Data Exfiltration", service="external",
                          severity="critical")
        nodes.append(exfil)
        for n in nodes[1:-1]:
            edges.append(GraphEdge(n.id, exfil.id, EdgeType.HAS_ACCESS,
                                   "data can be downloaded"))

        return AttackPath(
            id=_make_id(),
            title="Publicly Exposed Data Stores",
            description="Data stores with public access enabled allow anyone on the internet "
                        "to access potentially sensitive data without authentication. This is "
                        "a critical data security risk that could lead to data breaches.",
            severity=self._max_severity([f["severity"] for f in data_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Internet / Anonymous User",
            target="Sensitive Data Stores",
            category="data_exfiltration",
            techniques=["Collection: Data from Cloud Storage Object",
                         "Exfiltration: Transfer Data to Cloud Account",
                         "Initial Access: Exploit Public-Facing Application"],
            affected_resources=affected,
            remediation=[
                "Disable public access on all data storage services",
                "Implement bucket/container-level access policies",
                "Use private endpoints for database access",
                "Enable Cloud DLP/Macie/Purview for sensitive data discovery",
                "Apply data classification tags to all data stores",
            ],
        )

    def _build_data_encryption_weakness_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Unencrypted data stores → data exposure path (DSPM-specific)."""
        data_services = {"s3", "rds", "dynamodb", "storage", "sql", "bigquery",
                         "efs", "elasticache", "objectstorage", "database",
                         "gcs", "cloudsql", "kms", "keyvault", "dataproc",
                         "azure_blob", "azure_sql", "cosmosdb"}
        enc_findings = [f for f in findings
                        if f["service"].lower() in data_services
                        and any(k in f["check_id"].lower() for k in ["encrypt", "cmek", "cmk", "tde", "kms", "ssl"])
                        and f.get("status") == "FAIL"]
        if not enc_findings:
            return None

        nodes, edges, affected = [], [], []
        insider = GraphNode(id="data-insider", node_type=NodeType.IDENTITY,
                            label="Insider / Compromised Credential", service="IAM")
        nodes.append(insider)

        for f in enc_findings[:5]:
            n = GraphNode(id=f"unenc-data-{_make_id()}", node_type=NodeType.DATA_STORE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(insider.id, n.id, EdgeType.HAS_ACCESS,
                                   "reads unencrypted/weakly encrypted data"))
            affected.append(f.get("resource_id") or f["check_title"])

        exfil = GraphNode(id=f"data-theft-{_make_id()}", node_type=NodeType.SERVICE,
                          label="Plaintext Data Exposure", service="external",
                          severity="critical")
        nodes.append(exfil)
        for n in nodes[1:-1]:
            edges.append(GraphEdge(n.id, exfil.id, EdgeType.STORES_DATA,
                                   "data accessible in plaintext"))

        return AttackPath(
            id=_make_id(),
            title="Data Encryption Gaps Enable Data Theft",
            description="Data stores lacking proper encryption (at rest or in transit) allow "
                        "an attacker with access to read sensitive data in plaintext. Missing "
                        "customer-managed keys (CMEK) reduce control over data protection.",
            severity=self._max_severity([f["severity"] for f in enc_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Insider / Compromised Credential",
            target="Unencrypted Data",
            category="data_exfiltration",
            techniques=["Collection: Data from Cloud Storage Object",
                         "Collection: Data from Information Repositories",
                         "Credential Access: Unsecured Credentials"],
            affected_resources=affected,
            remediation=[
                "Enable encryption at rest on all data stores with CMEK",
                "Enforce TLS/SSL for all database connections",
                "Implement KMS key rotation policies",
                "Use customer-managed keys for sensitive data",
                "Enable encryption in transit for cache and messaging services",
            ],
        )

    def _build_data_logging_gap_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Missing data access logging → undetected data access (DSPM-specific)."""
        data_services = {"s3", "rds", "storage", "sql", "bigquery", "database",
                         "objectstorage", "keyvault", "cloudsql", "gcs",
                         "azure_blob", "azure_sql"}
        log_findings = [f for f in findings
                        if f["service"].lower() in data_services
                        and any(k in f["check_id"].lower() for k in ["logging", "audit", "access_log"])
                        and f.get("status") == "FAIL"]
        if not log_findings:
            return None

        nodes, edges, affected = [], [], []
        attacker = GraphNode(id="data-stealth", node_type=NodeType.IDENTITY,
                             label="Threat Actor", service="external")
        nodes.append(attacker)

        for f in log_findings[:4]:
            n = GraphNode(id=f"unlogged-{_make_id()}", node_type=NodeType.DATA_STORE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(attacker.id, n.id, EdgeType.HAS_ACCESS,
                                   "accesses data store without audit trail"))
            affected.append(f.get("resource_id") or f["check_title"])

        target = GraphNode(id=f"unaudited-{_make_id()}", node_type=NodeType.SERVICE,
                           label="Undetected Data Access", service="audit",
                           severity="high")
        nodes.append(target)
        for n in nodes[1:-1]:
            edges.append(GraphEdge(n.id, target.id, EdgeType.LATERAL_MOVE,
                                   "no audit trail for data access"))

        return AttackPath(
            id=_make_id(),
            title="Data Access Without Audit Logging",
            description="Data stores without access logging enabled allow attackers to access "
                        "and exfiltrate data without leaving an audit trail, making incident "
                        "response and forensics impossible.",
            severity=self._max_severity([f["severity"] for f in log_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Threat Actor",
            target="Undetected Data Access",
            category="detection_evasion",
            techniques=["Defense Evasion: Impair Defenses - Disable Cloud Logs",
                         "Collection: Data from Cloud Storage",
                         "Exfiltration: Automated Exfiltration"],
            affected_resources=affected,
            remediation=[
                "Enable access logging on all S3 buckets and storage accounts",
                "Enable database audit logging for all SQL instances",
                "Enable BigQuery audit logging via Data Access audit logs",
                "Configure Key Vault diagnostic logging",
                "Set up alerts for unusual data access patterns",
            ],
        )

    def _build_alibaba_ram_escalation_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Alibaba RAM: Compromised user → weak MFA → wildcard policy → admin access."""
        ram_findings = [f for f in findings
                        if any(k in f["check_id"] for k in ["ali_ram_no_wildcard", "ali_ram_mfa",
                                                             "ali_ram_access_key", "ali_ram_unused",
                                                             "ali_ram_policies_groups"])
                        and f.get("status") == "FAIL"]
        if not ram_findings:
            return None

        nodes, edges, affected = [], [], []
        attacker = GraphNode(id="ali-ram-attacker", node_type=NodeType.IDENTITY,
                             label="Compromised RAM User", service="ram")
        nodes.append(attacker)

        mfa_findings = [f for f in ram_findings if "mfa" in f["check_id"].lower()]
        policy_findings = [f for f in ram_findings if "wildcard" in f["check_id"].lower()
                           or "policies" in f["check_id"].lower()]
        key_findings = [f for f in ram_findings if "access_key" in f["check_id"].lower()
                        or "unused" in f["check_id"].lower()]

        for f in (mfa_findings + key_findings)[:2]:
            n = GraphNode(id=f"ali-mfa-{_make_id()}", node_type=NodeType.IDENTITY,
                          label=f.get("resource_name") or f["check_title"],
                          service="ram", severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(attacker.id if len(nodes) == 2 else nodes[-2].id,
                                   n.id, EdgeType.CAN_ESCALATE, "bypasses weak MFA"))
            affected.append(f.get("resource_id") or f["check_title"])

        for f in policy_findings[:2]:
            n = GraphNode(id=f"ali-policy-{_make_id()}", node_type=NodeType.IDENTITY,
                          label=f.get("resource_name") or f["check_title"],
                          service="ram", severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(nodes[-2].id, n.id, EdgeType.CAN_ESCALATE,
                                   "exploits wildcard policy"))
            affected.append(f.get("resource_id") or f["check_title"])

        admin_node = GraphNode(id=f"ali-admin-{_make_id()}", node_type=NodeType.IDENTITY,
                               label="Administrator Access", service="ram", severity="critical")
        nodes.append(admin_node)
        edges.append(GraphEdge(nodes[-2].id, admin_node.id, EdgeType.CAN_ESCALATE,
                               "gains administrator access"))

        return AttackPath(
            id=_make_id(),
            title="Alibaba RAM Privilege Escalation",
            description="Compromised RAM user with weak MFA and wildcard policies escalates to "
                        "administrator access across all Alibaba Cloud services.",
            severity=self._max_severity([f["severity"] for f in ram_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Compromised RAM User",
            target="Administrator Access",
            category="privilege_escalation",
            techniques=["T1078.004", "T1098", "T1548"],
            affected_resources=affected,
            remediation=[
                "Enable MFA for all RAM users",
                "Remove wildcard (*) actions from RAM policies",
                "Rotate RAM access keys every 90 days",
                "Remove unused RAM users and access keys",
                "Attach policies to groups instead of individual users",
            ],
        )

    def _build_alibaba_ecs_oss_exposure_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Alibaba ECS/OSS: Internet → public ECS → open SG → public OSS → data."""
        ecs_findings = [f for f in findings
                        if any(k in f["check_id"] for k in ["ali_ecs_no_public", "ali_ecs_sg"])
                        and f.get("status") == "FAIL"]
        oss_findings = [f for f in findings
                        if any(k in f["check_id"] for k in ["ali_oss_no_public", "ali_oss_encryption"])
                        and f.get("status") == "FAIL"]
        if not ecs_findings and not oss_findings:
            return None

        nodes, edges, affected = [], [], []
        internet = GraphNode(id="ali-internet", node_type=NodeType.INTERNET,
                             label="Internet", service="external")
        nodes.append(internet)

        for f in ecs_findings[:2]:
            n = GraphNode(id=f"ali-ecs-{_make_id()}", node_type=NodeType.RESOURCE,
                          label=f.get("resource_name") or f["check_title"],
                          service="ecs", severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(internet.id, n.id, EdgeType.EXPOSES,
                                   "publicly accessible ECS instance"))
            affected.append(f.get("resource_id") or f["check_title"])

        for f in oss_findings[:2]:
            n = GraphNode(id=f"ali-oss-{_make_id()}", node_type=NodeType.DATA_STORE,
                          label=f.get("resource_name") or f["check_title"],
                          service="oss", severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            src = nodes[-2].id if len(nodes) > 2 else internet.id
            edges.append(GraphEdge(src, n.id, EdgeType.HAS_ACCESS,
                                   "pivots to public OSS bucket"))
            affected.append(f.get("resource_id") or f["check_title"])

        data_node = GraphNode(id=f"ali-data-{_make_id()}", node_type=NodeType.DATA_STORE,
                              label="Exfiltrated Data", service="oss", severity="critical")
        nodes.append(data_node)
        edges.append(GraphEdge(nodes[-2].id, data_node.id, EdgeType.HAS_ACCESS,
                               "mass data exfiltration"))

        return AttackPath(
            id=_make_id(),
            title="Alibaba ECS/OSS Public Data Exposure",
            description="Internet-facing ECS instance with open security groups provides pivot to "
                        "publicly accessible unencrypted OSS buckets, enabling mass data exfiltration.",
            severity=self._max_severity([f["severity"] for f in ecs_findings + oss_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Internet",
            target="OSS Data",
            category="data_exfiltration",
            techniques=["T1190", "T1530", "T1537"],
            affected_resources=affected,
            remediation=[
                "Remove public IP addresses from ECS instances",
                "Restrict security group inbound rules to known IPs",
                "Disable public access on OSS buckets",
                "Enable server-side encryption on all OSS buckets",
                "Use VPC endpoints for OSS access",
            ],
        )

    def _build_alibaba_network_chain_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Alibaba Network: Internet via SLB → HTTP → ECS SSH → VPC → public RDS."""
        net_findings = [f for f in findings
                        if any(k in f["check_id"] for k in ["ali_vpc_flow", "ali_ecs_sg_no_ssh",
                                                             "ali_slb_https", "ali_rds_no_public"])
                        and f.get("status") == "FAIL"]
        if not net_findings:
            return None

        nodes, edges, affected = [], [], []
        internet = GraphNode(id="ali-net-internet", node_type=NodeType.INTERNET,
                             label="Internet", service="external")
        nodes.append(internet)

        slb_findings = [f for f in net_findings if "slb" in f["check_id"].lower()]
        ecs_findings = [f for f in net_findings if "ecs" in f["check_id"].lower()]
        vpc_findings = [f for f in net_findings if "vpc" in f["check_id"].lower()]
        rds_findings = [f for f in net_findings if "rds" in f["check_id"].lower()]

        prev_id = internet.id
        for layer, prefix, svc, etype, lbl in [
            (slb_findings, "ali-slb", "slb", EdgeType.ROUTES_TO, "HTTP listener on SLB"),
            (ecs_findings, "ali-ssh", "ecs", EdgeType.EXPOSES, "open SSH on ECS"),
            (vpc_findings, "ali-vpc", "vpc", EdgeType.LATERAL_MOVE, "no VPC flow logs"),
            (rds_findings, "ali-rds", "rds", EdgeType.HAS_ACCESS, "publicly accessible RDS"),
        ]:
            for f in layer[:1]:
                n = GraphNode(id=f"{prefix}-{_make_id()}", node_type=self._classify_node_type(svc),
                              label=f.get("resource_name") or f["check_title"],
                              service=svc, severity=f["severity"],
                              metadata={"finding_id": f["id"], "check_id": f["check_id"]})
                nodes.append(n)
                edges.append(GraphEdge(prev_id, n.id, etype, lbl))
                prev_id = n.id
                affected.append(f.get("resource_id") or f["check_title"])

        if len(nodes) < 3:
            return None

        return AttackPath(
            id=_make_id(),
            title="Alibaba Network/SLB to Database Chain",
            description="HTTP listener on SLB combined with open SSH on ECS, missing VPC flow logs, "
                        "and publicly accessible RDS creates a network-based attack chain.",
            severity=self._max_severity([f["severity"] for f in net_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Internet via SLB",
            target="Public RDS Database",
            category="exposure",
            techniques=["T1190", "T1021.004", "T1046"],
            affected_resources=affected,
            remediation=[
                "Configure HTTPS listeners on SLB instead of HTTP",
                "Restrict SSH access in ECS security groups to bastion hosts",
                "Enable VPC flow logs for network monitoring",
                "Disable public access on RDS instances",
                "Use internal SLB for backend service communication",
            ],
        )

    def _build_alibaba_monitoring_blindspot_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Alibaba Monitoring: Threat Actor → disabled ActionTrail → no SLS → no Security Center."""
        monitor_findings = [f for f in findings
                            if any(k in f["check_id"] for k in ["ali_actiontrail", "ali_sls",
                                                                  "ali_security_center", "ali_sas"])
                            and f.get("status") == "FAIL"]
        if not monitor_findings:
            return None

        nodes, edges, affected = [], [], []
        attacker = GraphNode(id="ali-threat-actor", node_type=NodeType.IDENTITY,
                             label="Threat Actor", service="external")
        nodes.append(attacker)

        for f in monitor_findings[:4]:
            n = GraphNode(id=f"ali-blind-{_make_id()}", node_type=NodeType.SERVICE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(attacker.id, n.id, EdgeType.LATERAL_MOVE,
                                   "undetected due to disabled monitoring"))
            affected.append(f.get("resource_id") or f["check_title"])

        target = GraphNode(id=f"ali-unmonitored-{_make_id()}", node_type=NodeType.RESOURCE,
                           label="Unmonitored Environment", service="multi-service")
        nodes.append(target)
        for n in nodes[1:-1]:
            edges.append(GraphEdge(n.id, target.id, EdgeType.LATERAL_MOVE,
                                   "monitoring dead zone"))

        return AttackPath(
            id=_make_id(),
            title="Alibaba Monitoring Blindspot",
            description="Disabled ActionTrail, missing SLS alerts, and absent Security Center agents "
                        "create a monitoring dead zone where attacker activity goes undetected.",
            severity=self._max_severity([f["severity"] for f in monitor_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Threat Actor",
            target="Unmonitored Environment",
            category="detection_evasion",
            techniques=["T1562.008", "T1070", "T1562.001"],
            affected_resources=affected,
            remediation=[
                "Enable ActionTrail in all regions with multi-account delivery",
                "Configure SLS alerts for security-critical events",
                "Deploy Security Center agents on all ECS instances",
                "Set SLS log retention to at least 365 days",
                "Enable ActionTrail log file validation",
            ],
        )

    def _build_github_secrets_cloud_path(self, findings, services, checks) -> Optional[AttackPath]:
        """GitHub → missing secret scanning → committed credential → unrotated key → cloud."""
        gh_findings = [f for f in findings
                       if any(k in f["check_id"] for k in ["github_repo_secret_scanning"])
                       and f.get("status") == "FAIL"]
        key_findings = [f for f in findings
                        if any(k in f["check_id"] for k in ["iam_access_key_rotation",
                                                              "ali_ram_access_key",
                                                              "azure_iam_custom_role"])
                        and f.get("status") == "FAIL"]
        all_findings = gh_findings + key_findings
        if not gh_findings or not key_findings:
            return None

        nodes, edges, affected = [], [], []
        repo = GraphNode(id="gh-repo", node_type=NodeType.SERVICE,
                         label="GitHub Repository", service="github")
        nodes.append(repo)

        for f in gh_findings[:2]:
            n = GraphNode(id=f"gh-scan-{_make_id()}", node_type=NodeType.SERVICE,
                          label=f.get("resource_name") or f["check_title"],
                          service="github", severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(repo.id, n.id, EdgeType.EXPOSES,
                                   "missing secret scanning"))
            affected.append(f.get("resource_id") or f["check_title"])

        cred_node = GraphNode(id=f"gh-cred-{_make_id()}", node_type=NodeType.IDENTITY,
                              label="Committed Cloud Credential", service="github",
                              severity="critical")
        nodes.append(cred_node)
        edges.append(GraphEdge(nodes[-2].id, cred_node.id, EdgeType.CREDENTIAL_ACCESS,
                               "leaked cloud credential"))

        for f in key_findings[:2]:
            n = GraphNode(id=f"gh-key-{_make_id()}", node_type=NodeType.IDENTITY,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(cred_node.id, n.id, EdgeType.HAS_ACCESS,
                                   "unrotated access key"))
            affected.append(f.get("resource_id") or f["check_title"])

        cloud = GraphNode(id=f"gh-cloud-{_make_id()}", node_type=NodeType.RESOURCE,
                          label="Cloud Infrastructure", service="multi-service",
                          severity="critical")
        nodes.append(cloud)
        edges.append(GraphEdge(nodes[-2].id, cloud.id, EdgeType.HAS_ACCESS,
                               "persistent cloud access"))

        return AttackPath(
            id=_make_id(),
            title="GitHub Secrets Exposure to Cloud Access",
            description="Repositories without secret scanning leak cloud credentials. Combined with "
                        "unrotated access keys, attackers gain persistent cloud infrastructure access.",
            severity=self._max_severity([f["severity"] for f in all_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="GitHub Repository",
            target="Cloud Infrastructure",
            category="credential_access",
            techniques=["T1552", "T1552.001", "T1078.004"],
            affected_resources=affected,
            remediation=[
                "Enable secret scanning on all GitHub repositories",
                "Enable push protection to block secrets before commit",
                "Rotate all cloud access keys every 90 days",
                "Use OIDC federation instead of long-lived credentials in CI/CD",
                "Implement pre-commit hooks to detect secrets locally",
            ],
        )

    def _build_m365_identity_azure_path(self, findings, services, checks) -> Optional[AttackPath]:
        """M365: Phishing → legacy auth → no MFA → Azure AD → Azure resources."""
        m365_findings = [f for f in findings
                         if any(k in f["check_id"] for k in ["m365_ca_block_legacy",
                                                               "m365_admin_mfa"])
                         and f.get("status") == "FAIL"]
        azure_findings = [f for f in findings
                          if any(k in f["check_id"] for k in ["azure_iam_owner_count"])
                          and f.get("status") == "FAIL"]
        all_findings = m365_findings + azure_findings
        if not m365_findings or not azure_findings:
            return None

        nodes, edges, affected = [], [], []
        phishing = GraphNode(id="m365-phish", node_type=NodeType.INTERNET,
                             label="Phishing Email", service="external")
        nodes.append(phishing)

        for f in m365_findings[:2]:
            n = GraphNode(id=f"m365-auth-{_make_id()}", node_type=NodeType.SERVICE,
                          label=f.get("resource_name") or f["check_title"],
                          service="m365", severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(phishing.id if len(nodes) == 2 else nodes[-2].id,
                                   n.id, EdgeType.EXPOSES,
                                   "exploits legacy auth / missing MFA"))
            affected.append(f.get("resource_id") or f["check_title"])

        azure_ad = GraphNode(id=f"m365-aad-{_make_id()}", node_type=NodeType.IDENTITY,
                             label="Azure AD Identity", service="azure_iam",
                             severity="high")
        nodes.append(azure_ad)
        edges.append(GraphEdge(nodes[-2].id, azure_ad.id, EdgeType.CAN_ESCALATE,
                               "shared Azure AD identity"))

        for f in azure_findings[:2]:
            n = GraphNode(id=f"m365-az-{_make_id()}", node_type=NodeType.RESOURCE,
                          label=f.get("resource_name") or f["check_title"],
                          service="azure_iam", severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(azure_ad.id, n.id, EdgeType.HAS_ACCESS,
                                   "accesses Azure subscription resources"))
            affected.append(f.get("resource_id") or f["check_title"])

        return AttackPath(
            id=_make_id(),
            title="M365 Identity Compromise to Azure Resources",
            description="Legacy authentication and weak MFA in Microsoft 365 allow credential "
                        "phishing that pivots to Azure subscription resources via shared Azure AD identity.",
            severity=self._max_severity([f["severity"] for f in all_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Phishing Email",
            target="Azure Subscription Resources",
            category="privilege_escalation",
            techniques=["T1566", "T1078.004", "T1484"],
            affected_resources=affected,
            remediation=[
                "Block legacy authentication via Conditional Access policies",
                "Enforce MFA for all administrators and privileged roles",
                "Limit the number of subscription owners to 3 or fewer",
                "Enable Azure AD Identity Protection for risky sign-in detection",
                "Implement Conditional Access policies for Azure management",
            ],
        )

    def _build_saas_credential_cloud_path(self, findings, services, checks) -> Optional[AttackPath]:
        """SaaS: Compromised platform → unencrypted data → stored credentials → cloud."""
        saas_findings = [f for f in findings
                         if any(k in f["check_id"] for k in ["servicenow_encryption",
                                                               "servicenow_ac_acl",
                                                               "salesforce_encryption"])
                         and f.get("status") == "FAIL"]
        cloud_findings = [f for f in findings
                          if any(k in f["check_id"] for k in ["iam_access_key_rotation",
                                                                "azure_iam_custom_role"])
                          and f.get("status") == "FAIL"]
        all_findings = saas_findings + cloud_findings
        if not saas_findings or not cloud_findings:
            return None

        nodes, edges, affected = [], [], []
        entry = GraphNode(id="saas-compromised", node_type=NodeType.SERVICE,
                          label="Compromised SaaS Platform", service="saas")
        nodes.append(entry)

        for f in saas_findings[:2]:
            n = GraphNode(id=f"saas-data-{_make_id()}", node_type=NodeType.DATA_STORE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(entry.id if len(nodes) == 2 else nodes[-2].id,
                                   n.id, EdgeType.HAS_ACCESS,
                                   "accesses unencrypted data"))
            affected.append(f.get("resource_id") or f["check_title"])

        cred_node = GraphNode(id=f"saas-cred-{_make_id()}", node_type=NodeType.IDENTITY,
                              label="Stored Cloud Credentials", service="saas",
                              severity="critical")
        nodes.append(cred_node)
        edges.append(GraphEdge(nodes[-2].id, cred_node.id, EdgeType.CREDENTIAL_ACCESS,
                               "extracts stored cloud credentials"))

        for f in cloud_findings[:2]:
            n = GraphNode(id=f"saas-cloud-{_make_id()}", node_type=NodeType.RESOURCE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(cred_node.id, n.id, EdgeType.HAS_ACCESS,
                                   "unauthorized cloud access"))
            affected.append(f.get("resource_id") or f["check_title"])

        return AttackPath(
            id=_make_id(),
            title="SaaS Platform Credential Theft to Cloud",
            description="Compromised SaaS platform without encryption at rest exposes stored cloud "
                        "credentials in custom fields, providing unauthorized cloud infrastructure access.",
            severity=self._max_severity([f["severity"] for f in all_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Compromised SaaS Platform",
            target="Cloud Infrastructure",
            category="credential_access",
            techniques=["T1552", "T1078.004", "T1213"],
            affected_resources=affected,
            remediation=[
                "Enable encryption at rest on ServiceNow and Salesforce",
                "Enforce ACL rules to restrict access to sensitive records",
                "Never store cloud credentials in SaaS custom fields",
                "Rotate all cloud access keys regularly",
                "Implement a secrets management solution for integrations",
            ],
        )

    def _build_supply_chain_container_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Supply chain: Malicious image → registry without scanning → cluster → production."""
        registry_findings = [f for f in findings
                             if any(k in f["check_id"] for k in ["ecr_image_scanning",
                                                                   "ecr_lifecycle_policy",
                                                                   "gcp_gke_binary_authorization",
                                                                   "k8s_image_pull_policy"])
                             and f.get("status") == "FAIL"]
        if not registry_findings:
            return None

        nodes, edges, affected = [], [], []
        malicious = GraphNode(id="sc-malicious", node_type=NodeType.INTERNET,
                              label="Malicious Image", service="external")
        nodes.append(malicious)

        for f in registry_findings[:3]:
            n = GraphNode(id=f"sc-reg-{_make_id()}", node_type=NodeType.SERVICE,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(malicious.id if len(nodes) == 2 else nodes[-2].id,
                                   n.id, EdgeType.EXPOSES,
                                   "registry without image scanning"))
            affected.append(f.get("resource_id") or f["check_title"])

        cluster = GraphNode(id=f"sc-cluster-{_make_id()}", node_type=NodeType.RESOURCE,
                            label="Production Cluster", service="kubernetes",
                            severity="high")
        nodes.append(cluster)
        edges.append(GraphEdge(nodes[-2].id, cluster.id, EdgeType.LATERAL_MOVE,
                               "deploys to production cluster"))

        target = GraphNode(id=f"sc-data-{_make_id()}", node_type=NodeType.DATA_STORE,
                           label="Production Data (via Task Role)", service="multi-service",
                           severity="critical")
        nodes.append(target)
        edges.append(GraphEdge(cluster.id, target.id, EdgeType.ASSUMES_ROLE,
                               "task role permissions"))

        return AttackPath(
            id=_make_id(),
            title="Supply Chain via Container Registry",
            description="Container registries without image scanning allow malicious or vulnerable "
                        "images to deploy into production clusters, achieving code execution with "
                        "task role permissions.",
            severity=self._max_severity([f["severity"] for f in registry_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Malicious Image",
            target="Production Data",
            category="supply_chain",
            techniques=["T1525", "T1195", "T1610"],
            affected_resources=affected,
            remediation=[
                "Enable image scanning on all container registries",
                "Configure lifecycle policies to remove untagged images",
                "Enable Binary Authorization or admission controllers",
                "Set imagePullPolicy to Always on all workloads",
                "Implement image signing and verification pipelines",
            ],
        )

    def _build_ransomware_kill_chain_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Ransomware: Internet → RDP/SSH → no MFA → disable logging → delete backups → encrypt."""
        rw_findings = [f for f in findings
                       if any(k in f["check_id"] for k in ["ec2_sg_open_port_22",
                                                             "ec2_sg_open_port_3389",
                                                             "iam_user_mfa",
                                                             "cloudtrail_multiregion",
                                                             "s3_bucket_versioning",
                                                             "s3_bucket_object_lock",
                                                             "rds_automated_backups"])
                       and f.get("status") == "FAIL"]
        if len(rw_findings) < 3:
            return None

        nodes, edges, affected = [], [], []
        internet = GraphNode(id="rw-internet", node_type=NodeType.INTERNET,
                             label="Internet", service="external")
        nodes.append(internet)

        access_findings = [f for f in rw_findings if "sg_open_port" in f["check_id"]]
        mfa_findings = [f for f in rw_findings if "mfa" in f["check_id"]]
        log_findings = [f for f in rw_findings if "cloudtrail" in f["check_id"]]
        backup_findings = [f for f in rw_findings if "versioning" in f["check_id"]
                           or "object_lock" in f["check_id"]
                           or "automated_backups" in f["check_id"]]

        prev_id = internet.id
        for layer, prefix, lbl, etype in [
            (access_findings, "rw-rdp", "open RDP/SSH access", EdgeType.EXPOSES),
            (mfa_findings, "rw-mfa", "no MFA on user", EdgeType.CAN_ESCALATE),
            (log_findings, "rw-log", "disables logging", EdgeType.LATERAL_MOVE),
            (backup_findings, "rw-backup", "deletes backups", EdgeType.LATERAL_MOVE),
        ]:
            for f in layer[:1]:
                n = GraphNode(id=f"{prefix}-{_make_id()}", node_type=self._classify_node_type(f["service"]),
                              label=f.get("resource_name") or f["check_title"],
                              service=f["service"], severity=f["severity"],
                              metadata={"finding_id": f["id"], "check_id": f["check_id"]})
                nodes.append(n)
                edges.append(GraphEdge(prev_id, n.id, etype, lbl))
                prev_id = n.id
                affected.append(f.get("resource_id") or f["check_title"])

        encrypt_target = GraphNode(id=f"rw-encrypt-{_make_id()}", node_type=NodeType.DATA_STORE,
                                   label="Encrypted / Ransomed Data", service="multi-service",
                                   severity="critical")
        nodes.append(encrypt_target)
        edges.append(GraphEdge(prev_id, encrypt_target.id, EdgeType.HAS_ACCESS,
                               "encrypts data for ransom"))

        return AttackPath(
            id=_make_id(),
            title="Ransomware Kill Chain",
            description="Complete ransomware attack chain: internet-facing RDP/SSH without MFA enables "
                        "initial access, followed by logging disablement, backup destruction, and "
                        "data encryption for impact.",
            severity="critical",
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Internet",
            target="Encrypted / Ransomed Data",
            category="ransomware",
            techniques=["T1190", "T1110", "T1078", "T1562.008", "T1490", "T1486", "T1485"],
            affected_resources=affected,
            remediation=[
                "Close RDP (3389) and SSH (22) to the internet",
                "Enforce MFA for all IAM users and console access",
                "Enable CloudTrail in all regions with tamper protection",
                "Enable S3 bucket versioning and Object Lock",
                "Enable automated backups with deletion protection on RDS",
                "Implement immutable backup strategies",
            ],
        )

    def _build_insider_exfiltration_saas_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Insider: Unmasked Snowflake → Salesforce export → M365 sharing → exfiltration."""
        saas_findings = [f for f in findings
                         if any(k in f["check_id"] for k in ["m365_external_sharing",
                                                               "m365_dlp_policies",
                                                               "salesforce_field_level",
                                                               "snowflake_column_masking"])
                         and f.get("status") == "FAIL"]
        if len(saas_findings) < 2:
            return None

        nodes, edges, affected = [], [], []
        insider = GraphNode(id="insider-actor", node_type=NodeType.IDENTITY,
                            label="Malicious Insider", service="internal")
        nodes.append(insider)

        snow_findings = [f for f in saas_findings if "snowflake" in f["check_id"]]
        sf_findings = [f for f in saas_findings if "salesforce" in f["check_id"]]
        m365_findings = [f for f in saas_findings if "m365" in f["check_id"]]

        prev_id = insider.id
        for layer, prefix, svc, lbl in [
            (snow_findings, "ins-snow", "snowflake", "accesses unmasked data"),
            (sf_findings, "ins-sf", "salesforce", "unrestricted data export"),
            (m365_findings, "ins-m365", "m365", "external sharing without DLP"),
        ]:
            for f in layer[:1]:
                n = GraphNode(id=f"{prefix}-{_make_id()}", node_type=NodeType.DATA_STORE,
                              label=f.get("resource_name") or f["check_title"],
                              service=svc, severity=f["severity"],
                              metadata={"finding_id": f["id"], "check_id": f["check_id"]})
                nodes.append(n)
                edges.append(GraphEdge(prev_id, n.id, EdgeType.HAS_ACCESS, lbl))
                prev_id = n.id
                affected.append(f.get("resource_id") or f["check_title"])

        exfil = GraphNode(id=f"ins-exfil-{_make_id()}", node_type=NodeType.SERVICE,
                          label="Data Exfiltration", service="external",
                          severity="high")
        nodes.append(exfil)
        edges.append(GraphEdge(prev_id, exfil.id, EdgeType.HAS_ACCESS,
                               "data exfiltrated via SaaS channels"))

        return AttackPath(
            id=_make_id(),
            title="Insider Data Exfiltration via SaaS Channels",
            description="Malicious insider leverages unmasked data in Snowflake, unrestricted "
                        "Salesforce exports, and M365 external sharing without DLP to exfiltrate "
                        "sensitive data through SaaS channels.",
            severity=self._max_severity([f["severity"] for f in saas_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Malicious Insider",
            target="Data Exfiltration",
            category="data_exfiltration",
            techniques=["T1530", "T1567", "T1537"],
            affected_resources=affected,
            remediation=[
                "Enable column-level masking policies in Snowflake",
                "Enforce field-level security in Salesforce",
                "Restrict external sharing in Microsoft 365",
                "Configure DLP policies across all SaaS platforms",
                "Implement data loss prevention monitoring and alerts",
            ],
        )

    def _build_multi_cloud_lateral_path(self, findings, services, checks) -> Optional[AttackPath]:
        """Multi-cloud: Weakest IAM → compromised → cross-cloud service account → all envs."""
        iam_findings = [f for f in findings
                        if any(k in f["check_id"] for k in ["iam_user_mfa", "azure_iam_owner",
                                                              "gcp_iam_no_public", "ali_ram_mfa"])
                        and f.get("status") == "FAIL"]
        if len(iam_findings) < 3:
            return None

        nodes, edges, affected = [], [], []
        entry = GraphNode(id="mcl-weakest", node_type=NodeType.IDENTITY,
                          label="Weakest Cloud IAM", service="multi-service")
        nodes.append(entry)

        prev_id = entry.id
        for f in iam_findings[:4]:
            n = GraphNode(id=f"mcl-iam-{_make_id()}", node_type=NodeType.IDENTITY,
                          label=f.get("resource_name") or f["check_title"],
                          service=f["service"], severity=f["severity"],
                          metadata={"finding_id": f["id"], "check_id": f["check_id"]})
            nodes.append(n)
            edges.append(GraphEdge(prev_id, n.id, EdgeType.LATERAL_MOVE,
                                   "cross-cloud lateral movement"))
            prev_id = n.id
            affected.append(f.get("resource_id") or f["check_title"])

        cross_cloud = GraphNode(id=f"mcl-cross-{_make_id()}", node_type=NodeType.IDENTITY,
                                label="Cross-Cloud Service Account", service="multi-service",
                                severity="high")
        nodes.append(cross_cloud)
        edges.append(GraphEdge(prev_id, cross_cloud.id, EdgeType.ASSUMES_ROLE,
                               "pivots via federation / service account"))

        all_envs = GraphNode(id=f"mcl-all-{_make_id()}", node_type=NodeType.RESOURCE,
                             label="All Cloud Environments", service="multi-service",
                             severity="critical")
        nodes.append(all_envs)
        edges.append(GraphEdge(cross_cloud.id, all_envs.id, EdgeType.HAS_ACCESS,
                               "full access to all environments"))

        return AttackPath(
            id=_make_id(),
            title="Multi-Cloud Lateral Movement",
            description="IAM misconfigurations across multiple cloud providers allow attackers to "
                        "pivot from the weakest environment to all connected cloud accounts via "
                        "cross-cloud service accounts and federation.",
            severity=self._max_severity([f["severity"] for f in iam_findings]),
            risk_score=0,
            nodes=nodes, edges=edges,
            entry_point="Weakest Cloud IAM",
            target="All Cloud Environments",
            category="lateral_movement",
            techniques=["T1078.004", "T1021", "T1563", "T1550"],
            affected_resources=affected,
            remediation=[
                "Enforce MFA across all cloud provider IAM users",
                "Limit subscription/account owners to a minimum",
                "Remove public IAM bindings in GCP",
                "Audit cross-cloud service accounts and federation trusts",
                "Implement consistent identity governance across all clouds",
            ],
        )

    def _score_paths(self) -> None:
        """Assign risk scores to discovered attack paths."""
        severity_weights = {
            "critical": 40, "high": 30, "medium": 20, "low": 10, "informational": 5
        }
        category_weights = {
            "ransomware": 1.5,
            "privilege_escalation": 1.3,
            "credential_access": 1.25,
            "data_exfiltration": 1.2,
            "supply_chain": 1.15,
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
