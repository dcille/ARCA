"""Attack Paths analysis engine for D-ARCA."""

from .graph_engine import AttackPathAnalyzer, AttackPathGraph
from .scoring import score_path, compute_path_comparison
from .blast_radius import BlastRadiusCalculator
from .detection import DetectionCoverageAnalyzer
from .iam_graph import IAMGraphBuilder, IAMPrincipal
from .iam_privesc import (
    IAMPrivescDiscovery,
    AWS_PRIVESC_PATTERNS,
    AZURE_PRIVESC_PATTERNS,
    GCP_PRIVESC_PATTERNS,
    OCI_PRIVESC_PATTERNS,
    ALIBABA_PRIVESC_PATTERNS,
    IBM_CLOUD_PRIVESC_PATTERNS,
    K8S_PRIVESC_PATTERNS,
    M365_PRIVESC_PATTERNS,
    GITHUB_PRIVESC_PATTERNS,
    GWS_PRIVESC_PATTERNS,
    SALESFORCE_PRIVESC_PATTERNS,
    SERVICENOW_PRIVESC_PATTERNS,
    SNOWFLAKE_PRIVESC_PATTERNS,
    CLOUDFLARE_PRIVESC_PATTERNS,
    OPENSTACK_PRIVESC_PATTERNS,
    ALL_PRIVESC_PATTERNS,
    build_from_provider,
)

__all__ = [
    "AttackPathAnalyzer",
    "AttackPathGraph",
    "score_path",
    "compute_path_comparison",
    "BlastRadiusCalculator",
    "DetectionCoverageAnalyzer",
    "IAMGraphBuilder",
    "IAMPrincipal",
    "IAMPrivescDiscovery",
    # Pattern registries
    "AWS_PRIVESC_PATTERNS",
    "AZURE_PRIVESC_PATTERNS",
    "GCP_PRIVESC_PATTERNS",
    "OCI_PRIVESC_PATTERNS",
    "ALIBABA_PRIVESC_PATTERNS",
    "IBM_CLOUD_PRIVESC_PATTERNS",
    "K8S_PRIVESC_PATTERNS",
    "M365_PRIVESC_PATTERNS",
    "GITHUB_PRIVESC_PATTERNS",
    "GWS_PRIVESC_PATTERNS",
    "SALESFORCE_PRIVESC_PATTERNS",
    "SERVICENOW_PRIVESC_PATTERNS",
    "SNOWFLAKE_PRIVESC_PATTERNS",
    "CLOUDFLARE_PRIVESC_PATTERNS",
    "OPENSTACK_PRIVESC_PATTERNS",
    "ALL_PRIVESC_PATTERNS",
    "build_from_provider",
]
