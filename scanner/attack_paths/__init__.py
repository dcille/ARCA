"""Attack Paths analysis engine for D-ARCA."""

from .graph_engine import AttackPathAnalyzer, AttackPathGraph
from .scoring import score_path, compute_path_comparison
from .blast_radius import BlastRadiusCalculator
from .detection import DetectionCoverageAnalyzer
from .iam_graph import IAMGraphBuilder, IAMPrincipal
from .iam_privesc import IAMPrivescDiscovery, AWS_PRIVESC_PATTERNS

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
    "AWS_PRIVESC_PATTERNS",
]
