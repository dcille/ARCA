"""Enhanced scoring engine for attack paths with contextual enrichment."""

from typing import Any
from .models import CATEGORY_WEIGHTS, SEVERITY_WEIGHTS, KILL_CHAIN_PHASES, TACTIC_TO_PHASE


def score_path(path: dict, centrality_scores: dict | None = None,
               mitre_techniques_db: dict | None = None,
               blast_radius: dict | None = None,
               detection_coverage: dict | None = None) -> dict:
    """
    Enhanced scoring for a single attack path.

    Returns dict with:
      - risk_score (float 0-100)
      - kill_chain_phases (list of covered phases)
      - kill_chain_coverage (float 0-1)
      - choke_points (list of node IDs with high centrality)
      - scoring_factors (dict of individual factor contributions)
    """
    severity = path.get('severity', 'medium')
    category = path.get('category', 'exposure')
    nodes = path.get('nodes', [])
    edges = path.get('edges', [])
    techniques = path.get('techniques', [])
    affected_resources = path.get('affected_resources', [])

    # Base severity score
    base_score = SEVERITY_WEIGHTS.get(severity, 4.0)

    # Category weight
    cat_weight = CATEGORY_WEIGHTS.get(category, 1.0)

    # Step complexity factor: longer chains = higher risk (with diminishing returns)
    step_count = max(len(nodes), 1)
    step_factor = min(1.0 + (step_count - 1) * 0.12, 2.0)

    # Resource count factor
    resource_count = len(affected_resources) if affected_resources else 1
    resource_factor = min(1.0 + resource_count * 0.05, 1.8)

    # Kill chain analysis
    kill_chain_phases = _compute_kill_chain_phases(techniques, mitre_techniques_db)
    phase_count = len(kill_chain_phases)
    # Paths covering 4+ kill chain phases get a bonus
    kill_chain_factor = 1.0
    if phase_count >= 5:
        kill_chain_factor = 1.5
    elif phase_count >= 4:
        kill_chain_factor = 1.3
    elif phase_count >= 3:
        kill_chain_factor = 1.15

    # Public exposure factor
    entry_point = path.get('entry_point', '')
    exposure_factor = 1.3 if 'internet' in entry_point.lower() else 1.0

    # Environment factor (if tags available)
    env_factor = _compute_env_factor(path)

    # Centrality factor (choke points)
    choke_points = []
    centrality_factor = 1.0
    if centrality_scores:
        for node in nodes:
            node_id = node.get('id', '') if isinstance(node, dict) else str(node)
            c = centrality_scores.get(node_id, 0.0)
            if c > 0.1:
                choke_points.append({'node_id': node_id, 'centrality': round(c, 4)})
        if choke_points:
            max_centrality = max(cp['centrality'] for cp in choke_points)
            centrality_factor = 1.0 + max_centrality * 0.5

    # ── BAS 2.0: Blast radius factor ──────────────────────────────
    blast_radius_factor = 1.0
    if blast_radius:
        total_reachable = blast_radius.get('total_reachable', 0)
        if total_reachable >= 50:
            blast_radius_factor = 1.6
        elif total_reachable >= 20:
            blast_radius_factor = 1.4
        elif total_reachable >= 10:
            blast_radius_factor = 1.2
        elif total_reachable >= 5:
            blast_radius_factor = 1.1
        # PII or admin escalation further increases the factor
        if blast_radius.get('pii_exposure'):
            blast_radius_factor *= 1.15
        if blast_radius.get('admin_escalation'):
            blast_radius_factor *= 1.1
        blast_radius_factor = min(blast_radius_factor, 2.0)

    # ── BAS 2.0: Detection gap factor ─────────────────────────────
    # Paths that are NOT detected by monitoring get a HIGHER score
    # (they are more dangerous because they're invisible)
    detection_gap_factor = 1.0
    if detection_coverage:
        coverage_pct = detection_coverage.get('coverage_pct', 100)
        if coverage_pct == 0:
            detection_gap_factor = 1.5   # Completely blind: max danger
        elif coverage_pct < 25:
            detection_gap_factor = 1.35  # Mostly blind
        elif coverage_pct < 50:
            detection_gap_factor = 1.2   # Partially monitored
        elif coverage_pct < 75:
            detection_gap_factor = 1.1   # Mostly monitored
        # Well-monitored paths (>=75%) get no boost

    # Compute final score (normalized to 0-100)
    raw_score = (base_score * cat_weight * step_factor * resource_factor *
                 kill_chain_factor * exposure_factor * env_factor * centrality_factor *
                 blast_radius_factor * detection_gap_factor)
    risk_score = min(round(raw_score, 1), 100.0)

    return {
        'risk_score': risk_score,
        'kill_chain_phases': kill_chain_phases,
        'kill_chain_coverage': round(phase_count / len(KILL_CHAIN_PHASES), 2),
        'choke_points': choke_points,
        'scoring_factors': {
            'base_severity': base_score,
            'category_weight': cat_weight,
            'step_complexity': round(step_factor, 2),
            'resource_count': round(resource_factor, 2),
            'kill_chain': round(kill_chain_factor, 2),
            'public_exposure': exposure_factor,
            'environment': env_factor,
            'centrality': round(centrality_factor, 2),
            'blast_radius': round(blast_radius_factor, 2),
            'detection_gap': round(detection_gap_factor, 2),
        },
    }


def _compute_kill_chain_phases(techniques: list, mitre_db: dict | None) -> list[str]:
    """Determine which kill chain phases are covered by the path's techniques."""
    if not mitre_db or not techniques:
        return []

    phases = set()
    for tech_id in techniques:
        tech = mitre_db.get(tech_id, {})
        tactic = tech.get('tactic', '')
        phase = TACTIC_TO_PHASE.get(tactic, '')
        if phase:
            phases.add(phase)

    # Return in kill chain order
    return [p for p in KILL_CHAIN_PHASES if p in phases]


def _compute_env_factor(path: dict) -> float:
    """Compute environment factor based on resource tags."""
    affected = path.get('affected_resources', [])
    for res in (affected or []):
        res_str = str(res).lower() if res else ''
        if any(tag in res_str for tag in ['prod', 'production', 'prd']):
            return 1.5
    return 1.0


def compute_path_comparison(paths_run1: list[dict], paths_run2: list[dict]) -> dict:
    """
    Compare attack paths between two analysis runs.
    Two paths match if same category + entry_point + target + >=50% resource overlap.
    """
    def path_key(p):
        return (p.get('category', ''), p.get('entry_point', ''), p.get('target', ''))

    def resource_set(p):
        return set(str(r) for r in (p.get('affected_resources', []) or []))

    matched_run1 = set()
    matched_run2 = set()
    persistent = []
    risk_changes = []

    for i, p1 in enumerate(paths_run1):
        key1 = path_key(p1)
        res1 = resource_set(p1)
        for j, p2 in enumerate(paths_run2):
            if j in matched_run2:
                continue
            key2 = path_key(p2)
            if key1 != key2:
                continue
            res2 = resource_set(p2)
            if res1 and res2:
                overlap = len(res1 & res2) / max(len(res1 | res2), 1)
                if overlap < 0.5:
                    continue
            matched_run1.add(i)
            matched_run2.add(j)
            persistent.append({
                'title': p2.get('title', ''),
                'category': p2.get('category', ''),
                'risk_score_before': p1.get('risk_score', 0),
                'risk_score_after': p2.get('risk_score', 0),
                'risk_change': round(p2.get('risk_score', 0) - p1.get('risk_score', 0), 1),
            })
            break

    new_paths = [paths_run2[j] for j in range(len(paths_run2)) if j not in matched_run2]
    resolved_paths = [paths_run1[i] for i in range(len(paths_run1)) if i not in matched_run1]

    return {
        'new_paths': len(new_paths),
        'resolved_paths': len(resolved_paths),
        'persistent_paths': len(persistent),
        'new_path_details': [{'title': p.get('title', ''), 'severity': p.get('severity', ''), 'risk_score': p.get('risk_score', 0)} for p in new_paths],
        'resolved_path_details': [{'title': p.get('title', ''), 'severity': p.get('severity', '')} for p in resolved_paths],
        'risk_changes': [p for p in persistent if p['risk_change'] != 0],
        'avg_risk_change': round(sum(p['risk_change'] for p in persistent) / max(len(persistent), 1), 1),
    }
