"""Cross-reference validation between the registry and MITRE/Ransomware modules.

This module provides detailed validation and reporting functions that verify
the integrity of check_id references across the three systems:

1. Registry (source of truth for check definitions)
2. MITRE ATT&CK mappings (CHECK_TO_MITRE in attack_mapping.py)
3. Ransomware Readiness rules (check_ids in RRRule definitions)

MITRE and Ransomware Readiness keep their own mapping logic — this module
only validates that the check_ids they reference actually exist in the registry.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def validate_all(registry=None) -> dict:
    """Run full cross-reference validation.

    Returns a comprehensive report with:
    - Registry stats
    - MITRE coverage and orphaned references
    - Ransomware Readiness coverage and orphaned references
    - Recommendations for fixing gaps
    """
    if registry is None:
        from scanner.registry.registry import get_default_registry
        registry = get_default_registry()

    report = {
        "registry_total": registry.total_count,
        "registry_enabled": registry.enabled_count,
        "mitre": _validate_mitre(registry),
        "ransomware_readiness": _validate_rr(registry),
    }

    report["recommendations"] = _build_recommendations(report)
    return report


def _validate_mitre(registry) -> dict:
    """Validate MITRE ATT&CK CHECK_TO_MITRE references."""
    try:
        from scanner.mitre.attack_mapping import CHECK_TO_MITRE
    except ImportError:
        return {"error": "MITRE module not importable"}

    mitre_ids = set(CHECK_TO_MITRE.keys())
    registry_ids = registry.list_check_ids()

    valid = mitre_ids & registry_ids
    orphaned = mitre_ids - registry_ids
    unmapped = registry_ids - mitre_ids

    # Group orphaned by probable provider
    orphaned_by_provider: dict[str, list[str]] = {}
    for cid in sorted(orphaned):
        provider = _guess_provider(cid)
        orphaned_by_provider.setdefault(provider, []).append(cid)

    return {
        "total_references": len(mitre_ids),
        "valid": len(valid),
        "orphaned": len(orphaned),
        "orphaned_by_provider": orphaned_by_provider,
        "registry_unmapped": len(unmapped),
        "coverage_pct": round(len(valid) / max(len(mitre_ids), 1) * 100, 1),
    }


def _validate_rr(registry) -> dict:
    """Validate Ransomware Readiness rule check_id references."""
    try:
        from scanner.ransomware_readiness.framework import get_all_rules
    except ImportError:
        return {"error": "RR module not importable"}

    registry_ids = registry.list_check_ids()
    all_rr_ids: set[str] = set()
    orphaned: set[str] = set()
    by_domain: dict[str, dict] = {}

    for rule in get_all_rules():
        domain = rule.domain.value if hasattr(rule.domain, "value") else str(rule.domain)
        if domain not in by_domain:
            by_domain[domain] = {"rules": 0, "check_refs": 0, "valid": 0, "orphaned": []}
        by_domain[domain]["rules"] += 1

        for provider, check_ids in rule.check_ids.items():
            for cid in check_ids:
                all_rr_ids.add(cid)
                by_domain[domain]["check_refs"] += 1
                if cid in registry_ids:
                    by_domain[domain]["valid"] += 1
                else:
                    by_domain[domain]["orphaned"].append(cid)
                    orphaned.add(cid)

    valid = all_rr_ids & registry_ids

    # Group orphaned by provider
    orphaned_by_provider: dict[str, list[str]] = {}
    for cid in sorted(orphaned):
        provider = _guess_provider(cid)
        orphaned_by_provider.setdefault(provider, []).append(cid)

    return {
        "total_references": len(all_rr_ids),
        "valid": len(valid),
        "orphaned": len(orphaned),
        "orphaned_by_provider": orphaned_by_provider,
        "coverage_pct": round(len(valid) / max(len(all_rr_ids), 1) * 100, 1),
        "by_domain": by_domain,
    }


def _guess_provider(check_id: str) -> str:
    """Guess provider from check_id prefix."""
    prefixes = {
        "aws_": "aws", "azure_": "azure", "gcp_": "gcp",
        "oci_": "oci", "alibaba_": "alibaba", "ibm_": "ibm_cloud",
        "k8s_": "kubernetes", "m365_": "m365", "github_": "github",
        "gws_": "google_workspace", "sf_": "salesforce",
        "snow_": "snowflake", "cf_": "cloudflare",
    }
    for prefix, provider in prefixes.items():
        if check_id.startswith(prefix):
            return provider
    # Many AWS checks don't have prefix
    return "aws_or_unknown"


def _build_recommendations(report: dict) -> list[str]:
    """Build actionable recommendations from validation results."""
    recs = []

    mitre = report.get("mitre", {})
    rr = report.get("ransomware_readiness", {})

    if mitre.get("orphaned", 0) > 0:
        recs.append(
            f"MITRE: {mitre['orphaned']} check_ids referenced in CHECK_TO_MITRE "
            f"do not exist in the registry. These checks may use different naming "
            f"conventions or may be defined in Ransomware Readiness rules but not "
            f"in cloud/SaaS scanners. Consider adding them to the registry or "
            f"updating the MITRE mappings."
        )

    if rr.get("orphaned", 0) > 0:
        recs.append(
            f"Ransomware Readiness: {rr['orphaned']} check_ids referenced in RR "
            f"rules do not exist in the registry. These are likely using rule-level "
            f"check_ids that differ from scanner check_ids (resolved via "
            f"CHECK_ID_ALIASES in the evaluator). This is expected behavior — the "
            f"evaluator handles the translation at runtime."
        )

    if mitre.get("coverage_pct", 0) < 80:
        recs.append(
            f"MITRE coverage is {mitre['coverage_pct']}% — consider expanding "
            f"registry definitions to improve coverage."
        )

    if not recs:
        recs.append("All cross-references are healthy. No action needed.")

    return recs


def print_report(report: Optional[dict] = None) -> None:
    """Print a human-readable cross-reference validation report."""
    if report is None:
        report = validate_all()

    print("=" * 70)
    print("ARCA Registry Cross-Reference Validation Report")
    print("=" * 70)
    print(f"Registry: {report['registry_total']} checks "
          f"({report['registry_enabled']} enabled)")
    print()

    mitre = report.get("mitre", {})
    if "error" not in mitre:
        print(f"MITRE ATT&CK:")
        print(f"  References:  {mitre['total_references']}")
        print(f"  Valid:       {mitre['valid']}")
        print(f"  Orphaned:    {mitre['orphaned']}")
        print(f"  Coverage:    {mitre['coverage_pct']}%")
        if mitre.get("orphaned_by_provider"):
            print(f"  Orphaned by provider:")
            for prov, ids in mitre["orphaned_by_provider"].items():
                print(f"    {prov}: {len(ids)} ({', '.join(ids[:3])}{'...' if len(ids) > 3 else ''})")
    print()

    rr = report.get("ransomware_readiness", {})
    if "error" not in rr:
        print(f"Ransomware Readiness:")
        print(f"  References:  {rr['total_references']}")
        print(f"  Valid:       {rr['valid']}")
        print(f"  Orphaned:    {rr['orphaned']}")
        print(f"  Coverage:    {rr['coverage_pct']}%")
        if rr.get("by_domain"):
            print(f"  By domain:")
            for domain, info in sorted(rr["by_domain"].items()):
                print(f"    {domain}: {info['rules']} rules, "
                      f"{info['valid']}/{info['check_refs']} refs valid")
    print()

    print("Recommendations:")
    for rec in report.get("recommendations", []):
        print(f"  - {rec}")
    print("=" * 70)
