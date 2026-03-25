"""Cross-reference validation between the registry and MITRE/Ransomware modules.

Validates integrity of check_id references across three systems:

1. Registry (CIS-based source of truth, 904 controls + supplementary)
2. MITRE ATT&CK mappings (CHECK_TO_MITRE in attack_mapping.py)
3. Ransomware Readiness rules (check_ids in RRRule definitions)

Resolution chain:
  MITRE check_id → scanner_check_id → CIS control in registry
  RR check_id → CHECK_ID_ALIASES → scanner_check_id → CIS control in registry
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def validate_all(registry=None) -> dict:
    """Run full cross-reference validation."""
    if registry is None:
        from scanner.registry.registry import get_default_registry
        registry = get_default_registry()

    report = {
        "registry_total": registry.total_count,
        "registry_cis": registry.cis_count,
        "registry_supplementary": registry.supplementary_count,
        "scanner_ids_indexed": len(registry._scanner_index),
        "mitre": registry.validate_mitre_references(),
        "ransomware_readiness": registry.validate_rr_references(),
    }

    report["recommendations"] = _build_recommendations(report)
    return report


def _build_recommendations(report: dict) -> list[str]:
    recs = []

    mitre = report.get("mitre", {})
    rr = report.get("ransomware_readiness", {})

    if mitre.get("orphaned", 0) > 0:
        recs.append(
            f"MITRE: {mitre['orphaned']} check_ids not resolvable. "
            f"These use naming conventions that differ from both CIS controls "
            f"and scanner implementations. Add them as supplementary scanner "
            f"checks or update MITRE mappings to use scanner check_ids."
        )

    if rr.get("orphaned", 0) > 0:
        recs.append(
            f"RR: {rr['orphaned']} check_ids not resolvable through the full "
            f"chain (direct → CHECK_ID_ALIASES → scanner → registry). These "
            f"represent checks that need either new scanner implementations, "
            f"new alias mappings, or updates to the RR rule definitions."
        )

    if mitre.get("coverage_pct", 0) >= 95 and rr.get("coverage_pct", 0) >= 95:
        recs.append("Cross-reference coverage is excellent (>95%). No urgent action needed.")

    return recs


def print_report(report: Optional[dict] = None) -> None:
    """Print a human-readable cross-reference validation report."""
    if report is None:
        report = validate_all()

    print("=" * 70)
    print("ARCA Registry Cross-Reference Validation Report")
    print("=" * 70)
    print(f"Registry: {report['registry_total']} checks "
          f"(CIS: {report['registry_cis']}, "
          f"Supplementary: {report['registry_supplementary']})")
    print(f"Scanner IDs indexed: {report['scanner_ids_indexed']}")
    print()

    mitre = report.get("mitre", {})
    if "error" not in mitre:
        print("MITRE ATT&CK:")
        print(f"  References:  {mitre['total_references']}")
        print(f"  Resolved:    {mitre['resolved']}")
        print(f"  Orphaned:    {mitre['orphaned']}")
        print(f"  Coverage:    {mitre['coverage_pct']}%")
        if mitre.get("orphaned_check_ids"):
            print(f"  Orphaned IDs ({len(mitre['orphaned_check_ids'])}):")
            for cid in mitre["orphaned_check_ids"][:10]:
                print(f"    - {cid}")
            if len(mitre["orphaned_check_ids"]) > 10:
                print(f"    ... and {len(mitre['orphaned_check_ids']) - 10} more")
    print()

    rr = report.get("ransomware_readiness", {})
    if "error" not in rr:
        print("Ransomware Readiness:")
        print(f"  References:  {rr['total_references']}")
        print(f"  Resolved:    {rr['resolved']}")
        print(f"  Orphaned:    {rr['orphaned']}")
        print(f"  Coverage:    {rr['coverage_pct']}%")
        if rr.get("by_domain"):
            print("  By domain:")
            for domain, info in sorted(rr["by_domain"].items()):
                refs = info['check_refs']
                res = info['resolved']
                pct = round(res / max(refs, 1) * 100, 1) if refs > 0 else 0
                orph = len(info.get('orphaned', []))
                print(f"    {domain}: {info['rules']} rules, "
                      f"{res}/{refs} resolved ({pct}%), {orph} orphaned")
    print()

    print("Recommendations:")
    for rec in report.get("recommendations", []):
        print(f"  - {rec}")
    print("=" * 70)
