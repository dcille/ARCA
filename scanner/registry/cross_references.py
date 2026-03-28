"""Cross-reference validation between the registry, MITRE/RR, and frameworks.

Validates integrity of check_id references across four systems:

1. Registry (CIS-based source of truth, 904+ controls + supplementary)
2. MITRE ATT&CK mappings (CHECK_TO_MITRE in attack_mapping.py)
3. Ransomware Readiness rules (check_ids in RRRule definitions)
4. Compliance frameworks (check_ids in ENS/GDPR/HIPAA/PCI-DSS/SOC2)

Resolution chain:
  MITRE check_id → scanner_check_id → CIS control in registry
  RR check_id → CHECK_ID_ALIASES → scanner_check_id → CIS control in registry
  Framework check_id → scanner_check_id → CIS control in registry
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

    # Framework validation
    try:
        from scanner.registry.framework_validator import validate_framework_references
        report["frameworks"] = validate_framework_references(registry)
    except Exception as e:
        logger.warning("Framework validation failed: %s", e)
        report["frameworks"] = {"error": str(e)}

    report["recommendations"] = _build_recommendations(report)
    return report


def _build_recommendations(report: dict) -> list[str]:
    recs = []

    mitre = report.get("mitre", {})
    rr = report.get("ransomware_readiness", {})
    fw = report.get("frameworks", {})

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

    # Framework recommendations
    fw_gs = fw.get("global_stats", {})
    if fw_gs.get("total_orphaned", 0) > 0:
        recs.append(
            f"FRAMEWORKS: {fw_gs['total_orphaned']} check_ids referenced in "
            f"compliance frameworks do not resolve to any scanner implementation. "
            f"These produce no results in compliance reports."
        )
    if fw_gs.get("frameworks_without_saas", 0) > 0:
        recs.append(
            f"FRAMEWORKS: {fw_gs['frameworks_without_saas']} frameworks have "
            f"no SaaS check mappings. SaaS posture is invisible in compliance "
            f"reports for these frameworks."
        )
    if fw_gs.get("frameworks_missing_oci", 0) > 0:
        recs.append(
            f"FRAMEWORKS: {fw_gs['frameworks_missing_oci']} frameworks missing "
            f"OCI check mappings."
        )

    if (mitre.get("coverage_pct", 0) >= 95 and
            rr.get("coverage_pct", 0) >= 95 and
            fw_gs.get("total_orphaned", 0) == 0):
        recs.append(
            "Cross-reference coverage is excellent (>95%). "
            "No urgent action needed."
        )

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

    # MITRE
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

    # Ransomware Readiness
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

    # Compliance Frameworks
    fw = report.get("frameworks", {})
    if fw and "error" not in fw:
        fw_gs = fw.get("global_stats", {})
        print("Compliance Frameworks:")
        print(f"  Frameworks:      {fw_gs.get('total_frameworks', 0)}")
        print(f"  Controls:        {fw_gs.get('total_framework_controls', 0)}")
        print(f"  Check refs:      {fw_gs.get('total_check_refs', 0)}")
        print(f"  Resolved:        {fw_gs.get('total_resolved', 0)} "
              f"({fw_gs.get('global_coverage_pct', 0)}%)")
        print(f"  Orphaned:        {fw_gs.get('total_orphaned', 0)}")
        print(f"  SaaS coverage:   {fw_gs.get('frameworks_with_saas', 0)}/"
              f"{fw_gs.get('total_frameworks', 0)} frameworks")
        print(f"  Uncovered:       "
              f"{fw.get('uncovered_checks', {}).get('total', 0)} "
              f"scanner checks not in any framework")

        saas_gap = fw.get("saas_gap", {})
        if saas_gap:
            print("  SaaS by framework:")
            for fk, gap in sorted(saas_gap.items()):
                status = ("YES" if gap["has_saas"] else "NONE")
                cov = f"{gap['controls_with_saas']}/{gap['controls_total']}"
                print(f"    {fk:<15s} {status:<6s} ({cov} controls)")
    print()

    print("Recommendations:")
    for rec in report.get("recommendations", []):
        print(f"  - {rec}")
    print("=" * 70)
