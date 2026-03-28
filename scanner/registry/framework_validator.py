"""Framework check_id validation against the registry.

Validates that every check_id referenced in the compliance frameworks
(ENS, GDPR, HIPAA, PCI-DSS, SOC2) actually exists as either:
  - A registry check_id (CIS or supplementary), OR
  - A scanner_check_id within any registry entry

Also reports scanner check_ids that are NOT referenced by ANY framework
(uncovered checks — potential enrichment targets for Phase 1B).

Integration:
  Place in scanner/registry/framework_validator.py
  Called from cross_references.validate_all() alongside MITRE and RR validation.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Expected providers per framework (what SHOULD be present)
# ──────────────────────────────────────────────────────────────────────

EXPECTED_CLOUD_PROVIDERS = {"aws", "azure", "gcp", "oci", "alibaba"}

EXPECTED_SAAS_PROVIDERS = {
    "m365", "google_workspace", "snowflake", "github",
    "cloudflare", "servicenow", "salesforce", "openstack",
}

# Frameworks where we expect SaaS coverage
SAAS_APPLICABLE_FRAMEWORKS = {
    "ens", "gdpr", "hipaa", "pci_dss_v4", "soc2",
}


def _load_all_frameworks() -> dict[str, dict]:
    """Load all framework definitions from scanner/frameworks/*.py.

    Each framework module exposes a FRAMEWORK dict with structure:
      { "framework_key": { "name": ..., "version": ..., "controls": [...] } }

    Each control has:
      { "id": "...", "title": "...", "checks": { "aws": [...], "azure": [...] } }
    """
    frameworks: dict[str, dict] = {}

    modules = [
        "scanner.frameworks.ens",
        "scanner.frameworks.gdpr",
        "scanner.frameworks.hipaa",
        "scanner.frameworks.pci_dss_v4",
        "scanner.frameworks.soc2",
    ]

    for mod_path in modules:
        try:
            mod = __import__(mod_path, fromlist=["FRAMEWORK"])
            fw_dict = getattr(mod, "FRAMEWORK", {})
            frameworks.update(fw_dict)
        except Exception as e:
            logger.warning("Could not load framework %s: %s", mod_path, e)

    # Apply enrichment layers (OCI/Alibaba, SaaS mappings)
    try:
        from scanner.enrichment import enrich_frameworks
        enrich_frameworks(frameworks)
    except Exception as e:
        logger.debug("Framework enrichment skipped: %s", e)

    return frameworks


def validate_framework_references(registry=None) -> dict:
    """Validate all check_ids in compliance frameworks against the registry.

    Returns a comprehensive report with:
    - Per-framework stats (total refs, resolved, orphaned, coverage %)
    - Per-provider breakdown within each framework
    - Orphan details (check_ids in framework but not in any scanner)
    - Uncovered scanner checks (in scanner but no framework references them)
    - SaaS gap analysis (which frameworks have SaaS mappings)
    - Cloud gap analysis (missing OCI/Alibaba)

    Parameters
    ----------
    registry : CheckRegistry, optional
        If None, uses get_default_registry().
    """
    if registry is None:
        from scanner.registry.registry import get_default_registry
        registry = get_default_registry()

    frameworks = _load_all_frameworks()
    if not frameworks:
        return {"error": "No frameworks loaded. Check scanner/frameworks/ modules."}

    # Build the set of ALL known IDs from the registry
    # (registry check_ids + scanner_check_ids reverse index)
    all_known_ids = registry.list_all_scanner_ids() | registry.list_check_ids()

    report: dict = {
        "frameworks": {},
        "global_stats": {},
        "saas_gap": {},
        "cloud_gap": {},
        "uncovered_checks": {},
    }

    # Accumulate ALL check_ids referenced across ALL frameworks
    all_fw_check_ids: set[str] = set()
    total_refs = 0
    total_resolved = 0
    total_orphaned = 0

    # ── Per-framework validation ──────────────────────────────────────

    for fw_key, fw_data in sorted(frameworks.items()):
        controls = fw_data.get("controls", [])
        fw_name = fw_data.get("name", fw_key)

        fw_report = {
            "name": fw_name,
            "total_controls": len(controls),
            "total_check_refs": 0,
            "resolved": 0,
            "orphaned": 0,
            "orphaned_ids": [],
            "by_provider": {},
            "providers_present": [],
            "providers_missing_cloud": [],
            "providers_missing_saas": [],
            "has_saas": False,
            "saas_providers": [],
            "controls_with_saas": 0,
            "controls_without_checks": 0,
        }

        providers_seen: set[str] = set()

        for ctrl in controls:
            checks = ctrl.get("checks", {})
            ctrl_id = ctrl.get("id", "?")

            if not checks:
                fw_report["controls_without_checks"] += 1
                continue

            ctrl_has_saas = False

            for provider, check_ids in checks.items():
                providers_seen.add(provider)

                if provider not in fw_report["by_provider"]:
                    fw_report["by_provider"][provider] = {
                        "total": 0,
                        "resolved": 0,
                        "orphaned": 0,
                        "orphaned_ids": [],
                    }

                for cid in check_ids:
                    fw_report["total_check_refs"] += 1
                    fw_report["by_provider"][provider]["total"] += 1
                    all_fw_check_ids.add(cid)
                    total_refs += 1

                    # Check resolution: direct check_id OR scanner_check_id
                    if cid in all_known_ids:
                        fw_report["resolved"] += 1
                        fw_report["by_provider"][provider]["resolved"] += 1
                        total_resolved += 1
                    else:
                        fw_report["orphaned"] += 1
                        fw_report["by_provider"][provider]["orphaned"] += 1
                        fw_report["by_provider"][provider]["orphaned_ids"].append(
                            f"{ctrl_id}:{cid}")
                        fw_report["orphaned_ids"].append(f"{ctrl_id}:{cid}")
                        total_orphaned += 1

                # Track SaaS presence
                if provider in EXPECTED_SAAS_PROVIDERS:
                    ctrl_has_saas = True
                    if provider not in fw_report["saas_providers"]:
                        fw_report["saas_providers"].append(provider)

            if ctrl_has_saas:
                fw_report["controls_with_saas"] += 1

        fw_report["has_saas"] = len(fw_report["saas_providers"]) > 0
        fw_report["providers_present"] = sorted(providers_seen)
        fw_report["providers_missing_cloud"] = sorted(
            EXPECTED_CLOUD_PROVIDERS - providers_seen)
        fw_report["providers_missing_saas"] = sorted(
            EXPECTED_SAAS_PROVIDERS - providers_seen)
        fw_report["coverage_pct"] = round(
            fw_report["resolved"] / max(fw_report["total_check_refs"], 1) * 100, 1)
        fw_report["saas_coverage_pct"] = round(
            fw_report["controls_with_saas"] / max(len(controls), 1) * 100, 1)

        report["frameworks"][fw_key] = fw_report

    # ── Uncovered scanner checks ──────────────────────────────────────

    uncovered = all_known_ids - all_fw_check_ids
    uncovered_by_provider: dict[str, list[str]] = {}

    for cid in sorted(uncovered):
        chk = registry.get_check(cid)
        if chk is None:
            chk = registry.find_by_scanner_id(cid)
        prov = chk.provider if chk else "unknown"
        uncovered_by_provider.setdefault(prov, []).append(cid)

    report["uncovered_checks"] = {
        "total": len(uncovered),
        "by_provider": {p: len(ids) for p, ids in uncovered_by_provider.items()},
        "sample_per_provider": {
            p: ids[:5] for p, ids in uncovered_by_provider.items()
        },
    }

    # ── SaaS gap analysis ─────────────────────────────────────────────

    for fw_key, fw_rep in report["frameworks"].items():
        report["saas_gap"][fw_key] = {
            "has_saas": fw_rep["has_saas"],
            "saas_providers": fw_rep["saas_providers"],
            "missing_saas": fw_rep["providers_missing_saas"],
            "controls_with_saas": fw_rep["controls_with_saas"],
            "controls_total": fw_rep["total_controls"],
            "saas_coverage_pct": fw_rep["saas_coverage_pct"],
        }

    # ── Cloud gap analysis ────────────────────────────────────────────

    for fw_key, fw_rep in report["frameworks"].items():
        report["cloud_gap"][fw_key] = {
            "providers_present": [
                p for p in fw_rep["providers_present"]
                if p in EXPECTED_CLOUD_PROVIDERS
            ],
            "missing_cloud": fw_rep["providers_missing_cloud"],
        }

    # ── Global stats ──────────────────────────────────────────────────

    report["global_stats"] = {
        "total_frameworks": len(frameworks),
        "total_framework_controls": sum(
            f["total_controls"] for f in report["frameworks"].values()),
        "total_check_refs": total_refs,
        "total_resolved": total_resolved,
        "total_orphaned": total_orphaned,
        "global_coverage_pct": round(
            total_resolved / max(total_refs, 1) * 100, 1),
        "unique_check_ids_in_frameworks": len(all_fw_check_ids),
        "unique_check_ids_in_registry": len(all_known_ids),
        "uncovered_scanner_checks": len(uncovered),
        "frameworks_with_saas": sum(
            1 for f in report["frameworks"].values() if f["has_saas"]),
        "frameworks_without_saas": sum(
            1 for f in report["frameworks"].values() if not f["has_saas"]),
        "frameworks_missing_oci": sum(
            1 for f in report["frameworks"].values()
            if "oci" in f["providers_missing_cloud"]),
        "frameworks_missing_alibaba": sum(
            1 for f in report["frameworks"].values()
            if "alibaba" in f["providers_missing_cloud"]),
    }

    report["recommendations"] = _build_recommendations(report)
    return report


def _build_recommendations(report: dict) -> list[str]:
    """Generate actionable recommendations from the validation report."""
    recs = []
    gs = report["global_stats"]

    if gs["total_orphaned"] > 0:
        recs.append(
            f"ORPHAN CHECK_IDS: {gs['total_orphaned']} check_id references in "
            f"frameworks do not resolve to any scanner implementation. These "
            f"produce no results in compliance reports. Fix by adding scanner "
            f"implementations or correcting the check_id strings."
        )

    if gs["frameworks_without_saas"] > 0:
        fw_names = [
            fw_key for fw_key, data in report["frameworks"].items()
            if not data["has_saas"]
        ]
        recs.append(
            f"SAAS GAP: {gs['frameworks_without_saas']} frameworks have ZERO "
            f"SaaS check mappings ({', '.join(fw_names)}). SaaS security "
            f"posture is invisible in compliance reports for these frameworks."
        )

    for fw_key, gap in report["saas_gap"].items():
        if gap["has_saas"] and gap["saas_coverage_pct"] < 20:
            recs.append(
                f"SHALLOW SAAS ({fw_key}): Only {gap['controls_with_saas']}/"
                f"{gap['controls_total']} controls ({gap['saas_coverage_pct']}%) "
                f"have SaaS mappings. Most SaaS checks are invisible."
            )

    if gs["frameworks_missing_oci"] > 0:
        recs.append(
            f"OCI GAP: {gs['frameworks_missing_oci']} frameworks have no OCI "
            f"check mappings."
        )

    if gs["frameworks_missing_alibaba"] > 0:
        recs.append(
            f"ALIBABA GAP: {gs['frameworks_missing_alibaba']} frameworks have "
            f"no Alibaba check mappings."
        )

    uncovered_total = gs["uncovered_scanner_checks"]
    if uncovered_total > 50:
        recs.append(
            f"UNCOVERED CHECKS: {uncovered_total} scanner check_ids are not "
            f"referenced by ANY framework. These produce scan results that "
            f"don't appear in any compliance report."
        )

    if gs["total_orphaned"] == 0 and gs["global_coverage_pct"] >= 99:
        recs.append(
            "EXCELLENT: All framework check_id references resolve to real "
            "scanner implementations."
        )

    return recs


# ──────────────────────────────────────────────────────────────────────
# Human-readable output
# ──────────────────────────────────────────────────────────────────────

def print_report(report: Optional[dict] = None) -> None:
    """Print human-readable framework validation report."""
    if report is None:
        report = validate_framework_references()

    if "error" in report:
        print(f"ERROR: {report['error']}")
        return

    print("=" * 78)
    print("D-ARCA Framework Check_ID Validation Report")
    print("=" * 78)

    gs = report["global_stats"]
    print(f"Frameworks:          {gs['total_frameworks']}")
    print(f"Framework controls:  {gs['total_framework_controls']}")
    print(f"Check_id references: {gs['total_check_refs']}")
    print(f"  Resolved:          {gs['total_resolved']} ({gs['global_coverage_pct']}%)")
    print(f"  Orphaned:          {gs['total_orphaned']}")
    print(f"Registry check_ids:  {gs['unique_check_ids_in_registry']}")
    print(f"Referenced by fw:    {gs['unique_check_ids_in_frameworks']}")
    print(f"Uncovered:           {gs['uncovered_scanner_checks']}")
    print()

    for fw_key, fw in sorted(report["frameworks"].items()):
        print(f"── {fw_key} ({fw['name'][:50]}) ──")
        print(f"  Controls:     {fw['total_controls']} "
              f"({fw['controls_without_checks']} without any checks)")
        print(f"  Check refs:   {fw['total_check_refs']} "
              f"(resolved: {fw['resolved']}, orphaned: {fw['orphaned']}, "
              f"coverage: {fw['coverage_pct']}%)")

        cloud_present = [p for p in fw["providers_present"]
                         if p in EXPECTED_CLOUD_PROVIDERS]
        saas_present = fw["saas_providers"]
        print(f"  Cloud:        {', '.join(cloud_present) or 'NONE'}")
        if fw["providers_missing_cloud"]:
            print(f"    MISSING:    {', '.join(fw['providers_missing_cloud'])}")
        print(f"  SaaS:         {', '.join(saas_present) or 'NONE'} "
              f"({fw['controls_with_saas']}/{fw['total_controls']} controls)")
        if fw["providers_missing_saas"]:
            print(f"    MISSING:    {', '.join(fw['providers_missing_saas'])}")

        for prov, pdata in sorted(fw["by_provider"].items()):
            status = "OK" if pdata["orphaned"] == 0 else f"{pdata['orphaned']} ORPHANED"
            print(f"    {prov:<20s} {pdata['total']:>4d} refs  "
                  f"({pdata['resolved']} ok, {status})")

        if fw["orphaned_ids"]:
            print(f"  Orphaned check_ids ({len(fw['orphaned_ids'])}):")
            for oid in fw["orphaned_ids"][:5]:
                print(f"    - {oid}")
            if len(fw["orphaned_ids"]) > 5:
                print(f"    ... +{len(fw['orphaned_ids']) - 5} more")
        print()

    print("── SaaS Gap Summary ──")
    for fw_key, gap in sorted(report["saas_gap"].items()):
        status = ("YES" if gap["has_saas"] else "NONE")
        prov_str = (', '.join(gap['saas_providers'])
                    if gap['saas_providers'] else '—')
        cov = f"{gap['controls_with_saas']}/{gap['controls_total']}"
        print(f"  {fw_key:<15s} SaaS: {status:<6s} "
              f"Providers: {prov_str:<40s} Controls: {cov}")
    print()

    print("── Cloud Gap Summary ──")
    for fw_key, gap in sorted(report["cloud_gap"].items()):
        present = ', '.join(gap['providers_present']) or '—'
        missing = ', '.join(gap['missing_cloud']) or '—'
        print(f"  {fw_key:<15s} Present: {present:<30s} Missing: {missing}")
    print()

    uc = report["uncovered_checks"]
    print(f"── Uncovered Scanner Checks: {uc['total']} ──")
    for prov, count in sorted(uc["by_provider"].items(), key=lambda x: -x[1]):
        samples = uc["sample_per_provider"].get(prov, [])
        sample_str = f"  (e.g. {', '.join(samples[:3])})" if samples else ""
        print(f"  {prov:<20s} {count:>4d} uncovered{sample_str}")
    print()

    print("── Recommendations ──")
    for i, rec in enumerate(report.get("recommendations", []), 1):
        print(f"  {i}. {rec}")
    print("=" * 78)
