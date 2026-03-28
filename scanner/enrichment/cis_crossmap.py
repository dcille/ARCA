"""CIS benchmark to compliance framework cross-reference map.

Provides bidirectional lookup between CIS benchmark sections and
regulatory/industry framework controls, enabling:
  - Given a CIS check → which framework controls does it satisfy?
  - Given a framework control → which CIS checks cover it?

The mappings are derived from official compliance matrices published by
CIS and supplemented with ARCA-specific scanner check_id resolution.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Supported frameworks
# ──────────────────────────────────────────────────────────────────────

SUPPORTED_FRAMEWORKS = frozenset({"ENS", "GDPR", "HIPAA", "PCI-DSS-v4.0", "SOC2"})

# ──────────────────────────────────────────────────────────────────────
# CIS Section → Framework Control cross-references
# ──────────────────────────────────────────────────────────────────────

# Maps CIS benchmark section patterns to framework control IDs.
# The key is a CIS section prefix (e.g., "1." for IAM, "2." for Logging).
# Patterns are matched against CIS check IDs from the registry.

CIS_TO_FRAMEWORK: dict[str, dict[str, list[str]]] = {
    # CIS Section 1 (IAM/Identity) → framework controls
    "iam": {
        "ENS": ["op.acc.1", "op.acc.2", "op.acc.3", "op.acc.4", "op.acc.5", "op.acc.6"],
        "GDPR": ["Art.5(1)(b)", "Art.5(1)(f)", "Art.25(1)", "Art.32(1)"],
        "HIPAA": ["164.308(a)(3)(i)", "164.308(a)(4)(i)", "164.312(a)(1)", "164.312(d)"],
        "PCI-DSS-v4.0": ["7.2.1", "7.2.2", "7.2.3", "8.2.1", "8.3.1", "8.3.6"],
        "SOC2": ["CC6.1", "CC6.2", "CC6.3"],
    },
    # CIS Section 2 (Logging/Monitoring)
    "logging": {
        "ENS": ["op.exp.8", "op.exp.9", "op.exp.10", "op.mon.1", "op.mon.2", "op.mon.3"],
        "GDPR": ["Art.5(1)(a)", "Art.30(1)", "Art.33(1)"],
        "HIPAA": ["164.308(a)(1)(ii)(D)", "164.312(b)", "164.316(b)"],
        "PCI-DSS-v4.0": ["10.2.1", "10.2.2", "10.3.1", "10.4.1", "10.6.1", "10.7.1"],
        "SOC2": ["CC7.1", "CC7.2", "CC7.3"],
    },
    # CIS Section 3 (Networking)
    "networking": {
        "ENS": ["op.pl.2", "mp.com.1", "mp.com.2", "mp.com.3", "mp.com.4"],
        "GDPR": ["Art.32(1)"],
        "HIPAA": ["164.312(a)(1)", "164.312(e)(1)", "164.312(e)(2)"],
        "PCI-DSS-v4.0": ["1.2.1", "1.2.5", "1.3.1", "1.3.2", "1.4.1"],
        "SOC2": ["CC6.6", "CC6.7"],
    },
    # CIS Section 4 (Encryption/Data Protection)
    "encryption": {
        "ENS": ["mp.info.3", "mp.si.2", "mp.com.2"],
        "GDPR": ["Art.5(1)(f)", "Art.32(1)", "Art.34(3)(a)"],
        "HIPAA": ["164.312(a)(2)", "164.312(e)(2)"],
        "PCI-DSS-v4.0": ["3.4.1", "3.5.1", "4.2.1"],
        "SOC2": ["CC6.1", "CC6.7", "C1.1"],
    },
    # CIS Section 5 (Storage)
    "storage": {
        "ENS": ["mp.info.7", "mp.si.3"],
        "GDPR": ["Art.5(1)(c)", "Art.5(1)(e)", "Art.5(1)(f)"],
        "HIPAA": ["164.310(d)(1)", "164.312(c)(1)"],
        "PCI-DSS-v4.0": ["3.1.1", "3.3.1", "9.4.1"],
        "SOC2": ["CC6.1", "CC6.5"],
    },
    # CIS Section 6 (Database)
    "database": {
        "ENS": ["mp.info.3", "mp.info.1"],
        "GDPR": ["Art.5(1)(c)", "Art.5(1)(f)", "Art.25(1)"],
        "HIPAA": ["164.312(a)(2)", "164.312(c)(1)", "164.312(e)(2)"],
        "PCI-DSS-v4.0": ["3.4.1", "3.5.1", "6.2.1"],
        "SOC2": ["CC6.1", "C1.1", "C1.2"],
    },
    # CIS Section 7 (Compute/VM)
    "compute": {
        "ENS": ["op.exp.2", "op.exp.4", "op.acc.7"],
        "GDPR": ["Art.32(1)"],
        "HIPAA": ["164.310(a)(1)", "164.310(c)"],
        "PCI-DSS-v4.0": ["2.2.1", "5.2.1", "6.3.1"],
        "SOC2": ["CC6.1", "CC6.8", "CC8.1"],
    },
    # CIS Section 8 (Vulnerability/Detection)
    "detection": {
        "ENS": ["op.exp.6", "op.exp.7", "op.mon.1"],
        "GDPR": ["Art.32(1)", "Art.33(1)"],
        "HIPAA": ["164.308(a)(1)(i)", "164.308(a)(6)(i)"],
        "PCI-DSS-v4.0": ["5.2.1", "5.2.2", "11.3.1", "11.4.1"],
        "SOC2": ["CC7.1", "CC7.2", "CC7.4"],
    },
    # CIS Section 9 (Backup/DR)
    "backup": {
        "ENS": ["op.cont.1", "op.cont.2", "op.cont.3", "mp.info.7"],
        "GDPR": ["Art.32(1)"],
        "HIPAA": ["164.308(a)(7)(i)", "164.308(a)(7)(ii)(A)", "164.310(a)(2)"],
        "PCI-DSS-v4.0": ["9.4.1", "12.10.1"],
        "SOC2": ["A1.1", "A1.2", "A1.3"],
    },
}

# ──────────────────────────────────────────────────────────────────────
# Reverse index: Framework Control → CIS domains
# Built once at module load time for O(1) lookups.
# ──────────────────────────────────────────────────────────────────────

_FRAMEWORK_TO_DOMAINS: dict[str, dict[str, list[str]]] = {}


def _build_reverse_index() -> None:
    """Populate _FRAMEWORK_TO_DOMAINS from CIS_TO_FRAMEWORK."""
    for domain, frameworks in CIS_TO_FRAMEWORK.items():
        for fw_key, control_ids in frameworks.items():
            if fw_key not in _FRAMEWORK_TO_DOMAINS:
                _FRAMEWORK_TO_DOMAINS[fw_key] = {}
            for ctrl in control_ids:
                _FRAMEWORK_TO_DOMAINS[fw_key].setdefault(ctrl, [])
                if domain not in _FRAMEWORK_TO_DOMAINS[fw_key][ctrl]:
                    _FRAMEWORK_TO_DOMAINS[fw_key][ctrl].append(domain)


_build_reverse_index()

# ──────────────────────────────────────────────────────────────────────
# Domain classification heuristics
# ──────────────────────────────────────────────────────────────────────

# Each entry is (domain_key, category_patterns, check_id_patterns).
# category_patterns are matched case-insensitively against the check's category.
# check_id_patterns are matched case-insensitively against the check's check_id.
# Order matters: first match wins.

_DOMAIN_HEURISTICS: list[tuple[str, list[str], list[str]]] = [
    (
        "iam",
        ["Identity", "IAM"],
        ["iam"],
    ),
    (
        "logging",
        ["Logging"],
        ["log", "audit", "trail"],
    ),
    (
        "networking",
        ["Networking"],
        ["vpc", "firewall", "nsg", "sg_"],
    ),
    (
        "encryption",
        ["Encryption"],
        ["encrypt", "cmk", "kms", "tls"],
    ),
    (
        "storage",
        ["Storage"],
        ["s3_", "storage", "bucket"],
    ),
    (
        "database",
        ["Database"],
        ["rds_", "sql_", "db_"],
    ),
    (
        "compute",
        ["Compute"],
        ["ec2_", "vm_", "compute"],
    ),
    (
        "detection",
        ["Detection"],
        ["guard", "defender", "scc"],
    ),
    (
        "backup",
        ["Backup"],
        ["backup", "recovery", "replication"],
    ),
]


def classify_check_domain(
    check_id: str,
    category: str,
    service: Optional[str] = None,
) -> Optional[str]:
    """Determine the CIS security domain for a check using heuristics.

    Args:
        check_id: The canonical check identifier.
        category: The check's category string (e.g. "Identity", "Logging").
        service: Optional service name (currently unused but reserved for
                 future refinement).

    Returns:
        A domain key from CIS_TO_FRAMEWORK (e.g. "iam", "logging") or
        None if no heuristic matches.
    """
    check_id_lower = check_id.lower()
    category_lower = category.lower() if category else ""

    for domain, cat_patterns, id_patterns in _DOMAIN_HEURISTICS:
        # Check category patterns
        for pat in cat_patterns:
            if pat.lower() in category_lower:
                return domain
        # Check check_id patterns
        for pat in id_patterns:
            if pat.lower() in check_id_lower:
                return domain

    return None


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────


def get_framework_controls_for_domain(domain: str, framework_key: str) -> list[str]:
    """Get framework controls for a CIS security domain.

    Args:
        domain: A CIS domain key (e.g. "iam", "logging", "networking").
        framework_key: A framework identifier (e.g. "ENS", "GDPR", "SOC2").

    Returns:
        List of framework control IDs, or an empty list if the domain or
        framework is not found.
    """
    domain_entry = CIS_TO_FRAMEWORK.get(domain)
    if domain_entry is None:
        logger.debug("Unknown CIS domain: %s", domain)
        return []
    controls = domain_entry.get(framework_key, [])
    if not controls:
        logger.debug(
            "No %s controls mapped for CIS domain '%s'", framework_key, domain
        )
    return list(controls)


def get_domains_for_control(framework_key: str, control_id: str) -> list[str]:
    """Get CIS security domains that map to a framework control.

    Args:
        framework_key: A framework identifier (e.g. "HIPAA", "PCI-DSS-v4.0").
        control_id: A framework control ID (e.g. "164.312(a)(1)", "CC6.1").

    Returns:
        List of CIS domain keys (e.g. ["iam", "networking"]), or an empty
        list if no mapping exists.
    """
    fw_controls = _FRAMEWORK_TO_DOMAINS.get(framework_key)
    if fw_controls is None:
        logger.debug("Unknown framework: %s", framework_key)
        return []
    domains = fw_controls.get(control_id, [])
    if not domains:
        logger.debug(
            "No CIS domains mapped for %s control '%s'", framework_key, control_id
        )
    return list(domains)


def build_check_to_framework_map(
    registry=None,
) -> dict[str, dict[str, list[str]]]:
    """Build a mapping from scanner check_ids to framework controls.

    Uses the registry to resolve check_ids to CIS sections, then maps
    CIS sections to framework controls via CIS_TO_FRAMEWORK.

    Args:
        registry: A ``CheckRegistry`` instance.  If *None* the function
            attempts to import and use the default global registry.

    Returns:
        ``{ check_id: { framework_key: [control_ids] } }``
    """
    if registry is None:
        try:
            from scanner.registry.registry import CheckRegistry

            registry = CheckRegistry()
            logger.warning(
                "build_check_to_framework_map called without a registry; "
                "using an empty CheckRegistry. Pass a populated registry "
                "for meaningful results."
            )
        except ImportError:
            logger.error("Cannot import CheckRegistry; returning empty map.")
            return {}

    result: dict[str, dict[str, list[str]]] = {}

    for check in registry.list_checks(include_disabled=False):
        domain = classify_check_domain(
            check_id=check.check_id,
            category=check.category,
            service=check.service,
        )
        if domain is None:
            logger.debug(
                "Check %s (category=%s) did not match any CIS domain; skipping.",
                check.check_id,
                check.category,
            )
            continue

        frameworks = CIS_TO_FRAMEWORK.get(domain, {})
        if not frameworks:
            continue

        check_frameworks: dict[str, list[str]] = {}
        for fw_key, controls in frameworks.items():
            check_frameworks[fw_key] = list(controls)

        result[check.check_id] = check_frameworks

    logger.info(
        "Built check-to-framework map: %d checks mapped across %d domains.",
        len(result),
        len({
            classify_check_domain(c.check_id, c.category, c.service)
            for c in registry.list_checks(include_disabled=False)
            if classify_check_domain(c.check_id, c.category, c.service) is not None
        }),
    )
    return result


def print_crossmap_report(registry=None) -> None:
    """Print human-readable cross-map report.

    Produces a summary of CIS domain-to-framework mappings, and if a
    registry is provided, includes per-check resolution statistics.

    Args:
        registry: Optional ``CheckRegistry`` instance.  When provided the
            report includes check-level mapping statistics.
    """
    border = "=" * 72

    print(border)
    print("  ARCA CIS Cross-Reference Map Report")
    print(border)
    print()

    # ── Section 1: Domain → Framework summary ──
    print("CIS Domain → Framework Control Summary")
    print("-" * 72)
    for domain, frameworks in CIS_TO_FRAMEWORK.items():
        print(f"\n  [{domain.upper()}]")
        for fw_key in sorted(frameworks.keys()):
            controls = frameworks[fw_key]
            print(f"    {fw_key:<16s}  {len(controls):>3d} controls  {', '.join(controls)}")
    print()

    # ── Section 2: Framework → Domain reverse summary ──
    print("Framework Control → CIS Domain Reverse Index")
    print("-" * 72)
    for fw_key in sorted(_FRAMEWORK_TO_DOMAINS.keys()):
        controls = _FRAMEWORK_TO_DOMAINS[fw_key]
        print(f"\n  [{fw_key}]  ({len(controls)} controls)")
        for ctrl_id in sorted(controls.keys()):
            domains = controls[ctrl_id]
            print(f"    {ctrl_id:<30s} → {', '.join(domains)}")
    print()

    # ── Section 3: Registry-based check mapping stats ──
    if registry is not None:
        check_map = build_check_to_framework_map(registry)
        all_checks = registry.list_checks(include_disabled=False)
        mapped_count = len(check_map)
        total_count = len(all_checks)
        unmapped_count = total_count - mapped_count

        print("Check-to-Framework Mapping Statistics")
        print("-" * 72)
        print(f"  Total enabled checks:   {total_count}")
        print(f"  Mapped to frameworks:   {mapped_count}")
        print(f"  Unmapped:               {unmapped_count}")
        print()

        # Per-domain breakdown
        domain_counts: dict[str, int] = {}
        for check in all_checks:
            domain = classify_check_domain(
                check.check_id, check.category, check.service
            )
            if domain:
                domain_counts[domain] = domain_counts.get(domain, 0) + 1

        if domain_counts:
            print("  Per-domain check counts:")
            for domain in sorted(domain_counts.keys()):
                fw_count = len(CIS_TO_FRAMEWORK.get(domain, {}))
                print(
                    f"    {domain:<16s}  {domain_counts[domain]:>4d} checks  "
                    f"→ {fw_count} frameworks"
                )
            print()

        # List unmapped checks
        if unmapped_count > 0:
            print(f"  Unmapped checks ({unmapped_count}):")
            for check in all_checks:
                if check.check_id not in check_map:
                    print(f"    - {check.check_id} (category={check.category})")
            print()
    else:
        print("(No registry provided -- skipping check-level statistics.)")
        print()

    print(border)
    print("  End of report")
    print(border)
