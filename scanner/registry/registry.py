"""Central check registry based on CIS Benchmark controls.

The registry is the single source of truth for check definitions.
Primary source: CIS controls (904 across 9 benchmarks).
Supplementary: scanner check_ids not covered by CIS.

MITRE ATT&CK and Ransomware Readiness remain separate modules with their
own mapping logic. This registry validates and resolves their references
through the scanner_check_ids bridge.

Resolution chain:
  MITRE check_id → scanner_check_id in registry → CIS control
  RR check_id → CHECK_ID_ALIASES → scanner_check_id in registry → CIS control
"""

import logging
import json
from datetime import datetime
from typing import Optional

from scanner.registry.models import (
    CheckDefinition,
    ProviderType,
    CLOUD_PROVIDERS,
    SAAS_PROVIDERS,
)

logger = logging.getLogger(__name__)


class CheckRegistry:
    """Central registry cataloging all security checks.

    Based on CIS Benchmark controls as primary entries, with scanner
    check_ids mapped to each control. Provides cross-reference validation
    and resolution for MITRE ATT&CK and Ransomware Readiness modules.
    """

    def __init__(self) -> None:
        self._checks: dict[str, CheckDefinition] = {}
        self._custom_checks: set[str] = set()
        # Reverse index: scanner_check_id → registry check_id
        self._scanner_index: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_check(self, check: CheckDefinition, custom: bool = False) -> None:
        if check.check_id in self._checks:
            raise ValueError(
                f"Check '{check.check_id}' is already registered. "
                "Use a unique check_id or unregister first."
            )
        self._checks[check.check_id] = check
        if custom:
            self._custom_checks.add(check.check_id)
        # Build scanner reverse index
        for sid in check.scanner_check_ids:
            if sid not in self._scanner_index:
                self._scanner_index[sid] = check.check_id
        logger.debug("Registered check %s (custom=%s)", check.check_id, custom)

    def register_many(self, checks: list[CheckDefinition], custom: bool = False) -> int:
        count = 0
        for chk in checks:
            try:
                self.register_check(chk, custom=custom)
                count += 1
            except ValueError as exc:
                logger.warning("Skipping check: %s", exc)
        return count

    def unregister_check(self, check_id: str) -> CheckDefinition:
        if check_id not in self._checks:
            raise KeyError(f"Check '{check_id}' not found in registry.")
        check = self._checks.pop(check_id)
        self._custom_checks.discard(check_id)
        # Clean up scanner index
        for sid in check.scanner_check_ids:
            self._scanner_index.pop(sid, None)
        return check

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_check(self, check_id: str) -> Optional[CheckDefinition]:
        """Retrieve a check by its registry ID, or None if not found."""
        return self._checks.get(check_id)

    def find_by_scanner_id(self, scanner_check_id: str) -> Optional[CheckDefinition]:
        """Find the registry entry that contains this scanner_check_id.

        This is the key resolution method for MITRE/RR references:
        given a scanner check_id, find which CIS control it maps to.
        """
        # Direct match (supplementary checks use themselves as check_id)
        if scanner_check_id in self._checks:
            return self._checks[scanner_check_id]
        # Reverse index lookup
        registry_id = self._scanner_index.get(scanner_check_id)
        if registry_id:
            return self._checks.get(registry_id)
        return None

    def has_check(self, check_id: str) -> bool:
        return check_id in self._checks

    def has_scanner_id(self, scanner_check_id: str) -> bool:
        """Check if a scanner check_id is known (either as registry ID or in scanner_check_ids)."""
        return scanner_check_id in self._checks or scanner_check_id in self._scanner_index

    def list_checks(self, include_disabled: bool = False) -> list[CheckDefinition]:
        if include_disabled:
            return list(self._checks.values())
        return [c for c in self._checks.values() if c.enabled]

    def list_check_ids(self) -> set[str]:
        """Return all registry check_ids."""
        return set(self._checks.keys())

    def list_all_scanner_ids(self) -> set[str]:
        """Return all known scanner check_ids (from scanner_check_ids fields + supplementary)."""
        ids = set(self._scanner_index.keys())
        # Supplementary checks use their scanner ID as the registry ID
        for chk in self._checks.values():
            if chk.source == "scanner":
                ids.add(chk.check_id)
        return ids

    def list_custom_checks(self) -> list[CheckDefinition]:
        return [self._checks[cid] for cid in self._custom_checks if cid in self._checks]

    @property
    def total_count(self) -> int:
        return len(self._checks)

    @property
    def enabled_count(self) -> int:
        return sum(1 for c in self._checks.values() if c.enabled)

    @property
    def cis_count(self) -> int:
        return sum(1 for c in self._checks.values() if c.source == "cis")

    @property
    def supplementary_count(self) -> int:
        return sum(1 for c in self._checks.values() if c.source == "scanner")

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def filter_by_provider(
        self, provider: str, service: Optional[str] = None
    ) -> list[CheckDefinition]:
        result = [c for c in self._checks.values() if c.provider == provider and c.enabled]
        if service:
            result = [c for c in result if c.service.lower() == service.lower()]
        return result

    def filter_by_severity(self, severity: str) -> list[CheckDefinition]:
        return [c for c in self._checks.values() if c.severity == severity and c.enabled]

    def filter_by_category(self, category: str) -> list[CheckDefinition]:
        cat_lower = category.lower()
        return [c for c in self._checks.values() if c.category.lower() == cat_lower and c.enabled]

    def filter_by_tags(self, tags: list[str], match_all: bool = False) -> list[CheckDefinition]:
        tag_set = {t.lower() for t in tags}
        results: list[CheckDefinition] = []
        for chk in self._checks.values():
            chk_tags = {t.lower() for t in chk.tags}
            if match_all:
                if tag_set.issubset(chk_tags):
                    results.append(chk)
            else:
                if tag_set & chk_tags:
                    results.append(chk)
        return results

    def filter_by_compliance(self, framework: str) -> list[CheckDefinition]:
        fw_lower = framework.lower()
        return [
            c for c in self._checks.values()
            if any(fw_lower in m.lower() for m in c.compliance_mappings)
        ]

    def filter_cis_controls(self) -> list[CheckDefinition]:
        return [c for c in self._checks.values() if c.source == "cis" and c.enabled]

    def filter_supplementary(self) -> list[CheckDefinition]:
        return [c for c in self._checks.values() if c.source == "scanner" and c.enabled]

    def filter_cloud_providers(self) -> list[CheckDefinition]:
        cloud_vals = {p.value for p in CLOUD_PROVIDERS}
        return [c for c in self._checks.values() if c.provider in cloud_vals and c.enabled]

    def filter_saas_providers(self) -> list[CheckDefinition]:
        saas_vals = {p.value for p in SAAS_PROVIDERS}
        return [c for c in self._checks.values() if c.provider in saas_vals and c.enabled]

    def filter_rr_relevant(self) -> list[CheckDefinition]:
        return [c for c in self._checks.values() if c.rr_relevant and c.enabled]

    def filter_by_rr_domain(self, domain: str) -> list[CheckDefinition]:
        return [c for c in self._checks.values() if domain in c.rr_domains and c.enabled]

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search_checks(self, query: str) -> list[CheckDefinition]:
        q = query.lower()
        results: list[CheckDefinition] = []
        for chk in self._checks.values():
            searchable = " ".join([
                chk.check_id, chk.title, chk.description,
                chk.service, chk.category, " ".join(chk.tags),
                chk.cis_id or "", " ".join(chk.scanner_check_ids),
            ]).lower()
            if q in searchable:
                results.append(chk)
        return results

    # ------------------------------------------------------------------
    # Cross-reference validation (MITRE & Ransomware Readiness)
    # ------------------------------------------------------------------

    def validate_mitre_references(self) -> dict:
        """Validate MITRE CHECK_TO_MITRE references against the registry.

        Uses the scanner_check_ids reverse index — a MITRE reference is
        considered 'resolved' if its check_id exists as either:
        - A registry check_id (supplementary scanner check), OR
        - A scanner_check_id within any CIS control entry
        """
        try:
            from scanner.mitre.attack_mapping import CHECK_TO_MITRE
        except ImportError:
            return {"error": "MITRE module not available"}

        mitre_check_ids = set(CHECK_TO_MITRE.keys())
        all_known_ids = self.list_all_scanner_ids() | self.list_check_ids()

        resolved = mitre_check_ids & all_known_ids
        orphaned = mitre_check_ids - all_known_ids

        return {
            "total_references": len(mitre_check_ids),
            "resolved": len(resolved),
            "orphaned": len(orphaned),
            "orphaned_check_ids": sorted(orphaned),
            "coverage_pct": round(len(resolved) / max(len(mitre_check_ids), 1) * 100, 1),
        }

    def validate_rr_references(self) -> dict:
        """Validate Ransomware Readiness references against the registry.

        Uses the full resolution chain:
        RR check_id → CHECK_ID_ALIASES → scanner_check_id → registry

        A reference is 'resolved' if it or its alias target exists in
        the registry's scanner_check_ids.
        """
        try:
            from scanner.ransomware_readiness.framework import get_all_rules
        except ImportError:
            return {"error": "RR module not available"}

        # Load aliases for resolution
        try:
            from scanner.ransomware_readiness.evaluator import CHECK_ID_ALIASES
        except ImportError:
            CHECK_ID_ALIASES = {}

        all_known_ids = self.list_all_scanner_ids() | self.list_check_ids()
        all_rr_ids: set[str] = set()
        resolved: set[str] = set()
        orphaned: set[str] = set()
        by_domain: dict[str, dict] = {}

        for rule in get_all_rules():
            domain = rule.domain.value if hasattr(rule.domain, "value") else str(rule.domain)
            if domain not in by_domain:
                by_domain[domain] = {"rules": 0, "check_refs": 0, "resolved": 0, "orphaned": []}
            by_domain[domain]["rules"] += 1

            for provider, check_ids in rule.check_ids.items():
                for cid in check_ids:
                    all_rr_ids.add(cid)
                    by_domain[domain]["check_refs"] += 1

                    # Direct match
                    if cid in all_known_ids:
                        resolved.add(cid)
                        by_domain[domain]["resolved"] += 1
                        continue

                    # Alias resolution
                    alias_targets = CHECK_ID_ALIASES.get(cid, [])
                    if any(t in all_known_ids for t in alias_targets):
                        resolved.add(cid)
                        by_domain[domain]["resolved"] += 1
                        continue

                    # Special markers (not actual checks)
                    if cid.startswith("__") and cid.endswith("__"):
                        resolved.add(cid)
                        by_domain[domain]["resolved"] += 1
                        continue

                    orphaned.add(cid)
                    by_domain[domain]["orphaned"].append(cid)

        return {
            "total_references": len(all_rr_ids),
            "resolved": len(resolved),
            "orphaned": len(orphaned),
            "orphaned_check_ids": sorted(orphaned),
            "coverage_pct": round(len(resolved) / max(len(all_rr_ids), 1) * 100, 1),
            "by_domain": by_domain,
        }

    def get_mitre_techniques(self, check_id: str) -> list[str]:
        """Return MITRE technique IDs for a check_id (registry or scanner)."""
        try:
            from scanner.mitre.attack_mapping import CHECK_TO_MITRE
        except ImportError:
            return []

        # Direct lookup
        techs = CHECK_TO_MITRE.get(check_id, [])
        if techs:
            return techs

        # If it's a CIS control, check its scanner_check_ids
        chk = self._checks.get(check_id)
        if chk:
            all_techs = set()
            for sid in chk.scanner_check_ids:
                all_techs.update(CHECK_TO_MITRE.get(sid, []))
            return sorted(all_techs)

        return []

    def get_rr_rules(self, check_id: str) -> list[str]:
        """Return RR rule_ids that reference a check_id (direct or via scanner mapping)."""
        try:
            from scanner.ransomware_readiness.framework import get_all_rules
        except ImportError:
            return []

        # Collect all IDs to search for
        search_ids = {check_id}
        chk = self._checks.get(check_id)
        if chk:
            search_ids.update(chk.scanner_check_ids)

        rule_ids = []
        for rule in get_all_rules():
            for provider_checks in rule.check_ids.values():
                if search_ids & set(provider_checks):
                    rule_ids.append(rule.rule_id)
                    break
        return rule_ids

    # ------------------------------------------------------------------
    # Integrity report
    # ------------------------------------------------------------------

    def integrity_report(self) -> dict:
        """Full integrity report with cross-reference validation."""
        stats = self.generate_catalog_report()
        stats["cis_controls"] = self.cis_count
        stats["supplementary_scanner_checks"] = self.supplementary_count
        stats["total_scanner_ids_indexed"] = len(self._scanner_index)
        stats["mitre_validation"] = self.validate_mitre_references()
        stats["rr_validation"] = self.validate_rr_references()
        return stats

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_catalog_report(self) -> dict:
        report: dict = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_checks": self.total_count,
            "enabled_checks": self.enabled_count,
            "disabled_checks": self.total_count - self.enabled_count,
            "custom_checks": len(self._custom_checks),
            "by_source": {"cis": self.cis_count, "scanner": self.supplementary_count},
            "by_provider": {},
            "by_severity": {},
            "by_category": {},
        }

        for chk in self._checks.values():
            prov = chk.provider
            if prov not in report["by_provider"]:
                report["by_provider"][prov] = {"total": 0, "cis": 0, "scanner": 0, "by_service": {}}
            report["by_provider"][prov]["total"] += 1
            report["by_provider"][prov][chk.source] = report["by_provider"][prov].get(chk.source, 0) + 1
            svc = chk.service
            report["by_provider"][prov]["by_service"][svc] = (
                report["by_provider"][prov]["by_service"].get(svc, 0) + 1
            )
            report["by_severity"][chk.severity] = (
                report["by_severity"].get(chk.severity, 0) + 1
            )
            report["by_category"][chk.category] = (
                report["by_category"].get(chk.category, 0) + 1
            )

        return report

    def generate_catalog_text(self) -> str:
        lines: list[str] = []
        lines.append("=" * 100)
        lines.append("ARCA Security Check Registry (CIS-based)")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        lines.append(f"Total: {self.total_count} checks "
                     f"(CIS: {self.cis_count}, Supplementary: {self.supplementary_count})")
        lines.append("=" * 100)

        providers: dict[str, list[CheckDefinition]] = {}
        for chk in self._checks.values():
            providers.setdefault(chk.provider, []).append(chk)

        for prov in sorted(providers):
            checks = providers[prov]
            cis_n = sum(1 for c in checks if c.source == "cis")
            sup_n = sum(1 for c in checks if c.source == "scanner")
            lines.append("")
            lines.append(f"--- {prov.upper()} ({len(checks)} checks: {cis_n} CIS + {sup_n} supplementary) ---")
            for chk in sorted(checks, key=lambda c: c.check_id):
                lines.append(chk.summary())

        lines.append("")
        lines.append("=" * 100)
        return "\n".join(lines)

    def export_json(self) -> str:
        return json.dumps(self.generate_catalog_report(), indent=2)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_all_definitions(self) -> int:
        """Load CIS controls + supplementary scanner checks."""
        from scanner.registry.cis_loader import load_all_cis_checks

        checks = load_all_cis_checks()
        return self.register_many(checks)


# ======================================================================
# Module-level singleton
# ======================================================================

_default_registry: Optional[CheckRegistry] = None


def get_default_registry() -> CheckRegistry:
    """Return (and lazily initialise) the module-level default registry."""
    global _default_registry
    if _default_registry is None:
        _default_registry = CheckRegistry()
        _default_registry.load_all_definitions()
    return _default_registry


def reset_default_registry() -> None:
    """Reset the singleton — useful for testing."""
    global _default_registry
    _default_registry = None
