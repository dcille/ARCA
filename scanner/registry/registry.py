"""Central check registry with cross-reference validation.

The registry is the single source of truth for check definitions.
MITRE ATT&CK and Ransomware Readiness remain separate modules with their
own mapping logic, but this registry can validate that every check_id
they reference actually exists.
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
    """Central registry that catalogs all available security checks.

    Usage::

        registry = get_default_registry()

        # Query checks
        aws_checks = registry.filter_by_provider("aws")
        critical   = registry.filter_by_severity("critical")

        # Validate MITRE/RR references
        orphans = registry.validate_mitre_references()
        rr_orphans = registry.validate_rr_references()

        # Cross-reference queries
        mitre_for_check = registry.get_mitre_techniques("aws_iam_001")
        rr_for_check    = registry.get_rr_rules("aws_iam_001")
    """

    def __init__(self) -> None:
        self._checks: dict[str, CheckDefinition] = {}
        self._custom_checks: set[str] = set()

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
        return check

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_check(self, check_id: str) -> Optional[CheckDefinition]:
        """Retrieve a check by ID, or None if not found."""
        return self._checks.get(check_id)

    def has_check(self, check_id: str) -> bool:
        return check_id in self._checks

    def list_checks(self, include_disabled: bool = False) -> list[CheckDefinition]:
        if include_disabled:
            return list(self._checks.values())
        return [c for c in self._checks.values() if c.enabled]

    def list_check_ids(self) -> set[str]:
        return set(self._checks.keys())

    def list_custom_checks(self) -> list[CheckDefinition]:
        return [self._checks[cid] for cid in self._custom_checks if cid in self._checks]

    @property
    def total_count(self) -> int:
        return len(self._checks)

    @property
    def enabled_count(self) -> int:
        return sum(1 for c in self._checks.values() if c.enabled)

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

    def filter_cloud_providers(self) -> list[CheckDefinition]:
        cloud_vals = {p.value for p in CLOUD_PROVIDERS}
        return [c for c in self._checks.values() if c.provider in cloud_vals and c.enabled]

    def filter_saas_providers(self) -> list[CheckDefinition]:
        saas_vals = {p.value for p in SAAS_PROVIDERS}
        return [c for c in self._checks.values() if c.provider in saas_vals and c.enabled]

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
            ]).lower()
            if q in searchable:
                results.append(chk)
        return results

    # ------------------------------------------------------------------
    # Cross-reference validation (MITRE & Ransomware Readiness)
    # ------------------------------------------------------------------

    def validate_mitre_references(self) -> dict:
        """Validate that all check_ids in MITRE CHECK_TO_MITRE exist in registry.

        Returns a dict with 'valid', 'orphaned' (in MITRE but not registry),
        and 'unmapped' (in registry but not MITRE) check_ids.
        """
        try:
            from scanner.mitre.attack_mapping import CHECK_TO_MITRE
        except ImportError:
            logger.warning("Could not import MITRE mappings for validation")
            return {"error": "MITRE module not available"}

        mitre_check_ids = set(CHECK_TO_MITRE.keys())
        registry_ids = self.list_check_ids()

        valid = mitre_check_ids & registry_ids
        orphaned = mitre_check_ids - registry_ids
        unmapped = registry_ids - mitre_check_ids

        return {
            "valid": len(valid),
            "orphaned_check_ids": sorted(orphaned),
            "unmapped_check_ids": sorted(unmapped),
            "coverage_pct": round(len(valid) / max(len(mitre_check_ids), 1) * 100, 1),
        }

    def validate_rr_references(self) -> dict:
        """Validate that all check_ids in Ransomware Readiness rules exist in registry.

        Returns a dict with validation results per domain.
        """
        try:
            from scanner.ransomware_readiness.framework import get_all_rules
        except ImportError:
            logger.warning("Could not import RR framework for validation")
            return {"error": "RR module not available"}

        registry_ids = self.list_check_ids()
        all_rr_check_ids: set[str] = set()
        orphaned: set[str] = set()
        by_domain: dict[str, dict] = {}

        for rule in get_all_rules():
            domain = rule.domain.value if hasattr(rule.domain, "value") else str(rule.domain)
            if domain not in by_domain:
                by_domain[domain] = {"total_refs": 0, "valid": 0, "orphaned": []}

            for provider, check_ids in rule.check_ids.items():
                for cid in check_ids:
                    all_rr_check_ids.add(cid)
                    by_domain[domain]["total_refs"] += 1
                    if cid in registry_ids:
                        by_domain[domain]["valid"] += 1
                    else:
                        by_domain[domain]["orphaned"].append(cid)
                        orphaned.add(cid)

        valid = all_rr_check_ids & registry_ids

        return {
            "valid": len(valid),
            "orphaned_check_ids": sorted(orphaned),
            "coverage_pct": round(len(valid) / max(len(all_rr_check_ids), 1) * 100, 1),
            "by_domain": by_domain,
        }

    def get_mitre_techniques(self, check_id: str) -> list[str]:
        """Return MITRE ATT&CK technique IDs mapped to a given check_id."""
        try:
            from scanner.mitre.attack_mapping import CHECK_TO_MITRE
        except ImportError:
            return []
        return CHECK_TO_MITRE.get(check_id, [])

    def get_rr_rules(self, check_id: str) -> list[str]:
        """Return Ransomware Readiness rule_ids that reference a given check_id."""
        try:
            from scanner.ransomware_readiness.framework import get_all_rules
        except ImportError:
            return []
        rule_ids = []
        for rule in get_all_rules():
            for provider_checks in rule.check_ids.values():
                if check_id in provider_checks:
                    rule_ids.append(rule.rule_id)
                    break
        return rule_ids

    # ------------------------------------------------------------------
    # Integrity report
    # ------------------------------------------------------------------

    def integrity_report(self) -> dict:
        """Full integrity report: registry stats + MITRE/RR cross-reference validation."""
        stats = self.generate_catalog_report()
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
            "by_provider": {},
            "by_severity": {},
            "by_category": {},
        }

        for chk in self._checks.values():
            prov = chk.provider
            if prov not in report["by_provider"]:
                report["by_provider"][prov] = {"total": 0, "by_service": {}}
            report["by_provider"][prov]["total"] += 1
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
        lines.append("=" * 90)
        lines.append("ARCA Cloud Security & SaaS Check Catalog")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        lines.append(f"Total checks: {self.total_count}  (enabled: {self.enabled_count})")
        lines.append("=" * 90)

        providers: dict[str, list[CheckDefinition]] = {}
        for chk in self._checks.values():
            providers.setdefault(chk.provider, []).append(chk)

        for prov in sorted(providers):
            checks = providers[prov]
            lines.append("")
            lines.append(f"--- {prov.upper()} ({len(checks)} checks) ---")
            for chk in sorted(checks, key=lambda c: c.check_id):
                lines.append(chk.summary())

        lines.append("")
        lines.append("=" * 90)
        return "\n".join(lines)

    def export_json(self) -> str:
        return json.dumps(self.generate_catalog_report(), indent=2)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_all_definitions(self) -> int:
        """Load check definitions from all provider definition modules."""
        total = 0
        definition_modules = [
            "scanner.registry.definitions.aws_checks",
            "scanner.registry.definitions.azure_checks",
            "scanner.registry.definitions.gcp_checks",
            "scanner.registry.definitions.oci_checks",
            "scanner.registry.definitions.alibaba_checks",
            "scanner.registry.definitions.ibm_cloud_checks",
            "scanner.registry.definitions.kubernetes_checks",
            "scanner.registry.definitions.m365_checks",
            "scanner.registry.definitions.github_checks",
            "scanner.registry.definitions.google_workspace_checks",
            "scanner.registry.definitions.salesforce_checks",
            "scanner.registry.definitions.servicenow_checks",
            "scanner.registry.definitions.snowflake_checks",
            "scanner.registry.definitions.cloudflare_checks",
            "scanner.registry.definitions.openstack_checks",
        ]

        for module_path in definition_modules:
            try:
                import importlib
                mod = importlib.import_module(module_path)
                checks = mod.get_checks()
                count = self.register_many(checks)
                total += count
                logger.debug("Loaded %d checks from %s", count, module_path)
            except ImportError as e:
                logger.warning("Could not load %s: %s", module_path, e)
            except Exception as e:
                logger.error("Error loading %s: %s", module_path, e)

        return total


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
