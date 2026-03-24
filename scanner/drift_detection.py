"""Configuration drift detection for cloud resources.

Captures point-in-time resource state baselines, compares current state against
baselines to detect configuration drift, classifies drift severity, and
generates reports with remediation suggestions.

Only uses Python standard library imports.
"""

import copy
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


# ======================================================================
# Data classes
# ======================================================================

@dataclass
class ResourceState:
    """Point-in-time snapshot of a single cloud resource configuration."""

    resource_id: str
    resource_type: str
    provider: str
    region: str
    configuration: dict
    captured_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: dict = field(default_factory=dict)
    checksum: str = ""

    def __post_init__(self) -> None:
        if not self.checksum:
            self.checksum = self._compute_checksum()

    def _compute_checksum(self) -> str:
        blob = json.dumps(self.configuration, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


@dataclass
class DriftResult:
    """Describes a single piece of configuration drift between baseline and current state."""

    resource_id: str
    resource_type: str
    drift_type: str  # added | removed | modified
    field_path: str
    expected_value: object
    actual_value: object
    severity: str = "medium"
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    drift_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    provider: str = ""
    region: str = ""
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        valid_types = {"added", "removed", "modified"}
        if self.drift_type not in valid_types:
            raise ValueError(
                f"Invalid drift_type '{self.drift_type}'. "
                f"Must be one of: {', '.join(sorted(valid_types))}"
            )

    def to_dict(self) -> dict:
        return {
            "drift_id": self.drift_id,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "drift_type": self.drift_type,
            "field_path": self.field_path,
            "expected_value": _safe_serialize(self.expected_value),
            "actual_value": _safe_serialize(self.actual_value),
            "severity": self.severity,
            "detected_at": self.detected_at,
            "provider": self.provider,
            "region": self.region,
            "tags": self.tags,
        }

    def summary(self) -> str:
        return (
            f"[{self.severity.upper():>8s}] {self.drift_type:<8s} "
            f"{self.resource_id} -> {self.field_path}"
        )


# ======================================================================
# Helpers
# ======================================================================

def _safe_serialize(value: object) -> object:
    """Best-effort JSON-safe conversion of a value."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    try:
        json.dumps(value, default=str)
        return value
    except (TypeError, ValueError):
        return str(value)


# Mapping of sensitive/critical configuration fields to severity overrides.
_CRITICAL_FIELDS: set[str] = {
    "public_access", "publicly_accessible", "encryption", "encrypted",
    "ssl_enabled", "tls_enabled", "mfa", "mfa_enabled",
    "iam_policy", "policy", "acl", "access_control",
    "firewall_rules", "security_groups", "network_acls",
    "kms_key", "kms_key_id", "logging", "audit_logging",
    "backup_enabled", "deletion_protection",
}

_HIGH_FIELDS: set[str] = {
    "instance_type", "machine_type", "sku", "size",
    "port", "ports", "protocol", "cidr",
    "subnet", "vpc", "vnet", "network",
    "tags", "labels", "retention", "versioning",
    "auto_scaling", "min_count", "max_count",
}


# ======================================================================
# Drift detector
# ======================================================================

class DriftDetector:
    """Detects configuration drift between baseline and current resource states.

    Usage::

        detector = DriftDetector()
        detector.capture_baseline(resource_states)
        # ... time passes and resources change ...
        drifts = detector.detect_drift(current_states)
        report = detector.generate_drift_report()
    """

    def __init__(self) -> None:
        self._baseline: dict[str, ResourceState] = {}
        self._baseline_captured_at: Optional[str] = None
        self._history: list[dict] = []  # list of detection runs
        self._current_drifts: list[DriftResult] = []

    def capture_baseline(self, resources: list[ResourceState]) -> int:
        """Snapshot the current resource configurations as the baseline.

        Args:
            resources: List of ResourceState objects representing current state.

        Returns:
            Number of resources captured.
        """
        self._baseline.clear()
        for rs in resources:
            self._baseline[rs.resource_id] = copy.deepcopy(rs)
        self._baseline_captured_at = datetime.utcnow().isoformat()
        logger.info(
            "Baseline captured: %d resources at %s",
            len(self._baseline), self._baseline_captured_at,
        )
        return len(self._baseline)

    def update_baseline_resource(self, resource: ResourceState) -> None:
        """Update or add a single resource in the existing baseline."""
        self._baseline[resource.resource_id] = copy.deepcopy(resource)
        logger.debug("Updated baseline for %s", resource.resource_id)

    def remove_baseline_resource(self, resource_id: str) -> None:
        """Remove a resource from the baseline."""
        self._baseline.pop(resource_id, None)

    def get_baseline(self) -> dict[str, ResourceState]:
        """Return a copy of the current baseline."""
        return copy.deepcopy(self._baseline)

    @property
    def baseline_size(self) -> int:
        return len(self._baseline)

    @property
    def baseline_captured_at(self) -> Optional[str]:
        return self._baseline_captured_at

    def detect_drift(
        self,
        current_states: list[ResourceState],
        baseline: Optional[dict[str, ResourceState]] = None,
    ) -> list[DriftResult]:
        """Compare current state against baseline and return drift results.

        Args:
            current_states: Current resource configurations.
            baseline: Optional explicit baseline. Falls back to captured baseline.

        Returns:
            List of DriftResult objects describing every detected change.

        Raises:
            RuntimeError: If no baseline is available.
        """
        base = baseline if baseline is not None else self._baseline
        if not base:
            raise RuntimeError(
                "No baseline available. Call capture_baseline() first."
            )

        drifts: list[DriftResult] = []
        current_map: dict[str, ResourceState] = {rs.resource_id: rs for rs in current_states}
        detection_time = datetime.utcnow().isoformat()

        # Check for removed resources (in baseline but not in current)
        for rid, baseline_rs in base.items():
            if rid not in current_map:
                drift = DriftResult(
                    resource_id=rid,
                    resource_type=baseline_rs.resource_type,
                    drift_type="removed",
                    field_path="(entire resource)",
                    expected_value=baseline_rs.resource_type,
                    actual_value=None,
                    detected_at=detection_time,
                    provider=baseline_rs.provider,
                    region=baseline_rs.region,
                )
                drift.severity = self.classify_drift_severity(drift)
                drifts.append(drift)

        # Check for added resources (in current but not in baseline)
        for rid, current_rs in current_map.items():
            if rid not in base:
                drift = DriftResult(
                    resource_id=rid,
                    resource_type=current_rs.resource_type,
                    drift_type="added",
                    field_path="(entire resource)",
                    expected_value=None,
                    actual_value=current_rs.resource_type,
                    detected_at=detection_time,
                    provider=current_rs.provider,
                    region=current_rs.region,
                )
                drift.severity = self.classify_drift_severity(drift)
                drifts.append(drift)

        # Check for modified resources (present in both)
        for rid in base:
            if rid not in current_map:
                continue
            baseline_rs = base[rid]
            current_rs = current_map[rid]

            # Fast path: compare checksums
            if baseline_rs.checksum == current_rs.checksum:
                continue

            # Deep diff the configurations
            field_diffs = self.deep_diff(
                baseline_rs.configuration,
                current_rs.configuration,
            )
            for diff in field_diffs:
                drift = DriftResult(
                    resource_id=rid,
                    resource_type=baseline_rs.resource_type,
                    drift_type=diff["type"],
                    field_path=diff["path"],
                    expected_value=diff.get("old"),
                    actual_value=diff.get("new"),
                    detected_at=detection_time,
                    provider=baseline_rs.provider,
                    region=baseline_rs.region,
                )
                drift.severity = self.classify_drift_severity(drift)
                drifts.append(drift)

        self._current_drifts = drifts

        # Record in history
        self._history.append({
            "detected_at": detection_time,
            "baseline_captured_at": self._baseline_captured_at,
            "total_drifts": len(drifts),
            "resources_checked": len(current_states),
            "drifts": [d.to_dict() for d in drifts],
        })

        logger.info("Drift detection complete: %d drifts found", len(drifts))
        return drifts

    def deep_diff(
        self, dict1: dict, dict2: dict, path: str = ""
    ) -> list[dict]:
        """Recursively compare two dictionaries and return field-level differences.

        Each returned dict has keys: type ('added'|'removed'|'modified'),
        path (dot-separated), old, new.
        """
        diffs: list[dict] = []
        self._recursive_diff(dict1, dict2, path, diffs)
        return diffs

    def _recursive_diff(
        self,
        old: object,
        new: object,
        path: str,
        diffs: list[dict],
    ) -> None:
        """Internal recursive helper for deep_diff."""
        if isinstance(old, dict) and isinstance(new, dict):
            all_keys = set(old.keys()) | set(new.keys())
            for key in sorted(all_keys):
                child_path = f"{path}.{key}" if path else key
                if key not in old:
                    diffs.append({
                        "type": "added",
                        "path": child_path,
                        "old": None,
                        "new": new[key],
                    })
                elif key not in new:
                    diffs.append({
                        "type": "removed",
                        "path": child_path,
                        "old": old[key],
                        "new": None,
                    })
                else:
                    self._recursive_diff(old[key], new[key], child_path, diffs)

        elif isinstance(old, list) and isinstance(new, list):
            if old != new:
                # Compare element-wise up to the shorter length
                max_len = max(len(old), len(new))
                for i in range(max_len):
                    item_path = f"{path}[{i}]"
                    if i >= len(old):
                        diffs.append({
                            "type": "added",
                            "path": item_path,
                            "old": None,
                            "new": new[i],
                        })
                    elif i >= len(new):
                        diffs.append({
                            "type": "removed",
                            "path": item_path,
                            "old": old[i],
                            "new": None,
                        })
                    elif old[i] != new[i]:
                        if isinstance(old[i], dict) and isinstance(new[i], dict):
                            self._recursive_diff(old[i], new[i], item_path, diffs)
                        else:
                            diffs.append({
                                "type": "modified",
                                "path": item_path,
                                "old": old[i],
                                "new": new[i],
                            })
        else:
            if old != new:
                diffs.append({
                    "type": "modified",
                    "path": path,
                    "old": old,
                    "new": new,
                })

    def classify_drift_severity(self, drift: DriftResult) -> str:
        """Determine the severity of a drift finding.

        Rules (in priority order):
        1. Removed resources are always high.
        2. Added resources are medium (shadow/unmanaged resources).
        3. Modified critical security fields are critical.
        4. Modified high-importance fields are high.
        5. Everything else is medium; purely cosmetic changes are low.
        """
        # Entire resource added/removed
        if drift.field_path == "(entire resource)":
            if drift.drift_type == "removed":
                return "high"
            return "medium"

        # Extract the leaf field name
        leaf = drift.field_path.rsplit(".", 1)[-1].lower()
        # Strip array indices
        if "[" in leaf:
            leaf = leaf.split("[")[0]

        # Security-critical field changed
        if leaf in _CRITICAL_FIELDS:
            # If the change disables a security feature, it is critical
            if _is_security_degradation(drift.expected_value, drift.actual_value):
                return "critical"
            return "high"

        # High-importance field
        if leaf in _HIGH_FIELDS:
            return "high"

        # Cosmetic-ish: tag/label only changes
        if leaf in {"tags", "labels", "description", "name"}:
            return "low"

        return "medium"

    def get_remediation_suggestions(self, drift: DriftResult) -> list[str]:
        """Return a list of suggested remediation steps for a drift finding."""
        suggestions: list[str] = []

        if drift.drift_type == "removed":
            suggestions.append(
                f"Resource {drift.resource_id} ({drift.resource_type}) was "
                "removed from the environment. Determine if this was intentional."
            )
            suggestions.append(
                "If unintentional, redeploy the resource from the infrastructure-as-code "
                "template or restore from a backup."
            )
            suggestions.append(
                "Update the baseline to reflect the removal if it was planned."
            )
            return suggestions

        if drift.drift_type == "added":
            suggestions.append(
                f"Resource {drift.resource_id} ({drift.resource_type}) was added "
                "outside of the managed baseline."
            )
            suggestions.append(
                "Import the resource into infrastructure-as-code to bring it under management."
            )
            suggestions.append(
                "If the resource is unauthorized, remove it and investigate who created it."
            )
            return suggestions

        # Modified field
        leaf = drift.field_path.rsplit(".", 1)[-1].lower()
        if "[" in leaf:
            leaf = leaf.split("[")[0]

        suggestions.append(
            f"Field '{drift.field_path}' on {drift.resource_id} changed from "
            f"'{_safe_serialize(drift.expected_value)}' to "
            f"'{_safe_serialize(drift.actual_value)}'."
        )

        if leaf in _CRITICAL_FIELDS:
            suggestions.append(
                "This is a security-critical configuration change. "
                "Revert to the baseline value immediately if unauthorized."
            )
            if leaf in {"public_access", "publicly_accessible", "acl", "access_control"}:
                suggestions.append(
                    "Verify no sensitive data is exposed. Check access logs for suspicious activity."
                )
            if leaf in {"encryption", "encrypted", "ssl_enabled", "tls_enabled"}:
                suggestions.append(
                    "Ensure encryption is re-enabled to protect data at rest or in transit."
                )
            if leaf in {"mfa", "mfa_enabled"}:
                suggestions.append(
                    "Re-enable MFA to maintain strong authentication."
                )
            if leaf in {"firewall_rules", "security_groups", "network_acls"}:
                suggestions.append(
                    "Review the network rule change for overly permissive ingress/egress."
                )
            if leaf in {"iam_policy", "policy"}:
                suggestions.append(
                    "Audit the policy change for privilege escalation or overly broad permissions."
                )
        elif leaf in _HIGH_FIELDS:
            suggestions.append(
                "This is a significant infrastructure change. Verify it aligns with "
                "the approved change management process."
            )
        else:
            suggestions.append(
                "Review the change and update the baseline if it was intentional."
            )

        suggestions.append(
            "Run a targeted compliance scan to check for new violations introduced by this drift."
        )
        return suggestions

    def generate_drift_report(self) -> dict:
        """Generate a summarised drift detection report from the most recent run.

        Returns a dict suitable for JSON serialisation.
        """
        drifts = self._current_drifts
        report: dict = {
            "generated_at": datetime.utcnow().isoformat(),
            "baseline_captured_at": self._baseline_captured_at,
            "baseline_resources": len(self._baseline),
            "total_drifts": len(drifts),
            "by_severity": {},
            "by_drift_type": {},
            "by_provider": {},
            "by_resource_type": {},
            "drifts": [],
            "history_runs": len(self._history),
        }

        for d in drifts:
            report["by_severity"][d.severity] = (
                report["by_severity"].get(d.severity, 0) + 1
            )
            report["by_drift_type"][d.drift_type] = (
                report["by_drift_type"].get(d.drift_type, 0) + 1
            )
            if d.provider:
                report["by_provider"][d.provider] = (
                    report["by_provider"].get(d.provider, 0) + 1
                )
            report["by_resource_type"][d.resource_type] = (
                report["by_resource_type"].get(d.resource_type, 0) + 1
            )
            entry = d.to_dict()
            entry["remediation"] = self.get_remediation_suggestions(d)
            report["drifts"].append(entry)

        return report

    def generate_drift_report_text(self) -> str:
        """Return a human-readable text summary of the latest drift detection."""
        drifts = self._current_drifts
        lines: list[str] = []
        lines.append("=" * 80)
        lines.append("ARCA Drift Detection Report")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        lines.append(f"Baseline captured: {self._baseline_captured_at or 'N/A'}")
        lines.append(f"Baseline resources: {len(self._baseline)}")
        lines.append(f"Total drifts found: {len(drifts)}")
        lines.append("=" * 80)

        if not drifts:
            lines.append("")
            lines.append("No configuration drift detected.")
            return "\n".join(lines)

        # Group by severity
        by_severity: dict[str, list[DriftResult]] = {}
        for d in drifts:
            by_severity.setdefault(d.severity, []).append(d)

        severity_order = ["critical", "high", "medium", "low"]
        for sev in severity_order:
            group = by_severity.get(sev, [])
            if not group:
                continue
            lines.append("")
            lines.append(f"--- {sev.upper()} ({len(group)}) ---")
            for d in group:
                lines.append(d.summary())
                suggestions = self.get_remediation_suggestions(d)
                if suggestions:
                    lines.append(f"    Remediation: {suggestions[0]}")

        lines.append("")
        lines.append("=" * 80)
        return "\n".join(lines)

    def export_json(self) -> str:
        """Export the drift report as a JSON string."""
        return json.dumps(self.generate_drift_report(), indent=2, default=str)

    def get_history(self) -> list[dict]:
        """Return the full history of drift detection runs."""
        return list(self._history)

    def get_drift_trend(self) -> list[dict]:
        """Return a simplified trend of drift counts over time."""
        trend: list[dict] = []
        for run in self._history:
            by_sev: dict[str, int] = {}
            for d in run.get("drifts", []):
                s = d.get("severity", "medium")
                by_sev[s] = by_sev.get(s, 0) + 1
            trend.append({
                "detected_at": run["detected_at"],
                "total_drifts": run["total_drifts"],
                "resources_checked": run["resources_checked"],
                "by_severity": by_sev,
            })
        return trend

    def clear_history(self) -> None:
        """Clear the detection history."""
        self._history.clear()
        self._current_drifts.clear()
        logger.debug("Drift detection history cleared.")


# ======================================================================
# Internal helpers
# ======================================================================

def _is_security_degradation(old_value: object, new_value: object) -> bool:
    """Heuristically determine if a change represents a security downgrade.

    For example, encryption going from True to False, or public_access going
    from False to True.
    """
    # Boolean security flags: True->False is a degradation
    if isinstance(old_value, bool) and isinstance(new_value, bool):
        # Fields like 'encrypted' going True->False is bad
        # Fields like 'public_access' going False->True is bad
        # We cannot distinguish here, so any boolean flip is suspect
        return old_value != new_value

    # String values: specific known patterns
    if isinstance(old_value, str) and isinstance(new_value, str):
        old_l = old_value.lower()
        new_l = new_value.lower()
        # "private" -> "public"
        if "private" in old_l and "public" in new_l:
            return True
        # "enabled" -> "disabled"
        if "enabled" in old_l and "disabled" in new_l:
            return True
        # "deny" -> "allow"
        if "deny" in old_l and "allow" in new_l:
            return True
        # More restrictive CIDR to less restrictive
        if old_l != "0.0.0.0/0" and new_l == "0.0.0.0/0":
            return True

    # Numeric: a value going to 0 from non-zero (e.g. retention days)
    if isinstance(old_value, (int, float)) and isinstance(new_value, (int, float)):
        if old_value > 0 and new_value == 0:
            return True

    # None means a field was removed, which could be a degradation
    if old_value is not None and new_value is None:
        return True

    return False


# ======================================================================
# Module-level convenience
# ======================================================================

def quick_diff(baseline_configs: dict, current_configs: dict) -> list[dict]:
    """Convenience function for a one-shot diff of two raw config dicts.

    Args:
        baseline_configs: Dict mapping resource_id -> config dict.
        current_configs:  Dict mapping resource_id -> config dict.

    Returns:
        List of drift dicts (serialisable).
    """
    detector = DriftDetector()
    baseline = [
        ResourceState(
            resource_id=rid,
            resource_type="unknown",
            provider="unknown",
            region="unknown",
            configuration=cfg,
        )
        for rid, cfg in baseline_configs.items()
    ]
    current = [
        ResourceState(
            resource_id=rid,
            resource_type="unknown",
            provider="unknown",
            region="unknown",
            configuration=cfg,
        )
        for rid, cfg in current_configs.items()
    ]
    detector.capture_baseline(baseline)
    drifts = detector.detect_drift(current)
    return [d.to_dict() for d in drifts]
