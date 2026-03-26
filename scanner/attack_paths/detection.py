"""
Detection Coverage Analyzer for attack paths.

For each step (edge) in an attack path, evaluates whether existing security
controls (logging, monitoring, threat detection) would detect the activity.
Works entirely from existing CSPM findings — no additional cloud API calls needed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .graph_engine import AttackPath, GraphEdge, EdgeType


@dataclass
class StepDetection:
    """Detection evaluation for a single attack-path edge."""
    edge_type: str
    label: str
    source_id: str
    target_id: str
    detections: list[dict]  # [{control, event, detected, status}]

    @property
    def is_detected(self) -> bool:
        return len(self.detections) > 0 and all(d["detected"] for d in self.detections)

    @property
    def is_partially_detected(self) -> bool:
        return any(d["detected"] for d in self.detections) and not self.is_detected

    @property
    def is_undetected(self) -> bool:
        return len(self.detections) == 0 or not any(d["detected"] for d in self.detections)


@dataclass
class DetectionReport:
    """Detection coverage report for a single attack path."""
    path_id: str
    path_title: str
    coverage_pct: float  # 0-100
    detected_steps: int
    undetected_steps: int
    partially_detected_steps: int
    total_steps: int
    steps: list[StepDetection]
    verdict: str  # "well_monitored", "partially_monitored", "blind"
    blind_spot_summary: list[str]  # human-readable list of undetected activities


# Mapping: EdgeType -> list of detection controls that SHOULD catch this activity.
# Each control maps to a check_id pattern that we look for in PASS findings.
DETECTION_REQUIREMENTS: dict[str, list[dict]] = {
    EdgeType.EXPOSES.value: [
        {
            "control": "guardduty_enabled",
            "check_patterns": ["guardduty_enabled", "guardduty_detector"],
            "event": "Reconnaissance / port scanning on public resource",
            "provider_scope": ["aws"],
        },
        {
            "control": "vpc_flow_logs",
            "check_patterns": ["vpc_flow_logs", "ali_vpc_flow_logs", "gcp_vpc_flow_logs"],
            "event": "Network connection to exposed resource",
            "provider_scope": ["aws", "gcp", "alibaba"],
        },
        {
            "control": "azure_network_watcher",
            "check_patterns": ["azure_network_watcher", "azure_nsg_flow_logs"],
            "event": "Network flow to exposed Azure resource",
            "provider_scope": ["azure"],
        },
    ],
    EdgeType.ASSUMES_ROLE.value: [
        {
            "control": "cloudtrail_enabled",
            "check_patterns": ["cloudtrail_enabled", "cloudtrail_multiregion"],
            "event": "AssumeRole API call logged in CloudTrail",
            "provider_scope": ["aws"],
        },
        {
            "control": "guardduty_enabled",
            "check_patterns": ["guardduty_enabled"],
            "event": "Unusual AssumeRole activity detected by GuardDuty",
            "provider_scope": ["aws"],
        },
        {
            "control": "azure_activity_log",
            "check_patterns": ["azure_monitor_activity_log", "azure_monitor_diagnostic"],
            "event": "Role assignment change in Azure Activity Log",
            "provider_scope": ["azure"],
        },
        {
            "control": "gcp_audit_logging",
            "check_patterns": ["gcp_audit_log", "gcp_logging_enabled"],
            "event": "IAM binding change in GCP Audit Logs",
            "provider_scope": ["gcp"],
        },
    ],
    EdgeType.CAN_ESCALATE.value: [
        {
            "control": "cloudtrail_enabled",
            "check_patterns": ["cloudtrail_enabled", "cloudtrail_multiregion"],
            "event": "IAM policy modification logged in CloudTrail",
            "provider_scope": ["aws"],
        },
        {
            "control": "guardduty_enabled",
            "check_patterns": ["guardduty_enabled"],
            "event": "Privilege escalation attempt detected",
            "provider_scope": ["aws"],
        },
        {
            "control": "config_enabled",
            "check_patterns": ["config_enabled", "config_recorder"],
            "event": "IAM configuration change tracked by AWS Config",
            "provider_scope": ["aws"],
        },
        {
            "control": "azure_defender",
            "check_patterns": ["azure_defender", "azure_security_center"],
            "event": "Suspicious identity activity in Azure Defender",
            "provider_scope": ["azure"],
        },
    ],
    EdgeType.CREDENTIAL_ACCESS.value: [
        {
            "control": "guardduty_enabled",
            "check_patterns": ["guardduty_enabled"],
            "event": "Credential exfiltration detected by GuardDuty",
            "provider_scope": ["aws"],
        },
        {
            "control": "cloudtrail_data_events",
            "check_patterns": ["cloudtrail_s3_object", "cloudtrail_data_events"],
            "event": "Secrets Manager / SSM access logged in CloudTrail data events",
            "provider_scope": ["aws"],
        },
        {
            "control": "azure_keyvault_logging",
            "check_patterns": ["azure_keyvault_logging", "azure_keyvault_diagnostic"],
            "event": "Key Vault access logged in Azure diagnostics",
            "provider_scope": ["azure"],
        },
    ],
    EdgeType.LATERAL_MOVE.value: [
        {
            "control": "vpc_flow_logs",
            "check_patterns": ["vpc_flow_logs", "ali_vpc_flow_logs"],
            "event": "Lateral network movement captured in VPC flow logs",
            "provider_scope": ["aws", "alibaba"],
        },
        {
            "control": "guardduty_enabled",
            "check_patterns": ["guardduty_enabled"],
            "event": "Unusual network activity detected by GuardDuty",
            "provider_scope": ["aws"],
        },
        {
            "control": "cloudtrail_enabled",
            "check_patterns": ["cloudtrail_enabled", "cloudtrail_multiregion"],
            "event": "Cross-service API calls logged in CloudTrail",
            "provider_scope": ["aws"],
        },
        {
            "control": "azure_network_watcher",
            "check_patterns": ["azure_network_watcher", "azure_nsg_flow_logs"],
            "event": "Lateral network movement captured in NSG flow logs",
            "provider_scope": ["azure"],
        },
    ],
    EdgeType.HAS_ACCESS.value: [
        {
            "control": "cloudtrail_enabled",
            "check_patterns": ["cloudtrail_enabled", "cloudtrail_multiregion"],
            "event": "Resource access API call logged in CloudTrail",
            "provider_scope": ["aws"],
        },
        {
            "control": "azure_activity_log",
            "check_patterns": ["azure_monitor_activity_log"],
            "event": "Resource access logged in Azure Activity Log",
            "provider_scope": ["azure"],
        },
        {
            "control": "gcp_audit_logging",
            "check_patterns": ["gcp_audit_log", "gcp_logging_enabled"],
            "event": "Resource access logged in GCP Audit Logs",
            "provider_scope": ["gcp"],
        },
    ],
    EdgeType.STORES_DATA.value: [
        {
            "control": "cloudtrail_data_events",
            "check_patterns": ["cloudtrail_s3_object", "cloudtrail_data_events"],
            "event": "Data store read/write logged in CloudTrail data events",
            "provider_scope": ["aws"],
        },
        {
            "control": "s3_access_logging",
            "check_patterns": ["s3_bucket_logging", "s3_access_logging"],
            "event": "S3 bucket access logged",
            "provider_scope": ["aws"],
        },
    ],
    EdgeType.ROUTES_TO.value: [
        {
            "control": "vpc_flow_logs",
            "check_patterns": ["vpc_flow_logs", "ali_vpc_flow_logs"],
            "event": "Network traffic captured in VPC flow logs",
            "provider_scope": ["aws", "alibaba"],
        },
        {
            "control": "azure_network_watcher",
            "check_patterns": ["azure_network_watcher", "azure_nsg_flow_logs"],
            "event": "Network traffic captured in NSG flow logs",
            "provider_scope": ["azure"],
        },
    ],
    EdgeType.HAS_FINDING.value: [],  # Meta-edge, no detection needed
}


class DetectionCoverageAnalyzer:
    """
    Evaluates detection coverage for attack paths using existing CSPM findings.

    For each edge in a path, checks whether the security controls that would
    detect that activity are enabled (PASS in findings) or disabled (FAIL/missing).
    """

    def __init__(self, all_findings: list[dict]):
        """
        Args:
            all_findings: ALL findings from the scan (both PASS and FAIL),
                         not just the failed ones used to build attack paths.
        """
        self._pass_check_ids: set[str] = set()
        self._fail_check_ids: set[str] = set()

        for f in all_findings:
            cid = f.get("check_id", "")
            if f.get("status") == "PASS":
                self._pass_check_ids.add(cid)
            elif f.get("status") == "FAIL":
                self._fail_check_ids.add(cid)

    def analyze_path(self, path: AttackPath) -> DetectionReport:
        """Evaluate detection coverage for every edge in an attack path."""
        steps: list[StepDetection] = []

        for edge in path.edges:
            edge_type_str = edge.edge_type.value if hasattr(edge.edge_type, "value") else str(edge.edge_type)
            requirements = DETECTION_REQUIREMENTS.get(edge_type_str, [])

            detections = []
            for req in requirements:
                detected = self._check_control_enabled(req["check_patterns"])
                detections.append({
                    "control": req["control"],
                    "event": req["event"],
                    "detected": detected,
                    "status": "DETECTED" if detected else "UNDETECTED",
                })

            steps.append(StepDetection(
                edge_type=edge_type_str,
                label=edge.label,
                source_id=edge.source_id,
                target_id=edge.target_id,
                detections=detections,
            ))

        # Calculate summary
        evaluable_steps = [s for s in steps if len(s.detections) > 0]
        total = len(evaluable_steps)
        detected = sum(1 for s in evaluable_steps if s.is_detected)
        partially = sum(1 for s in evaluable_steps if s.is_partially_detected)
        undetected = sum(1 for s in evaluable_steps if s.is_undetected)

        coverage = (detected / max(total, 1)) * 100

        # Generate blind spot summary
        blind_spots = []
        for s in evaluable_steps:
            if s.is_undetected:
                missing_controls = [d["control"] for d in s.detections if not d["detected"]]
                blind_spots.append(
                    f"Step '{s.label}' ({s.edge_type}): missing {', '.join(missing_controls)}"
                )

        verdict = self._compute_verdict(coverage, total)

        return DetectionReport(
            path_id=path.id,
            path_title=path.title,
            coverage_pct=round(coverage, 1),
            detected_steps=detected,
            undetected_steps=undetected,
            partially_detected_steps=partially,
            total_steps=total,
            steps=steps,
            verdict=verdict,
            blind_spot_summary=blind_spots,
        )

    def analyze_all_paths(self, paths: list[AttackPath]) -> list[DetectionReport]:
        """Analyze detection coverage for all attack paths."""
        return [self.analyze_path(p) for p in paths]

    def generate_heatmap(self, paths: list[AttackPath]) -> dict:
        """
        Generate a detection heatmap: paths x controls matrix.

        Returns:
            {
                "paths": [{"id", "title", "severity"}],
                "controls": ["cloudtrail_enabled", "guardduty_enabled", ...],
                "matrix": [[True/False/None, ...], ...],  # paths x controls
                "summary": {"total_paths", "avg_coverage", "fully_blind_paths"}
            }
        """
        reports = self.analyze_all_paths(paths)

        # Collect all unique controls
        all_controls: list[str] = []
        seen = set()
        for req_list in DETECTION_REQUIREMENTS.values():
            for req in req_list:
                if req["control"] not in seen:
                    all_controls.append(req["control"])
                    seen.add(req["control"])

        # Build matrix
        path_rows = []
        matrix = []
        for report in reports:
            path_rows.append({
                "id": report.path_id,
                "title": report.path_title,
                "coverage_pct": report.coverage_pct,
                "verdict": report.verdict,
            })

            # For each control, check if any step in this path requires it
            # and whether it's detected
            row = []
            for control in all_controls:
                # Find if this control appears in any step
                found = False
                status = None
                for step in report.steps:
                    for det in step.detections:
                        if det["control"] == control:
                            found = True
                            if status is None:
                                status = det["detected"]
                            elif not det["detected"]:
                                status = False
                if not found:
                    row.append(None)  # control not relevant for this path
                else:
                    row.append(status)
            matrix.append(row)

        avg_coverage = (
            sum(r.coverage_pct for r in reports) / max(len(reports), 1)
        )
        fully_blind = sum(1 for r in reports if r.verdict == "blind")

        return {
            "paths": path_rows,
            "controls": all_controls,
            "matrix": matrix,
            "summary": {
                "total_paths": len(reports),
                "avg_coverage": round(avg_coverage, 1),
                "fully_blind_paths": fully_blind,
                "well_monitored_paths": sum(1 for r in reports if r.verdict == "well_monitored"),
            },
        }

    def _check_control_enabled(self, check_patterns: list[str]) -> bool:
        """Check if any of the check_patterns appear in PASS findings."""
        for pattern in check_patterns:
            # Check exact match first
            if pattern in self._pass_check_ids:
                return True
            # Then check pattern-based (e.g., "cloudtrail_enabled" matches
            # "aws_cloudtrail_enabled_all_regions")
            for pass_id in self._pass_check_ids:
                if pattern in pass_id:
                    return True
        return False

    @staticmethod
    def _compute_verdict(coverage_pct: float, total_steps: int) -> str:
        if total_steps == 0:
            return "not_evaluable"
        if coverage_pct >= 80:
            return "well_monitored"
        if coverage_pct >= 40:
            return "partially_monitored"
        return "blind"
