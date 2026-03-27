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

# ── Extended provider detection entries ───────────────────────────────
# Add OCI, IBM Cloud, Kubernetes, and SaaS provider detection controls
# to existing edge types for full 15-provider coverage.

_EXTENDED_DETECTIONS: dict[str, list[dict]] = {
    EdgeType.EXPOSES.value: [
        {
            "control": "oci_vcn_flow_logs",
            "check_patterns": ["oci_vcn_flow_logs", "oci_logging_enabled"],
            "event": "Network connection to exposed OCI resource",
            "provider_scope": ["oci"],
        },
        {
            "control": "ibm_flow_logs",
            "check_patterns": ["ibm_flow_logs", "ibm_vpc_flow_logs"],
            "event": "Network connection to exposed IBM Cloud resource",
            "provider_scope": ["ibm_cloud"],
        },
        {
            "control": "k8s_network_policy",
            "check_patterns": ["k8s_network_policy", "k8s_pod_security"],
            "event": "Network exposure in Kubernetes detected via network policy audit",
            "provider_scope": ["kubernetes"],
        },
        {
            "control": "cloudflare_waf",
            "check_patterns": ["cloudflare_waf_enabled", "cloudflare_firewall"],
            "event": "WAF detection of inbound attack on exposed endpoint",
            "provider_scope": ["cloudflare"],
        },
    ],
    EdgeType.ASSUMES_ROLE.value: [
        {
            "control": "oci_audit_logging",
            "check_patterns": ["oci_audit_config", "oci_logging_enabled"],
            "event": "Identity assumption logged in OCI Audit",
            "provider_scope": ["oci"],
        },
        {
            "control": "ibm_activity_tracker",
            "check_patterns": ["ibm_activity_tracker", "ibm_at_enabled"],
            "event": "IAM token generation logged in IBM Activity Tracker",
            "provider_scope": ["ibm_cloud"],
        },
        {
            "control": "k8s_audit_logging",
            "check_patterns": ["k8s_audit_logging", "k8s_api_audit"],
            "event": "Service account impersonation logged in K8s audit log",
            "provider_scope": ["kubernetes"],
        },
    ],
    EdgeType.CAN_ESCALATE.value: [
        {
            "control": "oci_cloud_guard",
            "check_patterns": ["oci_cloud_guard", "oci_security_zone"],
            "event": "Privilege escalation attempt detected by OCI Cloud Guard",
            "provider_scope": ["oci"],
        },
        {
            "control": "ibm_security_advisor",
            "check_patterns": ["ibm_security_advisor", "ibm_scc_enabled"],
            "event": "IAM policy change detected by IBM Security & Compliance Center",
            "provider_scope": ["ibm_cloud"],
        },
        {
            "control": "k8s_rbac_audit",
            "check_patterns": ["k8s_audit_logging", "k8s_rbac_restriction"],
            "event": "RBAC privilege escalation attempt in K8s audit log",
            "provider_scope": ["kubernetes"],
        },
        {
            "control": "m365_unified_audit",
            "check_patterns": ["m365_audit_enabled", "m365_unified_audit_log"],
            "event": "Role assignment change in M365 Unified Audit Log",
            "provider_scope": ["m365"],
        },
        {
            "control": "github_audit_log",
            "check_patterns": ["github_audit_log", "github_org_audit"],
            "event": "Permission change in GitHub Audit Log",
            "provider_scope": ["github"],
        },
        {
            "control": "gws_admin_audit",
            "check_patterns": ["gws_admin_audit", "gws_login_audit"],
            "event": "Admin role change in Google Workspace Admin Audit",
            "provider_scope": ["google_workspace"],
        },
        {
            "control": "salesforce_event_monitoring",
            "check_patterns": ["sf_event_monitoring", "sf_shield_enabled"],
            "event": "Permission set change in Salesforce Event Monitoring",
            "provider_scope": ["salesforce"],
        },
        {
            "control": "servicenow_sys_audit",
            "check_patterns": ["sn_audit_enabled", "sn_system_logs"],
            "event": "Role grant detected in ServiceNow system audit",
            "provider_scope": ["servicenow"],
        },
        {
            "control": "snowflake_access_history",
            "check_patterns": ["snow_access_history", "snow_query_history"],
            "event": "GRANT statement detected in Snowflake Access History",
            "provider_scope": ["snowflake"],
        },
        {
            "control": "openstack_audit",
            "check_patterns": ["os_audit_middleware", "os_cadf_audit"],
            "event": "Role assignment change in OpenStack audit middleware",
            "provider_scope": ["openstack"],
        },
    ],
    EdgeType.CREDENTIAL_ACCESS.value: [
        {
            "control": "oci_vault_logging",
            "check_patterns": ["oci_logging_enabled", "oci_vault_audit"],
            "event": "Vault secret access logged in OCI Audit",
            "provider_scope": ["oci"],
        },
        {
            "control": "ibm_key_protect_logging",
            "check_patterns": ["ibm_activity_tracker", "ibm_key_protect"],
            "event": "Key Protect / Secrets Manager access in IBM Activity Tracker",
            "provider_scope": ["ibm_cloud"],
        },
        {
            "control": "k8s_secret_audit",
            "check_patterns": ["k8s_audit_logging", "k8s_secret_encryption"],
            "event": "Secret read operation logged in K8s audit log",
            "provider_scope": ["kubernetes"],
        },
        {
            "control": "github_secret_scanning",
            "check_patterns": ["github_secret_scanning", "github_advanced_security"],
            "event": "Secret exposure detected by GitHub secret scanning",
            "provider_scope": ["github"],
        },
    ],
    EdgeType.LATERAL_MOVE.value: [
        {
            "control": "oci_vcn_flow_logs",
            "check_patterns": ["oci_vcn_flow_logs", "oci_logging_enabled"],
            "event": "Lateral movement captured in OCI VCN flow logs",
            "provider_scope": ["oci"],
        },
        {
            "control": "ibm_flow_logs",
            "check_patterns": ["ibm_flow_logs", "ibm_vpc_flow_logs"],
            "event": "Lateral movement captured in IBM VPC flow logs",
            "provider_scope": ["ibm_cloud"],
        },
        {
            "control": "k8s_network_policy_audit",
            "check_patterns": ["k8s_network_policy", "k8s_audit_logging"],
            "event": "Pod-to-pod lateral movement in K8s network/audit logs",
            "provider_scope": ["kubernetes"],
        },
    ],
    EdgeType.HAS_ACCESS.value: [
        {
            "control": "oci_audit_logging",
            "check_patterns": ["oci_audit_config", "oci_logging_enabled"],
            "event": "Resource access logged in OCI Audit",
            "provider_scope": ["oci"],
        },
        {
            "control": "ibm_activity_tracker",
            "check_patterns": ["ibm_activity_tracker", "ibm_at_enabled"],
            "event": "Resource access logged in IBM Activity Tracker",
            "provider_scope": ["ibm_cloud"],
        },
        {
            "control": "k8s_audit_logging",
            "check_patterns": ["k8s_audit_logging", "k8s_api_audit"],
            "event": "Resource access logged in K8s API audit log",
            "provider_scope": ["kubernetes"],
        },
    ],
    EdgeType.STORES_DATA.value: [
        {
            "control": "oci_object_storage_logging",
            "check_patterns": ["oci_objectstorage_logging", "oci_logging_enabled"],
            "event": "Object Storage access logged in OCI",
            "provider_scope": ["oci"],
        },
        {
            "control": "ibm_cos_logging",
            "check_patterns": ["ibm_activity_tracker", "ibm_cos_logging"],
            "event": "COS bucket access logged in IBM Activity Tracker",
            "provider_scope": ["ibm_cloud"],
        },
        {
            "control": "snowflake_access_history",
            "check_patterns": ["snow_access_history", "snow_query_history"],
            "event": "Data access logged in Snowflake Access History",
            "provider_scope": ["snowflake"],
        },
    ],
    EdgeType.ROUTES_TO.value: [
        {
            "control": "oci_vcn_flow_logs",
            "check_patterns": ["oci_vcn_flow_logs", "oci_logging_enabled"],
            "event": "Network traffic captured in OCI VCN flow logs",
            "provider_scope": ["oci"],
        },
        {
            "control": "ibm_flow_logs",
            "check_patterns": ["ibm_flow_logs", "ibm_vpc_flow_logs"],
            "event": "Network traffic captured in IBM VPC flow logs",
            "provider_scope": ["ibm_cloud"],
        },
        {
            "control": "k8s_network_policy",
            "check_patterns": ["k8s_network_policy", "k8s_audit_logging"],
            "event": "Network traffic between pods/services in K8s",
            "provider_scope": ["kubernetes"],
        },
        {
            "control": "cloudflare_analytics",
            "check_patterns": ["cloudflare_analytics", "cloudflare_logpush"],
            "event": "Traffic routing captured in Cloudflare analytics/logpush",
            "provider_scope": ["cloudflare"],
        },
    ],
}

# Merge extended detections into the main registry
for _edge_type, _entries in _EXTENDED_DETECTIONS.items():
    if _edge_type in DETECTION_REQUIREMENTS:
        DETECTION_REQUIREMENTS[_edge_type].extend(_entries)
    else:
        DETECTION_REQUIREMENTS[_edge_type] = _entries


class DetectionCoverageAnalyzer:
    """
    Evaluates detection coverage for attack paths using existing CSPM findings.

    For each edge in a path, checks whether the security controls that would
    detect that activity are enabled (PASS in findings) or disabled (FAIL/missing).
    Filters detection requirements by provider_scope to avoid cross-provider false positives.
    """

    # Provider prefix mapping for check_id inference
    _PROVIDER_PREFIXES = {
        "azure_": "azure", "gcp_": "gcp", "oci_": "oci",
        "ali_": "alibaba", "ibm_": "ibm_cloud", "k8s_": "kubernetes",
        "m365_": "m365", "github_": "github", "gws_": "google_workspace",
        "sf_": "salesforce", "sn_": "servicenow", "snow_": "snowflake",
        "cloudflare_": "cloudflare", "os_": "openstack",
    }

    def __init__(self, all_findings: list[dict]):
        """
        Args:
            all_findings: ALL findings from the scan (both PASS and FAIL),
                         not just the failed ones used to build attack paths.
        """
        self._pass_check_ids: set[str] = set()
        self._fail_check_ids: set[str] = set()
        self._provider_pass: dict[str, set[str]] = {}

        for f in all_findings:
            cid = f.get("check_id", "")
            provider = self._infer_provider(cid)
            if f.get("status") == "PASS":
                self._pass_check_ids.add(cid)
                self._provider_pass.setdefault(provider, set()).add(cid)
            elif f.get("status") == "FAIL":
                self._fail_check_ids.add(cid)

    def _infer_provider(self, check_id: str) -> str:
        """Infer provider from check_id prefix."""
        for prefix, prov in self._PROVIDER_PREFIXES.items():
            if check_id.startswith(prefix):
                return prov
        return "aws"  # Default for non-prefixed checks (e.g. cloudtrail_, guardduty_)

    def _detect_path_provider(self, path: AttackPath) -> str:
        """Detect the primary provider of an attack path from its nodes/metadata."""
        for node in path.nodes:
            svc = (node.service or "").lower()
            label = (node.label or "").lower()
            combined = f"{svc} {label}"
            if any(k in combined for k in ("azure", "entra", "keyvault", "nsg")):
                return "azure"
            if any(k in combined for k in ("gcp", "bigquery", "gke", "cloudfunctions", "gcs")):
                return "gcp"
            if any(k in combined for k in ("oci", "objectstorage", "cloudguard", "vcn")):
                return "oci"
            if any(k in combined for k in ("alibaba", "aliyun", "ecs", "oss", "ram")):
                return "alibaba"
            if any(k in combined for k in ("ibm", "cloud object storage")):
                return "ibm_cloud"
            if any(k in combined for k in ("kubernetes", "k8s", "pod", "rbac")):
                return "kubernetes"
            if any(k in combined for k in ("m365", "microsoft 365", "exchange", "sharepoint")):
                return "m365"
            if any(k in combined for k in ("github",)):
                return "github"
            if any(k in combined for k in ("google workspace", "gws")):
                return "google_workspace"
            if any(k in combined for k in ("salesforce", "sfdc")):
                return "salesforce"
            if any(k in combined for k in ("servicenow",)):
                return "servicenow"
            if any(k in combined for k in ("snowflake",)):
                return "snowflake"
            if any(k in combined for k in ("cloudflare",)):
                return "cloudflare"
            if any(k in combined for k in ("openstack", "keystone", "nova")):
                return "openstack"
        return "aws"  # Default

    def analyze_path(self, path: AttackPath) -> DetectionReport:
        """Evaluate detection coverage for every edge in an attack path."""
        path_provider = self._detect_path_provider(path)
        steps: list[StepDetection] = []

        for edge in path.edges:
            edge_type_str = edge.edge_type.value if hasattr(edge.edge_type, "value") else str(edge.edge_type)
            requirements = DETECTION_REQUIREMENTS.get(edge_type_str, [])

            detections = []
            for req in requirements:
                # Filter by provider_scope to avoid cross-provider false positives
                provider_scope = req.get("provider_scope")
                if provider_scope and path_provider not in provider_scope:
                    continue  # This control doesn't apply to this provider

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
