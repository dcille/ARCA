"""CIS Benchmark control registries for all supported platforms.

Provides unified access to all 781 CIS controls across 9 benchmarks:
- AWS (62 controls, 34 automated)
- Alibaba Cloud (85 controls, 41 automated)
- GCP (84 controls, 72 automated)
- Google Workspace (89 controls, 0 automated)
- IBM Cloud (73 controls, 7 automated)
- Microsoft 365 (140 controls, 129 automated)
- Microsoft Azure (155 controls, 93 automated)
- Oracle Cloud Infrastructure (54 controls, 44 automated)
- Snowflake (39 controls, 23 automated)
"""

from scanner.cis_controls.aws_cis_controls import (
    AWS_CIS_CONTROLS,
    get_aws_cis_registry,
    get_aws_control_count,
    get_aws_automated_count,
    get_aws_manual_count,
    get_aws_dspm_controls,
    get_aws_rr_controls,
)
from scanner.cis_controls.alibaba_cis_controls import (
    ALIBABA_CIS_CONTROLS,
    get_alibaba_cis_registry,
    get_alibaba_control_count,
    get_alibaba_automated_count,
    get_alibaba_manual_count,
    get_alibaba_dspm_controls,
    get_alibaba_rr_controls,
)
from scanner.cis_controls.gcp_cis_controls import (
    GCP_CIS_CONTROLS,
    get_gcp_cis_registry,
    get_gcp_control_count,
    get_gcp_automated_count,
    get_gcp_manual_count,
    get_gcp_dspm_controls,
    get_gcp_rr_controls,
)
from scanner.cis_controls.google_workspace_cis_controls import (
    GOOGLE_WORKSPACE_CIS_CONTROLS,
    get_google_workspace_cis_registry,
    get_google_workspace_control_count,
    get_google_workspace_automated_count,
    get_google_workspace_manual_count,
    get_google_workspace_dspm_controls,
    get_google_workspace_rr_controls,
)
from scanner.cis_controls.ibm_cloud_cis_controls import (
    IBM_CLOUD_CIS_CONTROLS,
    get_ibm_cloud_cis_registry,
    get_ibm_cloud_control_count,
    get_ibm_cloud_automated_count,
    get_ibm_cloud_manual_count,
    get_ibm_cloud_dspm_controls,
    get_ibm_cloud_rr_controls,
)
from scanner.cis_controls.m365_cis_controls import (
    M365_CIS_CONTROLS,
    get_m365_cis_registry,
    get_m365_control_count,
    get_m365_automated_count,
    get_m365_manual_count,
    get_m365_dspm_controls,
    get_m365_rr_controls,
)
from scanner.cis_controls.azure_cis_controls import (
    AZURE_CIS_CONTROLS,
    get_azure_cis_registry,
    get_azure_control_count,
    get_azure_automated_count,
    get_azure_manual_count,
    get_azure_dspm_controls,
    get_azure_rr_controls,
)
from scanner.cis_controls.oci_cis_controls import (
    OCI_CIS_CONTROLS,
    get_oci_cis_registry,
    get_oci_control_count,
    get_oci_automated_count,
    get_oci_manual_count,
    get_oci_dspm_controls,
    get_oci_rr_controls,
)
from scanner.cis_controls.snowflake_cis_controls import (
    SNOWFLAKE_CIS_CONTROLS,
    get_snowflake_cis_registry,
    get_snowflake_control_count,
    get_snowflake_automated_count,
    get_snowflake_manual_count,
    get_snowflake_dspm_controls,
    get_snowflake_rr_controls,
)


# ─── Unified registry access ────────────────────────────────────

ALL_REGISTRIES = {
    "aws": AWS_CIS_CONTROLS,
    "alibaba": ALIBABA_CIS_CONTROLS,
    "gcp": GCP_CIS_CONTROLS,
    "google_workspace": GOOGLE_WORKSPACE_CIS_CONTROLS,
    "ibm_cloud": IBM_CLOUD_CIS_CONTROLS,
    "microsoft_365": M365_CIS_CONTROLS,
    "azure": AZURE_CIS_CONTROLS,
    "oci": OCI_CIS_CONTROLS,
    "snowflake": SNOWFLAKE_CIS_CONTROLS,
}


def get_all_controls() -> list[dict]:
    """Return all 781 CIS controls across all benchmarks."""
    controls = []
    for platform, registry in ALL_REGISTRIES.items():
        for ctrl in registry:
            ctrl_copy = dict(ctrl)
            ctrl_copy["platform"] = platform
            controls.append(ctrl_copy)
    return controls


def get_all_dspm_controls() -> list[dict]:
    """Return all DSPM-relevant controls across all benchmarks."""
    return [c for c in get_all_controls() if c.get("dspm_relevant")]


def get_all_rr_controls() -> list[dict]:
    """Return all Ransomware Readiness-relevant controls across all benchmarks."""
    return [c for c in get_all_controls() if c.get("rr_relevant")]


def get_platform_summary() -> dict:
    """Return a summary of controls per platform."""
    summary = {}
    for platform, registry in ALL_REGISTRIES.items():
        total = len(registry)
        automated = sum(1 for c in registry if c["assessment_type"] == "automated")
        dspm = sum(1 for c in registry if c.get("dspm_relevant"))
        rr = sum(1 for c in registry if c.get("rr_relevant"))
        summary[platform] = {
            "total": total,
            "automated": automated,
            "manual": total - automated,
            "dspm_relevant": dspm,
            "rr_relevant": rr,
        }
    return summary


def get_total_control_count() -> int:
    """Return the total number of CIS controls across all benchmarks."""
    return sum(len(r) for r in ALL_REGISTRIES.values())
