"""Load CIS Benchmark controls as the primary source for the check registry.

Processes all 9 CIS benchmarks (904 controls) and maps scanner check_ids
to each control. Scanner checks not covered by any CIS control are added
as supplementary entries.

Resolution chain for MITRE/RR:
  MITRE check_id → scanner_check_id → CIS control in registry
  RR check_id → CHECK_ID_ALIASES → scanner_check_id → CIS control in registry
"""

import logging
import re
from typing import Optional

from scanner.registry.models import CheckDefinition

logger = logging.getLogger(__name__)

# ======================================================================
# Service area → Category mapping
# ======================================================================

_SERVICE_CATEGORY_MAP = {
    "iam": "Identity",
    "identity": "Identity",
    "conditional access": "Identity",
    "entra": "Identity",
    "storage": "Storage",
    "object storage": "Storage",
    "oss": "Storage",
    "networking": "Networking",
    "network": "Networking",
    "vpc": "Networking",
    "firewall": "Networking",
    "dns": "DNS",
    "cdn": "CDN",
    "logging": "Logging",
    "monitoring": "Logging",
    "audit": "Logging",
    "encryption": "Encryption",
    "key management": "Encryption",
    "kms": "Encryption",
    "compute": "Compute",
    "virtual machines": "Compute",
    "app service": "Compute",
    "database": "Database",
    "sql": "Database",
    "rds": "Database",
    "container": "Container",
    "kubernetes": "Container",
    "aks": "Container",
    "eks": "Container",
    "gke": "Container",
    "serverless": "Serverless",
    "lambda": "Serverless",
    "functions": "Serverless",
    "data protection": "Data Protection",
    "dlp": "Data Protection",
    "backup": "Backup",
    "email security": "Email Security",
    "email": "Email Security",
    "exchange": "Email Security",
    "collaboration": "Collaboration",
    "teams": "Collaboration",
    "sharepoint": "Collaboration",
    "devops": "DevOps",
    "analytics": "Analytics",
    "defender": "Threat Detection",
    "security center": "Threat Detection",
    "guard": "Threat Detection",
    "governance": "Governance",
    "admin center": "Governance",
    "intune": "Governance",
    "fabric": "Governance",
    "api": "API Security",
    "api security": "API Security",
    "control_plane": "Container",
    "etcd": "Container",
    "worker_nodes": "Container",
    "policies": "Governance",
    "general": "Compliance",
}


def _resolve_category(service_area: str) -> str:
    """Map a CIS service_area to a registry Category."""
    sa = service_area.lower().strip()
    if sa in _SERVICE_CATEGORY_MAP:
        return _SERVICE_CATEGORY_MAP[sa]
    for key, cat in _SERVICE_CATEGORY_MAP.items():
        if key in sa:
            return cat
    return "Compliance"


# ======================================================================
# Scanner check_id mapping: CIS control → scanner check_ids
# ======================================================================

def _build_scanner_mapping() -> dict[str, set[str]]:
    """Build a mapping from (provider, cis_id) → set of scanner check_ids.

    Uses the compliance frameworks module which already contains
    CIS control → scanner check_id mappings.
    """
    mapping: dict[str, set[str]] = {}

    try:
        from scanner.compliance.frameworks import FRAMEWORKS
    except ImportError:
        logger.warning("Could not import compliance frameworks for scanner mapping")
        return mapping

    # Map CIS framework keys to provider names
    fw_provider = {
        "CIS-AWS": "aws", "CIS-Azure": "azure", "CIS-GCP": "gcp",
        "CIS-OCI": "oci", "CIS-Alibaba": "alibaba", "CIS-K8s": "kubernetes",
        "CIS-M365": "m365", "CIS-GW": "google_workspace",
    }

    for fw_key, fw_data in FRAMEWORKS.items():
        provider = None
        for prefix, prov in fw_provider.items():
            if fw_key.startswith(prefix):
                provider = prov
                break
        if not provider:
            continue

        for control in fw_data.get("controls", []):
            cis_id = control.get("id", "")
            checks = control.get("checks", {})
            key = f"{provider}:{cis_id}"
            if key not in mapping:
                mapping[key] = set()
            for prov_checks in checks.values():
                mapping[key].update(prov_checks)

    return mapping


def _build_scanner_ids_set() -> set[str]:
    """Extract all check_ids from all scanner implementations."""
    scanner_ids: set[str] = set()

    scanner_files = [
        "scanner/providers/aws/aws_scanner.py",
        "scanner/providers/azure/azure_scanner.py",
        "scanner/providers/gcp/gcp_scanner.py",
        "scanner/providers/oci/oci_scanner.py",
        "scanner/providers/alibaba/alibaba_scanner.py",
        "scanner/providers/ibm_cloud/ibm_cloud_scanner.py",
        "scanner/providers/kubernetes/k8s_scanner.py",
        "scanner/saas/m365/m365_scanner.py",
        "scanner/saas/github/github_scanner.py",
        "scanner/saas/google_workspace/google_workspace_scanner.py",
        "scanner/saas/salesforce/salesforce_scanner.py",
        "scanner/saas/servicenow/servicenow_scanner.py",
        "scanner/saas/snowflake/snowflake_scanner.py",
        "scanner/saas/cloudflare/cloudflare_scanner.py",
        "scanner/saas/openstack/openstack_scanner.py",
    ]

    for filepath in scanner_files:
        try:
            with open(filepath) as f:
                content = f.read()
            ids = re.findall(r'check_id="([^"]+)"', content)
            scanner_ids.update(ids)
        except FileNotFoundError:
            pass

    return scanner_ids


def _extract_scanner_check_metadata(filepath: str) -> dict[str, dict]:
    """Extract check_id → {title, service, severity} from a scanner file."""
    metadata: dict[str, dict] = {}
    try:
        with open(filepath) as f:
            content = f.read()
    except FileNotFoundError:
        return metadata

    # Match CheckResult or SaaSCheckResult constructions
    for pattern in [
        r'(?:CheckResult|SaaSCheckResult)\((.*?)\)\.to_dict\(\)',
    ]:
        for m in re.finditer(pattern, content, re.DOTALL):
            block = m.group(1)
            cid = re.search(r'check_id\s*=\s*["\x27]([^"\x27]+)', block)
            title = re.search(r'check_title\s*=\s*["\x27]([^"\x27]+)', block)
            svc = re.search(r'(?:service|service_area)\s*=\s*["\x27]([^"\x27]+)', block)
            sev = re.search(r'severity\s*=\s*["\x27]([^"\x27]+)', block)
            if cid and cid.group(1) not in metadata:
                metadata[cid.group(1)] = {
                    "title": title.group(1) if title else cid.group(1),
                    "service": svc.group(1) if svc else "General",
                    "severity": sev.group(1) if sev else "medium",
                }
    return metadata


# ======================================================================
# CIS control loaders per provider format
# ======================================================================

def _load_dict_cis_controls(provider: str, controls: list[dict],
                             scanner_mapping: dict[str, set[str]]) -> list[CheckDefinition]:
    """Load CIS controls in dict format (AWS, Azure, GCP, OCI, Alibaba, IBM, M365, GWS, Snowflake)."""
    checks: list[CheckDefinition] = []

    for ctrl in controls:
        cis_id = ctrl.get("cis_id", "")
        check_id = f"{provider}_cis_{cis_id.replace('.', '_')}"

        # Find mapped scanner check_ids
        key = f"{provider}:{cis_id}"
        scanner_ids = sorted(scanner_mapping.get(key, set()))

        service_area = ctrl.get("service_area", ctrl.get("domain", "General"))
        category = _resolve_category(service_area)

        description = ctrl.get("description", ctrl.get("title", ""))
        if ctrl.get("rationale"):
            description = f"{description} {ctrl['rationale']}"
        # Truncate very long descriptions
        if len(description) > 500:
            description = description[:497] + "..."

        remediation = ctrl.get("remediation", "")
        if isinstance(remediation, str) and len(remediation) > 500:
            remediation = remediation[:497] + "..."

        checks.append(CheckDefinition(
            check_id=check_id,
            title=ctrl.get("title", ""),
            description=description,
            severity=ctrl.get("severity", "medium"),
            provider=provider,
            service=service_area,
            category=category,
            cis_id=cis_id,
            cis_level=ctrl.get("cis_level"),
            cis_profile=ctrl.get("cis_profile"),
            assessment_type=ctrl.get("assessment_type", "manual"),
            scanner_check_ids=scanner_ids,
            rr_relevant=ctrl.get("rr_relevant", False),
            rr_domains=ctrl.get("rr_domains", []),
            dspm_relevant=ctrl.get("dspm_relevant", False),
            dspm_categories=ctrl.get("dspm_categories", []),
            remediation=remediation,
            tags=_build_tags(service_area, cis_id),
            source="cis",
        ))

    return checks


def _load_tuple_cis_controls(provider: str, controls: list[tuple],
                              scanner_mapping: dict[str, set[str]]) -> list[CheckDefinition]:
    """Load CIS controls in tuple format (Kubernetes)."""
    checks: list[CheckDefinition] = []

    for ctrl in controls:
        # Tuple format: (cis_id, title, cis_level, assessment_type, severity, service_area)
        cis_id = ctrl[0]
        title = ctrl[1] if len(ctrl) > 1 else ""
        cis_level = ctrl[2] if len(ctrl) > 2 else None
        assessment_type = ctrl[3] if len(ctrl) > 3 else "manual"
        severity = ctrl[4] if len(ctrl) > 4 else "medium"
        service_area = ctrl[5] if len(ctrl) > 5 else "General"

        check_id = f"{provider}_cis_{cis_id.replace('.', '_')}"
        key = f"{provider}:{cis_id}"
        scanner_ids = sorted(scanner_mapping.get(key, set()))

        category = _resolve_category(service_area)

        checks.append(CheckDefinition(
            check_id=check_id,
            title=title,
            description=title,
            severity=severity,
            provider=provider,
            service=service_area,
            category=category,
            cis_id=cis_id,
            cis_level=cis_level,
            assessment_type=assessment_type,
            scanner_check_ids=scanner_ids,
            tags=_build_tags(service_area, cis_id),
            source="cis",
        ))

    return checks


def _build_tags(service_area: str, cis_id: str) -> list[str]:
    """Build tags from service area and CIS ID."""
    tags = ["cis"]
    if service_area:
        tag = service_area.lower().replace(" ", "-").replace("_", "-")
        if tag and tag != "general":
            tags.append(tag)
    return tags


# ======================================================================
# Supplementary scanner checks (not covered by CIS)
# ======================================================================

def _load_supplementary_scanner_checks(
    cis_scanner_ids: set[str],
) -> list[CheckDefinition]:
    """Load scanner check_ids that are NOT mapped to any CIS control.

    These are implementation checks from the scanners that complement
    the CIS-based registry.
    """
    provider_files = {
        "aws": "scanner/providers/aws/aws_scanner.py",
        "azure": "scanner/providers/azure/azure_scanner.py",
        "gcp": "scanner/providers/gcp/gcp_scanner.py",
        "oci": "scanner/providers/oci/oci_scanner.py",
        "alibaba": "scanner/providers/alibaba/alibaba_scanner.py",
        "ibm_cloud": "scanner/providers/ibm_cloud/ibm_cloud_scanner.py",
        "kubernetes": "scanner/providers/kubernetes/k8s_scanner.py",
        "m365": "scanner/saas/m365/m365_scanner.py",
        "github": "scanner/saas/github/github_scanner.py",
        "google_workspace": "scanner/saas/google_workspace/google_workspace_scanner.py",
        "salesforce": "scanner/saas/salesforce/salesforce_scanner.py",
        "servicenow": "scanner/saas/servicenow/servicenow_scanner.py",
        "snowflake": "scanner/saas/snowflake/snowflake_scanner.py",
        "cloudflare": "scanner/saas/cloudflare/cloudflare_scanner.py",
        "openstack": "scanner/saas/openstack/openstack_scanner.py",
    }

    supplementary: list[CheckDefinition] = []

    for provider, filepath in provider_files.items():
        metadata = _extract_scanner_check_metadata(filepath)
        for check_id, meta in sorted(metadata.items()):
            if check_id in cis_scanner_ids:
                continue  # Already covered by a CIS control

            category = _resolve_category(meta["service"])
            supplementary.append(CheckDefinition(
                check_id=check_id,
                title=meta["title"],
                description=f"{meta['title']}.",
                severity=meta["severity"],
                provider=provider,
                service=meta["service"],
                category=category,
                scanner_check_ids=[check_id],
                tags=["scanner-supplementary"],
                source="scanner",
            ))

    return supplementary


# ======================================================================
# Main loader
# ======================================================================

def load_all_cis_checks() -> list[CheckDefinition]:
    """Load ALL CIS controls from all 9 benchmarks + supplementary scanner checks.

    Returns the complete list of CheckDefinition entries for the registry.
    """
    scanner_mapping = _build_scanner_mapping()
    all_checks: list[CheckDefinition] = []

    # -- Dict-format CIS providers --
    dict_providers = {
        "aws": ("scanner.cis_controls.aws_cis_controls", "AWS_CIS_CONTROLS"),
        "azure": ("scanner.cis_controls.azure_cis_controls", "AZURE_CIS_CONTROLS"),
        "gcp": ("scanner.cis_controls.gcp_cis_controls", "GCP_CIS_CONTROLS"),
        "oci": ("scanner.cis_controls.oci_cis_controls", "OCI_CIS_CONTROLS"),
        "alibaba": ("scanner.cis_controls.alibaba_cis_controls", "ALIBABA_CIS_CONTROLS"),
        "ibm_cloud": ("scanner.cis_controls.ibm_cloud_cis_controls", "IBM_CLOUD_CIS_CONTROLS"),
        "m365": ("scanner.cis_controls.m365_cis_controls", "M365_CIS_CONTROLS"),
        "google_workspace": ("scanner.cis_controls.google_workspace_cis_controls", "GOOGLE_WORKSPACE_CIS_CONTROLS"),
        "snowflake": ("scanner.cis_controls.snowflake_cis_controls", "SNOWFLAKE_CIS_CONTROLS"),
    }

    for provider, (module_path, var_name) in dict_providers.items():
        try:
            mod = __import__(module_path, fromlist=[var_name])
            controls = getattr(mod, var_name)
            checks = _load_dict_cis_controls(provider, controls, scanner_mapping)
            all_checks.extend(checks)
            logger.debug("Loaded %d CIS checks for %s", len(checks), provider)
        except Exception as e:
            logger.error("Failed to load CIS controls for %s: %s", provider, e)

    # -- Tuple-format CIS providers --
    tuple_providers = {
        "kubernetes": ("scanner.cis_controls.kubernetes_cis_controls", "KUBERNETES_CIS_CONTROLS"),
    }

    for provider, (module_path, var_name) in tuple_providers.items():
        try:
            mod = __import__(module_path, fromlist=[var_name])
            controls = getattr(mod, var_name)
            checks = _load_tuple_cis_controls(provider, controls, scanner_mapping)
            all_checks.extend(checks)
            logger.debug("Loaded %d CIS checks for %s", len(checks), provider)
        except Exception as e:
            logger.error("Failed to load CIS controls for %s: %s", provider, e)

    # -- Collect all scanner IDs already covered by CIS controls --
    cis_scanner_ids: set[str] = set()
    for chk in all_checks:
        cis_scanner_ids.update(chk.scanner_check_ids)

    # -- Add supplementary scanner checks --
    supplementary = _load_supplementary_scanner_checks(cis_scanner_ids)
    all_checks.extend(supplementary)
    logger.debug("Loaded %d supplementary scanner checks", len(supplementary))

    return all_checks
