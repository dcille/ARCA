"""Framework enrichment data modules.

Contains new controls, SaaS mappings, OCI/Alibaba mappings, MITRE mappings,
and CIS cross-references for the D-ARCA compliance frameworks.

Usage:
    from scanner.enrichment import enrich_frameworks
    frameworks = _load_all_frameworks()   # from framework_validator
    count = enrich_frameworks(frameworks)
    print(f"Enriched {count} controls")
"""

import logging

logger = logging.getLogger(__name__)


def enrich_frameworks(frameworks: dict) -> dict:
    """Apply all enrichment layers to loaded frameworks.

    Modifies frameworks in-place and returns enrichment statistics.

    Layers applied (in order):
      1. Cloud gap (OCI/Alibaba) mappings
      2. SaaS provider mappings
    """
    stats = {
        "new_controls_added": 0,
        "cloud_gap_enriched": 0,
        "saas_enriched": 0,
        "total_enriched": 0,
    }

    # Layer 0: New controls (must come before provider enrichment)
    try:
        from scanner.enrichment.new_controls import apply_new_controls
        count = apply_new_controls(frameworks)
        stats["new_controls_added"] = count
        logger.info("New controls added: %d", count)
    except Exception as e:
        logger.warning("New controls enrichment failed: %s", e)

    # Layer 1: OCI / Alibaba cloud gap
    try:
        from scanner.enrichment.cloud_gap_mappings import apply_cloud_gap_enrichment
        count = apply_cloud_gap_enrichment(frameworks)
        stats["cloud_gap_enriched"] = count
        logger.info("Cloud gap enrichment: %d controls enriched", count)
    except Exception as e:
        logger.warning("Cloud gap enrichment failed: %s", e)

    # Layer 2: SaaS provider mappings
    try:
        from scanner.enrichment.saas_mappings import apply_saas_enrichment
        count = apply_saas_enrichment(frameworks)
        stats["saas_enriched"] = count
        logger.info("SaaS enrichment: %d controls enriched", count)
    except Exception as e:
        logger.warning("SaaS enrichment failed: %s", e)

    stats["total_enriched"] = (
        stats["new_controls_added"] + stats["cloud_gap_enriched"] + stats["saas_enriched"]
    )
    return stats
