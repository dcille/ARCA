"""Ransomware Readiness Framework - Rule catalog mapped to CSPM check_ids.

Defines 7 domains with 105 rules total, each mapping to existing CSPM checks
across AWS, Azure, and GCP. Based on NIST CSF 2.0 and NISTIR 8374.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Domain(str, Enum):
    D1 = "D1"  # Identity & Access Management
    D2 = "D2"  # Data Protection & Encryption
    D3 = "D3"  # Backup & Recovery Readiness
    D4 = "D4"  # Network Segmentation
    D5 = "D5"  # Platform Hardening
    D6 = "D6"  # Logging & Monitoring
    D7 = "D7"  # Awareness & Governance


class ScoreLevel(str, Enum):
    EXCELLENT = "Excelente"
    GOOD = "Bueno"
    MODERATE = "Moderado"
    LOW = "Bajo"
    CRITICAL = "Critico"


SCORE_LEVELS = [
    {"min": 90, "max": 100, "level": ScoreLevel.EXCELLENT, "color": "#2D8B4E"},
    {"min": 70, "max": 89, "level": ScoreLevel.GOOD, "color": "#27AE60"},
    {"min": 50, "max": 69, "level": ScoreLevel.MODERATE, "color": "#F39C12"},
    {"min": 30, "max": 49, "level": ScoreLevel.LOW, "color": "#E67E22"},
    {"min": 0, "max": 29, "level": ScoreLevel.CRITICAL, "color": "#C0392B"},
]

SEVERITY_PENALTY = {
    Severity.CRITICAL: -15,
    Severity.HIGH: -8,
    Severity.MEDIUM: -3,
    Severity.LOW: -1,
}


@dataclass
class RRRule:
    """A single Ransomware Readiness evaluation rule."""
    rule_id: str
    name: str
    description: str
    domain: Domain
    severity: Severity
    cloud_providers: list[str]
    resource_types: list[str]
    nist_category: str
    nist_subcategory: str
    check_ids: dict[str, list[str]]  # provider -> [check_ids]
    remediation: dict[str, str] = field(default_factory=dict)  # provider -> guidance
    ransomware_context: str = ""  # Why this control matters specifically for ransomware readiness
    is_composite: bool = False  # requires composite evaluation logic
    is_manual: bool = False  # requires manual operator input (D7)


@dataclass
class RRDomain:
    """A Ransomware Readiness evaluation domain."""
    domain_id: Domain
    name: str
    description: str
    nist_csf: str
    weight: float
    rules: list[RRRule]


def get_score_level(score: int) -> dict:
    """Return the level info for a given score."""
    for level in SCORE_LEVELS:
        if level["min"] <= score <= level["max"]:
            return level
    return SCORE_LEVELS[-1]


# ─── Domain weights ──────────────────────────────────────────
DOMAIN_WEIGHTS = {
    Domain.D1: 0.25,  # IAM
    Domain.D2: 0.20,  # Data Protection
    Domain.D3: 0.20,  # Backup & Recovery
    Domain.D4: 0.15,  # Network Segmentation
    Domain.D5: 0.10,  # Platform Hardening
    Domain.D6: 0.05,  # Logging & Monitoring
    Domain.D7: 0.05,  # Awareness & Governance
}


# ─── Domain metadata ────────────────────────────────────────
DOMAIN_METADATA = {
    Domain.D1: {
        "name": "Identity & Access Management",
        "description": "Evaluación de MFA, least privilege, credential management, service accounts, session management y privileged access.",
        "nist_csf": "PR.AA",
    },
    Domain.D2: {
        "name": "Data Protection & Encryption",
        "description": "Estado de cifrado at rest y in transit, gestión de claves KMS, CMK vs SSE, rotación de claves, DLP.",
        "nist_csf": "PR.DS",
    },
    Domain.D3: {
        "name": "Backup & Recovery Readiness",
        "description": "Inmutabilidad de backups, aislamiento, pruebas de restauración, RTO/RPO, cross-region/cross-account backup.",
        "nist_csf": "PR.DS / PR.IR",
    },
    Domain.D4: {
        "name": "Network Segmentation",
        "description": "Microsegmentación, deny-by-default, private endpoints, eliminación de acceso público, inspección de tráfico.",
        "nist_csf": "PR.IR",
    },
    Domain.D5: {
        "name": "Platform Hardening",
        "description": "Baseline configurations, CIS compliance, patch management, software inventory, secure defaults.",
        "nist_csf": "PR.PS",
    },
    Domain.D6: {
        "name": "Logging & Monitoring",
        "description": "Cobertura de logging, centralización, retención, protección anti-tampering de logs, alertas de cambio.",
        "nist_csf": "PR.PS",
    },
    Domain.D7: {
        "name": "Awareness & Governance",
        "description": "Políticas documentadas, training, roles y responsabilidades, tabletop exercises realizados.",
        "nist_csf": "PR.AT / GV",
    },
}


def get_all_rules() -> list[RRRule]:
    """Load and return all 105 rules from all domain modules."""
    from scanner.ransomware_readiness.rules_d1_iam import D1_RULES
    from scanner.ransomware_readiness.rules_d2_encryption import D2_RULES
    from scanner.ransomware_readiness.rules_d3_backup import D3_RULES
    from scanner.ransomware_readiness.rules_d4_network import D4_RULES
    from scanner.ransomware_readiness.rules_d5_hardening import D5_RULES
    from scanner.ransomware_readiness.rules_d6_logging import D6_RULES
    from scanner.ransomware_readiness.rules_d7_governance import D7_RULES
    return D1_RULES + D2_RULES + D3_RULES + D4_RULES + D5_RULES + D6_RULES + D7_RULES


def get_rules_by_domain(domain: Domain) -> list[RRRule]:
    """Return rules for a specific domain."""
    return [r for r in get_all_rules() if r.domain == domain]


def get_rule_by_id(rule_id: str) -> Optional[RRRule]:
    """Look up a single rule by its ID (e.g. RR-IAM-001)."""
    for r in get_all_rules():
        if r.rule_id == rule_id:
            return r
    return None


def build_check_id_to_rules_map() -> dict[str, list[RRRule]]:
    """Build a reverse index: CSPM check_id -> list of RR rules that reference it."""
    mapping: dict[str, list[RRRule]] = {}
    for rule in get_all_rules():
        for provider, check_ids in rule.check_ids.items():
            for cid in check_ids:
                if cid.startswith("__"):  # skip composite placeholders
                    continue
                mapping.setdefault(cid, []).append(rule)
    return mapping
