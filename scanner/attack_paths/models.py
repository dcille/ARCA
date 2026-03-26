"""Shared data models for attack path analysis."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AttackCategory(str, Enum):
    """Categories of attack paths."""
    PRIVILEGE_ESCALATION = 'privilege_escalation'
    DATA_EXFILTRATION = 'data_exfiltration'
    LATERAL_MOVEMENT = 'lateral_movement'
    EXPOSURE = 'exposure'
    DETECTION_EVASION = 'detection_evasion'
    CREDENTIAL_ACCESS = 'credential_access'
    SUPPLY_CHAIN = 'supply_chain'
    RANSOMWARE = 'ransomware'


# Kill chain phases in order (for kill chain progress scoring)
KILL_CHAIN_PHASES = [
    'reconnaissance',
    'initial-access',
    'execution',
    'persistence',
    'privilege-escalation',
    'defense-evasion',
    'credential-access',
    'discovery',
    'lateral-movement',
    'collection',
    'exfiltration',
    'impact',
]

# Tactic to kill chain phase mapping
TACTIC_TO_PHASE = {
    'Reconnaissance': 'reconnaissance',
    'Initial Access': 'initial-access',
    'Execution': 'execution',
    'Persistence': 'persistence',
    'Privilege Escalation': 'privilege-escalation',
    'Defense Evasion': 'defense-evasion',
    'Credential Access': 'credential-access',
    'Discovery': 'discovery',
    'Lateral Movement': 'lateral-movement',
    'Collection': 'collection',
    'Exfiltration': 'exfiltration',
    'Impact': 'impact',
}

# Category weights for scoring (ransomware-specific impact weighting)
CATEGORY_WEIGHTS = {
    'privilege_escalation': 1.3,
    'data_exfiltration': 1.4,
    'lateral_movement': 1.2,
    'exposure': 1.0,
    'detection_evasion': 1.1,
    'credential_access': 1.3,
    'supply_chain': 1.5,
    'ransomware': 1.6,
}

# Severity weights
SEVERITY_WEIGHTS = {
    'critical': 10.0,
    'high': 7.0,
    'medium': 4.0,
    'low': 1.0,
}


# ── BAS 2.0 Confidence Levels ───────────────────────────────────────


class PathConfidence(str, Enum):
    """How confident we are that the attack path is exploitable."""
    TEMPLATE = "template"          # Discovered via CSPM template matching
    THEORETICAL = "theoretical"    # Discovered via IAM policy analysis (read-only)
    CONFIRMED = "confirmed"        # Confirmed via BAS simulation (future)


class PathSource(str, Enum):
    """How the attack path was discovered."""
    SCENARIO = "scenario"          # From SCENARIO_TEMPLATES
    IAM_DISCOVERY = "iam_discovery"  # From IAM Privesc Discovery engine
    COMBINED = "combined"          # From both


# ── IAM Privesc Pattern (for Phase 2+) ──────────────────────────────


@dataclass
class PrivescPattern:
    """A known IAM privilege escalation pattern."""
    id: str
    name: str
    required_perms: list[str]
    mitre_id: str
    description: str
    provider: str = "aws"

    def matches(self, effective_perms: set[str]) -> bool:
        """Check if the principal's effective permissions match this pattern."""
        for perm in self.required_perms:
            if perm.endswith("*"):
                prefix = perm[:-1]
                if not any(p.startswith(prefix) for p in effective_perms):
                    return False
            elif perm not in effective_perms:
                # Also check wildcard in effective_perms
                perm_parts = perm.split(":")
                if len(perm_parts) == 2:
                    service_wildcard = f"{perm_parts[0]}:*"
                    if service_wildcard not in effective_perms and "*" not in effective_perms:
                        return False
                else:
                    return False
        return True


@dataclass
class ShadowAdmin:
    """A non-admin principal that can escalate to admin."""
    principal_id: str
    principal_name: str
    principal_type: str  # iam_user, iam_role, service_account
    provider: str
    escalation_paths: list[str]  # list of PrivescPattern.id
    shortest_path_steps: int
    blast_radius_estimate: int = 0
