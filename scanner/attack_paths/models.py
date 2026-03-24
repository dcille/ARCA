"""Shared data models for attack path analysis."""

from enum import Enum


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
