"""CIS Kubernetes v1.12.0 evaluator functions.

Organized by CIS benchmark section:
  - section_1_control_plane: API Server (1.2), Controller Manager (1.3), Scheduler (1.4)
  - section_2_3_4: etcd (2), Control Plane Config (3), Worker Nodes (4)
  - section_5_supplements: RBAC, Pod Security, Network, Secrets, Admission supplements

All evaluators register themselves in EVALUATOR_REGISTRY via @register decorator.
The K8sCISEvaluatorEngine imports all modules and runs registered evaluators.

Path: scanner/providers/kubernetes/evaluators/__init__.py
"""

from scanner.providers.kubernetes.evaluators.base import EVALUATOR_REGISTRY

__all__ = ["EVALUATOR_REGISTRY"]
