"""Base utilities for CIS Kubernetes v1.12.0 evaluators.

Provides K8s client caching, pod argument extraction helpers,
and the EVALUATOR_REGISTRY pattern used by all sections.

Path: scanner/providers/kubernetes/evaluators/base.py
"""

import logging
import re
from typing import Optional, Callable

logger = logging.getLogger(__name__)


# ── Evaluator Registry ──────────────────────────────────────────────
# Maps CIS control ID → evaluator function
# Populated by section modules at import time
EVALUATOR_REGISTRY: dict[str, Callable] = {}


def register(cis_id: str):
    """Decorator to register an evaluator function for a CIS control."""
    def decorator(func):
        EVALUATOR_REGISTRY[cis_id] = func
        return func
    return decorator


# ── K8s Client Cache ────────────────────────────────────────────────

class K8sClientCache:
    """Caches K8s API clients and common queries to avoid redundant calls."""

    def __init__(self, credentials: dict):
        self.credentials = credentials
        self._client = None
        self._v1 = None
        self._rbac = None
        self._net = None
        self._api_server_args: Optional[list[str]] = None
        self._controller_manager_args: Optional[list[str]] = None
        self._scheduler_args: Optional[list[str]] = None
        self._etcd_args: Optional[list[str]] = None
        self._kubelet_configs: Optional[dict] = None

    @property
    def client(self):
        if self._client is None:
            from kubernetes import client, config
            kubeconfig = self.credentials.get("kubeconfig")
            if self.credentials.get("auth_method") == "in_cluster":
                config.load_incluster_config()
            elif kubeconfig:
                import tempfile, os, yaml
                with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
                    if isinstance(kubeconfig, dict):
                        yaml.dump(kubeconfig, f)
                    else:
                        f.write(kubeconfig)
                    path = f.name
                config.load_kube_config(path)
                os.unlink(path)
            else:
                config.load_incluster_config()
            self._client = client
        return self._client

    @property
    def v1(self):
        if self._v1 is None:
            self._v1 = self.client.CoreV1Api()
        return self._v1

    @property
    def rbac(self):
        if self._rbac is None:
            self._rbac = self.client.RbacAuthorizationV1Api()
        return self._rbac

    @property
    def net(self):
        if self._net is None:
            self._net = self.client.NetworkingV1Api()
        return self._net

    def get_component_args(self, component: str) -> list[str]:
        """Extract all command+args from a control plane component pod.

        Args:
            component: One of 'kube-apiserver', 'kube-controller-manager',
                       'kube-scheduler', 'etcd'
        Returns:
            List of all argument strings from the component's containers.
        """
        cache_attr = f"_{component.replace('-', '_').replace('kube_', '')}_args"
        # Normalize cache key
        if component == "kube-apiserver":
            cache_attr = "_api_server_args"
        elif component == "kube-controller-manager":
            cache_attr = "_controller_manager_args"
        elif component == "kube-scheduler":
            cache_attr = "_scheduler_args"
        elif component == "etcd":
            cache_attr = "_etcd_args"

        cached = getattr(self, cache_attr, None)
        if cached is not None:
            return cached

        all_args = []
        try:
            pods = self.v1.list_namespaced_pod(
                "kube-system", label_selector=f"component={component}")
            for pod in pods.items:
                for container in pod.spec.containers or []:
                    all_args.extend(container.command or [])
                    all_args.extend(container.args or [])
        except Exception as e:
            logger.warning("Could not read %s pod args: %s", component, e)

        setattr(self, cache_attr, all_args)
        return all_args

    @property
    def api_server_args(self) -> list[str]:
        return self.get_component_args("kube-apiserver")

    @property
    def controller_manager_args(self) -> list[str]:
        return self.get_component_args("kube-controller-manager")

    @property
    def scheduler_args(self) -> list[str]:
        return self.get_component_args("kube-scheduler")

    @property
    def etcd_args(self) -> list[str]:
        return self.get_component_args("etcd")


# ── Argument Checking Helpers ───────────────────────────────────────

def has_flag(args: list[str], flag: str) -> bool:
    """Check if a specific flag appears in the argument list."""
    return any(flag in a for a in args)


def get_flag_value(args: list[str], flag: str) -> Optional[str]:
    """Extract the value of a flag like --flag=value or --flag value."""
    for i, a in enumerate(args):
        if f"{flag}=" in a:
            return a.split("=", 1)[1]
        if a == flag and i + 1 < len(args):
            return args[i + 1]
    return None


def flag_is_true(args: list[str], flag: str) -> bool:
    """Check if a boolean flag is explicitly set to true."""
    val = get_flag_value(args, flag)
    return val is not None and val.lower() == "true"


def flag_is_false(args: list[str], flag: str) -> bool:
    """Check if a boolean flag is explicitly set to false."""
    val = get_flag_value(args, flag)
    return val is not None and val.lower() == "false"


def flag_not_set(args: list[str], flag: str) -> bool:
    """Check that a flag is NOT present in args."""
    return not has_flag(args, flag)


def flag_includes(args: list[str], flag: str, value: str) -> bool:
    """Check if a comma-separated flag value includes a specific item.
    E.g., --authorization-mode=Node,RBAC includes 'RBAC'.
    """
    val = get_flag_value(args, flag)
    if val is None:
        return False
    return value in val.split(",")


def flag_excludes(args: list[str], flag: str, value: str) -> bool:
    """Check if a comma-separated flag value does NOT include a specific item."""
    val = get_flag_value(args, flag)
    if val is None:
        return True  # Not set = doesn't include
    return value not in val.split(",")


def flag_int_gte(args: list[str], flag: str, minimum: int) -> Optional[bool]:
    """Check if a numeric flag value is >= minimum. Returns None if not set."""
    val = get_flag_value(args, flag)
    if val is None:
        return None
    try:
        return int(val) >= minimum
    except ValueError:
        return None


# ── Result Builder ──────────────────────────────────────────────────

COMPLIANCE = ["CIS-K8s-1.12", "NIST-800-53", "CCM-4.1"]


def build_result(check_id: str, title: str, service: str, severity: str,
                 status: str, resource_id: str, status_extended: str,
                 remediation: str, resource_name: str = "",
                 cis_id: str = "", assessment_type: str = "automated") -> dict:
    """Build a standardized check result dict."""
    from scanner.providers.base_check import CheckResult
    return CheckResult(
        check_id=check_id,
        check_title=title,
        service=service,
        severity=severity,
        status=status,
        resource_id=resource_id,
        resource_name=resource_name or resource_id,
        status_extended=status_extended,
        remediation=remediation,
        compliance_frameworks=COMPLIANCE,
        assessment_type=assessment_type,
        cis_control_id=cis_id,
    ).to_dict()
