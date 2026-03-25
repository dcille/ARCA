"""Centralized security check registry for ARCA CSPM.

Provides the single source of truth for all security check definitions across
cloud providers (AWS, Azure, GCP, OCI, Alibaba, IBM Cloud, Kubernetes) and
SaaS platforms (M365, GitHub, Google Workspace, Salesforce, ServiceNow,
Snowflake, Cloudflare, OpenStack).

MITRE ATT&CK and Ransomware Readiness modules remain separate — they own
their mapping logic but can be cross-referenced/validated against this registry.
"""

from scanner.registry.models import CheckDefinition, ProviderType, Severity, Category
from scanner.registry.registry import CheckRegistry, get_default_registry

__all__ = [
    "CheckDefinition",
    "CheckRegistry",
    "ProviderType",
    "Severity",
    "Category",
    "get_default_registry",
]
