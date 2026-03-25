"""Cloud security scanner engine.

Supports AWS, Azure, GCP, Kubernetes, OCI, Alibaba, and IBM Cloud security assessments.
Each provider implements checks organized by service.
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class CloudScanner:
    """Main cloud scanner that dispatches to provider-specific scanners."""

    def __init__(
        self,
        provider_type: str,
        credentials: dict,
        region: Optional[str] = None,
        services: Optional[list] = None,
        regions: Optional[list] = None,
    ):
        self.provider_type = provider_type
        self.credentials = credentials
        self.region = region
        self.services = services
        self.regions = regions

    def run_checks(self) -> list[dict]:
        """Run all applicable security checks for the configured provider."""
        scanner_map = {
            "aws": self._run_aws_checks,
            "azure": self._run_azure_checks,
            "gcp": self._run_gcp_checks,
            "kubernetes": self._run_kubernetes_checks,
            "oci": self._run_oci_checks,
            "alibaba": self._run_alibaba_checks,
            "ibm_cloud": self._run_ibm_cloud_checks,
        }

        scanner_fn = scanner_map.get(self.provider_type)
        if not scanner_fn:
            raise ValueError(f"Unsupported provider: {self.provider_type}")

        return scanner_fn()

    def _run_aws_checks(self) -> list[dict]:
        from scanner.providers.aws.aws_scanner import AWSScanner
        scanner = AWSScanner(self.credentials, self.regions, self.services)
        return scanner.scan()

    def _run_azure_checks(self) -> list[dict]:
        from scanner.providers.azure.azure_scanner import AzureScanner
        scanner = AzureScanner(self.credentials, self.services)
        return scanner.scan()

    def _run_gcp_checks(self) -> list[dict]:
        from scanner.providers.gcp.gcp_scanner import GCPScanner
        scanner = GCPScanner(self.credentials, self.services)
        return scanner.scan()

    def _run_kubernetes_checks(self) -> list[dict]:
        from scanner.providers.kubernetes.k8s_scanner import K8sScanner
        scanner = K8sScanner(self.credentials)
        return scanner.scan()

    def _run_oci_checks(self) -> list[dict]:
        from scanner.providers.oci.oci_scanner import OCIScanner
        scanner = OCIScanner(self.credentials, self.regions, self.services)
        return scanner.scan()

    def _run_alibaba_checks(self) -> list[dict]:
        from scanner.providers.alibaba.alibaba_scanner import AlibabaScanner
        scanner = AlibabaScanner(self.credentials, self.regions, self.services)
        return scanner.scan()

    def _run_ibm_cloud_checks(self) -> list[dict]:
        from scanner.providers.ibm_cloud.ibm_cloud_scanner import IBMCloudScanner
        scanner = IBMCloudScanner(self.credentials, self.regions, self.services)
        return scanner.scan()
