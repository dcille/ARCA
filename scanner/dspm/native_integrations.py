"""Integration with native cloud data security services.

Provides optional, enhanced scanning by leveraging cloud-native data
security services:

- **AWS Macie** — automated sensitive-data discovery for S3.
- **Azure Purview** — unified data governance and classification.
- **GCP DLP** — Data Loss Prevention API for content inspection.

All cloud SDK imports are wrapped in ``try/except`` so this module can
be imported regardless of which SDKs are installed.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════
# Optional SDK imports
# ═══════════════════════════════════════════════════════════════════════

try:
    import boto3
    from botocore.exceptions import ClientError as BotoClientError

    HAS_BOTO3 = True
except ImportError:
    boto3 = None  # type: ignore[assignment]
    BotoClientError = Exception  # type: ignore[misc,assignment]
    HAS_BOTO3 = False

try:
    from azure.identity import DefaultAzureCredential  # type: ignore[import-untyped]
    from azure.purview.catalog import PurviewCatalogClient  # type: ignore[import-untyped]
    from azure.purview.scanning import PurviewScanningClient  # type: ignore[import-untyped]

    HAS_AZURE_PURVIEW = True
except ImportError:
    HAS_AZURE_PURVIEW = False

try:
    from google.cloud import dlp_v2  # type: ignore[import-untyped]

    HAS_GCP_DLP = True
except ImportError:
    dlp_v2 = None  # type: ignore[assignment]
    HAS_GCP_DLP = False


# ═══════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class NativeServiceStatus:
    """Status of a cloud-native data-security service."""

    service_name: str
    provider: str
    enabled: bool
    configuration: dict = field(default_factory=dict)
    findings_count: int = 0
    last_scan: Optional[str] = None


@dataclass
class NativeScanResult:
    """Result set returned by a cloud-native scan or findings query."""

    provider: str
    service: str
    findings: list = field(default_factory=list)
    total_findings: int = 0
    sensitive_data_types: list = field(default_factory=list)
    resources_scanned: int = 0


# ═══════════════════════════════════════════════════════════════════════
# NativeIntegrations
# ═══════════════════════════════════════════════════════════════════════


class NativeIntegrations:
    """Unified interface to cloud-native data-security services.

    Each method gracefully handles missing SDKs and API errors, returning
    sensible defaults so that callers never need to guard imports
    themselves.
    """

    # ── AWS Macie ─────────────────────────────────────────────────────

    def check_macie_status(
        self,
        credentials: dict,
        region: str = "us-east-1",
    ) -> NativeServiceStatus:
        """Check whether Amazon Macie is enabled in the account/region.

        Args:
            credentials: Dict with ``aws_access_key_id``,
                         ``aws_secret_access_key``, and optionally
                         ``aws_session_token``.
            region: AWS region to query.

        Returns:
            :class:`NativeServiceStatus` for Macie.
        """
        if not HAS_BOTO3:
            logger.warning("boto3 is not installed; cannot check Macie status.")
            return NativeServiceStatus(
                service_name="Amazon Macie",
                provider="aws",
                enabled=False,
                configuration={"error": "boto3 not installed"},
            )

        try:
            session = boto3.Session(
                aws_access_key_id=credentials.get("aws_access_key_id"),
                aws_secret_access_key=credentials.get("aws_secret_access_key"),
                aws_session_token=credentials.get("aws_session_token"),
                region_name=region,
            )
            client = session.client("macie2")
            response = client.get_macie_session()

            status = response.get("status", "UNKNOWN")
            enabled = status == "ENABLED"

            return NativeServiceStatus(
                service_name="Amazon Macie",
                provider="aws",
                enabled=enabled,
                configuration={
                    "status": status,
                    "region": region,
                    "finding_publishing_frequency": response.get(
                        "findingPublishingFrequency", "UNKNOWN"
                    ),
                    "service_role": response.get("serviceRole", ""),
                    "created_at": str(response.get("createdAt", "")),
                    "updated_at": str(response.get("updatedAt", "")),
                },
            )
        except BotoClientError as exc:
            logger.error("AWS Macie status check failed: %s", exc)
            return NativeServiceStatus(
                service_name="Amazon Macie",
                provider="aws",
                enabled=False,
                configuration={"error": str(exc)},
            )

    def get_macie_findings(
        self,
        credentials: dict,
        region: str = "us-east-1",
        max_results: int = 100,
    ) -> NativeScanResult:
        """Retrieve Amazon Macie findings.

        Args:
            credentials: AWS credentials dict.
            region: AWS region.
            max_results: Maximum number of findings to retrieve.

        Returns:
            :class:`NativeScanResult` with Macie findings.
        """
        if not HAS_BOTO3:
            logger.warning("boto3 is not installed; cannot retrieve Macie findings.")
            return NativeScanResult(provider="aws", service="macie")

        try:
            session = boto3.Session(
                aws_access_key_id=credentials.get("aws_access_key_id"),
                aws_secret_access_key=credentials.get("aws_secret_access_key"),
                aws_session_token=credentials.get("aws_session_token"),
                region_name=region,
            )
            client = session.client("macie2")

            # List finding IDs
            list_response = client.list_findings(maxResults=max_results)
            finding_ids = list_response.get("findingIds", [])

            if not finding_ids:
                return NativeScanResult(provider="aws", service="macie")

            # Fetch full finding details
            details_response = client.get_findings(findingIds=finding_ids)
            raw_findings = details_response.get("findings", [])

            findings = []
            sensitive_types: set = set()
            resources_scanned: set = set()

            for f in raw_findings:
                finding = {
                    "id": f.get("id"),
                    "title": f.get("title"),
                    "description": f.get("description"),
                    "severity": f.get("severity", {}).get("description", "UNKNOWN"),
                    "type": f.get("type"),
                    "created_at": str(f.get("createdAt", "")),
                    "resource_type": (
                        f.get("resourcesAffected", {})
                        .get("s3Bucket", {})
                        .get("name", "")
                    ),
                }
                findings.append(finding)

                # Collect sensitive data types
                for detection in (
                    f.get("classificationDetails", {})
                    .get("result", {})
                    .get("sensitiveData", [])
                ):
                    for det in detection.get("detections", []):
                        sensitive_types.add(det.get("type", "unknown"))

                bucket_name = (
                    f.get("resourcesAffected", {})
                    .get("s3Bucket", {})
                    .get("name")
                )
                if bucket_name:
                    resources_scanned.add(bucket_name)

            return NativeScanResult(
                provider="aws",
                service="macie",
                findings=findings,
                total_findings=len(findings),
                sensitive_data_types=sorted(sensitive_types),
                resources_scanned=len(resources_scanned),
            )
        except BotoClientError as exc:
            logger.error("Failed to retrieve Macie findings: %s", exc)
            return NativeScanResult(provider="aws", service="macie")

    def trigger_macie_scan(
        self,
        credentials: dict,
        bucket_name: str,
        region: str = "us-east-1",
    ) -> dict:
        """Create an Amazon Macie classification job for a specific S3 bucket.

        Args:
            credentials: AWS credentials dict.
            bucket_name: Target S3 bucket name.
            region: AWS region.

        Returns:
            Dict with ``job_id`` and ``status`` keys.
        """
        if not HAS_BOTO3:
            logger.warning("boto3 is not installed; cannot trigger Macie scan.")
            return {"error": "boto3 not installed", "job_id": None, "status": "FAILED"}

        try:
            session = boto3.Session(
                aws_access_key_id=credentials.get("aws_access_key_id"),
                aws_secret_access_key=credentials.get("aws_secret_access_key"),
                aws_session_token=credentials.get("aws_session_token"),
                region_name=region,
            )
            client = session.client("macie2")

            response = client.create_classification_job(
                jobType="ONE_TIME",
                name=f"arca-dspm-scan-{bucket_name}",
                s3JobDefinition={
                    "bucketDefinitions": [
                        {
                            "accountId": credentials.get("account_id", ""),
                            "buckets": [bucket_name],
                        }
                    ]
                },
                description=f"ARCA DSPM on-demand scan for bucket {bucket_name}",
            )

            return {
                "job_id": response.get("jobId"),
                "job_arn": response.get("jobArn"),
                "status": "CREATED",
            }
        except BotoClientError as exc:
            logger.error("Failed to trigger Macie scan for %s: %s", bucket_name, exc)
            return {"error": str(exc), "job_id": None, "status": "FAILED"}

    # ── Azure Purview ─────────────────────────────────────────────────

    def check_purview_status(
        self,
        credentials: dict,
        account_name: str,
    ) -> NativeServiceStatus:
        """Check the status of an Azure Purview account.

        Args:
            credentials: Dict with Azure credentials. If empty, the
                         ``DefaultAzureCredential`` is used.
            account_name: Purview account name.

        Returns:
            :class:`NativeServiceStatus` for Purview.
        """
        if not HAS_AZURE_PURVIEW:
            logger.warning("Azure Purview SDK is not installed; cannot check status.")
            return NativeServiceStatus(
                service_name="Azure Purview",
                provider="azure",
                enabled=False,
                configuration={"error": "Azure Purview SDK not installed"},
            )

        try:
            credential = DefaultAzureCredential()
            endpoint = f"https://{account_name}.purview.azure.com"
            catalog_client = PurviewCatalogClient(
                endpoint=endpoint, credential=credential
            )

            # A lightweight call to verify connectivity
            # glossary list is typically available even on fresh accounts
            glossary = catalog_client.glossary.list_glossaries()
            # If the call succeeds the account is reachable and enabled
            return NativeServiceStatus(
                service_name="Azure Purview",
                provider="azure",
                enabled=True,
                configuration={
                    "account_name": account_name,
                    "endpoint": endpoint,
                    "glossary_count": len(list(glossary)),
                },
            )
        except Exception as exc:
            logger.error("Azure Purview status check failed: %s", exc)
            return NativeServiceStatus(
                service_name="Azure Purview",
                provider="azure",
                enabled=False,
                configuration={"error": str(exc)},
            )

    def get_purview_scan_results(
        self,
        credentials: dict,
        account_name: str,
    ) -> NativeScanResult:
        """Retrieve scan results from Azure Purview.

        Args:
            credentials: Azure credentials dict.
            account_name: Purview account name.

        Returns:
            :class:`NativeScanResult` with Purview findings.
        """
        if not HAS_AZURE_PURVIEW:
            logger.warning("Azure Purview SDK is not installed; cannot get results.")
            return NativeScanResult(provider="azure", service="purview")

        try:
            credential = DefaultAzureCredential()
            endpoint = f"https://{account_name}.purview.azure.com"

            scanning_client = PurviewScanningClient(
                endpoint=endpoint, credential=credential
            )

            # List data sources and their latest scan results
            findings = []
            sensitive_types: set = set()
            resources_scanned = 0

            data_sources = scanning_client.data_sources.list_all()
            for ds in data_sources:
                ds_name = ds.get("name", "")
                resources_scanned += 1

                scans = scanning_client.scans.list_by_data_source(ds_name)
                for scan in scans:
                    scan_name = scan.get("name", "")
                    runs = scanning_client.scan_result.list_scan_results(
                        data_source_name=ds_name, scan_name=scan_name
                    )
                    for run in runs:
                        finding = {
                            "data_source": ds_name,
                            "scan_name": scan_name,
                            "status": run.get("status", "UNKNOWN"),
                            "start_time": run.get("startTime", ""),
                            "end_time": run.get("endTime", ""),
                            "diagnostics": run.get("diagnostics", {}),
                        }
                        findings.append(finding)

                        # Extract classification types from diagnostics
                        for notification in run.get("diagnostics", {}).get(
                            "notifications", []
                        ):
                            if "classification" in notification.get("message", "").lower():
                                sensitive_types.add(notification.get("code", "unknown"))

            return NativeScanResult(
                provider="azure",
                service="purview",
                findings=findings,
                total_findings=len(findings),
                sensitive_data_types=sorted(sensitive_types),
                resources_scanned=resources_scanned,
            )
        except Exception as exc:
            logger.error("Failed to retrieve Purview scan results: %s", exc)
            return NativeScanResult(provider="azure", service="purview")

    # ── GCP DLP ───────────────────────────────────────────────────────

    def check_dlp_status(
        self,
        credentials: dict,
        project: str,
    ) -> NativeServiceStatus:
        """Check if the GCP DLP API is enabled for a project.

        Args:
            credentials: GCP credentials dict (unused when the
                         environment provides Application Default
                         Credentials).
            project: GCP project ID.

        Returns:
            :class:`NativeServiceStatus` for GCP DLP.
        """
        if not HAS_GCP_DLP:
            logger.warning("google-cloud-dlp is not installed; cannot check DLP status.")
            return NativeServiceStatus(
                service_name="GCP DLP",
                provider="gcp",
                enabled=False,
                configuration={"error": "google-cloud-dlp not installed"},
            )

        try:
            client = dlp_v2.DlpServiceClient()
            parent = f"projects/{project}"

            # A lightweight listing call to confirm the API is reachable
            stored_types = client.list_stored_info_types(request={"parent": parent})
            type_count = sum(1 for _ in stored_types)

            return NativeServiceStatus(
                service_name="GCP DLP",
                provider="gcp",
                enabled=True,
                configuration={
                    "project": project,
                    "stored_info_types": type_count,
                },
            )
        except Exception as exc:
            logger.error("GCP DLP status check failed: %s", exc)
            return NativeServiceStatus(
                service_name="GCP DLP",
                provider="gcp",
                enabled=False,
                configuration={"error": str(exc)},
            )

    def run_dlp_inspection(
        self,
        credentials: dict,
        project: str,
        content: str,
        info_types: list = None,
    ) -> NativeScanResult:
        """Inspect content using the GCP DLP API.

        Args:
            credentials: GCP credentials dict.
            project: GCP project ID.
            content: The text content to inspect.
            info_types: List of DLP info-type names to look for. If
                        ``None``, a sensible default set is used.

        Returns:
            :class:`NativeScanResult` with DLP inspection findings.
        """
        if not HAS_GCP_DLP:
            logger.warning("google-cloud-dlp is not installed; cannot run DLP inspection.")
            return NativeScanResult(provider="gcp", service="dlp")

        default_info_types = [
            "CREDIT_CARD_NUMBER",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "PERSON_NAME",
            "STREET_ADDRESS",
            "DATE_OF_BIRTH",
            "PASSPORT",
            "SPAIN_DNI_NUMBER",
            "SPAIN_NIE_NUMBER",
            "SPAIN_NIF_NUMBER",
            "IBAN_CODE",
            "MEDICAL_RECORD_NUMBER",
        ]

        selected_types = info_types or default_info_types

        try:
            client = dlp_v2.DlpServiceClient()
            parent = f"projects/{project}"

            inspect_config = {
                "info_types": [{"name": t} for t in selected_types],
                "min_likelihood": dlp_v2.Likelihood.POSSIBLE,
                "include_quote": True,
                "limits": {"max_findings_per_request": 100},
            }

            item = {"value": content}

            response = client.inspect_content(
                request={
                    "parent": parent,
                    "inspect_config": inspect_config,
                    "item": item,
                }
            )

            findings = []
            sensitive_types: set = set()

            for finding in response.result.findings:
                findings.append(
                    {
                        "info_type": finding.info_type.name,
                        "likelihood": dlp_v2.Likelihood(finding.likelihood).name,
                        "quote": finding.quote,
                        "location": {
                            "start": finding.location.byte_range.start,
                            "end": finding.location.byte_range.end,
                        },
                    }
                )
                sensitive_types.add(finding.info_type.name)

            return NativeScanResult(
                provider="gcp",
                service="dlp",
                findings=findings,
                total_findings=len(findings),
                sensitive_data_types=sorted(sensitive_types),
                resources_scanned=1,
            )
        except Exception as exc:
            logger.error("GCP DLP inspection failed: %s", exc)
            return NativeScanResult(provider="gcp", service="dlp")

    def get_dlp_findings(
        self,
        credentials: dict,
        project: str,
    ) -> NativeScanResult:
        """Retrieve existing GCP DLP job findings for a project.

        Args:
            credentials: GCP credentials dict.
            project: GCP project ID.

        Returns:
            :class:`NativeScanResult` with aggregated DLP findings.
        """
        if not HAS_GCP_DLP:
            logger.warning("google-cloud-dlp is not installed; cannot get DLP findings.")
            return NativeScanResult(provider="gcp", service="dlp")

        try:
            client = dlp_v2.DlpServiceClient()
            parent = f"projects/{project}"

            # List completed DLP jobs
            jobs = client.list_dlp_jobs(
                request={
                    "parent": parent,
                    "type_": dlp_v2.DlpJobType.INSPECT_JOB,
                    "filter": "state=DONE",
                }
            )

            findings = []
            sensitive_types: set = set()
            resources_scanned: set = set()

            for job in jobs:
                job_findings = job.inspect_details.result.info_type_stats
                resource_name = job.name
                resources_scanned.add(resource_name)

                for stat in job_findings:
                    info_type_name = stat.info_type.name
                    count = stat.count
                    sensitive_types.add(info_type_name)
                    findings.append(
                        {
                            "job_name": job.name,
                            "info_type": info_type_name,
                            "count": count,
                            "state": job.state.name,
                            "created": str(job.create_time),
                        }
                    )

            return NativeScanResult(
                provider="gcp",
                service="dlp",
                findings=findings,
                total_findings=len(findings),
                sensitive_data_types=sorted(sensitive_types),
                resources_scanned=len(resources_scanned),
            )
        except Exception as exc:
            logger.error("Failed to retrieve GCP DLP findings: %s", exc)
            return NativeScanResult(provider="gcp", service="dlp")

    # ── Dispatcher ────────────────────────────────────────────────────

    def get_native_service_status(
        self,
        provider: str,
        credentials: dict,
        **kwargs,
    ) -> NativeServiceStatus:
        """Check the status of the native data-security service for a provider.

        Acts as a dispatcher that routes to the appropriate provider-specific
        method.

        Args:
            provider: Cloud provider name (``aws``, ``azure``, ``gcp``).
            credentials: Provider-specific credentials dict.
            **kwargs: Additional keyword arguments forwarded to the
                      provider-specific method (e.g. ``region`` for AWS,
                      ``account_name`` for Azure, ``project`` for GCP).

        Returns:
            :class:`NativeServiceStatus` for the requested provider.
        """
        provider_lower = provider.lower().strip()

        if provider_lower == "aws":
            return self.check_macie_status(
                credentials=credentials,
                region=kwargs.get("region", "us-east-1"),
            )

        if provider_lower == "azure":
            account_name = kwargs.get("account_name", "")
            if not account_name:
                logger.error("account_name is required for Azure Purview status check.")
                return NativeServiceStatus(
                    service_name="Azure Purview",
                    provider="azure",
                    enabled=False,
                    configuration={"error": "account_name not provided"},
                )
            return self.check_purview_status(
                credentials=credentials,
                account_name=account_name,
            )

        if provider_lower == "gcp":
            project = kwargs.get("project", "")
            if not project:
                logger.error("project is required for GCP DLP status check.")
                return NativeServiceStatus(
                    service_name="GCP DLP",
                    provider="gcp",
                    enabled=False,
                    configuration={"error": "project not provided"},
                )
            return self.check_dlp_status(
                credentials=credentials,
                project=project,
            )

        logger.warning("No native data-security integration for provider '%s'.", provider)
        return NativeServiceStatus(
            service_name="Unknown",
            provider=provider,
            enabled=False,
            configuration={"error": f"Unsupported provider: {provider}"},
        )
