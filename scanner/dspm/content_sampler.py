"""Content sampling module for cloud data stores.

Samples objects from cloud storage services (S3, Azure Blob, GCS,
OCI Object Storage, Alibaba OSS) for PII scanning.  Downloads only
text-readable files, applies configurable sampling strategies, and
returns structured results with timing information.

Cloud SDK imports are deferred and wrapped in try/except so the module
stays importable even when a particular SDK is not installed.
"""

import logging
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION & DATA CLASSES
# ═══════════════════════════════════════════════════════════════════

_DEFAULT_SUPPORTED_EXTENSIONS: list[str] = [
    ".txt", ".csv", ".json", ".xml", ".log", ".tsv",
    ".sql", ".html", ".md", ".yaml", ".yml", ".ini",
    ".conf", ".properties",
]

_TEXT_CONTENT_TYPE_PREFIXES = (
    "text/",
    "application/json",
    "application/xml",
    "application/x-yaml",
    "application/sql",
    "application/csv",
)


@dataclass
class SampleConfig:
    """Controls how objects are selected and downloaded from a store."""

    max_objects_per_store: int = 100
    max_file_size: int = 1_048_576  # 1 MB
    supported_extensions: list[str] = field(
        default_factory=lambda: list(_DEFAULT_SUPPORTED_EXTENSIONS)
    )
    sampling_strategy: str = "random"  # random | recent | largest
    include_metadata: bool = True

    def __post_init__(self) -> None:
        valid_strategies = ("random", "recent", "largest")
        if self.sampling_strategy not in valid_strategies:
            raise ValueError(
                f"sampling_strategy must be one of {valid_strategies}, "
                f"got {self.sampling_strategy!r}"
            )


@dataclass
class SampledObject:
    """Represents a single object retrieved (or attempted) from a store."""

    store_type: str  # s3 | blob | gcs | oci | oss
    bucket_or_container: str
    object_key: str
    size_bytes: int
    last_modified: Optional[datetime] = None
    content_type: str = "application/octet-stream"
    content: Optional[bytes] = None
    metadata: dict = field(default_factory=dict)
    sample_error: Optional[str] = None


@dataclass
class ContentSampleResult:
    """Aggregated result of sampling a single cloud store."""

    store_type: str
    bucket_or_container: str
    total_objects_listed: int = 0
    objects_sampled: int = 0
    objects_with_content: int = 0
    errors: list[str] = field(default_factory=list)
    sampled_objects: list[SampledObject] = field(default_factory=list)
    sampling_duration_seconds: float = 0.0


# ═══════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def detect_encoding(content: bytes) -> str:
    """Return a best-guess encoding for *content* (utf-8, ascii, or latin-1).

    Uses a simple heuristic: try utf-8 first, then ascii, then fall back
    to latin-1 which accepts every byte sequence.
    """
    if not content:
        return "utf-8"
    for encoding in ("utf-8", "ascii"):
        try:
            content.decode(encoding)
            return encoding
        except (UnicodeDecodeError, ValueError):
            continue
    return "latin-1"


def decode_content(content: bytes) -> str:
    """Decode *content* to a string with automatic encoding detection.

    Falls back through utf-8 -> latin-1 so a string is always returned.
    """
    if not content:
        return ""
    encoding = detect_encoding(content)
    try:
        return content.decode(encoding)
    except (UnicodeDecodeError, ValueError):
        logger.warning("Decoding failed with %s, falling back to latin-1", encoding)
        return content.decode("latin-1", errors="replace")


# ═══════════════════════════════════════════════════════════════════
# CONTENT SAMPLER
# ═══════════════════════════════════════════════════════════════════

class ContentSampler:
    """Samples text-readable objects from cloud object stores."""

    def __init__(self, config: Optional[SampleConfig] = None) -> None:
        self.config = config or SampleConfig()

    # ── internal helpers ───────────────────────────────────────────

    @staticmethod
    def _is_text_content(content_type: str, key: str) -> bool:
        """Return *True* if the object is likely text based on MIME or extension."""
        if content_type:
            ct_lower = content_type.lower()
            if any(ct_lower.startswith(prefix) for prefix in _TEXT_CONTENT_TYPE_PREFIXES):
                return True

        _, ext = os.path.splitext(key)
        if ext.lower() in _DEFAULT_SUPPORTED_EXTENSIONS:
            return True

        return False

    def _filter_objects(self, objects: list[dict], config: SampleConfig) -> list[dict]:
        """Filter *objects* by extension and apply the configured sampling strategy.

        Each element of *objects* must be a dict with at least:
            key, size, last_modified (datetime or None), content_type
        """
        # Extension filter
        filtered = []
        for obj in objects:
            _, ext = os.path.splitext(obj["key"])
            if ext.lower() in config.supported_extensions:
                filtered.append(obj)

        if not filtered:
            return []

        # Apply strategy
        if config.sampling_strategy == "recent":
            filtered.sort(
                key=lambda o: o.get("last_modified") or datetime.min,
                reverse=True,
            )
            return filtered[: config.max_objects_per_store]

        if config.sampling_strategy == "largest":
            filtered.sort(key=lambda o: o.get("size", 0), reverse=True)
            return filtered[: config.max_objects_per_store]

        # Default: random
        if len(filtered) > config.max_objects_per_store:
            return random.sample(filtered, config.max_objects_per_store)
        return filtered

    # ── S3 ─────────────────────────────────────────────────────────

    def sample_s3_bucket(
        self,
        bucket_name: str,
        credentials: dict,
        region: Optional[str] = None,
    ) -> ContentSampleResult:
        """Sample text-readable objects from an Amazon S3 bucket."""
        t0 = time.monotonic()
        result = ContentSampleResult(store_type="s3", bucket_or_container=bucket_name)

        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError:
            msg = "boto3 is required for S3 sampling. Install with: pip install boto3"
            logger.error(msg)
            result.errors.append(msg)
            result.sampling_duration_seconds = time.monotonic() - t0
            return result

        try:
            session_kwargs: dict = {}
            if credentials.get("aws_access_key_id"):
                session_kwargs["aws_access_key_id"] = credentials["aws_access_key_id"]
                session_kwargs["aws_secret_access_key"] = credentials.get("aws_secret_access_key", "")
            if credentials.get("aws_session_token"):
                session_kwargs["aws_session_token"] = credentials["aws_session_token"]
            if credentials.get("profile_name"):
                session_kwargs["profile_name"] = credentials["profile_name"]

            session = boto3.Session(**session_kwargs)
            client_kwargs: dict = {}
            if region:
                client_kwargs["region_name"] = region
            s3 = session.client("s3", **client_kwargs)

            # List objects with pagination
            all_objects: list[dict] = []
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket_name):
                for item in page.get("Contents", []):
                    all_objects.append({
                        "key": item["Key"],
                        "size": item.get("Size", 0),
                        "last_modified": item.get("LastModified"),
                        "content_type": "",  # not available in listing
                    })

            result.total_objects_listed = len(all_objects)
            logger.info("S3 bucket %s: listed %d objects", bucket_name, result.total_objects_listed)

            selected = self._filter_objects(all_objects, self.config)
            result.objects_sampled = len(selected)

            for obj_info in selected:
                sampled = SampledObject(
                    store_type="s3",
                    bucket_or_container=bucket_name,
                    object_key=obj_info["key"],
                    size_bytes=obj_info["size"],
                    last_modified=obj_info.get("last_modified"),
                )
                try:
                    get_kwargs: dict = {"Bucket": bucket_name, "Key": obj_info["key"]}
                    read_size = min(obj_info["size"], self.config.max_file_size)
                    if read_size > 0:
                        get_kwargs["Range"] = f"bytes=0-{read_size - 1}"

                    resp = s3.get_object(**get_kwargs)
                    sampled.content = resp["Body"].read(self.config.max_file_size)
                    sampled.content_type = resp.get("ContentType", "")
                    if self.config.include_metadata:
                        sampled.metadata = resp.get("Metadata", {})
                    result.objects_with_content += 1
                except Exception as exc:
                    error_msg = f"Error downloading s3://{bucket_name}/{obj_info['key']}: {exc}"
                    logger.warning(error_msg)
                    sampled.sample_error = str(exc)
                    result.errors.append(error_msg)

                result.sampled_objects.append(sampled)

        except Exception as exc:
            error_msg = f"Error sampling S3 bucket {bucket_name}: {exc}"
            logger.error(error_msg)
            result.errors.append(error_msg)

        result.sampling_duration_seconds = time.monotonic() - t0
        return result

    # ── Azure Blob ─────────────────────────────────────────────────

    def sample_azure_blob_container(
        self,
        container_name: str,
        storage_account: str,
        credentials: dict,
    ) -> ContentSampleResult:
        """Sample text-readable objects from an Azure Blob Storage container."""
        t0 = time.monotonic()
        result = ContentSampleResult(store_type="blob", bucket_or_container=container_name)

        try:
            from azure.storage.blob import BlobServiceClient  # type: ignore[import-untyped]
        except ImportError:
            msg = (
                "azure-storage-blob is required for Azure Blob sampling. "
                "Install with: pip install azure-storage-blob"
            )
            logger.error(msg)
            result.errors.append(msg)
            result.sampling_duration_seconds = time.monotonic() - t0
            return result

        try:
            if credentials.get("connection_string"):
                service_client = BlobServiceClient.from_connection_string(
                    credentials["connection_string"]
                )
            else:
                account_url = f"https://{storage_account}.blob.core.windows.net"
                service_client = BlobServiceClient(
                    account_url=account_url,
                    credential=credentials.get("credential"),
                )

            container_client = service_client.get_container_client(container_name)

            # List blobs with pagination (iterator handles continuation automatically)
            all_objects: list[dict] = []
            for blob in container_client.list_blobs(include=["metadata"] if self.config.include_metadata else []):
                all_objects.append({
                    "key": blob.name,
                    "size": blob.size or 0,
                    "last_modified": blob.last_modified,
                    "content_type": (blob.content_settings.content_type or "") if blob.content_settings else "",
                    "metadata": blob.metadata or {},
                })

            result.total_objects_listed = len(all_objects)
            logger.info(
                "Azure container %s/%s: listed %d blobs",
                storage_account, container_name, result.total_objects_listed,
            )

            selected = self._filter_objects(all_objects, self.config)
            result.objects_sampled = len(selected)

            for obj_info in selected:
                sampled = SampledObject(
                    store_type="blob",
                    bucket_or_container=container_name,
                    object_key=obj_info["key"],
                    size_bytes=obj_info["size"],
                    last_modified=obj_info.get("last_modified"),
                    content_type=obj_info.get("content_type", ""),
                    metadata=obj_info.get("metadata", {}),
                )
                try:
                    blob_client = container_client.get_blob_client(obj_info["key"])
                    download = blob_client.download_blob(
                        offset=0,
                        length=self.config.max_file_size,
                    )
                    sampled.content = download.readall()
                    result.objects_with_content += 1
                except Exception as exc:
                    error_msg = (
                        f"Error downloading blob {storage_account}/"
                        f"{container_name}/{obj_info['key']}: {exc}"
                    )
                    logger.warning(error_msg)
                    sampled.sample_error = str(exc)
                    result.errors.append(error_msg)

                result.sampled_objects.append(sampled)

        except Exception as exc:
            error_msg = f"Error sampling Azure container {storage_account}/{container_name}: {exc}"
            logger.error(error_msg)
            result.errors.append(error_msg)

        result.sampling_duration_seconds = time.monotonic() - t0
        return result

    # ── GCS ────────────────────────────────────────────────────────

    def sample_gcs_bucket(
        self,
        bucket_name: str,
        credentials: dict,
    ) -> ContentSampleResult:
        """Sample text-readable objects from a Google Cloud Storage bucket."""
        t0 = time.monotonic()
        result = ContentSampleResult(store_type="gcs", bucket_or_container=bucket_name)

        try:
            from google.cloud import storage as gcs_storage  # type: ignore[import-untyped]
        except ImportError:
            msg = (
                "google-cloud-storage is required for GCS sampling. "
                "Install with: pip install google-cloud-storage"
            )
            logger.error(msg)
            result.errors.append(msg)
            result.sampling_duration_seconds = time.monotonic() - t0
            return result

        try:
            client_kwargs: dict = {}
            if credentials.get("project"):
                client_kwargs["project"] = credentials["project"]
            if credentials.get("credentials"):
                client_kwargs["credentials"] = credentials["credentials"]

            client = gcs_storage.Client(**client_kwargs)
            bucket = client.bucket(bucket_name)

            # List objects (pages automatically)
            all_objects: list[dict] = []
            for blob in client.list_blobs(bucket):
                all_objects.append({
                    "key": blob.name,
                    "size": blob.size or 0,
                    "last_modified": blob.updated,
                    "content_type": blob.content_type or "",
                    "metadata": blob.metadata or {},
                })

            result.total_objects_listed = len(all_objects)
            logger.info("GCS bucket %s: listed %d objects", bucket_name, result.total_objects_listed)

            selected = self._filter_objects(all_objects, self.config)
            result.objects_sampled = len(selected)

            for obj_info in selected:
                sampled = SampledObject(
                    store_type="gcs",
                    bucket_or_container=bucket_name,
                    object_key=obj_info["key"],
                    size_bytes=obj_info["size"],
                    last_modified=obj_info.get("last_modified"),
                    content_type=obj_info.get("content_type", ""),
                    metadata=obj_info.get("metadata", {}),
                )
                try:
                    blob = bucket.blob(obj_info["key"])
                    sampled.content = blob.download_as_bytes(
                        start=0,
                        end=self.config.max_file_size - 1,
                    )
                    result.objects_with_content += 1
                except Exception as exc:
                    error_msg = f"Error downloading gs://{bucket_name}/{obj_info['key']}: {exc}"
                    logger.warning(error_msg)
                    sampled.sample_error = str(exc)
                    result.errors.append(error_msg)

                result.sampled_objects.append(sampled)

        except Exception as exc:
            error_msg = f"Error sampling GCS bucket {bucket_name}: {exc}"
            logger.error(error_msg)
            result.errors.append(error_msg)

        result.sampling_duration_seconds = time.monotonic() - t0
        return result

    # ── OCI Object Storage ─────────────────────────────────────────

    def sample_oci_bucket(
        self,
        bucket_name: str,
        namespace: str,
        credentials: dict,
    ) -> ContentSampleResult:
        """Sample text-readable objects from an OCI Object Storage bucket."""
        t0 = time.monotonic()
        result = ContentSampleResult(store_type="oci", bucket_or_container=bucket_name)

        try:
            import oci  # type: ignore[import-untyped]
        except ImportError:
            msg = "oci is required for OCI Object Storage sampling. Install with: pip install oci"
            logger.error(msg)
            result.errors.append(msg)
            result.sampling_duration_seconds = time.monotonic() - t0
            return result

        try:
            if credentials.get("config"):
                config = credentials["config"]
            else:
                config = oci.config.from_file(
                    file_location=credentials.get("config_file", oci.config.DEFAULT_LOCATION),
                    profile_name=credentials.get("profile_name", "DEFAULT"),
                )

            object_storage = oci.object_storage.ObjectStorageClient(config)

            # List objects with pagination
            all_objects: list[dict] = []
            next_start = None
            while True:
                list_kwargs: dict = {
                    "namespace_name": namespace,
                    "bucket_name": bucket_name,
                }
                if next_start:
                    list_kwargs["start"] = next_start

                response = object_storage.list_objects(**list_kwargs, fields="name,size,timeModified")
                for obj in response.data.objects:
                    all_objects.append({
                        "key": obj.name,
                        "size": obj.size or 0,
                        "last_modified": obj.time_modified,
                        "content_type": "",
                    })

                next_start = response.data.next_start_with
                if not next_start:
                    break

            result.total_objects_listed = len(all_objects)
            logger.info("OCI bucket %s/%s: listed %d objects", namespace, bucket_name, result.total_objects_listed)

            selected = self._filter_objects(all_objects, self.config)
            result.objects_sampled = len(selected)

            for obj_info in selected:
                sampled = SampledObject(
                    store_type="oci",
                    bucket_or_container=bucket_name,
                    object_key=obj_info["key"],
                    size_bytes=obj_info["size"],
                    last_modified=obj_info.get("last_modified"),
                )
                try:
                    resp = object_storage.get_object(
                        namespace_name=namespace,
                        bucket_name=bucket_name,
                        object_name=obj_info["key"],
                        range=f"bytes=0-{self.config.max_file_size - 1}",
                    )
                    sampled.content = resp.data.content
                    sampled.content_type = resp.headers.get("Content-Type", "")
                    if self.config.include_metadata:
                        sampled.metadata = {
                            k: v for k, v in resp.headers.items()
                            if k.lower().startswith("opc-meta-")
                        }
                    result.objects_with_content += 1
                except Exception as exc:
                    error_msg = (
                        f"Error downloading oci://{namespace}/{bucket_name}/{obj_info['key']}: {exc}"
                    )
                    logger.warning(error_msg)
                    sampled.sample_error = str(exc)
                    result.errors.append(error_msg)

                result.sampled_objects.append(sampled)

        except Exception as exc:
            error_msg = f"Error sampling OCI bucket {namespace}/{bucket_name}: {exc}"
            logger.error(error_msg)
            result.errors.append(error_msg)

        result.sampling_duration_seconds = time.monotonic() - t0
        return result

    # ── Alibaba OSS ────────────────────────────────────────────────

    def sample_alibaba_oss_bucket(
        self,
        bucket_name: str,
        credentials: dict,
        region: Optional[str] = None,
    ) -> ContentSampleResult:
        """Sample text-readable objects from an Alibaba Cloud OSS bucket."""
        t0 = time.monotonic()
        result = ContentSampleResult(store_type="oss", bucket_or_container=bucket_name)

        try:
            import oss2  # type: ignore[import-untyped]
        except ImportError:
            msg = "oss2 is required for Alibaba OSS sampling. Install with: pip install oss2"
            logger.error(msg)
            result.errors.append(msg)
            result.sampling_duration_seconds = time.monotonic() - t0
            return result

        try:
            access_key_id = credentials.get("access_key_id", "")
            access_key_secret = credentials.get("access_key_secret", "")
            endpoint = credentials.get("endpoint", "")
            if not endpoint and region:
                endpoint = f"https://oss-{region}.aliyuncs.com"

            auth = oss2.Auth(access_key_id, access_key_secret)
            bucket = oss2.Bucket(auth, endpoint, bucket_name)

            # List objects with pagination
            all_objects: list[dict] = []
            marker = ""
            while True:
                result_list = bucket.list_objects(marker=marker)
                for obj in result_list.object_list:
                    all_objects.append({
                        "key": obj.key,
                        "size": obj.size or 0,
                        "last_modified": datetime.utcfromtimestamp(obj.last_modified) if isinstance(obj.last_modified, (int, float)) else obj.last_modified,
                        "content_type": obj.type or "",
                    })
                if result_list.is_truncated:
                    marker = result_list.next_marker
                else:
                    break

            result.total_objects_listed = len(all_objects)
            logger.info("Alibaba OSS bucket %s: listed %d objects", bucket_name, result.total_objects_listed)

            selected = self._filter_objects(all_objects, self.config)
            result.objects_sampled = len(selected)

            for obj_info in selected:
                sampled = SampledObject(
                    store_type="oss",
                    bucket_or_container=bucket_name,
                    object_key=obj_info["key"],
                    size_bytes=obj_info["size"],
                    last_modified=obj_info.get("last_modified"),
                    content_type=obj_info.get("content_type", ""),
                )
                try:
                    byte_range = (0, self.config.max_file_size - 1)
                    resp = bucket.get_object(obj_info["key"], byte_range=byte_range)
                    sampled.content = resp.read(self.config.max_file_size)
                    if self.config.include_metadata:
                        sampled.metadata = resp.headers.get("x-oss-meta", {})
                    result.objects_with_content += 1
                except Exception as exc:
                    error_msg = (
                        f"Error downloading oss://{bucket_name}/{obj_info['key']}: {exc}"
                    )
                    logger.warning(error_msg)
                    sampled.sample_error = str(exc)
                    result.errors.append(error_msg)

                result.sampled_objects.append(sampled)

        except Exception as exc:
            error_msg = f"Error sampling Alibaba OSS bucket {bucket_name}: {exc}"
            logger.error(error_msg)
            result.errors.append(error_msg)

        result.sampling_duration_seconds = time.monotonic() - t0
        return result

    # ── Dispatcher ─────────────────────────────────────────────────

    def sample_store(self, store_type: str, **kwargs) -> ContentSampleResult:
        """Dispatch to the appropriate cloud sampling method.

        Parameters
        ----------
        store_type:
            One of ``s3``, ``blob``, ``gcs``, ``oci``, ``oss``.
        **kwargs:
            Forwarded to the provider-specific method.
        """
        dispatchers = {
            "s3": self.sample_s3_bucket,
            "blob": self.sample_azure_blob_container,
            "gcs": self.sample_gcs_bucket,
            "oci": self.sample_oci_bucket,
            "oss": self.sample_alibaba_oss_bucket,
        }

        handler = dispatchers.get(store_type)
        if handler is None:
            error_msg = (
                f"Unsupported store_type {store_type!r}. "
                f"Must be one of: {', '.join(sorted(dispatchers))}"
            )
            logger.error(error_msg)
            return ContentSampleResult(
                store_type=store_type,
                bucket_or_container=kwargs.get("bucket_name", "unknown"),
                errors=[error_msg],
            )

        return handler(**kwargs)
