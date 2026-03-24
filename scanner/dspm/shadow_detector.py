"""DSPM Shadow Data Detector — finds copies of sensitive data in unmanaged locations."""
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# Secret patterns for environment variable scanning
# ═══════════════════════════════════════════════════════════════════════

SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+'), 'password'),
    (re.compile(r'(?i)(secret|api_key|apikey|access_key)\s*[=:]\s*\S+'), 'api_key'),
    (re.compile(r'(?i)(token|bearer)\s*[=:]\s*\S+'), 'token'),
    (re.compile(r'(?i)(connection_string|conn_str|database_url)\s*[=:]\s*\S+'), 'connection_string'),
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'aws_access_key'),
    (re.compile(r'(?i)(private_key|privatekey)\s*[=:]\s*\S+'), 'private_key'),
]


# ═══════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ShadowDataFinding:
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_type: str = ""  # public_snapshot, public_ami, unencrypted_export, etc.
    provider: str = ""
    resource_id: str = ""
    resource_name: str = ""
    region: str = ""
    severity: str = "medium"
    description: str = ""
    source_data_store: Optional[str] = None
    remediation: str = ""
    evidence: dict = field(default_factory=dict)


@dataclass
class ShadowDataReport:
    provider: str = ""
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    findings: list[ShadowDataFinding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0


# ═══════════════════════════════════════════════════════════════════════
# Default AWS regions to scan when none are specified
# ═══════════════════════════════════════════════════════════════════════

_DEFAULT_AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-northeast-1",
]


# ═══════════════════════════════════════════════════════════════════════
# ShadowDataDetector
# ═══════════════════════════════════════════════════════════════════════

class ShadowDataDetector:
    """Detects shadow copies of sensitive data in unmanaged cloud locations."""

    # ── Main dispatcher ──────────────────────────────────────────────

    def detect_shadow_data(
        self,
        provider: str,
        credentials: Optional[dict] = None,
        **kwargs,
    ) -> ShadowDataReport:
        """Dispatch to the correct provider-specific detector."""
        dispatch = {
            "aws": self.detect_aws_shadow_data,
            "azure": self.detect_azure_shadow_data,
            "gcp": self.detect_gcp_shadow_data,
        }
        handler = dispatch.get(provider)
        if handler is None:
            logger.warning("Unsupported provider=%s for shadow data detection", provider)
            return ShadowDataReport(
                provider=provider,
                findings=[ShadowDataFinding(
                    finding_type="unsupported_provider",
                    provider=provider,
                    severity="low",
                    description=f"Provider '{provider}' is not supported for shadow data detection",
                )],
                total_findings=1,
                low=1,
            )
        return handler(credentials=credentials, **kwargs)

    # ═══════════════════════════════════════════════════════════════════
    # AWS
    # ═══════════════════════════════════════════════════════════════════

    def detect_aws_shadow_data(
        self,
        credentials: Optional[dict] = None,
        regions: Optional[list[str]] = None,
    ) -> ShadowDataReport:
        """Orchestrate all AWS shadow data checks across the specified regions."""
        try:
            import boto3
        except ImportError:
            logger.error("boto3 is required for AWS shadow data detection")
            return ShadowDataReport(provider="aws")

        start_time = datetime.utcnow()
        regions = regions or _DEFAULT_AWS_REGIONS
        findings: list[ShadowDataFinding] = []

        session_kwargs = {}
        if credentials:
            session_kwargs.update({
                "aws_access_key_id": credentials.get("access_key"),
                "aws_secret_access_key": credentials.get("secret_key"),
                "aws_session_token": credentials.get("session_token"),
            })

        for region in regions:
            session = boto3.Session(region_name=region, **session_kwargs)
            ec2_client = session.client("ec2")
            rds_client = session.client("rds")
            s3_client = session.client("s3")
            lambda_client = session.client("lambda")

            findings.extend(self._check_public_ebs_snapshots(ec2_client, region))
            findings.extend(self._check_public_amis(ec2_client, region))
            findings.extend(self._check_rds_snapshot_public(rds_client, region))
            findings.extend(self._check_unencrypted_rds_exports(s3_client, rds_client, region))
            findings.extend(self._check_lambda_env_secrets(lambda_client, region))
            findings.extend(self._check_orphaned_ebs_volumes(ec2_client, region))

        # Cross-region replication (uses the first region's S3 client)
        session = boto3.Session(region_name=regions[0], **session_kwargs)
        s3_client = session.client("s3")
        findings.extend(self._check_cross_region_replication(s3_client))

        elapsed = (datetime.utcnow() - start_time).total_seconds()
        return self._build_report("aws", findings, elapsed)

    # ── AWS helpers ──────────────────────────────────────────────────

    def _check_public_ebs_snapshots(
        self, ec2_client, region: str,
    ) -> list[ShadowDataFinding]:
        """Detect EBS snapshots shared publicly (createVolumePermission = all)."""
        findings: list[ShadowDataFinding] = []
        try:
            paginator = ec2_client.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                for snap in page.get("Snapshots", []):
                    snapshot_id = snap["SnapshotId"]
                    try:
                        attrs = ec2_client.describe_snapshot_attribute(
                            SnapshotId=snapshot_id,
                            Attribute="createVolumePermission",
                        )
                        for perm in attrs.get("CreateVolumePermissions", []):
                            if perm.get("Group") == "all":
                                findings.append(ShadowDataFinding(
                                    finding_type="public_ebs_snapshot",
                                    provider="aws",
                                    resource_id=snapshot_id,
                                    resource_name=snap.get("Description", snapshot_id),
                                    region=region,
                                    severity="critical",
                                    description=(
                                        f"EBS snapshot {snapshot_id} is publicly shared. "
                                        "Anyone can create volumes from this snapshot."
                                    ),
                                    source_data_store=snap.get("VolumeId"),
                                    remediation=(
                                        "Remove public sharing: modify snapshot permissions "
                                        "to remove the 'all' group."
                                    ),
                                    evidence={
                                        "volume_id": snap.get("VolumeId"),
                                        "volume_size_gb": snap.get("VolumeSize"),
                                        "encrypted": snap.get("Encrypted", False),
                                        "start_time": str(snap.get("StartTime", "")),
                                    },
                                ))
                    except Exception as exc:
                        logger.debug(
                            "Could not check attributes for snapshot %s: %s",
                            snapshot_id, exc,
                        )
        except Exception as exc:
            logger.warning("Could not list EBS snapshots in %s: %s", region, exc)

        return findings

    def _check_public_amis(
        self, ec2_client, region: str,
    ) -> list[ShadowDataFinding]:
        """Detect AMIs owned by self that are publicly shared."""
        findings: list[ShadowDataFinding] = []
        try:
            resp = ec2_client.describe_images(Owners=["self"])
            for image in resp.get("Images", []):
                if image.get("Public", False):
                    image_id = image["ImageId"]
                    findings.append(ShadowDataFinding(
                        finding_type="public_ami",
                        provider="aws",
                        resource_id=image_id,
                        resource_name=image.get("Name", image_id),
                        region=region,
                        severity="high",
                        description=(
                            f"AMI {image_id} is publicly shared. "
                            "It may contain sensitive data baked into the image."
                        ),
                        remediation=(
                            "Modify the AMI launch permissions to remove public access."
                        ),
                        evidence={
                            "name": image.get("Name"),
                            "creation_date": image.get("CreationDate"),
                            "block_device_mappings": [
                                bdm.get("Ebs", {}).get("SnapshotId", "")
                                for bdm in image.get("BlockDeviceMappings", [])
                                if "Ebs" in bdm
                            ],
                        },
                    ))
        except Exception as exc:
            logger.warning("Could not list AMIs in %s: %s", region, exc)

        return findings

    def _check_rds_snapshot_public(
        self, rds_client, region: str,
    ) -> list[ShadowDataFinding]:
        """Detect RDS snapshots shared with 'all' (public)."""
        findings: list[ShadowDataFinding] = []
        try:
            paginator = rds_client.get_paginator("describe_db_snapshots")
            for page in paginator.paginate(SnapshotType="manual"):
                for snap in page.get("DBSnapshots", []):
                    snapshot_id = snap["DBSnapshotIdentifier"]
                    try:
                        attrs = rds_client.describe_db_snapshot_attributes(
                            DBSnapshotIdentifier=snapshot_id,
                        )
                        result = attrs.get("DBSnapshotAttributesResult", {})
                        for attr in result.get("DBSnapshotAttributes", []):
                            if attr.get("AttributeName") == "restore" and "all" in attr.get("AttributeValues", []):
                                findings.append(ShadowDataFinding(
                                    finding_type="public_rds_snapshot",
                                    provider="aws",
                                    resource_id=snapshot_id,
                                    resource_name=snapshot_id,
                                    region=region,
                                    severity="critical",
                                    description=(
                                        f"RDS snapshot {snapshot_id} is publicly shared. "
                                        "Anyone can restore a database from this snapshot."
                                    ),
                                    source_data_store=snap.get("DBInstanceIdentifier"),
                                    remediation=(
                                        "Remove public access from the RDS snapshot by "
                                        "modifying the snapshot attribute to remove 'all'."
                                    ),
                                    evidence={
                                        "db_instance": snap.get("DBInstanceIdentifier"),
                                        "engine": snap.get("Engine"),
                                        "allocated_storage_gb": snap.get("AllocatedStorage"),
                                        "encrypted": snap.get("Encrypted", False),
                                        "snapshot_create_time": str(
                                            snap.get("SnapshotCreateTime", "")
                                        ),
                                    },
                                ))
                    except Exception as exc:
                        logger.debug(
                            "Could not check RDS snapshot attrs for %s: %s",
                            snapshot_id, exc,
                        )
        except Exception as exc:
            logger.warning("Could not list RDS snapshots in %s: %s", region, exc)

        return findings

    def _check_unencrypted_rds_exports(
        self, s3_client, rds_client, region: str,
    ) -> list[ShadowDataFinding]:
        """Detect RDS export tasks that target unencrypted S3 destinations."""
        findings: list[ShadowDataFinding] = []
        try:
            resp = rds_client.describe_export_tasks()
            for task in resp.get("ExportTasks", []):
                task_id = task.get("ExportTaskIdentifier", "")
                s3_bucket = task.get("S3Bucket", "")
                kms_key_id = task.get("KmsKeyId", "")

                if not kms_key_id:
                    findings.append(ShadowDataFinding(
                        finding_type="unencrypted_rds_export",
                        provider="aws",
                        resource_id=task_id,
                        resource_name=task_id,
                        region=region,
                        severity="high",
                        description=(
                            f"RDS export task {task_id} exports data to S3 bucket "
                            f"'{s3_bucket}' without KMS encryption."
                        ),
                        source_data_store=task.get("SourceArn"),
                        remediation=(
                            "Re-create the export task with a KMS key for encryption, "
                            "and delete the unencrypted export from S3."
                        ),
                        evidence={
                            "s3_bucket": s3_bucket,
                            "s3_prefix": task.get("S3Prefix", ""),
                            "source_arn": task.get("SourceArn"),
                            "status": task.get("Status"),
                            "percent_progress": task.get("PercentProgress"),
                        },
                    ))
        except Exception as exc:
            logger.warning("Could not list RDS export tasks in %s: %s", region, exc)

        return findings

    def _check_cross_region_replication(
        self, s3_client,
    ) -> list[ShadowDataFinding]:
        """Detect S3 replication rules that target unencrypted destinations."""
        findings: list[ShadowDataFinding] = []
        try:
            buckets = s3_client.list_buckets().get("Buckets", [])
        except Exception as exc:
            logger.warning("Could not list S3 buckets: %s", exc)
            return findings

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                repl = s3_client.get_bucket_replication(Bucket=bucket_name)
                rules = repl.get("ReplicationConfiguration", {}).get("Rules", [])
                for rule in rules:
                    if rule.get("Status") != "Enabled":
                        continue
                    dest = rule.get("Destination", {})
                    dest_bucket = dest.get("Bucket", "")
                    encryption = dest.get("EncryptionConfiguration", {})
                    if not encryption.get("ReplicaKmsKeyID"):
                        findings.append(ShadowDataFinding(
                            finding_type="unencrypted_replication",
                            provider="aws",
                            resource_id=bucket_name,
                            resource_name=bucket_name,
                            region="global",
                            severity="medium",
                            description=(
                                f"S3 bucket '{bucket_name}' replicates to "
                                f"'{dest_bucket}' without KMS encryption on the replica."
                            ),
                            source_data_store=bucket_name,
                            remediation=(
                                "Update the replication rule to include a KMS key "
                                "for encrypting replicated objects."
                            ),
                            evidence={
                                "destination_bucket": dest_bucket,
                                "rule_id": rule.get("ID", ""),
                                "rule_priority": rule.get("Priority"),
                            },
                        ))
            except s3_client.exceptions.ClientError:
                # No replication configuration — that is fine
                pass
            except Exception as exc:
                logger.debug("Could not check replication for %s: %s", bucket_name, exc)

        return findings

    def _check_lambda_env_secrets(
        self, lambda_client, region: str,
    ) -> list[ShadowDataFinding]:
        """Scan Lambda function environment variables for embedded secrets."""
        findings: list[ShadowDataFinding] = []
        try:
            paginator = lambda_client.get_paginator("list_functions")
            for page in paginator.paginate():
                for func in page.get("Functions", []):
                    func_name = func.get("FunctionName", "")
                    func_arn = func.get("FunctionArn", "")
                    env_vars = func.get("Environment", {}).get("Variables", {})
                    detected_secrets: list[dict] = []

                    for key, value in env_vars.items():
                        combined = f"{key}={value}"
                        for pattern, secret_type in SECRET_PATTERNS:
                            if pattern.search(combined):
                                detected_secrets.append({
                                    "env_var": key,
                                    "secret_type": secret_type,
                                })
                                break  # One match per env var is enough

                    if detected_secrets:
                        findings.append(ShadowDataFinding(
                            finding_type="lambda_env_secret",
                            provider="aws",
                            resource_id=func_arn,
                            resource_name=func_name,
                            region=region,
                            severity="high",
                            description=(
                                f"Lambda function '{func_name}' has "
                                f"{len(detected_secrets)} environment variable(s) "
                                "containing potential secrets."
                            ),
                            remediation=(
                                "Move secrets to AWS Secrets Manager or SSM Parameter "
                                "Store and reference them at runtime."
                            ),
                            evidence={
                                "secrets_found": [
                                    {"env_var": s["env_var"], "type": s["secret_type"]}
                                    for s in detected_secrets
                                ],
                            },
                        ))
        except Exception as exc:
            logger.warning("Could not list Lambda functions in %s: %s", region, exc)

        return findings

    def _check_orphaned_ebs_volumes(
        self, ec2_client, region: str,
    ) -> list[ShadowDataFinding]:
        """Detect EBS volumes that are not attached to any instance."""
        findings: list[ShadowDataFinding] = []
        try:
            paginator = ec2_client.get_paginator("describe_volumes")
            for page in paginator.paginate(
                Filters=[{"Name": "status", "Values": ["available"]}],
            ):
                for vol in page.get("Volumes", []):
                    volume_id = vol["VolumeId"]
                    encrypted = vol.get("Encrypted", False)
                    severity = "medium" if encrypted else "high"

                    # Get volume name from tags
                    tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
                    vol_name = tags.get("Name", volume_id)

                    findings.append(ShadowDataFinding(
                        finding_type="orphaned_ebs_volume",
                        provider="aws",
                        resource_id=volume_id,
                        resource_name=vol_name,
                        region=region,
                        severity=severity,
                        description=(
                            f"EBS volume {volume_id} ({vol.get('Size', '?')} GB) "
                            "is not attached to any instance and may contain "
                            "residual sensitive data."
                        ),
                        remediation=(
                            "Review the volume contents, create a snapshot if needed, "
                            "and delete the orphaned volume."
                        ),
                        evidence={
                            "size_gb": vol.get("Size"),
                            "encrypted": encrypted,
                            "volume_type": vol.get("VolumeType"),
                            "create_time": str(vol.get("CreateTime", "")),
                            "availability_zone": vol.get("AvailabilityZone"),
                        },
                    ))
        except Exception as exc:
            logger.warning("Could not list EBS volumes in %s: %s", region, exc)

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # Azure
    # ═══════════════════════════════════════════════════════════════════

    def detect_azure_shadow_data(
        self,
        credentials: Optional[dict] = None,
    ) -> ShadowDataReport:
        """Orchestrate all Azure shadow data checks."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.compute import ComputeManagementClient
            from azure.mgmt.storage import StorageManagementClient
        except ImportError:
            logger.error("Azure SDK packages are required for Azure shadow data detection")
            return ShadowDataReport(provider="azure")

        start_time = datetime.utcnow()
        subscription_id = (credentials or {}).get("subscription_id", "")

        credential = DefaultAzureCredential()
        compute_client = ComputeManagementClient(credential, subscription_id)
        storage_client = StorageManagementClient(credential, subscription_id)

        findings: list[ShadowDataFinding] = []
        findings.extend(self._check_public_disk_snapshots(compute_client))
        findings.extend(self._check_public_managed_images(compute_client))
        findings.extend(self._check_unmanaged_blobs(storage_client))
        findings.extend(self._check_orphaned_disks(compute_client))

        elapsed = (datetime.utcnow() - start_time).total_seconds()
        return self._build_report("azure", findings, elapsed)

    # ── Azure helpers ────────────────────────────────────────────────

    def _check_public_disk_snapshots(
        self, compute_client,
    ) -> list[ShadowDataFinding]:
        """Detect Azure managed disk snapshots with public network access."""
        findings: list[ShadowDataFinding] = []
        try:
            for snap in compute_client.snapshots.list():
                network_access = getattr(snap, "network_access_policy", "DenyAll")
                public_access = getattr(snap, "public_network_access", "Disabled")

                if network_access == "AllowAll" or public_access == "Enabled":
                    findings.append(ShadowDataFinding(
                        finding_type="public_disk_snapshot",
                        provider="azure",
                        resource_id=getattr(snap, "id", ""),
                        resource_name=getattr(snap, "name", ""),
                        region=getattr(snap, "location", ""),
                        severity="high",
                        description=(
                            f"Disk snapshot '{snap.name}' has public network access "
                            "enabled, allowing data exfiltration."
                        ),
                        source_data_store=getattr(snap, "creation_data", {}).get(
                            "source_resource_id", None
                        ) if hasattr(snap, "creation_data") else None,
                        remediation=(
                            "Set network access policy to DenyAll and disable "
                            "public network access on the snapshot."
                        ),
                        evidence={
                            "network_access_policy": network_access,
                            "public_network_access": public_access,
                            "disk_size_gb": getattr(snap, "disk_size_gb", None),
                            "time_created": str(getattr(snap, "time_created", "")),
                        },
                    ))
        except Exception as exc:
            logger.warning("Could not list Azure disk snapshots: %s", exc)

        return findings

    def _check_public_managed_images(
        self, compute_client,
    ) -> list[ShadowDataFinding]:
        """Detect Azure managed images accessible outside their resource group."""
        findings: list[ShadowDataFinding] = []
        try:
            for image in compute_client.images.list():
                # Azure managed images do not have a direct "public" flag, but
                # images in shared galleries with public access are a risk.
                hyper_v = getattr(image, "hyper_v_generation", "")
                source_disk = None
                if hasattr(image, "storage_profile") and hasattr(image.storage_profile, "os_disk"):
                    managed_disk = getattr(image.storage_profile.os_disk, "managed_disk", None)
                    if managed_disk:
                        source_disk = getattr(managed_disk, "id", None)

                # Flag images that have no tags (potential unmanaged / shadow copies)
                tags = getattr(image, "tags", {}) or {}
                if not tags:
                    findings.append(ShadowDataFinding(
                        finding_type="untagged_managed_image",
                        provider="azure",
                        resource_id=getattr(image, "id", ""),
                        resource_name=getattr(image, "name", ""),
                        region=getattr(image, "location", ""),
                        severity="medium",
                        description=(
                            f"Managed image '{image.name}' has no tags and may be "
                            "a shadow copy without proper governance."
                        ),
                        source_data_store=source_disk,
                        remediation=(
                            "Tag the image or delete it if it is no longer needed."
                        ),
                        evidence={
                            "hyper_v_generation": hyper_v,
                            "source_disk": source_disk,
                        },
                    ))
        except Exception as exc:
            logger.warning("Could not list Azure managed images: %s", exc)

        return findings

    def _check_unmanaged_blobs(
        self, storage_client,
    ) -> list[ShadowDataFinding]:
        """Detect storage accounts with public blob access enabled (potential shadow data)."""
        findings: list[ShadowDataFinding] = []
        try:
            for account in storage_client.storage_accounts.list():
                allow_public = getattr(account, "allow_blob_public_access", False)
                if allow_public:
                    findings.append(ShadowDataFinding(
                        finding_type="public_blob_access",
                        provider="azure",
                        resource_id=getattr(account, "id", ""),
                        resource_name=getattr(account, "name", ""),
                        region=getattr(account, "location", ""),
                        severity="high",
                        description=(
                            f"Storage account '{account.name}' allows public blob "
                            "access. Containers may expose sensitive data."
                        ),
                        remediation=(
                            "Disable public blob access on the storage account "
                            "and review container access levels."
                        ),
                        evidence={
                            "kind": getattr(account, "kind", ""),
                            "sku": getattr(getattr(account, "sku", None), "name", ""),
                            "https_only": getattr(
                                account, "enable_https_traffic_only", True
                            ),
                        },
                    ))
        except Exception as exc:
            logger.warning("Could not list Azure storage accounts: %s", exc)

        return findings

    def _check_orphaned_disks(
        self, compute_client,
    ) -> list[ShadowDataFinding]:
        """Detect Azure managed disks not attached to any VM."""
        findings: list[ShadowDataFinding] = []
        try:
            for disk in compute_client.disks.list():
                disk_state = getattr(disk, "disk_state", "")
                managed_by = getattr(disk, "managed_by", None)
                if disk_state == "Unattached" or (not managed_by and disk_state != "Reserved"):
                    encrypted = False
                    encryption = getattr(disk, "encryption", None)
                    if encryption and getattr(encryption, "type", "") != "EncryptionAtRestWithPlatformKey":
                        encrypted = True

                    severity = "medium" if encrypted else "high"

                    findings.append(ShadowDataFinding(
                        finding_type="orphaned_disk",
                        provider="azure",
                        resource_id=getattr(disk, "id", ""),
                        resource_name=getattr(disk, "name", ""),
                        region=getattr(disk, "location", ""),
                        severity=severity,
                        description=(
                            f"Managed disk '{disk.name}' ({getattr(disk, 'disk_size_gb', '?')} GB) "
                            "is not attached to any VM and may contain residual data."
                        ),
                        remediation=(
                            "Review the disk contents, snapshot if needed, "
                            "and delete the orphaned disk."
                        ),
                        evidence={
                            "disk_size_gb": getattr(disk, "disk_size_gb", None),
                            "os_type": getattr(disk, "os_type", None),
                            "disk_state": disk_state,
                            "time_created": str(getattr(disk, "time_created", "")),
                        },
                    ))
        except Exception as exc:
            logger.warning("Could not list Azure managed disks: %s", exc)

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # GCP
    # ═══════════════════════════════════════════════════════════════════

    def detect_gcp_shadow_data(
        self,
        credentials: Optional[dict] = None,
        project: Optional[str] = None,
    ) -> ShadowDataReport:
        """Orchestrate all GCP shadow data checks."""
        try:
            from googleapiclient import discovery as google_discovery
            from google.cloud import storage as gcs_storage
        except ImportError:
            logger.error(
                "google-api-python-client and google-cloud-storage are required "
                "for GCP shadow data detection"
            )
            return ShadowDataReport(provider="gcp")

        start_time = datetime.utcnow()
        project = project or (credentials or {}).get("project", "")
        if not project:
            logger.error("GCP project ID is required for shadow data detection")
            return ShadowDataReport(provider="gcp")

        compute_client = google_discovery.build("compute", "v1")
        storage_client = gcs_storage.Client(project=project)
        sqladmin_client = google_discovery.build("sqladmin", "v1beta4")
        functions_client = google_discovery.build("cloudfunctions", "v1")

        findings: list[ShadowDataFinding] = []
        findings.extend(self._check_public_disk_images(compute_client, project))
        findings.extend(self._check_public_snapshots(compute_client, project))
        findings.extend(
            self._check_sql_export_buckets(storage_client, sqladmin_client, project)
        )
        findings.extend(
            self._check_cloud_function_env_secrets(functions_client, project)
        )

        elapsed = (datetime.utcnow() - start_time).total_seconds()
        return self._build_report("gcp", findings, elapsed)

    # ── GCP helpers ──────────────────────────────────────────────────

    def _check_public_disk_images(
        self, compute_client, project: str,
    ) -> list[ShadowDataFinding]:
        """Detect Compute Engine images that are publicly accessible."""
        findings: list[ShadowDataFinding] = []
        try:
            resp = compute_client.images().list(project=project).execute()
            for image in resp.get("items", []):
                image_name = image.get("name", "")
                image_id = image.get("id", "")
                # Check IAM policy for public access
                try:
                    policy = compute_client.images().getIamPolicy(
                        project=project, resource=image_name,
                    ).execute()
                    for binding in policy.get("bindings", []):
                        members = binding.get("members", [])
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            findings.append(ShadowDataFinding(
                                finding_type="public_disk_image",
                                provider="gcp",
                                resource_id=image_id,
                                resource_name=image_name,
                                region="global",
                                severity="high",
                                description=(
                                    f"Compute image '{image_name}' is publicly "
                                    "accessible and may contain sensitive data."
                                ),
                                source_data_store=image.get("sourceDisk"),
                                remediation=(
                                    "Remove allUsers/allAuthenticatedUsers from "
                                    "the image IAM policy."
                                ),
                                evidence={
                                    "source_disk": image.get("sourceDisk"),
                                    "disk_size_gb": image.get("diskSizeGb"),
                                    "creation_timestamp": image.get("creationTimestamp"),
                                    "public_members": [
                                        m for m in members
                                        if m in ("allUsers", "allAuthenticatedUsers")
                                    ],
                                },
                            ))
                except Exception as exc:
                    logger.debug(
                        "Could not get IAM policy for image %s: %s", image_name, exc
                    )
        except Exception as exc:
            logger.warning("Could not list GCP images for project %s: %s", project, exc)

        return findings

    def _check_public_snapshots(
        self, compute_client, project: str,
    ) -> list[ShadowDataFinding]:
        """Detect Compute Engine snapshots that are publicly accessible."""
        findings: list[ShadowDataFinding] = []
        try:
            resp = compute_client.snapshots().list(project=project).execute()
            for snap in resp.get("items", []):
                snap_name = snap.get("name", "")
                snap_id = snap.get("id", "")
                try:
                    policy = compute_client.snapshots().getIamPolicy(
                        project=project, resource=snap_name,
                    ).execute()
                    for binding in policy.get("bindings", []):
                        members = binding.get("members", [])
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            findings.append(ShadowDataFinding(
                                finding_type="public_snapshot",
                                provider="gcp",
                                resource_id=snap_id,
                                resource_name=snap_name,
                                region="global",
                                severity="critical",
                                description=(
                                    f"Compute snapshot '{snap_name}' is publicly "
                                    "accessible and may contain sensitive disk data."
                                ),
                                source_data_store=snap.get("sourceDisk"),
                                remediation=(
                                    "Remove allUsers/allAuthenticatedUsers from "
                                    "the snapshot IAM policy."
                                ),
                                evidence={
                                    "source_disk": snap.get("sourceDisk"),
                                    "disk_size_gb": snap.get("diskSizeGb"),
                                    "storage_bytes": snap.get("storageBytes"),
                                    "creation_timestamp": snap.get("creationTimestamp"),
                                },
                            ))
                except Exception as exc:
                    logger.debug(
                        "Could not get IAM policy for snapshot %s: %s", snap_name, exc
                    )
        except Exception as exc:
            logger.warning("Could not list GCP snapshots for project %s: %s", project, exc)

        return findings

    def _check_sql_export_buckets(
        self, storage_client, sqladmin_client, project: str,
    ) -> list[ShadowDataFinding]:
        """Detect Cloud SQL export operations targeting publicly accessible buckets."""
        findings: list[ShadowDataFinding] = []
        try:
            resp = sqladmin_client.operations().list(project=project).execute()
            for op in resp.get("items", []):
                if op.get("operationType") != "EXPORT":
                    continue
                export_ctx = op.get("exportContext", {})
                uri = export_ctx.get("uri", "")
                if not uri.startswith("gs://"):
                    continue

                # Extract bucket name from gs://bucket/path
                bucket_name = uri.replace("gs://", "").split("/")[0]
                try:
                    bucket = storage_client.get_bucket(bucket_name)
                    policy = bucket.get_iam_policy(requested_policy_version=3)
                    for binding in policy.bindings:
                        members = binding.get("members", []) if isinstance(binding, dict) else getattr(binding, "members", [])
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            findings.append(ShadowDataFinding(
                                finding_type="sql_export_public_bucket",
                                provider="gcp",
                                resource_id=bucket_name,
                                resource_name=bucket_name,
                                region="global",
                                severity="critical",
                                description=(
                                    f"Cloud SQL export targets publicly accessible "
                                    f"bucket '{bucket_name}'. Database data may be exposed."
                                ),
                                source_data_store=op.get("targetId"),
                                remediation=(
                                    "Remove public access from the export bucket "
                                    "and re-export to a private bucket."
                                ),
                                evidence={
                                    "export_uri": uri,
                                    "instance": op.get("targetId"),
                                    "file_type": export_ctx.get("fileType"),
                                    "operation_id": op.get("name"),
                                },
                            ))
                            break
                except Exception as exc:
                    logger.debug("Could not check bucket %s: %s", bucket_name, exc)
        except Exception as exc:
            logger.warning("Could not list Cloud SQL operations for %s: %s", project, exc)

        return findings

    def _check_cloud_function_env_secrets(
        self, functions_client, project: str,
    ) -> list[ShadowDataFinding]:
        """Scan Cloud Functions environment variables for embedded secrets."""
        findings: list[ShadowDataFinding] = []
        try:
            parent = f"projects/{project}/locations/-"
            resp = functions_client.projects().locations().functions().list(
                parent=parent,
            ).execute()
            for func in resp.get("functions", []):
                func_name = func.get("name", "")
                env_vars = func.get("environmentVariables", {})
                # Also check build env vars
                build_env_vars = func.get("buildEnvironmentVariables", {})
                all_env_vars = {**env_vars, **build_env_vars}

                detected_secrets: list[dict] = []
                for key, value in all_env_vars.items():
                    combined = f"{key}={value}"
                    for pattern, secret_type in SECRET_PATTERNS:
                        if pattern.search(combined):
                            detected_secrets.append({
                                "env_var": key,
                                "secret_type": secret_type,
                            })
                            break

                if detected_secrets:
                    # Extract short name from full resource path
                    short_name = func_name.rsplit("/", 1)[-1] if "/" in func_name else func_name
                    findings.append(ShadowDataFinding(
                        finding_type="cloud_function_env_secret",
                        provider="gcp",
                        resource_id=func_name,
                        resource_name=short_name,
                        region=func.get("name", "").split("/locations/")[1].split("/")[0]
                        if "/locations/" in func.get("name", "") else "",
                        severity="high",
                        description=(
                            f"Cloud Function '{short_name}' has "
                            f"{len(detected_secrets)} environment variable(s) "
                            "containing potential secrets."
                        ),
                        remediation=(
                            "Move secrets to Secret Manager and reference them "
                            "using secret environment variable bindings."
                        ),
                        evidence={
                            "secrets_found": [
                                {"env_var": s["env_var"], "type": s["secret_type"]}
                                for s in detected_secrets
                            ],
                            "runtime": func.get("runtime", ""),
                        },
                    ))
        except Exception as exc:
            logger.warning(
                "Could not list Cloud Functions for project %s: %s", project, exc
            )

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # Report builder
    # ═══════════════════════════════════════════════════════════════════

    def _build_report(
        self,
        provider: str,
        findings: list[ShadowDataFinding],
        elapsed: float,
    ) -> ShadowDataReport:
        """Build a ShadowDataReport from a list of findings."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            key = f.severity.lower()
            if key in severity_counts:
                severity_counts[key] += 1

        return ShadowDataReport(
            provider=provider,
            total_findings=len(findings),
            critical=severity_counts["critical"],
            high=severity_counts["high"],
            medium=severity_counts["medium"],
            low=severity_counts["low"],
            findings=findings,
            scan_duration_seconds=elapsed,
        )
