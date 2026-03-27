"""Base evaluator infrastructure for Alibaba Cloud CIS v2.0.0 control evaluation.

Every CIS evaluator function receives an AlibabaClientCache and EvalConfig,
and returns a list of CheckResult dicts.

Mirrors the AWS/Azure/GCP/OCI evaluator pattern but uses Alibaba Cloud SDKs.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, Any

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------

@dataclass
class EvalConfig:
    """Runtime configuration passed to every evaluator."""
    account_id: str = ""
    regions: list[str] = field(default_factory=lambda: ["cn-hangzhou"])
    max_resources_per_check: int = 500
    timeout_seconds: int = 60


# -----------------------------------------------------------------
# Result builder helpers
# -----------------------------------------------------------------

def make_result(
    *,
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
    status: str,             # PASS | FAIL | MANUAL | ERROR | N/A
    resource_id: str,
    resource_name: str = "",
    status_extended: str = "",
    remediation: str = "",
    region: str = "",
    compliance_frameworks: Optional[list[str]] = None,
) -> dict:
    """Build a CheckResult dict compatible with the existing scanner output."""
    return {
        "check_id": check_id,
        "check_title": title,
        "service": service,
        "severity": severity,
        "status": status,
        "resource_id": resource_id,
        "resource_name": resource_name or (resource_id.split("/")[-1] if resource_id else ""),
        "region": region,
        "status_extended": status_extended,
        "remediation": remediation,
        "compliance_frameworks": compliance_frameworks or ["CIS-Alibaba-2.0"],
        "cis_control_id": cis_id,
    }


def make_manual_result(
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
    account_id: str,
    reason: str,
) -> dict:
    """Build a MANUAL result for controls that cannot be automated."""
    return make_result(
        cis_id=cis_id,
        check_id=check_id,
        title=title,
        service=service,
        severity=severity,
        status="MANUAL",
        resource_id=account_id,
        status_extended=f"Manual verification required: {reason}",
        remediation=f"Refer to CIS Alibaba Cloud Foundation Benchmark v2.0.0, control {cis_id}.",
    )


def make_error_result(
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
    account_id: str,
    error: str,
) -> dict:
    """Build an ERROR result when the evaluator fails."""
    return make_result(
        cis_id=cis_id,
        check_id=check_id,
        title=title,
        service=service,
        severity=severity,
        status="ERROR",
        resource_id=account_id,
        status_extended=f"Evaluation failed: {error}",
        remediation="Check that the Alibaba Cloud credentials have the required RAM permissions.",
    )


# -----------------------------------------------------------------
# SDK client caching
# -----------------------------------------------------------------

class AlibabaClientCache:
    """Lazy-loading cache for Alibaba Cloud SDK clients.

    Avoids creating a new client for every evaluator function.
    One instance is created per scan run and shared across evaluators.
    """

    def __init__(self, access_key_id: str, access_key_secret: str, regions: list[str] = None):
        self._access_key_id = access_key_id
        self._access_key_secret = access_key_secret
        self._regions = regions or ["cn-hangzhou"]
        self._cache: dict[str, Any] = {}

    def _get_or_create(self, key: str, factory: Callable) -> Any:
        if key not in self._cache:
            self._cache[key] = factory()
        return self._cache[key]

    @property
    def regions(self):
        return self._regions

    def _make_config(self, endpoint: str = None, region_id: str = None):
        """Create an OpenAPI config for Alibaba Cloud SDK clients."""
        from alibabacloud_tea_openapi.models import Config
        cfg = Config(
            access_key_id=self._access_key_id,
            access_key_secret=self._access_key_secret,
            region_id=region_id or self._regions[0],
        )
        if endpoint:
            cfg.endpoint = endpoint
        return cfg

    # --- RAM (Identity and Access Management) ---

    @property
    def ram(self):
        from alibabacloud_ram20150501.client import Client as RamClient
        return self._get_or_create(
            "ram",
            lambda: RamClient(self._make_config(endpoint="ram.aliyuncs.com")),
        )

    # --- ECS (Elastic Compute Service) ---

    def ecs(self, region: str = None):
        region = region or self._regions[0]
        key = f"ecs:{region}"
        from alibabacloud_ecs20140526.client import Client as EcsClient
        return self._get_or_create(
            key,
            lambda: EcsClient(self._make_config(
                endpoint=f"ecs.{region}.aliyuncs.com", region_id=region,
            )),
        )

    # --- RDS (Relational Database Service) ---

    def rds(self, region: str = None):
        region = region or self._regions[0]
        key = f"rds:{region}"
        from alibabacloud_rds20140815.client import Client as RdsClient
        return self._get_or_create(
            key,
            lambda: RdsClient(self._make_config(
                endpoint=f"rds.{region}.aliyuncs.com", region_id=region,
            )),
        )

    # --- VPC ---

    def vpc(self, region: str = None):
        region = region or self._regions[0]
        key = f"vpc:{region}"
        from alibabacloud_vpc20160428.client import Client as VpcClient
        return self._get_or_create(
            key,
            lambda: VpcClient(self._make_config(
                endpoint=f"vpc.{region}.aliyuncs.com", region_id=region,
            )),
        )

    # --- KMS ---

    def kms(self, region: str = None):
        region = region or self._regions[0]
        key = f"kms:{region}"
        from alibabacloud_kms20160120.client import Client as KmsClient
        return self._get_or_create(
            key,
            lambda: KmsClient(self._make_config(
                endpoint=f"kms.{region}.aliyuncs.com", region_id=region,
            )),
        )

    # --- ActionTrail ---

    @property
    def actiontrail(self):
        from alibabacloud_actiontrail20200706.client import Client as ActionTrailClient
        return self._get_or_create(
            "actiontrail",
            lambda: ActionTrailClient(self._make_config(
                endpoint="actiontrail.aliyuncs.com",
            )),
        )

    # --- ACK (Container Service for Kubernetes) ---

    @property
    def cs(self):
        from alibabacloud_cs20151215.client import Client as CsClient
        return self._get_or_create(
            "cs",
            lambda: CsClient(self._make_config(
                endpoint="cs.aliyuncs.com",
            )),
        )

    # --- SAS (Security Center / Security Advisor Service) ---

    @property
    def sas(self):
        from alibabacloud_sas20181203.client import Client as SasClient
        return self._get_or_create(
            "sas",
            lambda: SasClient(self._make_config(
                endpoint="tds.aliyuncs.com",
            )),
        )

    # --- OSS (Object Storage Service) ---

    def oss_bucket(self, bucket_name: str, endpoint: str = None):
        """Get an OSS bucket object. Uses oss2 SDK."""
        import oss2
        ep = endpoint or f"https://oss-{self._regions[0]}.aliyuncs.com"
        auth = oss2.Auth(self._access_key_id, self._access_key_secret)
        return oss2.Bucket(auth, ep, bucket_name)

    def oss_service(self):
        """Get OSS Service object for listing buckets."""
        import oss2
        auth = oss2.Auth(self._access_key_id, self._access_key_secret)
        ep = f"https://oss-{self._regions[0]}.aliyuncs.com"
        return oss2.Service(auth, ep)


# -----------------------------------------------------------------
# Evaluator type alias
# -----------------------------------------------------------------

EvaluatorFn = Callable[['AlibabaClientCache', EvalConfig], list[dict]]


def safe_evaluate(
    evaluator: EvaluatorFn,
    clients: AlibabaClientCache,
    config: EvalConfig,
    cis_id: str,
    check_id: str,
    title: str,
    service: str,
    severity: str,
) -> list[dict]:
    """Run an evaluator with error handling -- never let one check crash the scan."""
    try:
        return evaluator(clients, config)
    except Exception as e:
        logger.warning("Evaluator %s failed: %s", cis_id, e)
        return [make_error_result(
            cis_id=cis_id,
            check_id=check_id,
            title=title,
            service=service,
            severity=severity,
            account_id=config.account_id,
            error=str(e),
        )]
