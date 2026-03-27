"""DSPM Celery tasks — runs DSPMOrchestrator in background."""
import json
import logging
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from api.celery_app import celery_app

logger = logging.getLogger(__name__)

SYNC_DATABASE_URL = "postgresql://darca:darca@postgres:5432/darca"


def _get_sync_session() -> Session:
    engine = create_engine(SYNC_DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


SERVICE_TO_STORE = {
    "s3": "s3", "rds": "rds", "dynamodb": "dynamodb",
    "redshift": "redshift", "efs": "efs", "elasticache": "elasticache",
    "storage": "azure_storage", "azure_blob": "azure_storage",
    "sql": "azure_sql", "azure_sql": "azure_sql", "database": "azure_sql",
    "cosmosdb": "cosmosdb", "keyvault": "keyvault",
    "gcs": "gcs", "cloud_storage": "gcs",
    "cloudsql": "cloud_sql", "cloud_sql": "cloud_sql",
    "bigquery": "bigquery", "firestore": "firestore",
    "secretsmanager": "secretsmanager", "secretmanager": "secretmanager",
}


def _build_dspm_targets(session: Session, user_id: str, provider_id: str) -> list[dict]:
    """Build DSPM targets from resources discovered in previous cloud scans."""
    from api.models.finding import Finding
    from api.models.scan import Scan

    targets = []
    seen = set()

    results = (
        session.query(Finding.resource_id, Finding.service)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.user_id == user_id,
            Finding.resource_id.isnot(None),
        )
        .distinct()
        .all()
    )

    for resource_id, service in results:
        if not resource_id or not service:
            continue
        store_type = SERVICE_TO_STORE.get(service.lower())
        if store_type and resource_id not in seen:
            seen.add(resource_id)
            targets.append({
                "store_type": store_type,
                "resource_id": resource_id,
                "resource_name": resource_id,
            })

    return targets


@celery_app.task(bind=True, name="api.tasks.dspm_tasks.run_dspm_scan")
def run_dspm_scan(self, dspm_scan_id: str, provider_id: str, user_id: str,
                  enable_content_scanning: bool = False,
                  skip_modules: list[str] | None = None):
    """Execute the DSPMOrchestrator in background."""
    from api.models.dspm_scan import DSPMScan
    from api.models.dspm_finding import DSPMFinding
    from api.models.provider import Provider
    from api.services.auth_service import decrypt_credentials
    from scanner.dspm.router import DSPMOrchestrator

    session = _get_sync_session()
    try:
        dspm_scan = session.query(DSPMScan).filter(DSPMScan.id == dspm_scan_id).first()
        if not dspm_scan:
            logger.error("DSPM scan %s not found", dspm_scan_id)
            return

        dspm_scan.status = "running"
        session.commit()

        provider = session.query(Provider).filter(Provider.id == provider_id).first()
        if not provider:
            dspm_scan.status = "failed"
            session.commit()
            return

        credentials = decrypt_credentials(provider.credentials_encrypted)

        # Auto-discover targets from existing findings
        targets = _build_dspm_targets(session, user_id, provider_id)
        logger.info("DSPM scan %s: discovered %d targets for provider %s",
                     dspm_scan_id, len(targets), provider.provider_type)

        # Build skip list: by default skip content-scanning modules unless opted in
        effective_skip = list(skip_modules or [])
        if not enable_content_scanning:
            for mod in ("content_sampler", "pii_scanner", "data_classifier"):
                if mod not in effective_skip:
                    effective_skip.append(mod)

        config = {
            "provider": provider.provider_type,
            "credentials": credentials,
            "targets": targets,
            "skip_modules": effective_skip,
        }

        # Run the orchestrator
        orchestrator = DSPMOrchestrator()
        report = orchestrator.run_full_scan(config)

        # Persist findings to DB
        finding_count = 0
        for finding in report.prioritised_findings:
            dspm_finding = DSPMFinding(
                user_id=user_id,
                provider_id=provider_id,
                scan_id=dspm_scan_id,
                module=finding.module,
                title=finding.title,
                severity=finding.severity,
                confidence=finding.confidence,
                description=finding.description,
                resource_id=finding.resource_id or None,
                resource_name=finding.resource_name or None,
                category=finding.category,
                remediation=finding.remediation or None,
                risk_score=finding.risk_score,
                evidence=json.dumps(finding.evidence) if finding.evidence else None,
            )
            session.add(dspm_finding)
            finding_count += 1

        # Update scan record
        dspm_scan.status = "completed"
        dspm_scan.total_findings = report.total_findings
        dspm_scan.overall_risk_score = report.overall_risk_score
        dspm_scan.overall_risk_label = report.overall_risk_label
        dspm_scan.modules_run = report.total_modules_run
        dspm_scan.modules_failed = report.total_modules_failed
        dspm_scan.findings_by_severity = json.dumps(dict(report.findings_by_severity))
        dspm_scan.findings_by_module = json.dumps(dict(report.findings_by_module))
        dspm_scan.duration_seconds = report.scan_duration_seconds
        dspm_scan.fingerprint = report.fingerprint
        dspm_scan.completed_at = datetime.utcnow()
        session.commit()

        logger.info(
            "DSPM scan %s completed: %d findings, risk=%s (%.1f), duration=%.2fs",
            dspm_scan_id, report.total_findings, report.overall_risk_label,
            report.overall_risk_score, report.scan_duration_seconds,
        )

        # Send notification
        try:
            from api.services.notification_service import create_scan_complete_notification
            create_scan_complete_notification(
                session,
                user_id=user_id,
                scan_id=dspm_scan_id,
                scan_type="dspm",
                total=report.total_findings,
                passed=0,
                failed=report.total_findings,
            )
            session.commit()
        except Exception as notify_err:
            logger.warning("DSPM notification failed: %s", notify_err)

    except Exception as e:
        logger.exception("DSPM scan %s failed: %s", dspm_scan_id, e)
        dspm_scan = session.query(DSPMScan).filter(DSPMScan.id == dspm_scan_id).first()
        if dspm_scan:
            dspm_scan.status = "failed"
            session.commit()
    finally:
        session.close()
