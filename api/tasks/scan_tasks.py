"""Cloud scan Celery tasks."""
import json
import logging
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from api.celery_app import celery_app

logger = logging.getLogger(__name__)

SYNC_DATABASE_URL = "postgresql://darca:darca@postgres:5432/darca"


def get_sync_session() -> Session:
    engine = create_engine(SYNC_DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


@celery_app.task(bind=True, name="api.tasks.scan_tasks.run_cloud_scan")
def run_cloud_scan(self, scan_id: str, provider_id: str, services=None, regions=None):
    """Execute a cloud security scan."""
    from api.models.scan import Scan
    from api.models.provider import Provider
    from api.models.finding import Finding
    from api.services.auth_service import decrypt_credentials
    from scanner.mitre.attack_mapping import CHECK_TO_MITRE, CHECK_DESCRIPTIONS, CHECK_EVIDENCE
    from scanner.compliance.frameworks import get_frameworks_for_check

    session = get_sync_session()
    try:
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        session.commit()

        provider = session.query(Provider).filter(Provider.id == provider_id).first()
        if not provider:
            scan.status = "failed"
            session.commit()
            return

        credentials = decrypt_credentials(provider.credentials_encrypted)

        from scanner.providers.cloud_scanner import CloudScanner
        scanner = CloudScanner(
            provider_type=provider.provider_type,
            credentials=credentials,
            region=provider.region,
            services=services,
            regions=regions,
        )

        results = scanner.run_checks()

        total = 0
        passed = 0
        failed = 0

        for result in results:
            check_id = result["check_id"]

            # Enrich with MITRE mappings, descriptions, and evidence
            mitre_techs = result.get("mitre_techniques") or CHECK_TO_MITRE.get(check_id, [])
            check_desc = result.get("check_description") or CHECK_DESCRIPTIONS.get(check_id, "")
            evidence = result.get("evidence_log") or CHECK_EVIDENCE.get(check_id, "")

            finding = Finding(
                scan_id=scan_id,
                provider_id=provider_id,
                check_id=check_id,
                check_title=result["check_title"],
                service=result["service"],
                severity=result["severity"],
                status=result["status"],
                region=result.get("region"),
                resource_id=result.get("resource_id"),
                resource_name=result.get("resource_name"),
                status_extended=result.get("status_extended"),
                remediation=result.get("remediation"),
                remediation_url=result.get("remediation_url"),
                compliance_frameworks=json.dumps(
                    list(set(result.get("compliance_frameworks", []) + get_frameworks_for_check(check_id)))
                ),
                check_description=check_desc,
                evidence_log=evidence,
                mitre_techniques=json.dumps(mitre_techs) if mitre_techs else None,
            )
            session.add(finding)
            total += 1
            if result["status"] == "PASS":
                passed += 1
            else:
                failed += 1

            if total % 50 == 0:
                scan.progress = min(95.0, (total / max(len(results), 1)) * 100)
                session.commit()

        scan.status = "completed"
        scan.progress = 100.0
        scan.total_checks = total
        scan.passed_checks = passed
        scan.failed_checks = failed
        scan.completed_at = datetime.utcnow()
        session.commit()

        # Fire notifications and webhooks
        try:
            from api.services.notification_service import (
                create_scan_complete_notification,
                create_critical_finding_notification,
            )
            create_scan_complete_notification(
                session,
                user_id=scan.user_id,
                scan_id=scan_id,
                scan_type="cloud",
                total=total,
                passed=passed,
                failed=failed,
            )
            session.commit()
        except Exception as notify_err:
            logger.warning(f"Notification dispatch failed: {notify_err}")

        logger.info(f"Cloud scan {scan_id} completed: {total} checks, {passed} passed, {failed} failed")

    except Exception as e:
        logger.exception(f"Cloud scan {scan_id} failed: {e}")
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            session.commit()
    finally:
        session.close()
