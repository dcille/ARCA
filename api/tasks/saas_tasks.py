"""SaaS scan Celery tasks."""
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


@celery_app.task(bind=True, name="api.tasks.saas_tasks.run_saas_scan")
def run_saas_scan(self, scan_id: str, connection_id: str):
    """Execute a SaaS security scan."""
    from api.models.scan import Scan
    from api.models.saas_connection import SaaSConnection
    from api.models.saas_finding import SaaSFinding
    from api.services.auth_service import decrypt_credentials

    session = get_sync_session()
    try:
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        session.commit()

        connection = session.query(SaaSConnection).filter(SaaSConnection.id == connection_id).first()
        if not connection:
            scan.status = "failed"
            session.commit()
            return

        credentials = decrypt_credentials(connection.credentials_encrypted)

        from scanner.saas.saas_scanner import SaaSScannerFactory
        scanner = SaaSScannerFactory.create(connection.provider_type, credentials)
        results = scanner.run_all_checks()

        total = 0
        passed = 0
        failed = 0

        for result in results:
            finding = SaaSFinding(
                scan_id=scan_id,
                connection_id=connection_id,
                provider_type=connection.provider_type,
                check_id=result["check_id"],
                check_title=result["check_title"],
                service_area=result["service_area"],
                severity=result["severity"],
                status=result["status"],
                resource_id=result.get("resource_id"),
                resource_name=result.get("resource_name"),
                description=result.get("description"),
                remediation=result.get("remediation"),
                remediation_url=result.get("remediation_url"),
                compliance_frameworks=str(result.get("compliance_frameworks", [])),
            )
            session.add(finding)
            total += 1
            if result["status"] == "PASS":
                passed += 1
            else:
                failed += 1

        scan.status = "completed"
        scan.progress = 100.0
        scan.total_checks = total
        scan.passed_checks = passed
        scan.failed_checks = failed
        scan.completed_at = datetime.utcnow()

        connection.last_scan_at = datetime.utcnow()

        session.commit()

        # Fire notifications and webhooks
        try:
            from api.services.notification_service import create_scan_complete_notification
            create_scan_complete_notification(
                session,
                user_id=scan.user_id,
                scan_id=scan_id,
                scan_type="saas",
                total=total,
                passed=passed,
                failed=failed,
            )
            session.commit()
        except Exception as notify_err:
            logger.warning(f"Notification dispatch failed: {notify_err}")

        logger.info(f"SaaS scan {scan_id} completed: {total} checks, {passed} passed, {failed} failed")

    except Exception as e:
        logger.exception(f"SaaS scan {scan_id} failed: {e}")
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            session.commit()
    finally:
        session.close()
