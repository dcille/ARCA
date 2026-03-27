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


def _load_custom_controls(session: Session, user_id: str, provider_type: str) -> list[dict]:
    """Load custom controls with evaluation logic for the given provider from DB."""
    from api.models.custom_framework import CustomFramework, CustomControl

    try:
        frameworks = (
            session.query(CustomFramework)
            .filter(CustomFramework.user_id == user_id, CustomFramework.is_active == True)
            .all()
        )

        controls = []
        for fw in frameworks:
            # Check if this framework applies to the provider
            providers_json = fw.providers
            if providers_json:
                import json as _json
                try:
                    fw_providers = _json.loads(providers_json)
                except (ValueError, TypeError):
                    fw_providers = []
                if fw_providers and provider_type not in fw_providers:
                    continue

            fw_controls = (
                session.query(CustomControl)
                .filter(CustomControl.framework_id == fw.id)
                .all()
            )

            for ctrl in fw_controls:
                # Only include controls that have executable evaluation logic
                eval_script = getattr(ctrl, "evaluation_script", None)
                cli_cmd = getattr(ctrl, "cli_command", None)
                if not eval_script and not cli_cmd:
                    continue

                controls.append({
                    "control_id": ctrl.check_id,
                    "title": ctrl.title,
                    "description": ctrl.description or "",
                    "severity": ctrl.severity,
                    "service": ctrl.service,
                    "framework_id": fw.id,
                    "remediation": ctrl.remediation or "",
                    "compliance_frameworks": [fw.name],
                    "evaluation_script": eval_script,
                    "cli_command": cli_cmd,
                    "pass_condition": getattr(ctrl, "pass_condition", "empty") or "empty",
                })

        return controls
    except Exception as e:
        logger.warning("Failed to load custom controls: %s", e)
        return []


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

        # Load custom controls with evaluation logic for this provider type
        custom_controls = _load_custom_controls(session, scan.user_id, provider.provider_type)
        logger.info("Loaded %d custom controls for scan %s", len(custom_controls), scan_id)

        from scanner.providers.cloud_scanner import CloudScanner
        scanner = CloudScanner(
            provider_type=provider.provider_type,
            credentials=credentials,
            region=provider.region,
            services=services,
            regions=regions,
            custom_controls=custom_controls,
        )

        results = scanner.run_checks()

        # Save scan execution log
        try:
            scan.scan_log = scanner.scan_logger.to_json()
            session.commit()
        except Exception as log_err:
            logger.warning("Failed to save scan log: %s", log_err)

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

        # Trigger Ransomware Readiness evaluation
        try:
            celery_app.send_task(
                "api.tasks.rr_tasks.evaluate_ransomware_readiness",
                args=[scan.user_id],
                kwargs={"scan_id": scan_id},
            )
            logger.info(f"RR evaluation triggered for scan {scan_id}")
        except Exception as rr_err:
            logger.warning(f"RR evaluation trigger failed: {rr_err}")

        logger.info(f"Cloud scan {scan_id} completed: {total} checks, {passed} passed, {failed} failed")

    except Exception as e:
        logger.exception(f"Cloud scan {scan_id} failed: {e}")
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            session.commit()
    finally:
        session.close()
