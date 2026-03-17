"""Task to check and execute scheduled scans."""
from api.celery_app import celery_app
from datetime import datetime


@celery_app.task(name="api.tasks.schedule_tasks.check_and_run_scheduled_scans")
def check_and_run_scheduled_scans():
    """Check for scheduled scans that are due and trigger them."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from api.config import settings
    from api.models.scan_schedule import ScanSchedule
    from api.models.scan import Scan

    engine = create_engine(settings.DATABASE_URL.replace("+asyncpg", ""))
    with Session(engine) as db:
        now = datetime.utcnow()
        schedules = db.query(ScanSchedule).filter(
            ScanSchedule.enabled == True,
            ScanSchedule.next_run_at <= now,
        ).all()

        for schedule in schedules:
            scan = Scan(
                user_id=schedule.user_id,
                provider_id=schedule.provider_id,
                connection_id=schedule.connection_id,
                scan_type=schedule.scan_type,
                status="pending",
            )
            db.add(scan)
            db.flush()

            if schedule.scan_type == "cloud" and schedule.provider_id:
                celery_app.send_task(
                    "api.tasks.scan_tasks.run_cloud_scan",
                    args=[scan.id, schedule.provider_id],
                )
            elif schedule.scan_type == "saas" and schedule.connection_id:
                celery_app.send_task(
                    "api.tasks.saas_tasks.run_saas_scan",
                    args=[scan.id, schedule.connection_id],
                )

            # Update schedule timing
            from datetime import timedelta
            deltas = {"daily": timedelta(days=1), "weekly": timedelta(weeks=1), "monthly": timedelta(days=30)}
            schedule.last_run_at = now
            schedule.next_run_at = now + deltas.get(schedule.frequency, timedelta(days=1))

        db.commit()
