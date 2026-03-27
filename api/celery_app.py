"""Celery application for D-ARCA background tasks."""
from celery import Celery
from api.config import settings

celery_app = Celery(
    "darca",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "api.tasks.scan_tasks",
        "api.tasks.saas_tasks",
        "api.tasks.schedule_tasks",
        "api.tasks.rr_tasks",
        "api.tasks.dspm_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "check-scheduled-scans": {
            "task": "api.tasks.schedule_tasks.check_and_run_scheduled_scans",
            "schedule": 60.0,  # Check every minute
        },
    },
)
