"""D-ARCA API - Asset Risk & Cloud Analysis"""
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import IntegrityError, OperationalError

from api.config import settings
from api.database import engine, Base
from api.routers import (
    auth, providers, scans, findings, compliance, saas, dashboard,
    attack_paths, reports, inventory, schedules, notifications, integrations,
    organizations, mitre, dspm, security_graph, ransomware_readiness,
    audit_log, custom_frameworks,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # When running with multiple gunicorn workers, each worker executes this
    # lifespan concurrently. Even with checkfirst=True (CREATE TABLE IF NOT
    # EXISTS), asyncpg + PostgreSQL can raise an IntegrityError on the implicit
    # pg_type entry for a table name when two workers race. This is safe to
    # ignore -- the table was already created by the other worker.
    try:
        async with engine.begin() as conn:
            await conn.run_sync(
                lambda sync_conn: Base.metadata.create_all(sync_conn, checkfirst=True)
            )
    except (IntegrityError, OperationalError) as exc:
        logger.warning("Table creation race condition (safe to ignore): %s", exc)

    # Sync custom controls from DB into the runtime registry
    try:
        from api.database import async_session
        from api.services.custom_framework_service import sync_custom_controls_to_registry
        async with async_session() as db:
            n = await sync_custom_controls_to_registry(db)
            if n > 0:
                logger.info("Synced %d custom controls to registry", n)
    except Exception as exc:
        logger.warning("Could not sync custom controls to registry: %s", exc)

    import api.models.framework_preference  # noqa: F401
    import api.models.dspm_scan  # noqa: F401
    import api.models.dspm_finding  # noqa: F401

    yield


app = FastAPI(
    title="D-ARCA API",
    description="Asset Risk & Cloud Analysis - Cloud & SaaS Security Posture Management",
    version="1.0.0",
    lifespan=lifespan,
    redirect_slashes=True,
)

cors_origins = settings.CORS_ORIGINS
if "*" in cors_origins:
    cors_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True if "*" not in cors_origins else False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(providers.router, prefix="/api/v1/providers", tags=["Providers"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(findings.router, prefix="/api/v1/findings", tags=["Findings"])
app.include_router(compliance.router, prefix="/api/v1/compliance", tags=["Compliance"])
app.include_router(saas.router, prefix="/api/v1/saas", tags=["SaaS Security"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])
app.include_router(attack_paths.router, prefix="/api/v1/attack-paths", tags=["Attack Paths"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(inventory.router, prefix="/api/v1/inventory", tags=["Inventory"])
app.include_router(schedules.router, prefix="/api/v1/schedules", tags=["Schedules"])
app.include_router(notifications.router, prefix="/api/v1/notifications", tags=["Notifications"])
app.include_router(integrations.router, prefix="/api/v1/integrations", tags=["Integrations"])
app.include_router(organizations.router, prefix="/api/v1/organizations", tags=["Organizations"])
app.include_router(mitre.router, prefix="/api/v1/mitre", tags=["MITRE ATT&CK"])
app.include_router(dspm.router, prefix="/api/v1/dspm", tags=["DSPM"])
app.include_router(security_graph.router, prefix="/api/v1/security-graph", tags=["Security Graph"])
app.include_router(ransomware_readiness.router, prefix="/api/v1/ransomware-readiness", tags=["Ransomware Readiness"])
app.include_router(audit_log.router, prefix="/api/v1/audit-log", tags=["Audit Log"])
app.include_router(custom_frameworks.router, prefix="/api/v1/custom-frameworks", tags=["Custom Frameworks"])

# CLI → SDK Transpiler endpoint
try:
    from scanner.providers.azure.cli_to_sdk_transpiler import create_transpiler_router
    app.include_router(create_transpiler_router(), prefix="/api/v1", tags=["Transpiler"])
except ImportError:
    logger.warning("CLI-to-SDK transpiler not available")

# Custom control examples endpoint
try:
    from scanner.providers.azure.custom_control_models import create_custom_controls_router
    app.include_router(create_custom_controls_router(), prefix="/api/v1", tags=["Custom Controls"])
except ImportError:
    logger.warning("Custom control examples router not available")


@app.get("/api/v1/health")
async def health_check():
    return {"status": "healthy", "application": "D-ARCA", "version": "1.0.0"}
