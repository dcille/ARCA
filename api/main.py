"""D-ARCA API - Asset Risk & Cloud Analysis"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.config import settings
from api.database import engine, Base
from api.routers import (
    auth, providers, scans, findings, compliance, saas, dashboard,
    attack_paths, reports, inventory, schedules, notifications, integrations,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(
    title="D-ARCA API",
    description="Asset Risk & Cloud Analysis - Cloud & SaaS Security Posture Management",
    version="1.0.0",
    lifespan=lifespan,
    redirect_slashes=True,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
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


@app.get("/api/v1/health")
async def health_check():
    return {"status": "healthy", "application": "D-ARCA", "version": "1.0.0"}
