"""Tests for the health check and basic API functionality."""
import pytest
from httpx import AsyncClient, ASGITransport
from api.main import app


class TestHealthCheck:
    async def test_health_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["application"] == "D-ARCA"
        assert data["version"] == "1.0.0"
