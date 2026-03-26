"""Shared fixtures for D-ARCA tests."""
import os
import uuid

# Override DB URL BEFORE any app code imports
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from api.database import Base


@pytest_asyncio.fixture
async def db_engine():
    """Create an in-memory SQLite engine for tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    """Provide an async DB session for tests."""
    session_factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest.fixture
def user_id():
    return str(uuid.uuid4())


@pytest.fixture
def provider_id():
    return str(uuid.uuid4())


@pytest.fixture
def scan_id():
    return str(uuid.uuid4())


@pytest.fixture
def fake_azure_credentials():
    return {
        "subscription_id": "00000000-1111-2222-3333-444444444444",
        "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "client_id": "fake-client-id",
        "client_secret": "fake-client-secret",
    }
