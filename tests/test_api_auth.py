"""Tests for the /api/v1/auth endpoints — registration, login, API keys."""
import pytest
import hashlib

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession

from api.main import app
from api.models.user import User
from api.models.api_key import ApiKey
from api.services.auth_service import hash_password, create_access_token


def _auth_headers(user_id: str) -> dict:
    token = create_access_token(data={"sub": user_id})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


class TestRegister:
    async def test_register_success(self, db_session: AsyncSession):
        # Patch get_db to use test session
        from api.database import get_db

        async def override_get_db():
            yield db_session

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/auth/register", json={
                "email": "new@example.com",
                "password": "StrongPass123!",
                "name": "New User",
            })
        assert resp.status_code == 201
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["email"] == "new@example.com"
        assert data["user"]["name"] == "New User"

        app.dependency_overrides.clear()

    async def test_register_duplicate_email(self, db_session: AsyncSession):
        user = User(email="dup@example.com", hashed_password=hash_password("x"), name="First")
        db_session.add(user)
        await db_session.commit()

        from api.database import get_db

        async def override_get_db():
            yield db_session

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/auth/register", json={
                "email": "dup@example.com",
                "password": "Pass123!",
                "name": "Second",
            })
        assert resp.status_code == 400
        assert "already registered" in resp.json()["detail"]

        app.dependency_overrides.clear()


class TestLogin:
    async def test_login_success(self, db_session: AsyncSession):
        user = User(
            email="login@example.com",
            hashed_password=hash_password("MyPass123"),
            name="Login User",
        )
        db_session.add(user)
        await db_session.commit()

        from api.database import get_db

        async def override_get_db():
            yield db_session

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/auth/login", json={
                "email": "login@example.com",
                "password": "MyPass123",
            })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["email"] == "login@example.com"

        app.dependency_overrides.clear()

    async def test_login_wrong_password(self, db_session: AsyncSession):
        user = User(
            email="wrong@example.com",
            hashed_password=hash_password("RightPass"),
            name="Wrong User",
        )
        db_session.add(user)
        await db_session.commit()

        from api.database import get_db

        async def override_get_db():
            yield db_session

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/auth/login", json={
                "email": "wrong@example.com",
                "password": "WrongPass",
            })
        assert resp.status_code == 401

        app.dependency_overrides.clear()


class TestMe:
    async def test_get_me(self, db_session: AsyncSession):
        user = User(
            email="me@example.com",
            hashed_password=hash_password("x"),
            name="Me User",
            role="admin",
        )
        db_session.add(user)
        await db_session.commit()

        from api.database import get_db

        async def override_get_db():
            yield db_session

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/auth/me",
                headers=_auth_headers(user.id),
            )
        assert resp.status_code == 200
        assert resp.json()["email"] == "me@example.com"

        app.dependency_overrides.clear()

    async def test_get_me_no_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 403


class TestApiKeys:
    async def test_create_and_list_api_keys(self, db_session: AsyncSession):
        user = User(email="keys@example.com", hashed_password=hash_password("x"), name="Keys")
        db_session.add(user)
        await db_session.commit()

        from api.database import get_db

        async def override_get_db():
            yield db_session

        app.dependency_overrides[get_db] = override_get_db
        headers = _auth_headers(user.id)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Create key
            create_resp = await client.post(
                "/api/v1/auth/api-keys",
                json={"name": "Test Key"},
                headers=headers,
            )
            assert create_resp.status_code == 201
            key_data = create_resp.json()
            assert key_data["name"] == "Test Key"
            assert key_data["key"].startswith("darca_")

            # List keys
            list_resp = await client.get("/api/v1/auth/api-keys", headers=headers)
            assert list_resp.status_code == 200
            keys = list_resp.json()
            assert len(keys) == 1
            assert keys[0]["name"] == "Test Key"

            # Delete key
            del_resp = await client.delete(
                f"/api/v1/auth/api-keys/{key_data['id']}",
                headers=headers,
            )
            assert del_resp.status_code == 204

        app.dependency_overrides.clear()
