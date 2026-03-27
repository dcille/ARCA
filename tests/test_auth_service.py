"""Tests for the authentication service — password hashing, JWT, credential encryption."""
import pytest
from datetime import timedelta

from api.services.auth_service import (
    hash_password,
    verify_password,
    create_access_token,
    encrypt_credentials,
    decrypt_credentials,
)


class TestPasswordHashing:
    def test_hash_and_verify(self):
        password = "S3cureP@ssw0rd!"
        hashed = hash_password(password)
        assert hashed != password
        assert verify_password(password, hashed) is True

    def test_wrong_password(self):
        hashed = hash_password("correct")
        assert verify_password("wrong", hashed) is False

    def test_different_hashes_for_same_password(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2  # bcrypt uses random salt


class TestJWT:
    def test_create_token(self):
        token = create_access_token(data={"sub": "user-123"})
        assert isinstance(token, str)
        assert len(token) > 0

    def test_create_token_with_expiry(self):
        token = create_access_token(
            data={"sub": "user-123"},
            expires_delta=timedelta(minutes=5),
        )
        assert isinstance(token, str)

    def test_token_payload(self):
        from jose import jwt
        from api.config import settings

        token = create_access_token(data={"sub": "user-456", "role": "admin"})
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["sub"] == "user-456"
        assert payload["role"] == "admin"
        assert "exp" in payload


class TestCredentialEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        creds = {
            "access_key_id": "AKIA1234",
            "secret_access_key": "s3cr3t",
            "region": "us-east-1",
        }
        encrypted = encrypt_credentials(creds)
        assert encrypted != str(creds)
        decrypted = decrypt_credentials(encrypted)
        assert decrypted == creds

    def test_encrypt_empty_dict(self):
        encrypted = encrypt_credentials({})
        decrypted = decrypt_credentials(encrypted)
        assert decrypted == {}

    def test_encrypt_nested_dict(self):
        creds = {"tenant_id": "t", "nested": {"key": "value"}}
        decrypted = decrypt_credentials(encrypt_credentials(creds))
        assert decrypted["nested"]["key"] == "value"
