import pytest

from cloud_guard.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_and_verify(self):
        password = "SecureP@ss123!"
        hashed = hash_password(password)
        assert hashed != password
        assert verify_password(password, hashed)

    def test_wrong_password_fails(self):
        hashed = hash_password("correct")
        assert not verify_password("wrong", hashed)

    def test_different_hashes_for_same_password(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2


class TestJWT:
    def test_create_and_decode_token(self):
        data = {"sub": "testuser", "role": "admin"}
        token = create_access_token(data)
        decoded = decode_access_token(token)
        assert decoded is not None
        assert decoded["sub"] == "testuser"
        assert decoded["role"] == "admin"

    def test_invalid_token_returns_none(self):
        assert decode_access_token("invalid.token.here") is None

    def test_token_contains_expiry(self):
        token = create_access_token({"sub": "user"})
        decoded = decode_access_token(token)
        assert "exp" in decoded
