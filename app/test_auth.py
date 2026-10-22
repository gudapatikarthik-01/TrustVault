import jwt
import pytest

from app.auth import (
    create_access_token,
    SECRET_KEY,
    ALGORITHM,
)


def test_create_access_token():
    user = {
        "id": 1,
        "username": "test_owner",
        "role": "owner",
    }

    token = create_access_token(user)

    assert isinstance(token, str)
    assert len(token) > 0


def test_decode_access_token():
    user = {
        "id": 1,
        "username": "test_owner",
        "role": "owner",
    }

    token = create_access_token(user)

    decoded = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
    )

    assert decoded["sub"] == "1"
    assert decoded["username"] == "test_owner"
    assert decoded["role"] == "owner"


def test_invalid_token_is_rejected():
    with pytest.raises(jwt.InvalidTokenError):
        jwt.decode(
            "invalid.token.value",
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )