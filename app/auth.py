from django.db import connection
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
from datetime import datetime, timedelta, timezone
import jwt
from dotenv import load_dotenv
from pwdlib import PasswordHash

password_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Convert a password into a secure hash."""
    return password_hasher.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Check whether a password matches its hash."""
    return password_hasher.verify(password, hashed_password)
from app.database import get_connection, log_action


def register_user(username: str, password: str, role: str):
    if role not in ("admin", "owner", "viewer"):
        raise ValueError("Invalid role")

    hashed_password = hash_password(password)

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (username, hashed_password, role),
        )
        connection.commit()
        return {"message": "User registered successfully"}

    finally:
        connection.close()


def login_user(username: str, password: str):
    connection = get_connection()

    try:
        user = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user is None:
            return None

        if not verify_password(password, user["password_hash"]):
            return None

        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        }

    finally:
        connection.close()
load_dotenv()

SECRET_KEY = os.getenv("TRUSTVAULT_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("TRUSTVAULT_SECRET_KEY is missing from .env")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
def create_access_token(user: dict) -> str:
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
security = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
):
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        )

    connection = get_connection()
    try:
        user = connection.execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

        if user is None:
            raise HTTPException(
                status_code=401,
                detail="User not found",
            )

        return dict(user)
    finally:
        connection.close()

from typing import Callable
from fastapi import Depends, HTTPException


from collections.abc import Callable
from fastapi import Depends, HTTPException, status


def require_role(*allowed_roles: str) -> Callable:
    def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user.get("role") not in allowed_roles:
            log_action(
                user_id=current_user.get("id"),
                action="ACCESS_DENIED",
                details=f"Required role: {', '.join(allowed_roles)}",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return current_user

    return role_checker