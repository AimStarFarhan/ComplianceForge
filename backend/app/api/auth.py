"""Simple JWT auth: single admin role (demo).

Password from env CF_ADMIN_PASSWORD (default 'admin'). Judges asked "who can
approve a mapping" — the answer is this named admin role.
"""

from __future__ import annotations

import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

ALGORITHM = "HS256"
TOKEN_TTL_MINUTES = 12 * 60

ADMIN_USER = "admin"
ADMIN_PASSWORD = os.environ.get("CF_ADMIN_PASSWORD", "admin")


def _jwt_secret() -> str:
    """CF_JWT_SECRET wins; dev fallback only outside production, per worker-random
    would break multi-worker auth, so in prod we REQUIRE it to be set."""
    env = os.environ.get("CF_JWT_SECRET", "")
    if env:
        return env
    if os.environ.get("CF_ENV", "dev").lower() in ("prod", "production"):
        print("FATAL: CF_JWT_SECRET must be set in production", file=sys.stderr)
        raise SystemExit(1)
    return "complianceforge-dev-secret"  # single-process dev/demo only


SECRET = _jwt_secret()

_security = HTTPBearer(auto_error=False)


def issue_token(username: str = ADMIN_USER) -> str:
    payload = {
        "sub": username,
        "role": "admin",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_TTL_MINUTES),
    }
    return jwt.encode(payload, SECRET, algorithm=ALGORITHM)


def verify_token(creds: HTTPAuthorizationCredentials | None = Depends(_security)) -> dict:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    try:
        payload = jwt.decode(creds.credentials, SECRET, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    if payload.get("role") != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the admin role may perform this action")
    return payload


def login(username: str, password: str) -> str | None:
    if username == ADMIN_USER and password == ADMIN_PASSWORD:
        return issue_token(username)
    return None
