"""JWT auth: single admin role.

Startup REQUIRES CF_ADMIN_PASSWORD and CF_JWT_SECRET to be set, unless the
explicit dev escape hatch CF_DEV_ALLOW_DEFAULTS=1 is present (tests + local
demo only). There is deliberately no production default: shipping admin/admin
means anyone who can reach the login endpoint becomes the human in the loop.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

ALGORITHM = "HS256"
TOKEN_TTL_MINUTES = 12 * 60

ADMIN_USER = "admin"


def _dev_defaults_allowed() -> bool:
    return os.environ.get("CF_DEV_ALLOW_DEFAULTS", "0") == "1"


def demo_open() -> bool:
    """Public-demo escape hatch (judge/demo links).

    OFF by default. Set CF_DEMO_OPEN=1 ONLY on a throwaway demo deployment
    where anyone with the link may ingest, audit, and train (every demo
    action is still attributed to the 'demo-judge' reviewer in the decision
    log). Never enable on infrastructure holding real configs.
    """
    return os.environ.get("CF_DEMO_OPEN", "0") == "1"


def _require_env(name: str, dev_default: str) -> str:
    value = os.environ.get(name, "")
    if value:
        return value
    if _dev_defaults_allowed():
        print(
            f"WARNING: {name} not set -- using insecure dev default. "
            "Set it before any shared/demo deployment.",
            file=sys.stderr,
        )
        return dev_default
    print(
        f"FATAL: {name} must be set (or set CF_DEV_ALLOW_DEFAULTS=1 for local "
        "dev/tests only). Refusing to start with default credentials.",
        file=sys.stderr,
    )
    raise SystemExit(1)


ADMIN_PASSWORD = _require_env("CF_ADMIN_PASSWORD", "admin")


def _jwt_secret() -> str:
    return _require_env("CF_JWT_SECRET", "complianceforge-dev-secret")


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
        if demo_open():
            return {"sub": "demo-judge", "role": "admin"}
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
