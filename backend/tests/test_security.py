"""Security hardening tests: rate limiting, headers, upload validation, auth."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("CF_DB_PATH", str(Path(__file__).parent / "test_cf.db"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.core.security import upload_is_safe  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_security_headers_present(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in r.headers


def test_login_rate_limited():
    # fresh app instance so this test's limiter state doesn't leak to others
    from app.core.security import RateLimiter, SecurityMiddleware
    from fastapi import FastAPI

    api = FastAPI()
    api.add_middleware(SecurityMiddleware, rate_limiter=RateLimiter(login_limit=3, login_window=60))

    @api.post("/login")
    def login():
        return {"ok": True}

    with TestClient(api) as c:
        for i in range(5):
            r = c.post("/login", json={"username": "admin", "password": "wrong"})
            if r.status_code == 429:
                break
        assert r.status_code == 429, f"expected 429 by attempt 5, got {r.status_code} on attempt {i + 1}"
        assert "Retry-After" in r.headers


def test_upload_extension_blocked():
    ok, reason = upload_is_safe("payload.exe", 100)
    assert not ok and "not allowed" in reason
    ok, _ = upload_is_safe("router.cfg", 100)
    assert ok
    ok, reason = upload_is_safe("huge.cfg", 3 * 1024 * 1024)
    assert not ok and "2 MB" in reason


def test_upload_rejects_executable(client):
    r = client.post(
        "/login",
        json={"username": "admin", "password": os.environ.get("CF_ADMIN_PASSWORD", "admin")},
    )
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    r = client.post(
        "/ingest",
        files={"file": ("evil.exe", b"MZ\x90\x00", "application/octet-stream")},
        data={"device_id": "evil-test"},
        headers=h,
    )
    assert r.status_code in (415, 403, 413)
    assert "not allowed" in r.json()["detail"] or "not an accepted" in r.json()["detail"]


def test_auth_required_everywhere(client):
    for path in ("/devices", "/dashboard", "/training/mappings", "/chat/status"):
        r = client.get(path)
        assert r.status_code == 401, f"{path} must require auth, got {r.status_code}"


def test_jwt_secret_required_in_prod():
    # simulate prod without secret -> must refuse to boot
    import importlib
    import app.api.auth as auth_mod
    os.environ["CF_ENV"] = "prod"
    os.environ.pop("CF_JWT_SECRET", None)
    try:
        importlib.reload(auth_mod)  # re-evaluates _jwt_secret()
        pytest.fail("auth must SystemExit in prod without CF_JWT_SECRET")
    except SystemExit:
        pass
    finally:
        os.environ["CF_ENV"] = "dev"
        importlib.reload(auth_mod)
