"""ComplianceForge FastAPI entrypoint."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.api import auth
from app.api.routes_audit import router as audit_router
from app.api.routes_chat import router as chat_router
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_devices import router as devices_router
from app.api.routes_ingest import router as ingest_router
from app.api.routes_report import router as report_router
from app.api.routes_training import router as training_router
from app.core.ai_classifier import get_classifier
from app.core.security import SecurityMiddleware
from app.db import init_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("complianceforge")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    clf = get_classifier()
    if clf.local_lm_available():
        mode = "LOCAL LM (air-gapped few-shot classification)"
    elif not clf.offline:
        mode = "cloud LLM"
    else:
        mode = "offline heuristic"
    logger.info("ComplianceForge up. AI classifier mode: %s", mode)
    yield


app = FastAPI(
    title="ComplianceForge",
    description=(
        "AI-augmented, vendor-agnostic network security compliance auditor. "
        "Ingest raw CLI configs, normalize to a vendor-neutral baseline, audit "
        "against CIS-style rule packs, train unknown-command mappings with a "
        "human in the loop, and generate PDF reports."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
_extra = os.environ.get("CF_ALLOWED_ORIGINS", "")
if _extra:
    _origins.extend(o.strip() for o in _extra.split(",") if o.strip())

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(SecurityMiddleware)

app.include_router(ingest_router)
app.include_router(audit_router)
app.include_router(devices_router)
app.include_router(training_router)
app.include_router(report_router)
app.include_router(dashboard_router)
app.include_router(chat_router)


class _StripApiPrefixMiddleware:
    """On Vercel, the backend service receives the ORIGINAL public path
    (/api/health), while locally it serves /health directly. This pure-ASGI
    middleware strips the /api prefix when present so both work unchanged."""

    def __init__(self, asgi_app):
        self.asgi_app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            if path == "/api" or path.startswith("/api/"):
                scope = dict(scope)
                scope["path"] = path[4:] or "/"
                raw = scope.get("raw_path")
                if raw and len(raw) > 4:
                    scope["raw_path"] = raw[4:]
        await self.asgi_app(scope, receive, send)


handler = _StripApiPrefixMiddleware(app)


class LoginBody(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(body: LoginBody):
    token = auth.login(body.username, body.password)
    if token is None:
        raise HTTPException(401, "Invalid credentials")
    return {"token": token, "role": "admin", "username": body.username}


@app.get("/health")
def health():
    clf = get_classifier()
    if clf.local_lm_available():
        mode = "local_lm"
    elif not clf.offline:
        mode = "llm"
    else:
        mode = "offline_heuristic"
    return {
        "status": "ok",
        "ai_mode": mode,
        "local_lm_url": "http://localhost:1234",
        "advisory_only": True,
    }
