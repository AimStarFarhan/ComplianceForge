"""ComplianceForge FastAPI entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.api import auth
from app.api.routes_audit import router as audit_router
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_devices import router as devices_router
from app.api.routes_ingest import router as ingest_router
from app.api.routes_report import router as report_router
from app.api.routes_training import router as training_router
from app.core.ai_classifier import get_classifier
from app.db import init_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("complianceforge")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    mode = "offline heuristic" if get_classifier().offline else "LLM"
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest_router)
app.include_router(audit_router)
app.include_router(devices_router)
app.include_router(training_router)
app.include_router(report_router)
app.include_router(dashboard_router)


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
    return {
        "status": "ok",
        "ai_mode": "offline_heuristic" if get_classifier().offline else "llm",
        "advisory_only": True,
    }
