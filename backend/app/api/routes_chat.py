"""POST /chat — report analyst chatbot.

Grounded chat over the LATEST audit run of a device (or the fleet's worst
device when none is specified). The LLM never issues verdicts; it only
explains stored findings. Deterministic template fallback keeps the chat
working fully offline.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import verify_token
from app.core.parsers.base_parser import VENDOR_LABELS
from app.core.report_analyst import answer_question, analyst_mode
from app.db import get_db
from app.models import AuditRun, Device, Finding

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatBody(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    device_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]*$")


@router.get("/status", dependencies=[Depends(verify_token)])
def chat_status():
    mode = analyst_mode()
    label = {
        "local_lm": "CompilerAI Analyst — Online (Local LM, air-gapped)",
        "llm": "CompilerAI Analyst — Online (Cloud LLM)",
        "template": "CompilerAI Analyst — Online (Deterministic, offline mode)",
    }.get(mode, mode)
    return {"status": "ok", "analyst_mode": mode, "label": label, "ai_name": "CompilerAI"}


def _device_dict(device: Device) -> dict:
    return {
        "device_id": device.device_id,
        "hostname": device.hostname,
        "vendor": device.vendor,
        "vendor_label": VENDOR_LABELS.get(device.vendor, device.vendor),
        "os_version": device.os_version,
        "model": device.model,
    }


def _load_run(db: Session, device: Device):
    run = db.scalar(
        select(AuditRun).where(AuditRun.device_fk == device.id).order_by(AuditRun.id.desc())
    )
    if run is None:
        return None, []
    findings = list(db.scalars(select(Finding).where(Finding.run_fk == run.id)).all())
    return run, findings


@router.post("", dependencies=[Depends(verify_token)])
def chat(body: ChatBody, db: Session = Depends(get_db)):
    device = None
    if body.device_id:
        device = db.scalar(select(Device).where(Device.device_id == body.device_id))
        if device is None:
            raise HTTPException(404, f"Device '{body.device_id}' not found")
    else:
        # no device selected -> fleet's most recently audited device
        run = db.scalar(select(AuditRun).order_by(AuditRun.id.desc()))
        if run is not None:
            device = db.scalar(select(Device).where(Device.id == run.device_fk))

    if device is None:
        raise HTTPException(400, "No ingested devices yet — upload a config first")

    run, findings = _load_run(db, device)
    if run is None:
        raise HTTPException(
            400,
            f"No audit run yet for '{device.device_id}' — run POST /audit/{device.device_id} first",
        )

    summary = json.loads(run.summary_json or "{}")
    findings_dicts = [
        {
            "rule_id": f.rule_id,
            "title": f.rule_title,
            "severity": f.severity,
            "status": f.status,
            "evidence": f.evidence,
            "maps_to": f.maps_to,
            "explanation": f.explanation,
            "remediation": f.remediation,
            "source": f.source,
        }
        for f in findings
    ]

    result = answer_question(
        body.question,
        _device_dict(device),
        summary,
        findings_dicts,
        unparsed_count=run.unparsed_count,
    )

    return {
        "device_id": device.device_id,
        "hostname": device.hostname,
        "run_id": run.id,
        "compliance_pct": run.compliance_pct,
        "answer": result["answer"],
        "source": result["source"],
    }
