"""Device listing + single-device latest audit detail."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import verify_token
from app.core.parsers.base_parser import VENDOR_LABELS
from app.db import get_db
from app.models import AuditRun, ConfigSnapshot, Device, Finding

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", dependencies=[Depends(verify_token)])
def list_devices(db: Session = Depends(get_db)):
    devices = list(db.scalars(select(Device).order_by(Device.id)).all())
    out = []
    for d in devices:
        run = db.scalar(
            select(AuditRun).where(AuditRun.device_fk == d.id).order_by(AuditRun.id.desc())
        )
        out.append(
            {
                "device_id": d.device_id,
                "hostname": d.hostname,
                "vendor": d.vendor,
                "vendor_label": VENDOR_LABELS.get(d.vendor, d.vendor),
                "os_version": d.os_version,
                "model": d.model,
                "is_unseen_vendor": d.is_unseen_vendor,
                "compliance_pct": run.compliance_pct if run else None,
                "pass_count": run.pass_count if run else 0,
                "fail_count": run.fail_count if run else 0,
                "unparsed_count": run.unparsed_count if run else 0,
                "last_audit": run.ran_at.isoformat() if run else None,
            }
        )
    return {"devices": out}


@router.get("/{device_id}", dependencies=[Depends(verify_token)])
def device_detail(device_id: str, db: Session = Depends(get_db)):
    device = db.scalar(select(Device).where(Device.device_id == device_id))
    if device is None:
        raise HTTPException(404, f"Device '{device_id}' not found")
    run = db.scalar(
        select(AuditRun).where(AuditRun.device_fk == device.id).order_by(AuditRun.id.desc())
    )
    if run is None:
        return {
            "device_id": device.device_id,
            "vendor": device.vendor,
            "vendor_label": VENDOR_LABELS.get(device.vendor, device.vendor),
            "hostname": device.hostname,
            "os_version": device.os_version,
            "model": device.model,
            "summary": None,
            "findings": [],
            "raw_config": None,
            "normalized": None,
            "history": [],
        }
    findings = list(db.scalars(select(Finding).where(Finding.run_fk == run.id)).all())

    # latest snapshot raw config + normalized baseline for the dual-pane view
    snap = db.scalar(
        select(ConfigSnapshot)
        .where(ConfigSnapshot.device_fk == device.id)
        .order_by(ConfigSnapshot.id.desc())
    )
    raw_config = snap.raw_config if snap else None
    try:
        normalized = json.loads(snap.normalized) if snap else None
    except json.JSONDecodeError:
        normalized = None

    # audit history timeline (all runs, oldest first)
    history_runs = list(
        db.scalars(
            select(AuditRun).where(AuditRun.device_fk == device.id).order_by(AuditRun.id.asc())
        ).all()
    )
    history = [
        {
            "run_id": r.id,
            "ran_at": r.ran_at.isoformat() if r.ran_at else None,
            "compliance_pct": r.compliance_pct,
            "pass_count": r.pass_count,
            "fail_count": r.fail_count,
            "unparsed_count": r.unparsed_count,
        }
        for r in history_runs
    ]

    return {
        "device_id": device.device_id,
        "vendor": device.vendor,
        "vendor_label": VENDOR_LABELS.get(device.vendor, device.vendor),
        "hostname": device.hostname,
        "os_version": device.os_version,
        "model": device.model,
        "summary": json.loads(run.summary_json or "{}"),
        "findings": [
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
        ],
        "raw_config": raw_config,
        "normalized": normalized,
        "history": history,
    }
