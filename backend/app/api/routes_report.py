"""GET /report/{device_id} — PDF compliance report per device."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import verify_token
from app.core.parsers.base_parser import VENDOR_LABELS
from app.core.report_builder import build_pdf
from app.db import get_db
from app.models import AuditRun, Device, Finding

router = APIRouter(prefix="/report", tags=["report"])


@router.get("/{device_id}", dependencies=[Depends(verify_token)])
def device_report(device_id: str, db: Session = Depends(get_db)):
    device = db.scalar(select(Device).where(Device.device_id == device_id))
    if device is None:
        raise HTTPException(404, f"Device '{device_id}' not found")

    run = db.scalar(
        select(AuditRun)
        .where(AuditRun.device_fk == device.id)
        .order_by(AuditRun.id.desc())
    )
    if run is None:
        raise HTTPException(404, f"No audit run yet for device '{device_id}' — run POST /audit/{device_id} first")

    findings = list(db.scalars(select(Finding).where(Finding.run_fk == run.id)).all())

    device_dict = {
        "device_id": device.device_id,
        "hostname": device.hostname,
        "vendor": device.vendor,
        "vendor_label": VENDOR_LABELS.get(device.vendor, device.vendor),
        "os_version": device.os_version,
        "model": device.model,
    }
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

    pdf_bytes = build_pdf(device_dict, summary, findings_dicts, unparsed_count=run.unparsed_count)
    filename = f"complianceforge_{device.device_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
