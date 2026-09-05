"""GET /dashboard — fleet-wide compliance posture + device inventory."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import verify_token
from app.core.parsers.base_parser import VENDOR_LABELS
from app.db import get_db
from app.models import AuditRun, Device

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("", dependencies=[Depends(verify_token)])
def fleet_summary(db: Session = Depends(get_db)):
    devices = list(db.scalars(select(Device).order_by(Device.id)).all())
    device_rows = []
    compliance_scores = []
    severity_totals: dict[str, int] = {}

    for d in devices:
        run = db.scalar(
            select(AuditRun)
            .where(AuditRun.device_fk == d.id)
            .order_by(AuditRun.id.desc())
        )
        if run:
            summary = json.loads(run.summary_json or "{}")
            row = {
                "device_id": d.device_id,
                "hostname": d.hostname,
                "vendor": d.vendor,
                "vendor_label": VENDOR_LABELS.get(d.vendor, d.vendor),
                "os_version": d.os_version,
                "model": d.model,
                "compliance_pct": run.compliance_pct,
                "pass_count": run.pass_count,
                "fail_count": run.fail_count,
                "run_id": run.id,
                "audited": True,
                "unparsed_count": run.unparsed_count,
                "is_unseen_vendor": d.is_unseen_vendor,
            }
            compliance_scores.append(run.compliance_pct)
            for sev, n in (summary.get("failed_by_severity") or {}).items():
                severity_totals[sev] = severity_totals.get(sev, 0) + n
        else:
            row = {
                "device_id": d.device_id,
                "hostname": d.hostname,
                "vendor": d.vendor,
                "vendor_label": VENDOR_LABELS.get(d.vendor, d.vendor),
                "os_version": d.os_version,
                "model": d.model,
                "compliance_pct": None,
                "pass_count": 0,
                "fail_count": 0,
                "run_id": None,
                "audited": False,
                "unparsed_count": 0,
                "is_unseen_vendor": d.is_unseen_vendor,
            }
        device_rows.append(row)

    fleet_score = round(sum(compliance_scores) / len(compliance_scores), 1) if compliance_scores else None

    vendors = {}
    for row in device_rows:
        v = vendors.setdefault(row["vendor"], {"vendor": row["vendor"], "label": row["vendor_label"], "devices": 0, "audited": 0, "scores": []})
        v["devices"] += 1
        if row["audited"]:
            v["audited"] += 1
            v["scores"].append(row["compliance_pct"])
    for v in vendors.values():
        v["avg_compliance"] = round(sum(v["scores"]) / len(v["scores"]), 1) if v["scores"] else None
        del v["scores"]

    return {
        "fleet_compliance_score": fleet_score,
        "device_count": len(device_rows),
        "audited_count": sum(1 for r in device_rows if r["audited"]),
        "total_open_findings": sum(r["fail_count"] for r in device_rows),
        "severity_totals": severity_totals,
        "devices": device_rows,
        "by_vendor": list(vendors.values()),
    }
