"""POST /audit/{device_id} — re-run normalization + rule evaluation.

Steps:
  1. Load latest snapshot raw config for the device.
  2. Parse (fresh) with the confirmed rule cache applied to unparsed lines.
  3. Run the rule pack for the vendor.
  4. Persist AuditRun + Findings; findings whose evidence came from an
     AI-suggested + human-confirmed mapping are tagged with
     source='ai_suggested_human_confirmed'.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import verify_token
from app.core.baseline_inference import infer_baseline
from app.core.parsers import get_parser
from app.core.parsers.base_parser import VENDOR_UNSEEN
from app.core.rule_cache import RuleCache
from app.core.rule_engine import run_audit, summarize
from app.db import get_db
from app.models import AuditRun, ConfigSnapshot, Device, Finding

router = APIRouter(prefix="/audit", tags=["audit"])


@router.post("/{device_id}", dependencies=[Depends(verify_token)])
def audit_device(device_id: str, db: Session = Depends(get_db)):
    device = db.scalar(select(Device).where(Device.device_id == device_id))
    if device is None:
        raise HTTPException(404, f"Device '{device_id}' not found — ingest a config first")

    snapshot = db.scalar(
        select(ConfigSnapshot)
        .where(ConfigSnapshot.device_fk == device.id)
        .order_by(ConfigSnapshot.id.desc())
    )
    if snapshot is None:
        raise HTTPException(404, f"No config snapshot for device '{device_id}'")

    baseline = _normalize(db, snapshot, device)

    if device.vendor == VENDOR_UNSEEN:
        # Learned-vendor audit: the baseline is INFERRED from human-confirmed
        # mappings, so every finding is tagged ai_suggested_human_confirmed.
        if _mapping_coverage(db, snapshot) > 0:
            results = run_audit(baseline)
            for r in results:
                r["source"] = "ai_suggested_human_confirmed"
        else:
            results = []
    else:
        results = run_audit(baseline)

    summary = summarize(results) if results else {
        "total_rules": 0, "pass_count": 0, "fail_count": 0, "error_count": 0,
        "not_applicable_count": 0, "compliance_pct": 0.0,
        "failed_by_severity": {}, "top_critical_findings": [],
    }

    run = AuditRun(
        snapshot_fk=snapshot.id,
        device_fk=device.id,
        total_rules=summary["total_rules"],
        pass_count=summary["pass_count"],
        fail_count=summary["fail_count"],
        error_count=summary["error_count"],
        compliance_pct=summary["compliance_pct"],
        unparsed_count=len(baseline.unparsed_lines),
        summary_json=json.dumps(summary),
    )
    db.add(run)
    db.flush()
    for r in results:
        db.add(Finding(run_fk=run.id, **{k: r.get(k, "") for k in (
            "rule_id", "rule_title", "title", "severity", "status", "evidence",
            "maps_to", "explanation", "remediation", "source", "category",
        ) if k in ("rule_id", "severity", "status", "evidence", "maps_to", "explanation", "remediation", "source", "category")} | {"rule_title": r["title"]}))
    snapshot.audited = True
    if device.vendor == VENDOR_UNSEEN and results:
        # persist the INFERRED baseline so the UI's "Normalized Baseline" pane
        # shows what the learned mappings produced, not the empty ingest-time state
        snapshot.normalized = baseline.model_dump_json()
    db.commit()
    db.refresh(run)

    return {
        "run_id": run.id,
        "device_id": device.device_id,
        "vendor": device.vendor,
        "summary": summary,
        "findings": results,
        "unparsed_count": len(baseline.unparsed_lines),
        "unparsed_lines": [ul.model_dump() for ul in baseline.unparsed_lines],
    }


def _normalize(db, snapshot, device):
    parser = get_parser(device.vendor)
    if parser is None:
        # UNSEEN vendor: infer the baseline from human-confirmed mappings.
        # Lines with no confirmed mapping stay in unparsed_lines (queue).
        baseline, _tallies = infer_baseline(db, device.device_id, snapshot.raw_config)
        return baseline
    baseline = parser.parse(snapshot.raw_config, device.device_id)
    cache = RuleCache(db)
    for ul in baseline.unparsed_lines:
        hit = cache.match(ul.text, vendor_hint=device.vendor)
        if hit:
            ul.category = hit["category"]
            ul.suggested_category = hit["category"]
            ul.suggested_confidence = hit["confidence"]
    return baseline


def _mapping_coverage(db, snapshot) -> float:
    """Fraction of substantive raw lines that have a confirmed mapping."""
    cache = RuleCache(db)
    total = matched = 0
    for line in snapshot.raw_config.splitlines():
        s = line.strip()
        if not s or s.startswith("!") or s.startswith("#"):
            continue
        total += 1
        if cache.match(s, vendor_hint="any"):
            matched += 1
    return matched / total if total else 0.0
