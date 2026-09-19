"""Training Loop API.

GET  /training/queue           — unparsed lines needing review (with AI suggestions)
GET  /training/mappings       — confirmed mapping cache (L1, bounded)
POST /training/classify       — unified L1/L2/L3 propose a category (no verdicts)
POST /training/confirm        — human confirms/corrects -> cache AND learning dataset
DELETE /training/mappings/{id} — remove a mapping
GET  /training/stats          — cache + model stats for the dashboard
GET  /training/model/info     — trained model version, accuracy, per-class F1
POST /training/model/retrain  — retrain on dataset, promote if acc >= current-0.02
POST /training/model/rollback/{version} — rollback to a previous artifact
GET  /training/dataset/export — JSONL {text,label} for future LLM fine-tune

HUMAN-IN-THE-LOOP BOUNDARY: nothing enters the cache/dataset without POST
/confirm or POST /train-device, which represent human decisions in the UI.
Human-verified mappings are continuously added to the learning dataset and
used for periodic model updates/fine-tuning.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import verify_token
from app.core.ai_classifier import get_classifier
from app.core.rule_cache import RuleCache, normalize_pattern
from app.core.schema import SECURITY_CATEGORIES
from app.db import get_db
from app.models import ConfigSnapshot, Device

router = APIRouter(prefix="/training", tags=["training"])


class ClassifyRequest(BaseModel):
    line: str = Field(min_length=1, max_length=500)


class ConfirmRequest(BaseModel):
    example_line: str = Field(min_length=1, max_length=500)
    category: str
    confirmed_by: str = "admin"
    ai_suggested: bool = False
    ai_confidence: float | None = None
    notes: str = ""
    vendor_hint: str = "any"


class TrainDeviceRequest(BaseModel):
    """One-click: accept AI proposals (or corrections) for every pending line
    of a device. Each entry becomes a human-confirmed mapping via the same
    gate as /confirm — this endpoint IS the human pressing 'Train'."""
    device_id: str
    corrections: dict[str, str] = Field(default_factory=dict, description="raw_line -> category overrides")
    confirmed_by: str = "admin"


@router.get("/queue", dependencies=[Depends(verify_token)])
def training_queue(db: Session = Depends(get_db)):
    """Unparsed lines from all latest snapshots, minus already-matched ones.

    Returns both the flat `queue` (backward-compat, one entry per unique raw
    line) and `clusters` — lines grouped by normalized pattern so the UI can
    offer one-click "confirm N lines" pattern recognition. The classifier is
    invoked once per *pattern*, not once per line.
    """
    cache = RuleCache(db)
    # 1 — collect pending raw lines (skip cache-covered), dedupe identical lines
    pending: list[dict] = []
    seen_raw: set[str] = set()
    devices = list(db.scalars(select(Device)).all())
    for device in devices:
        snap = db.scalar(
            select(ConfigSnapshot)
            .where(ConfigSnapshot.device_fk == device.id)
            .order_by(ConfigSnapshot.id.desc())
        )
        if snap is None:
            continue
        normalized = _load_normalized(snap)
        for ul in normalized.get("unparsed_lines", []):
            text = ul.get("text", "")
            if not text or text in seen_raw:
                continue
            seen_raw.add(text)
            # SKIP anything the cache already covers (exact) —
            # that line is already "learned" and must not re-ask a human.
            hit = cache.match(text, vendor_hint=device.vendor)
            if hit and hit.get("confidence", 0) >= 1.0:
                continue
            pending.append(
                {
                    "device_id": device.device_id,
                    "vendor": device.vendor,
                    "line_number": ul.get("line_number", 0),
                    "raw_line": text,
                    "suggested_category": ul.get("suggested_category"),
                    "suggested_confidence": ul.get("suggested_confidence"),
                    "cache_hit": hit,
                }
            )
    # 2 — group by normalized pattern (pattern recognition), classify once each
    by_pattern: dict[str, list[dict]] = {}
    for p in pending:
        by_pattern.setdefault(normalize_pattern(p["raw_line"]), []).append(p)
    classifier = get_classifier()
    queue: list[dict] = []
    clusters: list[dict] = []
    for pattern, members in by_pattern.items():
        rep = members[0]
        if rep["suggested_category"]:
            category, confidence, source = (
                rep["suggested_category"],
                rep["suggested_confidence"],
                "ingest_suggestion",
            )
            model_version = None
        elif rep["cache_hit"]:
            # exact-cache proposal surfaced via ingest enrichment — still
            # needs human confirmation (queue never auto-confirms)
            category = rep["cache_hit"]["category"]
            confidence = rep["cache_hit"]["confidence"]
            source = rep["cache_hit"].get("match_type", "pattern_exact")
            model_version = None
        else:
            # unified L1 -> L2 -> L3 chain (L1 already checked above, so
            # this is effectively L2 trained model -> L3 fallback)
            proposal = classifier.classify(rep["raw_line"], db=db, vendor_hint=rep["vendor"])
            category, confidence, source = (
                proposal["category"],
                proposal["confidence"],
                proposal["source"],
            )
            model_version = proposal.get("model_version")
        for m in members:
            entry = {
                "device_id": m["device_id"],
                "vendor": m["vendor"],
                "line_number": m["line_number"],
                "raw_line": m["raw_line"],
                "pattern": pattern,
                "ai_category": category,
                "ai_confidence": confidence,
                "ai_source": source,
                "model_version": model_version,
            }
            if m["cache_hit"] and not m["suggested_category"]:
                entry["match_type"] = m["cache_hit"].get("match_type")
            queue.append(entry)
        clusters.append(
            {
                "pattern": pattern,
                "count": len(members),
                "ai_category": category,
                "ai_confidence": confidence,
                "ai_source": source,
                "model_version": model_version,
                "vendor": rep["vendor"],
                "representative_line": rep["raw_line"],
                "examples": [
                    {
                        "raw_line": m["raw_line"],
                        "device_id": m["device_id"],
                        "line_number": m["line_number"],
                    }
                    for m in members[:5]
                ],
                "device_ids": sorted({m["device_id"] for m in members}),
            }
        )
    clusters.sort(key=lambda c: (-c["count"], c["pattern"]))
    return {
        "queue": queue,
        "count": len(queue),
        "clusters": clusters,
        "cluster_count": len(clusters),
    }


@router.post("/classify", dependencies=[Depends(verify_token)])
def classify_line(req: ClassifyRequest, db: Session = Depends(get_db)):
    """Unified L1/L2/L3 proposal. NEVER a pass/fail verdict — human must confirm."""
    proposal = get_classifier().classify(req.line, db=db)
    # backward-compat shape: cache_match vs ai (tests + UI read both)
    if proposal.get("source") == "cache_exact":
        return {
            "line": req.line,
            "cache_match": {
                "category": proposal["category"],
                "confidence": proposal["confidence"],
                "match_type": proposal.get("match_type", "pattern_exact"),
                "mapping_id": proposal.get("mapping_id"),
            },
            "ai": None,
            "source": proposal["source"],
            "model_version": proposal.get("model_version"),
        }
    return {
        "line": req.line,
        "cache_match": None,
        "ai": proposal,
        "source": proposal.get("source"),
        "model_version": proposal.get("model_version"),
    }


@router.get("/mappings", dependencies=[Depends(verify_token)])
def list_mappings(db: Session = Depends(get_db)):
    mappings = RuleCache(db).all_mappings()
    return {
        "mappings": [
            {
                "id": m.id,
                "pattern": m.pattern,
                "example_line": m.example_line,
                "category": m.category,
                "vendor_hint": m.vendor_hint,
                "confirmed_by": m.confirmed_by,
                "ai_suggested": m.ai_suggested,
                "ai_confidence": m.ai_confidence,
                "times_matched": m.times_matched,
                "confirmed_at": m.confirmed_at.isoformat() if m.confirmed_at else None,
                "notes": m.notes,
            }
            for m in mappings
        ]
    }


@router.post("/confirm", dependencies=[Depends(verify_token)])
def confirm_mapping(req: ConfirmRequest, db: Session = Depends(get_db)):
    if req.category not in SECURITY_CATEGORIES:
        raise HTTPException(422, f"Unknown category '{req.category}'. Valid: {SECURITY_CATEGORIES}")
    mapping = RuleCache(db).confirm(
        example_line=req.example_line,
        category=req.category,
        confirmed_by=req.confirmed_by,
        ai_suggested=req.ai_suggested,
        ai_confidence=req.ai_confidence,
        notes=req.notes,
        vendor_hint=req.vendor_hint,
    )
    # Human-verified mappings are continuously added to the learning dataset
    # and used for periodic model updates/fine-tuning.
    from app.core.trained_classifier import append_example

    dataset_appended = append_example(
        req.example_line, req.category, source=f"human-confirm:{req.confirmed_by}"
    )
    return {
        "confirmed": True,
        "mapping": {
            "id": mapping.id,
            "pattern": mapping.pattern,
            "category": mapping.category,
            "confirmed_by": mapping.confirmed_by,
            "ai_suggested": mapping.ai_suggested,
        },
        "dataset_appended": dataset_appended,
        "note": "Human-in-the-loop: this mapping will now auto-match its exact pattern, and is logged to the learning dataset for the next model update.",
    }


@router.delete("/mappings/{mapping_id}", dependencies=[Depends(verify_token)])
def delete_mapping(mapping_id: int, db: Session = Depends(get_db)):
    ok = RuleCache(db).delete(mapping_id)
    if not ok:
        raise HTTPException(404, "Mapping not found")
    return {"deleted": True}


@router.post("/train-device", dependencies=[Depends(verify_token)])
def train_device(req: TrainDeviceRequest, db: Session = Depends(get_db)):
    """One-click 'Train this device': confirm a category for every pending
    (unlearned) line of the device. Uses the AI proposal by default; any line
    present in `corrections` uses the human's category instead. This endpoint
    represents the human's bulk approval in the UI."""
    device = db.scalar(select(Device).where(Device.device_id == req.device_id))
    if device is None:
        raise HTTPException(404, f"Device '{req.device_id}' not found")
    snap = db.scalar(
        select(ConfigSnapshot)
        .where(ConfigSnapshot.device_fk == device.id)
        .order_by(ConfigSnapshot.id.desc())
    )
    if snap is None:
        raise HTTPException(404, f"No config snapshot for device '{req.device_id}'")

    cache = RuleCache(db)
    classifier = get_classifier()
    from app.core.trained_classifier import append_example as _append

    trained, skipped, lines = 0, 0, []
    for raw in snap.raw_config.splitlines():
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        hit = cache.match(line, vendor_hint=device.vendor)
        if hit and hit.get("confidence", 0) >= 1.0:
            skipped += 1  # already learned — auto-recognized
            continue
        category = req.corrections.get(line)
        ai_suggested = False
        if category is None:
            proposal = classifier.classify(line, db=db, vendor_hint=device.vendor)
            category = proposal["category"]
            confidence = proposal["confidence"]
            ai_suggested = True
        else:
            confidence = 1.0
        if category not in SECURITY_CATEGORIES:
            category = "unknown"
        cache.confirm(
            example_line=line,
            category=category,
            confirmed_by=req.confirmed_by,
            ai_suggested=ai_suggested,
            ai_confidence=confidence,
            vendor_hint=device.vendor,
            notes="bulk train-device",
        )
        _append(line, category, source=f"train-device:{req.confirmed_by}")
        trained += 1
        lines.append({"line": line, "category": category, "source": "ai+human" if ai_suggested else "human"})

    return {
        "device_id": req.device_id,
        "trained_lines": trained,
        "already_learned": skipped,
        "learned": trained > 0,
        "detail": lines[:50],
        "note": "Device is now known to the application. Re-ingest the same file (or just re-run the audit) — its lines will auto-recognize and full rule checks apply.",
    }


@router.get("/stats", dependencies=[Depends(verify_token)])
def training_stats(db: Session = Depends(get_db)):
    from app.core.trained_classifier import dataset_size, get_model_info

    stats = RuleCache(db).stats()
    info = get_model_info()
    stats.update(
        {
            "dataset_size": dataset_size(),
            "model_version": info.get("model_version", 0),
            "model_accuracy": info.get("accuracy"),
            "model_size_bytes": info.get("size_bytes", 0),
        }
    )
    return stats


@router.get("/model/info", dependencies=[Depends(verify_token)])
def model_info():
    """Versioned artifact info: version, accuracy, per-category F1, size."""
    from app.core.trained_classifier import dataset_size, get_model_info

    info = get_model_info()
    info["dataset_size"] = dataset_size()
    return info


@router.post("/model/retrain", dependencies=[Depends(verify_token)])
def model_retrain():
    """Periodic update job: retrain on the learning dataset (80/20 split).

    Promotes the new artifact only if accuracy >= current - 0.02 (accuracy
    gate); otherwise rolls back to the previous version and reports both
    scores. Storage stays O(model size), not O(unknowns).
    """
    from app.core.trained_classifier import get_model_info, set_current_version, train_and_save

    before = get_model_info()
    prev_version = before.get("model_version", 0)
    prev_acc = before.get("accuracy")
    entry = train_and_save()
    new_acc = entry["accuracy"]
    gate = (prev_acc is None) or (new_acc >= prev_acc - 0.02)
    if not gate:
        set_current_version(prev_version)
        return {
            "promoted": False,
            "reason": f"accuracy gate: new {new_acc} < current {prev_acc} - 0.02; kept v{prev_version}",
            "previous": {"version": prev_version, "accuracy": prev_acc},
            "candidate": entry,
        }
    return {"promoted": True, "model": entry, "previous": {"version": prev_version, "accuracy": prev_acc}}


@router.post("/model/rollback/{version}", dependencies=[Depends(verify_token)])
def model_rollback(version: int):
    """Rollback to a previous versioned artifact."""
    from app.core.trained_classifier import set_current_version

    try:
        info = set_current_version(version)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    return {"rolled_back": True, "model": info}


@router.get("/dataset/export", dependencies=[Depends(verify_token)])
def dataset_export():
    """Export learning dataset as JSONL {text,label} for future LLM fine-tune."""
    from fastapi.responses import PlainTextResponse

    from app.core.trained_classifier import DATASET_PATH

    if not DATASET_PATH.exists():
        raise HTTPException(404, "No dataset yet")
    rows = []
    with open(DATASET_PATH, encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                rows.append(json.dumps({"text": obj["text"], "label": obj["label"]}))
            except (json.JSONDecodeError, KeyError):
                continue
    return PlainTextResponse("\n".join(rows), media_type="application/x-ndjson")


def _load_normalized(snap: ConfigSnapshot) -> dict:
    try:
        return json.loads(snap.normalized or "{}")
    except json.JSONDecodeError:
        return {}
