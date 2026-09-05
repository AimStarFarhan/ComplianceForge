"""Training Loop API.

GET  /training/queue           — unparsed lines needing review (with AI suggestions)
GET  /training/mappings       — confirmed mapping cache
POST /training/classify       — ask the AI classifier to propose a category (no verdicts)
POST /training/confirm        — human confirms/corrects a mapping -> cache
DELETE /training/mappings/{id} — remove a mapping
GET  /training/stats          — cache stats for the dashboard

HUMAN-IN-THE-LOOP BOUNDARY: nothing enters the cache without POST /confirm,
which represents a human decision in the UI.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import verify_token
from app.core.ai_classifier import get_classifier
from app.core.rule_cache import RuleCache
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
    """Unparsed lines from all latest snapshots, minus already-matched ones."""
    cache = RuleCache(db)
    queue: list[dict] = []
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
            if not text:
                continue
            # SKIP anything the cache already covers (exact or fuzzy) —
            # that line is already "learned" and must not re-ask a human.
            hit = cache.match(text, vendor_hint=device.vendor)
            if hit and hit.get("confidence", 0) >= 1.0:
                continue
            # propose an AI classification for everything still pending
            entry = {
                "device_id": device.device_id,
                "vendor": device.vendor,
                "line_number": ul.get("line_number", 0),
                "raw_line": text,
                "ai_category": None,
                "ai_confidence": None,
            }
            if ul.get("suggested_category"):
                entry["ai_category"] = ul["suggested_category"]
                entry["ai_confidence"] = ul.get("suggested_confidence")
            elif hit:
                # fuzzy/similarity proposal — still needs human confirmation
                entry["ai_category"] = hit["category"]
                entry["ai_confidence"] = hit["confidence"]
                entry["match_type"] = hit["match_type"]
            else:
                proposal = get_classifier().classify(text)
                entry["ai_category"] = proposal["category"]
                entry["ai_confidence"] = proposal["confidence"]
                entry["ai_source"] = proposal["source"]
            queue.append(entry)
    # dedupe identical raw lines across devices
    seen: set[str] = set()
    deduped = []
    for e in queue:
        key = e["raw_line"]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(e)
    return {"queue": deduped, "count": len(deduped)}


@router.post("/classify", dependencies=[Depends(verify_token)])
def classify_line(req: ClassifyRequest, db: Session = Depends(get_db)):
    """AI proposes a category. NEVER a pass/fail verdict — human must confirm."""
    cache = RuleCache(db)
    hit = cache.match(req.line)
    if hit:
        return {"line": req.line, "cache_match": hit, "ai": None}
    proposal = get_classifier().classify(req.line)
    return {"line": req.line, "cache_match": None, "ai": proposal}


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
    return {
        "confirmed": True,
        "mapping": {
            "id": mapping.id,
            "pattern": mapping.pattern,
            "category": mapping.category,
            "confirmed_by": mapping.confirmed_by,
            "ai_suggested": mapping.ai_suggested,
        },
        "note": "Human-in-the-loop: this mapping will now auto-match similar future lines.",
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
            proposal = classifier.classify(line)
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
    return RuleCache(db).stats()


def _load_normalized(snap: ConfigSnapshot) -> dict:
    try:
        return json.loads(snap.normalized or "{}")
    except json.JSONDecodeError:
        return {}
