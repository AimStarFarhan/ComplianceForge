"""Training Loop API.

GET  /training/queue           — unparsed lines needing review (with AI suggestions)
GET  /training/mappings       — confirmed mapping cache (L1, bounded)
GET  /training/decisions      — immutable human-decision audit log
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
Human-verified mappings are continuously added to the learning dataset
and used for periodic model updates/fine-tuning.

TRUST BOUNDARY: reviewer identity ALWAYS comes from the JWT (never from the
request body). Proposal provenance (source/confidence/model version) is
recomputed server-side at decision time. Every decision appends an immutable
ProposalRecord; corrections never rewrite history.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

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
from app.models.mapping import ProposalRecord

router = APIRouter(prefix="/training", tags=["training"])

# Retrain rate-limit buckets per reviewer (in-memory; Redis when multi-worker).
_RETRAIN_HITS: dict[str, object] = {}

# AI proposals below this confidence may only be approved with an explicit
# human review flag; otherwise they stay unresolved. Mirrors the L2 gate.
REVIEW_THRESHOLD = 0.7

# Proposal sources that count as "AI-suggested" (vs deterministic fallback).
AI_SOURCES = ("cache_exact", "trained_model", "llm_", "local_lm")


class ClassifyRequest(BaseModel):
    line: str = Field(min_length=1, max_length=500)


class ConfirmRequest(BaseModel):
    """NOTE: no confirmed_by / ai_suggested / ai_confidence fields.

    Those used to be client-supplied (forgeable). Identity now comes from the
    JWT; proposal provenance is recomputed server-side at decision time.
    Extra fields are ignored.
    """

    example_line: str = Field(min_length=1, max_length=500)
    category: str
    notes: str = ""
    vendor_hint: str = "any"


class DeviceApproval(BaseModel):
    """One explicit per-line approval. Identity = (line_number, raw_line)
    matched against the device's CURRENT unparsed set -- the proposal ID."""

    line_number: int
    raw_line: str = Field(min_length=1, max_length=500)
    category: str
    # Must be true when the server-side AI proposal for this line is
    # low-confidence; the UI sets it only for rows the reviewer touched.
    human_reviewed: bool = False


class TrainDeviceRequest(BaseModel):
    """Bulk train ONLY from explicit approvals. No 'everything not corrected'
    semantics: lines absent from `approvals` stay unresolved. `unknown`
    categories are always rejected. `dry_run` returns the review summary
    ('You are approving N lines across M patterns') without writing."""

    device_id: str
    approvals: list[DeviceApproval] = Field(default_factory=list)
    dry_run: bool = False


def _proposal_for(line: str, db: Session, vendor: str) -> dict:
    """Server-side proposal: the single source of truth at decision time."""
    return get_classifier().classify(line, db=db, vendor_hint=vendor)


def _is_ai_source(source: str) -> bool:
    return source == "cache_exact" or source.startswith("trained_model") or source.startswith("llm_") or source == "local_lm"


def _log_decision(
    db: Session,
    *,
    original_line: str,
    vendor: str,
    category: str,
    proposal: dict,
    reviewer: str,
    decision: str,
    mapping_id: int | None,
    note: str = "",
) -> ProposalRecord:
    rec = ProposalRecord(
        original_line=original_line,
        normalized_pattern=normalize_pattern(original_line),
        vendor=vendor,
        category_decided=category,
        proposal_source=proposal.get("source", ""),
        proposal_confidence=proposal.get("confidence"),
        model_version=proposal.get("model_version"),
        reviewer=reviewer,
        decision=decision,
        mapping_id=mapping_id,
        note=note,
    )
    db.add(rec)
    db.flush()
    return rec


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


@router.get("/vendors", dependencies=[Depends(verify_token)])
def trained_vendors(db: Session = Depends(get_db)):
    """Past unknown-vendor training record: one row per vendor_hint that
    CompilerAI has learned mappings for — mapping count, contributing
    devices, reviewers, last trained. Revoke per vendor below."""
    from collections import defaultdict

    from app.models.mapping import CommandMapping

    mappings = list(db.scalars(select(CommandMapping)).all())
    devices = {d.device_id: d for d in db.scalars(select(Device)).all()}
    by_vendor: dict[str, dict] = defaultdict(
        lambda: {"mappings": 0, "device_ids": set(), "reviewers": set(), "last_trained": None}
    )
    for m in mappings:
        v = by_vendor[m.vendor_hint or "any"]
        v["mappings"] += 1
        if m.last_reviewer or m.confirmed_by:
            v["reviewers"].add(m.last_reviewer or m.confirmed_by)
        if m.confirmed_at and (v["last_trained"] is None or m.confirmed_at > v["last_trained"]):
            v["last_trained"] = m.confirmed_at
    # attribute devices whose vendor matches a trained vendor_hint
    for d in devices.values():
        if d.vendor in by_vendor:
            by_vendor[d.vendor]["device_ids"].add(d.device_id)
    return {
        "ai_name": "CompilerAI",
        "vendors": [
            {
                "vendor": vendor,
                "mappings": v["mappings"],
                "device_ids": sorted(v["device_ids"]),
                "reviewers": sorted(v["reviewers"]),
                "last_trained": v["last_trained"].isoformat() if v["last_trained"] else None,
            }
            for vendor, v in sorted(by_vendor.items())
        ],
    }


@router.post("/vendors/{vendor}/revoke")
def revoke_vendor(
    vendor: str,
    reviewer: dict = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Remove a learned vendor's access: delete every confirmed mapping for
    this vendor_hint so its lines return to the Training Queue (unknown
    again). Decision history is preserved — each removal appends a `revoked`
    ProposalRecord. Use from the Training Loop "Trained vendors" panel."""
    from app.models.mapping import CommandMapping

    who = str(reviewer.get("sub", "admin"))
    rows = list(db.scalars(select(CommandMapping).where(CommandMapping.vendor_hint == vendor)).all())
    if not rows:
        raise HTTPException(404, f"No learned mappings for vendor '{vendor}'")
    for m in rows:
        _log_decision(
            db,
            original_line=m.example_line or "",
            vendor=vendor,
            category=m.category,
            proposal={
                "source": m.proposal_source or "",
                "confidence": m.proposal_confidence,
                "model_version": m.model_version,
            },
            reviewer=who,
            decision="revoked",
            mapping_id=m.id,
            note="vendor access revoked — mapping removed",
        )
        db.delete(m)
    db.commit()
    return {
        "revoked": True,
        "vendor": vendor,
        "removed_mappings": len(rows),
        "reviewer": who,
        "note": f"CompilerAI no longer recognizes '{vendor}' syntax — its lines return to the Training Queue.",
    }


@router.get("/decisions")
def list_decisions(limit: int = 100, db: Session = Depends(get_db), reviewer: dict = Depends(verify_token)):
    """Immutable human-decision audit log (newest first). Corrections appear as
    new rows; history is never rewritten. Deleting a mapping removes serving
    state only -- its decision records stay here."""
    from sqlalchemy import desc

    rows = list(
        db.scalars(select(ProposalRecord).order_by(desc(ProposalRecord.id)).limit(min(limit, 500))).all()
    )
    return {
        "decisions": [
            {
                "id": r.id,
                "original_line": r.original_line,
                "pattern": r.normalized_pattern,
                "vendor": r.vendor,
                "category": r.category_decided,
                "proposal_source": r.proposal_source,
                "proposal_confidence": r.proposal_confidence,
                "model_version": r.model_version,
                "reviewer": r.reviewer,
                "decision": r.decision,
                "mapping_id": r.mapping_id,
                "decided_at": r.decided_at.isoformat() if r.decided_at else None,
            }
            for r in rows
        ]
    }
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


@router.post("/confirm")
def confirm_mapping(
    req: ConfirmRequest,
    reviewer: dict = Depends(verify_token),
    db: Session = Depends(get_db),
):
    if req.category not in SECURITY_CATEGORIES:
        raise HTTPException(422, f"Unknown category '{req.category}'. Valid: {SECURITY_CATEGORIES}")
    if req.category == "unknown":
        raise HTTPException(
            422, "'unknown' is never accepted as a confirmed mapping — "
            "leave the line unresolved until its true category is known."
        )
    who = str(reviewer.get("sub", "admin"))
    # Server-side proposal: identity + provenance can never be forged by the client.
    proposal = _proposal_for(req.example_line, db, req.vendor_hint)
    ai_suggested = _is_ai_source(proposal.get("source", ""))
    decision = "confirmed" if proposal.get("category") == req.category else "corrected"
    mapping = RuleCache(db).confirm(
        example_line=req.example_line,
        category=req.category,
        confirmed_by=who,
        ai_suggested=ai_suggested,
        ai_confidence=proposal.get("confidence"),
        notes=req.notes,
        vendor_hint=req.vendor_hint,
        proposal_source=proposal.get("source", ""),
        proposal_confidence=proposal.get("confidence"),
        model_version=proposal.get("model_version"),
        reviewer=who,
    )
    rec = _log_decision(
        db,
        original_line=req.example_line,
        vendor=req.vendor_hint,
        category=req.category,
        proposal=proposal,
        reviewer=who,
        decision=decision,
        mapping_id=mapping.id,
        note=req.notes,
    )
    db.commit()
    # Human-verified mappings are continuously added to the learning dataset
    # and used for periodic model updates/fine-tuning.
    from app.core.trained_classifier import append_example

    dataset_appended = append_example(
        req.example_line, req.category, source=f"human-confirm:{who}"
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
        "decision_id": rec.id,
        "decision": decision,
        "proposal": {
            "source": proposal.get("source"),
            "confidence": proposal.get("confidence"),
            "model_version": proposal.get("model_version"),
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


@router.post("/train-device")
def train_device(
    req: TrainDeviceRequest,
    reviewer: dict = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Bulk train from EXPLICIT per-line approvals only.

    Each approval is matched against the device's CURRENT unparsed set
    (line_number + raw text); anything else is rejected. `unknown` categories
    are never accepted; low-confidence AI proposals require human_reviewed.
    Lines absent from `approvals` stay unresolved. dry_run=true returns the
    review summary without writing anything.
    """
    who = str(reviewer.get("sub", "admin"))
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

    unparsed = {
        (ul.get("line_number"), ul.get("text"))
        for ul in _load_normalized(snap).get("unparsed_lines", [])
        if ul.get("text")
    }
    if not req.approvals:
        raise HTTPException(422, "No approvals supplied -- lines stay unresolved until explicitly approved.")

    cache = RuleCache(db)
    from app.core.trained_classifier import append_example as _append

    validated: list[dict] = []
    errors: list[str] = []
    for ap in req.approvals:
        key = (ap.line_number, ap.raw_line)
        if key not in unparsed:
            errors.append(f"L{ap.line_number}: not in the current unparsed set -- cannot approve.")
            continue
        if ap.category not in SECURITY_CATEGORIES:
            errors.append(f"L{ap.line_number}: unknown category '{ap.category}'.")
            continue
        if ap.category == "unknown":
            errors.append(f"L{ap.line_number}: 'unknown' is never accepted -- leave unresolved.")
            continue
        proposal = _proposal_for(ap.raw_line, db, device.vendor)
        conf = proposal.get("confidence") or 0.0
        if conf < REVIEW_THRESHOLD and not ap.human_reviewed:
            errors.append(
                f"L{ap.line_number}: low-confidence proposal ({proposal.get('source')}, "
                f"{conf}) requires human_reviewed=true."
            )
            continue
        validated.append({"approval": ap, "proposal": proposal})
    if errors:
        raise HTTPException(422, {"message": "Approvals rejected; nothing was written.", "errors": errors})

    patterns = {normalize_pattern(v["approval"].raw_line) for v in validated}
    per_category: dict[str, int] = {}
    for v in validated:
        per_category[v["approval"].category] = per_category.get(v["approval"].category, 0) + 1
    approved_keys = {(v["approval"].line_number, v["approval"].raw_line) for v in validated}
    unresolved = sorted(
        {"line_number": n, "raw_line": t} for (n, t) in unparsed if (n, t) not in approved_keys
    )
    summary = {
        "device_id": req.device_id,
        "reviewer": who,
        "approved_lines": len(validated),
        "patterns_covered": len(patterns),
        "per_category": per_category,
        "unresolved_remaining": len(unresolved),
        "unresolved": unresolved[:50],
        "headline": (
            f"You are approving {len(validated)} lines across {len(patterns)} "
            f"normalized patterns; {len(unresolved)} lines remain unresolved."
        ),
    }
    if req.dry_run:
        return {"dry_run": True, **summary}

    trained = 0
    for v in validated:
        ap, proposal = v["approval"], v["proposal"]
        ai_suggested = _is_ai_source(proposal.get("source", ""))
        mapping = cache.confirm(
            example_line=ap.raw_line,
            category=ap.category,
            confirmed_by=who,
            ai_suggested=ai_suggested,
            ai_confidence=proposal.get("confidence"),
            vendor_hint=device.vendor,
            notes="bulk train-device (explicit approval)",
            proposal_source=proposal.get("source", ""),
            proposal_confidence=proposal.get("confidence"),
            model_version=proposal.get("model_version"),
            reviewer=who,
        )
        decision = "confirmed" if proposal.get("category") == ap.category else "corrected"
        _log_decision(
            db,
            original_line=ap.raw_line,
            vendor=device.vendor,
            category=ap.category,
            proposal=proposal,
            reviewer=who,
            decision=f"bulk-{decision}",
            mapping_id=mapping.id,
            note="train-device explicit approval",
        )
        _append(ap.raw_line, ap.category, source=f"train-device:{who}")
        trained += 1
    db.commit()
    return {
        "device_id": req.device_id,
        "trained_lines": trained,
        "learned": trained > 0,
        **summary,
        "note": "Approved lines are now known. Re-ingest the same file (or re-run the audit) -- approved patterns auto-recognize and full rule checks apply. Unresolved lines stay queued.",
    }


@router.get("/stats", dependencies=[Depends(verify_token)])
def training_stats(db: Session = Depends(get_db)):
    from app.core.trained_classifier import dataset_size, get_model_info

    stats = RuleCache(db).stats()
    info = get_model_info()
    stats.update(
        {
            "ai_name": "CompilerAI",
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


@router.post("/model/retrain")
def model_retrain(reviewer: dict = Depends(verify_token)):
    """Periodic update job: train a CANDIDATE (current_version untouched),
    score it against the incumbent on the immutable holdout, and promote
    atomically only if the overall + per-category gates pass.

    Rate-limited (expensive + privileged). A rejected candidate never becomes
    the active model, even briefly.
    """
    import time
    from collections import deque

    from app.core.trained_classifier import promote_candidate, train_and_save

    now = time.monotonic()
    bucket = _RETRAIN_HITS.setdefault(str(reviewer.get("sub", "?")), deque())
    while bucket and bucket[0] <= now - 600:
        bucket.popleft()
    if len(bucket) >= 5:
        raise HTTPException(429, "Retrain rate limit: max 5 per 10 minutes.")
    bucket.append(now)

    entry = train_and_save()
    verdict = promote_candidate(entry["version"])
    return {
        "candidate": entry,
        **verdict,
        "note": "Candidates train isolated from serving; promotion is one atomic metadata write after holdout gating.",
    }


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
