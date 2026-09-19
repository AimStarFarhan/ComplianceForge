"""POST /ingest — upload a raw config, detect vendor, parse, normalize, store."""

from __future__ import annotations

import json
import re
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import verify_token
from app.core.parsers import detect_vendor, get_parser, vendor_from_string
from app.core.parsers.base_parser import VENDOR_LABELS, VENDOR_UNSEEN
from app.core.rule_cache import RuleCache
from app.core.security import upload_is_safe
from app.db import get_db
from app.models import ConfigSnapshot, Device

router = APIRouter(prefix="/ingest", tags=["ingest"])

MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", s).strip("-")[:64] or "device"


@router.post("", dependencies=[Depends(verify_token)])
async def ingest_config(
    file: UploadFile = File(...),
    device_id: Optional[str] = Form(None),
    vendor: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    raw_bytes = await file.read()
    filename = file.filename or "upload.cfg"
    ok, reason = upload_is_safe(filename, len(raw_bytes))
    if not ok:
        raise HTTPException(415, reason)
    # reject embedded NUL / high binary content — configs are plain text
    if b"\x00" in raw_bytes:
        raise HTTPException(415, "Binary content detected — upload plain-text CLI configs only.")
    text = raw_bytes.decode("utf-8", errors="replace")

    detected = detect_vendor(text, filename)
    chosen_vendor = vendor_from_string(vendor) if vendor else detected
    if vendor and vendor_from_string(vendor) == VENDOR_UNSEEN:
        chosen_vendor = detected  # ignore unknown vendor strings, fall back to detection

    # device id: explicit > hostname hint > filename
    hostname_hint = None
    hm = re.search(r"^\s*hostname\s+(\S+)", text, re.MULTILINE) or re.search(
        r"^\s*set system host-name\s+(\S+)", text, re.MULTILINE
    )
    if hm:
        hostname_hint = hm.group(1)
    dev_id = device_id or hostname_hint or _slug(filename.rsplit(".", 1)[0])
    dev_id = _slug(dev_id)

    # upsert device
    device = db.scalar(select(Device).where(Device.device_id == dev_id))
    if device is None:
        device = Device(device_id=dev_id, vendor=chosen_vendor, hostname=hostname_hint)
        db.add(device)
        db.flush()
    else:
        device.vendor = chosen_vendor
        if hostname_hint:
            device.hostname = hostname_hint

    # parse + normalize
    parser = get_parser(chosen_vendor)
    if parser is None:
        # unseen vendor: store raw; every substantive line goes to unparsed for training
        from app.core.schema import DeviceInfo, RawLine, SecurityBaselineModel

        baseline = SecurityBaselineModel(
            device=DeviceInfo(device_id=dev_id, vendor=VENDOR_UNSEEN, device_type="unseen"),
            unparsed_lines=[
                RawLine(line_number=i, text=line)
                for i, line in enumerate(text.splitlines(), 1)
                if line.strip() and not line.strip().startswith("!") and not line.strip().startswith("#")
            ][:200],
        )
        device.is_unseen_vendor = True
        normalized = baseline.model_dump()
    else:
        baseline = parser.parse(text, dev_id)
        if baseline.device.hostname:
            device.hostname = baseline.device.hostname
        device.os_version = baseline.device.os_version
        device.model = baseline.device.model
        device.device_type = baseline.device.device_type
        device.is_unseen_vendor = False
        normalized = baseline.model_dump()

    snapshot = ConfigSnapshot(
        device_fk=device.id,
        filename=filename,
        raw_config=text,
        normalized=json.dumps(normalized),
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    db.refresh(device)

    # enrichment: L1 exact-cache recognition + L2/L3 suggestions.
    # Only exact human-confirmed patterns count as recognized; L2/L3
    # proposals are attached as suggestions for the Training Queue.
    from app.core.ai_classifier import get_classifier as _get_clf

    cache = RuleCache(db)
    clf = _get_clf()
    enriched_unparsed = []
    recognized_count = 0
    for ul in normalized.get("unparsed_lines", []):
        hit = cache.match(ul["text"], vendor_hint=chosen_vendor)
        if hit:
            ul["category"] = hit["category"]
            ul["suggested_category"] = hit["category"]
            ul["suggested_confidence"] = hit["confidence"]
            ul["match_type"] = hit["match_type"]
            recognized_count += 1
        else:
            try:
                proposal = clf.classify(ul["text"], db=db, vendor_hint=chosen_vendor)
            except Exception:
                proposal = None
            if proposal and proposal.get("category") not in (None, "unknown"):
                ul["suggested_category"] = proposal["category"]
                ul["suggested_confidence"] = proposal["confidence"]
                ul["suggested_source"] = proposal.get("source")
                ul["suggested_model_version"] = proposal.get("model_version")
        enriched_unparsed.append(ul)

    is_unknown = chosen_vendor == VENDOR_UNSEEN
    trainable = is_unknown and len(enriched_unparsed) > 0
    fully_recognized = is_unknown and len(enriched_unparsed) > 0 and recognized_count == len(enriched_unparsed)

    return {
        "device_id": device.device_id,
        "snapshot_id": snapshot.id,
        "vendor": chosen_vendor,
        "vendor_label": VENDOR_LABELS.get(chosen_vendor, chosen_vendor),
        "detected_vendor": detected,
        "hostname": device.hostname,
        "os_version": device.os_version,
        "model": device.model,
        "unparsed_count": len(enriched_unparsed),
        "unparsed_lines": enriched_unparsed,
        "recognized_count": recognized_count,
        "is_unknown_vendor": is_unknown,
        "trainable": trainable,
        "fully_recognized": fully_recognized,
        "next_step": (
            "recognized_unknown" if fully_recognized
            else "train" if trainable
            else "audit"
        ),
    }
