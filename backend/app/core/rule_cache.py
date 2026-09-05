"""Rule cache: persistent confirmed command->category mappings + similarity match.

The "learning" in ComplianceForge is exactly this:
  1. AI proposes a category for an unknown line
  2. a human confirms/corrects/rejects
  3. confirmed mappings are stored as normalized patterns
  4. future lines auto-match via pattern + fuzzy similarity
     (so "set ssh timeout 30" matches an earlier "set ssh timeout 10" mapping)

We deliberately do NOT call this a trained ML classifier — it is a
human-in-the-loop adaptive mapping cache.
"""

from __future__ import annotations

import difflib
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.mapping import CommandMapping

# tokens that look like variable values -> replaced with <N>/<V> placeholders
_NUM_RE = re.compile(r"\b\d{1,5}\b")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX_RE = re.compile(r"\b[0-9A-Fa-f]{8,}\b")
_QUOTED_RE = re.compile(r'"[^"]*"')


def normalize_pattern(line: str) -> str:
    """Template out variable values so similar lines collapse to one pattern."""
    p = line.strip()
    p = _QUOTED_RE.sub('"<V>"', p)
    p = _IP_RE.sub("<IP>", p)
    p = _HEX_RE.sub("<HASH>", p)
    p = _NUM_RE.sub("<N>", p)
    p = re.sub(r"\s+", " ", p)
    return p.lower()[:250]


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


AUTO_MATCH_THRESHOLD = 0.82


class RuleCache:
    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------- confirmed
    def all_mappings(self) -> list[CommandMapping]:
        return list(self.db.scalars(select(CommandMapping).order_by(CommandMapping.confirmed_at.desc())).all())

    def confirm(
        self,
        example_line: str,
        category: str,
        confirmed_by: str = "admin",
        ai_suggested: bool = False,
        ai_confidence: float | None = None,
        notes: str = "",
        vendor_hint: str = "any",
    ) -> CommandMapping:
        pattern = normalize_pattern(example_line)
        existing = self.find_by_pattern(pattern, vendor_hint)
        if existing:
            existing.category = category
            existing.confirmed_by = confirmed_by
            existing.ai_suggested = ai_suggested
            existing.ai_confidence = ai_confidence
            existing.example_line = example_line
            existing.notes = notes
            existing.confirmed_at = datetime.now(timezone.utc)
            self.db.commit()
            return existing
        mapping = CommandMapping(
            pattern=pattern,
            example_line=example_line,
            category=category,
            vendor_hint=vendor_hint,
            confirmed_by=confirmed_by,
            ai_suggested=ai_suggested,
            ai_confidence=ai_confidence,
            notes=notes,
        )
        self.db.add(mapping)
        self.db.commit()
        self.db.refresh(mapping)
        return mapping

    def delete(self, mapping_id: int) -> bool:
        obj = self.db.get(CommandMapping, mapping_id)
        if obj is None:
            return False
        self.db.delete(obj)
        self.db.commit()
        return True

    # ------------------------------------------------------------- matching
    def find_by_pattern(self, pattern: str, vendor_hint: str = "any") -> CommandMapping | None:
        stmt = select(CommandMapping).where(CommandMapping.pattern == pattern)
        rows = list(self.db.scalars(stmt).all())
        for row in rows:
            if row.vendor_hint in ("any", vendor_hint):
                return row
        return rows[0] if rows else None

    def match(self, line: str, vendor_hint: str = "any") -> dict | None:
        """Exact pattern match first, then fuzzy above threshold."""
        pattern = normalize_pattern(line)
        exact = self.find_by_pattern(pattern, vendor_hint)
        if exact:
            exact.times_matched += 1
            exact.last_matched_at = datetime.now(timezone.utc)
            self.db.commit()
            return {
                "category": exact.category,
                "confidence": 1.0,
                "match_type": "pattern_exact",
                "mapping_id": exact.id,
                "confirmed_by": exact.confirmed_by,
                "ai_suggested": exact.ai_suggested,
            }

        mappings = self.all_mappings()
        best = None
        best_score = 0.0
        for mp in mappings:
            if mp.vendor_hint not in ("any", vendor_hint):
                continue
            score = similarity(pattern, mp.pattern)
            if score > best_score:
                best, best_score = mp, score
        if best and best_score >= AUTO_MATCH_THRESHOLD:
            best.times_matched += 1
            best.last_matched_at = datetime.now(timezone.utc)
            self.db.commit()
            return {
                "category": best.category,
                "confidence": round(best_score, 3),
                "match_type": "similarity",
                "mapping_id": best.id,
                "confirmed_by": best.confirmed_by,
                "ai_suggested": best.ai_suggested,
            }
        return None

    def stats(self) -> dict:
        mappings = self.all_mappings()
        return {
            "total_mappings": len(mappings),
            "ai_confirmed": sum(1 for m in mappings if m.ai_suggested),
            "total_matches": sum(m.times_matched for m in mappings),
        }
