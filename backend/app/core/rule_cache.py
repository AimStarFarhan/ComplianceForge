"""Rule cache (L1): persistent confirmed command->category mappings.

The LEARNING in ComplianceForge is NOT this cache alone:
  Human-verified mappings are continuously added to the learning dataset
  and used for periodic model updates/fine-tuning.

This cache is L1 of a 3-layer chain (see ai_classifier.classify):
  L1 exact cache (this file, BOUNDED + high-precision only)
  L2 trained model (sklearn TF-IDF + LogisticRegression, fixed-size file)
  L3 fallback (LLM few-shot / offline heuristic, true zero-shot only)

Trust properties (hardened):
  - VENDOR ISOLATION: a mapping confirmed under one vendor NEVER classifies
    another vendor's lines. find_by_pattern returns None instead of falling
    back to a cross-vendor row.
  - NO TRUNCATION: patterns are full-length (Text column). Truncating at N
    chars merges distinct long lines sharing a prefix into one identity.
  - VALUES PRESERVED: the normalized pattern still templates values out (that
    is what keeps storage bounded), but security-meaningful values are
    extracted per command family into typed slots (COMMAND_TEMPLATES) stored
    on the mapping + returned on every match, with secrets redacted. A match
    whose values drift from the confirmed example reports value_drift so the
    queue and inference can surface it instead of silently agreeing.
  - Bounded: MAX_MAPPINGS caps rows so storage is O(1).
"""

from __future__ import annotations

import difflib
import json
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.mapping import CommandMapping

# tokens that look like variable values -> replaced with <N>/<V> placeholders
# for MATCHING. The raw values are NOT destroyed: example_line keeps the full
# text and extract_slots() captures typed values per command family below.
_NUM_RE = re.compile(r"\b\d{1,5}\b")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX_RE = re.compile(r"\b[0-9A-Fa-f]{8,}\b")
_QUOTED_RE = re.compile(r'"[^"]*"')


def normalize_pattern(line: str) -> str:
    """Template out variable values so similar lines collapse to one pattern.

    Full-length: never truncated (truncation merges distinct long lines).
    """
    p = line.strip()
    p = _QUOTED_RE.sub('"<V>"', p)
    p = _IP_RE.sub("<IP>", p)
    p = _HEX_RE.sub("<HASH>", p)
    p = _NUM_RE.sub("<N>", p)
    p = re.sub(r"\s+", " ", p)
    return p.lower()


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


AUTO_MATCH_THRESHOLD = 0.82  # proposals only — never auto-recognizes (see suggest_similar)

# L1 is bounded: storage O(MAX) not O(unknowns). The trained model file
# (L2) is the fixed-size learner; this cache holds only high-precision
# exact-pattern shortcuts.
MAX_MAPPINGS = 2000

# Per-command value templates: (family, regex, {slot_name: group_name}).
# Values that change security meaning (ssh version, min-length, server IPs)
# are captured here as typed slots; secrets (community strings, passwords)
# are REDACTED, never stored verbatim.
COMMAND_TEMPLATES: list[tuple[str, str, dict[str, str]]] = [
    ("ssh_version", r"ssh[^\n]*?version\s*(?P<v>[12])\b", {"ssh_version": "v"}),
    ("ssh_timeout", r"(?:ssh|secure-shell)[^\n]*?time-?out\s*(?P<v>\d+)", {"ssh_timeout": "v"}),
    ("password_min_length", r"min(?:imum)?[-\s]?length\s*(?P<v>\d+)", {"min_length": "v"}),
    ("snmp_community", r"snmp[^\n]*?community\s+(?P<v>\S+)", {"community": "v"}),
    ("syslog_host", r"(?:logging|syslog)[^\n]*?host\s+(?P<v>\S+)", {"syslog_host": "v"}),
    ("ntp_server", r"ntp[^\n]*?server\s+(?P<v>\S+)", {"ntp_server": "v"}),
    ("login_lockout", r"(?:block-for|lockout|tries-before-disconnect)\s*(?P<v>\d+)", {"lockout_value": "v"}),
    ("aaa_server", r"(?:tacacs|radius|tacplus)[^\n]*?(?:host|server)\s+(?P<v>\S+)", {"aaa_server": "v"}),
]

_DEFAULT_COMMUNITIES = {"public", "private"}

_INT_SLOTS = {"ssh_version", "ssh_timeout", "min_length", "lockout_value"}


def extract_slots(line: str) -> dict:
    """Typed security-meaningful values for a raw CLI line (secrets redacted)."""
    slots: dict = {}
    for _family, regex, mapping in COMMAND_TEMPLATES:
        m = re.search(regex, line, re.I)
        if not m:
            continue
        for slot, group in mapping.items():
            try:
                raw = m.group(group)
            except IndexError:
                continue
            if raw is None:
                continue
            if slot == "community":
                slots[slot] = "REDACTED"
                slots["community_is_default"] = raw.strip('"').lower() in _DEFAULT_COMMUNITIES
                continue
            if slot in _INT_SLOTS:
                try:
                    slots[slot] = int(raw)
                except ValueError:
                    slots[slot] = raw
            else:
                slots[slot] = raw.strip('"')[:64]
    return slots


def slots_drift(stored: dict, current: dict) -> dict:
    """Slots present in both but with different values (stored -> current)."""
    drift = {}
    for key, old in stored.items():
        if key in current and current[key] != old:
            drift[key] = [old, current[key]]
    return drift


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
        # server-derived provenance (routes pass these; never from clients)
        proposal_source: str = "",
        proposal_confidence: float | None = None,
        model_version: int | None = None,
        reviewer: str = "",
    ) -> CommandMapping:
        pattern = normalize_pattern(example_line)
        slots = extract_slots(example_line)
        existing = self.find_by_pattern(pattern, vendor_hint)
        if existing:
            existing.category = category
            existing.confirmed_by = reviewer or confirmed_by
            existing.ai_suggested = ai_suggested
            existing.ai_confidence = ai_confidence
            existing.example_line = example_line
            existing.notes = notes
            existing.slots_json = json.dumps(slots)
            if proposal_source:
                existing.proposal_source = proposal_source
            if proposal_confidence is not None:
                existing.proposal_confidence = proposal_confidence
            if model_version is not None:
                existing.model_version = model_version
            if reviewer:
                existing.last_reviewer = reviewer
            existing.confirmed_at = datetime.now(timezone.utc)
            self.db.commit()
            return existing
        mapping = CommandMapping(
            pattern=pattern,
            example_line=example_line,
            category=category,
            vendor_hint=vendor_hint,
            confirmed_by=reviewer or confirmed_by,
            ai_suggested=ai_suggested,
            ai_confidence=ai_confidence,
            proposal_source=proposal_source,
            proposal_confidence=proposal_confidence,
            model_version=model_version,
            last_reviewer=reviewer,
            slots_json=json.dumps(slots),
            notes=notes,
        )
        self.db.add(mapping)
        self.db.flush()
        self._enforce_bound()
        self.db.commit()
        self.db.refresh(mapping)
        return mapping

    def _enforce_bound(self) -> None:
        """Evict least-used oldest rows while over cap (keeps storage O(1))."""
        from app.models.mapping import CommandMapping as _CM

        total = self.db.query(_CM).count()
        overflow = total - MAX_MAPPINGS
        if overflow <= 0:
            return
        victims = (
            self.db.query(_CM)
            .order_by(_CM.times_matched.asc(), _CM.confirmed_at.asc())
            .limit(overflow)
            .all()
        )
        for v in victims:
            self.db.delete(v)

    def delete(self, mapping_id: int) -> bool:
        obj = self.db.get(CommandMapping, mapping_id)
        if obj is None:
            return False
        self.db.delete(obj)
        self.db.commit()
        return True

    # ------------------------------------------------------------- matching
    def find_by_pattern(self, pattern: str, vendor_hint: str = "any") -> CommandMapping | None:
        """Strict vendor isolation: only a vendor-compatible row may match.

        Returns None when no mapping exists for this vendor -- NEVER falls back
        to another vendor's row. A Cisco-confirmed pattern must not classify
        Juniper input (cross-vendor leakage caused false PASS findings).
        """
        stmt = select(CommandMapping).where(CommandMapping.pattern == pattern)
        rows = list(self.db.scalars(stmt).all())
        for row in rows:
            if row.vendor_hint in ("any", vendor_hint):
                return row
        return None

    def match(self, line: str, vendor_hint: str = "any") -> dict | None:
        """L1 auto-match: EXACT normalized-pattern only (confidence 1.0).

        High-precision by design: a wrong human confirm affects exactly its
        own pattern, never a fuzzy neighborhood. Similar-line proposals are
        available via suggest_similar() but always require human confirm.

        The hit carries typed value slots for the CURRENT line plus any drift
        from the confirmed example, so downstream inference uses real values
        instead of silently agreeing on a templated shape.
        """
        pattern = normalize_pattern(line)
        exact = self.find_by_pattern(pattern, vendor_hint)
        if exact:
            exact.times_matched += 1
            exact.last_matched_at = datetime.now(timezone.utc)
            self.db.commit()
            try:
                stored_slots = json.loads(exact.slots_json or "{}")
            except (json.JSONDecodeError, TypeError):
                stored_slots = {}
            current_slots = extract_slots(line)
            drift = slots_drift(stored_slots, current_slots)
            return {
                "category": exact.category,
                "confidence": 1.0,
                "match_type": "pattern_exact",
                "mapping_id": exact.id,
                "confirmed_by": exact.confirmed_by,
                "ai_suggested": exact.ai_suggested,
                "reviewer": exact.last_reviewer or exact.confirmed_by,
                "proposal_source": exact.proposal_source,
                "proposal_confidence": exact.proposal_confidence,
                "model_version": exact.model_version,
                "decided_at": exact.confirmed_at.isoformat() if exact.confirmed_at else None,
                "slots": current_slots,
                "mapping_slots": stored_slots,
                "value_drift": bool(drift),
                "drift_details": drift,
            }
        return None

    def suggest_similar(self, line: str, vendor_hint: str = "any") -> dict | None:
        """Fuzzy proposal (NOT auto-match): best pattern with similarity
        >= AUTO_MATCH_THRESHOLD, returned for human review only."""
        pattern = normalize_pattern(line)
        best = None
        best_score = 0.0
        for mp in self.all_mappings():
            if mp.vendor_hint not in ("any", vendor_hint):
                continue
            score = similarity(pattern, mp.pattern)
            if score > best_score:
                best, best_score = mp, score
        if best and best_score >= AUTO_MATCH_THRESHOLD:
            # NOTE: no times_matched increment — a proposal is not a match.
            return {
                "category": best.category,
                "confidence": round(best_score, 3),
                "match_type": "similarity_proposal",
                "mapping_id": best.id,
                "confirmed_by": best.confirmed_by,
                "ai_suggested": best.ai_suggested,
            }
        return None

    def stats(self) -> dict:
        mappings = self.all_mappings()
        return {
            "total_mappings": len(mappings),
            "max_mappings": MAX_MAPPINGS,
            "bounded": True,
            "ai_confirmed": sum(1 for m in mappings if m.ai_suggested),
            "total_matches": sum(m.times_matched for m in mappings),
        }
