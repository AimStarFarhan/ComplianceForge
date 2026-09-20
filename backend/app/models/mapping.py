"""ORM models: human-confirmed unknown-command mappings + append-only decision log.

Two tables, two jobs:
  CommandMapping — SERVING state (latest human decision per pattern; upserted).
  ProposalRecord — AUDIT state (immutable log; every confirm/correction appends,
    never overwritten). A correction changes what the cache serves but the
    original decision record stays queryable forever.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.device import utcnow


class CommandMapping(Base):
    __tablename__ = "command_mappings"
    __table_args__ = (UniqueConstraint("pattern", "vendor_hint", name="uq_pattern_vendor"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Text, NOT length-capped: truncating patterns merges distinct long lines
    # into one identity (same-prefix collision). SQLite ignores VARCHAR limits
    # anyway; Postgres needs the width -- Text is correct on both.
    pattern: Mapped[str] = mapped_column(Text, index=True)
    example_line: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(64), index=True)
    vendor_hint: Mapped[str] = mapped_column(String(32), default="any")
    confirmed_by: Mapped[str] = mapped_column(String(128), default="admin")
    ai_suggested: Mapped[bool] = mapped_column(default=False)
    ai_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    # server-derived proposal provenance (set at confirm time, never from client)
    proposal_source: Mapped[str] = mapped_column(String(64), default="")
    proposal_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    model_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_reviewer: Mapped[str] = mapped_column(String(128), default="")
    # typed per-command values extracted at confirm time (secrets redacted).
    # The normalized pattern still templates values out for bounded matching;
    # security-meaningful values live here + in example_line, never destroyed.
    slots_json: Mapped[str] = mapped_column(Text, default="{}")
    times_matched: Mapped[int] = mapped_column(Integer, default=0)
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    notes: Mapped[str] = mapped_column(Text, default="")


class ProposalRecord(Base):
    """Immutable log of every human mapping decision (confirm + bulk-train).

    Append-only: corrections insert a NEW row pointing at the same pattern;
    no endpoint updates or deletes these rows.
    """

    __tablename__ = "proposal_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    original_line: Mapped[str] = mapped_column(Text, default="")
    normalized_pattern: Mapped[str] = mapped_column(Text, default="", index=True)
    vendor: Mapped[str] = mapped_column(String(32), default="any")
    category_decided: Mapped[str] = mapped_column(String(64), index=True)
    proposal_source: Mapped[str] = mapped_column(String(64), default="")
    proposal_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    model_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reviewer: Mapped[str] = mapped_column(String(128), default="", index=True)
    # confirmed | corrected (differed from proposal) | bulk-approved
    decision: Mapped[str] = mapped_column(String(32), default="confirmed")
    mapping_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
