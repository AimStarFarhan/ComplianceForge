"""ORM model: human-confirmed unknown-command mappings (the learned rule cache)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.device import utcnow


class CommandMapping(Base):
    __tablename__ = "command_mappings"
    __table_args__ = (UniqueConstraint("pattern", "vendor_hint", name="uq_pattern_vendor"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    pattern: Mapped[str] = mapped_column(String(255), index=True)
    example_line: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(64), index=True)
    vendor_hint: Mapped[str] = mapped_column(String(32), default="any")
    confirmed_by: Mapped[str] = mapped_column(String(128), default="admin")
    ai_suggested: Mapped[bool] = mapped_column(default=False)
    ai_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    times_matched: Mapped[int] = mapped_column(Integer, default=0)
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    notes: Mapped[str] = mapped_column(Text, default="")
