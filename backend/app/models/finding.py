"""ORM model: audit results per (snapshot, rule)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.device import utcnow


class AuditRun(Base):
    __tablename__ = "audit_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_fk: Mapped[int] = mapped_column(ForeignKey("config_snapshots.id"), index=True)
    device_fk: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    total_rules: Mapped[int] = mapped_column(Integer, default=0)
    pass_count: Mapped[int] = mapped_column(Integer, default=0)
    fail_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    compliance_pct: Mapped[float] = mapped_column(Float, default=0.0)
    unparsed_count: Mapped[int] = mapped_column(Integer, default=0)
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_fk: Mapped[int] = mapped_column(ForeignKey("audit_runs.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(64))
    rule_title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16))  # pass | fail | error | not_applicable
    evidence: Mapped[str] = mapped_column(Text, default="")
    maps_to: Mapped[str] = mapped_column(Text, default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(32), default="built_in")  # built_in | ai_suggested_human_confirmed
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)

    run: Mapped[AuditRun] = relationship(back_populates="findings")
