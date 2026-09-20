"""Database session setup.

Local dev: SQLite file (zero-config).
Vercel/serverless: SQLite in /tmp is EPHEMERAL — the filesystem resets
between cold starts and separate function instances do NOT share /tmp, so
audit history disappears and dashboards vary per instance. For real
persistence on Vercel, set CF_DATABASE_URL to a hosted Postgres (Neon free
tier works); the engine switches automatically.
"""

from __future__ import annotations

import os
import tempfile

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

_POSTGRES_SCHEMES = ("postgres://", "postgresql://")


def _normalize_postgres_url(url: str) -> str:
    """Map any postgres:// URL onto SQLAlchemy's psycopg3 dialect."""
    if url.startswith("postgresql+"):
        return url  # already explicit
    for scheme in _POSTGRES_SCHEMES:
        if url.startswith(scheme):
            return "postgresql+psycopg://" + url[len(scheme):]
    return url


def _sqlite_path() -> str:
    if os.environ.get("VERCEL") or os.environ.get("CF_SERVERLESS"):
        return os.path.join(tempfile.gettempdir(), "complianceforge.db")
    return os.environ.get(
        "CF_DB_PATH",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "complianceforge.db"),
    )


def _build_engine() -> Engine:
    url = os.environ.get("CF_DATABASE_URL")
    if url and url.startswith(_POSTGRES_SCHEMES):
        # Neon/managed PG: connections are killed after a few minutes idle,
        # so pre-ping + short recycle keeps serverless invocations healthy.
        return create_engine(
            _normalize_postgres_url(url),
            pool_pre_ping=True,
            pool_recycle=280,
            echo=False,
        )
    if url:  # explicit sqlite:// URL
        return create_engine(url, echo=False)
    return create_engine(
        f"sqlite:///{_sqlite_path()}",
        connect_args={"check_same_thread": False},
        echo=False,
    )


engine = _build_engine()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def _ensure_columns() -> None:
    """Lightweight additive migration for existing databases.

    create_all() never alters tables that already exist, so columns added to
    models after first deploy (slots_json, provenance_json, proposal tables
    excluded -- new tables ARE created by create_all) must be added here.
    Works on SQLite and Postgres; ignores "already exists" errors.
    """
    from sqlalchemy import text

    additions = [
        ("command_mappings", "slots_json", "TEXT"),
        ("command_mappings", "proposal_source", "VARCHAR(64)"),
        ("command_mappings", "proposal_confidence", "FLOAT"),
        ("command_mappings", "model_version", "INTEGER"),
        ("command_mappings", "last_reviewer", "VARCHAR(128)"),
        ("findings", "provenance_json", "TEXT"),
    ]
    with engine.begin() as conn:
        for table, column, ddl in additions:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
            except Exception:
                pass  # column already exists (or DB is fresh -- create_all covers it)
        # pattern was VARCHAR(255) with app-side truncation: widen on Postgres
        # (SQLite ignores VARCHAR widths, so dev DBs need nothing).
        if engine.dialect.name != "sqlite":
            try:
                conn.execute(text("ALTER TABLE command_mappings ALTER COLUMN pattern TYPE TEXT"))
            except Exception:
                pass


def init_db() -> None:
    """Import models so tables register, then create-all (idempotent)."""
    from app.models import device, finding, mapping  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_columns()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
