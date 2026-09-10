"""SQLite + SQLAlchemy session setup. Zero-config for hackathon scale.

Serverless note: on Vercel the filesystem is read-only except /tmp, so the
DB lives there. It resets between cold starts (demo-acceptable); for
persistence swap the engine for Postgres/Neon via CF_DATABASE_URL.
"""

from __future__ import annotations

import os
import tempfile

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

def _db_path() -> str:
    url = os.environ.get("CF_DATABASE_URL")
    if url:
        return url
    if os.environ.get("VERCEL") or os.environ.get("CF_SERVERLESS"):
        return os.path.join(tempfile.gettempdir(), "complianceforge.db")
    return os.environ.get(
        "CF_DB_PATH",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "complianceforge.db"),
    )


DB_PATH = _db_path()

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    """Import models so tables register, then create-all (idempotent)."""
    from app.models import device, finding, mapping  # noqa: F401

    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
