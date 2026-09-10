"""One-off: verify Supabase Postgres via the app's own db layer."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import inspect

from app.db import Base, engine, init_db

init_db()
tables = sorted(inspect(engine).get_table_names())
print("TABLES:", tables)
assert {"devices", "config_snapshots", "audit_runs", "findings", "command_mappings"} <= set(tables)
print("ALL APP TABLES PRESENT — Supabase ready")
