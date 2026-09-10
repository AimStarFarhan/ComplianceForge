"""Vercel serverless entrypoint: exposes the FastAPI app as an ASGI function.

Vercel invokes this module for /api/* routes. The app's routers all live
under their own prefixes (/login, /health, /devices, ...), so we mount the
whole FastAPI app at the /api base path via RootPath.
"""

import sys
from pathlib import Path

# make `backend/` importable (api/index.py -> repo root/backend)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.main import app  # noqa: E402

# Vercel strips /api prefix before invoking; set root_path so generated
# docs/redirects stay correct
app.root_path = "/api"

handler = app
