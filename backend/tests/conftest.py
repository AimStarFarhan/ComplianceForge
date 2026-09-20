"""Shared test bootstrap: dev-default credentials + throwaway DB path.

auth.py refuses to import without CF_ADMIN_PASSWORD / CF_JWT_SECRET unless
CF_DEV_ALLOW_DEFAULTS=1. Tests run with dev defaults on an isolated DB.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("CF_DEV_ALLOW_DEFAULTS", "1")
os.environ.setdefault("CF_DB_PATH", str(Path(__file__).parent / "test_cf.db"))
sys.path.insert(0, str(Path(__file__).parent.parent))


def prune_model_versions_after(version: int) -> None:
    """Delete candidate artifacts minted by retrain tests above `version`.

    Retrain/promotion tests must prove gating without littering the repo with
    a new model_vN.pkl on every run. Call in a finally block.
    """
    import json

    from app.core.trained_classifier import METADATA_PATH, MODEL_DIR

    meta = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    keep = [v for v in meta["versions"] if v.get("version", 0) <= version]
    drop = [v for v in meta["versions"] if v.get("version", 0) > version]
    for v in drop:
        pkl = MODEL_DIR / v.get("model_file", "")
        try:
            if pkl.exists() and pkl.name.startswith("model_v"):
                pkl.unlink()
        except OSError:
            pass
    meta["versions"] = keep
    METADATA_PATH.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    from app.core import trained_classifier as tc

    tc._cache.clear()

