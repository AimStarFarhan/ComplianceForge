"""L2 trained-model tests: smoke + retrain promote/rollback gate.

Run: pytest tests/test_model.py -q
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault("CF_DB_PATH", str(Path(__file__).parent / "test_cf.db"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app.core import trained_classifier as tc  # noqa: E402
from app.main import app  # noqa: E402


def test_model_smoke():
    info = tc.get_model_info()
    assert info["model_version"] >= 1, "model v1 artifact must exist (run scripts/train_model.py)"
    assert info["n_examples"] >= 1000, f"dataset too small: {info['n_examples']}"
    assert info["accuracy"] is not None and info["accuracy"] >= 0.7, f"accuracy too low: {info['accuracy']}"
    assert info["size_bytes"] > 0
    # fixed-size proof: artifact is KB-scale, not rows-scale
    assert info["size_bytes"] < 10 * 1024 * 1024

    # swappable interface: known lines classify with confidence
    cat, conf = tc.predict("snmp-server community S3cr3tStr1ng RO")
    assert cat == "snmp_management", f"expected snmp_management, got {cat}"
    assert conf >= 0.5
    cat2, _ = tc.predict("ntp server 10.10.1.1 prefer")
    assert cat2 == "ntp", f"expected ntp, got {cat2}"
    # empty / unknown-safe
    cat3, conf3 = tc.predict("")
    assert cat3 == "unknown" and conf3 == 0.0


def test_retrain_promote_rollback_gate():
    with TestClient(app) as c:
        r = c.post("/login", json={"username": "admin", "password": "admin"})
        assert r.status_code == 200
        h = {"Authorization": f"Bearer {r.json()['token']}"}

        before = c.get("/training/model/info", headers=h).json()
        v0 = before["model_version"]
        assert v0 >= 1

        # retrain on the same dataset: accuracy should be within gate -> promote
        r = c.post("/training/model/retrain", headers=h)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "promoted" in body
        after = c.get("/training/model/info", headers=h).json()
        if body["promoted"]:
            assert after["model_version"] == v0 + 1
            # rollback restores
            r = c.post(f"/training/model/rollback/{v0}", headers=h)
            assert r.status_code == 200, r.text
            rolled = c.get("/training/model/info", headers=h).json()
            assert rolled["model_version"] == v0
            # re-promote forward so the DB ends on latest
            r = c.post(f"/training/model/rollback/{v0 + 1}", headers=h)
            assert r.status_code == 200
        else:
            # gate rejected: version unchanged
            assert after["model_version"] == v0

        # export returns JSONL {text,label}
        r = c.get("/training/dataset/export", headers=h)
        assert r.status_code == 200
        first = r.text.splitlines()[0]
        obj = json.loads(first)
        assert "text" in obj and "label" in obj

        # stats carry model proof for the dashboard header
        r = c.get("/training/stats", headers=h)
        s = r.json()
        assert s["dataset_size"] >= 1000
        assert s["model_version"] >= 1
        assert s["model_accuracy"] is not None

        # health carries the same proof
        r = c.get("/health")
        assert r.status_code == 200
        health = r.json()
        assert health["dataset_size"] >= 1000
        assert health["model_version"] >= 1
