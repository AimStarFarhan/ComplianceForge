"""Trust tests: the learning loop must be Causally Honest.

Proves (against the ChatGPT audit findings list):
- Cisco mappings cannot classify Juniper input (vendor isolation).
- Long lines sharing a prefix do not collide (no truncation).
- Security-meaningful values are captured per command (slots), secrets redacted,
  value drift reported.
- Forged confirmed_by / ai_* body fields are ignored; identity comes from JWT.
- Corrections are append-only (decision log grows, serving shows latest).
- Bulk training accepts ONLY explicit approvals: unparsed-only, never unknown,
  low-confidence requires human_reviewed; dry_run writes nothing.
- A rejected candidate never becomes the active model, even briefly.
- Every AI-derived finding carries immutable human-review provenance;
  AI-derived audits are flagged provisional.
- Default credentials are rejected outside development (subprocess).
- Pickle artifacts fail closed on hash mismatch.
- OpenAI credentials dispatch to OpenAI, never Anthropic.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from fastapi.testclient import TestClient

from app.main import app

LONG_A = "set policy rule description " + "word " * 60 + "tail-ALPHA"
LONG_B = "set policy rule description " + "word " * 60 + "tail-BRAVO"

def _mini_unseen(tag: int) -> str:
    # unique raw values per test: the queue dedupes identical raw lines
    # across devices, so each test needs its own values (same patterns)
    ssh_v = 2 if tag % 2 == 0 else 1
    return (
        f"set admin-sport {400 + tag}\n"
        f"set ssh-version {ssh_v} max-sessions {tag}\n"
        f"set admin-telnet-port {20 + tag}\n"
        f"set admin-password-min-length {10 + tag}\n"
    )


def _mini_cats(tag: int) -> dict[str, str]:
    ssh_v = 2 if tag % 2 == 0 else 1
    return {
        f"set admin-sport {400 + tag}": "management_protocol",
        f"set ssh-version {ssh_v} max-sessions {tag}": "ssh_policy",
        f"set admin-telnet-port {20 + tag}": "management_protocol",
        f"set admin-password-min-length {10 + tag}": "password_policy",
    }


@pytest.fixture(autouse=True)
def _isolated_dataset(tmp_path, monkeypatch, request):
    # API tests must not append probe rows to the real learning dataset.
    # (The promotion test trains on the real dataset but never appends, so
    # it keeps the real path -- matched by test name.)
    if "never_serves" in request.node.name:
        return
    import app.core.trained_classifier as tc
    fake = tmp_path / "dataset.jsonl"
    fake.write_text("", encoding="utf-8")
    monkeypatch.setattr(tc, "DATASET_PATH", fake)


@pytest.fixture(scope="module")
def auth():
    # clean slate: the shared test DB persists across runs, and leftover
    # trust-* devices/mappings would cover queue lines and break idempotency
    from app.db import SessionLocal
    from app.models import Device
    from app.models.mapping import CommandMapping, ProposalRecord
    db = SessionLocal()
    try:
        for d in db.query(Device).filter(Device.device_id.like("trust-%")).all():
            db.delete(d)
        for m in db.query(CommandMapping).all():
            ex = m.example_line or ""
            if "probe" in ex or ex.startswith("set admin-") or ex.startswith("set ssh-version"):
                db.delete(m)
        for r in db.query(ProposalRecord).all():
            orig = r.original_line or ""
            if "probe" in orig or orig.startswith("set admin-") or orig.startswith("set ssh-version"):
                db.delete(r)
        db.commit()
    finally:
        db.close()
    with TestClient(app) as c:
        r = c.post("/login", json={"username": "admin", "password": "admin"})
        assert r.status_code == 200
        yield c, {"Authorization": f"Bearer {r.json()['token']}"}


def _upload(c, h, text, filename, device_id):
    r = c.post(
        "/ingest",
        files={"file": (filename, text, "text/plain")},
        data={"device_id": device_id},
        headers=h,
    )
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------ isolation

def test_vendor_isolation_no_cross_vendor_leak(auth):
    c, h = auth
    line = "set isolation-probe-vendor CISCOTEST"
    r = c.post("/training/confirm", json={
        "example_line": line, "category": "banner", "vendor_hint": "cisco_ios",
    }, headers=h)
    assert r.status_code == 200, r.text

    from app.db import SessionLocal
    from app.core.rule_cache import RuleCache
    db = SessionLocal()
    try:
        cache = RuleCache(db)
        assert cache.match(line, vendor_hint="cisco_ios") is not None
        assert cache.match(line, vendor_hint="juniper_srx") is None
        assert cache.find_by_pattern(
            __import__("app.core.rule_cache", fromlist=["normalize_pattern"]).normalize_pattern(line),
            "juniper_srx",
        ) is None
    finally:
        db.close()

    # generic ("any") queries must not surface vendor-specific rows either
    r = c.post("/training/classify", json={"line": line}, headers=h)
    assert r.status_code == 200
    assert r.json()["source"] != "cache_exact"


def test_long_lines_no_prefix_collision():
    from app.core.rule_cache import normalize_pattern
    pa, pb = normalize_pattern(LONG_A), normalize_pattern(LONG_B)
    assert len(pa) > 250 and len(pb) > 250  # would have been truncated before
    assert pa != pb


def test_slots_captured_secrets_redacted_drift_reported(auth):
    c, h = auth
    line = "set snmp community public"
    r = c.post("/training/confirm", json={
        "example_line": line, "category": "snmp_management", "vendor_hint": "any",
    }, headers=h)
    assert r.status_code == 200, r.text

    from app.db import SessionLocal
    from app.core.rule_cache import RuleCache, extract_slots
    assert extract_slots("ip ssh version 2")["ssh_version"] == 2
    slots = extract_slots(line)
    assert slots["community"] == "REDACTED"  # never stored verbatim
    assert slots["community_is_default"] is True

    db = SessionLocal()
    try:
        # exact-pattern match on a templated VALUE difference reports drift:
        # confirm with timeout 90, match timeout 120 -> same pattern, drift
        c.post("/training/confirm", json={
            "example_line": "ip ssh time-out 90", "category": "ssh_policy",
            "vendor_hint": "any",
        }, headers=h)
        hit = RuleCache(db).match("ip ssh time-out 120", vendor_hint="any")
        assert hit is not None
        assert hit["slots"].get("ssh_timeout") == 120
        assert hit["mapping_slots"].get("ssh_timeout") == 90
        assert hit["value_drift"] is True
        assert hit["drift_details"]["ssh_timeout"] == [90, 120]
    finally:
        db.close()


# ------------------------------------------------------------------ auditability

def test_forged_confirmed_by_ignored(auth):
    c, h = auth
    line = "set forgery-probe banner motd"
    r = c.post("/training/confirm", json={
        "example_line": line,
        "category": "banner",
        "confirmed_by": "mallory",  # forged: must be ignored
        "ai_suggested": False,
        "ai_confidence": 0.99,
        "vendor_hint": "any",
    }, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mapping"]["confirmed_by"] == "admin"

    r = c.get("/training/decisions?limit=5", headers=h)
    assert r.status_code == 200
    rec = next(d for d in r.json()["decisions"] if d["original_line"] == line)
    assert rec["reviewer"] == "admin"
    assert "mallory" not in json.dumps(rec)


def test_corrections_append_only(auth):
    c, h = auth
    line = "set append-only-probe timeout 30"
    for cat in ("ssh_policy", "management_protocol"):
        r = c.post("/training/confirm", json={
            "example_line": line, "category": cat, "vendor_hint": "any",
        }, headers=h)
        assert r.status_code == 200, r.text
    r = c.get("/training/decisions?limit=500", headers=h)
    recs = [d for d in r.json()["decisions"] if d["original_line"] == line]
    assert len(recs) >= 2  # original decision record preserved, correction appended
    assert {d["category"] for d in recs} >= {"ssh_policy", "management_protocol"}
    # serving state reflects the latest decision
    r = c.post("/training/classify", json={"line": line}, headers=h)
    assert r.json()["source"] == "cache_exact"
    assert r.json()["cache_match"]["category"] == "management_protocol"


# ------------------------------------------------------------------ bulk training

def _ingest_queue(c, h, device_id, tag):
    info = _upload(c, h, _mini_unseen(tag), "mini.cfg", device_id)
    assert info["is_unknown_vendor"] is True
    q = c.get("/training/queue", headers=h).json()
    mine = [e for e in q["queue"] if e["device_id"] == device_id]
    assert len(mine) == 4
    return mine


def test_bulk_rejects_empty_unknown_foreign_lowconf(auth):
    c, h = auth
    _ingest_queue(c, h, "trust-bulk-neg", 11)

    r = c.post("/training/train-device", json={"device_id": "trust-bulk-neg", "approvals": []}, headers=h)
    assert r.status_code == 422

    mine = [e for e in c.get("/training/queue", headers=h).json()["queue"] if e["device_id"] == "trust-bulk-neg"]
    first = mine[0]
    # unknown category never accepted
    r = c.post("/training/train-device", json={"device_id": "trust-bulk-neg", "approvals": [{
        "line_number": first["line_number"], "raw_line": first["raw_line"],
        "category": "unknown", "human_reviewed": True}]}, headers=h)
    assert r.status_code == 422
    # line outside the unparsed set cannot be approved
    r = c.post("/training/train-device", json={"device_id": "trust-bulk-neg", "approvals": [{
        "line_number": 999, "raw_line": "no such line anywhere",
        "category": "banner", "human_reviewed": True}]}, headers=h)
    assert r.status_code == 422
    # low-confidence proposal without human_reviewed stays unresolved
    low = next(e for e in mine if (e["ai_confidence"] or 0) < 0.7)
    r = c.post("/training/train-device", json={"device_id": "trust-bulk-neg", "approvals": [{
        "line_number": low["line_number"], "raw_line": low["raw_line"],
        "category": _mini_cats(11)[low["raw_line"]]}]}, headers=h)
    assert r.status_code == 422


def test_bulk_dry_run_writes_nothing(auth):
    c, h = auth
    mine = _ingest_queue(c, h, "trust-bulk-dry", 22)
    before_m = c.get("/training/mappings", headers=h).json()["mappings"]
    before_d = c.get("/training/decisions?limit=500", headers=h).json()["decisions"]
    approvals = [{
        "line_number": e["line_number"], "raw_line": e["raw_line"],
        "category": _mini_cats(22)[e["raw_line"]], "human_reviewed": True} for e in mine]
    r = c.post("/training/train-device",
               json={"device_id": "trust-bulk-dry", "approvals": approvals, "dry_run": True},
               headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dry_run"] is True
    assert body["approved_lines"] == 4
    assert "patterns" in body["headline"] and "unresolved" in body["headline"]
    assert c.get("/training/mappings", headers=h).json()["mappings"] == before_m
    assert c.get("/training/decisions?limit=500", headers=h).json()["decisions"] == before_d


def test_bulk_happy_path_then_provenance_and_provisional(auth):
    c, h = auth
    mine = _ingest_queue(c, h, "trust-bulk-e2e", 33)
    approvals = [{
        "line_number": e["line_number"], "raw_line": e["raw_line"],
        "category": _mini_cats(33)[e["raw_line"]], "human_reviewed": True} for e in mine]
    r = c.post("/training/train-device",
               json={"device_id": "trust-bulk-e2e", "approvals": approvals},
               headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["trained_lines"] == 4

    # re-ingest: approved patterns auto-recognize under the same vendor
    info = _upload(c, h, _mini_unseen(33), "mini.cfg", "trust-bulk-e2e")
    assert info["recognized_count"] == 4
    assert info["fully_recognized"] is True

    # audit: every AI-derived finding carries immutable review provenance;
    # the result is flagged provisional, never full-confidence
    r = c.post("/audit/trust-bulk-e2e", headers=h)
    assert r.status_code == 200, r.text
    audit = r.json()
    assert audit["provisional"] is True
    ai_findings = [f for f in audit["findings"] if f.get("source") == "ai_suggested_human_confirmed"]
    assert ai_findings, "expected AI-derived findings on a learned vendor"
    for f in ai_findings:
        prov = f.get("provenance") or {}
        assert prov.get("mappings"), f"finding {f.get('rule_id')} lacks provenance"
        for m in prov["mappings"]:
            assert m["mapping_id"] and m["reviewer"] == "admin"
    assert "confidence_note" in audit["summary"]


# ------------------------------------------------------------------ promotion

def test_rejected_candidate_never_serves():
    from app.core import trained_classifier as tc
    v0 = tc.get_model_info()["model_version"]
    max_pre = max(tc.get_model_info().get("available_versions", [v0]))
    served_before, _ = tc.predict("ntp server 10.10.1.1 prefer")
    try:
        entry = tc.train_and_save()  # candidate only: serving untouched
        assert tc.get_model_info()["model_version"] == v0
        verdict = tc.promote_candidate(entry["version"])
        assert "promoted" in verdict
        after = tc.get_model_info()["model_version"]
        if verdict["promoted"]:
            assert after == entry["version"]
            tc.set_current_version(v0)  # restore incumbent for other tests
        else:
            assert after == v0
            served_after, _ = tc.predict("ntp server 10.10.1.1 prefer")
            assert served_after == served_before
        assert tc.get_model_info()["model_version"] == v0
    finally:
        from conftest import prune_model_versions_after
        prune_model_versions_after(max_pre)


def test_pickle_tamper_fails_closed():
    import json as _json
    from app.core.trained_classifier import _verify_sha256, MODEL_DIR, METADATA_PATH
    meta = _json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    assert all(v.get("sha256") for v in meta["versions"]), "every artifact must record sha256"
    v4 = next(v for v in meta["versions"] if v["version"] == meta["current_version"])
    _verify_sha256(MODEL_DIR / v4["model_file"], v4["sha256"])  # genuine: passes
    try:
        _verify_sha256(MODEL_DIR / v4["model_file"], "0" * 64)
        raise AssertionError("tampered hash must raise")
    except ValueError:
        pass


# ------------------------------------------------------------------ provider + boot

def test_openai_credentials_dispatch_to_openai(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-fake")
    monkeypatch.delenv("CF_USE_LOCAL_LM", raising=False)
    from app.core.ai_classifier import AIClassifier
    clf = AIClassifier()
    assert clf.provider == "openai"
    monkeypatch.setattr(clf, "_classify_anthropic",
                        lambda line: (_ for _ in ()).throw(AssertionError("must not call Anthropic")))
    monkeypatch.setattr(clf, "_classify_openai",
                        lambda line: {"category": "ntp", "confidence": 0.9,
                                      "source": "llm_gpt", "model_version": None, "reason": "t"})
    # L3 dispatch (L2 may answer first on familiar lines; test the layer itself)
    out = clf._classify_l3("ntp server 1.2.3.4")
    assert out["source"] == "llm_gpt"


def test_startup_refuses_default_credentials():
    env = {k: v for k, v in os.environ.items()
           if k not in ("CF_DEV_ALLOW_DEFAULTS", "CF_ADMIN_PASSWORD", "CF_JWT_SECRET")}
    p = subprocess.run(
        [sys.executable, "-c", "import app.main"],
        cwd=str(Path(__file__).parent.parent),
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert p.returncode != 0, "must refuse to boot with default credentials"


# ------------------------------------------------- CompilerAI visibility + history + revoke

def test_compilerai_branding_in_health_chat_stats(auth):
    c, h = auth
    assert c.get("/health").json()["ai_name"] == "CompilerAI"
    st = c.get("/chat/status", headers=h).json()
    assert st["ai_name"] == "CompilerAI" and "CompilerAI" in st["label"]
    assert c.get("/training/stats", headers=h).json()["ai_name"] == "CompilerAI"
    assert c.get("/dashboard", headers=h).json()["model"]["ai_name"] == "CompilerAI"


def test_dashboard_recent_audits_lists_audited_devices(auth):
    c, h = auth
    _upload(c, h,
            "hostname hist-probe\nip ssh version 2\nline vty 0 4\n"
            "aaa new-model\nlogging host 1.2.3.4\nntp server 1.2.3.4\n",
            "hist-probe.cfg", "trust-hist")
    r = c.post("/audit/trust-hist", headers=h)
    assert r.status_code == 200, r.text
    dash = c.get("/dashboard", headers=h).json()
    assert "recent_audits" in dash
    mine = [a for a in dash["recent_audits"] if a["device_id"] == "trust-hist"]
    assert mine and mine[0]["compliance_pct"] is not None
    assert mine[0]["pass_count"] + mine[0]["fail_count"] > 0


def test_trained_vendors_record_and_revoke(auth):
    c, h = auth
    vendor = "compilerai-probe-os"
    line = "compilerai-probe enable secure-shell v2"
    r = c.post("/training/confirm", json={
        "example_line": line, "category": "ssh_policy", "vendor_hint": vendor,
    }, headers=h)
    assert r.status_code == 200, r.text
    vendors = c.get("/training/vendors", headers=h).json()
    assert vendors["ai_name"] == "CompilerAI"
    mine = [v for v in vendors["vendors"] if v["vendor"] == vendor]
    assert mine and mine[0]["mappings"] >= 1

    r = c.post(f"/training/vendors/{vendor}/revoke", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["removed_mappings"] >= 1

    vendors = c.get("/training/vendors", headers=h).json()["vendors"]
    assert not [v for v in vendors if v["vendor"] == vendor]
    # revocation is preserved in the immutable decision log
    decisions = c.get("/training/decisions?limit=500", headers=h).json()["decisions"]
    assert any(d["decision"] == "revoked" and d["vendor"] == vendor for d in decisions)
    # second revoke: nothing left to remove
    r = c.post(f"/training/vendors/{vendor}/revoke", headers=h)
    assert r.status_code == 404
