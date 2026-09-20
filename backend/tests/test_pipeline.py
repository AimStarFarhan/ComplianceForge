"""ComplianceForge backend test suite.

Run:  pytest -q
Uses a throwaway SQLite DB per session.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("CF_DB_PATH", str(Path(__file__).parent / "test_cf.db"))

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app.core.parsers import detect_vendor, get_parser  # noqa: E402
from app.core.parsers.base_parser import (  # noqa: E402
    VENDOR_CISCO_IOS,
    VENDOR_JUNIPER_SRX,
    VENDOR_SONIC,
    VENDOR_UNSEEN,
)
from app.core.rule_engine import load_rules, run_audit, summarize  # noqa: E402
from app.core.rule_cache import normalize_pattern, similarity  # noqa: E402
from app.core.report_builder import build_pdf  # noqa: E402
from app.main import app  # noqa: E402

SAMPLES = Path(__file__).parent.parent / "sample_configs"


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def auth_headers(client):
    r = client.post("/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


# ------------------------------------------------------------------ parser tests
def test_detect_vendor_all_samples():
    cases = {
        "cisco_ios_compliant.cfg": VENDOR_CISCO_IOS,
        "cisco_ios_noncompliant.cfg": VENDOR_CISCO_IOS,
        "juniper_srx_compliant.cfg": VENDOR_JUNIPER_SRX,
        "juniper_srx_noncompliant.cfg": VENDOR_JUNIPER_SRX,
        "sonic_compliant.cfg": VENDOR_SONIC,
        "sonic_noncompliant.cfg": VENDOR_SONIC,
    }
    for fname, expected in cases.items():
        text = (SAMPLES / fname).read_text(encoding="utf-8")
        assert detect_vendor(text, fname) == expected, f"{fname} misdetected"


def test_cisco_compliant_baseline():
    text = (SAMPLES / "cisco_ios_compliant.cfg").read_text(encoding="utf-8")
    model = get_parser(VENDOR_CISCO_IOS).parse(text, "c-test")
    assert model.device.hostname == "CORE-SW-01"
    assert model.management.telnet_enabled is not True
    assert model.management.ssh_version == 2
    assert model.management.http_mgmt_enabled is False
    assert model.auth.aaa_enabled is True
    assert model.auth.password_min_length == 12
    assert model.auth.default_credentials_changed is True
    assert model.logging.remote_logging_enabled is True
    assert "public" not in model.management.snmp_communities
    assert model.management.banner_present is True
    assert model.management.ntp_configured is True
    assert model.crypto.key_modulus_bits == 2048
    assert model.management.idle_timeout_seconds == 600


def test_cisco_noncompliant_baseline():
    text = (SAMPLES / "cisco_ios_noncompliant.cfg").read_text(encoding="utf-8")
    model = get_parser(VENDOR_CISCO_IOS).parse(text, "c-bad")
    assert model.management.telnet_enabled is True
    assert model.management.http_mgmt_enabled is True
    assert model.management.ssh_version is None
    assert model.auth.default_credentials_changed is False
    assert "public" in model.management.snmp_communities
    assert model.management.cdp_enabled is True
    assert model.services.finger_enabled is not False


def test_juniper_parsing():
    text = (SAMPLES / "juniper_srx_compliant.cfg").read_text(encoding="utf-8")
    model = get_parser(VENDOR_JUNIPER_SRX).parse(text, "j-test")
    assert model.device.hostname == "SRX-FW-01"
    assert model.management.ssh_version == 2
    assert model.management.telnet_enabled is not True
    assert model.auth.password_min_length == 12
    assert model.auth.aaa_enabled is True
    assert model.logging.remote_logging_enabled is True
    assert model.management.banner_present is True

    text_bad = (SAMPLES / "juniper_srx_noncompliant.cfg").read_text(encoding="utf-8")
    bad = get_parser(VENDOR_JUNIPER_SRX).parse(text_bad, "j-bad")
    assert bad.management.telnet_enabled is True
    assert bad.management.http_mgmt_enabled is True
    assert bad.crypto.ipsec_dh_group_weak is True
    assert "public" in bad.management.snmp_communities


def test_sonic_parsing():
    text = (SAMPLES / "sonic_compliant.cfg").read_text(encoding="utf-8")
    model = get_parser(VENDOR_SONIC).parse(text, "s-test")
    assert model.device.hostname == "SPINE-01"
    assert model.management.ntp_configured is True
    assert model.logging.remote_logging_enabled is True
    assert model.auth.aaa_enabled is True
    assert "public" not in model.management.snmp_communities
    assert model.management.banner_present is True
    assert model.acl.management_acl_bound is True
    assert model.acl.default_deny is True

    text_bad = (SAMPLES / "sonic_noncompliant.cfg").read_text(encoding="utf-8")
    bad = get_parser(VENDOR_SONIC).parse(text_bad, "s-bad")
    assert bad.management.telnet_enabled is True
    assert bad.management.http_mgmt_enabled is True
    assert "public" in bad.management.snmp_communities
    assert bad.auth.aaa_enabled is not True


# ------------------------------------------------------------------ rule engine
def test_rule_packs_load():
    for vendor, minimum in [(VENDOR_CISCO_IOS, 15), (VENDOR_JUNIPER_SRX, 15), (VENDOR_SONIC, 15)]:
        rules = load_rules(vendor)
        assert len(rules) >= minimum, f"{vendor} pack has {len(rules)} rules, expected >= {minimum}"
        ids = [r.rule_id for r in rules]
        assert len(ids) == len(set(ids)), f"{vendor} has duplicate rule ids"


def test_cisco_audit_scores():
    good = get_parser(VENDOR_CISCO_IOS).parse(
        (SAMPLES / "cisco_ios_compliant.cfg").read_text(encoding="utf-8"), "c-good"
    )
    bad = get_parser(VENDOR_CISCO_IOS).parse(
        (SAMPLES / "cisco_ios_noncompliant.cfg").read_text(encoding="utf-8"), "c-bad"
    )
    sg = summarize(run_audit(good))
    sb = summarize(run_audit(bad))
    assert sg["compliance_pct"] > sb["compliance_pct"]
    assert sg["pass_count"] > sb["pass_count"]
    assert sb["fail_count"] > 0
    # every rule in the noncompliant config must land in a definite state
    assert sb["total_rules"] == sb["pass_count"] + sb["fail_count"] + sb["not_applicable_count"] + sb["error_count"]


def test_safety_of_evaluator():
    """The DSL must not allow arbitrary code execution via check strings."""
    from app.core.rule_engine import Rule, evaluate_rule
    from app.core.parsers import get_parser
    from app.core.parsers.base_parser import VENDOR_CISCO_IOS

    model = get_parser(VENDOR_CISCO_IOS).parse("hostname X\n", "evil")
    evil = Rule(
        {"rule_id": "EVIL-1", "title": "x", "check": "__import__('os').system('echo pwned')"},
        VENDOR_CISCO_IOS,
    )
    status, _, _ = evaluate_rule(evil, model)
    assert status == "error"


# ------------------------------------------------------------------ rule cache
def test_normalize_and_similarity():
    a = normalize_pattern("set ssh timeout 10")
    b = normalize_pattern("set ssh timeout 30")
    assert a == b, "numeric templating should collapse both to the same pattern"
    assert similarity("banner motd hello", "banner motd welcome") > 0.5


# ------------------------------------------------------------------ API flow
def test_full_api_flow(client, auth_headers):
    # ingest compliant cisco
    with open(SAMPLES / "cisco_ios_compliant.cfg", "rb") as f:
        r = client.post(
            "/ingest",
            files={"file": ("cisco_ios_compliant.cfg", f, "text/plain")},
            data={"device_id": "cisco-good"},
            headers=auth_headers,
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["vendor"] == VENDOR_CISCO_IOS

    # audit it
    r = client.post("/audit/cisco-good", headers=auth_headers)
    assert r.status_code == 200, r.text
    audit = r.json()
    assert audit["summary"]["compliance_pct"] >= 70

    # ingest noncompliant cisco + audit
    with open(SAMPLES / "cisco_ios_noncompliant.cfg", "rb") as f:
        r = client.post(
            "/ingest",
            files={"file": ("cisco_ios_noncompliant.cfg", f, "text/plain")},
            data={"device_id": "cisco-bad"},
            headers=auth_headers,
        )
    assert r.status_code == 200
    r = client.post("/audit/cisco-bad", headers=auth_headers)
    bad_audit = r.json()
    assert bad_audit["summary"]["fail_count"] >= 10

    # PDF report
    r = client.get("/report/cisco-bad", headers=auth_headers)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"

    # training loop: classify + confirm + auto-match
    r = client.post(
        "/training/classify",
        json={"line": "ip ssh time-out 90"},
        headers=auth_headers,
    )
    assert r.status_code == 200
    proposal = r.json()["ai"] or r.json()["cache_match"]
    assert proposal is not None

    r = client.post(
        "/training/confirm",
        json={
            "example_line": "ip ssh time-out 90",
            "category": "ssh_policy",
            # forged identity fields: the server must ignore these and use the JWT
            "confirmed_by": "mallory",
            "ai_suggested": False,
            "ai_confidence": 0.99,
            "vendor_hint": "cisco_ios",
        },
        headers=auth_headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["mapping"]["confirmed_by"] == "admin"

    # similar line should now auto-match without re-asking
    r = client.post(
        "/training/classify",
        json={"line": "ip ssh time-out 120"},
        headers=auth_headers,
    )
    data = r.json()
    assert data["cache_match"] is not None
    assert data["cache_match"]["category"] == "ssh_policy"

    # unseen vendor config goes to training queue
    demo = Path(__file__).parent.parent.parent / "demo" / "unseen_vendor_config.txt"
    if demo.exists():
        with open(demo, "rb") as f:
            r = client.post(
                "/ingest",
                files={"file": ("unseen_vendor_config.txt", f, "text/plain")},
                data={"device_id": "unseen-demo"},
                headers=auth_headers,
            )
        assert r.status_code == 200
        assert r.json()["unparsed_count"] > 5

    # dashboard
    r = client.get("/dashboard", headers=auth_headers)
    assert r.status_code == 200
    dash = r.json()
    assert dash["device_count"] >= 2
    assert dash["audited_count"] >= 1


def test_pdf_builder_direct():
    device = {
        "device_id": "x", "hostname": "X", "vendor": "cisco_ios",
        "vendor_label": "Cisco IOS/IOS-XE", "os_version": "15.2", "model": "ISR",
    }
    summary = {
        "total_rules": 2, "pass_count": 1, "fail_count": 1,
        "compliance_pct": 50.0, "top_critical_findings": [{"rule_id": "CF-1", "title": "t"}],
    }
    findings = [
        {"rule_id": "CF-1", "title": "Pass rule", "severity": "low", "status": "pass", "source": "built_in"},
        {"rule_id": "CF-2", "title": "Fail rule", "severity": "critical", "status": "fail",
         "remediation": "no ip telnet\nssh version 2", "source": "ai_suggested_human_confirmed"},
    ]
    pdf = build_pdf(device, summary, findings, unparsed_count=3)
    assert pdf[:5] == b"%PDF-"
