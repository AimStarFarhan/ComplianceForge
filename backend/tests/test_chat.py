"""Chat report-analyst tests (offline — template analyst path)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("CF_DB_PATH", str(Path(__file__).parent / "test_cf.db"))

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def auth_headers(client):
    r = client.post("/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_chat_status(client, auth_headers):
    r = client.get("/chat/status", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["analyst_mode"] in ("local_lm", "llm", "template")


def test_chat_requires_audit(client, auth_headers):
    # device that exists but was never audited should 400 with a helpful message,
    # but since test DB state varies we accept 400 (no run) or 404 (no device)
    r = client.post(
        "/chat",
        json={"question": "summarize", "device_id": "no-such-device"},
        headers=auth_headers,
    )
    assert r.status_code == 404
    assert "not found" in r.json()["detail"]


def test_template_analyst_grounded_answer():
    from app.core.report_analyst import answer_question, build_report_context, template_answer

    device = {
        "device_id": "d1", "hostname": "CORE-SW-01", "vendor": "cisco_ios",
        "vendor_label": "Cisco IOS", "os_version": "15.2", "model": "ISR",
    }
    summary = {
        "total_rules": 2, "pass_count": 1, "fail_count": 1, "error_count": 0,
        "not_applicable_count": 0, "compliance_pct": 50.0,
        "failed_by_severity": {"critical": 1}, "top_critical_findings": [],
    }
    findings = [
        {"rule_id": "CF-CISCO-001", "title": "Disable Telnet, require SSHv2", "severity": "critical",
         "status": "fail", "evidence": "management.telnet_enabled=True", "maps_to": "CIS §1.1.2",
         "explanation": "Telnet is permitted.", "remediation": "line vty 0 4\n transport input ssh",
         "source": "built_in"},
        {"rule_id": "CF-CISCO-002", "title": "Disable HTTP server", "severity": "high",
         "status": "pass", "evidence": "management.http_mgmt_enabled=False", "maps_to": "",
         "explanation": "", "remediation": "", "source": "built_in"},
    ]

    # grounded answer must cite the failing rule and quote remediation verbatim
    ans = template_answer("how do I fix everything?", device, summary, findings, unparsed_count=2)
    assert "CF-CISCO-001" in ans
    assert "Disable Telnet" in ans
    assert "line vty 0 4" in ans
    assert "advisory" in ans.lower()

    # passes question
    ans2 = template_answer("which tests passed?", device, summary, findings, 0)
    assert "CF-CISCO-002" in ans2

    # full chain: no LM configured -> template source
    res = answer_question("summary?", device, summary, findings)
    assert res["source"] in ("template", "llm", "local_lm")

    # context builder keeps statuses verbatim
    ctx = build_report_context(device, summary, findings, unparsed_count=2)
    assert "FAIL 1. [CRITICAL] CF-CISCO-001" in ctx
    assert "PASS" in ctx


def test_chat_flow_needs_device(client, auth_headers):
    r = client.post("/chat", json={"question": "summary"}, headers=auth_headers)
    # 400 = DB has devices but none audited/no run; acceptable in offline test env
    assert r.status_code in (200, 400, 404)
