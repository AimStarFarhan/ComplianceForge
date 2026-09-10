"""Report analyst: answers natural-language questions about an audit report.

DESIGN BOUNDARY (same as the classifier):
  The LLM NEVER invents pass/fail verdicts — the rule engine owns those. The
  analyst receives the actual stored findings as ground truth and may only
  rephrase/explain them. If no LM is reachable, a deterministic template
  analyst answers from the same data, so the chat always works offline.

Answer chain (first success wins):
  1. local LM (LM Studio, OpenAI-compatible) — opt-in via CF_USE_LOCAL_LM=1
  2. cloud LLM (Anthropic/OpenAI) — if an API key is configured
  3. deterministic template analyst — instant, always works
"""

from __future__ import annotations

import json
import os
import re

try:
    import httpx
except ImportError:
    httpx = None

LOCAL_LM_URL = os.environ.get("CF_LOCAL_LM_URL", "http://localhost:1234")
LOCAL_LM_TIMEOUT = float(os.environ.get("CF_LOCAL_LM_TIMEOUT", "90"))

MAX_FINDINGS_IN_CONTEXT = 40

ANALYST_SYSTEM = """You are the ComplianceForge report analyst — a network security compliance assistant.
You are given the ground-truth results of a deterministic rule-engine audit (device info, summary,
and per-rule findings). Your job is ONLY to explain and rephrase this data for the user.

Hard rules:
- NEVER contradict, invent, or change any pass/fail status, severity, or remediation CLI.
- Remediation commands come from the rule pack; quote them verbatim in code blocks.
- If the user asks something not covered by the provided findings, say so honestly.
- When advising on fixes, ALWAYS add: commands are advisory and must be applied in a
  maintenance window after review — never auto-pushed.
- Be concise, structured, and use short markdown (headings, bullets, code blocks).
- Answers are grounded ONLY in the audit data you are given."""

ADVISORY_NOTICE = (
    "Remediation commands are advisory. Apply in a maintenance window after "
    "review — not for unattended auto-execution."
)

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ------------------------------------------------------------------ context
def build_report_context(device: dict, summary: dict, findings: list[dict], unparsed_count: int = 0) -> str:
    """Render the audit report as compact, LLM-friendly markdown ground truth."""
    fails = sorted(
        [f for f in findings if f.get("status") == "fail"],
        key=lambda f: SEV_ORDER.get(f.get("severity", "low"), 99),
    )
    passes = [f for f in findings if f.get("status") == "pass"]

    lines = [
        "# AUDIT REPORT (ground truth — do not contradict)",
        f"Device: {device.get('hostname') or device.get('device_id')} "
        f"({device.get('vendor_label') or device.get('vendor')}, "
        f"OS: {device.get('os_version') or 'unknown'}, model: {device.get('model') or 'unknown'})",
        f"Device ID: {device.get('device_id')}",
        "",
        "## Summary",
        f"- Compliance: {summary.get('compliance_pct', 0)}% "
        f"({summary.get('pass_count', 0)} passed / {summary.get('fail_count', 0)} failed "
        f"of {summary.get('total_rules', 0)} checks; {summary.get('not_applicable_count', 0)} n/a, "
        f"{summary.get('error_count', 0)} errors)",
        f"- Failed by severity: {json.dumps(summary.get('failed_by_severity') or {})}",
        f"- Unparsed config lines routed to training queue: {unparsed_count}",
        "",
        f"## FAILED checks ({len(fails)})",
    ]
    for i, f in enumerate(fails[:MAX_FINDINGS_IN_CONTEXT], 1):
        lines += [
            f"### FAIL {i}. [{f.get('severity', '?').upper()}] {f.get('rule_id')} — {f.get('title')}",
            f"- Evidence (normalized baseline): {f.get('evidence') or 'n/a'}",
            f"- Why it matters: {f.get('explanation') or 'n/a'}",
            f"- Maps to: {f.get('maps_to') or 'n/a'}",
            f"- Remediation CLI (verbatim from rule pack):",
            "```",
            str(f.get("remediation") or "(no template in rule pack)"),
            "```",
        ]
    if len(fails) > MAX_FINDINGS_IN_CONTEXT:
        lines.append(f"(…{len(fails) - MAX_FINDINGS_IN_CONTEXT} more failures truncated)")

    lines += ["", f"## PASSED checks ({len(passes)})"]
    for f in passes[:MAX_FINDINGS_IN_CONTEXT]:
        lines.append(
            f"- PASS [{f.get('severity', '?').upper()}] {f.get('rule_id')} — {f.get('title')} "
            f"(evidence: {f.get('evidence') or 'n/a'})"
        )
    if len(passes) > MAX_FINDINGS_IN_CONTEXT:
        lines.append(f"(…{len(passes) - MAX_FINDINGS_IN_CONTEXT} more passes truncated)")

    other = [f for f in findings if f.get("status") not in ("pass", "fail")]
    if other:
        lines += ["", f"## OTHER statuses ({len(other)})"]
        for f in other:
            lines.append(f"- {f.get('status', '?').upper()} {f.get('rule_id')} — {f.get('title')}")

    return "\n".join(lines)


# ------------------------------------------------------------------ deterministic analyst
def _fmt_cli(remediation: str) -> str:
    return "\n".join(f"    {ln}" for ln in str(remediation or "").splitlines()) or "    (no template)"


def template_summary(device: dict, summary: dict, findings: list[dict], unparsed_count: int) -> str:
    host = device.get("hostname") or device.get("device_id")
    vendor = device.get("vendor_label") or device.get("vendor")
    pct = summary.get("compliance_pct", 0)
    pct_str = f"{pct:g}%" if pct is not None else "0%"
    out = [
        f"## Report summary — {host} ({vendor})",
        "",
        f"**Compliance index: {pct_str}** — {summary.get('pass_count', 0)} of "
        f"{summary.get('pass_count', 0) + summary.get('fail_count', 0)} scored checks passed, "
        f"{summary.get('fail_count', 0)} failed"
        f" ({summary.get('not_applicable_count', 0)} not applicable, {summary.get('error_count', 0)} errors).",
    ]
    sev = summary.get("failed_by_severity") or {}
    if summary.get("fail_count", 0):
        out += [
            "",
            "**Failed by severity:** "
            + ", ".join(f"{k}: {v}" for k, v in sorted(sev.items(), key=lambda kv: SEV_ORDER.get(kv[0], 99))),
        ]
    if unparsed_count:
        out += ["", f"_{unparsed_count} config lines were unrecognized and routed to the human training queue._"]
    return "\n".join(out)


def template_answer(question: str, device: dict, summary: dict, findings: list[dict], unparsed_count: int) -> str:
    """Deterministic template analyst — grounded purely in the findings data."""
    q = question.lower()
    host = device.get("hostname") or device.get("device_id")
    vendor = device.get("vendor_label") or device.get("vendor")
    fails = sorted(
        [f for f in findings if f.get("status") == "fail"],
        key=lambda f: SEV_ORDER.get(f.get("severity", "low"), 99),
    )
    passes = [f for f in findings if f.get("status") == "pass"]

    if not summary or not findings:
        return (
            f"No audit results are available for **{host}** yet. "
            "Run the audit first (Devices → Run Audit), then ask me again."
        )

    if re.search(r"\b(pass|passed|passing|okay|good|clean)\b", q) and not re.search(r"\bfail", q):
        out = [f"### Passed checks — {host} ({len(passes)})", ""]
        for f in passes:
            out.append(f"- **PASS** [{f.get('severity', '?').upper()}] {f.get('rule_id')} — {f.get('title')}")
        if not passes:
            out.append("_No checks passed on the last audit._")
        return "\n".join(out)

    if re.search(r"\b(fail|failed|failing|issue|problem|violation|default|gap)\b", q) or True:
        if not fails:
            return (
                f"**{host} has no failed checks** — {len(passes)} of "
                f"{summary.get('total_rules', len(findings))} checks passed "
                f"({summary.get('compliance_pct', 0)}% compliance). Nothing to remediate on this device."
            )
        out = [f"### Failed checks — {host} ({len(fails)})", ""]
        for f in fails:
            out += [
                f"**{f.get('severity', '?').upper()} · {f.get('rule_id')} — {f.get('title')}**",
                f"- Why it failed: {f.get('explanation') or 'n/a'}",
                f"- Evidence: `{f.get('evidence') or 'n/a'}`",
                f"- Fix (vendor CLI):",
                "```",
                str(f.get("remediation") or "(no template in rule pack)"),
                "```",
                "",
            ]
        out += [f"_{ADVISORY_NOTICE}_", ""]
        out += [
            f"Apply all {len(fails)} fixes, then re-run the audit — the compliance index "
            f"should move from {summary.get('compliance_pct', 0)}% toward 100%.",
        ]
        return "\n".join(out)

    return template_summary(device, summary, findings, unparsed_count)


# ------------------------------------------------------------------ LLM layer
def _llm_answer(question: str, context: str) -> str:
    """Try local LM first, then cloud. Returns text or raises."""
    if httpx is None:
        raise RuntimeError("httpx unavailable")

    prompt = f"{context}\n\n---\nAuditor question: {question}\n\nAnswer based only on the report data above."

    # 1 — local LM Studio (air-gapped)
    if os.environ.get("CF_USE_LOCAL_LM", "0") == "1":
        payload = {
            "model": os.environ.get("CF_LOCAL_LM_MODEL", "local-model"),
            "messages": [
                {"role": "system", "content": ANALYST_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": int(os.environ.get("CF_LOCAL_LM_MAX_TOKENS", "2048")),
            "stream": False,
        }
        try:
            with httpx.Client(timeout=LOCAL_LM_TIMEOUT) as client:
                resp = client.post(f"{LOCAL_LM_URL}/v1/chat/completions", json=payload)
                resp.raise_for_status()
                data = resp.json()
            msg = (data.get("choices") or [{}])[0].get("message", {})
            text = msg.get("content") or msg.get("reasoning_content") or ""
            if text and text.strip():
                return text.strip()
        except Exception:
            pass  # fall through to cloud

    # 2 — cloud LLM
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        payload = {
            "model": os.environ.get("CF_LLM_MODEL", "claude-3-5-haiku-latest"),
            "max_tokens": 1500,
            "system": ANALYST_SYSTEM,
            "messages": [{"role": "user", "content": prompt}],
        }
        with httpx.Client(timeout=60) as client:
            resp = client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
        text = "".join(b.get("text", "") for b in data.get("content", []))
        if text.strip():
            return text.strip()

    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        payload = {
            "model": os.environ.get("CF_LLM_MODEL", "gpt-4o-mini"),
            "messages": [
                {"role": "system", "content": ANALYST_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        with httpx.Client(timeout=60) as client:
            resp = client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {openai_key}", "content-type": "application/json"},
                json=payload,
            )
            resp.raise_for_status()
            text = resp.json()["choices"][0]["message"]["content"]
        if text and text.strip():
            return text.strip()

    raise RuntimeError("no LLM backend reachable")


def answer_question(
    question: str,
    device: dict,
    summary: dict,
    findings: list[dict],
    unparsed_count: int = 0,
) -> dict:
    """Public entry: ground-truth context + question -> {answer, source}.

    source: local_lm | llm | template (deterministic fallback always answers).
    """
    try:
        text = _llm_answer(question, build_report_context(device, summary, findings, unparsed_count))
        source = "local_lm" if os.environ.get("CF_USE_LOCAL_LM", "0") == "1" else "llm"
        # local_lm flag may be on while server is down -> cloud answered
        if source == "local_lm" and not _local_lm_up():
            source = "llm"
        return {"answer": text, "source": source}
    except Exception:
        return {
            "answer": template_answer(question, device, summary, findings, unparsed_count),
            "source": "template",
        }


def _local_lm_up() -> bool:
    if httpx is None:
        return False
    try:
        with httpx.Client(timeout=3) as client:
            r = client.get(f"{LOCAL_LM_URL}/v1/models")
            return r.status_code == 200 and bool(r.json().get("data"))
    except Exception:
        return False


def analyst_mode() -> str:
    if os.environ.get("CF_USE_LOCAL_LM", "0") == "1" and _local_lm_up():
        return "local_lm"
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY"):
        return "llm"
    return "template"
