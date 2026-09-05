# ComplianceForge

AI-augmented, vendor-agnostic network security compliance auditor.
**SIH26155 (NTRO) — Quantum Forgers**

Ingest raw CLI configs (Cisco IOS / Juniper SRX / SONiC), normalize to one
vendor-neutral baseline, audit against CIS-style rule packs, train unknown
commands with a human in the loop, and export professional PDF reports with
exact remediation CLI.

> **Design boundaries (deliberate):** advisory-only remediation (no auto-push
> to devices), static file upload (no live SSH polling in v1), depth-of-
> correctness on ~16-20 hand-verified rules per vendor.

## Quick start

### 1. Backend (FastAPI, Python 3.11+)

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

- API docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/health
- Default demo login: `admin` / `admin` (override with `CF_ADMIN_PASSWORD`)

### 2. Frontend (React + Vite + Tailwind)

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

The UI ships with two themes (toggle in the sidebar):
**Forensic Monochrome** (light) and **Industrial Telemetry** (dark).

### 3. Run the demo flow

1. Open http://localhost:5173 → Dashboard (fleet posture).
2. **Ingest Config** → upload any file from `backend/sample_configs/`
   (vendor is auto-detected; compliant vs noncompliant variants per vendor).
3. Open the device → **Run Audit** → severity-ranked findings + remediation
   runbook.
4. **Training Queue** → review AI-suggested categories for unrecognized lines,
   confirm one (e.g. `ip ssh time-out 90`), then notice `ip ssh time-out 120`
   auto-matches without re-asking.
5. **Reports & Evidence** → export the per-device PDF.

### Live "unseen vendor" demo (for judges)

Keep `demo/unseen_vendor_config.txt` untouched during development. In the
demo, ingest it: the syntax fingerprints route it to the *unseen vendor* path,
every substantive line lands in the Training Queue with AI proposals, and the
admin confirms mappings live. `demo/sample_report_noncompliant.pdf` is a
pre-generated example report.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | LLM classification of unknown lines | unset → offline heuristic |
| `CF_ADMIN_PASSWORD` | admin login password | `admin` |
| `CF_JWT_SECRET` | JWT signing secret | dev value |
| `CF_DB_PATH` | SQLite file location | `backend/complianceforge.db` |

## Tests

```bash
cd backend
python -m pytest tests -q
```

Covers: vendor autodetection, all three parsers (compliant + noncompliant),
rule-pack loading, safe-evaluator code-execution rejection, rule-cache
normalization/similarity, full API flow (ingest → audit → PDF → training
confirm → auto-match → dashboard).

## Repo layout

```
backend/           FastAPI app, parsers, rule engine, rule packs, AI layer, reports, tests
  sample_configs/  synthetic compliant/noncompliant fixtures (6 files)
frontend/          React control-plane UI (Dashboard, Devices, Training Loop, Reports)
docs/              ARCHITECTURE.md (≤2 pages), README
demo/              unseen_vendor_config.txt (live judge demo), sample PDF
```

## Honest AI claims

The system uses **human-in-the-loop adaptive mapping**, not autonomous ML:
an LLM proposes categories for unknown lines, a named admin confirms, and a
normalized pattern cache auto-matches future similar lines. The LLM never
issues pass/fail verdicts, and every rule cites its control-family mapping
(labeled "illustrative") in the rule pack and PDF.
