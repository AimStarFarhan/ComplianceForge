# ComplianceForge

**AI-augmented, vendor-agnostic network security compliance auditor.**

ComplianceForge ingests raw CLI configuration files from network devices (Cisco IOS, Juniper SRX, SONiC), normalizes them into a single vendor-neutral security baseline, audits them against CIS-style hardening rule packs, routes unrecognized commands into a **human-in-the-loop training loop**, and generates professional PDF compliance reports with severity-ranked findings and exact remediation CLI.

> **Design boundaries (deliberate):** advisory-only remediation (no auto-push to devices), static file upload (no live SSH polling in v1), depth-of-correctness on ~16-20 hand-verified rules per vendor.

## The Training Loop (flagship)

The system learns **new, previously unseen vendor syntaxes**:

1. Ingest an unknown-vendor config → every unrecognized line lands in the Training Queue with an AI-proposed category
2. A human admin confirms/corrects — one line at a time, or one-click **"Train on this data"**
3. Confirmed mappings are stored as normalized patterns (numbers/IPs templated out)
4. Re-ingesting the same file: every line **auto-recognizes** — the vendor is now *known*
5. Full rule audits then run on the learned vendor, with every finding tagged `ai_suggested_human_confirmed` for auditability

The AI layer **never issues pass/fail verdicts** — it only proposes categories for a human to confirm. With no API key configured, a deterministic offline heuristic classifier is used so demos never break.

## Quick start

### Backend (FastAPI, Python 3.11+)

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

- API docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/health
- Default demo login: `admin` / `admin`

### Frontend (React + Vite + Tailwind)

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

Or on Windows: double-click `launch.bat` (starts both, installs deps if missing).

### Demo flow

1. **Ingest Config** → upload any fixture from `backend/sample_configs/` (vendor auto-detected)
2. Open the device → **Run Audit** → severity-ranked findings + remediation runbook
3. Upload `demo/unseen_vendor_config.txt` → unknown vendor detected → **Train on this data**
4. Re-upload the same file → fully recognized → **Run Audit** — full rule checks on the learned vendor
5. **Reports & Evidence** → export the per-device PDF

## Repo layout

```
backend/           FastAPI app — parsers, rule engine, rule packs, AI layer, reports, tests
  sample_configs/  synthetic compliant/noncompliant fixtures (6 files, 3 vendors)
frontend/          React control-plane UI (Tactical Field Telemetry design system)
docs/              ARCHITECTURE.md (≤2 pages), README
demo/              unseen_vendor_config.txt (live judge demo fixture)
```

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

Covers vendor autodetection, all three parsers, rule packs, the safe AST evaluator (including code-injection rejection), the rule cache similarity matching, and the full API flow including the learn-a-new-vendor loop.

## Honest AI claims

This is **human-in-the-loop adaptive mapping**, not autonomous ML: an LLM proposes categories for unknown lines, a named admin confirms, and a normalized pattern cache auto-matches future similar lines. Every rule cites its control-family mapping (labeled "illustrative") in the rule pack and the PDF report.
