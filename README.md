# ComplianceForge

**AI-augmented, vendor-agnostic network security compliance auditor.**

ComplianceForge ingests raw CLI configuration files from network devices (Cisco IOS, Juniper SRX, SONiC), normalizes them into a single vendor-neutral security baseline, audits them against CIS-style hardening rule packs, routes unrecognized commands into a **human-in-the-loop training loop**, and generates professional PDF compliance reports with severity-ranked findings and exact remediation CLI.

> **Design boundaries (deliberate):** advisory-only remediation (no auto-push to devices), static file upload (no live SSH polling in v1), depth-of-correctness on ~16-20 hand-verified rules per vendor.

## Prerequisites

- **Python 3.11+** (`python --version`)
- **Node.js 18+** (`node --version`) — frontend only
- **Git** to clone (or download the ZIP and extract it)
- Optional: **Docker** for the one-command deployment

## Setup

### Option A — Windows one-click (recommended)

Double-click **`launch.bat`** in the repo root. It installs backend/frontend dependencies if missing, starts the API on `:8000` and the UI on `:5173`, then opens the app. Stop with `stop.bat` or by closing the two server windows.

### Option B — Manual (any OS)

Backend (FastAPI):

```bash
cd backend
pip install -r requirements.txt
CF_DEV_ALLOW_DEFAULTS=1 python -m uvicorn app.main:app --port 8000
```

(`CF_DEV_ALLOW_DEFAULTS=1` enables the local demo login `admin` / `admin`. For anything shared, set `CF_ADMIN_PASSWORD` + `CF_JWT_SECRET` instead — the backend refuses default credentials otherwise.)

Frontend (React + Vite):

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

### Option C — Docker

```bash
docker compose up
```

CPU-only `python:3.12-slim` backend (model baked in) + Vite UI. No API keys needed — the app runs fully offline by default.

### Where everything lives

- App: http://localhost:5173 (landing page → **OPEN CONSOLE**)
- API docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/health (shows AI mode, dataset size, model version)
- Login: `admin` / `admin` (local demo only)

> First load may show a brief "waking up the backend" splash on the console route — it disappears automatically once the API answers.

## 5-minute first run

1. **Ingest Config** → upload `backend/sample_configs/cisco_ios_noncompliant.cfg` (vendor auto-detected). Try selecting 2–4 files at once — each gets its own parallel lane: ingest → audit → score.
2. Open the device → findings with quoted evidence + copy-paste remediation CLI. Or audit straight from the lane's **View report**.
3. Upload `demo/unseen_vendor_config.txt` → unknown vendor detected → lane shows **Needs training** (other lanes are not blocked).
4. Open the **Training Loop** → bulk-review table → correct any wrong proposal → tick **"I reviewed every row above"** → **Approve reviewed**. (Without the tick, low-confidence rows stay queued — the server rejects the batch and tells you exactly that.)
5. Re-upload the same file → every line auto-recognizes → **Run Audit** — full rule checks on the learned vendor.
6. **Reports & Evidence** → export the per-device PDF.

## The Training Loop (flagship)

The system learns **new, previously unseen vendor syntaxes**:

1. Ingest an unknown-vendor config → every unrecognized line lands in the Training Queue with an AI-proposed category
2. A named human admin confirms/corrects — one line, one pattern, or explicit per-line bulk approvals with a dry-run summary (`POST /training/train-device` accepts only explicit approvals; `unknown`/low-confidence lines stay unresolved without the review tick)
3. Human-verified mappings are continuously added to the learning dataset and used for periodic model updates/fine-tuning
4. Re-ingesting the same file: every line **auto-recognizes** — the vendor is now *known*
5. Full rule audits then run on the learned vendor, with every finding tagged `ai_suggested_human_confirmed` for auditability

Classification is a 3-layer chain: **L1** exact confirmed-pattern cache (bounded, high-precision only) → **L2** trained sklearn TF-IDF + LogisticRegression model (fixed-size ~1MB artifact, accuracy-gated promotion, rollbackable) → **L3** LLM/heuristic fallback for true zero-shot lines only. Listing pages use a fast L1→L2→heuristic path so the queue stays interactive.

The AI layer **never issues pass/fail verdicts** — it only proposes categories for a human to confirm. With no API key configured, the trained model + deterministic offline heuristic classifier are used so demos never break.

## Repo layout

```
backend/           FastAPI app — parsers, rule engine, rule packs, AI layer, reports, tests
  sample_configs/  synthetic compliant/noncompliant fixtures (6 files, 3 vendors)
  scripts/         model training helpers
frontend/          React console + landing (lanes, training loop, splash, chatbot)
docs/              ARCHITECTURE.md, README
demo/              unseen_vendor_config.txt (12-line unseen-vendor fixture)
launch.bat         Windows one-click start · stop.bat stops everything
```

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `CF_ADMIN_PASSWORD` | admin login password | **required** (`CF_DEV_ALLOW_DEFAULTS=1` for local dev/tests only) |
| `CF_JWT_SECRET` | JWT signing secret | **required** (same dev escape hatch) |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | LLM classification of unknown lines | unset → offline heuristic |
| `CF_USE_LOCAL_LM` | route L3 through LM Studio (`http://localhost:1234`) | `0` (launch.bat sets `1`) |
| `CF_DB_PATH` | SQLite file location | `backend/complianceforge.db` |
| `CF_DATABASE_URL` | Postgres URL (serverless/production persistence) | unset → SQLite |
| `CF_DEMO_OPEN` | skip login gate on shared demo links | `0` |
| `VITE_API_BASE` | frontend → API base override | `/api` (Vercel rewrites) |

## Tests

```bash
cd backend
python -m pytest tests -q
```

41 tests cover vendor autodetection, all three parsers, rule packs, the safe AST evaluator (including code-injection rejection), exact-cache vendor isolation, forged-identity rejection, explicit-approval bulk training, candidate-never-serves promotion, AI-finding provenance + provisional flags, the trained-model smoke + retrain promote/rollback gate, and the full API flow including the learn-a-new-vendor loop.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `address already in use :8000` | An old backend is still running — close all API windows, `taskkill /PID <n> /F` for anything on `:8000`, re-run `launch.bat` |
| Training Queue loads forever / proposals stall | Backend is running code from before a restart — restart it (uvicorn here runs without `--reload`) |
| Bulk approve rejected, nothing written | Tick **"I reviewed every row above"** (or edit low-confidence rows) and approve again — the toast names the exact fix |
| Approved rows still showing | Hard-refresh (`Ctrl+Shift+R`); approvals validate against the latest snapshot, so re-ingesting mid-review orphans the old queue |
| Queue slow with local LM on | Listing paths use the fast classifier, but single-line classify/chat still call the model — unset `CF_USE_LOCAL_LM` for the instant path |
| Deployed link shows backend errors | Serverless cold start — the splash covers it; check `CF_DATABASE_URL` is set or history resets on sleep |

## Model

- Dataset: `backend/app/core/training_data/dataset.jsonl` — ~1,300 balanced lines (~53–80 per each of 19 categories), deduped by normalized pattern, zero conflicting patterns. Sources: hand-verified rule-pack remediation CLI, sample-config syntax, sieved real-world configs, STIG-mined CLI, synthetic fills for thin classes.
- Train: `python backend/scripts/train_model.py` — trains a CANDIDATE (holdout rows excluded, sha256 recorded); serving version untouched. Promote: `--promote` or `POST /training/model/retrain` — candidate vs incumbent scored on the immutable `holdout.jsonl`; atomic promotion only on overall + per-category (ssh_policy, management_protocol) gates.
- Trust: reviewer identity from JWT (never request bodies); every decision appended to an immutable log (`GET /training/decisions`); L1 exact-only per-vendor matching; AI-derived findings carry mapping/reviewer provenance and audits flag `provisional`.
- Serve: fixed-size artifact (~1MB whether 1k or 100k examples) via `trained_classifier.predict(text)`. Retrain/rollback/export: `POST /training/model/retrain`, `POST /training/model/rollback/{version}`, `GET /training/dataset/export`. Health + dashboard show `dataset_size, model_version, accuracy`.
- Docker: `docker compose up` (CPU-only `python:3.12-slim` backend with baked-in model + Vite UI).

## Honest AI claims

This is **human-in-the-loop adaptive mapping**, not autonomous ML: an LLM proposes categories for unknown lines, a named admin confirms, and a bounded exact-pattern cache auto-recognizes identical future lines (similar lines are proposals, never auto-matches). Every rule cites its control-family mapping (labeled "illustrative") in the rule pack and the PDF report.
