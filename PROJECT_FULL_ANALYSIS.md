# ComplianceForge — Complete Technical & Business Analysis

**Version:** 1.0  
**Date:** September 2026  
**Classification:** Internal / External Panel Ready

---

## Executive Summary

ComplianceForge is an **AI-augmented, vendor-agnostic network security compliance auditor** that solves the fundamental problem of auditing heterogeneous network fleets across multiple vendors without waiting for vendor-specific connectors. It ingests raw CLI configuration files, normalizes them into a single vendor-neutral security baseline, audits against CIS-style hardening rule packs, and — through its **flagship Training Loop** — learns previously unseen vendor syntaxes via a human-in-the-loop adaptive mapping cache, all without a single code redeploy.

**Key Differentiator:** The industry's first compliance engine where an administrator can extend support to a brand-new CLI syntax in minutes through an interactive GUI, not a vendor roadmap quarter.

---

## 1. Problem Space — Why This Exists

### The Operational Gap
| Current State | Pain Point |
|---|---|
| Manual audits | Slow, inconsistent, doesn't scale past ~50 devices |
| Commercial suites (Tufin, FireMon, Titania, SolarWinds) | Fixed vendor-connector libraries; new vendor = vendor roadmap wait |
| Open source (Netmiko/NAPALM/Batfish) | Hand-written parsers per vendor — same bottleneck |
| Misconfiguration | Leading root cause of network breaches (Verizon DBIR, Gartner) |

### What the Problem Statement Required
1. Ingest configuration files (not live SSH polling)
2. Normalize to vendor-neutral baseline
3. Score compliance against CIS-style rules
4. Generate PDF report with severity-ranked findings + exact remediation CLI
5. **The twist:** Learn vendors never seen before, without code redeploy, via interactive training GUI

---

## 2. Solution Architecture — The Complete Pipeline

```
┌─────────────┐     ┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│  Upload     │────▶│  Vendor     │────▶│  Parser (per     │────▶│  Security   │
│  Config     │     │  Autodetect │     │  vendor regex)   │     │  Baseline   │
└─────────────┘     └─────────────┘     └──────────────────┘     │  Model      │
                                                                    └──────┬──────┘
                                                                           │
                                              ┌──────────────┐            │
                                              │  Rule Engine │            │
                                              │  (YAML packs │            ▼
                                              │  + Safe AST) │     ┌─────────────┐
                                              └──────┬───────┘     │  Findings   │
                                                     │            │  + Score    │
                                                     ▼            └──────┬──────┘
                                            ┌─────────────┐             │
                                            │  SQLite     │             │
                                            │  (Postgres- │             ▼
                                            │  swappable) │      ┌─────────────┐
                                            └──────┬──────┘      │  ReportLab  │
                                                   │            │  PDF Report │
                                                   ▼            └─────────────┘
                                            ┌─────────────┐
                                            │  Training   │
                                            │  Loop (AI   │
                                            │  proposes,  │
                                            │  human      │
                                            │  confirms)  │
                                            └─────────────┘
```

### Core Architectural Decision: The Security Baseline Model
**One Pydantic schema** that every parser emits and the rule engine exclusively consumes:

```python
SecurityBaselineModel
├── device          (id, vendor, hostname, os_version, model, device_type)
├── management      (ssh/telnet/http, idle timeout, banner, NTP, SNMP, CDP/LLDP)
├── auth            (password policy, AAA, default credentials, lockout)
├── logging         (remote syslog, admin-access logging, severity)
├── acl             (rules, default-deny, mgmt ACL binding, ACL logging)
├── crypto          (weak ciphers, key size, DH groups, hash algorithms)
├── services        (unused services: finger/bootp/pad/small-servers)
├── unparsed_lines  ← ANYTHING UNMAPPABLE feeds the Training Loop
└── metadata        (vendor extras, transparency-only, not rule-evaluated)
```

**Why this generalizes:** Models security *concepts* (auth, logging, crypto, access control), not vendor CLI structure. A firewall and a switch map into the same concept buckets. Adding a vendor = writing one parser that emits this shape.

---

## 3. Backend — Deep Technical Breakdown

### 3.1 Stack
| Layer | Technology | Rationale |
|---|---|---|
| API | FastAPI (Python 3.11+) | Auto OpenAPI docs, async, type-safe |
| Persistence | SQLite + SQLAlchemy 2.0 | Zero-config dev; Postgres-swappable via URL |
| Parsing | Deterministic regex | No ML drift, 100% reproducible, auditable |
| AI Layer | Anthropic Claude / OpenAI (few-shot) | Provider-agnostic, graceful offline fallback |
| Rule Engine | YAML packs + Safe AST evaluator | Data-driven rules, injection-proof |
| Reporting | ReportLab | Professional PDF, no browser dependency |
| Auth | JWT (HS256) | Single named admin = human in the loop |
| Frontend | React 18 + Vite 5 + Tailwind 3 | Modern, fast, dual-theme UI |

### 3.2 Module Map (`backend/app/`)

| Module | Responsibility | Key APIs |
|---|---|---|
| `main.py` | FastAPI entrypoint, CORS, lifespan DB init, `/login`, `/health` | — |
| `db.py` | SQLite engine + session factory; `CF_DB_PATH` override | `init_db()`, `get_db()` |
| `api/auth.py` | JWT issue/verify, `CF_ADMIN_PASSWORD` / `CF_JWT_SECRET` | `login()`, `verify_token()` |
| `api/routes_ingest.py` | `POST /ingest` — upload ≤2MB, vendor autodetect, parse, store snapshot, enrich via cache | `ingest_config()` |
| `api/routes_audit.py` | `POST /audit/{device_id}` — run rule pack, persist run + findings | `run_audit()` |
| `api/routes_devices.py` | `GET /devices`, `GET /devices/{id}` — fleet + per-device state | — |
| `api/routes_training.py` | **Training Loop API**: queue, classify, confirm, mappings CRUD, `train-device`, stats | 8 endpoints |
| `api/routes_report.py` | `GET /report/{device_id}` — ReportLab PDF, `application/pdf` | `get_report()` |
| `api/routes_dashboard.py` | `GET /dashboard` — fleet compliance score, severity totals, per-vendor rollup | — |
| `core/schema.py` | **SecurityBaselineModel** + 19-category taxonomy | — |
| `core/parsers/` | `base_parser` (vendor fingerprints + autodetect) + Cisco IOS, Juniper SRX, SONiC | `parse()`, `detect_vendor()` |
| `core/rule_engine.py` | YAML pack loader, `_SafeEval` AST visitor, `run_audit`, `summarize` | `run_audit()` |
| `core/rule_cache.py` | Confirmed-mapping store: pattern normalization + exact/fuzzy match | `match()`, `confirm()` |
| `core/ai_classifier.py` | LLM few-shot classifier + offline heuristic fallback | `classify()`, `local_lm_available()` |
| `core/baseline_inference.py` | Reconstructs baseline for unseen vendor purely from confirmed mappings | `infer_baseline()` |
| `core/report_builder.py` | ReportLab PDF: identification, executive summary, findings table, remediation appendix | `build_pdf()` |
| `models/` | SQLAlchemy ORM: `Device`, `ConfigSnapshot`, `AuditRun`, `Finding`, `CommandMapping` | — |

### 3.3 Vendor Autodetection & Parsers
`detect_vendor()` fingerprints config syntax:
- **Cisco IOS**: `hostname`, `ip ssh`, `enable secret`, `line vty`
- **Juniper SRX**: `set system`, `set security`, `set interfaces`
- **SONiC**: `sudo config feature`, `sonic-cfggen`

Three deterministic regex parsers emit the baseline model; anything they can't confidently map goes to `unparsed_lines` with line number + context — the deliberate escape hatch feeding the Training Loop.

### 3.4 Rule Engine & Packs
- **4 YAML rule packs**: Cisco IOS (20 rules), Juniper SRX (20), SONiC (16), Unseen Vendor (16)
- Each rule: `rule_id`, `title`, `severity` (critical/high/medium/low), `check` (restricted DSL), `maps_to` (illustrative CIS/NIST/STIG citation), `remediation_template` (vendor-correct CLI), pass/fail explanations, optional `applies_to`
- Checks evaluate through `_SafeEval` — a **whitelisted `ast` visitor** (comparisons, boolean ops, list membership, attribute reads, arithmetic) — **never `eval`**
- Malicious/malformed checks return `error`, not a crash (proven by `test_safety_of_evaluator`)
- `run_audit()` sorts by severity, tags findings `source=built_in` or `source=ai_suggested_human_confirmed`
- `summarize()` computes compliance % = pass/(pass+fail), severity totals, top critical findings

### 3.5 The AI Layer (`ai_classifier.py`)
- **Few-shot LLM classification**: 24 example line→category pairs sent with each unknown line; model must respond only with JSON `{category, confidence, reason}`; validated against canonical taxonomy
- **Provider-agnostic**: Anthropic Claude (default) or OpenAI via env vars
- **Graceful degradation**: no key, no network, quota failure, or unparseable output → deterministic keyword-heuristic classifier (16 regex rules, confidence 0.55/0.2). **Demos never break.**
- **Design boundary (in code, README, report)**: LLM never used for pass/fail verdicts

### 3.6 The Learning Mechanism — Human-in-the-Loop Adaptive Mapping

#### Rule Cache (`rule_cache.py`)
```python
# Normalization: templates out variable values
"ip ssh time-out 90" → "ip ssh time-out <N>"
"set snmp community public" → 'set snmp community "<V>"'
"logging host 192.168.1.50" → "logging host <IP>"

# Matching: exact pattern (confidence 1.0) → fuzzy ≥0.82 (difflib)
```

**Every confirmed mapping stores:**
- Normalized pattern
- Example line
- Category
- `confirmed_by` (named human)
- `ai_suggested` + confidence
- Vendor hint
- Timestamps
- `times_matched`

#### Baseline Inference (`baseline_inference.py`)
For unseen vendors, the cache + polarity inference reconstructs a genuine `SecurityBaselineModel`:
- Line polarity (enable/disable verbs: `no`/`disable`/`shutdown`/`deny` vs `enable`/`permit`/`run`)
- Weak-cipher keywords (des/3des/rc4/md5/sha1)
- Default SNMP strings (public/private)
- "min" + number for password lengths
- IP extraction for syslog servers

The `cis_unseen_vendor.yaml` pack then audits that inferred baseline **exactly like a known vendor**, with every finding tagged `ai_suggested_human_confirmed`.

### 3.7 Training Loop API (8 Endpoints)

| Endpoint | Purpose |
|---|---|
| `GET /training/queue` | Unparsed lines needing review, AI proposals; skips cache-matched; dedupes across devices |
| `POST /training/classify` | Ask classifier for one line (cache match first) |
| `POST /training/confirm` | **Human gate** — validates category, writes/updates mapping |
| `POST /training/train-device` | One-click bulk train: AI proposals or human `corrections` overrides |
| `GET /training/mappings` | Full mapping cache with provenance |
| `DELETE /training/mappings/{id}` | Remove a mapping |
| `GET /training/stats` | Cache stats for dashboard |

### 3.8 Auth & Security Posture
- JWT (HS256) with env-configurable secret and admin password
- Single named admin role = the human in the loop
- All API routes token-gated except `/login` and `/health`
- 2MB upload cap, UTF-8 decode with replacement, slugified device IDs
- **Test `test_safety_of_evaluator` proves** `__import__('os').system(...)` in a rule check returns `error` — DSL cannot execute arbitrary code

### 3.9 PDF Report (`report_builder.py`)
Professional layout:
1. Device identification
2. Executive summary (compliance %, severity totals)
3. Findings table (rule ID, severity, status, evidence, control-family mapping)
4. Remediation appendix (monospace CLI per failed rule, tagged with source)
5. Advisory disclaimer + generation timestamp

### 3.10 Tests (11 tests, ~1.3s)
- Vendor autodetection on all 6 fixtures
- Cisco compliant/noncompliant parsing
- Juniper parsing
- SONiC parsing
- Rule pack loading (≥15 rules, no duplicate IDs, per vendor)
- Audit scoring sanity (compliant > noncompliant; every rule definite state)
- **Evaluator safety (code-injection rejected)**
- Pattern normalization + similarity
- **Full API flow**: ingest → audit → PDF → classify → confirm → auto-match on similar line → unseen-vendor ingest lands in queue → dashboard → direct PDF builder

---

## 4. Frontend — Control Plane

### Stack
React 18 + Vite 5 + Tailwind CSS 3, react-router-dom 6. Dual theme:
- **Forensic Monochrome** (light)
- **Industrial Telemetry** (dark)

### Pages

| Page | Function |
|---|---|
| `Login.jsx` | JWT login (admin/admin default) |
| `Dashboard.jsx` | Fleet compliance score, severity distribution, per-vendor rollup, device drill-in |
| `UploadIngest.jsx` | Config upload (drag/drop), live vendor detection, unparsed-line preview, next-step guidance (`train` vs `audit`), one-click "Train on this data" |
| `Devices.jsx` | Fleet table: vendor, OS, compliance %, pass/fail counts, audited state |
| `DeviceDetail.jsx` | Per-device: normalized baseline view, run audit, severity-ranked findings with evidence + remediation CLI, source tags (built-in vs AI+human-confirmed) |
| `TrainingLoop.jsx` | **Flagship UI**: pending-line queue with AI proposals (confidence + source), confirm/correct per line, mapping cache management with provenance and times-matched |
| `ReportPreview.jsx` | Dashboard-level report + per-device PDF export |
| `components/Header/Sidebar/Footer` | Live stats from `/health` + `/training/stats` (AI mode, mappings, matches) |

### API Layer
`lib/api.js` centralizes fetch + JWT injection + 401 auto-logout; `useApi` hook gives every page data/error/loading/reload. Vite dev server proxies `/api` → backend :8000.

---

## 5. Data Model

| Entity | Key Fields |
|---|---|
| **Device** | device_id, vendor, hostname, OS/model/type, `is_unseen_vendor` |
| **ConfigSnapshot** | filename, raw config (kept for re-audit), normalized JSON baseline |
| **AuditRun** | per audit: compliance summary |
| **Finding** | per rule: status, severity, evidence, explanation, remediation, **source** (built_in / ai_suggested_human_confirmed) |
| **CommandMapping** | The learning: pattern, example line, category, confirmed_by, ai_suggested, ai_confidence, vendor_hint, times_matched, timestamps |

SQLite via SQLAlchemy — Postgres-swappable by changing connection URL.

---

## 6. Demo Flow (Judge-Facing Script)

1. **Upload** a known-vendor config (`cisco_ios_noncompliant.cfg`) → vendor auto-detected, normalized baseline shown
2. **Run Audit** → 20 CIS-style rules, severity-ranked findings, evidence, exact remediation CLI, compliance %
3. **PDF report** — one click, professional evidence artifact
4. **The differentiator:** upload `demo/unseen_vendor_config.txt` (synthetic CLI never tested during development) → system honestly flags every line as unrecognized — it does *not* guess
5. **Training Loop** → AI proposes categories per line with confidence; human confirms/corrects (or one-click "Train on this data")
6. **Re-ingest the same file** → every line auto-recognizes → **Run Audit** → full rule checks on a vendor that didn't exist in the codebase, findings tagged `ai_suggested_human_confirmed`
7. **Dashboard** — fleet view across known + learned vendors, per-vendor compliance

---

## 7. Competitive Positioning

| Capability | ComplianceForge | Tufin / FireMon / Titania / SolarWinds |
|---|---|---|
| Multi-vendor automated ingestion | ✅ | ✅ (fixed vendor list) |
| Real-time JSON normalization | ✅ one vendor-neutral schema | connector-specific |
| Automated compliance auditing | ✅ CIS-style packs, safe DSL | ✅ |
| **Human-in-the-loop AI verification** | ✅ AI proposes, human confirms | ❌ |
| **Auto-generated executable fixes** | ✅ exact vendor CLI per rule | partial |
| **Zero-trust rule validation** | ✅ AST sandbox, injection-proof | n/a |
| **Learn unseen vendor without code redeploy** | ✅ the Training Loop | ❌ — the industry gap |

**The common gap:** Every competitor is a pre-built vendor-connector library. None can adapt to a brand-new CLI syntax without engineering work. The Training Loop closes this gap — an administrator extends support themselves in minutes, not a vendor roadmap quarter.

---

## 8. Impact & Beneficiaries

| Beneficiary | Value |
|---|---|
| **Government / Critical Infrastructure** | Heterogeneous networks audited without single-vendor ecosystem lock-in |
| **PSUs & State Government Networks** | L1-tender procurement across years/vendors creates exactly the mixed-fleet problem this solves |
| **MSSPs & Audit Firms** | Manual multi-client audits become repeatable pipelines |
| **SMEs** | Tufin/FireMon per-device licensing is out of reach; priced for Indian market |
| **Strategic Sovereignty** | India-built, vendor-agnostic compliance engine reduces reliance on foreign security tooling |
| **Security Outcomes** | Misconfiguration is a leading breach cause; continuous, broad auditing directly shrinks attack surface |

---

## 9. Extension Path

- **New vendors**: One `BaseParser` subclass + one YAML pack — and even before that exists, the `unseen_vendor` path makes a new vendor *usable on day zero* via the training loop
- **New frameworks**: Rule packs are data, not code — community/sector STIGs plug in as YAML
- **Live collection**: Netmiko/NAPALM as optional add-on for SSH polling (deliberately out of v1 scope)
- **Deploy**: FastAPI on Railway/Render, frontend on Vercel; SQLite → Postgres by swapping SQLAlchemy URL
- **Roadmap honesty**: Auto-remediation explicitly *not* in v1 (advisory-only by design); staged rollout with config-diff preview and rollback, lab-tested first

---

## 10. Honest Boundaries (Owned Proactively)

1. **"Learning" = human-in-the-loop adaptive mapping**, not trained ML. An LLM (or offline heuristic) proposes; a named human confirms; a normalized pattern cache auto-matches future similar lines. Stated in README, code comments, and PDF report.
2. **Depth over breadth**: ~16–20 hand-verified rules per vendor instead of shallow 100+. Every rule cites its control-family mapping (labeled illustrative). A wrong mapping that reports false PASS is worse than no tool.
3. **Advisory-only remediation**: No auto-push to devices. A v1 security tool that blindly applies config changes would itself be an operational risk.
4. **Static file ingestion**: Upload-based per the PS; live SSH polling is an extension path, not a v1 gap.
5. **Unattended operation**: The human-in-the-loop gate means fully autonomous deployment is a known v1 limitation, not a solved problem.

---

## 11. Repo Layout

```
complianceforge/
├── backend/                    # FastAPI application
│   ├── app/
│   │   ├── api/               # 7 route modules (ingest, audit, devices, training, report, dashboard, chat)
│   │   ├── core/              # schema, parsers, rule_engine, rule_cache, ai_classifier, baseline_inference, report_builder
│   │   ├── models/            # SQLAlchemy ORM models
│   │   ├── main.py            # FastAPI entrypoint
│   │   └── db.py              # Database setup
│   ├── sample_configs/        # 6 synthetic fixtures (compliant + noncompliant × 3 vendors)
│   ├── app/core/rule_packs/   # 4 YAML packs (cisco_ios, juniper_srx, sonic, unseen_vendor)
│   ├── tests/                 # 11 pytest tests
│   └── requirements.txt       # 11 dependencies
├── frontend/                   # React control plane
│   ├── src/
│   │   ├── pages/             # 7 pages (Login, Dashboard, UploadIngest, Devices, DeviceDetail, TrainingLoop, ReportPreview)
│   │   ├── components/        # Header, Sidebar, Footer, ChatBot, Toast, ThemeToggle, etc.
│   │   └── lib/api.js         # Centralized fetch + JWT + hooks
│   └── package.json
├── docs/                       # ARCHITECTURE.md (≤2 pages), README
├── demo/                       # unseen_vendor_config.txt (live judge fixture, never pre-tested)
├── launch.bat / stop.bat       # Windows one-click start/stop
├── vercel.json                 # Vercel monorepo config (frontend + backend services)
└── README.md
```

### Run Commands

```bash
# Backend
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000   # /docs, /health

# Frontend
cd frontend
npm install
npm run dev              # :5173

# Tests
cd backend
python -m pytest tests -q               # 11 passed
```

**Login:** `admin` / `admin`  
**Env vars:** `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` (LLM mode; unset → offline heuristic), `CF_ADMIN_PASSWORD`, `CF_JWT_SECRET`, `CF_DB_PATH`, `CF_ALLOWED_ORIGINS`

---

## 12. Production Deployment Checklist

### Backend (Vercel / Railway / Render)
- [ ] `CF_JWT_SECRET` — required in production (app exits if missing)
- [ ] `CF_DATABASE_URL` — Postgres (Neon/Supabase/Railway); SQLite in `/tmp` is ephemeral
- [ ] `CF_ALLOWED_ORIGINS` — frontend URL (e.g., `https://complianceforge-beta.vercel.app`)
- [ ] `CF_ADMIN_PASSWORD` — change from default
- [ ] `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` — optional (enables cloud LLM mode)
- [ ] `psycopg2-binary` instead of `psycopg[binary]` for Vercel compatibility

### Frontend (Vercel)
- [ ] `VITE_API_BASE` — backend URL if separate project (e.g., `https://complianceforge-backend.vercel.app`)

---

## 13. Key Files for Deep Dive

| File | Why It Matters |
|---|---|
| `backend/app/core/schema.py` | The architectural backbone — every parser emits, rule engine consumes |
| `backend/app/core/rule_engine.py` | `_SafeEval` AST visitor proves injection-proof DSL |
| `backend/app/core/rule_cache.py` | The "learning" — pattern normalization + exact/fuzzy match |
| `backend/app/core/ai_classifier.py` | Few-shot LLM + offline heuristic + design boundary comments |
| `backend/app/core/baseline_inference.py` | Reconstructs baseline from confirmed mappings (unseen vendor path) |
| `backend/app/core/parsers/base_parser.py` | Vendor fingerprinting + autodetection logic |
| `backend/app/api/routes_training.py` | Training Loop API — the human gate endpoints |
| `backend/app/core/report_builder.py` | Professional PDF generation |
| `frontend/src/pages/TrainingLoop.jsx` | Flagship UI — queue with AI proposals, confirm/correct, one-click train |
| `backend/app/core/rule_packs/cis_cisco_ios.yaml` | Example rule pack with illustrative CIS mappings |
| `backend/tests/test_pipeline.py` | Full API flow test + evaluator safety proof |

---

*Advisory-only remediation by design; every AI-influenced finding is traceable to the human who confirmed it.*