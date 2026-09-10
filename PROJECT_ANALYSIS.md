# ComplianceForge — Complete Project Analysis

**ComplianceForge — Project Analysis**

> AI-augmented, vendor-agnostic network security compliance auditor: ingest raw CLI configs from *any* network device vendor, normalize them into one vendor-neutral security baseline, audit against CIS-style rule packs, learn unknown vendors through a human-in-the-loop training loop, and generate PDF compliance reports with exact remediation CLI.

---

## 1. The Problem

Enterprises and government networks run hybrid fleets built from many vendors — Cisco, Juniper, Palo Alto, Fortinet, white-box SONiC, niche regional vendors. Every vendor invented its own CLI grammar, and hardening frameworks (CIS Benchmarks, NIST 800-53, DISA STIGs) are written as human-readable prose, not machine-parsable rules.

**The operational gap today:**

- **Manual audits** are slow, inconsistent between auditors, and don't scale past a few dozen devices.
- **Commercial suites** (Tufin, FireMon, Titania Nipper, SolarWinds NCM) are fundamentally *libraries of pre-built vendor connectors*. A new vendor waits on the vendor's own engineering roadmap.
- **Open-source tooling** (Netmiko/NAPALM/Batfish) requires engineers to hand-write parsers per vendor — exactly the bottleneck.
- **Misconfiguration** remains a leading root cause of network breaches precisely because nobody re-audits configs continuously across a mixed fleet.

**What the problem statement asked for:** a working engine that ingests configuration files (not live SSH polling), normalizes them, scores compliance, produces a PDF report with remediation, and — the namesake twist — **learns vendors it has never seen** without a code redeploy, via an interactive training GUI.

---

## 2. The Solution — What We Built

ComplianceForge is a full-stack web application:

```
upload config ──▶ vendor autodetect (syntax fingerprints)
              ──▶ parser (deterministic regex, per vendor)
              ──▶ SecurityBaselineModel (one vendor-neutral schema)
              ──▶ rule engine (safe AST-evaluated YAML rule packs)
              ──▶ findings + compliance % ──▶ SQLite (devices, snapshots, runs, findings)
                                           ──▶ ReportLab PDF (exec summary, findings,
                                                remediation appendix, disclaimer)
                 anything unrecognized ──▶ TRAINING LOOP
```

**Flagship: the Training Loop.** For a config from a vendor the system has never seen, every unrecognized line lands in a Training Queue with an AI-proposed category. A human admin confirms or corrects — one line at a time or one-click "Train on this data". Confirmed mappings are stored as **normalized patterns** (numbers/IPs/hashes templated out), and future similar lines auto-match via exact pattern or ≥0.82 string similarity. Re-ingesting the same file fully recognizes it, and a full rule audit runs against the learned vendor. **No code redeploy ever happens.**

### 2.1 Architecture decisions that define the product

| Decision | Why it matters |
|---|---|
| **One vendor-neutral schema (the Security Baseline Model)** | The schema models security *concepts* (auth, logging, crypto, access control), not vendor CLI structure. The rule engine only ever reads this shape — never raw vendor syntax. A firewall and a switch map into the same concept buckets. Adding a vendor = writing one parser that emits this shape. |
| **The AI proposes, never decides** | The LLM only suggests a category for unknown lines. A named human admin confirms via the UI before anything enters the rule cache. Low-confidence AI classifications can never silently become a hard PASS — they either wait for a human or don't exist. |
| **Safe AST rule evaluator — never `eval`** | Rule checks are a tiny restricted DSL (`management.telnet_enabled != true and management.ssh_version == 2`) compiled through a whitelisted Python `ast` visitor. Code injection in a rule pack returns `status=error` (proven by test). |
| **Advisory-only remediation** | Remediation CLI is a recommended command sequence for a human engineer in a maintenance window — not auto-push. Blind auto-application of config changes is itself a major operational risk; this is a deliberate security scope boundary, not a gap. |
| **Offline-deterministic demo** | With no LLM API key configured, a deterministic heuristic classifier takes over so the demo never breaks in front of judges. |
| **Honest AI claims** | This is *human-in-the-loop adaptive mapping*, not autonomous ML — and the code, README, and PDF report all say exactly that. Every rule carries an "illustrative" `maps_to` citation to the CIS/NIST/STIG control family it mirrors. |

---

## 3. Backend — Deep Technical Breakdown

**Stack:** FastAPI (Python 3.11+), Pydantic v2, SQLAlchemy + SQLite, PyYAML, ReportLab, httpx, PyJWT. 11 pytest tests, all passing.

### 3.1 Module map (`backend/app/`)

| Module | Role |
|---|---|
| `main.py` | FastAPI entrypoint: CORS (5173), lifespan DB init, `/login` (JWT), `/health` (reports AI mode) |
| `db.py` | SQLite engine + session factory; `CF_DB_PATH` env override; idempotent `create_all` |
| `api/auth.py` | JWT issue/verify, `CF_ADMIN_PASSWORD` / `CF_JWT_SECRET` env-configurable |
| `api/routes_ingest.py` | `POST /ingest` — upload ≤2MB, vendor autodetect, parse, store snapshot, enrich unparsed lines via cache |
| `api/routes_audit.py` | `POST /audit/{device_id}` — run rule pack, persist run + findings |
| `api/routes_devices.py` | `GET /devices`, `GET /devices/{id}` — fleet + per-device state |
| `api/routes_training.py` | The Training Loop API: queue, classify, confirm, mappings CRUD, one-click `train-device`, stats |
| `api/routes_report.py` | `GET /report/{device_id}` — ReportLab PDF, `application/pdf` |
| `api/routes_dashboard.py` | `GET /dashboard` — fleet compliance score, severity totals, per-vendor rollup |
| `core/schema.py` | The SecurityBaselineModel (see 3.2) + 19-category taxonomy |
| `core/parsers/` | `base_parser` (vendor fingerprints + autodetect) + Cisco IOS, Juniper SRX, SONiC parsers |
| `core/rule_engine.py` | YAML pack loader, `_SafeEval` AST visitor, `run_audit`, `summarize` |
| `core/rule_cache.py` | Confirmed-mapping store: pattern normalization + exact/fuzzy match |
| `core/ai_classifier.py` | LLM few-shot classifier (Anthropic/OpenAI) + offline heuristic fallback |
| `core/baseline_inference.py` | Reconstructs a baseline for an unseen vendor purely from confirmed mappings |
| `core/report_builder.py` | ReportLab PDF: identification, executive summary, findings table, remediation appendix |
| `models/` | `Device`, `ConfigSnapshot`, `AuditRun`, `Finding`, `CommandMapping` |

### 3.2 The Security Baseline Model (`core/schema.py`)

The architectural backbone — every parser emits this, the rule engine only reads this:

```
SecurityBaselineModel
├── device          (id, vendor, hostname, os_version, model, device_type)
├── management      (ssh/telnet/http, idle timeout, banner, NTP, SNMP, CDP/LLDP)
├── auth            (password policy, AAA, default credentials, lockout)
├── logging         (remote syslog, admin-access logging, severity)
├── acl             (rules, default-deny, mgmt ACL binding, ACL logging)
├── crypto          (weak ciphers, key size, DH groups, hash algorithms)
├── services        (unused services: finger/bootp/pad/small-servers)
├── unparsed_lines  ← anything unmappable feeds the Training Loop
└── metadata        (vendor extras, transparency-only, not rule-evaluated)
```

A shared 19-category taxonomy (`ssh_policy`, `password_policy`, `acl_logging`, `zone_policy`, ...) is the single vocabulary used by parsers, the AI classifier, and the rule cache — so an AI proposal, a human confirmation, and a parser output all speak the same language.

### 3.3 Vendor autodetection & parsers

`detect_vendor()` fingerprints config syntax (Cisco `hostname`/`ip ssh`, Juniper `set system`, SONiC `sudo config`, etc.). Three deterministic regex parsers (Cisco IOS, Juniper SRX, SONiC) emit the baseline model; anything they can't confidently map goes to `unparsed_lines` with line number + context — the deliberate escape hatch that feeds the Training Loop.

### 3.4 Rule engine & packs

- 4 YAML rule packs: **Cisco IOS (20 rules), Juniper SRX (20), SONiC (16), Unseen Vendor (16)** — each rule: `rule_id`, `title`, `severity` (critical/high/medium/low), `check` (restricted DSL), `maps_to` (illustrative CIS/NIST/STIG control-family citation), `remediation_template` (vendor-correct CLI), pass/fail explanations, optional `applies_to` device class.
- Checks evaluate through `_SafeEval`, a whitelisted `ast` visitor (comparisons, boolean ops, list membership, attribute reads, arithmetic) — **never `eval`**. Malicious or malformed checks return `error`, not a crash.
- `run_audit()` sorts by severity, tags each finding `source=built_in` or `source=ai_suggested_human_confirmed` (for findings whose evidence exists only because a human confirmed an AI mapping) — the auditability requirement.
- `summarize()` computes compliance % = pass/(pass+fail), severity totals, top critical findings.

### 3.5 The AI layer (`ai_classifier.py`)

- **Few-shot LLM classification**: 24 example line→category pairs are sent with each unknown line; the model must respond only with JSON `{category, confidence, reason}`; the response is validated against the canonical taxonomy (unknown category → forced `unknown`).
- **Provider-agnostic**: Anthropic Claude (default) or OpenAI, via `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` env.
- **Graceful degradation**: no key, no network, quota failure, or unparseable LLM output → deterministic keyword-heuristic classifier (16 regex rules, confidence 0.55/0.2). Demos never break.
- **Design boundary (in code comments, README, and report)**: the LLM is never used for pass/fail verdicts.

### 3.6 The learning mechanism (`rule_cache.py` + `baseline_inference.py`)

**Rule cache** — the honest "training":
1. `normalize_pattern()` templates out variable values: quoted strings → `"<V>"`, IPs → `<IP>`, hex → `<HASH>`, numbers → `<N>`. So `ip ssh time-out 90` and `ip ssh time-out 120` collapse to one pattern.
2. Every confirmed mapping stores: normalized pattern, example line, category, `confirmed_by` (a named human), `ai_suggested` + confidence, vendor hint, timestamps, `times_matched`.
3. Matching: exact pattern first (confidence 1.0), then `difflib` similarity ≥0.82 ("set ssh timeout 30" matches a confirmed "set ssh timeout 10").

**Baseline inference** — closing the loop for unseen vendors:
1. Ingest unknown-syntax config → every substantive line is unparsed.
2. Human confirms AI-proposed categories.
3. On re-audit, `infer_baseline()` replays the config through the cache: confirmed category + **line polarity** (enable/disable verbs: `no`/`disable`/`shutdown`/`deny` vs `enable`/`permit`/`run`), weak-cipher keywords (des/3des/rc4/md5/sha1), default SNMP strings (public/private), "min" + number for password lengths, IP extraction for syslog servers — all infer a genuine `SecurityBaselineModel`.
4. The `cis_unseen_vendor.yaml` pack then audits that inferred baseline **exactly like a known vendor**, with every finding tagged `ai_suggested_human_confirmed`.

### 3.7 Training Loop API

| Endpoint | Purpose |
|---|---|
| `GET /training/queue` | Unparsed lines needing review, each with an AI proposal; skips anything the cache already auto-matches (never re-asks a human); dedupes across devices |
| `POST /training/classify` | Ask the classifier for one line (cache match first) |
| `POST /training/confirm` | **The human gate** — validates category against taxonomy, writes/updates the mapping |
| `POST /training/train-device` | One-click bulk train: AI proposals (or human `corrections` overrides) for every pending line — the endpoint *is* the human pressing "Train" |
| `GET /training/mappings` | Full mapping cache with provenance |
| `DELETE /training/mappings/{id}` | Remove a mapping |
| `GET /training/stats` | Cache stats for the dashboard |

### 3.8 Auth & security posture

- JWT (HS256) with env-configurable secret and admin password; single named admin role = the human in the loop.
- All API routes token-gated except `/login` and `/health`.
- 2MB upload cap, UTF-8 decode with replacement, slugified device IDs.
- Test `test_safety_of_evaluator` proves `__import__('os').system(...)` in a rule check returns `error` — the DSL cannot execute arbitrary code.

### 3.9 PDF report (`report_builder.py`)

Professional layout: device identification → executive summary (compliance %, severity totals) → findings table (rule ID, severity, status, evidence, control-family mapping) → remediation appendix (monospace CLI per failed rule, tagged with source) → advisory disclaimer. Footer marks every report as advisory-only with generation timestamp.

### 3.10 Tests (`backend/tests/test_pipeline.py`, 11 tests, ~1.3s)

Vendor autodetection on all 6 fixtures · Cisco compliant/noncompliant parsing · Juniper parsing · SONiC parsing · rule pack loading (≥15 rules, no duplicate IDs, per vendor) · audit scoring sanity (compliant > noncompliant; every rule lands in a definite state) · **evaluator safety (code-injection rejected)** · pattern normalization + similarity · **full API flow**: ingest → audit → PDF → classify → confirm → auto-match on similar line → unseen-vendor ingest lands in queue → dashboard · direct PDF builder.

---

## 4. Frontend — Control Plane

**Stack:** React 18 + Vite 5 + Tailwind CSS 3, react-router-dom 6. Dual theme: "Forensic Monochrome" light / "Industrial Telemetry" dark.

| Page | Function |
|---|---|
| `Login.jsx` | JWT login (admin/admin default) |
| `Dashboard.jsx` | Fleet compliance score, severity distribution, per-vendor rollup, device drill-in |
| `UploadIngest.jsx` | Config upload (drag/drop), live vendor detection feedback, unparsed-line preview, next-step guidance (`train` vs `audit`), one-click "Train on this data" for unknown vendors |
| `Devices.jsx` | Fleet table: vendor, OS, compliance %, pass/fail counts, audited state |
| `DeviceDetail.jsx` | Per-device: normalized baseline view, run audit, severity-ranked findings with evidence + remediation CLI, source tags (built-in vs AI+human-confirmed) |
| `TrainingLoop.jsx` | **The flagship UI**: pending-line queue with AI proposals (confidence + source), confirm/correct per line, mapping cache management with provenance and times-matched |
| `ReportPreview.jsx` | Dashboard-level report + per-device PDF export |
| `components/Header/Sidebar/Footer` | Live stats from `/health` + `/training/stats` (AI mode, mappings, matches) |

`lib/api.js` centralizes fetch + JWT injection + 401 auto-logout; `useApi` hook gives every page data/error/loading/reload. Vite dev server proxies `/api` → backend :8000.

---

## 5. Data Model

- **Device** — device_id, vendor, hostname, OS/model/type, `is_unseen_vendor`
- **ConfigSnapshot** — filename, raw config (kept for re-audit), normalized JSON baseline
- **AuditRun** — per audit: compliance summary
- **Finding** — per rule: status, severity, evidence, explanation, remediation, **source** (built_in / ai_suggested_human_confirmed)
- **CommandMapping** — the learning: pattern, example line, category, confirmed_by, ai_suggested, ai_confidence, vendor_hint, times_matched, timestamps

SQLite via SQLAlchemy — Postgres-swappable by changing the connection URL.

---

## 6. Demo Flow (the judge-facing script)

1. **Upload** a known-vendor config (`cisco_ios_noncompliant.cfg`) → vendor auto-detected, normalized baseline shown.
2. **Run Audit** → 20 CIS-style rules, severity-ranked findings, evidence, exact remediation CLI, compliance %.
3. **PDF report** — one click, professional evidence artifact.
4. **The differentiator:** upload `demo/unseen_vendor_config.txt` (a synthetic CLI deliberately never tested during development) → system honestly flags every line as unrecognized — it does *not* guess.
5. **Training Loop** → AI proposes categories per line with confidence; human confirms/corrects (or one-click "Train on this data").
6. **Re-ingest the same file** → every line auto-recognizes → **Run Audit** → full rule checks on a vendor that didn't exist in the codebase, findings tagged `ai_suggested_human_confirmed`.
7. **Dashboard** — fleet view across known + learned vendors, per-vendor compliance.

---

## 7. Competitive Positioning (from slide 6)

| Capability | ComplianceForge | Tufin / FireMon / Titania / SolarWinds |
|---|---|---|
| Multi-vendor automated ingestion | ✅ | ✅ (fixed vendor list) |
| Real-time JSON normalization | ✅ one vendor-neutral schema | connector-specific |
| Automated compliance auditing | ✅ CIS-style packs, safe DSL | ✅ |
| **Human-in-the-loop AI verification** | ✅ AI proposes, human confirms | ❌ |
| **Auto-generated executable fixes** | ✅ exact vendor CLI per rule | partial |
| **Zero-trust rule validation** | ✅ AST sandbox, injection-proof | n/a |
| **Learn an unseen vendor without code redeploy** | ✅ the Training Loop | ❌ — the industry gap |

The common gap across every competitor: they are all pre-built vendor-connector libraries. None can adapt to a brand-new CLI syntax without engineering work. That gap is precisely what the Training Loop closes — an administrator extends support themselves in minutes, not a vendor roadmap quarter.

---

## 8. Impact & Beneficiaries (slide 5)

- **Government / critical infrastructure (government, critical infrastructure)**: heterogeneous networks audited without depending on any single vendor's ecosystem — the sponsor's own operational pain point.
- **PSUs & state government networks**: L1-tender procurement across years/vendors creates exactly the mixed-fleet problem this solves.
- **MSSPs & audit firms**: manual multi-client audits become repeatable pipelines.
- **SMEs**: Tufin/FireMon per-device licensing is out of reach; this is priced for the Indian market.
- **Strategic sovereignty**: an India-built, vendor-agnostic compliance engine reduces reliance on foreign security tooling for government networks.
- **Security outcomes**: misconfiguration is a leading breach cause; continuous, broad auditing directly shrinks attack surface.

---

## 9. Extension Path

- **New vendors**: one `BaseParser` subclass + one YAML pack — and even before that exists, the `unseen_vendor` path makes a new vendor *usable on day zero* via the training loop.
- **New frameworks**: rule packs are data, not code — community/sector STIGs plug in as YAML.
- **Live collection**: Netmiko/NAPALM as an optional add-on for SSH polling (deliberately out of v1 scope per the PS).
- **Deploy**: FastAPI on Railway/Render, frontend on Vercel; SQLite → Postgres by swapping the SQLAlchemy URL.
- **Roadmap honesty**: auto-remediation is explicitly *not* in v1 (advisory-only by design); a staged rollout with config-diff preview and rollback, lab-tested first, is the path.

---

## 10. Honest Boundaries (own them proactively)

1. **"Learning" = human-in-the-loop adaptive mapping**, not trained ML. An LLM (or offline heuristic) proposes; a named human confirms; a normalized pattern cache auto-matches future similar lines. No false marketing — this is stated in the README, code comments, and the PDF report.
2. **Depth over breadth**: ~16–20 hand-verified rules per vendor instead of a shallow 100+. Every rule cites its control-family mapping (labeled illustrative). A wrong mapping that reports false PASS is worse than no tool — so rules were encoded carefully, not bulk-generated.
3. **Advisory-only remediation**: no auto-push to devices. A v1 security tool that blindly applies config changes would itself be an operational risk.
4. **Static file ingestion**: upload-based per the PS; live SSH polling is an extension path, not a v1 gap.
5. **Unattended operation**: the human-in-the-loop gate means fully autonomous deployment is a known v1 limitation, not a solved problem.

---

## 11. Repo Layout & Run

```
backend/           FastAPI app — parsers, rule engine, packs, AI layer, reports, tests
  sample_configs/  6 synthetic fixtures (compliant + noncompliant × 3 vendors)
  app/core/rule_packs/  4 YAML packs (cisco_ios, juniper_srx, sonic, unseen_vendor)
frontend/          React control-plane UI
docs/              ARCHITECTURE.md (≤2 pages) + README
demo/              unseen_vendor_config.txt (live judge fixture, never pre-tested)
launch.bat / stop.bat  Windows one-click start/stop
```

```bash
# backend
cd backend && pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000   # /docs, /health

# frontend
cd frontend && npm install && npm run dev              # :5173

# tests
cd backend && python -m pytest tests -q               # 11 passed
```

Login: `admin` / `admin`. Env: `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` (LLM mode; unset → offline heuristic), `CF_ADMIN_PASSWORD`, `CF_JWT_SECRET`, `CF_DB_PATH`.

---

*Advisory-only remediation by design; every AI-influenced finding is traceable to the human who confirmed it.*
