# ComplianceForge — Switch Context (Main Round)

> Last updated: 2026-09-19 | Use this file to resume work after switching models (OpenCode / ChatGPT / Muse Spark). Copy the **PASTE TO NEW MODEL** block into the new session.

## 1. What ComplianceForge Is

AI-augmented, vendor-agnostic network security compliance auditor:

- **Ingest** raw CLI configs (Cisco IOS, Juniper SRX, SONiC, + unknown vendors) -> vendor autodetect (`core/parsers/base_parser.py:52 detect_vendor`) -> deterministic regex parsers -> `SecurityBaselineModel` (`core/schema.py:132`) — one vendor-neutral shape.
- **Audit** against CIS-style YAML rule packs (16-20 rules/vendor, `core/rule_engine.py` safe AST evaluator, never `eval`) -> findings + compliance % -> SQLite (`Device`, `ConfigSnapshot`, `AuditRun`, `Finding`, `CommandMapping`).
- **Training Loop**: anything unparsable -> `unparsed_lines` -> Training Queue with AI-proposed category -> human confirms (`POST /training/confirm`) -> normalized pattern cache (`core/rule_cache.py:31 normalize_pattern`, `similarity >=0.82`) auto-matches future similar lines. Re-ingest same file -> fully recognized -> full audit with `ai_suggested_human_confirmed` tags. One-click `POST /training/train-device`.
- **Report**: ReportLab PDF (exec summary, findings table, remediation appendix, advisory-only disclaimer).
- **Frontend**: React 18 + Vite 5 + Tailwind (Dashboard, UploadIngest, Devices, DeviceDetail, TrainingLoop, ReportPreview).

**Design boundaries (deliberate):** advisory-only remediation (no auto-push), file upload (no live SSH polling in v1), depth-of-correctness (~16-20 hand-verified rules/vendor), AI proposes never decides.

## 2. Repo Layout & How to Run

```
backend/           FastAPI app — parsers, rule engine, packs, AI layer, reports, tests
  sample_configs/  6 synthetic fixtures (cisco/juniper/sonic x compliant/noncompliant)
  app/core/rule_packs/  4 YAML packs (cisco_ios, juniper_srx, sonic, unseen_vendor)
  app/models/mapping.py  CommandMapping (pattern, vendor_hint unique)
frontend/          React control-plane UI
docs/              ARCHITECTURE.md (≤2 pages)
demo/              unseen_vendor_config.txt (26 lines, live judge fixture)
```

```bash
# backend (Python 3.12.10, win32)
cd backend && pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000   # /docs, /health
# frontend
cd frontend && npm install && npm run dev              # :5173
# tests (11 tests, throwaway SQLite test_cf.db)
cd backend && python -m pytest tests -q
```

Env: `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` (LLM mode; unset -> offline heuristic), `CF_ADMIN_PASSWORD`/`CF_JWT_SECRET`/`CF_DB_PATH`, `CF_USE_LOCAL_LM=1` + `CF_LOCAL_LM_URL=http://localhost:1234` (optional LM Studio, heavy models ~30-60s/line).
Login: `admin` / `admin`.

## 3. Judge Feedback & Required Narrative Fix

Internal round cleared. Judge critique: "Making it deterministic will increase file size as every time it gets unknown it will map it and store — which would be wrong."

**Current mechanism (the flaw):** `rule_cache.py:normalize_pattern` + `CommandMapping` = 1 DB row per unknown pattern forever. 10k devices -> 10k rows. Wrong confirm persists + auto-matches via `similarity >=0.82`. No generalization, no accuracy metric, no rollback — a cache, not learning.

**Use this exact sentence going forward (slide + README + report):**

> Human-verified mappings are continuously added to the learning dataset and used for periodic model updates/fine-tuning.

What it means in engineering: dataset is source of truth (versioned, correctable), runtime is fixed-size model file (~1-5MB, constant whether 1k or 100k examples), updates are accuracy-gated + rollbackable. Storage O(model size) not O(unknowns).

## 4. Agreed Architecture (Locked)

```
unknown line
  -> L1 exact cache (existing RuleCache, now BOUNDED + high-precision only)
  -> L2 TRAINED model (new: sklearn TF-IDF + LogisticRegression, ~100KB-5MB file)
  -> L3 fallback (existing LLM/heuristic, true zero-shot only)

Human confirm (POST /training/confirm, train-device)
  -> appends to learning dataset (immutable log; corrections = deprecate old + insert new)
  -> periodic retrain job (80/20 stratified split, promote only if accuracy >= current -0.02)
  -> versioned artifact: model_vN.pkl/json + metadata.json {version, trained_at, n_examples, accuracy, per_category_F1}
  -> rollback: POST /training/model/rollback/{version}
  -> export: GET /training/dataset/export (JSONL {text,label} for future LLM fine-tune)
```

Wiring: unify chain in `ai_classifier.py` (one `classify(line) -> {category, confidence, source, model_version}`), used by BOTH `routes_training.py:queue/classify` and `routes_ingest.py` enrichment. `/health` + dashboard header show `dataset_size, model_version, accuracy`.

## 5. Model Decision (Locked)

**sklearn TF-IDF + LogisticRegression** (chosen over MiniLM+SetFit/ONNX and pure-Python Naive Bayes).
- Why: ~1,500 examples is ideal for sklearn (80-90% expected), Docker stays ~200MB (+~30MB for sklearn), trains in seconds (demoable live), no GPU/torch, fully offline, no download at demo time.
- MiniLM+SetFit (~80MB) + onnxruntime only wins under ~500 examples or heavy paraphrase; generative models (SmolLM2-360M, Qwen0.5B, TinyLlama) are 10-50x bigger/slower — keep existing LM Studio as optional L3 fallback, not trained model.
- Code interface kept swappable: `predict(text) -> (category, confidence)` so future upgrade is drop-in.

## 6. Dataset Spec

**19 SECURITY_CATEGORIES** (`core/schema.py:148`): `management_protocol`, `ssh_policy`, `authentication`, `aaa`, `password_policy`, `logging`, `syslog`, `access_control`, `acl_logging`, `cryptography`, `snmp_management`, `ntp`, `service_hardening`, `banner`, `privilege_escalation`, `routing_integrity`, `interface_security`, `zone_policy`, `unknown`.

Target: **~1,200–1,500 balanced lines (~50–80/category)** -> 80/20 stratified (1200 train / 300 test -> ~15 per class in test). Below ~500 total, report per-category F1 qualitatively.
Rules: balance rare classes (zone_policy, routing_integrity, privilege_escalation, unknown are thin in sample_configs), vendor + value diversity (2-3 phrasings per concept, varied IPs/numbers/hostnames), dedupe by `normalize_pattern`. Verified > synthetic (~3-5x value).

## 7. Data Sources Evaluated

**Government-provided pointers (verified 2026-03 via search):**

| Source | Where to get | What it gives | How we use | License note |
|---|---|---|---|---|
| **DISA STIGs** (BEST FOR TRAINING) | `https://public.cyber.mil/stigs/downloads` (no-CAC mirror) + `ncp.nist.gov` checklist zips + `stigviewer.com` browse | XCCDF XML: rule severity + check text (exact CLI to verify) + fix text (exact remediation CLI) + CCI->NIST mapping. Cisco IOS XE Router/Switch STIG, Juniper SRX STIG, Palo Alto/Fortinet NDM STIGs all there. | Write XCCDF->dataset parser (section->19 categories map). One STIG yields 500-1,000 labeled lines. Pre-labeled by section — highest value. | US public release, check each zip disclaimer |
| **CIS Benchmarks** | `https://portal.cisecurity.org/benchmarks` (free account, free PDFs, non-commercial ok for SIH). Covers Cisco, Juniper, Palo Alto, Fortinet, Check Point, F5, Arista, Aruba, pfSense. | Each recommendation = audit CLI + remediation CLI + rationale + CIS CSC mapping | Mine for labels + grow rule packs beyond 16-20 hand-written. Prioritize Cisco + Juniper PDFs only (PDFs not machine-readable, semi-manual). | Free non-commercial + attribution |
| **NIST SP 800-53 Rev5** | OSCAL JSON `github.com/usnistgov/oscal-content/nist.gov/SP800-53/rev5/json/` + PDF `nvlpubs.nist.gov/.../NIST.SP.800-53r5.pdf` | Control catalog (what to enforce), not CLI | Replace "illustrative" `maps_to` with real IDs (AC-2, IA-5, SC-12) for credibility | Public domain |
| **ISO/IEC 27001** | Not fetchable as open data (paid standard) — cite mapping only | - | - | - |
| **NCIIPC** `nciipc.gov.in`, `helpdesk1@nciipc.gov.in` | Guidelines PDFs site-wide | Policy PDFs, coordination contact | Cite "aligned with national CII guidance" + email only for permission/clarification; don't plan dataset around reply | - |
| **Vendor CLI samples** | `batfish/batfish` repo (Apache-2.0), `ntc-templates` (mostly show outputs, skip) | Thousands of real-syntax configs (Cisco IOS/XE/XR/NX-OS/ASA, JunOS, Palo Alto, Fortinet, SONiC, Arista) | Extra parser fixtures + positive/negative audit cases | Apache-2.0 with citation |

**Friend's dataset:** `C:\Users\Farhan Ali\Downloads\complianceforge-network-dataset-main\complianceforge-network-dataset-main\Data` (collaborator access; 404 if private to anonymous fetch; works locally via extracted zip).
- **1,876 files, 9.8 MB**: 1310 .cfg, 330 .txt, 144 .json, 82 no-ext, 10 .conf. README empty, **zero labels**.
- Content: mostly Batfish routing test topologies (`cbver_reach/hijack/vf` series: interfaces/IPs/hostnames, ~0 security lines in 200-file sample). Bright spots: fortios fw files (~335 hits each), `ios_example` (12-27 hits), juniper (~10 hits). Duplicates exist. Checkpoint JSONs = CheckPoint mgmt-API JSONs — wrong modality, drop (keep 1-2 as negatives max).
- Verdict: **not trainable as-is**, but useful raw material. Plan: filter CLI configs, dedupe by content hash, keyword-sieve security lines, heuristic propose -> human verify ~200-300 ambiguous lines, merge with STIG-mined labels.

## 8. Current State & Todo (updated 2026-09-19, evening session)

Done:
- Evaluated govt sources + friend dataset (file counts, sizes, security-line density, modality).
- Locked architecture + model choice + dataset spec.
- Sieved friend data (5,158 candidates) + parsed 9 STIG XCCDFs (891 rows) + built
  1,323-row balanced dataset (53-80/category, 0 conflicting patterns).
- Shared `backend/app/core/line_override.py`: high-precision line->category table
  used by BOTH parse_stig.py and build_seed_dataset.py (rulepack/sample/sieve lines).
- Trained v1-v12; 3-layer chain + retrain/rollback/export APIs + /health + dashboard
  header wired; 23 tests green; fresh-DB unseen loop verified offline
  (12 unparsed -> queue -> train -> 12/12 recognized -> 16 findings all
  ai_suggested_human_confirmed -> PDF).
- REGRESSION DIAGNOSIS (v4 84.96% -> v6+ ~79%): root causes were (1) STIG
  section-first labeling (session/timeout rule swallowed SSH/crypto; one rule's fix
  text mixes heterogeneous lines), (2) multi-line rulepack templates inheriting one
  category, (3) identical lines under two labels across sources, (4) JunOS block-opener
  fragments as false attractors. Fixed 1-4; STIG error rate 61% -> 9%.
  Residual plateau (~76-80% holdout, ~66% 5-fold CV) is diffuse boundary noise
  (logging/syslog/auth/aaa overlap), NOT one poison source (ablation: no-sieve 74%,
  no-stig breaks rare-class coverage). Serving stays v4 per accuracy gate;
  v10/v11/v12 recorded as correctly-REJECTED candidates (gate working as designed).
- SERVING: model v4 (acc 0.8496, n=1226, 841KB). Dataset has since grown to 1323;
  next promotion requires >= 0.8296.

Pending (P0 order):
1. [BLOCKED-USER] Docker build test — no Docker daemon on dev machine. Static review
   passed (artifacts ship via COPY app, sqlite default writable, sklearn pinned).
   User runs: `docker compose up --build`, then unseen loop once at :5173/:8000.
2. [PENDING-USER] 30-min label review on boundary rows I flag (logging/syslog/auth).
3. [AGENT, quick] `git commit` all below.
4. P1: quality guards visible, model card + dataset stats page, README 1-pager update.

## 15. SESSION RESUME — open a new session and paste this whole section

Date: 2026-09-19/20 (late night). User said "still fixes to do, continue tomorrow."
No briefing needed beyond this file.

### Git state (verify first with `git status --short`)
- On `main` (PR #1 merged: 11339f8). The entire 7-item trust-hardening work below
  is UNCOMMITTED on top of main: 22 modified + 3 new files
  (`backend/app/core/training_data/holdout.jsonl`, `backend/tests/conftest.py`,
  `backend/tests/test_trust.py`). `login.json` untracked (leave it).
- Serving model: v4 (acc 0.8496), 13 versions in metadata. Dataset 1,323 rows.
  Suite: 36/36 green (`cd backend && python -m pytest tests -q`).

### What was built this session (all in working tree, tested)
1. `rule_cache.py`: strict vendor isolation (no cross-vendor fallback), no
   250-char truncation (Text column), COMMAND_TEMPLATES + extract_slots
   (secrets redacted) + value_drift, confirm() stores server provenance.
2. `models/mapping.py`: ProposalRecord append-only table; CommandMapping +
   slots_json/proposal_source/proposal_confidence/model_version/last_reviewer.
   `models/finding.py`: provenance_json. `db.py`: _ensure_columns migration.
3. `routes_training.py`: ConfirmRequest WITHOUT identity fields (JWT sub used);
   server recomputes proposal; decision log; GET /training/decisions;
   train-device = explicit approvals + unparsed-only + unknown rejected +
   low-conf needs human_reviewed + dry_run summary; retrain rate-limited 5/10min.
4. `trained_classifier.py`: candidates never touch current_version; frozen
   163-row holdout.jsonl (strided); overall + per-category (ssh_policy, mgmt)
   gates; atomic promote; sha256 recorded + verified on load.
   v14 live test REJECTED on per-category gates (4 ambiguous rows) — keep it
   that way; serving v4 stands. Do NOT manually promote; the rejection is the story.
5. `routes_audit.py` + `baseline_inference.py`: per-line provenance, finding
   provenance {adapter, mapping_ids, reviewers}, summary.provisional +
   confidence_note; infer takes vendor_hint (no more "any" leak).
6. `auth.py`: refuses default creds without CF_DEV_ALLOW_DEFAULTS=1
   (conftest.py + launch.bat set it). `ai_classifier.py`: OpenAI→OpenAI /
   Anthropic→Anthropic dispatch fixed (_classify_openai was dead code).
7. `tests/test_trust.py` (12 tests) + conftest prune helper + isolated dataset
   fixture; test_model/test_pipeline/test_security updated to new contracts.
   Frontend: TrainingLoop bulk dry-run/approve panel + no forged fields;
   DeviceDetail/UploadIngest one-click → queue links; 0.82-similarity claims removed.
8. README + this file updated. Demo-fixture rows appended to dataset.jsonl by
   verification scripts were REVERTED (keep demo out of training data).

### Known remaining fixes / next actions (user: "still fixes, tomorrow")
- [ ] Commit trust work: branch `feat/trust-hardening` → 3-4 grouped commits
  (backend trust, promotion flow, tests, frontend+docs) → push → PR → merge.
  Follow skills/committing-changes (feature branch + PR, never push main).
- [ ] Docker live run still blocked (no daemon on dev box): `docker compose up
  --build` + unseen loop once. Static review already passed.
- [ ] 30-min label review: boundary rows (logging/syslog/auth) still the
  accuracy drag; 5-fold CV ~0.66 vs holdout ~0.80 — thin classes qualitative.
- [ ] Optional P1: decisions-log UI section in TrainingLoop; PDF report
  provenance appendix; grow holdout as dataset grows (currently 163).
- [ ] Scratch scripts live OUTSIDE repo (do not commit):
  C:\Users\FARHAN~1\AppData\Local\Temp\opencode\audit_all.py,
  verify_trust.py, diagnose.py, ablate.py, cvtest.py, make_holdout.py,
  backfill.py, rebuild.py, diff_stig.py. Re-run backfill.py after any
  metadata reset. Friend STIG sources: Downloads/iosxe-ansible,
  Downloads/junos-ansible, Downloads/U_Cisco_IOS-XE_Switch_Y26M04_STIG.
- [ ] Test-hygiene rules learned: shared test_cf.db persists — trust tests use
  unique device ids + fixture cleanup; retrain tests must prune candidates
  above pre-existing MAX (never above serving — that deleted committed v5-v13
  once); trust API tests redirect DATASET_PATH to tmp.

### Resume commands
```powershell
cd C:\Users\Farhan` Ali\Desktop\complianceforge   # backtick-escapes space if needed
git status --short --branch
cd backend; python -m pytest tests -q   # expect 36 passed
python ..\..\FARHAN~1\AppData\Local\Temp\opencode\verify_trust.py  # full loop
```

## 14. Trust hardening session (ChatGPT audit → implemented, all green)

ChatGPT Plus adversarial audit returned a 7-item trust list; ALL implemented on
top of main (uncommitted — say the word to commit):
1. Cache isolation: find_by_pattern never falls back cross-vendor; patterns no
   longer truncated (Text column + pg migration); per-command typed slots
   (COMMAND_TEMPLATES, secrets redacted) with value_drift reporting; slots feed
   baseline inference (ssh_version, min_length).
2. Auditable confirmations: confirmed_by/ai_* removed from request bodies;
   reviewer from JWT; server recomputes proposal; every decision appends
   ProposalRecord (GET /training/decisions); corrections append, never rewrite.
3. Bulk training: explicit approvals only (line_number+raw_line vs unparsed set),
   unparsed-only, unknown always rejected, low-conf requires human_reviewed,
   dry_run summary ("N lines across M patterns"); UI: TrainingLoop bulk panel,
   DeviceDetail/UploadIngest one-click → queue review links.
4. Real promotion: candidates never touch current_version; immutable 163-row
   holdout.jsonl (strided, frozen, committed); overall + per-category
   (ssh_policy, mgmt_protocol) gates; atomic single-write promote; v14 live test
   REJECTED on per-category gates (4 ambiguous rows) while serving v4 — gates work.
5. Evidence adapter: category routes into reviewed extractor; findings carry
   provenance {adapter, mapping_ids, reviewers}; audits flag provisional +
   confidence_note when AI-derived/unresolved remain.
6. Hardening: startup refuses default creds without CF_DEV_ALLOW_DEFAULTS=1
   (conftest sets it; launch.bat sets it); retrain rate-limited 5/10min;
   OpenAI→OpenAI / Anthropic→Anthropic dispatch fixed (_classify_openai was dead);
   sha256 recorded + verified on every artifact load.
7. Tests: 36/36 green (12 new test_trust.py + dev-defaults test). Retrain tests
   prune their candidate artifacts; trust API tests use isolated dataset file.
   Serving: v4 (0.8496). Fresh-DB verify: 12 unparsed → forged confirm attributed
   admin → dry-run → 11 trained → 12/12 recognized → 16 findings all provenanced →
   provisional → PDF.

P1 (after P0 green): quality guards visible (low-confidence stays queued, disputed patterns excluded, thin-category warnings), model card + dataset stats page/doc, README/ARCHITECTURE 1-pager update.
OUT until after submission: LLM fine-tuning, generative models, GPU, live SSH polling, auto-remediation push, Postgres/Redis/K8s.

## 9. Who Does What

- **Agent (me) does:** all code — dataset scripts, classifier, wiring, APIs, Docker, tests, docs.
- **User does:** (1) download STIG zips + tell path, (2) optional CIS account/PDFs, (3) run `docker compose up` + click unseen loop once, (4) 30-min label review on 30-50 ambiguous lines I flag, (5) submit + video/recording, (6) tell me video length limit + submission checklist when known.
- **Together:** confidence threshold tuning (propose 0.7 -> verify on 10 queue lines), fresh-DB rehearsal before recording.
- **Review split:** build with this agent; one adversarial audit pass with ChatGPT Plus over finished state (give it ARCHITECTURE + model card + ai_classifier.py + routes_training.py + rule_cache.py, ask for file:line + severity ranking).

## 10. Key File References

- `backend/app/core/rule_cache.py:31` normalize_pattern, `backend/app/core/ai_classifier.py:98` heuristic_classify, `backend/app/core/schema.py:148` SECURITY_CATEGORIES, `backend/app/core/schema.py:132` SecurityBaselineModel
- `backend/app/api/routes_training.py:56` queue/classify/confirm/train-device, `backend/app/api/routes_ingest.py:30` ingest + cache enrichment, `backend/app/core/baseline_inference.py:75` infer_baseline, `backend/app/main.py:118` /health ai_mode
- `backend/sample_configs/*.cfg` (6 fixtures), `demo/unseen_vendor_config.txt` (26 lines), `backend/app/core/rule_packs/*.yaml` (4 packs)
- Friend data: `C:\Users\Farhan Ali\Downloads\complianceforge-network-dataset-main\complianceforge-network-dataset-main\Data` (extracted zip)
- Training data target: `backend/app/core/training_data/` (create; dataset.csv/jsonl) + `backend/app/core/model_artifacts/` (model_vN.pkl, metadata.json) + `backend/scripts/` (build_seed_dataset.py, parse_stig.py, sieve_dataset.py)

## 11. PASTE TO NEW MODEL

Copy below into new OpenCode session with OpenAI key:

```
You are resuming work on ComplianceForge — vendor-agnostic network compliance auditor. Repo: C:\Users\Farhan Ali\Desktop\complianceforge | Stack: FastAPI+Pydantic2+SQLAlchemy/SQLite, React+Vite, Python 3.12.10 win32, no sklearn yet | Run: backend uvicorn :8000, frontend npm dev, pytest -q (11 tests) | Login admin/admin

Judge fix sentence to use: "Human-verified mappings are continuously added to the learning dataset and used for periodic model updates/fine-tuning." Old mechanism (rule_cache.py:31 normalize_pattern + difflib >=0.82 -> CommandMapping) = 1 row per unknown forever -> unbounded + error amplification; new: 3-layer L1 exact cache (bounded) -> L2 sklearn TF-IDF+LogReg (~1-5MB fixed) -> L3 LLM/heuristic; dataset is source of truth, retrain 80/20 promote if acc >= current-0.02, rollbackable.

Model LOCKED: sklearn TF-IDF+LogReg (over MiniLM+SetFit/ONNX — too big/slow for this). MiniLM stays as slide "scaling path" only.

Dataset: 19 categories (schema.py:148) target 1,200-1,500 balanced (~50-80/cat), 80/20 stratified. Govt sources verified: STIGs (public.cyber.mil/stigs/downloads + ncp.nist.gov zips, XCCDF XML with fix CLI = best labels), CIS PDFs (portal.cisecurity.org/benchmarks free account), NIST OSCAL JSON (github.com/usnistgov/oscal-content SP800-53 rev5). Friend data at Downloads/.../Data: 1,876 files 9.8MB, zero labels, mostly Batfish routing topologies (~0 sec lines/sample) + fortios/ios_example/juniper bright spots; 144 JSONs drop; dedupe+sieve+human-verify ~200-300 lines.

Todos: [1 IN PROGRESS] sieve friend data [2 PENDING-USER] STIG zips -> XCCDF parser [3] merge dataset [4] train sklearn v1 + evaluate + versioned artifact [5] wire chain + retrain/rollback/export APIs + Docker + tests green. User tasks: STIG zips path, optional CIS PDFs, docker run check, 30-min label review, submit/video. Build with you, audit once with ChatGPT Plus after green (give ARCHITECTURE+model card+ai_classifier/routes_training/rule_cache, ask file:line severity ranking).

Next: continue sieve script on friend Data folder; ask user for STIG zip path to build parser; then generate balanced dataset.
Key files: rule_cache.py:31, ai_classifier.py:98, schema.py:148, routes_training.py:56, routes_ingest.py:30, baseline_inference.py:75, sample_configs/*.cfg, demo/unseen_vendor_config.txt
```

## 12. Quick Resume Commands

```powershell
# Resume sieve (agent)
# Sieve script target: friend Data -> backend/app/core/training_data/candidates.jsonl
# After STIG zip dropped:
# python backend/scripts/parse_stig.py <path/to/STIG.zip> --out backend/app/core/training_data/stig_labels.jsonl
# python backend/scripts/build_seed_dataset.py  # merges stig + sieve candidates + heuristic proposals
# pip install scikit-learn  # then train
python -m pytest backend/tests -q
```

## 13. Video Script Outline (deferred, ~5 min)

0:00 one-liner + 3 bullets | 0:30 known vendor upload->audit one finding | 1:30 PDF | 2:00-3:30 unseen vendor unknown->train->re-audit (differentiator) | 3:30 model proof (dataset N, model vN, acc X%, fixed size) | 4:15 fleet + close + boundaries (advisory-only, human confirms). Need length limit + submission checklist from user.
