# ComplianceForge — Architecture

## 1. Purpose

ComplianceForge is an AI-augmented, vendor-agnostic network security compliance
auditor. It ingests raw CLI configuration files from network devices (Cisco IOS,
Juniper SRX, SONiC), normalizes them into one vendor-neutral security baseline
schema, audits them against CIS-style hardening rule packs, routes unrecognized
commands into a human-in-the-loop training loop, and generates a professional
PDF compliance report with severity-ranked findings and exact remediation CLI.

**Deliberate v1 boundaries:** static file upload only (no live device polling),
advisory-only remediation (no auto-push — a security decision, not a gap), and
depth over breadth (~16-20 hand-verified rules per vendor instead of a shallow
100+).

## 2. The architectural backbone: the Security Baseline Model

Every vendor parser emits the same Pydantic shape (`app/core/schema.py`), and
the rule engine only ever reads this shape — never raw vendor syntax:

```
SecurityBaselineModel
├── device        (id, vendor, hostname, os_version, ...)
├── management    (ssh/telnet/http, idle timeout, banner, NTP, SNMP, CDP/LLDP)
├── auth          (password policy, AAA, default credentials, lockout)
├── logging       (remote syslog, admin-access logging, severity)
├── acl           (rules, default-deny, mgmt ACL binding, ACL logging)
├── crypto        (weak ciphers, key size, DH groups, hash algorithms)
├── services      (unused services: finger/bootp/pad/small-servers)
└── unparsed_lines  ← anything the parser can't map feeds the Training Loop
```

**Why this generalizes:** the schema models security *concepts* (auth,
logging, crypto, access control), not vendor CLI structure. A firewall and a
switch map into the same concept buckets even when some buckets are empty for
a device class. Adding a vendor = writing one parser that emits this shape.

## 3. Pipeline

```
upload config ──▶ vendor autodetect (syntax fingerprints)
             ──▶ parser (deterministic regex, per vendor)
             ──▶ SecurityBaselineModel  ──▶ rule engine (safe AST-evaluated checks
                                           against YAML rule packs, 16-20 rules/vendor)
             ──▶ findings + compliance % ──▶ SQLite (devices, snapshots, runs, findings)
                                          ──▶ ReportLab PDF (identification, executive
                                               summary, findings w/ source, remediation
                                               appendix, advisory disclaimer)
```

Rule checks are written in a tiny restricted DSL (`management.telnet_enabled
!= true and management.ssh_version == 2`) and evaluated through a whitelisted
Python `ast` visitor — never `eval`. Each rule carries an honest `maps_to`
citation labeled "illustrative mapping" to the CIS/NIST/STIG control family
it mirrors, plus a vendor-correct remediation template.

## 4. The Training Loop (flagship differentiator)

The "learning" is deliberately **not** a trained ML classifier — it is
human-in-the-loop adaptive mapping, and we say exactly that:

1. Parser emits `unparsed_lines` for anything unrecognized.
2. **AI proposes, never decides:** `ai_classifier.py` sends each unknown line
   to an LLM (Claude/OpenAI, few-shot) that returns a *suggested* category +
   confidence. With no API key it falls back to a deterministic offline
   heuristic so demos never break.
3. A human admin reviews in `TrainingLoop.jsx` and confirms/corrects/rejects.
4. Only on confirm does `rule_cache.py` store a **normalized pattern**
   (numbers/IPs/hashes templated out: `ip ssh time-out 90` → `ip ssh time-out
   <N>`) plus `confirmed_by` and timestamp.
5. Future similar lines auto-match via exact pattern or ≥0.82 string
   similarity — "set ssh timeout 30" matches a confirmed "set ssh timeout 10"
   without re-asking.
6. PDF reports mark which findings derive from AI-suggested-then-human-
   confirmed mappings vs built-in rules — the auditability requirement.

Low-confidence AI classifications can never silently become a hard PASS:
they either wait for a human or don't exist.

## 5. Stack

| Layer | Choice |
|---|---|
| API | FastAPI (Python 3.11+), auto OpenAPI docs at `/docs` |
| Persistence | SQLite + SQLAlchemy (Postgres-swappable) |
| Parsing | Deterministic regex → Pydantic normalization |
| AI layer | Anthropic Claude API (few-shot) with offline heuristic fallback |
| Rule engine | YAML packs + safe AST evaluator |
| Reporting | ReportLab |
| Frontend | React + Vite + Tailwind; dual theme: "Forensic Monochrome" light / "Industrial Telemetry" dark |
| Auth | JWT, single named admin role (the human in the loop) |

## 6. Extension path

- **New vendors:** implement one `BaseParser` subclass + one YAML rule pack.
  The `unseen_vendor` path already routes unknown syntax to the Training Loop,
  so an unseen vendor is *usable* on day zero (classified via cache/similarity)
  before a full parser exists.
- **Deploy:** FastAPI on Railway/Render, frontend on Vercel; SQLite → Postgres
  by swapping the SQLAlchemy URL.
