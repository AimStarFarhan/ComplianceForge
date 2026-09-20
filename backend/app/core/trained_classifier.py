"""L2 trained model: sklearn TF-IDF + LogisticRegression (fixed-size artifact).

Design (per SWITCH_CONTEXT locked architecture):
  - Dataset is the source of truth (training_data/dataset.jsonl, versioned,
    correctable). Runtime is a fixed-size model file (~100KB-5MB, constant
    whether 1k or 100k examples). Storage O(model size), not O(unknowns).
  - Promotion is REAL and atomic: candidates train WITHOUT touching
    current_version, then candidate and incumbent are scored on ONE IMMUTABLE
    holdout set (training_data/holdout.jsonl, frozen). Promotion happens in a
    single metadata write only if the overall gate (acc >= current - 0.02)
    AND per-category gates (no material F1 drop on guarded categories) pass.
    A below-threshold candidate never becomes the active model, even briefly.
  - Rollback points current_version at any existing artifact (explicit human
    action, always allowed).
  - Interface is swappable: predict(text) -> (category, confidence) so a
    future MiniLM/SetFit upgrade is drop-in.

Artifact layout (model_artifacts/):
  model_v{N}.pkl   pickle {vectorizer, clf, labels, version}
  metadata.json    {current_version, versions: [{version, trained_at,
                   n_examples, accuracy, per_category_f1, holdout_accuracy,
                   holdout_f1, sha256, status, model_file, size_bytes}]}
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

MODEL_DIR = Path(__file__).parent / "model_artifacts"
DATASET_PATH = Path(__file__).parent / "training_data" / "dataset.jsonl"
HOLDOUT_PATH = Path(__file__).parent / "training_data" / "holdout.jsonl"
METADATA_PATH = MODEL_DIR / "metadata.json"

CONFIDENCE_THRESHOLD = 0.7  # below this, L2 abstains -> L3 fallback

# Promotion gates (measured on the immutable holdout, candidate vs incumbent).
GATE_TOLERANCE = 0.02  # overall accuracy may not drop more than this
# Guarded categories: a material F1 regression here rejects the candidate
# even if overall accuracy passes (averages hide per-class damage).
GATED_CATEGORIES = {"ssh_policy": 0.05, "management_protocol": 0.05}

_cache: dict = {}


def _load_metadata() -> dict:
    if METADATA_PATH.exists():
        try:
            return json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_sha256(path: Path, expected: str | None) -> None:
    """Refuse to unpickle an artifact whose hash doesn't match metadata.

    Model files are privileged: only the training job writes them. A hash
    mismatch means tampering or corruption -- fail closed, never load.
    Entries written before hashing existed (no sha256 recorded) load with
    no verification (legacy path, logged by callers that care).
    """
    if not expected:
        return
    actual = _sha256(path)
    if actual != expected:
        raise ValueError(f"Artifact {path.name} failed integrity check (sha256 mismatch) -- refusing to load")


def get_model_info() -> dict:
    """Current version info for /health, dashboard header, model/info API."""
    meta = _load_metadata()
    versions = meta.get("versions", [])
    current = meta.get("current_version", 0)
    for v in reversed(versions):
        if v.get("version") == current:
            return {
                "model_version": current,
                "trained_at": v.get("trained_at"),
                "n_examples": v.get("n_examples", 0),
                "accuracy": v.get("accuracy"),
                "per_category_f1": v.get("per_category_f1", {}),
                "holdout_accuracy": v.get("holdout_accuracy"),
                "holdout_f1": v.get("holdout_f1", {}),
                "status": v.get("status", "serving"),
                "model_file": v.get("model_file"),
                "size_bytes": v.get("size_bytes", 0),
                "available_versions": [x.get("version") for x in versions],
            }
    # no model yet: report dataset size so UI can show "not trained"
    n = 0
    if DATASET_PATH.exists():
        try:
            with open(DATASET_PATH, encoding="utf-8") as f:
                n = sum(1 for line in f if line.strip())
        except OSError:
            n = 0
    return {
        "model_version": 0,
        "trained_at": None,
        "n_examples": n,
        "accuracy": None,
        "per_category_f1": {},
        "model_file": None,
        "size_bytes": 0,
        "available_versions": [],
    }


def dataset_size() -> int:
    if not DATASET_PATH.exists():
        return 0
    try:
        with open(DATASET_PATH, encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0


def append_example(text: str, label: str, source: str = "human-confirm") -> bool:
    """Append a human-verified mapping to the learning dataset (immutable log).

    Human-verified mappings are continuously added to the learning dataset
    and used for periodic model updates/fine-tuning. Corrections are handled
    by appending the corrected row (the dataset is an append-only log; the
    runtime cache holds the latest decision per pattern). Returns True if
    appended, False if the exact (pattern, label) row already exists.
    """
    from app.core.rule_cache import normalize_pattern

    t = (text or "").strip()
    if not t or not label:
        return False
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    pat = normalize_pattern(t)
    if DATASET_PATH.exists():
        try:
            with open(DATASET_PATH, encoding="utf-8") as f:
                for raw in f:
                    try:
                        obj = json.loads(raw)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if normalize_pattern(str(obj.get("text", ""))) == pat and str(
                        obj.get("label", "")
                    ) == label:
                        return False
        except OSError:
            pass
    try:
        with open(DATASET_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps({"text": t, "label": label, "source": source}) + "\n")
        return True
    except OSError:
        return False


def _load_bundle(version: int | None = None):
    """Load (and cache) a model bundle. version=None -> current."""
    import pickle

    meta = _load_metadata()
    versions = meta.get("versions", [])
    if not versions:
        return None
    if version is None:
        version = meta.get("current_version")
    entry = next((v for v in versions if v.get("version") == version), None)
    if entry is None:
        return None
    path = MODEL_DIR / entry["model_file"]
    if not path.exists():
        return None
    _verify_sha256(path, entry.get("sha256"))
    key = f"v{version}"
    if key not in _cache:
        with open(path, "rb") as f:
            _cache[key] = pickle.load(f)
    return _cache[key]


def predict(text: str, version: int | None = None) -> tuple[str, float]:
    """Swappable interface: predict(text) -> (category, confidence).

    Returns ("unknown", 0.0) when no model is available or text is empty.
    Confidence is the max softmax probability from LogisticRegression.
    """
    if not text or not text.strip():
        return "unknown", 0.0
    try:
        bundle = _load_bundle(version)
    except Exception:
        return "unknown", 0.0
    if bundle is None:
        return "unknown", 0.0
    try:
        vec = bundle["vectorizer"].transform([text])
        proba = bundle["clf"].predict_proba(vec)[0]
        idx = int(proba.argmax())
        labels = bundle["labels"]
        category = labels[idx] if 0 <= idx < len(labels) else "unknown"
        return category, round(float(proba[idx]), 3)
    except Exception:
        return "unknown", 0.0


def load_holdout() -> list[dict]:
    """The immutable promotion set. Returns [] if not created yet."""
    if not HOLDOUT_PATH.exists():
        return []
    rows = []
    with open(HOLDOUT_PATH, encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if raw:
                try:
                    rows.append(json.loads(raw))
                except (json.JSONDecodeError, ValueError):
                    continue
    return rows


def holdout_identities() -> set[tuple[str, str]]:
    """(normalized pattern, label) pairs excluded from training."""
    from app.core.rule_cache import normalize_pattern

    return {(normalize_pattern(r["text"]), r["label"]) for r in load_holdout()}


def score_on_holdout(bundle, holdout: list[dict] | None = None) -> dict:
    """Score a loaded bundle on the immutable holdout (never trained on)."""
    from sklearn.metrics import accuracy_score, f1_score

    holdout = holdout if holdout is not None else load_holdout()
    if not holdout:
        return {"accuracy": None, "per_category_f1": {}, "n_holdout": 0}
    texts = [r["text"] for r in holdout]
    truth = [r["label"] for r in holdout]
    vec = bundle["vectorizer"].transform(texts)
    pred = bundle["clf"].predict(vec)
    acc = round(float(accuracy_score(truth, pred)), 4)
    classes = sorted(set(truth))
    try:
        scores = f1_score(truth, pred, labels=classes, average=None, zero_division=0)
        f1_per = {c: round(float(s), 3) for c, s in zip(classes, scores)}
    except Exception:
        f1_per = {}
    return {"accuracy": acc, "per_category_f1": f1_per, "n_holdout": len(holdout)}
def train_and_save(dataset_path: Path | None = None) -> dict:
    """Train TF-IDF+LogReg as a CANDIDATE. Never touches current_version
    (except when no model exists yet, i.e. first boot).

    The immutable holdout rows are EXCLUDED from training. Promotion is a
    separate atomic step (promote_candidate) that scores candidate vs
    incumbent on the holdout. Returns the new version entry.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, f1_score
    from sklearn.model_selection import train_test_split
    import pickle

    from app.core.rule_cache import normalize_pattern

    ds = Path(dataset_path) if dataset_path else DATASET_PATH
    excluded = holdout_identities()
    texts: list[str] = []
    labels: list[str] = []
    skipped_holdout = 0
    with open(ds, encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            obj = json.loads(raw)
            text, label = str(obj["text"]), str(obj["label"])
            if (normalize_pattern(text), label) in excluded:
                skipped_holdout += 1
                continue
            texts.append(text)
            labels.append(label)

    if len(texts) < 40:
        raise ValueError(f"Dataset too small to train: {len(texts)} rows")

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2), max_features=5000, lowercase=True, strip_accents="unicode"
    )
    Xtr = vectorizer.fit_transform(X_train)
    Xte = vectorizer.transform(X_test)
    clf = LogisticRegression(max_iter=1000, class_weight="balanced", C=4.0)
    clf.fit(Xtr, y_train)
    pred = clf.predict(Xte)
    acc = round(float(accuracy_score(y_test, pred)), 4)
    f1_per: dict[str, float] = {}
    try:
        classes = sorted(set(labels))
        scores = f1_score(y_test, pred, labels=classes, average=None, zero_division=0)
        f1_per = {c: round(float(s), 3) for c, s in zip(classes, scores)}
    except Exception:
        f1_per = {}

    meta = _load_metadata()
    versions = meta.get("versions", [])
    nxt = (max((v.get("version", 0) for v in versions), default=0) + 1)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    fname = f"model_v{nxt}.pkl"
    bundle = {
        "vectorizer": vectorizer,
        "clf": clf,
        "labels": list(clf.classes_),
        "version": nxt,
    }
    with open(MODEL_DIR / fname, "wb") as f:
        pickle.dump(bundle, f)
    size = (MODEL_DIR / fname).stat().st_size
    digest = _sha256(MODEL_DIR / fname)
    holdout_score = score_on_holdout(bundle)
    entry = {
        "version": nxt,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_examples": len(texts),
        "n_holdout_excluded": skipped_holdout,
        "accuracy": acc,
        "per_category_f1": f1_per,
        "holdout_accuracy": holdout_score["accuracy"],
        "holdout_f1": holdout_score["per_category_f1"],
        "n_holdout": holdout_score["n_holdout"],
        "sha256": digest,
        "status": "candidate",
        "model_file": fname,
        "size_bytes": size,
    }
    versions.append(entry)
    meta["versions"] = versions
    if not meta.get("current_version"):
        # first-ever model: nothing to gate against
        meta["current_version"] = nxt
        entry["status"] = "serving"
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    _cache.clear()
    return entry


def promote_candidate(version: int) -> dict:
    """Atomically promote a candidate after holdout gating (single write).

    Scores candidate AND incumbent on the immutable holdout. Promotes only if
    overall accuracy >= incumbent - GATE_TOLERANCE AND no guarded category
    F1 drops beyond its tolerance. Otherwise marks the candidate rejected and
    leaves current_version untouched. Returns a verdict dict.
    """
    meta = _load_metadata()
    versions = meta.get("versions", [])
    cand = next((v for v in versions if v.get("version") == version), None)
    if cand is None:
        raise ValueError(f"Model version {version} not found")
    current_version = meta.get("current_version", 0)
    if current_version == version:
        return {"promoted": True, "already_serving": True, "model": cand}

    def _holdout_metrics(v: dict) -> dict:
        if v.get("holdout_accuracy") is not None:
            return {
                "accuracy": v["holdout_accuracy"],
                "f1": v.get("holdout_f1", {}) or {},
            }
        bundle = _load_bundle(v.get("version"))
        if bundle is None:
            raise ValueError(f"Artifact for version {v.get('version')} missing")
        s = score_on_holdout(bundle)
        v["holdout_accuracy"] = s["accuracy"]
        v["holdout_f1"] = s["per_category_f1"]
        v["n_holdout"] = s["n_holdout"]
        return {"accuracy": s["accuracy"], "f1": s["per_category_f1"]}

    incumbent = next((v for v in versions if v.get("version") == current_version), None)
    if incumbent is None or current_version == 0:
        # nothing to gate against: promote directly
        cand["status"] = "serving"
        meta["current_version"] = version
        with open(METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        _cache.clear()
        return {"promoted": True, "model": cand, "reason": "no incumbent; first model"}

    cand_m = _holdout_metrics(cand)
    inc_m = _holdout_metrics(incumbent)
    reasons = []
    c_acc, i_acc = cand_m["accuracy"], inc_m["accuracy"]
    if c_acc is None or i_acc is None:
        reasons.append("holdout unavailable; refusing to promote blind")
    elif c_acc < i_acc - GATE_TOLERANCE:
        reasons.append(f"overall gate: candidate holdout {c_acc} < incumbent {i_acc} - {GATE_TOLERANCE}")
    for cat, tol in GATED_CATEGORIES.items():
        cf = (cand_m["f1"] or {}).get(cat)
        inf = (inc_m["f1"] or {}).get(cat)
        if cf is not None and inf is not None and cf < inf - tol:
            reasons.append(f"per-category gate: {cat} F1 {cf} < incumbent {inf} - {tol}")
    if reasons:
        cand["status"] = "rejected"
        with open(METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        _cache.clear()
        return {
            "promoted": False,
            "reasons": reasons,
            "candidate": {"version": version, "holdout_accuracy": c_acc},
            "incumbent": {"version": current_version, "holdout_accuracy": i_acc},
        }
    # ATOMIC promotion: one metadata write flips serving version.
    for v in versions:
        if v.get("status") == "serving":
            v["status"] = "superseded"
    cand["status"] = "serving"
    meta["current_version"] = version
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    _cache.clear()
    return {
        "promoted": True,
        "model": cand,
        "candidate": {"version": version, "holdout_accuracy": c_acc},
        "incumbent": {"version": current_version, "holdout_accuracy": i_acc},
    }


def set_current_version(version: int) -> dict:
    """Rollback: point current_version at an existing artifact."""
    meta = _load_metadata()
    versions = meta.get("versions", [])
    if not any(v.get("version") == version for v in versions):
        raise ValueError(f"Model version {version} not found")
    path = MODEL_DIR / f"model_v{version}.pkl"
    if not path.exists():
        raise ValueError(f"Artifact for version {version} missing")
    meta["current_version"] = version
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    _cache.clear()
    return get_model_info()
