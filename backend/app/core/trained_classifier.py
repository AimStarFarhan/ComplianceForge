"""L2 trained model: sklearn TF-IDF + LogisticRegression (fixed-size artifact).

Design (per SWITCH_CONTEXT locked architecture):
  - Dataset is the source of truth (training_data/dataset.jsonl, versioned,
    correctable). Runtime is a fixed-size model file (~100KB-5MB, constant
    whether 1k or 100k examples). Storage O(model size), not O(unknowns).
  - Updates are accuracy-gated + rollbackable: retrain does an 80/20
    stratified split and promotes only if accuracy >= current - 0.02.
  - Interface is swappable: predict(text) -> (category, confidence) so a
    future MiniLM/SetFit upgrade is drop-in.

Artifact layout (model_artifacts/):
  model_v{N}.pkl   pickle {vectorizer, clf, labels, version}
  metadata.json    {current_version, versions: [{version, trained_at,
                   n_examples, accuracy, per_category_f1, model_file, size_bytes}]}
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

MODEL_DIR = Path(__file__).parent / "model_artifacts"
DATASET_PATH = Path(__file__).parent / "training_data" / "dataset.jsonl"
METADATA_PATH = MODEL_DIR / "metadata.json"

CONFIDENCE_THRESHOLD = 0.7  # below this, L2 abstains -> L3 fallback

_cache: dict = {}


def _load_metadata() -> dict:
    if METADATA_PATH.exists():
        try:
            return json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


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


def train_and_save(dataset_path: Path | None = None) -> dict:
    """Train TF-IDF+LogReg on 80/20 stratified split, save next version.

    Always saves (script path). The accuracy gate (>= current - 0.02) is
    enforced by the retrain API; this function reports metrics so the caller
    can decide. Returns the new version entry.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, f1_score
    from sklearn.model_selection import train_test_split
    import pickle

    ds = Path(dataset_path) if dataset_path else DATASET_PATH
    texts: list[str] = []
    labels: list[str] = []
    with open(ds, encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            obj = json.loads(raw)
            texts.append(str(obj["text"]))
            labels.append(str(obj["label"]))

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
    entry = {
        "version": nxt,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_examples": len(texts),
        "accuracy": acc,
        "per_category_f1": f1_per,
        "model_file": fname,
        "size_bytes": size,
    }
    versions.append(entry)
    meta["versions"] = versions
    meta["current_version"] = nxt
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    _cache.clear()
    return entry


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
