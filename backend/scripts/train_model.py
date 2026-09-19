"""Train L2 model v1 (or next version) from the learning dataset.

Usage:
    python backend/scripts/train_model.py [--dataset ...]

Trains TF-IDF + LogisticRegression with an 80/20 stratified split and saves a
versioned artifact (model_vN.pkl + metadata.json with accuracy + per-class F1).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.core.trained_classifier import get_model_info, train_and_save  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=None)
    args = ap.parse_args()

    entry = train_and_save(Path(args.dataset) if args.dataset else None)
    print(f"trained model v{entry['version']}:")
    print(f"  examples : {entry['n_examples']}")
    print(f"  accuracy : {entry['accuracy']}")
    print(f"  size     : {entry['size_bytes']} bytes ({entry['model_file']})")
    thin = {k: v for k, v in entry["per_category_f1"].items() if v < 0.7}
    if thin:
        print("  low-F1 categories (<0.7) — qualitative until more verified examples:")
        for k, v in sorted(thin.items(), key=lambda x: x[1]):
            print(f"    {k}: {v}")
    info = get_model_info()
    print(f"current version: v{info['model_version']}")


if __name__ == "__main__":
    main()
