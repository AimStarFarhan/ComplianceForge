"""Train an L2 model CANDIDATE from the learning dataset (never promotes).

Usage:
    python backend/scripts/train_model.py [--dataset ...] [--promote]

Trains TF-IDF + LogisticRegression (holdout rows excluded), saves a versioned
candidate artifact, scores it on the immutable holdout. Promotion happens only
via --promote (same gates as the API) or POST /training/model/retrain.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.core.trained_classifier import (  # noqa: E402
    get_model_info,
    promote_candidate,
    train_and_save,
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=None)
    ap.add_argument("--promote", action="store_true",
                    help="run holdout gates and promote atomically if they pass")
    args = ap.parse_args()

    entry = train_and_save(Path(args.dataset) if args.dataset else None)
    print(f"trained CANDIDATE v{entry['version']}:")
    print(f"  examples : {entry['n_examples']} (+{entry.get('n_holdout_excluded', 0)} holdout-excluded)")
    print(f"  accuracy : {entry['accuracy']} (80/20 split)")
    print(f"  holdout  : {entry.get('holdout_accuracy')} (n={entry.get('n_holdout')})")
    print(f"  size     : {entry['size_bytes']} bytes ({entry['model_file']})")
    thin = {k: v for k, v in entry["per_category_f1"].items() if v < 0.7}
    if thin:
        print("  low-F1 categories (<0.7) -- qualitative until more verified examples:")
        for k, v in sorted(thin.items(), key=lambda x: x[1]):
            print(f"    {k}: {v}")
    if args.promote:
        verdict = promote_candidate(entry["version"])
        if verdict["promoted"]:
            print(f"PROMOTED v{entry['version']}: {verdict.get('candidate')}")
        else:
            print(f"REJECTED v{entry['version']}:")
            for r in verdict.get("reasons", []):
                print(f"  - {r}")
    else:
        print("candidate recorded; serving version unchanged.")
        print("run with --promote (or POST /training/model/retrain) to gate + promote.")
    info = get_model_info()
    print(f"serving version: v{info['model_version']}")


if __name__ == "__main__":
    main()
