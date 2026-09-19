"""Sieve friend's 1,876-file raw dataset -> labelable security-line candidates.

Steps: filter CLI configs (skip Checkpoint JSON modality) -> dedupe files by
content hash -> keyword-sieve security lines -> heuristic propose category
-> dedupe lines by normalize_pattern -> candidates.jsonl

Usage:
    python backend/scripts/sieve_dataset.py [DATA_DIR] [--out backend/app/core/training_data/candidates.jsonl]

Output row: {text, proposed_label, confidence, source_file, vendor_hint}
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.core.ai_classifier import heuristic_classify  # noqa: E402
from app.core.rule_cache import normalize_pattern  # noqa: E402

DEFAULT_DATA = Path(
    r"C:\Users\Farhan Ali\Downloads\complianceforge-network-dataset-main"
    r"\complianceforge-network-dataset-main\Data"
)
DEFAULT_OUT = BACKEND / "app" / "core" / "training_data" / "candidates.jsonl"

SKIP_SUFFIXES = {".json"}  # Checkpoint mgmt-API JSONs = wrong modality
SKIP_COMMENT = ("!", "#")


def infer_vendor_hint(path: Path, text_head: str) -> str:
    name = path.name.lower() + " " + text_head[:500].lower()
    if "fortios" in name or "fortigate" in name or "fortinet" in name:
        return "fortinet"
    if "juniper" in name or "junos" in name or "srx" in name:
        return "juniper_srx"
    if "sonic" in name or "spine" in name and "sonic" in name:
        return "sonic"
    if "ios" in name or "cisco" in name or "hostname" in name:
        return "cisco_ios"
    if "palo" in name or "pan-os" in name:
        return "palo_alto"
    if "arista" in name or "eos" in name:
        return "arista"
    return "any"


def iter_cli_files(data_dir: Path):
    for f in sorted(data_dir.rglob("*")):
        if not f.is_file():
            continue
        if f.suffix.lower() in SKIP_SUFFIXES:
            continue
        if f.stat().st_size == 0 or f.stat().st_size > 2_000_000:
            continue
        yield f


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("data_dir", nargs="?", default=str(DEFAULT_DATA))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    data_dir = Path(args.data_dir)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not data_dir.exists():
        print(f"Data dir not found: {data_dir}", file=sys.stderr)
        sys.exit(1)

    seen_file_hash: set[str] = set()
    seen_pattern: set[str] = set()
    per_label: Counter = Counter()
    total_files = 0
    dup_files = 0
    total_lines = 0
    kept = 0
    skipped_json = 0

    with open(out_path, "w", encoding="utf-8") as out:
        for f in data_dir.rglob("*"):
            if not f.is_file():
                continue
            if f.suffix.lower() in SKIP_SUFFIXES:
                skipped_json += 1
                continue
        for f in iter_cli_files(data_dir):
            total_files += 1
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            h = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
            if h in seen_file_hash:
                dup_files += 1
                continue
            seen_file_hash.add(h)
            vendor_hint = infer_vendor_hint(f, text)
            for raw in text.splitlines():
                line = raw.strip()
                total_lines += 1
                if not line or line.startswith(SKIP_COMMENT):
                    continue
                if len(line) < 4 or len(line) > 300:
                    continue
                # skip pure topology noise (interface ip + bgp neighbor route-map pairs
                # are kept only via routing keywords below)
                label, conf = heuristic_classify(line)
                if label == "unknown":
                    # keep only if it looks CLI-security-ish (avoid hostnames etc.)
                    low = line.lower()
                    if not re.search(
                        r"ssh|telnet|aaa|tacacs|radius|password|secret|passwd|snmp|"
                        r"ntp|banner|motd|crypt|cipher|isakmp|encrypt|access|acl|"
                        r"syslog|logging|cdp|lldp|finger|bootp|login|lockout|"
                        r"privileg|ospf|bgp|route|zone|http|community|permit|deny|"
                        r"interface|vlan|port|policy|filter|key|hash|certificate",
                        low,
                    ):
                        continue
                    conf = 0.2
                pattern = normalize_pattern(line)
                if pattern in seen_pattern:
                    continue
                seen_pattern.add(pattern)
                per_label[label] += 1
                kept += 1
                out.write(
                    json.dumps(
                        {
                            "text": line,
                            "proposed_label": label,
                            "confidence": conf,
                            "source_file": f.name,
                            "vendor_hint": vendor_hint,
                        }
                    )
                    + "\n"
                )

    print(f"files scanned: {total_files} (dup files skipped: {dup_files}, json skipped: {skipped_json})")
    print(f"lines scanned: {total_lines}, candidates kept: {kept}")
    print("per proposed label:")
    for label, n in per_label.most_common():
        print(f"  {label}: {n}")
    print(f"wrote: {out_path}")


if __name__ == "__main__":
    main()
