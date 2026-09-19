import json
import random

rows = [
    json.loads(line)
    for line in open("app/core/training_data/stig_labels.jsonl", encoding="utf-8")
    if line.strip()
]
random.seed(1)
for r in random.sample(rows, 15):
    print("[" + r["label"] + "] " + r["text"][:95] + "  (" + r["rule_id"] + " " + str(r["cci"]) + ")")
