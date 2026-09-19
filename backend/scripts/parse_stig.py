"""XCCDF STIG -> labeled dataset rows (highest-value source).

Parses DISA Manual-xccdf.xml Benchmarks (Cisco IOS-XE Router/Switch,
Juniper SRX SG, ...). Each Rule yields:
  - severity + title + CCI idents (real NIST mapping, stored per row for
    future maps_to upgrade)
  - CLI lines mined from <fixtext> and <check><check-content>, with device
    prompts (SW4(config)# ...) stripped

Rule -> 19-category mapping: STIG section keywords first (pre-labeled by
section), heuristic_classify(title + line) as backstop. Rows that still map
to `unknown` are dropped (STIGs must only feed positive classes).

Usage:
    python backend/scripts/parse_stig.py <stig_dir_or_file>... [--out backend/app/core/training_data/stig_labels.jsonl]

Output row: {text, label, source, severity, cci, rule_id}
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.core.ai_classifier import heuristic_classify  # noqa: E402
from app.core.line_override import LINE_OVERRIDE, line_override  # noqa: E402
from app.core.rule_cache import normalize_pattern  # noqa: E402
from app.core.schema import SECURITY_CATEGORIES  # noqa: E402

DEFAULT_OUT = BACKEND / "app" / "core" / "training_data" / "stig_labels.jsonl"

NS = {
    "x11": "http://checklists.nist.gov/xccdf/1.1",
    "x12": "http://checklists.nist.gov/xccdf/1.2",
}

# NOTE: LINE_OVERRIDE / line_override now live in app.core.line_override
# (shared with build_seed_dataset); imported above.
# ORDER MATTERS (first match wins): specific technology rules (ssh, crypto,
# aaa, snmp, ntp, banner, ...) come BEFORE the generic session/management
# rule, which previously swallowed SSH-timeout and SSH-encryption rules into
# management_protocol (found via v4->v6 accuracy regression diagnosis:
# 60% of STIG rows disagreed with the model, almost all from that rule).
SECTION_MAP: list[tuple[str, str]] = [
    (r"ssh.*(version|v2|protocol 2)|root login|ssh.*timeout|authentication retries|protocol version", "ssh_policy"),
    (r"crypt|encrypt|hash|certificate|key.*(generat|exchange|length)|tls|ipsec|ike|diffie|modulus", "cryptography"),
    (r"tacacs|radius|aaa|authentication-order|accounting", "aaa"),
    (r"snmp.*(communit|version|v3|trap)|community.*string|private.*community", "snmp_management"),
    (r"ntp.*server|time.*synchron|clock.*source|ntp.*auth", "ntp"),
    (r"banner|login.*message|motd|warning.*notice|consent.*banner", "banner"),
    (r"telnet.*(disabl|prohibit|not.*enabl)|prohibit.*telnet|http.*(disabl|secure)|transport input ssh", "management_protocol"),
    # generic session/timeout rule goes LAST among management topics: ssh and
    # crypto titles are matched above, so this only fires without that context
    (r"concurrent management session|exec\.timeout|session-limit|idle.*timeout|session.*limit", "management_protocol"),
    (r"account.*(creat|modif|disabl|remov).*audit|audit.*account|log.*config|archive.*log", "logging"),
    (r"audit.*(fail|record|log)|syslog.*notif|notify syslog|logging.*(host|server|trap)|remote.*log", "syslog"),
    (r"password.*(length|complexity|min|expir|lifetime)|authentication.*fail.*delay|login.*attempt|retry.*lockout|block.*login", "password_policy"),
    (r"lockout|login.*block|authentication.*attempt.*fail|consecutive.*logon", "authentication"),
    (r"access.list|access.group|packet.*filter|traffic.*(permit|deny)|firewall.*polic", "access_control"),
    (r"(permit|deny).*log|log.*(permit|deny)|log.*dropped|firewall.*log", "acl_logging"),
    (r"cdp |lldp|finger|bootp|pad |small.server|unused.*service|auxiliary.*port|proxy.arp|source.route", "service_hardening"),
    (r"privilege.*level|role.*based|super.user|administrative.*privilege", "privilege_escalation"),
    (r"bgp|ospf|routing.*protocol|route.*authentic|prefix.list|route.map|neighbor.*password", "routing_integrity"),
    (r"port.*secur|switchport|spanning.tree|storm.control|dhcp.*snoop|dynamic.*arp|interface.*shutdown", "interface_security"),
    (r"zone.*polic|security.zone|from.zone|inter.zone|default.*deny.*zone", "zone_policy"),
]

_PROMPT_RE = re.compile(r"^\s*[\w\-.()]+(\([^()]*\))?\s*[#>]\s*")
_SHOW_RE = re.compile(r"^\s*show\s+", re.I)
_PROSE_MARKERS = re.compile(
    r"^(configure|if|verify|review|consult|determine|interview|examine|ensure|note|step\s+\d|"
    r"apply|view|check|confirm|for\s+example|this\s+(is|stig|includes)|the\s+(cisco|juniper|device|switch|router)|"
    r"all\s+users|from\s+the|to\s+configure|when|in\s+order|for\s+those|for\s+platforms|"
    r"-\s*this|\(e\.g|protect\s+usg|standard\s+mandatory)",
    re.I,
)

# A line is device CLI only if it STARTS with a config verb. Prose sentences
# ("Configure the router...", "If the switch is not...") are rejected even
# when they contain security keywords — they would poison the classifier.
_CLI_VERB_RE = re.compile(
    r"^(no\s+|set\s+|delete\s+|deactivate\s+|activate\s+|edit\s+|top\s+|up\s+|commit|"
    r"ip\s|ipv6\s|snmp|ntp|logging\s|log\s|banner|motd|access|line\s|transport|archive|"
    r"username|user\s|aaa\s|tacacs|radius|crypto|ssh|telnet|password|service\s|hostname|"
    r"enable|clock|zone|firewall|interface|vlan|permit\s|deny\s|community|key\s|login|"
    r"route|router\s|neighbor|switchport|spanning|storm|port-sec|class\s|role\s|privilege|"
    r"address|filter|policy|family|protocol|system\s|security\s|groups?|request\s|monitor|"
    r"event|audit|authentication|authorization|accounting|certificate|dhcp|ospf|bgp|"
    r"ethernet|chassis|forwarding|logical|applications|domain|name-server|syslog|alarm|"
    r"server\s|host\s|idle|session|transport-|exec-|flow|screen|alg|vpn|ike|proposal|"
    r"traceoptions|archival|transfer|daemon|facility|trap|version|license|contracts|"
    r"pki|cert|mac|storm|spanning|loop|portfast|bpduguard|port-security|max-ports|"
    r"filter-list|prefix-list|route-map|community-list|as-path|distribute|redistribute|"
    r"passive|authenticat|message-digest|max-connections|max-conn|http\s|session-limit|"
    r"length|width|history|monitor|privilege-|secret|encrypt|hash)",
    re.I,
)


def section_label(title: str, discussion: str) -> str | None:
    blob = f"{title} {discussion}".lower()
    for pattern, category in SECTION_MAP:
        if re.search(pattern, blob):
            return category
    return None


def strip_prompt(line: str) -> str:
    return _PROMPT_RE.sub("", line).strip()


def looks_like_cli(line: str) -> bool:
    if len(line) < 4 or len(line) > 250:
        return False
    if _SHOW_RE.match(line):
        return False  # audit/verify commands, not device config
    if _PROSE_MARKERS.match(line):
        return False
    if "..." in line or "…" in line:
        return False  # elided examples, not real syntax
    if line.rstrip().endswith(":"):
        return False  # prose headers ("BGP Example:") leak through verb prefixes
    if re.match(r"^commit for the changes", line, re.I):
        return False  # STIG fix-text boilerplate, not a meaningful training line
    return bool(_CLI_VERB_RE.match(line))


def iter_rules(xccdf_path: Path):
    try:
        root = ET.parse(xccdf_path).getroot()
    except ET.ParseError as exc:
        print(f"  SKIP {xccdf_path.name}: XML parse error {exc}")
        return
    for prefix in ("x11", "x12"):
        rules = root.findall(f".//{prefix}:Rule", NS)
        if rules:
            yield from rules
            return
    print(f"  SKIP {xccdf_path.name}: no xccdf:Rule elements")


def text_of(el) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def parse_file(xccdf_path: Path, vendor_hint: str) -> list[dict]:
    rows: list[dict] = []
    for rule in iter_rules(xccdf_path):
        ns = "x11" if rule.tag.startswith("{http://checklists.nist.gov/xccdf/1.1}") else "x12"
        title = text_of(rule.find(f"{ns}:title", NS))
        discussion = text_of(rule.find(f"{ns}:description", NS))[:600]
        severity = rule.get("severity", "medium")
        ccis = sorted(
            {
                (i.text or "").strip()
                for i in rule.findall(f"{ns}:ident", NS)
                if (i.text or "").strip().startswith("CCI")
            }
        )
        rule_id = (text_of(rule.find(f"{ns}:version", NS)) or rule.get("id", ""))[:40]
        fix = text_of(rule.find(f"{ns}:fixtext", NS))
        check_el = rule.find(f"{ns}:check/{ns}:check-content", NS)
        check = text_of(check_el)
        label = section_label(title, discussion)
        for raw in (fix + "\n" + check).splitlines():
            line = strip_prompt(raw.strip().strip("\"'"))
            if not looks_like_cli(line):
                continue
            override = line_override(line)
            if override is not None:
                use = override  # line itself is unambiguous — beats section title
            elif label is None:
                back, _ = heuristic_classify(f"{title} {line}")
                use = back if back != "unknown" else None
            else:
                use = label
            if use is None or use not in SECURITY_CATEGORIES or use == "unknown":
                continue
            rows.append(
                {
                    "text": line,
                    "label": use,
                    "source": f"stig:{xccdf_path.stem}:{rule_id}",
                    "severity": severity,
                    "cci": ccis[0] if ccis else None,
                    "rule_id": rule_id,
                    "vendor_hint": vendor_hint,
                }
            )
    return rows


def vendor_hint_for(path: Path) -> str:
    name = path.name.lower()
    if "juniper" in name or "junos" in name or "srx" in name:
        return "juniper_srx"
    if "ios" in name or "cisco" in name:
        return "cisco_ios"
    return "any"


def collect(inputs: list[str]) -> list[Path]:
    found: list[Path] = []
    for raw in inputs:
        p = Path(raw)
        if p.is_file() and p.suffix.lower() == ".xml":
            found.append(p)
        elif p.is_dir():
            found.extend(sorted(p.rglob("*-xccdf.xml")))
            found.extend(
                f for f in sorted(p.rglob("*.xml")) if f not in found and "xccdf" in f.name.lower()
            )
    # dedupe, deterministic
    return sorted(set(found))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+", help="STIG dirs/files (extracted zips)")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    files = collect(args.inputs)
    if not files:
        print("No *-xccdf.xml files found in inputs.", file=sys.stderr)
        sys.exit(1)
    print(f"XCCDF files: {len(files)}")
    for f in files:
        print(f"  {f}")

    all_rows: list[dict] = []
    seen: set[str] = set()
    per_label: Counter = Counter()
    for f in files:
        rows = parse_file(f, vendor_hint_for(f))
        kept = 0
        for r in rows:
            pat = normalize_pattern(r["text"])
            key = (pat, r["label"])
            if key in seen:
                continue
            seen.add(key)
            all_rows.append(r)
            per_label[r["label"]] += 1
            kept += 1
        print(f"  {f.name}: {len(rows)} mined, {kept} kept (deduped)")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        for r in sorted(all_rows, key=lambda x: (x["label"], x["text"])):
            fh.write(json.dumps(r) + "\n")
    print(f"total STIG rows: {len(all_rows)}")
    for label, n in per_label.most_common():
        print(f"  {label}: {n}")
    print(f"wrote: {out}")


if __name__ == "__main__":
    main()
