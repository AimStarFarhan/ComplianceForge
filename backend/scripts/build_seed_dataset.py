"""Build balanced seed dataset (~1,200-1,500 rows, ~50-80 per category).

Merges, in priority order:
  1. Rule-pack remediation CLI (highest value: hand-verified, labeled by rule category)
  2. Sample-config lines (real vendor syntax, heuristic-labeled + parser-informed)
  3. Sieved friend candidates (raw material, heuristic proposals, capped per class)
  4. Synthetic templates (fills thin classes: banner, management_protocol,
     service_hardening, ntp, logging, acl_logging, etc. with vendor + value diversity)

Rules: dedupe by normalize_pattern, balance rare classes, vendor+value diversity.
Verified > synthetic (~3-5x value) so synthetic is capped at filling the gap.

Usage:
    python backend/scripts/build_seed_dataset.py [--candidates ...] [--out ...]

Output: dataset.jsonl rows {text, label, source} + per-category counts.
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import yaml  # noqa: E402

from app.core.ai_classifier import heuristic_classify  # noqa: E402
from app.core.line_override import line_override  # noqa: E402
from app.core.rule_cache import normalize_pattern  # noqa: E402
from app.core.schema import SECURITY_CATEGORIES  # noqa: E402

CANDIDATES = BACKEND / "app" / "core" / "training_data" / "candidates.jsonl"
STIG = BACKEND / "app" / "core" / "training_data" / "stig_labels.jsonl"
OUT = BACKEND / "app" / "core" / "training_data" / "dataset.jsonl"
SAMPLES = BACKEND / "sample_configs"
PACKS = BACKEND / "app" / "core" / "rule_packs"

TARGET_PER_CLASS_MIN = 55
TARGET_PER_CLASS_MAX = 80

# ---------------------------------------------------------------- synthetic
# Placeholders expanded for value diversity: {N} number, {IP} address,
# {HOST} hostname, {STR} string. Each template yields len(values) variants.
_SYNTH: dict[str, list[str]] = {
    "management_protocol": [
        "no ip telnet server",
        "ip telnet server disable",
        "service telnet daemon-start {N}",
        "set system services telnet disable",
        "no ip http server",
        "ip http server disable port {N}",
        "set system services web-management http disable",
        "management web-console port {N} plaintext",
        "disable insecure telnet service port",
        "disable telnet daemon on {HOST}",
        "enable secure http-server port {N}",
        "set system services web-management https enable",
        "transport input ssh line vty",
        "line vty transport input ssh only",
        "no transport input telnet line console",
        "web-management https port secure enable",
        "disable clear-text http management",
        "ip http secure-server enable",
        "set system services web-management session idle-timeout",
        "management telnet idle-disconnect enable",
        "no ip http secure-active session",
        "set system services rest disable",
        "console idle-timeout minutes secure",
        "vty line access-class MGMT inbound",
        "https tls-version minimum secure",
        "disable web admin over plain http",
        "set system services netconf ssh only",
    ],
    "ssh_policy": [
        "ip ssh version 2",
        "ssh version 2 enforce",
        "set system services ssh protocol-version v2",
        "ip ssh time-out {N}",
        "set ssh timeout {N} on {HOST}",
        "ip ssh authentication-retries {N}",
        "set system services ssh root-login deny",
        "disable secure-shell protocol-2 enforcement",
        "enable secure-shell protocol-2 on {HOST}",
        "ssh server session-timeout {N}",
    ],
    "authentication": [
        "login block-for {N} attempts {N} within {N}",
        "login on-failure log every {N}",
        "local-account admin password-strength minimum",
        "username admin privilege 15 secret {STR}",
        "set system login retry-options tries-before-disconnect {N}",
        "authentication fallback local enable",
        "no username guest account active",
        "user {HOST}-admin password {STR} role admin",
        "login delay seconds after failed attempt",
        "login quiet-mode access-class MGMT",
        "security authentication failure rate limit",
        "set system login deny-sources address {IP}",
        "clear local user guest account",
        "authentication lockout threshold attempts",
        "verify local account password expiry",
        "set system authentication password stale-timer",
        "password lifetime days enforce rotation",
        "unlock locked user account admin",
        "block repeated login failures cooldown",
        "set system login backdoor no-password disabled",
        "console password protect boot menu",
        "enable password history check",
        "lock console after idle timeout",
        "require minimum password change interval",
        "disable default operator account",
        "enforce smart-card login admin",
        "set system root-authentication encrypted-password",
    ],
    "aaa": [
        "aaa new-model",
        "aaa authentication login default group tacacs+ local",
        "aaa authorization exec default local",
        "set system authentication-order [ radius password ]",
        "tacacs-server host {IP} key {STR}",
        "radius-server host {IP} auth-port {N}",
        "configure authentication-order [ radius tacacs local ]",
        "aaa accounting exec default start-stop group tacacs+",
        "aaa authentication enable default group tacacs+ enable",
        "aaa authorization commands privilege authenticated",
        "tacacs server timeout seconds retransmit",
        "radius server retransmit timeout deadtime",
        "set system tacplus-server {IP} secret {STR}",
        "aaa group server tacacs+ NETOPS server {IP}",
    ],
    "password_policy": [
        "security passwords min-length {N}",
        "password-policy minimum-length {N} complexity on",
        "set system login password minimum-length {N}",
        'Set "PASSWD|POLICIES" minlen {N} in config_db',
        "service password-encryption enable",
        "password encryption aes {STR}",
        "local-account {HOST} password-strength minimum",
        "set password minimum-changes {N} enforce",
        "password lifetime days enforce rotation",
    ],
    "logging": [
        "logging buffered {N} informational",
        "logging trap informational",
        "logging facility local{N}",
        "set system syslog archive files {N}",
        "event-log forward destination {IP} minimum-severity debug",
        "logging console critical",
        "audit log admin-access enable",
        "set system accounting events login",
        "logging timestamp msec datetime localtime",
        "logging origin-id hostname",
        "set system syslog user info authorization",
        "archive log config logging enable",
        "logging persistent url flash persistent",
        "set system syslog file messages any notice",
        "logging history size warnings",
        "enable session logging on {HOST}",
        "set system syslog interactive-commands info",
        "logging synchronous level all",
        "audit trail privilege commands enable",
        "set system accounting destination syslog",
        "login logging successive failures",
        "set system syslog console info authorization",
        "monitor session event-logging enable",
        "archive configuration revision logging",
        "record configuration change history",
        "set system syslog external allow-duplicates",
        "terminal monitor logging buffered",
        "schedule tech-support log capture",
        "set system mirror destination syslog host",
        "exec accounting log start-stop",
        "set system syslog rate-limit messages",
        "logging queue-limit trap entries",
        "set system syslog host log-prefix",
        "audit backup log rotation enable",
        "clear logging alarm stale entries",
        "set system syslog time-format millisecond",
        "login quiet-message access-denied log",
        "archive tar log collection daily",
        "set system syslog source-address loopback",
        "monitor crash log exception dump",
        "logging event link-status global",
        "set system commit log revision-info",
        "set system syslog daemon facility",
        "logging userinfo command accounting",
        "service timestamps debug datetime show-timezone",
    ],
    "syslog": [
        "logging host {IP}",
        "logging {IP} facility syslog level info",
        "set system syslog host {IP} any info",
        "syslog-server {IP} port {N} protocol udp",
        "event-log forward destination {IP} minimum-severity info",
        "remote-log server {IP} enable",
    ],
    "access_control": [
        "ip access-list standard MGMT-HOSTS",
        "permit {IP} 0.0.0.255 log",
        "deny ip any any log",
        "ip access-group 110 in",
        "access-class MGMT in",
        "set firewall family inet filter MGMT term {N} from source-address {IP}",
        "firewall filter {HOST}-in discard all",
        "route-policy {HOST} permit {IP}",
    ],
    "acl_logging": [
        "access-list 110 deny ip any any log",
        "deny tcp any any eq {N} log",
        "permit ip {IP} any log-input",
        "set firewall filter {HOST} term {N} then log",
        "access-list {HOST} extended deny ip any any log",
        "log access-list hits on {HOST}",
        "deny udp any any log-input",
        "permit tcp {IP} any established log",
        "set firewall family inet filter MGMT term log then syslog",
        "access-list inbound deny icmp any any log",
        "ipv6 access-list {HOST} deny all log",
        "set security policies policy {HOST} then log session-init",
        "deny ip {IP} any log-input",
        "permit icmp any any echo log",
        "set firewall log prefix {HOST}",
        "access-group {HOST} in log enable",
        "deny esp any any log session-drop",
        "permit dns queries log-only",
        "set security log mode event",
        "access-list remarks audited rule",
        "log dropped packets ingress filter",
        "set firewall policer log violations",
        "ipv4 access-list log-update threshold",
        "deny all fragments log security",
        "permit established sessions log summary",
        "set security flow log dropped-icmp",
        "access-list log per-interface statistics",
        "firewall log-martians enable ingress",
        "set system firewall log-foreign",
        "deny spoofed source log discard",
        "permit management subnet log connection",
        "set policy id log at-session-end",
        "log security violations count threshold",
        "set firewall family log rejected-tcp",
        "access-list extended log both ingress egress",
        "deny private-rfc source log martian",
        "log session close reason statistics",
    ],
    "cryptography": [
        "crypto isakmp policy 10 encryption aes 256",
        "ip ssh dh min size 2048",
        "set security ike proposal {HOST} encryption-algorithm aes-256-cbc",
        "tls profile cipher enable des-cbc-md5 legacy",
        "ssh-keygen -t rsa -b 2048 -f /etc/sonic/key",
        "crypto key generate rsa modulus 2048",
        "set protocols ospf area authentication md5 {N}",
        "ssl cipher-list HIGH:!aNULL:!MD5",
    ],
    "snmp_management": [
        "snmp-server community {STR} RO",
        "snmp-server community {STR} RW {N}",
        "set snmp community {STR} authorization read-only",
        'monitor protocol snmp read-string "{STR}"',
        "no snmp-server community public",
        "snmp-server host {IP} version 2c {STR}",
    ],
    "ntp": [
        "ntp server {IP} prefer",
        "ntp server {IP} source Loopback0",
        "set system ntp server {IP}",
        "clock source ntp primary {IP}",
        "ntp authenticate enable key {N}",
        "chrony server {IP} iburst",
        "ntp authentication-key {N} md5 {STR}",
        "ntp trusted-key {N}",
        "set system ntp boot-server {IP}",
        "ntp access-group peer MGMT",
        "ntp master stratum authoritative",
        "clock timezone UTC offset zero",
        "set system time-zone UTC",
        "ntp update-calendar enable",
        "show ntp associations on {HOST}",
        "ntp source-interface Loopback prefer",
        "set system ntp authentication key-id",
        "ntp logging enable change-notify",
        "chrony makestep threshold poll",
        "disable unauthenticated time sync",
        "set system ntp trusted-network {IP}",
        "ntp peer {IP} key authenticated",
        "set system ntp max-poll interval",
        "ntp broadcast client disable",
        "clock calendar-valid enable date",
        "set system ntp symmetric-active",
        "ntp orphan stratum fallback",
        "ntp allow control query private",
        "set system ntp backup-server pool",
    ],
    "service_hardening": [
        "no cdp run",
        "no lldp run",
        "no ip finger",
        "no ip bootp server",
        "no service pad",
        "sudo config feature telnet disable",
        "loop-protection service activate",
        "no small-servers enable",
        "disable auxiliary port on {HOST}",
        "set system services finger disable",
        "no ip source-route",
        "no service tcp-small-servers",
        "no service udp-small-servers",
        "no ip redirects interface {HOST}",
        "no ip proxy-arp",
        "no service dhcp server",
        "disable unused ethernet port",
        "set system services tftp disable",
        "no mop enabled",
        "shutdown aux console port",
        "no ip identd enable",
        "no service config manifest",
        "disable lldp transmit receive",
        "no cdp enable interface ports",
        "unused vlan suspend prune",
        "set chassis alarm management-link down ignore",
        "no ip gratuitous-arps accept",
        "disable telnet-ssl fallback weak",
        "no ip domain-lookup insecure",
        "disable http api unauthorized port",
        "no service finger daylight",
        "shutdown monitor session span",
    ],
    "banner": [
        "banner motd ^C authorized access only ^C",
        "banner login ^C {HOST} restricted ^C",
        'set system login message "{HOST} authorized only"',
        "login banner {STR} display",
        'motd "{HOST} - no unauthorized access"',
        "banner exec ^C session timeout warning ^C",
        "set system login announcement {HOST} consent",
        "banner incoming {HOST} notice",
        "login-message {HOST} classified system",
        "set system login idle-message logout warning",
        "banner slip-ppp {STR}",
        "issue net {HOST} warning text",
        "pre-login banner {HOST} legal notice",
        "set system announcement {HOST} maintenance",
        "set system login banner success-message",
        "banner prompt-timeout warning text",
        "consent banner criminal penalty notice",
        "set system login welcome-message motd",
        "warning banner monitoring consent required",
        "display login disclaimer {HOST}",
        "set system legal notice unauthorized prohibited",
        "banner foreign-language consent same-text",
        "classified banner handling caveat display",
    ],
    "privilege_escalation": [
        "username {HOST} privilege 15 secret {STR}",
        "set system login class SUPER permissions all",
        "role {HOST}-operator privilege read-only",
        "privilege exec level {N} show running",
        "super-user {HOST} enable password {STR}",
        "set system login user {HOST} class super-user",
    ],
    "routing_integrity": [
        "router bgp {N}",
        "neighbor {IP} remote-as {N}",
        "neighbor {IP} password {STR}",
        "ip prefix-list internal permit 42.0.0.0/8",
        "route-map {HOST} permit 10",
        "set protocols bgp group {HOST} neighbor {IP} authentication-key {STR}",
        "ip ospf authentication message-digest key {N}",
        "bgp bestpath compare-routerid on {HOST}",
    ],
    "interface_security": [
        "interface {HOST}",
        "shutdown port {N} on {HOST}",
        "switchport mode access vlan {N}",
        "ip verify unicast source reachable-via rx",
        "storm-control broadcast level {N}",
        "port-security maximum {N} violation shutdown",
        "set interfaces {HOST} unit 0 family inet filter {HOST}",
        "spanning-tree portfast bpduguard enable",
    ],
    "zone_policy": [
        "set security policies from-zone untrust to-zone trust policy {HOST} match source-address any",
        "set security zones security-zone trust interfaces {HOST}",
        "threat-protection profile untrust-zone strict",
        "zone {HOST} default-policy deny-all",
        "firewall zone {HOST} to {HOST} action drop",
        "set policy from {HOST} to {HOST} deny log",
    ],
    "unknown": [
        "version 12.4",
        "hostname {HOST}",
        "device-system-id {HOST}",
        "serial-number {STR}",
        "model {HOST} rev {N}",
        "commit",
        "end",
        "exit",
        "! last updated {N}",
    ],
}

_VALUES = {
    "{N}": ["5", "10", "12", "30", "60", "90", "120", "300", "600", "2048"],
    "{IP}": ["10.0.0.9", "10.10.1.1", "192.0.2.99", "192.168.1.50", "172.16.0.5"],
    "{HOST}": ["CORE-SW-01", "SRX-FW-01", "SPINE-01", "EDGE-02", "AGGR-04"],
    "{STR}": ["S3cr3tStr1ng", "public-string", "netops-key", "audit-token", "cfg-hash"],
}


def expand_templates() -> dict[str, list[tuple[str, str]]]:
    out: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for label, templates in _SYNTH.items():
        for tmpl in templates:
            keys = [k for k in _VALUES if k in tmpl]
            if not keys:
                out[label].append((tmpl, "synthetic"))
                continue
            # cycle values for diversity without explosion (max 3 variants/template)
            for i in range(3):
                line = tmpl
                for k in keys:
                    vals = _VALUES[k]
                    line = line.replace(k, vals[(i + hash(tmpl) % len(vals)) % len(vals)])
                out[label].append((line, "synthetic"))
    return out


def _is_fragment(text: str) -> bool:
    """JunOS block openers ('role {'), single tokens ('login'), and other
    context-free fragments carry no classifiable signal and act as false
    attractors (e.g. 'forwarding-class X {' is QoS, not privilege_escalation).
    Curated sources (synthetic/rulepack/human) are exempt — bare 'commit' is
    a legitimate unknown-vendor line."""
    t = text.strip()
    if t.rstrip().endswith("{") or t in ("{", "}", "};"):
        return True
    return len(t.split()) < 2


def load_stig_lines() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    if not STIG.exists():
        return rows
    for raw in STIG.read_text(encoding="utf-8").splitlines():
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        text = str(obj.get("text", "")).strip()
        label = str(obj.get("label", "unknown"))
        if label not in SECURITY_CATEGORIES:
            continue
        if _is_fragment(text):
            continue
        rows.append((text, label, f"stig:{obj.get('source','?')}"))
    return rows


def load_rulepack_lines() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for pack in sorted(PACKS.glob("cis_*.yaml")):
        data = yaml.safe_load(pack.read_text(encoding="utf-8")) or {}
        for rule in data.get("rules", []):
            cat = str(rule.get("category", "unknown"))
            if cat not in SECURITY_CATEGORIES:
                continue
            for raw in str(rule.get("remediation_template", "")).splitlines():
                line = raw.strip()
                if len(line) < 4:
                    continue
                # multi-line templates span categories (e.g. a mgmt rule whose
                # fix also contains 'ip ssh version 2'): the line itself wins
                # when unambiguous, else the rule's category.
                use = line_override(line) or cat
                rows.append((line, use, f"rulepack:{pack.stem}:{rule.get('rule_id')}"))
    return rows


def load_sample_lines() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for cfg in sorted(SAMPLES.glob("*.cfg")):
        try:
            text = cfg.read_text(encoding="utf-8")
        except Exception:
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("!", "#")) or len(line) < 4:
                continue
            if _is_fragment(line):
                continue
            label, _ = heuristic_classify(line)
            label = line_override(line) or label
            rows.append((line, label, f"sample:{cfg.name}"))
    return rows


def load_candidates() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    if not CANDIDATES.exists():
        return rows
    for raw in CANDIDATES.read_text(encoding="utf-8").splitlines():
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        text = str(obj.get("text", "")).strip()
        label = str(obj.get("proposed_label", "unknown"))
        if label not in SECURITY_CATEGORIES:
            label = "unknown"
        if _is_fragment(text):
            continue
        label = line_override(text) or label
        rows.append((text, label, f"sieve:{obj.get('source_file','?')}"))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    buckets: dict[str, list[tuple[str, str]]] = defaultdict(list)
    seen: set[str] = set()

    def add(text: str, label: str, source: str) -> bool:
        if label not in SECURITY_CATEGORIES:
            return False
        t = text.strip()
        if len(t) < 4 or len(t) > 300:
            return False
        pat = normalize_pattern(t)
        if pat in seen:
            return False
        if len(buckets[label]) >= TARGET_PER_CLASS_MAX:
            return False
        seen.add(pat)
        buckets[label].append((t, source))
        return True

    # priority 1: STIG labels (highest value: pre-labeled by section, real CLI + CCI)
    for text, label, src in load_stig_lines():
        add(text, label, src)
    # priority 2: rule packs (verified)
    for text, label, src in load_rulepack_lines():
        add(text, label, src)
    # priority 3: sample configs (real vendor syntax)
    for text, label, src in load_sample_lines():
        add(text, label, src)
    # priority 3: sieved candidates (capped: shuffle-free deterministic round-robin
    # to avoid one vendor/flood dominating; cap unknown aggressively)
    cands = load_candidates()
    # deterministic interleave: sort then take round-robin per label
    by_label: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for text, label, src in sorted(cands, key=lambda r: r[0]):
        by_label[label].append((text, label, src))
    for label in SECURITY_CATEGORIES:
        for text, lab, src in by_label.get(label, []):
            if label == "unknown" and len(buckets[label]) >= 60:
                break
            add(text, lab, src)
    # priority 4: synthetic fill to floor
    synth = expand_templates()
    for label in SECURITY_CATEGORIES:
        need = TARGET_PER_CLASS_MIN - len(buckets[label])
        if need <= 0:
            continue
        cycled = itertools.cycle(sorted(synth.get(label, [])))
        guard = 0
        while need > 0 and guard < 500:
            guard += 1
            text, src = next(cycled)
            if add(text, label, src):
                need -= 1

    total = sum(len(v) for v in buckets.values())
    print(f"total rows: {total}")
    for label in SECURITY_CATEGORIES:
        n = len(buckets[label])
        flag = "THIN" if n < TARGET_PER_CLASS_MIN else ("CAP" if n >= TARGET_PER_CLASS_MAX else "ok")
        print(f"  {label}: {n} [{flag}]")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        # deterministic: category-major, alphabetical within
        for label in SECURITY_CATEGORIES:
            for text, src in sorted(buckets[label], key=lambda r: r[0]):
                f.write(json.dumps({"text": text, "label": label, "source": src}) + "\n")
    print(f"wrote: {out_path}")


if __name__ == "__main__":
    main()
