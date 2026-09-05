"""Inferred baseline: reconstruct a SecurityBaselineModel for an UNSEEN vendor
using only the human-confirmed rule cache.

This is the "learn a new vendor" loop closing:
  1. ingest unknown-syntax config -> every line lands in the Training Queue
  2. human confirms AI-suggested categories
  3. re-audit: confirmed categories + line polarity (+ enable/disable verbs,
     weak-cipher keywords, default SNMP strings...) infer a real baseline
  4. the generic rule pack then audits it EXACTLY like a known vendor

Every finding produced this way is tagged source='ai_suggested_human_confirmed'
because the evidence itself came from human-confirmed mappings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.core.rule_cache import RuleCache
from app.core.schema import (
    ACLRule,
    CryptoFinding,
    DeviceInfo,
    RawLine,
    SecurityBaselineModel,
)

# verb heuristics: does the line TURN ON or TURN OFF the concept?
ENABLE_RE = re.compile(r"\b(enable|enabled|start|activate|on|permit|allow|open|run|yes)\b", re.I)
DISABLE_RE = re.compile(r"\b(no |disable|disabled|shutdown|deny|deny-all|off|block|close|stop|no)\b", re.I)
WEAK_CIPHER_RE = re.compile(r"\b(des|3des|rc4|md5|sha1|export|null)\b", re.I)
DEFAULT_SNMP_RE = re.compile(r"^(public|private)[-_a-z0-9]*$", re.I)
QUOTED_VALUE_RE = re.compile(r'"([^"]*)"')
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
NUM_RE = re.compile(r"\b(\d{1,5})\b")

# category -> (model attribute path, polarity) where True means "good/secure on"
CATEGORY_SIGNALS: dict[str, list[tuple[str, bool]]] = {
    # management_protocol: lines usually describe a mgmt service being on/off
    "management_protocol": [("management", None)],  # resolved per-line below
    "ssh_policy": [("management.ssh_enabled", True)],
    "authentication": [],  # depends on verbs, handled per-line
    "aaa": [("auth.aaa_enabled", True)],
    "password_policy": [("auth.password_complexity_enabled", True)],
    "logging": [("logging.log_admin_access", True)],
    "syslog": [("logging.remote_logging_enabled", True)],
    "acl_logging": [("acl.acl_logging_enabled", True)],
    "cryptography": [("crypto.ssh_algorithm_bound", True)],
    "snmp_management": [("management.snmp_enabled", None)],
    "ntp": [("management.ntp_configured", True)],
    "banner": [("management.banner_present", True)],
    "zone_policy": [("acl.default_deny", None)],
}


@dataclass
class _Tally:
    on: int = 0
    off: int = 0
    examples: list[str] = field(default_factory=list)


def _line_polarity(line: str) -> bool | None:
    """True = enabling/on, False = disabling/off, None = ambiguous."""
    d = bool(DISABLE_RE.search(line))
    e = bool(ENABLE_RE.search(line))
    if d and not e:
        return False
    if e and not d:
        return True
    return None


def infer_baseline(db, device_id: str, raw_config: str) -> tuple[SecurityBaselineModel, dict[str, _Tally]]:
    """Build a baseline for unseen-vendor configs from confirmed mappings."""
    cache = RuleCache(db)
    model = SecurityBaselineModel(
        device=DeviceInfo(device_id=device_id, vendor="unseen_vendor", device_type="unseen")
    )
    tallies: dict[str, _Tally] = {}
    unmapped: list[RawLine] = []

    for i, raw in enumerate(raw_config.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        hit = cache.match(line, vendor_hint="any")
        if not hit:
            unmapped.append(RawLine(line_number=i, text=line))
            continue
        category = hit["category"]
        t = tallies.setdefault(category, _Tally())
        pol = _line_polarity(line)
        if pol is True:
            t.on += 1
        elif pol is False:
            t.off += 1
        t.examples.append(line)

        # per-category semantic inference
        low = line.lower()

        if category == "management_protocol":
            if "telnet" in low:
                model.management.telnet_enabled = pol is not False and (model.management.telnet_enabled is not False)
                if pol is False:
                    model.management.telnet_enabled = False
                elif pol is True:
                    model.management.telnet_enabled = True
            if re.search(r"http|web", low) and "https" not in low:
                cleartext = bool(re.search(r"plaintext|port 80\b|:80\b|http\b", low))
                if pol is False:
                    model.management.http_mgmt_enabled = False
                elif pol is True or cleartext:
                    model.management.http_mgmt_enabled = True
            if "ssh" in low or "secure-shell" in low:
                if pol is False:
                    model.management.ssh_enabled = False
                elif pol is True:
                    model.management.ssh_enabled = True

        elif category == "ssh_policy":
            if pol is False and re.search(r"protocol-?2|v2|version\s*2", low) is None:
                pass  # disabling something ssh-ish — don't guess
            m2 = re.search(r"protocol-?v?ersion?[- ]?2", low)
            if m2:
                model.management.ssh_version = 2
                model.management.ssh_enabled = True
            elif pol is True:
                model.management.ssh_enabled = True

        elif category == "authentication":
            if re.search(r"root|admin", low) and pol is False:
                model.auth.default_credentials_changed = True
            if re.search(r"lockout|block-for|retry", low):
                model.auth.login_retry_lockout = pol is not False
            m = NUM_RE.search(line)
            if "min" in low and m:
                try:
                    val = int(m.group(1))
                    if val <= 64:  # sane password lengths
                        model.auth.password_min_length = val
                except ValueError:
                    pass

        elif category == "password_policy":
            m = NUM_RE.search(line)
            if "min" in low and m:
                try:
                    val = int(m.group(1))
                    if val <= 64:
                        model.auth.password_min_length = val
                except ValueError:
                    pass
            if re.search(r"weak|default|plain", low) and pol is not False:
                model.auth.default_credentials_changed = False

        elif category == "syslog" or category == "logging":
            ip = IP_RE.search(line)
            if ip:
                model.logging.remote_syslog_servers.append(ip.group(0))
                model.logging.remote_logging_enabled = True
            elif category == "logging" and pol is not False:
                model.logging.log_admin_access = True

        elif category == "snmp_management":
            model.management.snmp_enabled = pol is not False if pol is not None else True
            qm = QUOTED_VALUE_RE.search(line)
            community = qm.group(1) if qm else None
            if community:
                model.management.snmp_communities.append(community)
                if DEFAULT_SNMP_RE.match(community):
                    model.crypto.password_hashes_plaintext  # keep import used
                    model.auth.default_credentials_changed = False

        elif category == "cryptography":
            if WEAK_CIPHER_RE.search(low) and pol is not False:
                model.crypto.weak_ciphers_present.append(CryptoFinding(cipher=WEAK_CIPHER_RE.search(low).group(1), raw=line))

        elif category == "ntp":
            model.management.ntp_configured = True

        elif category == "banner":
            model.management.banner_present = True

        elif category == "access_control" or category == "zone_policy":
            ip = IP_RE.search(line)
            model.acl.rules.append(
                ACLRule(raw=line, action="deny" if pol is False else "permit", source=ip.group(0) if ip else None)
            )
            if pol is False:
                model.acl.default_deny = True

        elif category == "acl_logging":
            model.acl.acl_logging_enabled = pol is not False

        elif category == "service_hardening":
            if pol is True:
                model.services.unused_services.append(line)

    model.unparsed_lines = unmapped
    return model, tallies
