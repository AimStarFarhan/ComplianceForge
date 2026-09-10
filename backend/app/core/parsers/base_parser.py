"""Abstract parser interface. Every vendor parser emits a SecurityBaselineModel."""

from __future__ import annotations

import abc
import re

from app.core.schema import SecurityBaselineModel

VENDOR_CISCO_IOS = "cisco_ios"
VENDOR_JUNIPER_SRX = "juniper_srx"
VENDOR_SONIC = "sonic"
VENDOR_UNSEEN = "unseen_vendor"

VENDORS = [VENDOR_CISCO_IOS, VENDOR_JUNIPER_SRX, VENDOR_SONIC]

VENDOR_LABELS = {
    VENDOR_CISCO_IOS: "Cisco IOS/IOS-XE",
    VENDOR_JUNIPER_SRX: "Juniper SRX",
    VENDOR_SONIC: "SONiC",
    VENDOR_UNSEEN: "Unseen Vendor (Training Loop)",
}


class BaseParser(abc.ABC):
    """Contract: parse() -> vendor-neutral SecurityBaselineModel.

    Implementations MUST:
      - map every confidently-recognized line into concept buckets
      - push anything unrecognized into unparsed_lines (with line numbers)
      - never raise on malformed input; record parse_warnings instead
    """

    vendor: str = "base"

    @abc.abstractmethod
    def parse(self, config_text: str, device_id: str) -> SecurityBaselineModel:
        ...

    # -- shared helpers -----------------------------------------------------
    @staticmethod
    def lines(config_text: str) -> list[tuple[int, str]]:
        """Yield (1-based line number, stripped line) skipping blanks only."""
        out = []
        for i, raw in enumerate(config_text.splitlines(), start=1):
            s = raw.strip()
            if s:
                out.append((i, s))
        return out


def detect_vendor(config_text: str, filename: str = "") -> str:
    """Best-effort vendor detection from config syntax fingerprints.

    Strategy: score POSITIVE evidence per vendor (multi-line, weighted), then
    also score foreign-syntax signals. A vendor wins only if it has positive
    evidence AND no stronger foreign signals — otherwise the config routes
    to the unseen-vendor path (Training Loop), which is always the safe
    default for unrecognized syntax.
    """
    lowered = config_text.lower()

    def _count(pattern: str) -> int:
        return len(re.findall(pattern, config_text, re.MULTILINE | re.IGNORECASE))

    # ---- Juniper positive signals (Junos set-style hierarchy) ----
    juniper_score = (
        _count(r"^set (system|security|interfaces|routing-options|groups|protocols|vlans|chassis|snmp)\b")
        + _count(r"^\s*(system|security|interfaces|routing-options)\s*\{")
    )

    # ---- SONiC positive signals (CONFIG_DB JSON tables / sonic CLI) ----
    sonic_score = (
        len(re.findall(r'"(DEVICE_METADATA|ACL_TABLE|ACL_RULE|SNMP_COMMUNITY|SYSLOG_SERVER|NTP_SERVER|FEATURE|TACPLUS_SERVER|BANNER|SSH_SERVER)"\s*:', config_text))
        + _count(r"^sudo config\s")
    )
    if "sonic" in lowered:
        sonic_score += 5

    # ---- Cisco IOS positive signals ----
    cisco_score = (
        _count(r"^(hostname|username|enable secret|ip domain-name|crypto key generate)\b")
        + _count(r"^ip (ssh|http)\b")
        + _count(r"^line (vty|console|aux)\b")
        + _count(r"^(interface|router)\s+\S+")
        + _count(r"^(aaa|service|snmp-server|logging|ntp server|banner motd|access-list|ip access-list)\b")
    )

    # ---- Foreign-syntax signals: things ComplianceForge's 3 parsers never emit.
    # Any of these present means the config is NOT one of the 3 known vendors,
    # even if some generic lines (hostname/ntp server/banner) look familiar.
    foreign_markers = [
        r"^devicehost\b",                 # PAN-OS style
        r"^device-name\b",                # ArubaOS-CX style
        r"^config system\b",              # FortiOS style
        r"^config (global|log|firewall|network)\b",
        r"^set deviceconfig\b",           # PAN-OS deviceconfig
        r"^set mgmt-interface\b",         # PAN-OS mgmt
        r"^set snmp-community\b",         # PAN-OS snmp
        r"^set security-policy\b",        # PAN-OS policy
        r"^set network profiles\b",       # PAN-OS ike
        r"^commit-confirmed\b",
        r"^vlan \d+ name\b",              # Aruba vlan naming
        r"^web-management\b",             # Aruba web mgmt
        r"^crypto tls-profile\b",         # Aruba crypto profile
        r"^password-policy\b",            # Aruba passwd policy
        r"^loop-protect\b",
        r"^banner ready\b",               # Aruba banner verb
        r"^interface 1/1/\d",             # Aruba slot/port naming (1/1/7)
        r"^no ssh public-key\b",          # Aruba ssh phrasing
        r"^set admin-sport\b",            # FortiOS
        r"^set admin-telnet-port\b",      # FortiOS
        r"^set admin-ftp\b",              # FortiOS
        r"^set ssh-version\b",            # FortiOS (vs Cisco 'ip ssh version')
        r"^set admin-password-min-length\b",
        r"^set community-name\b",         # FortiOS snmp
        r"^set ntpserver\b",              # FortiOS ntp
        r"^set ttl-default\b",            # FortiOS session ttl
        r"^edit \"",                      # FortiOS edit blocks
        r"^\s*next$",                     # FortiOS next terminator
    ]
    foreign_hits = sum(1 for pat in foreign_markers if re.search(pat, config_text, re.MULTILINE | re.IGNORECASE))

    # Decision: a known vendor needs REAL positive evidence, and fewer/equal
    # foreign markers than its own signal strength. If foreign syntax markers
    # are present at all, require the known-vendor signal to dominate 3:1.
    scores = {
        VENDOR_JUNIPER_SRX: juniper_score,
        VENDOR_SONIC: sonic_score,
        VENDOR_CISCO_IOS: cisco_score,
    }
    best_vendor, best_score = max(scores.items(), key=lambda kv: kv[1])

    if best_score >= 3 and (foreign_hits == 0 or best_score >= 3 * foreign_hits):
        return best_vendor

    # filename hints are only trusted when there is NO foreign syntax
    if foreign_hits == 0 and filename:
        fl = filename.lower()
        if "juniper" in fl or "srx" in fl or "junos" in fl:
            return VENDOR_JUNIPER_SRX
        if "sonic" in fl:
            return VENDOR_SONIC
        if "cisco" in fl or "ios" in fl:
            return VENDOR_CISCO_IOS

    return VENDOR_UNSEEN


def vendor_from_string(vendor: str) -> str:
    v = (vendor or "").lower().strip()
    alias = {
        "cisco": VENDOR_CISCO_IOS,
        "cisco_ios": VENDOR_CISCO_IOS,
        "ios": VENDOR_CISCO_IOS,
        "juniper": VENDOR_JUNIPER_SRX,
        "juniper_srx": VENDOR_JUNIPER_SRX,
        "srx": VENDOR_JUNIPER_SRX,
        "junos": VENDOR_JUNIPER_SRX,
        "sonic": VENDOR_SONIC,
    }
    if v in alias:
        return alias[v]
    return VENDOR_UNSEEN
