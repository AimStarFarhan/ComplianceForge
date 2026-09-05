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
    """Best-effort vendor detection from config syntax fingerprints."""
    lowered = config_text.lower()

    # Juniper: set security / set system / hierarchy + header text
    if (
        "set system" in lowered
        or "set security" in lowered
        or "set interfaces" in lowered
        or "set routing-options" in lowered
        or "set groups" in lowered
        or "system {" in lowered
        or "security {" in lowered
    ):
        return VENDOR_JUNIPER_SRX

    # SONiC: JSON {"<table>": {...}} with CONFIGDB tables or sudo config commands
    if re.search(r'^\s*"\w[\w-]*"\s*:\s*\{', config_text, re.MULTILINE) or re.search(
        r'"(INTERFACE|VLAN|NTP|SYSLOG_SERVER|AAA|DEVICE_METADATA|SNMP_COMMUNITY|ACL_TABLE|MGMT_PORT|TELEMETRY|FEATURE|BANNER)"\s*:', config_text
    ):
        return VENDOR_SONIC
    if "config banner" in lowered or "sudo config" in lowered or "sonic" in lowered:
        return VENDOR_SONIC

    # Cisco IOS: hostname/username/version style CLI
    if re.search(r"^(hostname|username|enable secret|ip domain-name|crypto key generate)", config_text, re.MULTILINE | re.IGNORECASE) or (
        "ip ssh version" in lowered
    ):
        return VENDOR_CISCO_IOS

    # strongly-vendor-flavored CLI lines — even without a full header, these
    # fingerprints identify the vendor family, not just any single line
    if re.search(r"^(ip|snmp-server|line vty|interface \S+|router |aaa |service )", config_text, re.MULTILINE) and re.search(
        r"(snmp-server |exec-timeout |access-list |ip http |ip ssh |banner motd)", lowered
    ):
        return VENDOR_CISCO_IOS

    if filename:
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
