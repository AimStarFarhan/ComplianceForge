"""Shared high-precision line -> category overrides.

Used by dataset builders (scripts/parse_stig.py, scripts/build_seed_dataset.py)
so every source labels unambiguous CLI lines the SAME way. When a mined line
itself declares its category, the line wins over section titles, rule-pack
categories, and heuristic guesses — a STIG rule's fix text mixes heterogeneous
lines (commit, login-class, syslog host) under one title, and multi-line
remediation templates span categories, so source-first labeling mislabels them.

First match wins; technology-specific patterns come before generic ones
(ntp before crypto so 'set system ntp authentication-key' stays ntp).
"""

from __future__ import annotations

import re

LINE_OVERRIDE: list[tuple[str, str]] = [
    (r"^ip ssh\b|^ssh\b|set system services ssh|ssh (version|algorithm|timeout)", "ssh_policy"),
    (r"ntp|chrony", "ntp"),
    (r"^snmp-server|^snmp\b|set snmp|community string", "snmp_management"),
    (r"logging host|syslog host|syslog server|notify syslog|set system syslog host|change-log", "syslog"),
    (r"tacacs|tacplus|radius|aaa (authentication|authorization|accounting)|authentication-order", "aaa"),
    (r"^banner\b|motd|login message|login announcement", "banner"),
    (r"^crypto\b|ssh-keygen|set security ike|hmac-sha|authentication-key|trusted-key|isakmp|\bcipher\b|lifetime-seconds| engine-id", "cryptography"),
    (r"^router bgp\b|^router ospf\b|neighbor .* remote-as|prefix-list|route-map|bgp group", "routing_integrity"),
    (r"^interface\b|switchport|spanning-tree|storm-control|port-security|set interfaces ", "interface_security"),
    (r"from-zone|security-zone", "zone_policy"),
    (r"dhcp|autoinstallation", "service_hardening"),
]


def line_override(line: str) -> str | None:
    """High-precision line category, or None if the line is ambiguous."""
    low = line.lower()
    for pattern, category in LINE_OVERRIDE:
        if re.search(pattern, low):
            return category
    return None
