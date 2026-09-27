"""Cisco IOS config parser -> SecurityBaselineModel.

Deterministic regex-based parsing. Every unmatched non-trivial line lands in
unparsed_lines so the Training Loop can propose a category for a human.
"""

from __future__ import annotations

import re

from app.core.parsers.base_parser import VENDOR_CISCO_IOS, BaseParser
from app.core.schema import (
    ACLRule,
    CryptoFinding,
    RawLine,
    SecurityBaselineModel,
)

INTERFACE_RE = re.compile(r"^interface\s+(\S+)")


class CiscoIOSParser(BaseParser):
    vendor = VENDOR_CISCO_IOS

    def parse(self, config_text: str, device_id: str) -> SecurityBaselineModel:
        model = SecurityBaselineModel.model_construct()
        model.device = self._device(device_id)
        self._ctx: str | None = None
        self._seen: set[int] = set()

        for line_no, line in self.lines(config_text):
            self._consume(model, line_no, line)
        return model

    # ------------------------------------------------------------------ device
    def _device(self, device_id):
        from app.core.schema import DeviceInfo

        return DeviceInfo(device_id=device_id, vendor=VENDOR_CISCO_IOS)

    # ------------------------------------------------------------------ consume
    def _consume(self, m: SecurityBaselineModel, line_no: int, line: str) -> None:
        self._remember(m, line_no, line)

        mgmt, auth, log, crypto, acl, svc = m.management, m.auth, m.logging, m.crypto, m.acl, m.services
        low = line.lower()

        # ---- device identity -------------------------------------------------
        mt = re.match(r"^hostname\s+(\S+)", line)
        if mt:
            m.device.hostname = mt.group(1)
            return
        mt = re.match(r"^version\s+(\S+)", line)
        if mt:
            m.device.os_version = mt.group(1)
            return
        mt = re.match(r"^(?:boot system flash[:\s]+)?(\S+)\s+software\s+\(.*\)\.?", line)
        if mt and not m.device.os_version:
            m.device.model = mt.group(1)

        # ---- management protocols -------------------------------------------
        if re.search(r"^ip http server|^\s+ip http server", line):
            mgmt.http_mgmt_enabled = True
            return
        if re.search(r"^no ip http server", line):
            mgmt.http_mgmt_enabled = False
            return
        if re.search(r"^ip http secure-server", line):
            mgmt.https_mgmt_enabled = True
            return
        mt = re.search(r"^ip ssh version\s+(\d+)", line)
        if mt:
            mgmt.ssh_version = int(mt.group(1))
            mgmt.ssh_enabled = True
            return
        if re.match(r"^ip domain[- ]name", line):
            return
        if re.match(r"^crypto key generate rsa", line):
            crypto.ssh_algorithm_bound = True
            mt = re.search(r"modulus\s+(\d+)", line)
            if mt:
                crypto.key_modulus_bits = int(mt.group(1))
            return
        if low == "line vty 0 4" or re.match(r"^line (aux|console|vty)", low):
            self._ctx = line
            return
        if self._ctx and "line " in (self._ctx or ""):
            mt = re.search(r"^exec-timeout\s+(\d+)(?:\s+(\d+))?", line)
            if mt:
                mins = int(mt.group(1))
                secs = int(mt.group(2) or 0)
                mgmt.idle_timeout_seconds = mins * 60 + secs
                mgmt.exec_timeout_configured = True
                self._remember(m, line_no, line)
                return
            if re.match(r"^transport input", line):
                low_t = low.replace("transport input", "").strip()
                mgmt.ssh_enabled = "ssh" in low_t
                mgmt.telnet_enabled = "telnet" in low_t or low_t == "all"
                return
            if re.match(r"^transport output", line):
                return
            if re.match(r"^exec-timeout", line):
                mgmt.exec_timeout_configured = True
                return
            if re.match(r"^access-class", line, re.I):
                svc.vty_acl_bound = True
                acl.management_acl_bound = True
                return
            if re.match(r"^login local", line, re.I):
                auth.aaa_enabled = auth.aaa_enabled or False
                return
            if re.match(r"^(password|login)$", low):
                return

        # ---- banners / NTP / SNMP / CDP --------------------------------------
        if re.match(r"^banner (motd|incoming|exec|login)", line, re.I):
            mgmt.banner_present = True
            self._banner = True
            return
        if re.match(r"^ntp server", line):
            mgmt.ntp_configured = True
            mt_ip = re.match(r"^ntp server\s+(\S+)", line)
            if mt_ip:
                mgmt.ntp_servers.append(mt_ip.group(1))
            return
        if re.match(r"^no cdp run", line, re.I):
            mgmt.cdp_enabled = False
            return
        if re.match(r"^cdp run", line, re.I):
            mgmt.cdp_enabled = True
            return
        mt = re.search(r"^snmp-server community\s+(\S+)(.*)", line)
        if mt:
            mgmt.snmp_enabled = True
            mgmt.snmp_communities.append(mt.group(1))
            if " ro" in mt.group(2).lower():
                pass
            return
        if re.match(r"^no snmp-server", line, re.I):
            mgmt.snmp_enabled = False
            return
        if re.match(r"^snmp-server (location|contact|host|enable traps)", line, re.I):
            mgmt.snmp_enabled = True
            return

        # ---- auth / AAA ------------------------------------------------------
        mt = re.search(r"^enable secret", line)
        if mt:
            auth.default_credentials_changed = True
            if " 5 " in line or " 8 " in line or " 9 " in line:
                crypto.password_hashes_plaintext.append(line)
            return
        mt = re.search(r"^enable password", line)
        if mt:
            auth.default_credentials_changed = False
            return
        mt = re.search(r"^username\s+(\S+)", line)
        if mt:
            auth.local_user_accounts += 1
            if " privilege 15 " in low or low.endswith(" privilege 15"):
                if re.search(r"privilege 15$", low):
                    auth.privilege_level_15_empty = auth.privilege_level_15_empty or None
            if re.search(r"(password|secret)\s+\d?", low):
                pass
            return
        if re.match(r"^service password-encryption", line, re.I):
            auth.password_encryption_enabled = True
            return
        if re.match(r"^aaa new-model", line, re.I):
            auth.aaa_enabled = True
            return
        if re.match(r"^aaa authentication", line, re.I):
            if "local" in low:
                auth.authentication_fallback_local = True
            auth.aaa_enabled = True
            return
        if re.match(r"^aaa authorization", line, re.I):
            auth.aaa_enabled = True
            return
        if re.match(r"^aaa accounting", line, re.I):
            auth.aaa_accounting_enabled = True
            return
        if re.match(r"^tacacs-server|^radius-server", line, re.I):
            mt_ip = re.search(r"host\s+(\S+)", line) or re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if mt_ip:
                auth.central_auth_servers.append(mt_ip.group(1))
            return
        mt = re.search(r"^security passwords min-length\s+(\d+)", line)
        if mt:
            auth.password_min_length = int(mt.group(1))
            return
        if re.match(r"^login block-for", line, re.I):
            auth.login_retry_lockout = True
            return
        if re.match(r"^login delay", line, re.I):
            auth.login_retry_lockout = True
            return
        if re.match(r"^no service password-recovery", line, re.I):
            auth.service_password_recovery_disabled = True
            return

        # ---- logging ---------------------------------------------------------
        mt = re.search(r"^logging host\s+(\S+)", line)
        if mt:
            log.remote_logging_enabled = True
            log.remote_syslog_servers.append(mt.group(1))
            return
        if re.match(r"^logging (.*) informational", line, re.I):
            log.logging_level_informational = True
            return
        if re.match(r"^logging buffered", line, re.I):
            log.logging_buffered = True
            return
        if re.match(r"^logging on", line, re.I):
            return
        mt = re.search(r"^logging\s+(?:host\s+)?(\d+\.\d+\.\d+\.\d+)", line)
        if mt:
            log.remote_logging_enabled = True
            log.remote_syslog_servers.append(mt.group(1))
            return
        if re.match(r"^service timestamps log", line, re.I):
            log.logging_timestamps = True
            return
        if re.match(r"^archive\s*$", line, re.I) or re.match(r"^log config", line, re.I) or re.match(r"^logging enable", line, re.I) or re.match(r"^notify syslog", line, re.I):
            log.log_admin_access = True
            return

        # ---- services --------------------------------------------------------
        if re.match(r"^no service pad", line, re.I):
            svc.pad_enabled = False
            return
        if re.match(r"^service pad", line, re.I):
            svc.pad_enabled = True
            return
        if re.match(r"^no ip bootp server", line, re.I):
            svc.bootp_enabled = False
            return
        if re.match(r"^ip bootp server", line, re.I):
            svc.bootp_enabled = True
            return
        if re.match(r"^no service finger", line, re.I) or re.match(r"^no ip finger", line, re.I):
            svc.finger_enabled = False
            return
        if re.match(r"^service tcp-small-servers", line, re.I) or re.match(r"^service udp-small-servers", line, re.I):
            svc.unused_services.append(line)
            return
        if re.match(r"^no service tcp-small-servers", line, re.I) or re.match(r"^no service udp-small-servers", line, re.I):
            return
        if re.match(r"^no ip http server", line, re.I):
            mgmt.http_mgmt_enabled = False
            return
        if re.match(r"^no service config", line, re.I):
            return
        if re.match(r"^no ip source-route", line, re.I):
            return
        if re.match(r"^no ip domain-lookup", line, re.I):
            return
        if re.match(r"^no ip http", line, re.I):
            mgmt.http_mgmt_enabled = False
            return
        if re.match(r"^lldp run", line, re.I):
            mgmt.lldp_enabled = True
            return
        if re.match(r"^no lldp run", line, re.I):
            mgmt.lldp_enabled = False
            return

        # ---- interfaces / ACLs ------------------------------------------------
        if INTERFACE_RE.match(line):
            self._ctx = line
            return
        if self._ctx and INTERFACE_RE.match(self._ctx or ""):
            if re.match(r"^no shutdown", line, re.I) or re.match(r"^shutdown", line, re.I):
                return
            if re.match(r"^(ip address|description|switchport|no switchport|spanning-tree|duplex|speed|mtu|vrf|standby|channel-group|ipv6|media-type|negotiation|flowcontrol|power|storm-control)", line, re.I):
                return
            if re.match(r"^(ip|ipv6)?\s*(access-group|access-list)", line, re.I):
                mt2 = re.search(r"access-group\s+(\S+)\s+(\S+)", line)
                if mt2:
                    acl.management_acl_bound = acl.management_acl_bound or ("in" in mt2.group(2))
                    svc.vty_acl_bound = svc.vty_acl_bound or None
                return
            if re.match(r"^(ip|ipv6)?\s*(dhcp|helper-address|pim|igsrp)", line, re.I):
                return
            if re.match(r"^(vrrp|hsrp|ospf|eigrp|isis)", line, re.I):
                return
            self._unparsed(m, line_no, line)
            return

        # Numbered ACL entries are single-line rules (e.g.
        # `access-list 99 permit 10.0.0.0 0.255.255.255`). Parse them BEFORE
        # the header branch below, which would otherwise swallow them via
        # `^access-list\s+\d+` and leave acl.rules empty (CF-CISCO-012 then
        # vacuously passes on `acl.rules == []` without ever evaluating).
        mt = re.search(r"^access-list\s+(\d+)\s+(permit|deny)\s+(\S+)\s+(\S+)(?:\s+(\S+))?", line, re.I)
        if mt:
            logged = bool(re.search(r"\blog\b", line, re.I))
            acl.rules.append(
                ACLRule(
                    raw=line,
                    action=mt.group(2).lower(),
                    protocol=mt.group(3),
                    source=mt.group(4),
                    destination=mt.group(5),
                    logged=logged,
                )
            )
            if logged:
                acl.acl_logging_enabled = True
            return
        if re.match(r"^ip access-list", line, re.I) or re.match(r"^access-list\s+\d+", line, re.I):
            self._acl_mode = True
            self._ctx = line
            return
        if getattr(self, "_acl_mode", False) and self._ctx and re.match(r"^ip access-list", self._ctx or "", re.I):
            mt = re.search(r"^(permit|deny)\s+(\S+)\s+(\S+)(?:\s+(\S+))?(?:\s+(\S+))?", line, re.I)
            logged = bool(re.search(r"\blog\b", line, re.I))
            if mt:
                acl.rules.append(
                    ACLRule(
                        raw=line,
                        action=mt.group(1).lower(),
                        protocol=mt.group(2),
                        source=mt.group(3),
                        destination=mt.group(4),
                        logged=logged,
                    )
                )
            else:
                # remark or sequence - still ACL content
                pass
            if logged:
                acl.acl_logging_enabled = True
            return
        # implicit deny: standard ACL ending in explicit deny
        for rule in acl.rules:
            if rule.action == "deny":
                pass
        if re.search(r"access-class\s+(\d+)\s+in", line, re.I):
            svc.vty_acl_bound = True
            acl.management_acl_bound = True
            return

        # ---- crypto ------------------------------------------------------------
        mt = re.search(r"^(?:ssh|ip ssh)\s+(?:algorithm|cipher|mac)\s+(\S+)\s+(\S+)", line, re.I)
        if mt:
            crypto.ssh_algorithm_bound = True
            return
        mt = re.search(r"^ip ssh dh min size\s+(\d+)", line, re.I)
        if mt:
            crypto.ipsec_dh_group_weak = int(mt.group(1)) < 2048
            return
        if re.search(r"snmp-server community (public|private)", line, re.I):
            return

        # ---- global structural commands ---------------------------------------
        if re.match(r"^(ip|ipv6) (subnet-zero|classless|cef|routing|name-server|domain-list)", line, re.I):
            return
        if re.match(r"^(spanning-tree mode|spanning-tree extend)", line, re.I):
            return
        if re.match(r"^(vlan|vtp|port-channel|mac access-list)", line, re.I):
            return
        if re.match(r"^(router|key|monitor|voice|telephony|mgmt|campus|ip dhcp|track|rmon|archive|setup|exception|process|license|boot|diag|event|memory|policy|redundancy|task|control-plane| call|gatekeeper|hw-module|linecard|cns|privacy|crypto pki|certificate|ip http|interface|controller|flash|file| errdisable|service-template|device|smart-license|platform|ethernet|mac-address-table|errdisable|logging console|line|ntp|max|vrf definition|parameter-map|identity policy)", line, re.I):
            # structural - skip as recognized container
            return
        if re.match(r"^logging console", line, re.I):
            return
        if re.match(r"^(ntp|max|time-range|ip scp|ip source|ip admission|ip inspect|ip verify|ip arp|access-list)", line, re.I):
            return
        if re.match(r"^(end|exit|!\s*$|!)", line):
            return
        if re.match(r"^(description)\b", line, re.I):
            return
        if re.match(r"^Current configuration", line, re.I):
            return
        if re.match(r"^(Building configuration|Last configuration change|NVRAM|Using)", line, re.I):
            return
        if re.match(r"^(username\s+\S+\s+privilege\s+\d+\s+(password|secret))", line, re.I):
            return

        self._unparsed(m, line_no, line)

    # ------------------------------------------------------------------ helpers
    def _remember(self, m: SecurityBaselineModel, line_no: int, line: str) -> None:
        self._seen.add(line_no)

    def _unparsed(self, m: SecurityBaselineModel, line_no: int, line: str) -> None:
        m.unparsed_lines.append(
            RawLine(line_number=line_no, text=line, context=self._ctx)
        )
