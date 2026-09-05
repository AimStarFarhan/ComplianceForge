"""Juniper SRX (Junos set-style / hierarchical) parser -> SecurityBaselineModel.

Supports both `set ...` one-liner dumps and brace hierarchy configs.
"""

from __future__ import annotations

import re

from app.core.parsers.base_parser import VENDOR_JUNIPER_SRX, BaseParser
from app.core.schema import ACLRule, RawLine, SecurityBaselineModel


class JuniperSRXParser(BaseParser):
    vendor = VENDOR_JUNIPER_SRX

    def parse(self, config_text: str, device_id: str) -> SecurityBaselineModel:
        is_set_style = re.search(r"^set\s+\w+", config_text, re.MULTILINE)
        if is_set_style:
            return self._parse_set(config_text, device_id)
        return self._parse_hierarchical(config_text, device_id)

    # ------------------------------------------------------------- set-style
    def _parse_set(self, config_text: str, device_id: str) -> SecurityBaselineModel:
        from app.core.schema import DeviceInfo

        m = SecurityBaselineModel.model_construct()
        m.device = DeviceInfo(device_id=device_id, vendor=VENDOR_JUNIPER_SRX, device_type="firewall")
        self._ctx = None

        for line_no, line in self.lines(config_text):
            self._consume_set(m, line_no, line)
        # post-process: infer ntp/syslog/snmp flags
        self._finalize(m)
        return m

    def _consume_set(self, m: SecurityBaselineModel, line_no: int, line: str) -> None:
        low = line.lower()
        mgmt, auth, log, crypto, acl, svc = m.management, m.auth, m.logging, m.crypto, m.acl, m.services

        mt = re.match(r"^set system host-name\s+(\S+)", line)
        if mt:
            m.device.hostname = mt.group(1)
            return
        mt = re.search(r'junos:version="?([\d.A-Za-z\[\]-]+)"?', line)
        if mt:
            m.device.os_version = mt.group(1)
            return

        # management protocols
        if re.match(r"^set system services ssh", line):
            mgmt.ssh_enabled = True
            mt = re.search(r"protocol-version\s+(v\d)", line)
            if mt:
                mgmt.ssh_version = 2 if "v2" in mt.group(1) else 1
            mt = re.search(r"protocol-version v2", low)
            return
        if "protocol-version v1" in low:
            mgmt.ssh_version = 1
            return
        if re.search(r"root-login (allow|deny|password-only)", low):
            if "deny" in low or "password-only" in low:
                auth.default_credentials_changed = auth.default_credentials_changed or True
            return
        if re.match(r"^set system services telnet", line):
            mgmt.telnet_enabled = True
            return
        if re.match(r"^set system services web-management http", line):
            mgmt.http_mgmt_enabled = True
            return
        if re.match(r"^set system services web-management https", line):
            mgmt.https_mgmt_enabled = True
            return
        if re.match(r"^set system ports console log-out-on-disconnect", line):
            mgmt.console_line_protection = True
            return
        if re.match(r"^set system autoinstallation", line):
            svc.unused_services.append(line)
            return

        # idle timeout
        mt = re.search(r"^set system login class \S+ idle-timeout\s+(\d+)", line)
        if mt:
            secs = int(mt.group(1))
            mgmt.idle_timeout_seconds = secs if secs < 1000 else secs // 60 if secs else 0
            # Junos idle-timeout is in minutes
            mgmt.idle_timeout_seconds = int(mt.group(1)) * 60
            mgmt.exec_timeout_configured = True
            return

        # banner
        if re.match(r"^set system login message", line) or re.match(r"^set system login banner", line):
            mgmt.banner_present = True
            return

        # auth / AAA
        if re.match(r"^set system login user", line):
            auth.local_user_accounts += 1
            return
        mt = re.search(r"minimum-length\s+(\d+)", line)
        if mt:
            auth.password_min_length = int(mt.group(1))
            return
        if re.match(r"^set system login password", line) or re.match(r"^set system login umd-local_authentication-password", line):
            return
        if re.match(r"^set system login retry-options", line):
            auth.login_retry_lockout = True
            return
        if re.match(r"^set system authentication-order", line):
            auth.aaa_enabled = True
            mt2 = re.search(r"\[([^\]]+)\]", line)
            if mt2:
                for srv in mt2.group(1).split():
                    auth.central_auth_servers.append(srv)
            return
        if re.match(r"^set system radius-server|^set system tacplus-server", line):
            auth.aaa_enabled = True
            return
        if re.match(r"^set system accounting", line):
            auth.aaa_accounting_enabled = True
            return

        # ntp
        if re.match(r"^set system ntp server", line):
            mgmt.ntp_configured = True
            mt = re.search(r"^set system ntp server\s+(\S+)", line)
            if mt:
                mgmt.ntp_servers.append(mt.group(1))
            return

        # syslog
        if re.match(r"^set system syslog host", line):
            log.remote_logging_enabled = True
            mt = re.search(r"^set system syslog host\s+(\S+)", line)
            if mt:
                log.remote_syslog_servers.append(mt.group(1))
            return
        if re.match(r"^set system syslog file", line):
            log.logging_buffered = True
            mt = re.search(r"log (info|any) (\w+-info|\w+-any)", low)
            return
        if re.match(r"^set system syslog", line):
            if re.search(r"interactive-commands|login", low):
                log.log_admin_access = True
            return

        # snmp
        if re.match(r"^set snmp community", line):
            mgmt.snmp_enabled = True
            mt = re.search(r"^set snmp community\s+(\S+)", line)
            if mt:
                mgmt.snmp_communities.append(mt.group(1))
            return
        if re.match(r"^set snmp", line):
            mgmt.snmp_enabled = True
            return

        # services hardening
        if re.match(r"^set system services netconf ssh", line):
            mgmt.ssh_enabled = True
            return
        if re.match(r"^set protocols lldp", line) or re.match(r"^set protocols ldp", line):
            mgmt.lldp_enabled = True
            return
        if re.match(r"^set protocols", line):
            return

        # crypto
        mt = re.search(r"set security ssh_host_protocol_v2", low)
        if mt:
            mgmt.ssh_version = mgmt.ssh_version or 2
            return
        if re.match(r"^set security pki", line) or re.match(r"^set security ike", line) or re.match(r"^set security ipsec", line):
            g = re.search(r"dh-group\s+(\S+)", low)
            if g:
                grp = g.group(1).replace("group", "")
                try:
                    num = int(grp)
                    crypto.ipsec_dh_group_weak = num < 14
                except ValueError:
                    crypto.ipsec_dh_group_weak = grp in ("1", "2", "5")
            return
        if re.match(r"^set security log", line):
            log.log_admin_access = log.log_admin_access or True
            return
        if re.match(r"^set security zones", line):
            self._ctx = "zones"
            return
        if self._ctx == "zones" and re.search(r"host-inbound-traffic system-services", line):
            return
        if re.match(r"^set security policies", line):
            self._ctx = "policies"
            acl.rules.append(self._policy_rule(line))
            if "log" in low or "log-session-close" in low:
                acl.acl_logging_enabled = True
            return
        if self._ctx == "policies" and re.match(r"^set security policies", line):
            return

        # interfaces / routing / misc structural
        if re.match(r"^set interfaces", line):
            return
        if re.match(r"^set routing-options|^set protocols bgp|^set policy-options", line):
            return
        if re.match(r"^set groups", line):
            return
        if re.match(r"^set vlans", line):
            return
        if re.match(r"^set access|^set accounting", line):
            return
        if re.match(r"^set chassis|^set event-options|^set syslog", line):
            return
        if re.match(r"^set", line):
            self._unparsed(m, line_no, line)
            return

    # ------------------------------------------------------------- hierarchy
    def _parse_hierarchical(self, config_text: str, device_id: str) -> SecurityBaselineModel:
        from app.core.schema import DeviceInfo

        m = SecurityBaselineModel.model_construct()
        m.device = DeviceInfo(device_id=device_id, vendor=VENDOR_JUNIPER_SRX, device_type="firewall")
        stack: list[str] = []

        for line_no, line in self.lines(config_text):
            stripped = line.strip()
            low = stripped.lower()

            if stripped == "}" or stripped.endswith("}"):
                if stack:
                    stack.pop()
                continue

            mt = re.match(r"^(\S+)\s*\{", stripped)
            if mt:
                path = " ".join(stack + [mt.group(1)])
                stack.append(mt.group(1))
                self._consume_hier(m, line_no, path, stripped, stack)
                continue

            self._consume_hier_leaf(m, line_no, " ".join(stack), stripped)

        self._finalize(m)
        return m

    def _consume_hier(self, m, line_no, path, line, stack):
        low = path.lower()
        mgmt, auth, log, crypto, acl, svc = m.management, m.auth, m.logging, m.crypto, m.acl, m.services

        mt = re.search(r"host-name\s+(\S+)", path)
        if mt and "system" in low:
            m.device.hostname = mt.group(1)
        if re.search(r"syslog host \S+", low):
            mt = re.search(r"syslog host (\S+)", low)
            if mt:
                log.remote_logging_enabled = True
                log.remote_syslog_servers.append(mt.group(1))
        if re.search(r"ntp server \S+", low):
            mt = re.search(r"ntp server (\S+)", low)
            mgmt.ntp_configured = True
            if mt:
                mgmt.ntp_servers.append(mt.group(1))

    def _consume_hier_leaf(self, m, line_no, path, line):
        low = line.lower()
        plow = path.lower()
        mgmt, auth, log, crypto, acl, svc = m.management, m.auth, m.logging, m.crypto, m.acl, m.services

        if not line or line == "}":
            return
        if re.match(r"^version", low):
            mt = re.search(r"version\s+([\d.A-Za-z-]+)", line)
            if mt:
                m.device.os_version = mt.group(1)
            return
        if re.search(r"telnet;", low) and "services" in plow:
            mgmt.telnet_enabled = True
            return
        if re.search(r"ssh {", low):
            return
        if "protocol-version v2;" in low or "protocol-version v2 " in low:
            mgmt.ssh_version = 2
            mgmt.ssh_enabled = True
            return
        if "protocol-version v1;" in low:
            mgmt.ssh_version = 1
            return
        if re.search(r"idle-timeout \d+;", low):
            mt = re.search(r"idle-timeout (\d+);", low)
            mgmt.idle_timeout_seconds = int(mt.group(1)) * 60
            mgmt.exec_timeout_configured = True
            return
        mt = re.search(r"minimum-length (\d+);", low)
        if mt and "password" in plow:
            auth.password_min_length = int(mt.group(1))
            return
        if "message " in low and "login" in plow:
            mgmt.banner_present = True
            return

    # ------------------------------------------------------------- helpers
    def _policy_rule(self, line: str) -> ACLRule:
        mt = re.search(r"match (\S+) (\S+)", line)
        return ACLRule(raw=line, action="match", logged="log" in line.lower())

    def _unparsed(self, m, line_no, line):
        m.unparsed_lines.append(RawLine(line_number=line_no, text=line, context=self._ctx))

    def _finalize(self, m: SecurityBaselineModel) -> None:
        if m.management.ntp_servers:
            m.management.ntp_configured = True
        if m.logging.remote_syslog_servers:
            m.logging.remote_logging_enabled = True
        if m.management.snmp_communities:
            m.management.snmp_enabled = True
        if m.auth.password_min_length is None:
            m.auth.password_min_length = None
