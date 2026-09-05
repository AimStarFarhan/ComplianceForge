"""SONiC (config-style JSON, CONFIG_DB) parser -> SecurityBaselineModel.

SONiC stores config in JSON tables (e.g. /etc/sonic/config_db.json) or is
configured via `sudo config ...` CLI. This parser handles the JSON form and
falls back to CLI lines.
"""

from __future__ import annotations

import json
import re

from app.core.parsers.base_parser import VENDOR_SONIC, BaseParser
from app.core.schema import ACLRule, SecurityBaselineModel


class SonicParser(BaseParser):
    vendor = VENDOR_SONIC

    def parse(self, config_text: str, device_id: str) -> SecurityBaselineModel:
        stripped = config_text.lstrip()
        if stripped.startswith("{"):
            try:
                data = json.loads(config_text)
                return self._parse_json(data, device_id, config_text)
            except json.JSONDecodeError:
                pass
        return self._parse_cli(config_text, device_id)

    # ------------------------------------------------------------------ JSON
    def _parse_json(self, data: dict, device_id: str, raw: str) -> SecurityBaselineModel:
        from app.core.schema import CryptoFinding, DeviceInfo, RawLine

        m = SecurityBaselineModel.model_construct()
        m.device = DeviceInfo(device_id=device_id, vendor=VENDOR_SONIC, device_type="switch")
        mgmt, auth, log, crypto, acl, svc = m.management, m.auth, m.logging, m.crypto, m.acl, m.services

        # DEVICE_METADATA
        meta = data.get("DEVICE_METADATA", {}).get("localhost", {})
        m.device.hostname = meta.get("hostname")
        m.device.os_version = meta.get("build_version") or meta.get("version")
        m.device.model = meta.get("model") or meta.get("hwsku")
        m.device.device_type = meta.get("type", "switch")
        if meta.get("bgp_asn"):
            m.metadata["bgp_asn"] = meta.get("bgp_asn")

        # NTP
        ntp = data.get("NTP_SERVER", {})
        if ntp:
            m.management.ntp_configured = True
            m.management.ntp_servers = list(ntp.keys())

        # SYSLOG_SERVER
        syslog = data.get("SYSLOG_SERVER", {})
        if syslog:
            log.remote_logging_enabled = True
            log.remote_syslog_servers = list(syslog.keys())

        # SNMP
        snmp_comm = data.get("SNMP_COMMUNITY", {})
        if snmp_comm:
            m.management.snmp_enabled = True
            m.management.snmp_communities = list(snmp_comm.keys())

        # AAA
        aaa = data.get("AAA", {})
        if isinstance(aaa, dict):
            authn = aaa.get("authentication", {}) or {}
            for module, spec in authn.items():
                if isinstance(spec, dict):
                    default_auth = spec.get("default", "") or ""
                    if any(svc in default_auth.lower() for svc in ("tacacs", "radius", "ldap")):
                        auth.aaa_enabled = True
            acct = aaa.get("accounting", {}) or {}
            if isinstance(acct, dict) and any(
                "tacacs" in str(v).lower() or "radius" in str(v).lower()
                for v in acct.values() if isinstance(v, dict)
                for v2 in v.values()
            ):
                auth.aaa_accounting_enabled = True
            elif isinstance(acct, dict) and any(
                isinstance(v, dict) and v for v in acct.values()
            ):
                auth.aaa_accounting_enabled = True

        # tacacs TACPLUS_SERVER
        tac = data.get("TACPLUS_SERVER", {})
        if tac:
            auth.central_auth_servers.extend(list(tac.keys()))
            auth.aaa_enabled = True

        # BANNER
        if data.get("BANNER") or "MOTD" in str(data.get("BANNER", {})):
            b = data.get("BANNER", {})
            if b and any(b.values()):
                m.management.banner_present = True

        # ACL_TABLE
        acl_tables = data.get("ACL_TABLE", {})
        for name, spec in acl_tables.items():
            if isinstance(spec, dict):
                for stage in ("ingress", "egress"):
                    ports = spec.get(stage) or []
                    if isinstance(ports, list) and any(p not in ("", []) for p in ports):
                        acl.management_acl_bound = True
                # default-deny: look for ANY drop style rules in ACL_RULE
                if spec.get("type") in ("MGMT", "L3", "L2", "CUSTOM"):
                    acl.default_deny = acl.default_deny or False
        acl_rules_tbl = data.get("ACL_RULE", {})
        for rname, rspec in (acl_rules_tbl or {}).items():
            if isinstance(rspec, dict):
                action = rspec.get("PACKET_ACTION", "").upper()
                if action in ("DROP", "DENY", "FORWARD"):
                    acl.rules.append(ACLRule(raw=json.dumps({rname: rspec}), action=action.lower()))
                if action == "DROP" and rspec.get("IP_TYPE", "").upper() in ("ANY", "IP", "IPV4", "IPV4ANY"):
                    acl.default_deny = True

        # FEATURE table — hardening switches
        features = data.get("FEATURE", {})
        if features:
            def _enabled(feat: str) -> bool:
                s = features.get(feat, {})
                return (s.get("state") or "").lower() == "enabled"
            mgmt.telnet_enabled = _enabled("telnet") if "telnet" in features else None
            mgmt.http_mgmt_enabled = _enabled("http") if "http" in features else None
            mgmt.https_mgmt_enabled = _enabled("https") if "https" in features else None
            m.management.snmp_enabled = (
                _enabled("snmp") if "snmp" in features else (True if snmp_comm else None)
            )
            # TELEMETRY / telemetry#gnmi etc
            if _enabled("telemetry"):
                pass

        # TECH_SUPPORT / restapi
        restapi = data.get("RESTAPI_SERVER", {})
        if restapi and "port" in str(restapi):
            mgmt.https_mgmt_enabled = True
        rest_servers = data.get("REST_SERVERS", {})
        if rest_servers:
            mgmt.https_mgmt_enabled = True

        # SSH — sonic has SSH_SERVER / SSHD hardening tables
        ssh_tbl = data.get("SSH_SERVER") or data.get("SSHD") or {}
        if isinstance(ssh_tbl, dict) and ssh_tbl:
            mgmt.ssh_enabled = True
            params = ssh_tbl.get("default", ssh_tbl)
            if isinstance(params, dict):
                root_login = str(params.get("PermitRootLogin", "")).lower()
                if root_login in ("yes", "true"):
                    auth.default_credentials_changed = False
                elif root_login in ("no", "false"):
                    auth.default_credentials_changed = True
                pw_auth = str(params.get("PasswordAuthentication", "")).lower()
                if pw_auth in ("no", "false"):
                    auth.password_complexity_enabled = True
                try:
                    crypto.key_modulus_bits = int(params.get("keysize") or params.get("KeySize") or 0) or None
                except (TypeError, ValueError):
                    crypto.key_modulus_bits = None

        # PASSWD hardening table
        passwd = data.get("PASSWD", {})
        if isinstance(passwd, dict) and passwd:
            pol = passwd.get("POLICIES", passwd)
            if isinstance(pol, dict):
                pmin = pol.get("minlen") or pol.get("min_len") or pol.get("minlen")
                try:
                    if pmin is not None:
                        auth.password_min_length = int(pmin)
                except (TypeError, ValueError):
                    pass

        # weak crypto detection via strings
        for table_name, table in data.items():
            if isinstance(table, dict):
                for key, value in table.items():
                    blob = json.dumps(value)
                    if re.search(r"(des|rc4|md5|sha1|export|null)[- ]?cipher", blob, re.I) or re.search(r"cipher.*(des|rc4|md5)", blob, re.I):
                        crypto.weak_ciphers_present.append(CryptoFinding(cipher="weak-cipher-in-config", raw=f"{table_name}.{key}"))
                    if re.search(r"\bdes\b|\brc4\b", blob, re.I) and "password" in blob.lower():
                        pass

        # anything unknown at top level tables — list as unparsed for training loop
        KNOWN = {
            "DEVICE_METADATA", "NTP_SERVER", "SYSLOG_SERVER", "SNMP_COMMUNITY", "AAA",
            "TACPLUS_SERVER", "BANNER", "ACL_TABLE", "ACL_RULE", "FEATURE",
            "RESTAPI_SERVER", "REST_SERVERS", "SSH_SERVER", "SSHD", "PASSWD",
            "INTERFACE", "VLAN", "VLAN_MEMBER", "PORT", "PORTCHANNEL", "LOOPBACK",
            "MGMT_PORT", "MGMT_INTERFACE", "MGMT_VRF_CONFIG", "BGP_GLOBALS",
            "BGP_NEIGHBOR", "INTERFACE", "ROUTE_TABLE", "SYSLOG_SERVER",
            "STATIC_ROUTE", "NTP_SERVER", "TELEMETRY", "KV_JYP", "WARM_RESET",
            "DSCP_TO_TC_MAP", "MAP_PFC_PRIORITY_TO_QUEUE", "QUEUE", "TC_TO_PRIORITY_GROUP_MAP",
            "PFC_WD", "SCHEDULER", "BUFFER_PG", "BUFFER_PROFILE", "BUFFER_QUEUE",
            "VXLAN_TUNNEL", "VXLAN_EVPN_NVO", "VRF", "VERSIONS", "DHCP_SERVER",
            "COPP_THRESHOLD", "ACL_TABLE", "FLEX_COUNTER_TABLE", "SNMP_AGENT",
            "INTEGRATION", "SNMP_AGENT_ADDRESS", "SYSTEM_DEFAULTS", "PORT_QOS_MAP",
            "KUBE", "SECURITY_RULE", "PFC_WD", "DHCP_RELAY", "MIRROR_SESSION",
            "TABLE", "SUBNET", "VXLAN_TUNNEL_MAP", "WRED_PROFILE",
        }
        for table_name, table in data.items():
            if table_name not in KNOWN:
                for key, value in list(table.items())[:5]:
                    if isinstance(value, dict):
                        for inner in list(value.items())[:3]:
                            m.unparsed_lines.append(
                                RawLine(line_number=0, text=f"{table_name}|{key}|{inner[0]}", context=table_name)
                            )
                    else:
                        m.unparsed_lines.append(RawLine(line_number=0, text=f"{table_name}|{key}", context=table_name))

        return m

    # ------------------------------------------------------------------ CLI
    def _parse_cli(self, config_text: str, device_id: str) -> SecurityBaselineModel:
        from app.core.schema import DeviceInfo

        m = SecurityBaselineModel.model_construct()
        m.device = DeviceInfo(device_id=device_id, vendor=VENDOR_SONIC, device_type="switch")
        self._ctx = None
        for line_no, line in self.lines(config_text):
            self._consume_cli(m, line_no, line)
        return m

    def _consume_cli(self, m, line_no, line):
        low = line.lower()
        mgmt, auth, log, crypto, acl, svc = m.management, m.auth, m.logging, m.crypto, m.acl, m.services

        mt = re.match(r"^sudo config hostname\s+(\S+)", line)
        if mt:
            m.device.hostname = mt.group(1)
            return
        mt = re.search(r"SONiC\.(\S+)", line)
        if mt:
            m.device.os_version = mt.group(1)
            return
        if re.match(r"^sudo config ntp add", line):
            mgmt.ntp_configured = True
            return
        if re.match(r"^sudo config syslog add", line):
            log.remote_logging_enabled = True
            return
        if re.match(r"^sudo config snmp community", line):
            mgmt.snmp_enabled = True
            mt = re.search(r"community\s+(\S+)", line)
            if mt:
                mgmt.snmp_communities.append(mt.group(1))
            return
        if re.match(r"^sudo config banner add", line):
            mgmt.banner_present = True
            return
        if re.match(r"^sudo config tacplus add", line):
            auth.aaa_enabled = True
            return
        if re.match(r"^sudo config aaa authentication", line):
            auth.aaa_enabled = True
            return
        if re.match(r"^sudo config", line):
            self._unparsed(m, line_no, line)
            return
        if re.match(r"^(interface|show|exit|end|do )", low):
            return
        self._unparsed(m, line_no, line)

    def _unparsed(self, m, line_no, line):
        from app.core.schema import RawLine

        m.unparsed_lines.append(RawLine(line_number=line_no, text=line, context=self._ctx))
