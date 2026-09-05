"""
ComplianceForge Security Baseline Model.

Every vendor parser normalizes raw CLI config into this single vendor-neutral
shape. The rule engine ONLY ever reads this shape, never raw vendor syntax.

`unparsed_lines` is the escape hatch that feeds the human-in-the-loop
Training Loop: anything a parser cannot confidently map into a concept
bucket lands there with its raw text and source line number.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ACLRule(BaseModel):
    """Vendor-neutral ACL entry (idiosyncratic details dropped by design)."""

    raw: str = Field(description="Original CLI line")
    action: Optional[str] = Field(default=None, description="permit | deny | reject | ...")
    protocol: Optional[str] = Field(default=None)
    source: Optional[str] = Field(default=None)
    destination: Optional[str] = Field(default=None)
    service: Optional[str] = Field(default=None, description="port/service if stated")
    logged: bool = Field(default=False, description="explicit log/log-set keyword on the rule")


class RawLine(BaseModel):
    """A line the parser could not map — candidate for the Training Loop."""

    line_number: int
    text: str
    context: Optional[str] = Field(default=None, description="enclosing section/interface, if known")
    suggested_category: Optional[str] = Field(default=None, description="AI proposal, unconfirmed until human confirms")
    suggested_confidence: Optional[float] = Field(default=None)
    category: Optional[str] = Field(default=None, description="confirmed category (from cache or human)")


class CryptoFinding(BaseModel):
    cipher: str
    raw: str


class ManagementModel(BaseModel):
    ssh_enabled: Optional[bool] = None
    ssh_version: Optional[int] = None
    telnet_enabled: Optional[bool] = None
    http_mgmt_enabled: Optional[bool] = None
    https_mgmt_enabled: Optional[bool] = None
    idle_timeout_seconds: Optional[int] = None
    exec_timeout_configured: Optional[bool] = None
    console_line_protection: Optional[bool] = None
    banner_present: Optional[bool] = None
    ntp_configured: Optional[bool] = None
    ntp_servers: list[str] = Field(default_factory=list)
    snmp_enabled: Optional[bool] = None
    snmp_communities: list[str] = Field(default_factory=list)
    cdp_enabled: Optional[bool] = None
    lldp_enabled: Optional[bool] = None
    auxiliary_ports_disabled: Optional[bool] = None
    source_interface_pinned: Optional[bool] = None


class AuthModel(BaseModel):
    password_min_length: Optional[int] = None
    password_complexity_enabled: Optional[bool] = None
    password_encryption_enabled: Optional[bool] = None
    aaa_enabled: Optional[bool] = None
    aaa_accounting_enabled: Optional[bool] = None
    default_credentials_changed: Optional[bool] = None
    local_user_accounts: int = Field(default=0)
    authentication_fallback_local: Optional[bool] = None
    central_auth_servers: list[str] = Field(default_factory=list)
    service_password_recovery_disabled: Optional[bool] = None
    privilege_level_15_empty: Optional[bool] = None
    login_retry_lockout: Optional[bool] = None


class LoggingModel(BaseModel):
    remote_logging_enabled: Optional[bool] = None
    remote_syslog_servers: list[str] = Field(default_factory=list)
    log_admin_access: Optional[bool] = None
    logging_level_informational: Optional[bool] = None
    logging_buffered: Optional[bool] = None
    logging_timestamps: Optional[bool] = None
    logging_severity_threshold: Optional[str] = None


class CryptoModel(BaseModel):
    weak_ciphers_present: list[CryptoFinding] = Field(default_factory=list)
    weak_hash_algorithms: list[str] = Field(default_factory=list)
    key_size_bits: Optional[int] = None
    key_modulus_bits: Optional[int] = None
    ssh_algorithm_bound: Optional[bool] = None
    ipsec_dh_group_weak: Optional[bool] = None
    tls_version_min: Optional[str] = None
    password_hashes_plaintext: list[str] = Field(default_factory=list)


class ACLModel(BaseModel):
    rules: list[ACLRule] = Field(default_factory=list)
    default_deny: Optional[bool] = None
    management_acl_bound: Optional[bool] = None
    acl_logging_enabled: Optional[bool] = None


class ServicesModel(BaseModel):
    unused_services: list[str] = Field(default_factory=list, description="small/udp/tcp services seen enabled")
    bootp_enabled: Optional[bool] = None
    dhcp_server_enabled: Optional[bool] = None
    pad_enabled: Optional[bool] = None
    web_cache_enabled: Optional[bool] = None
    finger_enabled: Optional[bool] = None
    vty_acl_bound: Optional[bool] = None


class DeviceInfo(BaseModel):
    device_id: str
    vendor: str
    hostname: Optional[str] = None
    os_version: Optional[str] = None
    model: Optional[str] = None
    device_type: Optional[str] = None
    serial: Optional[str] = None
    raw_config: str = Field(default="", exclude=True, description="original CLI text, kept for re-audit, excluded from JSON")


class SecurityBaselineModel(BaseModel):
    """The one shape every parser emits and the rule engine consumes."""

    device: DeviceInfo
    management: ManagementModel = Field(default_factory=ManagementModel)
    auth: AuthModel = Field(default_factory=AuthModel)
    logging: LoggingModel = Field(default_factory=LoggingModel)
    acl: ACLModel = Field(default_factory=ACLModel)
    crypto: CryptoModel = Field(default_factory=CryptoModel)
    services: ServicesModel = Field(default_factory=ServicesModel)
    unparsed_lines: list[RawLine] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict, description="vendor-specific extras for transparency, not rule-evaluated")


# Canonical category taxonomy shared by parsers, AI classifier, and rule cache.
SECURITY_CATEGORIES: list[str] = [
    "management_protocol",
    "ssh_policy",
    "authentication",
    "aaa",
    "password_policy",
    "logging",
    "syslog",
    "access_control",
    "acl_logging",
    "cryptography",
    "snmp_management",
    "ntp",
    "service_hardening",
    "banner",
    "privilege_escalation",
    "routing_integrity",
    "interface_security",
    "zone_policy",
    "unknown",
]
