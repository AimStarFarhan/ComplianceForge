"""Multi-framework views: CIS / NIST SP 800-53 / DISA STIG / ISO 27001.

DESIGN NOTE (honest):
  Rule packs are authored once as CIS-style hardening checks (the `check`
  DSL + remediation CLI). Each rule already carries a `category` (one of the
  19 canonical SECURITY_CATEGORIES). This module is a *view layer*: it maps
  that category onto the equivalent control family in each framework so the
  same audit can be presented as CIS, NIST, STIG, or ISO evidence.

  The crosswalk is ILLUSTRATIVE, not verbatim benchmark text — same honesty
  standard as the rule packs' `maps_to` field. Adding a genuinely different
  framework profile later = new YAML pack; this selector covers the PS ask
  for "user-selected benchmarks" without duplicating 70+ rules.
"""

from __future__ import annotations

FRAMEWORKS: dict[str, dict[str, str]] = {
    "cis": {
        "label": "CIS Benchmarks",
        "short": "CIS",
        "description": "CIS-style hardening checks (native rule authoring).",
    },
    "nist": {
        "label": "NIST SP 800-53",
        "short": "NIST",
        "description": "Same checks viewed through NIST SP 800-53 rev5 control families.",
    },
    "stig": {
        "label": "DISA STIGs",
        "short": "STIG",
        "description": "Same checks viewed through DISA STIG control concepts.",
    },
    "iso": {
        "label": "ISO/IEC 27001:2022",
        "short": "ISO",
        "description": "Same checks viewed through ISO 27001 Annex A controls.",
    },
}

# category -> per-framework illustrative control reference.
# Every reference below is a *family-level* pointer, deliberately coarse:
# it answers "which control family does this hardening concept satisfy?"
CATEGORY_CROSSWALK: dict[str, dict[str, str]] = {
    "management_protocol": {
        "cis": "CIS §1 — Secure management protocols",
        "nist": "NIST CM-7 / AC-17 (least functionality, remote access)",
        "stig": "STIG NET-DM-001 (disable cleartext mgmt)",
        "iso": "ISO A.8.20 / A.8.21 (network security, mgmt segregation)",
    },
    "ssh_policy": {
        "cis": "CIS §1 — SSH hardening",
        "nist": "NIST AC-17(2) / SC-8 (remote access, transmission protection)",
        "stig": "STIG SSH hardening (protocol v2, timeout)",
        "iso": "ISO A.8.20 (secure remote administration)",
    },
    "authentication": {
        "cis": "CIS §2 — Authentication",
        "nist": "NIST IA-2 (identification & authentication)",
        "stig": "STIG authentication controls",
        "iso": "ISO A.5.17 (authentication information)",
    },
    "aaa": {
        "cis": "CIS §2 — Centralized AAA",
        "nist": "NIST AC-2 / AU-2 (account mgmt, auditing)",
        "stig": "STIG AAA / accounting requirements",
        "iso": "ISO A.5.15–A.5.18 (access control, logging)",
    },
    "password_policy": {
        "cis": "CIS §2 — Password policy",
        "nist": "NIST IA-5 (authenticator management)",
        "stig": "STIG password complexity / length",
        "iso": "ISO A.5.17 (authentication information)",
    },
    "logging": {
        "cis": "CIS §3 — Admin-access logging",
        "nist": "NIST AU-2 / AU-6 (audit events, review)",
        "stig": "STIG audit record generation",
        "iso": "ISO A.8.15 (logging)",
    },
    "syslog": {
        "cis": "CIS §3 — Remote syslog",
        "nist": "NIST AU-9 / SI-4 (audit protection, monitoring)",
        "stig": "STIG remote log forwarding",
        "iso": "ISO A.8.15 (logging) / A.8.16 (monitoring)",
    },
    "access_control": {
        "cis": "CIS §1/§4 — Management-plane ACLs",
        "nist": "NIST AC-3 / AC-4 (access enforcement, flow)",
        "stig": "STIG traffic-filter / ACL requirements",
        "iso": "ISO A.8.20–A.8.22 (network controls, filtering)",
    },
    "acl_logging": {
        "cis": "CIS §4 — ACL / deny logging",
        "nist": "NIST AU-2 / SC-7 (audit events, boundary protection)",
        "stig": "STIG deny-by-default + log",
        "iso": "ISO A.8.15 / A.8.20 (logging, network security)",
    },
    "cryptography": {
        "cis": "CIS §5 — Cryptography",
        "nist": "NIST SC-12 / SC-13 (crypto key mgmt, protection)",
        "stig": "STIG approved-algorithms only",
        "iso": "ISO A.8.24 (cryptography)",
    },
    "snmp_management": {
        "cis": "CIS §6 — SNMP hardening",
        "nist": "NIST CM-7 / IA-2 (least functionality, auth)",
        "stig": "STIG SNMPv3 / no default strings",
        "iso": "ISO A.8.20 (network device hardening)",
    },
    "ntp": {
        "cis": "CIS §8 — Time synchronization",
        "nist": "NIST AU-8 (time stamps)",
        "stig": "STIG NTP / time-source requirements",
        "iso": "ISO A.8.15 (reliable timestamps for logs)",
    },
    "service_hardening": {
        "cis": "CIS §6 — Disable unused services",
        "nist": "NIST CM-7 (least functionality)",
        "stig": "STIG unneeded-service removal",
        "iso": "ISO A.8.9 (configuration management)",
    },
    "banner": {
        "cis": "CIS §7 — Warning banner",
        "nist": "NIST AC-8 (system use notification)",
        "stig": "STIG login banner",
        "iso": "ISO A.5.10 (acceptable use / notice)",
    },
    "privilege_escalation": {
        "cis": "CIS §2 — Least privilege",
        "nist": "NIST AC-6 (least privilege)",
        "stig": "STIG privilege-separation requirements",
        "iso": "ISO A.5.18 (access rights)",
    },
    "routing_integrity": {
        "cis": "CIS concept — Routing integrity",
        "nist": "NIST SC-7 / SC-20 (boundary, secure routing)",
        "stig": "STIG routing-protocol authentication",
        "iso": "ISO A.8.20–A.8.22 (network controls)",
    },
    "interface_security": {
        "cis": "CIS concept — Interface hardening",
        "nist": "NIST CM-7 / SC-7 (least functionality, boundary)",
        "stig": "STIG interface hardening",
        "iso": "ISO A.8.20 (network security)",
    },
    "zone_policy": {
        "cis": "CIS/STIG concept — Default-deny posture",
        "nist": "NIST SC-7(5) (deny by default)",
        "stig": "STIG default-deny policy",
        "iso": "ISO A.8.22 (segregation / filtering)",
    },
    "unknown": {
        "cis": "Unclassified — pending human review",
        "nist": "Unclassified — pending human review",
        "stig": "Unclassified — pending human review",
        "iso": "Unclassified — pending human review",
    },
}

VALID_FRAMEWORKS = tuple(FRAMEWORKS.keys())


def normalize_framework(value: str | None) -> str:
    v = (value or "cis").strip().lower()
    aliases = {
        "cis": "cis",
        "cis-benchmarks": "cis",
        "nist": "nist",
        "nist-800-53": "nist",
        "sp-800-53": "nist",
        "stig": "stig",
        "disa": "stig",
        "disa-stig": "stig",
        "iso": "iso",
        "iso-27001": "iso",
        "iso27001": "iso",
    }
    return aliases.get(v, "cis")


def framework_ref(category: str, framework: str) -> str:
    fw = normalize_framework(framework)
    entry = CATEGORY_CROSSWALK.get(category or "unknown", CATEGORY_CROSSWALK["unknown"])
    return entry.get(fw, entry["cis"])


def annotate_findings(findings: list[dict], framework: str) -> list[dict]:
    """Return findings with `framework` + `framework_ref` attached (non-mutating)."""
    fw = normalize_framework(framework)
    out: list[dict] = []
    for f in findings:
        g = dict(f)
        g["framework"] = fw
        g["framework_ref"] = framework_ref(str(f.get("category", "unknown")), fw)
        out.append(g)
    return out


def framework_summary(findings: list[dict], framework: str) -> dict:
    """Per-framework compliance rollup (same pass/fail, re-labelled evidence)."""
    fw = normalize_framework(framework)
    annotated = annotate_findings(findings, fw)
    total = len(annotated)
    passed = sum(1 for f in annotated if f.get("status") == "pass")
    failed = sum(1 for f in annotated if f.get("status") == "fail")
    scored = passed + failed
    return {
        "framework": fw,
        "framework_label": FRAMEWORKS[fw]["label"],
        "total_rules": total,
        "pass_count": passed,
        "fail_count": failed,
        "compliance_pct": round(100 * passed / scored, 1) if scored else 100.0,
        "note": "Illustrative crosswalk: one CIS-style rule pack presented through "
        + FRAMEWORKS[fw]["label"]
        + " control families.",
    }
