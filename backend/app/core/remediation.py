"""Remediation: rule_id -> vendor-specific fix template.

Templates come from the rule packs (remediation_template). This module adds:
  - lookup helper with override support
  - advisory safety wrapper text (the PS-required disclaimer)
"""

from __future__ import annotations

from app.core.rule_engine import Rule, load_rules

ADVISORY_NOTICE = (
    "Remediation commands are advisory. Apply in a maintenance window after "
    "review — not for unattended auto-execution."
)

_OVERRIDES: dict[str, str] = {}


def remediation_for(rule_id: str, vendor: str) -> str:
    rules = load_rules(vendor)
    for rule in rules:
        if rule.rule_id == rule_id:
            return _OVERRIDES.get(rule_id, rule.remediation)
    return _OVERRIDES.get(rule_id, "")


def remediation_with_notice(rule_id: str, vendor: str) -> dict:
    return {
        "rule_id": rule_id,
        "cli": remediation_for(rule_id, vendor),
        "notice": ADVISORY_NOTICE,
    }


def all_remediations(vendor: str) -> dict[str, str]:
    return {r.rule_id: r.remediation for r in load_rules(vendor) if r.remediation}
