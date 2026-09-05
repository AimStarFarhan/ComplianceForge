"""Rule engine: loads YAML rule packs, evaluates checks against the
vendor-neutral SecurityBaselineModel.

Check expressions are written in a tiny restricted-Python DSL:
  - attribute access on the model (management.telnet_enabled)
  - comparisons (==, !=, <, >, <=, >=), boolean and/or/not
  - literals (numbers, strings, booleans, None)
  - `in` membership on lists
Compiled via `ast` with a whitelist — never `eval`. Rules can also declare
`check_type: length_below` for list-length checks.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

import yaml

from app.core.schema import SecurityBaselineModel

RULE_PACK_DIR = Path(__file__).parent / "rule_packs"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class CheckError(Exception):
    pass


class _SafeEval(ast.NodeVisitor):
    ALLOWED_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod)
    ALLOWED_CMPS = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn)
    ALLOWED_BOOL = (ast.And, ast.Or)

    def __init__(self, model: SecurityBaselineModel):
        self.model = model

    def read(self, path: str) -> Any:
        node: Any = self.model
        for part in path.split("."):
            if not part:
                continue
            if not part.isidentifier() and not part.isdigit():
                raise CheckError(f"illegal attribute '{part}'")
            try:
                node = node[int(part)] if part.isdigit() else getattr(node, part)
            except (AttributeError, IndexError, ValueError, TypeError):
                return None
        return node

    def visit_Expression(self, node):
        return self.visit(node.body)

    def visit_BoolOp(self, node):
        if isinstance(node.op, ast.And):
            return all(self.visit(v) for v in node.values)
        return any(self.visit(v) for v in node.values)

    def visit_UnaryOp(self, node):
        if isinstance(node.op, ast.Not):
            return not self.visit(node.operand)
        raise CheckError("unsupported unary operator")

    def visit_BinOp(self, node):
        left, right = self.visit(node.left), self.visit(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.FloorDiv):
            return left // right
        if isinstance(node.op, ast.Mod):
            return left % right
        raise CheckError("unsupported binary operator")

    def visit_Compare(self, node):
        left = self.visit(node.left)
        for op, comp in zip(node.ops, node.comparators):
            right = self.visit(comp)
            if isinstance(op, ast.Eq):
                ok = left == right
            elif isinstance(op, ast.NotEq):
                ok = left != right
            elif isinstance(op, ast.Lt):
                ok = left is not None and right is not None and left < right
            elif isinstance(op, ast.LtE):
                ok = left is not None and right is not None and left <= right
            elif isinstance(op, ast.Gt):
                ok = left is not None and right is not None and left > right
            elif isinstance(op, ast.GtE):
                ok = left is not None and right is not None and left >= right
            elif isinstance(op, ast.In):
                ok = left in (right or [])
            elif isinstance(op, ast.NotIn):
                ok = left not in (right or [])
            else:
                raise CheckError("unsupported comparison")
            if not ok:
                return False
            left = right
        return True

    def visit_Name(self, node):
        if node.id in ("None",):
            return None
        if node.id == "true":
            return True
        if node.id == "false":
            return False
        raise CheckError(f"unknown name '{node.id}'")

    def visit_Constant(self, node):
        if isinstance(node.value, (bool, int, float, str, type(None))):
            return node.value
        raise CheckError("unsupported constant")

    def visit_Tuple(self, node):
        return tuple(self.visit(e) for e in node.elts)

    def visit_List(self, node):
        return [self.visit(e) for e in node.elts]

    def visit_Attribute(self, node):
        # reconstruct dotted path
        parts: list[str] = []
        cur: ast.AST = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if not isinstance(cur, ast.Name):
            raise CheckError("unsupported attribute base")
        parts.append(cur.id)
        path = ".".join(reversed(parts))
        return self.read(path)


class Rule:
    def __init__(self, data: dict, vendor: str):
        self.rule_id: str = data["rule_id"]
        self.title: str = data.get("title", "")
        self.severity: str = data.get("severity", "medium")
        self.maps_to: str = data.get("maps_to", "")
        self.check: str = data.get("check", "true")
        self.check_type: str = data.get("check_type", "expression")  # expression | length_below
        self.remediation: str = data.get("remediation_template", "")
        self.category: str = data.get("category", "unknown")
        self.explanation_pass: str = data.get("explanation_pass", "")
        self.explanation_fail: str = data.get("explanation_fail", "")
        self.applies_to: list[str] = data.get("applies_to", [])
        self.requires: list[str] = data.get("requires", [])
        self.vendor = vendor

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "maps_to": self.maps_to,
            "check": self.check,
            "category": self.category,
            "remediation": self.remediation,
        }


def load_rules(vendor: str) -> list[Rule]:
    path = RULE_PACK_DIR / f"cis_{vendor}.yaml"
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        pack = yaml.safe_load(f) or {}
    rules = [Rule(r, vendor) for r in pack.get("rules", [])]
    for pre in pack.get("imports", []):
        rules.extend(load_rules(pre))
    return rules


def evaluate_rule(rule: Rule, model: SecurityBaselineModel) -> tuple[str, str, str]:
    """Return (status, evidence, explanation). status: pass|fail|not_applicable|error"""
    if rule.applies_to:
        dev = (model.device.device_type or "").lower()
        if dev and not any(a.lower() == dev for a in rule.applies_to):
            return "not_applicable", f"device_type={dev}", "Rule not applicable to this device class."

    if rule.check_type == "length_below":
        # check = "crypto.weak_ciphers_present < 1"
        match = re.match(r"(\S+)\s*<\s*(\d+)$", rule.check)
        if not match:
            return "error", rule.check, "Malformed length check."
        value = _SafeEval(model).read(match.group(1))
        if value is None:
            return "fail", f"{match.group(1)} is unset", rule.explanation_fail
        length = len(value) if isinstance(value, (list, tuple, str)) else int(value)
        threshold = int(match.group(2))
        ok = length < threshold
        return ("pass" if ok else "fail"), f"{match.group(1)} length={length}", (
            rule.explanation_pass if ok else rule.explanation_fail
        )

    try:
        tree = ast.parse(rule.check, mode="eval")
        result = _SafeEval(model).visit(tree)
        result = bool(result)
    except CheckError as exc:
        return "error", str(exc), "Check could not be evaluated."
    except SyntaxError as exc:
        return "error", f"syntax: {exc}", "Check could not be parsed."

    evidence = extract_evidence(rule, model)
    return ("pass" if result else "fail"), evidence, (
        rule.explanation_pass if result else rule.explanation_fail
    )


def extract_evidence(rule: Rule, model: SecurityBaselineModel) -> str:
    """Pull the top relevant config fields cited in the check for evidence."""
    fields = re.findall(r"(management|auth|logging|acl|crypto|services)\.(\w+)", rule.check)
    seen: set[str] = set()
    parts: list[str] = []
    for section, field in fields:
        key = f"{section}.{field}"
        if key in seen:
            continue
        seen.add(key)
        try:
            value = _SafeEval(model).read(key)
        except CheckError:
            continue
        if isinstance(value, list):
            value = value[:4]
            if not value:
                value = "[]"
        parts.append(f"{key}={value}")
    return "; ".join(parts) if parts else "n/a"


def run_audit(model: SecurityBaselineModel, source_overrides: dict[str, str] | None = None) -> list[dict]:
    """Full pipeline: evaluate every rule for the model's vendor.

    source_overrides: rule_id -> "ai_suggested_human_confirmed" for rules whose
    category only exists because a human confirmed an AI-suggested mapping.
    """
    rules = load_rules(model.device.vendor)
    results: list[dict] = []
    overrides = source_overrides or {}
    for rule in sorted(rules, key=lambda r: SEVERITY_ORDER.get(r.severity, 99)):
        status, evidence, explanation = evaluate_rule(rule, model)
        results.append(
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "severity": rule.severity,
                "status": status,
                "evidence": evidence,
                "maps_to": rule.maps_to,
                "explanation": explanation,
                "remediation": rule.remediation,
                "source": overrides.get(rule.rule_id, "built_in"),
                "category": rule.category,
            }
        )
    return results


def summarize(results: list[dict]) -> dict:
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    errors = sum(1 for r in results if r["status"] == "error")
    na = sum(1 for r in results if r["status"] == "not_applicable")
    scored = passed + failed
    pct = round(100 * passed / scored, 1) if scored else 100.0
    by_sev = {}
    for r in results:
        if r["status"] == "fail":
            by_sev.setdefault(r["severity"], []).append(r)
    top_critical = [
        {"rule_id": r["rule_id"], "title": r["title"]}
        for r in sorted(by_sev.get("critical", []) + by_sev.get("high", []), key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))[:3]
    ]
    return {
        "total_rules": total,
        "pass_count": passed,
        "fail_count": failed,
        "error_count": errors,
        "not_applicable_count": na,
        "compliance_pct": pct,
        "failed_by_severity": {k: len(v) for k, v in by_sev.items()},
        "top_critical_findings": top_critical,
    }
