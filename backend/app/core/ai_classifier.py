"""AI classifier: LLM few-shot classification of unparsed config lines.

DESIGN BOUNDARY (stated deliberately):
  The LLM is NEVER used for pass/fail verdicts. It only PROPOSES a security
  category for lines the deterministic parsers didn't recognize. A human must
  confirm before anything enters the rule cache.

Offline safety: if no API key is configured, a deterministic heuristic
classifier proposes categories instead, so the demo works without network.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

from app.core.schema import SECURITY_CATEGORIES

try:
    import httpx
except ImportError:  # httpx is optional at import time; routes may also use it
    httpx = None

DEFAULT_MODEL = "claude-3-5-haiku-latest"

FEWSHOT_EXAMPLES = """\
Examples of CLI line -> security category pairs:
- "ip telnet server" -> management_protocol
- "no ip telnet server" -> management_protocol
- "ssh version 2" -> ssh_policy
- "ip ssh time-out 60" -> ssh_policy
- "set system services ssh root-login deny" -> ssh_policy
- "username admin privilege 15 secret 5 $1$mERr" -> authentication
- "aaa authentication login default group tacacs+ local" -> aaa
- "security passwords min-length 12" -> password_policy
- "logging host 192.168.1.50" -> syslog
- "logging trap informational" -> syslog
- "set system syslog host 10.0.0.9 any info" -> syslog
- "access-list 110 deny ip any any log" -> acl_logging
- "ip access-group 110 in" -> access_control
- "crypto isakmp policy 10 encryption aes 256" -> cryptography
- "ip ssh dh min size 2048" -> cryptography
- "snmp-server community S3cr3tStr1ng RO" -> snmp_management
- "set snmp community public" -> snmp_management
- "ntp server 10.10.1.1 prefer" -> ntp
- "no cdp run" -> service_hardening
- "banner motd ^C authorized access only ^C" -> banner
- "sudo config feature telnet disable" -> service_hardening
- "set security policies from-zone untrust to-zone trust default-policy deny-all" -> zone_policy

Categories: management_protocol, ssh_policy, authentication, aaa, password_policy,
logging, syslog, access_control, acl_logging, cryptography, snmp_management,
ntp, service_hardening, banner, privilege_escalation, routing_integrity,
interface_security, zone_policy, unknown"""


HEURISTIC_RULES: list[tuple[str, str]] = [
    (r"telnet|web-management http|ip http server|http server", "management_protocol"),
    (r"ssh|sshd", "ssh_policy"),
    (r"tacacs|radius|aaa |authentication-order|accounting", "aaa"),
    (r"password|min-length|minimum-length|secret|passwd", "password_policy"),
    (r"snmp|community", "snmp_management"),
    (r"ntp ", "ntp"),
    (r"banner|motd", "banner"),
    (r"crypt|cipher|dh-group|isakmp|encryption|modulus|hash", "cryptography"),
    (r"access-list|access-group|access-class|policy|acl|firewall filter", "access_control"),
    (r"syslog|logging|log host", "syslog"),
    (r"cdp|lldp|finger|bootp|pad|small-server|feature .* (enable|disable)", "service_hardening"),
    (r"login|lockout|block-for|retry", "authentication"),
    (r"privilege|role|class ", "privilege_escalation"),
    (r"ospf|bgp|route-map|routing", "routing_integrity"),
    (r"interface|port |eth", "interface_security"),
    (r"zone", "zone_policy"),
]


def heuristic_classify(line: str) -> tuple[str, float]:
    low = line.lower()
    for pattern, category in HEURISTIC_RULES:
        if re.search(pattern, low):
            return category, 0.55
    return "unknown", 0.2


class AIClassifier:
    """LLM few-shot classifier with deterministic offline fallback."""

    def __init__(self, api_key: Optional[str] = None, model: str = DEFAULT_MODEL):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")
        self.provider = "anthropic" if (os.environ.get("ANTHROPIC_API_KEY")) else ("openai" if os.environ.get("OPENAI_API_KEY") else ("anthropic" if self.api_key else "offline"))
        self.model = os.environ.get("CF_LLM_MODEL", model)
        self.offline = self.api_key is None

    # ------------------------------------------------------------------ public
    def classify(self, line: str) -> dict:
        """Return {category, confidence, source, reason}."""
        if self.offline or httpx is None:
            category, confidence = heuristic_classify(line)
            return {
                "category": category,
                "confidence": confidence,
                "source": "heuristic_offline",
                "reason": "Offline heuristic keyword match (no API key configured).",
            }
        try:
            return self._classify_anthropic(line)
        except Exception as exc:  # network/HTTP/quota — degrade gracefully
            category, confidence = heuristic_classify(line)
            return {
                "category": category,
                "confidence": confidence,
                "source": "heuristic_offline",
                "reason": f"LLM call failed ({type(exc).__name__}); heuristic fallback used.",
            }

    def classify_batch(self, lines: list[str]) -> list[dict]:
        return [self.classify(line) for line in lines]

    # ---------------------------------------------------------------- anthropic
    def _classify_anthropic(self, line: str) -> dict:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        prompt = (
            f"{FEWSHOT_EXAMPLES}\n\n"
            f'Classify this network device CLI line into exactly one category.\n'
            f'Line: "{line}"\n\n'
            f'Respond ONLY with JSON: {{"category": "<category>", "confidence": <0.0-1.0>, "reason": "<short>"}}'
        )
        payload = {
            "model": self.model,
            "max_tokens": 200,
            "messages": [{"role": "user", "content": prompt}],
        }
        with httpx.Client(timeout=15) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
        text = "".join(block.get("text", "") for block in data.get("content", []))
        return self._parse_llm_json(text, "claude")

    # ------------------------------------------------------------------- openai
    def _classify_openai(self, line: str) -> dict:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "content-type": "application/json"}
        payload = {
            "model": os.environ.get("CF_LLM_MODEL", "gpt-4o-mini"),
            "messages": [
                {"role": "system", "content": FEWSHOT_EXAMPLES},
                {"role": "user", "content": f'Classify this CLI line. Respond ONLY with JSON {{"category","confidence","reason"}}.\nLine: "{line}"'},
            ],
            "temperature": 0.1,
        }
        with httpx.Client(timeout=15) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            text = resp.json()["choices"][0]["message"]["content"]
        return self._parse_llm_json(text, "gpt")

    # ------------------------------------------------------------------ parsing
    @staticmethod
    def _parse_llm_json(text: str, engine: str) -> dict:
        try:
            m = re.search(r"\{.*\}", text, re.DOTALL)
            obj = json.loads(m.group(0) if m else text)
            category = str(obj.get("category", "unknown")).strip()
            if category not in SECURITY_CATEGORIES:
                category = "unknown"
            confidence = float(obj.get("confidence", 0.5))
            return {
                "category": category,
                "confidence": min(max(confidence, 0.0), 1.0),
                "source": f"llm_{engine}",
                "reason": str(obj.get("reason", ""))[:200],
            }
        except (json.JSONDecodeError, ValueError, TypeError):
            category, confidence = heuristic_classify(text)
            return {
                "category": "unknown",
                "confidence": 0.3,
                "source": "heuristic_offline",
                "reason": "LLM response unparseable; flagged for human review.",
            }


_default: AIClassifier | None = None


def get_classifier() -> AIClassifier:
    global _default
    if _default is None:
        _default = AIClassifier()
    return _default
