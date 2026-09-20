"""AI classifier: unified 3-layer classification chain for unparsed config lines.

DESIGN BOUNDARY (stated deliberately):
  The classifier NEVER issues pass/fail verdicts. It only PROPOSES a security
  category for lines the deterministic parsers didn't recognize. A human must
  confirm before anything enters the cache or dataset.

Chain (first success wins, never raises):
  L1 exact cache (RuleCache.match, confidence 1.0 — BOUNDED, high-precision)
  L2 trained model (sklearn TF-IDF + LogisticRegression, fixed-size file;
     Human-verified mappings are continuously added to the learning dataset
     and used for periodic model updates/fine-tuning.)
  L3 fallback (local LM when CF_USE_LOCAL_LM=1, else cloud LLM, else
     deterministic keyword heuristic — true zero-shot only)

One classify(line) entrypoint, used by BOTH routes_training (queue/classify)
and routes_ingest (enrichment). Returns
{category, confidence, source, model_version, reason}.
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

# Local LM (LM Studio / any OpenAI-compatible server). Tried FIRST so the
# classifier works fully air-gapped; falls back to cloud/heuristic otherwise.
LOCAL_LM_URL = os.environ.get("CF_LOCAL_LM_URL", "http://localhost:1234")
LOCAL_LM_TIMEOUT = float(os.environ.get("CF_LOCAL_LM_TIMEOUT", "90"))


def _local_lm_model() -> str:
    """Which loaded model answers classification calls.

    Per-purpose routing: the classifier fires once per *pattern* and must be
    fast, so it defaults to the small model. Override with
    CF_LOCAL_LM_CLASSIFY_MODEL (exact LM Studio identifier); falls back to
    the shared CF_LOCAL_LM_MODEL for single-model setups.
    """
    return os.environ.get(
        "CF_LOCAL_LM_CLASSIFY_MODEL",
        os.environ.get("CF_LOCAL_LM_MODEL", "local-model"),
    )

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
        if os.environ.get("ANTHROPIC_API_KEY"):
            self.provider = "anthropic"
        elif os.environ.get("OPENAI_API_KEY"):
            self.provider = "openai"
        elif self.api_key:
            # explicit key, no env: guess by prefix, never mix endpoints
            self.provider = "openai" if self.api_key.startswith("sk-proj-") or (
                self.api_key.startswith("sk-") and not self.api_key.startswith("sk-ant-")
            ) else "anthropic"
        else:
            self.provider = "offline"
        self.model = os.environ.get("CF_LLM_MODEL", model)
        self.offline = self.api_key is None
        # Local LM is opt-in: heavy local models (e.g. gemma-4 reasoning) take
        # ~30-60s per classification, fine for air-gapped batch runs, too slow
        # for interactive use. Enable with CF_USE_LOCAL_LM=1.
        self.use_local_lm = os.environ.get("CF_USE_LOCAL_LM", "0") == "1"

    # ------------------------------------------------------------------ public
    def classify(self, line: str, db=None, vendor_hint: str = "any") -> dict:
        """Unified L1 -> L2 -> L3 chain. Never raises.

        L1 needs a DB session (passed by routes); without one, starts at L2.
        """
        # L1 — exact cache (bounded, high-precision only)
        if db is not None:
            try:
                from app.core.rule_cache import RuleCache as _RC

                hit = _RC(db).match(line, vendor_hint=vendor_hint)
                if hit:
                    return {
                        "category": hit["category"],
                        "confidence": 1.0,
                        "source": "cache_exact",
                        "model_version": None,
                        "reason": "Exact normalized-pattern match on a human-confirmed mapping.",
                        "match_type": hit.get("match_type"),
                        "mapping_id": hit.get("mapping_id"),
                    }
            except Exception:
                pass  # fall through to L2

        # L2 — trained model (fixed-size file, accuracy-gated, rollbackable)
        try:
            from app.core import trained_classifier as _tc

            category, confidence = _tc.predict(line)
            if confidence >= _tc.CONFIDENCE_THRESHOLD and category != "unknown":
                info = _tc.get_model_info()
                return {
                    "category": category,
                    "confidence": confidence,
                    "source": f"trained_model_v{info.get('model_version', 0)}",
                    "model_version": info.get("model_version", 0),
                    "reason": (
                        f"L2 trained model (acc {info.get('accuracy')}, "
                        f"n={info.get('n_examples')}) — still needs human confirm."
                    ),
                }
        except Exception:
            pass  # fall through to L3

        # L3 — local LM / cloud LLM / heuristic (true zero-shot only)
        return self._classify_l3(line)

    def _classify_l3(self, line: str) -> dict:
        """Previous LLM+heuristic fallback chain, now explicitly L3."""
        # 1 — local LM, only when explicitly enabled (it's slow on most hardware)
        if self.use_local_lm and httpx is not None:
            try:
                result = self._classify_local_lm(line)
                result.setdefault("model_version", None)
                return result
            except Exception:
                pass  # fall through to next layer

        # 2 — cloud LLM, dispatched by credential provenance: an Anthropic key
        # ONLY ever goes to Anthropic, an OpenAI key ONLY to OpenAI. (A prior
        # version always called the Anthropic endpoint, so OpenAI-configured
        # deployments silently fell through to heuristic.)
        if not self.offline and httpx is not None:
            try:
                if self.provider == "openai":
                    result = self._classify_openai(line)
                else:
                    result = self._classify_anthropic(line)
                result.setdefault("model_version", None)
                return result
            except Exception as exc:
                category, confidence = heuristic_classify(line)
                return {
                    "category": category,
                    "confidence": confidence,
                    "source": "heuristic_offline",
                    "model_version": None,
                    "reason": f"LLM call failed ({type(exc).__name__}); heuristic fallback used.",
                }

        # 3 — heuristic
        category, confidence = heuristic_classify(line)
        return {
            "category": category,
            "confidence": confidence,
            "source": "heuristic_offline",
            "model_version": None,
            "reason": "Offline heuristic keyword match (no LM available).",
        }

    def local_lm_available(self) -> bool:
        """True only if enabled AND the local LM server responds with a loaded model."""
        if not self.use_local_lm or httpx is None:
            return False
        try:
            with httpx.Client(timeout=3) as client:
                r = client.get(f"{LOCAL_LM_URL}/v1/models")
                return r.status_code == 200 and bool(r.json().get("data"))
        except Exception:
            return False

    def classify_batch(self, lines: list[str]) -> list[dict]:
        return [self.classify(line) for line in lines]

    # ---------------------------------------------------------------- local LM
    def _classify_local_lm(self, line: str) -> dict:
        """Few-shot classify via a local OpenAI-compatible server (LM Studio).
        Raises on any failure — caller treats that as 'fall through to next layer'."""
        prompt = (
            f"{FEWSHOT_EXAMPLES}\n\n"
            f'Classify this network device CLI line into exactly one category.\n'
            f'Line: "{line}"\n\n'
            f'Respond ONLY with JSON, no other text: '
            f'{{"category": "<category>", "confidence": <0.0-1.0>, "reason": "<short>"}}'
        )
        payload = {
            "model": _local_lm_model(),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            # reasoning models (e.g. gemma-4) spend tokens on hidden thinking
            # BEFORE the visible JSON answer — budget generously, then trim
            "max_tokens": int(os.environ.get("CF_LOCAL_LM_MAX_TOKENS", "2048")),
            "stream": False,
        }
        with httpx.Client(timeout=LOCAL_LM_TIMEOUT) as client:
            resp = client.post(f"{LOCAL_LM_URL}/v1/chat/completions", json=payload)
            resp.raise_for_status()
            data = resp.json()
        msg = (data.get("choices") or [{}])[0].get("message", {})
        # some servers put the answer in 'content', others in 'reasoning_content'
        text = msg.get("content") or msg.get("reasoning_content") or ""
        if not text:
            raise ValueError("local LM returned empty content")
        return self._parse_llm_json(text, "local_lm")

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
                "model_version": None,
                "reason": str(obj.get("reason", ""))[:200],
            }
        except (json.JSONDecodeError, ValueError, TypeError):
            category, confidence = heuristic_classify(text)
            return {
                "category": "unknown",
                "confidence": 0.3,
                "source": "heuristic_offline",
                "model_version": None,
                "reason": "LLM response unparseable; flagged for human review.",
            }


_default: AIClassifier | None = None


def get_classifier() -> AIClassifier:
    global _default
    if _default is None:
        _default = AIClassifier()
    return _default
