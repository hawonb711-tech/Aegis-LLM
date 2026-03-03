"""
Data Leak Prevention (DLP) Guard.

Two-pass approach:
  Pass 1 — Regex patterns (email, phone, secret tokens, …)
  Pass 2 — Plain-text keyword list (api_key, PSH_SECRET, …)

Running patterns first prevents keywords that are substrings of a token from
partially matching after the token has already been redacted by a pattern.

Decision escalation:
  ALLOW  → upgraded to REDACT when any redaction is applied
  REDACT → upgraded to BLOCK  when a pattern/keyword has action "block"
  BLOCK  is never downgraded
"""
import re
from dataclasses import dataclass, field
from typing import List

from app.policy import DLPPolicy

_REDACTED = "[REDACTED]"


@dataclass
class DLPResult:
    decision: str          # "ALLOW" | "REDACT" | "BLOCK"
    redacted_text: str
    reason_codes: List[str] = field(default_factory=list)
    redaction_count: int = 0


def _sub(text: str, pattern: str) -> tuple[str, int]:
    """Apply a regex substitution and return (new_text, match_count)."""
    new_text, count = re.subn(pattern, _REDACTED, text)
    return new_text, count


def _escalate(current: str, action: str) -> str:
    """Escalate decision based on action; never downgrade."""
    if current == "BLOCK":
        return "BLOCK"
    if action == "block":
        return "BLOCK"
    if action == "redact" and current == "ALLOW":
        return "REDACT"
    return current


def apply_dlp(text: str, policy: DLPPolicy) -> DLPResult:
    """
    Scan *text* for sensitive data and return a DLPResult with a (possibly
    redacted) copy of the text and a decision.
    """
    result_text = text
    reason_codes: List[str] = []
    total = 0
    decision = "ALLOW"

    # ── Pass 1: regex patterns ────────────────────────────────────────────
    for pat in policy.patterns:
        new_text, count = _sub(result_text, pat.regex)
        if count:
            result_text = new_text
            total += count
            if pat.reason_code not in reason_codes:
                reason_codes.append(pat.reason_code)
            decision = _escalate(decision, pat.action)

    # ── Pass 2: keyword list ──────────────────────────────────────────────
    for kw in policy.keywords:
        pattern = f"(?i){re.escape(kw)}"
        new_text, count = _sub(result_text, pattern)
        if count:
            result_text = new_text
            total += count
            if policy.keyword_reason_code not in reason_codes:
                reason_codes.append(policy.keyword_reason_code)
            decision = _escalate(decision, policy.keyword_action)

    return DLPResult(
        decision=decision,
        redacted_text=result_text,
        reason_codes=reason_codes,
        redaction_count=total,
    )
