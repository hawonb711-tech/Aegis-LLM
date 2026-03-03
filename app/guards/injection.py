"""
Prompt Injection Guard — rule-based, no ML required.

Algorithm:
  1. Lower-case the full inbound text.
  2. Count how many injection phrases appear (overlapping hits counted once per phrase).
  3. risk_score = base_score + (hits * risk_per_hit)
  4. If risk_score >= block_threshold  →  BLOCK with reason code PI-001
     Otherwise                         →  ALLOW
"""
from dataclasses import dataclass, field
from typing import List

from app.policy import InjectionPolicy


@dataclass
class InjectionResult:
    decision: str          # "ALLOW" | "BLOCK"
    risk_score: int
    reason_codes: List[str] = field(default_factory=list)
    matched_phrases: List[str] = field(default_factory=list)


def check_injection(text: str, policy: InjectionPolicy) -> InjectionResult:
    """
    Evaluate *text* against the injection policy and return a decision.

    Each policy phrase is searched (case-insensitively) in the concatenated
    message text.  Multiple occurrences of the same phrase count as one hit so
    that adversarial repetition doesn't artificially inflate the score.
    """
    normalized = text.lower()
    matched: List[str] = []

    for phrase in policy.phrases:
        if phrase.lower() in normalized:
            matched.append(phrase)

    score = policy.base_score + len(matched) * policy.risk_per_hit

    if score >= policy.block_threshold:
        return InjectionResult(
            decision="BLOCK",
            risk_score=score,
            reason_codes=["PI-001"],
            matched_phrases=matched,
        )

    return InjectionResult(
        decision="ALLOW",
        risk_score=score,
        reason_codes=[],
        matched_phrases=matched,
    )
