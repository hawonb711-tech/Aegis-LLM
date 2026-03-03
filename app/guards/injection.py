"""
Prompt Injection Guard — rule-based phrase scoring + optional semantic layer.

Algorithm:
  1. Lower-case the full inbound text.
  2. Count how many injection phrases appear (overlapping hits counted once per phrase).
  3. phrase_score = base_score + (hits * risk_per_hit)
  4. If semantic_enabled:
       sem_score = cosine similarity × 100 vs policy-override intent corpus.
       risk_score = max(phrase_score, sem_score)
  5. If risk_score >= block_threshold  →  BLOCK (PI-001 and/or PI-SEM-001)
     Otherwise                         →  ALLOW
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List

from app.guards.semantic_injection import check_semantic
from app.policy import InjectionPolicy


@dataclass
class InjectionResult:
    decision: str          # "ALLOW" | "BLOCK"
    risk_score: int
    reason_codes: List[str] = field(default_factory=list)
    matched_phrases: List[str] = field(default_factory=list)
    semantic_matches: List[Dict[str, Any]] = field(default_factory=list)


def check_injection(text: str, policy: InjectionPolicy) -> InjectionResult:
    """
    Evaluate *text* against the injection policy and return a decision.

    Each policy phrase is searched (case-insensitively) in the concatenated
    message text.  Multiple occurrences of the same phrase count as one hit so
    that adversarial repetition doesn't artificially inflate the score.

    When policy.semantic_enabled is True, the phrase score is combined with a
    TF-IDF cosine similarity score against the policy-override intent corpus.
    The final risk_score is max(phrase_score, sem_score).
    """
    normalized = text.lower()
    matched: List[str] = [p for p in policy.phrases if p.lower() in normalized]
    phrase_score = policy.base_score + len(matched) * policy.risk_per_hit

    # --- optional semantic layer ---
    sem_score = 0
    sem_matches: List[Dict[str, Any]] = []
    if policy.semantic_enabled:
        sem = check_semantic(text)
        sem_score = sem.semantic_score
        sem_matches = [
            {"corpus_index": m.corpus_index, "similarity": m.similarity}
            for m in sem.top_matches
        ]

    score = max(phrase_score, sem_score) if policy.semantic_enabled else phrase_score

    if score >= policy.block_threshold:
        reason_codes: List[str] = []
        if matched:
            reason_codes.append("PI-001")
        if policy.semantic_enabled and sem_score >= policy.semantic_threshold:
            reason_codes.append("PI-SEM-001")
        if not reason_codes:
            # Score exceeded threshold but neither individual detector flagged;
            # attribute to whichever layer is active.
            reason_codes.append("PI-SEM-001" if policy.semantic_enabled else "PI-001")
        return InjectionResult(
            decision="BLOCK",
            risk_score=score,
            reason_codes=reason_codes,
            matched_phrases=matched,
            semantic_matches=sem_matches,
        )

    return InjectionResult(
        decision="ALLOW",
        risk_score=score,
        reason_codes=[],
        matched_phrases=matched,
        semantic_matches=sem_matches,
    )
