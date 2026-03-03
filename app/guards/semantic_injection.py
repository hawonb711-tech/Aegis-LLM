"""
Semantic prompt-injection detector — pure Python, no ML dependencies.

Algorithm
---------
1. Tokenise input and each corpus document (lower-case, strip punctuation,
   remove stop words).
2. Build a TF-IDF vector for each corpus document and normalise to unit length.
3. At query time, compute the TF-IDF unit vector for the input and take the
   dot product against every corpus vector (cosine similarity).
4. Return max(similarities) × 100, rounded to the nearest integer (0–100).

The corpus items are **abstract descriptions of policy-override intent**, not
exploit strings. They are safe to ship in plaintext and cannot be
reverse-engineered into working injection payloads.
"""

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# ── Stop words ────────────────────────────────────────────────────────────────
# High-frequency function words removed before TF-IDF to avoid false positives
# from common words like "the" or "and" appearing in corpus items.
_STOPWORDS: frozenset = frozenset({
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "as", "is", "was", "are", "were", "be",
    "been", "being", "have", "has", "had", "do", "does", "did", "will",
    "would", "could", "should", "may", "might", "shall", "can", "not",
    "no", "nor", "so", "yet", "both", "either", "neither", "each", "few",
    "more", "most", "other", "some", "such", "that", "this", "these",
    "those", "it", "its", "they", "them", "their", "there", "what",
    "which", "who", "when", "where", "why", "how", "all", "any", "if",
    "into", "through", "during", "before", "after", "above", "below",
    "up", "down", "out", "off", "over", "under", "again", "then", "than",
    "too", "very", "just", "now", "only", "also", "he", "she", "we",
    "i", "you", "your", "my", "his", "her", "our",
})

# ── Corpus ─────────────────────────────────────────────────────────────────────
# 15 abstract, non-exploitative descriptions of policy-override intent.
# Each item describes a *category* of adversarial intent, not a prompt string.
_CORPUS: List[str] = [
    "instruct system ignore safety guidelines policies",
    "override model operating instructions constraints",
    "replace existing system directives new unauthorized commands",
    "bypass content filtering restriction mechanisms",
    "assume alternative persona disregards original rules",
    "reveal internal configuration settings hidden instructions",
    "disregard established restrictions behave differently",
    "impersonate different system without standard safeguards",
    "escape defined role adopt unrestricted behavior",
    "manipulate underlying prompt change model goals",
    "extract sensitive system information confidential data",
    "circumvent standard operating procedures system",
    "act against intended purpose following embedded commands",
    "suppress warnings execute unauthorized instructions silently",
    "transfer control external directives override safety measures",
]


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class TopMatch:
    corpus_index: int   # 0-based index into _CORPUS
    similarity: float   # cosine similarity, 0.0–1.0


@dataclass
class SemanticResult:
    semantic_score: int                        # 0–100
    top_matches: List[TopMatch] = field(default_factory=list)


# ── TF-IDF engine ──────────────────────────────────────────────────────────────

class _TFIDFCorpus:
    """Immutable TF-IDF index built over a fixed list of documents."""

    def __init__(self, documents: List[str]) -> None:
        self._n = len(documents)
        self._tokenized: List[List[str]] = [self._tokenize(d) for d in documents]
        self._idf: Dict[str, float] = self._build_idf()
        self._unit_vecs: List[Dict[str, float]] = [
            self._to_unit_vec(tokens) for tokens in self._tokenized
        ]

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        tokens = re.findall(r"[a-z]+", text.lower())
        return [t for t in tokens if t not in _STOPWORDS]

    def _build_idf(self) -> Dict[str, float]:
        """Smooth IDF = log((1 + N) / (1 + df)) + 1  (sklearn-compatible)."""
        df: Dict[str, int] = {}
        for tokens in self._tokenized:
            for term in set(tokens):
                df[term] = df.get(term, 0) + 1
        return {
            term: math.log((1 + self._n) / (1 + count)) + 1
            for term, count in df.items()
        }

    def _tf_idf_vec(self, tokens: List[str]) -> Dict[str, float]:
        """Raw TF × IDF; terms absent from corpus vocabulary contribute 0."""
        tf: Dict[str, int] = {}
        for t in tokens:
            tf[t] = tf.get(t, 0) + 1
        return {
            term: count * self._idf.get(term, 0.0)
            for term, count in tf.items()
            if self._idf.get(term, 0.0) > 0.0
        }

    @staticmethod
    def _magnitude(vec: Dict[str, float]) -> float:
        return math.sqrt(sum(v * v for v in vec.values())) or 1.0

    def _to_unit_vec(self, tokens: List[str]) -> Dict[str, float]:
        vec = self._tf_idf_vec(tokens)
        mag = self._magnitude(vec)
        return {term: val / mag for term, val in vec.items()}

    def query(self, text: str, top_k: int = 3) -> SemanticResult:
        tokens = self._tokenize(text)
        if not tokens:
            return SemanticResult(semantic_score=0)

        q_unit = self._to_unit_vec(tokens)
        if not q_unit:
            return SemanticResult(semantic_score=0)

        sims: List[Tuple[int, float]] = [
            (i, sum(q_unit.get(t, 0.0) * v for t, v in corpus_unit.items()))
            for i, corpus_unit in enumerate(self._unit_vecs)
        ]
        sims.sort(key=lambda x: x[1], reverse=True)

        best = sims[0][1] if sims else 0.0
        score = min(100, int(round(best * 100)))
        top = [
            TopMatch(corpus_index=idx, similarity=round(sim, 4))
            for idx, sim in sims[:top_k]
        ]
        return SemanticResult(semantic_score=score, top_matches=top)


# ── Module-level singleton ─────────────────────────────────────────────────────
# Built once at import time; the corpus is static so this is safe and fast.
_INDEX: _TFIDFCorpus = _TFIDFCorpus(_CORPUS)


def check_semantic(text: str) -> SemanticResult:
    """
    Compute TF-IDF cosine similarity between *text* and the policy-override
    intent corpus.

    Returns a SemanticResult:
      - semantic_score: integer 0–100 (100 = identical vocabulary/distribution)
      - top_matches: up to 3 closest corpus items by cosine similarity
    """
    return _INDEX.query(text)
