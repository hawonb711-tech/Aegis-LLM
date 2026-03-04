"""
Aegis simulate — offline guard-pipeline trace for a given input.

Pure functions; no network calls, no DB writes.  Any component that
would invoke an upstream LLM is intentionally omitted.

Public API
----------
  load_inputs(input_text, file_path) -> List[str]
  run_simulation(inputs, policy_path_override, verbose) -> dict
  explain(result_dict, verbose) -> str
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aegis import __version__


# ── Input loading ──────────────────────────────────────────────────────────────

def load_inputs(
    input_text: Optional[str],
    file_path: Optional[Path],
) -> List[str]:
    """
    Resolve CLI inputs to a list of user-text strings.

    Priority: ``--input`` (inline text) over ``--file`` (JSONL transcript).
    Raises ValueError if neither is provided.
    Raises FileNotFoundError if the given file does not exist.
    """
    if input_text is not None:
        return [input_text]
    if file_path is not None:
        return _load_jsonl(file_path)
    raise ValueError("At least one of --input or --file must be provided.")


def _load_jsonl(path: Path) -> List[str]:
    """
    Parse a JSONL transcript file into a list of user-text strings.

    Accepted line formats
    ---------------------
    ``{"input": "..."}``                       — inline form
    ``{"role": "user", "content": "..."}``     — chat-message form

    Non-user messages (role != "user") are silently skipped so that full
    assistant transcripts can be fed in without filtering.
    """
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    texts: List[str] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"JSONL parse error at line {lineno}: {exc}"
                ) from exc
            if not isinstance(obj, dict):
                raise ValueError(
                    f"Line {lineno}: expected a JSON object, got {type(obj).__name__}"
                )
            if "input" in obj:
                texts.append(str(obj["input"]))
            elif obj.get("role") == "user":
                if "content" not in obj:
                    raise ValueError(
                        f"Line {lineno}: user message is missing the 'content' field"
                    )
                texts.append(str(obj["content"]))
            # Non-user role entries are skipped without error.

    if not texts:
        raise ValueError(f"No user inputs found in {path}")
    return texts


# ── Policy resolution ──────────────────────────────────────────────────────────

def _resolve_policy_path(override: Optional[Path]) -> Path:
    """
    Resolve the policy path using the same priority as the runtime:
      1. CLI ``--policy`` flag
      2. ``POLICY_PATH`` environment variable
      3. Compiled default in ``app.config``
    """
    if override is not None:
        return override
    try:
        from app import config as _cfg  # deferred: honours any env changes
        return _cfg.POLICY_PATH
    except ImportError:
        return Path("policies/default.yaml")


# ── Guard pipeline ─────────────────────────────────────────────────────────────

def _run_guards(
    text: str,
    policy: Any,
    verbose: bool,
) -> Tuple[List[Dict[str, Any]], str]:
    """
    Execute the inbound guard pipeline on a single text string.

    Guard order mirrors the runtime: injection → inbound DLP.
    The LLM provider call is intentionally omitted (no network).

    Returns
    -------
    (pipeline_steps, final_decision)
    final_decision is one of: ``"allow"`` | ``"incident"`` | ``"block"``
    """
    from app.guards.injection import check_injection
    from app.guards.dlp import apply_dlp

    pipeline: List[Dict[str, Any]] = []
    _RANK: Dict[str, int] = {"allow": 0, "incident": 1, "block": 2}
    overall = "allow"

    # ── 1. Injection guard ────────────────────────────────────────────────────
    inj = check_injection(text, policy.injection)

    inj_decision = "block" if inj.decision == "BLOCK" else "pass"
    if inj_decision == "block":
        overall = "block"

    inj_step: Dict[str, Any] = {
        "guard": "injection",
        "decision": inj_decision,
        "score": inj.risk_score,
        "threshold": policy.injection.block_threshold,
        "reason": ", ".join(inj.reason_codes) if inj.reason_codes else None,
    }
    if verbose:
        inj_step["meta"] = {
            "matched_phrases": inj.matched_phrases,
            "semantic_matches": inj.semantic_matches,
            "semantic_enabled": policy.injection.semantic_enabled,
        }
    pipeline.append(inj_step)

    # ── 2. Inbound DLP guard ──────────────────────────────────────────────────
    dlp = apply_dlp(text, policy.dlp)

    if dlp.decision == "BLOCK":
        dlp_decision = "block"
        if _RANK["block"] > _RANK[overall]:
            overall = "block"
    elif dlp.decision == "REDACT":
        dlp_decision = "warn"
        if _RANK["incident"] > _RANK[overall]:
            overall = "incident"
    else:
        dlp_decision = "pass"

    dlp_step: Dict[str, Any] = {
        "guard": "dlp",
        "decision": dlp_decision,
        "score": None,
        "threshold": None,
        "reason": ", ".join(dlp.reason_codes) if dlp.reason_codes else None,
    }
    if verbose:
        dlp_step["meta"] = {
            "redaction_count": dlp.redaction_count,
        }
    pipeline.append(dlp_step)

    return pipeline, overall


# ── Simulation entry point ─────────────────────────────────────────────────────

def run_simulation(
    inputs: List[str],
    policy_path_override: Optional[Path],
    verbose: bool,
) -> Dict[str, Any]:
    """
    Run the inbound guard pipeline on every input and return a trace dict.

    The returned dict matches the JSON schema from the spec::

        {
          "version": str,
          "policy_path": str,
          "items": [
            {
              "input": str,
              "pipeline": [{"guard", "decision", "score", "threshold",
                            "reason", "meta"?}, ...],
              "final_decision": "allow" | "incident" | "block"
            }
          ],
          "exit_code": 0 | 1 | 2
        }

    Raises
    ------
    FileNotFoundError   if the policy file does not exist.
    ValueError          if the policy YAML is invalid.
    """
    from app.policy import load_policy

    policy_path = _resolve_policy_path(policy_path_override)
    policy = load_policy(policy_path)  # raises on bad policy

    items: List[Dict[str, Any]] = []
    worst_exit = 0
    _EXIT: Dict[str, int] = {"allow": 0, "incident": 1, "block": 2}

    for text in inputs:
        pipeline, final_decision = _run_guards(text, policy, verbose)
        item_exit = _EXIT.get(final_decision, 2)
        if item_exit > worst_exit:
            worst_exit = item_exit
        items.append(
            {
                "input": text,
                "pipeline": pipeline,
                "final_decision": final_decision,
            }
        )

    return {
        "version": __version__,
        "policy_path": str(policy_path),
        "items": items,
        "exit_code": worst_exit,
    }


# ── Human-readable explain ─────────────────────────────────────────────────────

_SEP = "─" * 52

_DECISION_LABEL: Dict[str, str] = {
    "pass": "PASS",
    "warn": "WARN",
    "block": "BLOCK",
}

_FINAL_LABEL: Dict[str, str] = {
    "allow": "ALLOW",
    "incident": "INCIDENT (warn)",
    "block": "BLOCK",
}


def _guard_knobs(guard_name: str, decision: str) -> List[str]:
    """Return actionable policy-knob suggestions for a guard that triggered."""
    if decision not in ("warn", "block"):
        return []
    if guard_name == "injection":
        return [
            "injection.block_threshold: raise to reduce blocking sensitivity",
            "injection.phrases: audit phrase list for false positives",
            "injection.semantic_enabled / semantic_threshold: tune or disable semantic layer",
        ]
    if guard_name == "dlp":
        return [
            "dlp.keyword_action: set to 'redact' instead of 'block'",
            "dlp.keywords: remove keywords that produce false positives",
            "dlp.patterns: review regex patterns for over-matching",
        ]
    return []


def explain(result: Dict[str, Any], verbose: bool) -> str:
    """
    Format the simulation result as a concise human-readable report.

    Parameters
    ----------
    result  : dict returned by ``run_simulation``
    verbose : include meta fields and input preview when True
    """
    lines: List[str] = []
    lines.append(_SEP)
    lines.append(f"  Aegis Simulate  v{result['version']}")
    lines.append(f"  Policy: {result['policy_path']}")
    lines.append(_SEP)

    items: List[Dict[str, Any]] = result.get("items", [])
    knobs_seen: List[str] = []

    for idx, item in enumerate(items, 1):
        final = item["final_decision"]
        label = _FINAL_LABEL.get(final, final.upper())
        lines.append(f"\nItem {idx}  [{label}]")

        if verbose:
            truncated = item["input"][:120]
            suffix = "..." if len(item["input"]) > 120 else ""
            lines.append(f"  Input: {truncated!r}{suffix}")

        for step in item["pipeline"]:
            icon = _DECISION_LABEL.get(step["decision"], step["decision"].upper())
            reason = f"  \u2014 {step['reason']}" if step.get("reason") else ""

            score_part = ""
            if step.get("score") is not None:
                if step.get("threshold") is not None:
                    score_part = (
                        f"  [score={step['score']}, threshold={step['threshold']}]"
                    )
                else:
                    score_part = f"  [score={step['score']}]"

            lines.append(f"  [{icon}] {step['guard']}{reason}{score_part}")

            if verbose and step.get("meta"):
                for k, v in step["meta"].items():
                    lines.append(f"         {k}: {v!r}")

            for knob in _guard_knobs(step["guard"], step["decision"]):
                if knob not in knobs_seen:
                    knobs_seen.append(knob)

    if knobs_seen:
        lines.append("\nSuggested policy knobs:")
        for knob in knobs_seen:
            lines.append(f"  - {knob}")

    lines.append(f"\n{_SEP}")
    lines.append(
        f"  Exit {result['exit_code']}  ({len(items)} item(s) evaluated)"
    )
    lines.append(_SEP)
    return "\n".join(lines)
