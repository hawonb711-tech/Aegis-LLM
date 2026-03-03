"""
Policy loader and validator.
Reads policies/default.yaml (or a custom path) and exposes a typed Policy object.
Fails fast on any invalid configuration so misconfigurations are caught at startup.
"""
import re
import yaml
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, field_validator, model_validator


# ── Sub-models ───────────────────────────────────────────────────────────────

class InjectionPolicy(BaseModel):
    phrases: List[str]
    risk_per_hit: int
    base_score: int
    block_threshold: int
    semantic_enabled: bool = False
    semantic_threshold: int = 80

    @model_validator(mode="after")
    def check_threshold_positive(self) -> "InjectionPolicy":
        if self.block_threshold <= 0:
            raise ValueError("block_threshold must be > 0")
        if self.risk_per_hit < 0:
            raise ValueError("risk_per_hit must be >= 0")
        if not (0 <= self.semantic_threshold <= 100):
            raise ValueError("semantic_threshold must be in range 0-100")
        return self


class DLPPattern(BaseModel):
    name: str
    regex: str
    action: str  # "redact" | "block"
    reason_code: str

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in ("redact", "block"):
            raise ValueError(f"DLP pattern action must be 'redact' or 'block', got '{v}'")
        return v

    @field_validator("regex")
    @classmethod
    def validate_regex(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"Invalid regex '{v}': {exc}") from exc
        return v


class DLPPolicy(BaseModel):
    keywords: List[str]
    patterns: List[DLPPattern]
    keyword_action: str
    keyword_reason_code: str

    @field_validator("keyword_action")
    @classmethod
    def validate_keyword_action(cls, v: str) -> str:
        if v not in ("redact", "block"):
            raise ValueError(f"keyword_action must be 'redact' or 'block', got '{v}'")
        return v


class ToolConfig(BaseModel):
    allowed_domains: List[str]
    deny_reason_code: str


class ToolsPolicy(BaseModel):
    http_fetch: ToolConfig


class Policy(BaseModel):
    injection: InjectionPolicy
    dlp: DLPPolicy
    tools: ToolsPolicy


# ── Singleton ─────────────────────────────────────────────────────────────────

_policy: Optional[Policy] = None


def load_policy(path: Path) -> Policy:
    """Load and validate the policy YAML. Raises on any invalid configuration."""
    global _policy
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ValueError("Policy file must be a YAML mapping")
    _policy = Policy(**raw)
    return _policy


def get_policy() -> Policy:
    """Return the loaded policy singleton; raises if load_policy was never called."""
    if _policy is None:
        raise RuntimeError("Policy has not been loaded — call load_policy() first")
    return _policy


# ── Mode management ───────────────────────────────────────────────────────────
# 'strict' overrides tighten every control surface for incident response.
_STRICT_OVERRIDES: dict = {
    "injection": {"block_threshold": 30},          # 1 phrase hit → BLOCK
    "dlp":       {"keyword_action": "redact"},      # redact (not block) — service-friendly
    "tools":     {"http_fetch": {"allowed_domains": []}},  # all outbound denied
}

_active_mode: str = "default"


def get_active_mode() -> str:
    """Return the name of the currently active policy mode."""
    return _active_mode


def set_active_mode(mode: str) -> None:
    """Switch the active policy mode; raises ValueError for unknown modes."""
    global _active_mode
    if mode not in ("default", "strict"):
        raise ValueError(f"Unknown mode '{mode}'. Valid: default | strict")
    _active_mode = mode


def get_effective_policy() -> Policy:
    """
    Return the base policy with current-mode overrides applied.
    'default' → base policy unchanged (no copy).
    'strict'  → deep copy with tightened thresholds.
    """
    base = get_policy()
    if _active_mode == "default":
        return base

    p = base.model_copy(deep=True)
    ov = _STRICT_OVERRIDES

    if inj_ov := ov.get("injection"):
        if (t := inj_ov.get("block_threshold")) is not None:
            p.injection.block_threshold = t

    if dlp_ov := ov.get("dlp"):
        if (ka := dlp_ov.get("keyword_action")) is not None:
            p.dlp.keyword_action = ka

    if hf_ov := ov.get("tools", {}).get("http_fetch"):
        if "allowed_domains" in hf_ov:
            p.tools.http_fetch.allowed_domains = list(hf_ov["allowed_domains"])

    return p
