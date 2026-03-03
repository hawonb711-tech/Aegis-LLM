"""
Unit tests for policy loading and validation.

Tests confirm that valid YAML loads correctly and that invalid configs fail fast.
"""
import tempfile
from pathlib import Path

import pytest
import yaml

from app.policy import load_policy, Policy


# ── Test data ─────────────────────────────────────────────────────────────────

VALID = {
    "injection": {
        "phrases": ["ignore previous instructions", "jailbreak"],
        "risk_per_hit": 30,
        "base_score": 0,
        "block_threshold": 60,
    },
    "dlp": {
        "keywords": ["PSH_SECRET", "api_key"],
        "patterns": [
            {
                "name": "email",
                "regex": r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
                "action": "redact",
                "reason_code": "DLP-001",
            }
        ],
        "keyword_action": "redact",
        "keyword_reason_code": "DLP-001",
    },
    "tools": {
        "http_fetch": {
            "allowed_domains": ["api.example.com", "httpbin.org"],
            "deny_reason_code": "TOOL-001",
        }
    },
}


def _write(data: dict) -> Path:
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    yaml.dump(data, tmp)
    tmp.close()
    return Path(tmp.name)


# ── Valid policy ──────────────────────────────────────────────────────────────

class TestValidPolicy:
    def test_returns_policy_instance(self):
        policy = load_policy(_write(VALID))
        assert isinstance(policy, Policy)

    def test_injection_fields(self):
        policy = load_policy(_write(VALID))
        assert policy.injection.block_threshold == 60
        assert policy.injection.risk_per_hit == 30
        assert "jailbreak" in policy.injection.phrases

    def test_dlp_keywords(self):
        policy = load_policy(_write(VALID))
        assert "PSH_SECRET" in policy.dlp.keywords
        assert policy.dlp.keyword_action == "redact"

    def test_dlp_patterns_loaded(self):
        policy = load_policy(_write(VALID))
        assert len(policy.dlp.patterns) == 1
        assert policy.dlp.patterns[0].name == "email"
        assert policy.dlp.patterns[0].reason_code == "DLP-001"

    def test_tools_allowed_domains(self):
        policy = load_policy(_write(VALID))
        assert "api.example.com" in policy.tools.http_fetch.allowed_domains
        assert "httpbin.org" in policy.tools.http_fetch.allowed_domains

    def test_tools_deny_reason_code(self):
        policy = load_policy(_write(VALID))
        assert policy.tools.http_fetch.deny_reason_code == "TOOL-001"

    def test_multiple_patterns(self):
        data = dict(VALID)
        data["dlp"] = dict(VALID["dlp"])
        data["dlp"]["patterns"] = [
            {
                "name": "email",
                "regex": r'\S+@\S+',
                "action": "redact",
                "reason_code": "DLP-001",
            },
            {
                "name": "phone",
                "regex": r'\d{3}-\d{4}',
                "action": "redact",
                "reason_code": "DLP-001",
            },
        ]
        policy = load_policy(_write(data))
        assert len(policy.dlp.patterns) == 2


# ── Invalid policy — fail fast ────────────────────────────────────────────────

class TestInvalidPolicy:
    def test_missing_top_level_key_raises(self):
        bad = {"injection": VALID["injection"], "dlp": VALID["dlp"]}  # missing tools
        with pytest.raises(Exception):
            load_policy(_write(bad))

    def test_invalid_dlp_action_raises(self):
        data = {**VALID}
        data["dlp"] = {
            **VALID["dlp"],
            "patterns": [
                {
                    "name": "bad",
                    "regex": r"\d+",
                    "action": "explode",  # invalid
                    "reason_code": "DLP-001",
                }
            ],
        }
        with pytest.raises(Exception):
            load_policy(_write(data))

    def test_invalid_keyword_action_raises(self):
        data = {**VALID}
        data["dlp"] = {**VALID["dlp"], "keyword_action": "vanish"}  # invalid
        with pytest.raises(Exception):
            load_policy(_write(data))

    def test_invalid_regex_raises(self):
        data = {**VALID}
        data["dlp"] = {
            **VALID["dlp"],
            "patterns": [
                {
                    "name": "broken",
                    "regex": r"[invalid(regex",  # malformed
                    "action": "redact",
                    "reason_code": "DLP-001",
                }
            ],
        }
        with pytest.raises(Exception):
            load_policy(_write(data))

    def test_zero_block_threshold_raises(self):
        data = {**VALID}
        data["injection"] = {**VALID["injection"], "block_threshold": 0}
        with pytest.raises(Exception):
            load_policy(_write(data))

    def test_negative_risk_per_hit_raises(self):
        data = {**VALID}
        data["injection"] = {**VALID["injection"], "risk_per_hit": -5}
        with pytest.raises(Exception):
            load_policy(_write(data))

    def test_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_policy(Path("/nonexistent/path/policy.yaml"))

    def test_empty_yaml_raises(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        )
        tmp.write("")
        tmp.close()
        with pytest.raises(Exception):
            load_policy(Path(tmp.name))
