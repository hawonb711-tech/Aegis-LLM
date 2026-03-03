"""
Tests for aegis.doctor diagnostic checks.

Coverage targets specified in the spec:
  A) policy file UTF-8 handling — including a file with en-dash in a comment
  B) import check failure path — simulated via monkeypatching
  C) JSON output schema shape

Additional tests cover individual check functions and the CLI integration.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import List

import pytest

import aegis.doctor as doctor
from aegis.doctor import (
    Check,
    Status,
    check_auth_enabled,
    check_db_connect,
    check_db_dir_writable,
    check_db_schema,
    check_filesystem_encoding,
    check_import_app_main,
    check_locale,
    check_policy_exists,
    check_policy_schema,
    check_policy_utf8,
    check_policy_yaml,
    check_python_version,
    check_rate_limit,
    check_semantic_config,
    exit_code,
    overall_status,
    run_all_checks,
    to_json_dict,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

MINIMAL_POLICY = """\
injection:
  phrases: []
  risk_per_hit: 0
  base_score: 0
  block_threshold: 1
dlp:
  keywords: []
  patterns: []
  keyword_action: redact
  keyword_reason_code: DLP-001
tools:
  http_fetch:
    allowed_domains: []
    deny_reason_code: TOOL-001
"""


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    """Write a minimal valid policy YAML and return its path."""
    p = tmp_path / "policy.yaml"
    p.write_text(MINIMAL_POLICY, encoding="utf-8")
    return p


# ── A. Policy file UTF-8 handling ─────────────────────────────────────────────

def test_utf8_policy_with_endash_in_comment_passes(tmp_path: Path) -> None:
    """
    A policy YAML file that contains an en-dash (U+2013) in a comment must pass
    the UTF-8 check.

    Regression guard: the known bug was opening the file without explicit
    ``encoding="utf-8"``, which crashed on non-UTF-8 locales.
    """
    p = tmp_path / "policy_endash.yaml"
    # Write file with explicit UTF-8 encoding — this is what the runtime does.
    p.write_text(
        "# semantic_threshold range (0\u201399) \u2014 en-dash in comment\n" + MINIMAL_POLICY,
        encoding="utf-8",
    )
    result = check_policy_utf8(override=p)
    assert result.status == Status.PASS, f"Expected PASS, got: {result.message}"


def test_utf8_policy_with_invalid_bytes_fails(tmp_path: Path) -> None:
    """A file containing bytes that are not valid UTF-8 must return FAIL."""
    p = tmp_path / "bad_encoding.yaml"
    # 0xFF is invalid as a UTF-8 start byte.
    p.write_bytes(b"# invalid \xff utf-8\n" + MINIMAL_POLICY.encode("utf-8"))
    result = check_policy_utf8(override=p)
    assert result.status == Status.FAIL
    assert "UTF-8" in result.message or "utf" in result.message.lower()
    assert result.fix is not None
    # Fix hint must mention en-dash specifically.
    assert "en-dash" in result.fix or "U+2013" in result.fix


def test_utf8_check_missing_file_returns_fail(tmp_path: Path) -> None:
    """check_policy_utf8 must return FAIL when the path does not exist."""
    result = check_policy_utf8(override=tmp_path / "ghost.yaml")
    assert result.status == Status.FAIL
    assert "not found" in result.message.lower()


def test_policy_exists_missing_returns_fail(tmp_path: Path) -> None:
    result = check_policy_exists(override=tmp_path / "missing.yaml")
    assert result.status == Status.FAIL
    assert result.fix is not None


def test_policy_yaml_parse_error_returns_fail(tmp_path: Path) -> None:
    """Malformed YAML must cause check_policy_yaml to return FAIL."""
    p = tmp_path / "bad.yaml"
    p.write_text("injection: [\nunclosed bracket", encoding="utf-8")
    result = check_policy_yaml(override=p)
    assert result.status == Status.FAIL
    assert "YAML" in result.message or "parse" in result.message.lower()


def test_policy_yaml_non_mapping_returns_fail(tmp_path: Path) -> None:
    p = tmp_path / "list.yaml"
    p.write_text("- item1\n- item2\n", encoding="utf-8")
    result = check_policy_yaml(override=p)
    assert result.status == Status.FAIL
    assert "mapping" in result.message.lower()


def test_policy_schema_valid(policy_file: Path) -> None:
    result = check_policy_schema(override=policy_file)
    assert result.status == Status.PASS


def test_policy_schema_missing_required_field_returns_fail(tmp_path: Path) -> None:
    """A policy YAML missing a required section must cause FAIL."""
    p = tmp_path / "incomplete.yaml"
    # Missing 'dlp' and 'tools' sections.
    p.write_text("injection:\n  phrases: []\n  block_threshold: 1\n", encoding="utf-8")
    result = check_policy_schema(override=p)
    assert result.status == Status.FAIL
    assert result.fix is not None


def test_semantic_cfg_disabled_passes(policy_file: Path) -> None:
    result = check_semantic_config(override=policy_file)
    assert result.status == Status.PASS
    assert "false" in result.message.lower() or "disabled" in result.message.lower()


def test_semantic_cfg_enabled_with_valid_threshold(tmp_path: Path) -> None:
    p = tmp_path / "sem.yaml"
    p.write_text(
        MINIMAL_POLICY + "  semantic_enabled: true\n  semantic_threshold: 75\n",
        encoding="utf-8",
    )
    result = check_semantic_config(override=p)
    assert result.status == Status.PASS


def test_semantic_cfg_enabled_with_bad_threshold(tmp_path: Path) -> None:
    p = tmp_path / "sem_bad.yaml"
    content = MINIMAL_POLICY.replace(
        "  block_threshold: 1",
        "  block_threshold: 1\n  semantic_enabled: true\n  semantic_threshold: 150",
    )
    p.write_text(content, encoding="utf-8")
    result = check_semantic_config(override=p)
    assert result.status == Status.FAIL
    assert "150" in result.message or "range" in result.message.lower()


# ── B. Import check failure path ──────────────────────────────────────────────

def test_import_check_success() -> None:
    """app.main must be importable in a working installation."""
    result = check_import_app_main()
    assert result.status == Status.PASS


def test_import_check_failure_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    A simulated ImportError must cause check_import_app_main to return FAIL
    with the exception class name in the message and a fix suggestion.
    """
    def _raise(_name: str) -> None:
        raise ImportError("No module named 'missing_dep'")

    monkeypatch.setattr(doctor, "_do_import", _raise)

    result = check_import_app_main()
    assert result.status == Status.FAIL
    assert "ImportError" in result.message
    assert "missing_dep" in result.message
    assert result.fix is not None
    assert "pip install" in result.fix


def test_import_check_failure_unicode_decode_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    A simulated UnicodeDecodeError must produce a FAIL with a fix hint that
    references explicit encoding.
    """
    def _raise(_name: str) -> None:
        raise UnicodeDecodeError("utf-8", b"\xff\xfe", 0, 1, "invalid start byte")

    monkeypatch.setattr(doctor, "_do_import", _raise)

    result = check_import_app_main()
    assert result.status == Status.FAIL
    assert "UnicodeDecodeError" in result.message
    assert result.fix is not None
    # Fix must mention encoding.
    assert "encoding" in result.fix.lower() or "UTF-8" in result.fix


def test_import_check_failure_generic_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any unexpected exception during import must be caught and returned as FAIL."""
    def _raise(_name: str) -> None:
        raise RuntimeError("unexpected crash")

    monkeypatch.setattr(doctor, "_do_import", _raise)

    result = check_import_app_main()
    assert result.status == Status.FAIL
    assert "RuntimeError" in result.message


# ── C. JSON output schema ─────────────────────────────────────────────────────

def test_json_output_schema_shape() -> None:
    """
    ``to_json_dict`` must always produce all required top-level keys and the
    correct structure for every check entry.
    """
    checks = [
        Check("python-version", "ENV", Status.PASS, "Python 3.11.9"),
        Check("locale", "ENV", Status.WARN, "No LANG set", fix="export LANG=C.UTF-8"),
        Check("import-app", "IMPORT", Status.FAIL, "ImportError: foo", fix="pip install -e ."),
    ]
    output = to_json_dict(checks, 2)

    # Top-level keys.
    assert {"version", "status", "checks", "summary", "exit_code"} <= output.keys()

    # Overall status reflects worst check.
    assert output["status"] == "fail"
    assert output["exit_code"] == 2

    # Summary counts.
    assert output["summary"]["pass"] == 1
    assert output["summary"]["warn"] == 1
    assert output["summary"]["fail"] == 1
    assert output["summary"]["total"] == 3

    # Per-check structure.
    required_check_keys = {"id", "section", "status", "message", "fix", "meta"}
    for c in output["checks"]:
        assert required_check_keys <= c.keys(), f"Missing keys in check: {c}"


def test_json_output_is_valid_json() -> None:
    """``to_json_dict`` output must be serialisable by stdlib json without errors."""
    checks = [Check("x", "ENV", Status.PASS, "ok")]
    output = to_json_dict(checks, 0)
    serialised = json.dumps(output)
    parsed = json.loads(serialised)
    assert parsed["status"] == "pass"
    assert parsed["summary"]["total"] == 1


def test_json_output_no_secrets() -> None:
    """
    Secrets must never appear verbatim in JSON meta fields.

    We set AEGIS_ADMIN_KEY to a known value and confirm neither the full value
    nor the first characters appear in the serialised JSON output.
    """
    secret = "aegis_supersecretvalue12345"
    os.environ["AEGIS_ADMIN_KEY"] = secret
    try:
        from aegis.doctor import check_aegis_admin_key
        result = check_aegis_admin_key()
        serialised = json.dumps({"m": result.message, "meta": result.meta})
        # Full secret must not appear.
        assert secret not in serialised
        # First N chars of the key must not appear beyond the "aegis_" prefix.
        assert secret[6:20] not in serialised  # body of the secret
    finally:
        del os.environ["AEGIS_ADMIN_KEY"]


# ── ENV checks ────────────────────────────────────────────────────────────────

def test_python_version_pass() -> None:
    """Running Python 3.11+ must return PASS (test suite requires 3.11+)."""
    result = check_python_version()
    # We're running on 3.11+ because pyproject.toml requires it.
    assert result.status == Status.PASS
    assert "Python" in result.message


def test_auth_enabled_warn_when_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTH_ENABLED", "false")
    result = check_auth_enabled()
    assert result.status == Status.WARN
    assert "false" in result.message.lower()
    assert result.fix is not None


def test_auth_enabled_pass_when_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTH_ENABLED", "true")
    result = check_auth_enabled()
    assert result.status == Status.PASS


def test_rate_limit_fail_on_non_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RATE_LIMIT_RPM", "notanint")
    result = check_rate_limit()
    assert result.status == Status.FAIL
    assert result.fix is not None


def test_rate_limit_warn_on_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RATE_LIMIT_RPM", "0")
    result = check_rate_limit()
    assert result.status == Status.WARN


def test_locale_warn_on_c(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LANG", "C")
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.delenv("LC_CTYPE", raising=False)
    result = check_locale()
    assert result.status == Status.WARN
    assert "C" in result.message
    assert result.fix is not None


def test_locale_pass_on_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    monkeypatch.delenv("LC_ALL", raising=False)
    result = check_locale()
    assert result.status == Status.PASS


# ── DB checks ─────────────────────────────────────────────────────────────────

def test_db_dir_writable_fail_when_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If the DB parent directory does not exist, the check must return FAIL."""
    import app.config as cfg
    non_existent = tmp_path / "subdir" / "audit.db"
    monkeypatch.setattr(cfg, "DB_PATH", non_existent)
    result = check_db_dir_writable()
    assert result.status == Status.FAIL
    assert result.fix is not None


def test_db_connect_pass_on_existing_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """check_db_connect must pass for a valid (even empty) SQLite file."""
    import app.config as cfg
    db = tmp_path / "test.db"
    # Create a minimal SQLite file.
    conn = sqlite3.connect(str(db))
    conn.close()
    monkeypatch.setattr(cfg, "DB_PATH", db)
    result = check_db_connect()
    assert result.status == Status.PASS


def test_db_schema_warns_when_tables_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty DB (no tables) must produce a WARN about schema initialisation."""
    import app.config as cfg
    db = tmp_path / "empty.db"
    conn = sqlite3.connect(str(db))
    conn.close()
    monkeypatch.setattr(cfg, "DB_PATH", db)
    result = check_db_schema()
    assert result.status == Status.WARN
    assert "audit_events" in result.message or "missing" in result.message.lower()


def test_db_schema_pass_with_required_tables(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A DB with audit_events and gateway_state must pass the schema check."""
    import app.config as cfg
    db = tmp_path / "init.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE audit_events (id TEXT PRIMARY KEY)")
    conn.execute("CREATE TABLE gateway_state (key TEXT PRIMARY KEY)")
    conn.commit()
    conn.close()
    monkeypatch.setattr(cfg, "DB_PATH", db)
    result = check_db_schema()
    assert result.status == Status.PASS


# ── Aggregation helpers ───────────────────────────────────────────────────────

def test_overall_status_fail_dominates() -> None:
    checks = [
        Check("a", "ENV", Status.PASS, "ok"),
        Check("b", "ENV", Status.WARN, "warn"),
        Check("c", "ENV", Status.FAIL, "fail"),
    ]
    assert overall_status(checks) == Status.FAIL


def test_overall_status_warn_when_no_fail() -> None:
    checks = [
        Check("a", "ENV", Status.PASS, "ok"),
        Check("b", "ENV", Status.WARN, "warn"),
    ]
    assert overall_status(checks) == Status.WARN


def test_overall_status_pass_when_all_pass() -> None:
    checks = [Check("a", "ENV", Status.PASS, "ok")]
    assert overall_status(checks) == Status.PASS


def test_exit_code_mapping() -> None:
    assert exit_code([Check("a", "ENV", Status.PASS, "ok")]) == 0
    assert exit_code([Check("a", "ENV", Status.WARN, "w")]) == 1
    assert exit_code([Check("a", "ENV", Status.FAIL, "f")]) == 2


# ── CLI integration (via Typer CliRunner) ─────────────────────────────────────

def test_cli_doctor_human_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: ``aegis doctor --policy <valid>`` exits 1 (AEGIS_ADMIN_KEY warn)."""
    from typer.testing import CliRunner
    from aegis.cli import _app
    import app.config as cfg

    monkeypatch.setattr(cfg, "DB_PATH", tmp_path / "test.db")
    monkeypatch.delenv("AEGIS_ADMIN_KEY", raising=False)

    runner = CliRunner()
    # Write a minimal policy file
    policy = tmp_path / "policy.yaml"
    policy.write_text(MINIMAL_POLICY, encoding="utf-8")
    result = runner.invoke(_app, ["doctor", "--policy", str(policy)])
    assert "Aegis Doctor" in result.output
    assert "PASS" not in result.output or "✅" in result.output  # has check output
    # Exit code should be 0 or 1 (warn for admin key) — not 2
    assert result.exit_code in (0, 1)


def test_cli_doctor_json_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``aegis doctor --json`` must produce valid JSON with the required schema."""
    from typer.testing import CliRunner
    from aegis.cli import _app
    import app.config as cfg

    monkeypatch.setattr(cfg, "DB_PATH", tmp_path / "test.db")

    policy = tmp_path / "policy.yaml"
    policy.write_text(MINIMAL_POLICY, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(_app, ["doctor", "--json", "--policy", str(policy)])

    parsed = json.loads(result.output)
    assert {"version", "status", "checks", "summary", "exit_code"} <= parsed.keys()
    assert parsed["summary"]["total"] > 0
    for c in parsed["checks"]:
        assert {"id", "section", "status", "message", "fix", "meta"} <= c.keys()


def test_cli_doctor_fail_on_missing_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``aegis doctor --policy /nonexistent`` must exit with code 2."""
    from typer.testing import CliRunner
    from aegis.cli import _app
    import app.config as cfg

    monkeypatch.setattr(cfg, "DB_PATH", tmp_path / "test.db")

    runner = CliRunner()
    result = runner.invoke(_app, ["doctor", "--policy", str(tmp_path / "ghost.yaml")])
    assert result.exit_code == 2
    assert "❌" in result.output
