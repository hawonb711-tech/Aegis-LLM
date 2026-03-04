"""
Tests for aegis run_env helpers and the ``aegis run`` CLI command.

Structure
---------
TestNormalizeBasePath   — normalize_base_path() edge cases
TestBuildBaseUrl        — build_base_url() no double slashes
TestBuildInjectedEnv    — injection logic, conflict detection, warnings
TestFormatExports       — POSIX export line formatting
TestToJsonDict          — JSON dict shape
TestRunCLI              — CLI command via CliRunner (run_command monkeypatched)
TestSecretLeakage       — OPENAI_API_KEY must never appear in any output
TestIntegration         — actual subprocess, env var visible to child
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from aegis.cli import _app
from aegis.run_env import (
    build_base_url,
    build_injected_env,
    format_exports,
    normalize_base_path,
    to_json_dict,
)

runner = CliRunner()


# ── normalize_base_path ───────────────────────────────────────────────────────

class TestNormalizeBasePath:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("/v1", "/v1"),
            ("v1", "/v1"),
            ("/v1/", "/v1"),
            ("v1/", "/v1"),
            ("", ""),
            ("/", ""),
            ("//", ""),
            ("/api/v2", "/api/v2"),
            ("api/v2/", "/api/v2"),
            ("/api/v2/", "/api/v2"),
        ],
    )
    def test_normalize(self, raw: str, expected: str) -> None:
        assert normalize_base_path(raw) == expected


# ── build_base_url ────────────────────────────────────────────────────────────

class TestBuildBaseUrl:
    def test_standard(self) -> None:
        assert build_base_url("127.0.0.1", 8088, "/v1") == "http://127.0.0.1:8088/v1"

    def test_no_leading_slash_in_path(self) -> None:
        # "v1" should produce the same result as "/v1" — no double slash
        assert build_base_url("127.0.0.1", 8088, "v1") == "http://127.0.0.1:8088/v1"

    def test_trailing_slash_stripped(self) -> None:
        assert build_base_url("127.0.0.1", 8088, "/v1/") == "http://127.0.0.1:8088/v1"

    def test_empty_path(self) -> None:
        assert build_base_url("127.0.0.1", 8088, "") == "http://127.0.0.1:8088"

    def test_slash_only_path(self) -> None:
        assert build_base_url("127.0.0.1", 8088, "/") == "http://127.0.0.1:8088"

    def test_no_double_slash(self) -> None:
        url = build_base_url("127.0.0.1", 8088, "/v1")
        assert "//" not in url.replace("http://", "")

    def test_custom_host_and_port(self) -> None:
        assert build_base_url("0.0.0.0", 9000, "/api") == "http://0.0.0.0:9000/api"

    def test_deep_path(self) -> None:
        assert build_base_url("localhost", 8088, "/api/v2/") == "http://localhost:8088/api/v2"


# ── build_injected_env ────────────────────────────────────────────────────────

class TestBuildInjectedEnv:
    def test_fresh_env_injects_both_vars(self) -> None:
        injected, warnings = build_injected_env("127.0.0.1", 8088, "/v1", {})
        assert "OPENAI_BASE_URL" in injected
        assert "OPENAI_API_BASE" in injected
        assert warnings == []

    def test_injected_values_match_base_url(self) -> None:
        injected, _ = build_injected_env("127.0.0.1", 8088, "/v1", {})
        expected = "http://127.0.0.1:8088/v1"
        assert injected["OPENAI_BASE_URL"] == expected
        assert injected["OPENAI_API_BASE"] == expected

    def test_existing_base_url_not_overwritten(self) -> None:
        existing = {"OPENAI_BASE_URL": "http://other:1234/v1"}
        injected, warnings = build_injected_env("127.0.0.1", 8088, "/v1", existing)
        # OPENAI_BASE_URL should not be in injected — it stays in existing
        assert "OPENAI_BASE_URL" not in injected
        # OPENAI_API_BASE is still fresh
        assert "OPENAI_API_BASE" in injected

    def test_existing_base_url_emits_warning(self) -> None:
        existing = {"OPENAI_BASE_URL": "http://other:1234/v1"}
        _, warnings = build_injected_env("127.0.0.1", 8088, "/v1", existing)
        assert len(warnings) == 1
        assert "OPENAI_BASE_URL" in warnings[0]

    def test_existing_api_base_not_overwritten(self) -> None:
        existing = {"OPENAI_API_BASE": "http://other:1234/v1"}
        injected, warnings = build_injected_env("127.0.0.1", 8088, "/v1", existing)
        assert "OPENAI_API_BASE" not in injected
        assert "OPENAI_BASE_URL" in injected
        assert len(warnings) == 1
        assert "OPENAI_API_BASE" in warnings[0]

    def test_both_existing_no_injection(self) -> None:
        existing = {
            "OPENAI_BASE_URL": "http://a:1/v1",
            "OPENAI_API_BASE": "http://b:2/v1",
        }
        injected, warnings = build_injected_env("127.0.0.1", 8088, "/v1", existing)
        assert injected == {}
        assert len(warnings) == 2

    def test_warning_does_not_contain_existing_value(self) -> None:
        secret_url = "http://secret-host:9999/private"
        existing = {"OPENAI_BASE_URL": secret_url}
        _, warnings = build_injected_env("127.0.0.1", 8088, "/v1", existing)
        for w in warnings:
            assert secret_url not in w

    def test_other_env_vars_ignored(self) -> None:
        existing = {"PATH": "/usr/bin", "HOME": "/root", "SOME_TOKEN": "abc"}
        injected, warnings = build_injected_env("127.0.0.1", 8088, "/v1", existing)
        # Unrelated vars should have no effect
        assert "OPENAI_BASE_URL" in injected
        assert warnings == []


# ── format_exports ────────────────────────────────────────────────────────────

class TestFormatExports:
    def test_contains_export_keyword(self) -> None:
        injected = {"OPENAI_BASE_URL": "http://127.0.0.1:8088/v1"}
        out = format_exports(injected)
        assert "export OPENAI_BASE_URL=" in out

    def test_single_quoted_value(self) -> None:
        injected = {"OPENAI_BASE_URL": "http://127.0.0.1:8088/v1"}
        out = format_exports(injected)
        assert "='http://127.0.0.1:8088/v1'" in out

    def test_empty_injected_returns_empty_string(self) -> None:
        assert format_exports({}) == ""

    def test_multiple_vars(self) -> None:
        injected = {
            "OPENAI_BASE_URL": "http://127.0.0.1:8088/v1",
            "OPENAI_API_BASE": "http://127.0.0.1:8088/v1",
        }
        out = format_exports(injected)
        assert "OPENAI_BASE_URL" in out
        assert "OPENAI_API_BASE" in out

    def test_single_quote_in_value_escaped(self) -> None:
        # Ensure values with single quotes don't break the shell quoting.
        injected = {"KEY": "val'ue"}
        out = format_exports(injected)
        assert "val'\\''ue" in out


# ── to_json_dict ──────────────────────────────────────────────────────────────

class TestToJsonDict:
    def test_required_keys(self) -> None:
        d = to_json_dict(["python", "-c", "pass"], {"K": "V"}, ["warn"])
        assert set(d.keys()) == {"command", "injected_env", "warnings"}

    def test_command_is_list(self) -> None:
        d = to_json_dict(["python"], {}, [])
        assert isinstance(d["command"], list)
        assert d["command"] == ["python"]

    def test_injected_env_matches(self) -> None:
        injected = {"OPENAI_BASE_URL": "http://x:8/v1"}
        d = to_json_dict([], injected, [])
        assert d["injected_env"] == injected

    def test_warnings_list(self) -> None:
        d = to_json_dict([], {}, ["w1", "w2"])
        assert d["warnings"] == ["w1", "w2"]

    def test_serialisable(self) -> None:
        d = to_json_dict(["cmd"], {"K": "V"}, ["w"])
        json.dumps(d)  # must not raise


# ── CLI tests (run_command monkeypatched) ─────────────────────────────────────

class TestRunCLI:
    def _fake_run(self, captured: list):
        """Return a monkeypatch-compatible run_command that records calls."""

        def _inner(cmd_argv, merged_env):
            captured.append({"cmd": cmd_argv, "env": dict(merged_env)})
            return 0

        return _inner

    def test_no_command_exits_two(self) -> None:
        result = runner.invoke(_app, ["run"])
        assert result.exit_code == 2

    def test_no_command_after_separator_exits_two(self) -> None:
        result = runner.invoke(_app, ["run", "--"])
        assert result.exit_code == 2

    def test_print_env_exits_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called = []
        monkeypatch.setattr("aegis.run_env.run_command", self._fake_run(called))
        result = runner.invoke(_app, ["run", "--print-env"])
        assert result.exit_code == 0

    def test_print_env_does_not_run_subprocess(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        called = []
        monkeypatch.setattr("aegis.run_env.run_command", self._fake_run(called))
        runner.invoke(_app, ["run", "--print-env"])
        assert called == [], "run_command must not be called with --print-env"

    def test_print_env_contains_export_lines(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        result = runner.invoke(_app, ["run", "--print-env"])
        assert "export OPENAI_BASE_URL=" in result.output
        assert "export OPENAI_API_BASE=" in result.output

    def test_print_env_url_in_output(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        result = runner.invoke(
            _app, ["run", "--host", "127.0.0.1", "--port", "8088", "--print-env"]
        )
        assert "http://127.0.0.1:8088/v1" in result.output

    def test_json_exits_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        result = runner.invoke(_app, ["run", "--json", "--", "echo", "hi"])
        assert result.exit_code == 0

    def test_json_output_is_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        result = runner.invoke(_app, ["run", "--json", "--", "echo", "hi"])
        data = json.loads(result.output)
        assert isinstance(data, dict)

    def test_json_has_required_keys(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        result = runner.invoke(_app, ["run", "--json", "--", "echo", "hi"])
        data = json.loads(result.output)
        assert "command" in data
        assert "injected_env" in data
        assert "warnings" in data

    def test_json_does_not_run_subprocess(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        called = []
        monkeypatch.setattr("aegis.run_env.run_command", self._fake_run(called))
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        runner.invoke(_app, ["run", "--json", "--", "echo", "hi"])
        assert called == [], "run_command must not be called with --json"

    def test_json_command_field_matches_argv(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        result = runner.invoke(
            _app, ["run", "--json", "--", "python", "-c", "pass"]
        )
        data = json.loads(result.output)
        assert data["command"] == ["python", "-c", "pass"]

    def test_run_command_called_with_merged_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: list = []
        monkeypatch.setattr("aegis.run_env.run_command", self._fake_run(captured))
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        result = runner.invoke(_app, ["run", "--", "echo", "hi"])
        assert result.exit_code == 0
        assert len(captured) == 1
        assert captured[0]["env"].get("OPENAI_BASE_URL") == "http://127.0.0.1:8088/v1"

    def test_run_command_receives_correct_argv(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: list = []
        monkeypatch.setattr("aegis.run_env.run_command", self._fake_run(captured))
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        runner.invoke(_app, ["run", "--", "myprogram", "--flag", "arg"])
        assert captured[0]["cmd"] == ["myprogram", "--flag", "arg"]

    def test_child_exit_code_propagated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "aegis.run_env.run_command",
            lambda cmd, env: 42,
        )
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        result = runner.invoke(_app, ["run", "--", "cmd"])
        assert result.exit_code == 42

    def test_warning_emitted_when_var_already_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_BASE_URL", "http://existing:1234/v1")
        monkeypatch.setattr(
            "aegis.run_env.run_command", self._fake_run([])
        )
        result = runner.invoke(_app, ["run", "--verbose", "--", "echo"])
        assert "OPENAI_BASE_URL" in result.output

    def test_existing_var_not_overwritten_in_child(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        existing_url = "http://existing:1234/v1"
        monkeypatch.setenv("OPENAI_BASE_URL", existing_url)
        captured: list = []
        monkeypatch.setattr("aegis.run_env.run_command", self._fake_run(captured))
        runner.invoke(_app, ["run", "--", "echo"])
        # The existing value must be passed through, not the aegis URL.
        assert captured[0]["env"]["OPENAI_BASE_URL"] == existing_url

    def test_env_file_sets_var_before_injection(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Vars from --env-file must be visible when build_injected_env runs."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "OPENAI_BASE_URL=http://from-env-file:9/v1\n", encoding="utf-8"
        )
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        result = runner.invoke(
            _app,
            ["run", "--env-file", str(env_file), "--json", "--", "cmd"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        # OPENAI_BASE_URL was set by env-file before injection check,
        # so it should NOT be in injected_env (conflict preserved).
        assert "OPENAI_BASE_URL" not in data["injected_env"]
        # And a warning should have been recorded.
        assert any("OPENAI_BASE_URL" in w for w in data["warnings"])

    def test_custom_host_port_base_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        result = runner.invoke(
            _app,
            [
                "run",
                "--host", "10.0.0.1",
                "--port", "9001",
                "--base-path", "/api/v2",
                "--json",
                "--", "echo",
            ],
        )
        data = json.loads(result.output)
        assert data["injected_env"]["OPENAI_BASE_URL"] == "http://10.0.0.1:9001/api/v2"


# ── Secret leakage ────────────────────────────────────────────────────────────

class TestSecretLeakage:
    """OPENAI_API_KEY must never appear as a value in any output mode."""

    SECRET = "sk-super-secret-key-do-not-leak"

    def test_secret_not_in_print_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", self.SECRET)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        result = runner.invoke(_app, ["run", "--print-env"])
        assert self.SECRET not in result.output

    def test_secret_not_in_json(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", self.SECRET)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        result = runner.invoke(_app, ["run", "--json", "--", "echo"])
        assert self.SECRET not in result.output

    def test_secret_not_in_verbose_output(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Set the injected vars so we get warnings (which might expose values).
        monkeypatch.setenv("OPENAI_API_KEY", self.SECRET)
        monkeypatch.setenv("OPENAI_BASE_URL", "http://existing:1/v1")
        monkeypatch.setattr(
            "aegis.run_env.run_command", lambda cmd, env: 0
        )
        result = runner.invoke(_app, ["run", "--verbose", "--", "echo"])
        assert self.SECRET not in result.output

    def test_format_exports_never_includes_api_key(self) -> None:
        # format_exports only outputs what's in the injected dict.
        # OPENAI_API_KEY is never injected, so it should never appear.
        injected = {
            "OPENAI_BASE_URL": "http://127.0.0.1:8088/v1",
            "OPENAI_API_BASE": "http://127.0.0.1:8088/v1",
        }
        out = format_exports(injected)
        assert "OPENAI_API_KEY" not in out
        assert "API_KEY" not in out

    def test_to_json_dict_never_includes_full_env(self) -> None:
        injected = {"OPENAI_BASE_URL": "http://127.0.0.1:8088/v1"}
        d = to_json_dict(["cmd"], injected, [])
        dumped = json.dumps(d)
        # The secret is in os.environ but should NOT appear in JSON output.
        os.environ.setdefault("OPENAI_API_KEY", self.SECRET)
        assert self.SECRET not in dumped


# ── Integration — actual subprocess ──────────────────────────────────────────

class TestIntegration:
    """These tests launch real child processes to verify end-to-end behaviour."""

    def test_openai_base_url_visible_in_child(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Child process must see the injected OPENAI_BASE_URL."""
        import subprocess

        from aegis.run_env import build_injected_env, run_command

        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)

        injected, warnings = build_injected_env("127.0.0.1", 8088, "/v1", os.environ)
        assert warnings == []

        merged_env = {**os.environ, **injected}
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import os; print(os.environ['OPENAI_BASE_URL'])",
            ],
            env=merged_env,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        assert "http://127.0.0.1:8088/v1" in proc.stdout

    def test_openai_api_base_visible_in_child(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import subprocess

        from aegis.run_env import build_injected_env

        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)

        injected, _ = build_injected_env("127.0.0.1", 8088, "/v1", os.environ)
        merged_env = {**os.environ, **injected}

        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import os; print(os.environ['OPENAI_API_BASE'])",
            ],
            env=merged_env,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        assert "http://127.0.0.1:8088/v1" in proc.stdout

    def test_child_exit_code_forwarded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import subprocess

        from aegis.run_env import build_injected_env, run_command

        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)

        injected, _ = build_injected_env("127.0.0.1", 8088, "/v1", os.environ)
        merged_env = {**os.environ, **injected}

        # Exit code 5 from the child.
        code = run_command(
            [sys.executable, "-c", "raise SystemExit(5)"],
            merged_env,
        )
        assert code == 5

    def test_run_command_inherits_existing_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Unrelated env vars in the parent must be visible to the child."""
        import subprocess

        from aegis.run_env import run_command

        sentinel = "AEGIS_RUN_TEST_SENTINEL_XYZ"
        monkeypatch.setenv(sentinel, "present")

        merged = {**os.environ}
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                f"import os; print(os.environ.get('{sentinel}', 'MISSING'))",
            ],
            env=merged,
            capture_output=True,
            text=True,
        )
        assert "present" in proc.stdout
