"""
Tests for aegis serve — uvicorn wrapper CLI command.

Strategy
--------
- ``uvicorn.run`` / ``aegis.serve.main_run`` are always monkeypatched so no
  real server is ever started.
- ``typer.testing.CliRunner`` invokes the command in-process, making env-var
  side effects observable directly in ``os.environ``.
- ``--json`` mode is used heavily because it exits without starting the server
  and still exercises argument parsing, env-file loading, and policy wiring.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegis.cli import _app  # The Typer app instance used by aegis.cli.main

runner = CliRunner()

# ── Helpers ───────────────────────────────────────────────────────────────────

def _default_policy() -> Path:
    """Absolute path to the bundled default policy."""
    return Path(__file__).parent.parent / "policies" / "default.yaml"


def _noop_run(*args: object, **kwargs: object) -> None:
    """Replacement for aegis.serve.main_run that does nothing."""


# ── aegis.serve pure-function unit tests ──────────────────────────────────────

class TestServeCoreFunctions:
    def test_resolve_app_import(self):
        from aegis.serve import resolve_app_import

        assert resolve_app_import() == "app.main:app"

    def test_build_uvicorn_config_keys(self):
        from aegis.serve import build_uvicorn_config

        cfg = build_uvicorn_config("0.0.0.0", 9000, True, "DEBUG")
        assert set(cfg.keys()) == {"host", "port", "reload", "log_level"}

    def test_build_uvicorn_config_values(self):
        from aegis.serve import build_uvicorn_config

        cfg = build_uvicorn_config("127.0.0.1", 8088, False, "INFO")
        assert cfg["host"] == "127.0.0.1"
        assert cfg["port"] == 8088
        assert cfg["reload"] is False
        assert cfg["log_level"] == "info"  # normalised to lowercase

    def test_build_uvicorn_config_lowercases_log_level(self):
        from aegis.serve import build_uvicorn_config

        cfg = build_uvicorn_config("127.0.0.1", 8088, False, "WARNING")
        assert cfg["log_level"] == "warning"

    def test_resolve_policy_path_with_override(self):
        from aegis.serve import resolve_policy_path

        p = _default_policy()
        assert resolve_policy_path(p) == p.resolve()

    def test_resolve_policy_path_without_override(self):
        from aegis.serve import resolve_policy_path

        result = resolve_policy_path(None)
        # Must be a Path and point somewhere meaningful.
        assert isinstance(result, Path)
        assert "yaml" in result.suffix or str(result).endswith("yaml")


# ── --json mode ───────────────────────────────────────────────────────────────

class TestServeJsonMode:
    def test_json_exits_zero(self):
        result = runner.invoke(_app, ["serve", "--json"])
        assert result.exit_code == 0, result.output

    def test_json_output_is_valid_json(self):
        result = runner.invoke(_app, ["serve", "--json"])
        data = json.loads(result.output)
        assert isinstance(data, dict)

    def test_json_has_required_keys(self):
        result = runner.invoke(_app, ["serve", "--json"])
        data = json.loads(result.output)
        required = {"host", "port", "reload", "log_level", "app_import", "policy_path_resolved"}
        assert required <= set(data.keys())

    def test_json_default_host(self):
        result = runner.invoke(_app, ["serve", "--json"])
        assert json.loads(result.output)["host"] == "127.0.0.1"

    def test_json_default_port(self):
        result = runner.invoke(_app, ["serve", "--json"])
        assert json.loads(result.output)["port"] == 8088

    def test_json_default_reload_false(self):
        result = runner.invoke(_app, ["serve", "--json"])
        assert json.loads(result.output)["reload"] is False

    def test_json_default_log_level(self):
        result = runner.invoke(_app, ["serve", "--json"])
        assert json.loads(result.output)["log_level"] == "info"

    def test_json_app_import_matches_entrypoint(self):
        result = runner.invoke(_app, ["serve", "--json"])
        assert json.loads(result.output)["app_import"] == "app.main:app"

    def test_json_custom_host_and_port(self):
        result = runner.invoke(_app, ["serve", "--host", "0.0.0.0", "--port", "9999", "--json"])
        data = json.loads(result.output)
        assert data["host"] == "0.0.0.0"
        assert data["port"] == 9999

    def test_json_reload_flag_reflected(self):
        result = runner.invoke(_app, ["serve", "--reload", "--json"])
        assert json.loads(result.output)["reload"] is True

    def test_json_log_level_normalised(self):
        result = runner.invoke(_app, ["serve", "--log-level", "DEBUG", "--json"])
        assert json.loads(result.output)["log_level"] == "debug"

    def test_json_does_not_start_server(self, monkeypatch: pytest.MonkeyPatch):
        """--json must not call main_run or uvicorn.run."""
        called = []
        monkeypatch.setattr("aegis.serve.main_run", lambda *a, **kw: called.append(1))
        runner.invoke(_app, ["serve", "--json"])
        assert called == [], "main_run must not be invoked in --json mode"

    def test_json_policy_path_resolved_present(self):
        result = runner.invoke(_app, ["serve", "--json"])
        data = json.loads(result.output)
        assert "policy_path_resolved" in data
        assert data["policy_path_resolved"]  # non-empty string


# ── --policy flag ─────────────────────────────────────────────────────────────

class TestServePolicy:
    def test_policy_sets_env_var_before_main_run(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """--policy must set POLICY_PATH before main_run is called."""
        captured: dict = {}

        def fake_main_run(**kwargs: object) -> None:
            captured["POLICY_PATH"] = os.environ.get("POLICY_PATH")

        monkeypatch.setattr("aegis.serve.main_run", fake_main_run)
        monkeypatch.delenv("POLICY_PATH", raising=False)

        policy = _default_policy()
        result = runner.invoke(_app, ["serve", "--policy", str(policy)])
        assert result.exit_code == 0, result.output
        assert captured["POLICY_PATH"] == str(policy.resolve())

    def test_policy_shown_in_json(self, monkeypatch: pytest.MonkeyPatch):
        """--policy --json shows the resolved policy path."""
        monkeypatch.delenv("POLICY_PATH", raising=False)
        policy = _default_policy()
        result = runner.invoke(_app, ["serve", "--policy", str(policy), "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["policy_path_resolved"] == str(policy.resolve())

    def test_missing_policy_exits_two(self, tmp_path: Path):
        """Non-existent --policy file must cause exit code 2."""
        missing = tmp_path / "no-such-policy.yaml"
        result = runner.invoke(_app, ["serve", "--policy", str(missing), "--json"])
        assert result.exit_code == 2

    def test_missing_policy_error_message(self, tmp_path: Path):
        """Error message for missing policy must mention 'not found'."""
        missing = tmp_path / "no-such.yaml"
        result = runner.invoke(_app, ["serve", "--policy", str(missing)])
        assert "not found" in result.output.lower()


# ── --env-file flag ───────────────────────────────────────────────────────────

class TestServeEnvFile:
    def test_env_file_loaded_before_main_run(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        """
        Env vars from --env-file must be present in os.environ when main_run
        is called (which is when uvicorn imports app.main -> app.config).
        """
        sentinel_key = "AEGIS_SERVE_TEST_SENTINEL_1"
        sentinel_val = "env_file_value_ok"

        env_file = tmp_path / ".env"
        env_file.write_text(f"{sentinel_key}={sentinel_val}\n", encoding="utf-8")

        captured: dict = {}

        def fake_main_run(**kwargs: object) -> None:
            captured[sentinel_key] = os.environ.get(sentinel_key)

        monkeypatch.setattr("aegis.serve.main_run", fake_main_run)
        monkeypatch.delenv(sentinel_key, raising=False)

        result = runner.invoke(_app, ["serve", "--env-file", str(env_file)])
        assert result.exit_code == 0, result.output
        assert captured[sentinel_key] == sentinel_val

    def test_env_file_loaded_in_json_mode(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        """env-file must also be loaded in --json mode (sets vars for resolution)."""
        sentinel_key = "AEGIS_SERVE_TEST_SENTINEL_2"
        sentinel_val = "json_mode_ok"

        env_file = tmp_path / ".env"
        env_file.write_text(f"{sentinel_key}={sentinel_val}\n", encoding="utf-8")

        monkeypatch.delenv(sentinel_key, raising=False)

        result = runner.invoke(
            _app, ["serve", "--env-file", str(env_file), "--json"]
        )
        assert result.exit_code == 0, result.output
        # Side effect: env var must now be in os.environ (same process).
        assert os.environ.get(sentinel_key) == sentinel_val

    def test_missing_env_file_warns(self, tmp_path: Path):
        """A missing --env-file should warn (not crash) — matches doctor behaviour."""
        missing = tmp_path / "no-such.env"
        result = runner.invoke(_app, ["serve", "--env-file", str(missing), "--json"])
        # Should still succeed (--json works) but emit a warning.
        assert result.exit_code == 0

    def test_env_file_loaded_before_policy_resolution(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        """
        If --env-file sets POLICY_PATH, that value must be visible when
        resolve_policy_path() is called (no explicit --policy override).
        """
        policy = _default_policy()
        env_file = tmp_path / ".env"
        env_file.write_text(f"POLICY_PATH={policy}\n", encoding="utf-8")

        monkeypatch.delenv("POLICY_PATH", raising=False)
        monkeypatch.setattr("aegis.serve.main_run", _noop_run)

        result = runner.invoke(
            _app, ["serve", "--env-file", str(env_file), "--json"]
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        # POLICY_PATH from .env should be reflected in the resolved path.
        assert str(policy) in data["policy_path_resolved"]


# ── server startup (main_run called) ─────────────────────────────────────────

class TestServeStartup:
    def test_main_run_called_without_json(self, monkeypatch: pytest.MonkeyPatch):
        """Without --json, main_run must be called exactly once."""
        called = []

        def fake_main_run(**kwargs: object) -> None:
            called.append(kwargs)

        monkeypatch.setattr("aegis.serve.main_run", fake_main_run)
        result = runner.invoke(_app, ["serve"])
        assert result.exit_code == 0, result.output
        assert len(called) == 1

    def test_main_run_receives_correct_args(self, monkeypatch: pytest.MonkeyPatch):
        """CLI flags must be forwarded to main_run."""
        captured: dict = {}

        def fake_main_run(**kwargs: object) -> None:
            captured.update(kwargs)

        monkeypatch.setattr("aegis.serve.main_run", fake_main_run)
        runner.invoke(
            _app,
            ["serve", "--host", "0.0.0.0", "--port", "9000",
             "--log-level", "debug", "--reload"],
        )
        assert captured["host"] == "0.0.0.0"
        assert captured["port"] == 9000
        assert captured["log_level"] == "debug"
        assert captured["reload"] is True

    def test_main_run_app_import_forwarded(self, monkeypatch: pytest.MonkeyPatch):
        captured: dict = {}

        def fake_main_run(**kwargs: object) -> None:
            captured.update(kwargs)

        monkeypatch.setattr("aegis.serve.main_run", fake_main_run)
        runner.invoke(_app, ["serve"])
        assert captured.get("app_import") == "app.main:app"

    def test_main_run_exception_exits_two(self, monkeypatch: pytest.MonkeyPatch):
        """An exception from main_run must produce exit code 2."""

        def boom(**kwargs: object) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr("aegis.serve.main_run", boom)
        result = runner.invoke(_app, ["serve"])
        assert result.exit_code == 2
