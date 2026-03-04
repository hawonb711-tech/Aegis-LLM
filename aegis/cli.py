"""
Aegis CLI — ``aegis doctor`` entry point.

Usage
-----
    aegis doctor                       # human output (all sections)
    aegis doctor --json                # machine-readable JSON to stdout
    aegis doctor --verbose             # show meta fields for each check
    aegis doctor --policy ./my.yaml    # override policy file path
    aegis doctor --env-file .env       # load .env before running checks

Exit codes:
    0 — all checks passed
    1 — one or more warnings (non-fatal)
    2 — one or more failures (fatal / cannot run)
"""
from __future__ import annotations

import json as _json_mod
import os
import sys
from pathlib import Path
from typing import List, Optional

import typer

from aegis import __version__
from aegis.doctor import (
    ICONS,
    SECTIONS,
    Check,
    Status,
    exit_code,
    overall_status,
    run_all_checks,
    to_json_dict,
)

_app = typer.Typer(
    name="aegis",
    help="Aegis-LLM security gateway CLI.",
    add_completion=False,
    no_args_is_help=True,
)


@_app.callback()
def _root() -> None:
    """Aegis-LLM gateway tooling."""

# ── Output formatting ─────────────────────────────────────────────────────────

_SEP_WIDTH = 52
_SEP = "─" * _SEP_WIDTH
_SEP_HEAVY = "━" * _SEP_WIDTH

_EXIT_MESSAGES = {
    0: "All checks passed",
    1: "Warnings present — review the items above",
    2: "Fatal errors detected — gateway will not start correctly",
}


def _pad_id(id_: str, width: int) -> str:
    return id_.ljust(width)


def _format_human(checks: List[Check], verbose: bool) -> str:
    lines: List[str] = []

    lines.append(_SEP_HEAVY)
    lines.append(f"  Aegis Doctor  v{__version__}")
    lines.append(_SEP_HEAVY)

    # Find max ID width for alignment within each section.
    by_section: dict[str, List[Check]] = {s: [] for s in SECTIONS}
    for c in checks:
        by_section.setdefault(c.section, []).append(c)

    for section in SECTIONS:
        section_checks = by_section.get(section, [])
        if not section_checks:
            continue
        lines.append(f"\n[{section}]")
        id_width = max(len(c.id) for c in section_checks)
        for c in section_checks:
            icon = ICONS[c.status]
            id_padded = _pad_id(c.id, id_width)
            lines.append(f"  {icon}  {id_padded}   {c.message}")
            if c.fix:
                lines.append(f"       {'':>{id_width}}   Fix: {c.fix}")
            if verbose and c.meta:
                for k, v in c.meta.items():
                    lines.append(f"       {'':>{id_width}}   {k}: {v!r}")

    # Summary
    n_pass = sum(1 for c in checks if c.status == Status.PASS)
    n_warn = sum(1 for c in checks if c.status == Status.WARN)
    n_fail = sum(1 for c in checks if c.status == Status.FAIL)
    code = exit_code(checks)

    lines.append(f"\n{_SEP}")
    lines.append(f"  {n_pass} pass  |  {n_warn} warn  |  {n_fail} fail")
    lines.append(f"  Exit {code} — {_EXIT_MESSAGES[code]}")
    lines.append(_SEP)

    return "\n".join(lines)


# ── Env-file loading ──────────────────────────────────────────────────────────

def _load_env_file(path: Path) -> None:
    """
    Load key=value pairs from a .env file into os.environ.

    Uses python-dotenv if available (it ships with uvicorn[standard]).
    Falls back to a minimal parser for plain KEY=VALUE lines.
    """
    if not path.exists():
        typer.echo(f"Warning: env file not found: {path}", err=True)
        return

    # Prefer python-dotenv (available via uvicorn[standard]).
    try:
        from dotenv import load_dotenv  # type: ignore[import]
        load_dotenv(path, override=True)
        return
    except ImportError:
        pass

    # Minimal fallback parser — handles simple KEY=VALUE lines.
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, val = line.partition("=")
                    key = key.strip()
                    # Strip optional surrounding quotes.
                    val = val.strip()
                    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                        val = val[1:-1]
                    if key:
                        os.environ[key] = val
    except OSError as e:
        typer.echo(f"Warning: could not read env file {path}: {e}", err=True)


# ── Commands ──────────────────────────────────────────────────────────────────

@_app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def run(
    ctx: typer.Context,
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Gateway host (must match the running aegis serve --host).",
    ),
    port: int = typer.Option(
        8088,
        "--port",
        help="Gateway port (must match the running aegis serve --port).",
    ),
    base_path: str = typer.Option(
        "/v1",
        "--base-path",
        help="API base path appended to host:port when building the base URL.",
    ),
    env_file: Optional[Path] = typer.Option(
        None,
        "--env-file",
        help="Load environment variables from a .env file before running.",
        show_default=False,
    ),
    print_env: bool = typer.Option(
        False,
        "--print-env",
        help="Print POSIX export lines for injected vars, then exit 0 (no exec).",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print a JSON object describing injected env + command, then exit 0.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Print warnings to stderr (e.g., when a var is already set). "
             "Secret values are never printed.",
    ),
) -> None:
    """
    Run a command with env vars injected to route OpenAI-compatible SDK
    calls through the local Aegis gateway.

    Usage: aegis run [OPTIONS] -- <cmd> [args...]

    The injected vars are OPENAI_BASE_URL and OPENAI_API_BASE.
    Existing values in the current environment are never overwritten.

    Exit code equals the child process exit code (or 2 on fatal error).
    """
    # ── 1. Load env file BEFORE building the injected env ──────────────────
    if env_file:
        _load_env_file(env_file)

    # ── 2. Parse remaining args; strip leading '--' separator if present ────
    cmd_argv = list(ctx.args)
    if cmd_argv and cmd_argv[0] == "--":
        cmd_argv = cmd_argv[1:]

    # ── 3. Build injected env (checks os.environ AFTER env-file load) ───────
    import aegis.run_env as _run_env

    injected, warnings = _run_env.build_injected_env(
        host, port, base_path, os.environ
    )

    # ── 4. --print-env: output export lines and exit ─────────────────────
    if print_env:
        exports = _run_env.format_exports(injected)
        if exports:
            typer.echo(exports)
        if warnings and verbose:
            for w in warnings:
                typer.echo(f"Warning: {w}", err=True)
        raise typer.Exit(code=0)

    # ── 5. --json: output config dict and exit ───────────────────────────
    if json_output:
        payload = _run_env.to_json_dict(cmd_argv, injected, warnings)
        typer.echo(_json_mod.dumps(payload, indent=2))
        raise typer.Exit(code=0)

    # ── 6. Verbose warnings to stderr ────────────────────────────────────
    if verbose:
        for w in warnings:
            typer.echo(f"Warning: {w}", err=True)

    # ── 7. Require a command ─────────────────────────────────────────────
    if not cmd_argv:
        typer.echo(
            "Error: no command provided.\n"
            "Usage: aegis run [OPTIONS] -- <cmd> [args...]",
            err=True,
        )
        raise typer.Exit(code=2)

    # ── 8. Merge env and exec ────────────────────────────────────────────
    merged_env = {**os.environ, **injected}
    try:
        child_code = _run_env.run_command(cmd_argv, merged_env)
    except FileNotFoundError:
        typer.echo(f"Error: command not found: {cmd_argv[0]!r}", err=True)
        raise typer.Exit(code=2)
    except Exception as exc:
        typer.echo(f"Fatal: {exc}", err=True)
        raise typer.Exit(code=2)

    raise typer.Exit(code=child_code)


@_app.command()
def doctor(
    policy: Optional[Path] = typer.Option(
        None,
        "--policy",
        help="Override the policy file path (default: uses POLICY_PATH env or compiled default).",
        show_default=False,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON to stdout instead of the human-readable report.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Show metadata fields for each check in human output.",
    ),
    env_file: Optional[Path] = typer.Option(
        None,
        "--env-file",
        help="Load environment variables from a .env file before running checks.",
        show_default=False,
    ),
) -> None:
    """
    Run diagnostic checks on the Aegis gateway environment.

    Checks cover: ENV (Python version, locale, config vars), POLICY (path,
    encoding, YAML, schema), DATABASE (SQLite connectivity, schema), and
    IMPORT (app.main importability).
    """
    # Load env file first — BEFORE any app.* imports so env vars are visible
    # to app/config.py when it is first imported inside the check functions.
    if env_file:
        _load_env_file(env_file)

    checks = run_all_checks(policy_override=policy)
    code = exit_code(checks)

    if json_output:
        payload = to_json_dict(checks, code)
        typer.echo(_json_mod.dumps(payload, indent=2))
    else:
        typer.echo(_format_human(checks, verbose=verbose))

    raise typer.Exit(code=code)


@_app.command()
def serve(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Network interface to bind (use 0.0.0.0 to expose externally).",
    ),
    port: int = typer.Option(
        8088,
        "--port",
        help="TCP port to listen on.",
    ),
    reload: bool = typer.Option(
        False,
        "--reload",
        help="Enable uvicorn auto-reload (development only; do not use in production).",
    ),
    log_level: str = typer.Option(
        "info",
        "--log-level",
        help="Uvicorn log level (debug | info | warning | error | critical).",
    ),
    policy: Optional[Path] = typer.Option(
        None,
        "--policy",
        help=(
            "Override policy file path.  Sets POLICY_PATH env var before "
            "the server imports app.config."
        ),
        show_default=False,
    ),
    env_file: Optional[Path] = typer.Option(
        None,
        "--env-file",
        help="Load environment variables from a .env file before starting.",
        show_default=False,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help=(
            "Print a JSON object describing what would run, then exit 0 "
            "without starting the server.  Useful for CI and debugging."
        ),
    ),
) -> None:
    """
    Start the Aegis-LLM gateway using uvicorn.

    The server runs app.main:app (FastAPI) on the given host/port.
    Set POLICY_PATH (or use --policy) to change the active policy file.

    Exit codes: 0 success, 2 fatal (bad args, missing policy file, import error).
    """
    # ── Step 1: load env file BEFORE any app.* import ──────────────────────
    if env_file:
        _load_env_file(env_file)

    # ── Step 2: apply policy override via POLICY_PATH env var ──────────────
    # app/config.py reads POLICY_PATH at module import time, so this must be
    # set before uvicorn triggers the import.
    if policy is not None:
        if not policy.exists():
            typer.echo(f"Error: policy file not found: {policy}", err=True)
            raise typer.Exit(code=2)
        os.environ["POLICY_PATH"] = str(policy.resolve())

    # Deferred import keeps serve.py out of the CLI module-level graph
    # and makes main_run monkeypatchable in tests.
    import aegis.serve as _serve_mod

    app_import = _serve_mod.resolve_app_import()
    resolved_policy = _serve_mod.resolve_policy_path(policy)

    # ── Step 3: --json mode — describe config and exit without server ───────
    if json_output:
        payload = {
            "host": host,
            "port": port,
            "reload": reload,
            "log_level": log_level.lower(),
            "app_import": app_import,
            "policy_path_resolved": str(resolved_policy),
        }
        typer.echo(_json_mod.dumps(payload, indent=2))
        raise typer.Exit(code=0)

    # ── Step 4: start the server ────────────────────────────────────────────
    try:
        _serve_mod.main_run(
            host=host,
            port=port,
            reload=reload,
            log_level=log_level,
            app_import=app_import,
        )
    except Exception as exc:
        typer.echo(f"Fatal: server exited with error: {exc}", err=True)
        raise typer.Exit(code=2)

    raise typer.Exit(code=0)


@_app.command()
def simulate(
    input_text: Optional[str] = typer.Option(
        None,
        "--input",
        help="User text to simulate through the guard pipeline.",
        show_default=False,
    ),
    file: Optional[Path] = typer.Option(
        None,
        "--file",
        help=(
            "JSONL transcript to simulate.  Each line must be "
            '{"input":"..."} or {"role":"user","content":"..."}.'
        ),
        show_default=False,
    ),
    policy: Optional[Path] = typer.Option(
        None,
        "--policy",
        help="Override policy file path (default: resolves the same way as the runtime).",
        show_default=False,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON to stdout.",
    ),
    explain_output: bool = typer.Option(
        False,
        "--explain",
        help="Human-readable explanation (default when --json is not set).",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Include meta fields and per-guard details in output.",
    ),
    env_file: Optional[Path] = typer.Option(
        None,
        "--env-file",
        help="Load environment variables from a .env file before running.",
        show_default=False,
    ),
) -> None:
    """
    Simulate the inbound guard pipeline on a given input, producing a
    deterministic trace.  No network calls are made and no LLM is invoked.

    Exactly one of --input or --file is required.

    Exit codes: 0 = allow, 1 = warn/incident, 2 = block/fatal error.
    """
    if env_file:
        _load_env_file(env_file)

    if input_text is None and file is None:
        typer.echo("Error: provide --input TEXT or --file PATH", err=True)
        raise typer.Exit(code=2)

    from aegis.simulate import load_inputs, run_simulation
    from aegis.simulate import explain as _explain_sim

    try:
        inputs = load_inputs(input_text, file)
    except (ValueError, FileNotFoundError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2)

    try:
        result = run_simulation(inputs, policy, verbose)
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2)
    except Exception as exc:
        typer.echo(f"Fatal error during simulation: {exc}", err=True)
        raise typer.Exit(code=2)

    if json_output:
        typer.echo(_json_mod.dumps(result, indent=2))
    else:
        typer.echo(_explain_sim(result, verbose=verbose))

    raise typer.Exit(code=result["exit_code"])


def main() -> None:
    """Console-scripts entry point."""
    _app()
