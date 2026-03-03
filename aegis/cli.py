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


def main() -> None:
    """Console-scripts entry point."""
    _app()
