"""
Aegis run_env — pure helpers for the ``aegis run`` command.

Responsibilities
----------------
- Build the gateway base URL from host/port/path.
- Decide which env vars to inject and emit warnings when existing vars
  would be overwritten (they are not overwritten — existing values win).
- Format POSIX export lines and JSON output without leaking secrets.
- Execute a subprocess with the merged environment.

Public API
----------
  normalize_base_path(base_path: str) -> str
  build_base_url(host: str, port: int, base_path: str) -> str
  build_injected_env(host, port, base_path, existing_env) -> (dict, list[str])
  format_exports(injected: dict) -> str
  to_json_dict(cmd_argv, injected, warnings) -> dict
  run_command(cmd_argv, merged_env) -> int
"""
from __future__ import annotations

import subprocess
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

# Env vars that route OpenAI-compatible SDK calls to the gateway.
_INJECT_VARS = ("OPENAI_BASE_URL", "OPENAI_API_BASE")


# ── URL helpers ───────────────────────────────────────────────────────────────

def normalize_base_path(base_path: str) -> str:
    """
    Normalise *base_path* to have exactly one leading slash and no trailing
    slash.  An empty or slash-only value normalises to the empty string.

    Examples::

        normalize_base_path("/v1")   -> "/v1"
        normalize_base_path("v1")    -> "/v1"
        normalize_base_path("/v1/")  -> "/v1"
        normalize_base_path("")      -> ""
        normalize_base_path("/")     -> ""
    """
    stripped = base_path.strip("/")
    return f"/{stripped}" if stripped else ""


def build_base_url(host: str, port: int, base_path: str) -> str:
    """
    Construct the HTTP base URL for the gateway.

    The result never contains a double slash between host:port and path.

    Examples::

        build_base_url("127.0.0.1", 8088, "/v1")  -> "http://127.0.0.1:8088/v1"
        build_base_url("127.0.0.1", 8088, "v1")   -> "http://127.0.0.1:8088/v1"
        build_base_url("127.0.0.1", 8088, "")     -> "http://127.0.0.1:8088"
    """
    path = normalize_base_path(base_path)
    return f"http://{host}:{port}{path}"


# ── Env injection ─────────────────────────────────────────────────────────────

def build_injected_env(
    host: str,
    port: int,
    base_path: str,
    existing_env: Mapping[str, str],
) -> Tuple[Dict[str, str], List[str]]:
    """
    Decide which vars to inject and collect warnings for conflicts.

    Rules
    -----
    - For each var in ``_INJECT_VARS``:
      - If the var is **not** in *existing_env*: add ``var=base_url`` to
        the injected dict.
      - If the var **is** already in *existing_env*: do not overwrite;
        record a warning.  The warning mentions only the var name, never
        the existing value.
    - All other env vars in *existing_env* are left untouched (the caller
      merges ``existing_env`` with the returned dict before subprocess exec).

    Returns
    -------
    (injected, warnings)
      injected  — vars to add (never contains secrets)
      warnings  — human-readable strings, one per conflict
    """
    base_url = build_base_url(host, port, base_path)
    injected: Dict[str, str] = {}
    warnings: List[str] = []

    for var in _INJECT_VARS:
        if var in existing_env:
            warnings.append(
                f"{var} is already set in the environment; "
                "existing value preserved — unset it to let aegis run inject its value"
            )
        else:
            injected[var] = base_url

    return injected, warnings


# ── Output helpers ────────────────────────────────────────────────────────────

def format_exports(injected: Dict[str, str]) -> str:
    """
    Return POSIX ``export KEY='VALUE'`` lines for the injected vars.

    Only the injected (non-secret) vars are included.  Secret vars such as
    ``OPENAI_API_KEY`` are never part of *injected* and therefore never
    appear in the output.

    Single quotes are used so values are treated literally by shells.
    Any embedded single quote in a value is escaped as ``'\\''``.
    """
    lines: List[str] = []
    for key, value in injected.items():
        safe_val = value.replace("'", "'\\''")
        lines.append(f"export {key}='{safe_val}'")
    return "\n".join(lines)


def to_json_dict(
    cmd_argv: Sequence[str],
    injected: Dict[str, str],
    warnings: List[str],
) -> Dict[str, Any]:
    """
    Build the JSON-serialisable dict for ``--json`` mode.

    Only *injected* env vars are included (non-secret).  The full parent
    environment is never serialised.
    """
    return {
        "command": list(cmd_argv),
        "injected_env": dict(injected),
        "warnings": list(warnings),
    }


# ── Subprocess execution ──────────────────────────────────────────────────────

def run_command(
    cmd_argv: Sequence[str],
    merged_env: Mapping[str, str],
) -> int:
    """
    Execute *cmd_argv* in a subprocess, inheriting stdio, with *merged_env*
    as the complete environment.

    ``shell=False`` is used throughout to avoid shell-injection risks.

    Returns the child process exit code.
    Raises ``FileNotFoundError`` if the executable is not found.
    """
    result = subprocess.run(list(cmd_argv), env=dict(merged_env))
    return result.returncode
