"""
Aegis serve — thin uvicorn wrapper for the Aegis-LLM gateway.

The actual ASGI entrypoint is ``app.main:app`` (the FastAPI application
defined in ``app/main.py``).  Policy configuration is handled by setting
the ``POLICY_PATH`` environment variable before uvicorn starts, which is
the mechanism ``app/config.py`` already supports.

Public API (pure functions — designed for testability)
------------------------------------------------------
  resolve_app_import() -> str
  resolve_policy_path(override) -> Path
  build_uvicorn_config(host, port, reload, log_level) -> dict
  main_run(host, port, reload, log_level, app_import) -> None
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

# ── ASGI entrypoint ───────────────────────────────────────────────────────────

# Determined by scanning the repo:
#   - app/main.py defines `app = FastAPI(...)` and `lifespan`
#   - pyproject.toml confirms entry point pattern
#   - conftest.py uses `from app.main import app as fastapi_app`
#   - README quickstart: `uvicorn app.main:app --reload`
_APP_IMPORT = "app.main:app"


def resolve_app_import() -> str:
    """Return the canonical ASGI app import string for this repository."""
    return _APP_IMPORT


# ── Policy path resolution ────────────────────────────────────────────────────

def resolve_policy_path(override: Optional[Path]) -> Path:
    """
    Resolve the policy file path using the same priority as the runtime:

    1. Explicit ``--policy`` argument (passed as *override*)
    2. ``POLICY_PATH`` environment variable
    3. Compiled default in ``app.config``

    This mirrors the resolution logic in ``app/config.py`` so that
    ``--json`` output shows exactly what the server will use.
    """
    if override is not None:
        return override.resolve()
    try:
        from app import config as _cfg  # deferred: respects env changes above
        return _cfg.POLICY_PATH
    except ImportError:
        return Path("policies/default.yaml")


# ── Uvicorn configuration ─────────────────────────────────────────────────────

def build_uvicorn_config(
    host: str,
    port: int,
    reload: bool,
    log_level: str,
) -> Dict[str, Any]:
    """
    Build the keyword-argument dict for ``uvicorn.run()`` (excluding the
    positional ``app`` argument).

    Returns a plain dict so callers can inspect it in tests without
    starting a real server.
    """
    return {
        "host": host,
        "port": port,
        "reload": reload,
        "log_level": log_level.lower(),
    }


# ── Server entry point ────────────────────────────────────────────────────────

def main_run(
    host: str,
    port: int,
    reload: bool,
    log_level: str,
    app_import: str = _APP_IMPORT,
) -> None:
    """
    Start the uvicorn server.

    ``uvicorn`` is imported lazily inside this function so that tests can
    monkeypatch ``aegis.serve.main_run`` (or ``uvicorn.run`` directly)
    without affecting the module-level import graph.
    """
    import uvicorn  # noqa: PLC0415

    cfg = build_uvicorn_config(host, port, reload, log_level)
    uvicorn.run(app_import, **cfg)
