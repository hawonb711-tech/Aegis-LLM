"""
Aegis Doctor — runtime environment diagnostic checks.

Each public ``check_*`` function returns a :class:`Check` dataclass and is
safe to call independently (useful for testing).  ``run_all_checks()``
composes them in canonical order.

Design constraints
------------------
- Non-destructive: never writes to the database or modifies files.
- Non-leaking: secret values are never included in ``message`` or ``meta``;
  only presence and the last two characters are surfaced.
- Fast: the full suite completes in <1 s on a healthy installation.
- Resilient: each check catches its own exceptions so a broken check never
  prevents subsequent checks from running.
- Reuse: policy path and schema validation delegate to ``app.policy`` /
  ``app.config``; logic is not re-implemented here.
"""
from __future__ import annotations

import importlib
import os
import sqlite3
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ── Result types ──────────────────────────────────────────────────────────────

class Status(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


ICONS: Dict[Status, str] = {
    Status.PASS: "✅",
    Status.WARN: "⚠️ ",
    Status.FAIL: "❌",
}

SECTIONS = ["ENV", "POLICY", "DATABASE", "IMPORT"]


@dataclass
class Check:
    id: str
    section: str
    status: Status
    message: str
    fix: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _pass(id: str, section: str, msg: str, **meta: Any) -> Check:
    return Check(id=id, section=section, status=Status.PASS, message=msg, meta=dict(meta))


def _warn(id: str, section: str, msg: str, fix: Optional[str] = None, **meta: Any) -> Check:
    return Check(id=id, section=section, status=Status.WARN, message=msg, fix=fix, meta=dict(meta))


def _fail(id: str, section: str, msg: str, fix: Optional[str] = None, **meta: Any) -> Check:
    return Check(id=id, section=section, status=Status.FAIL, message=msg, fix=fix, meta=dict(meta))


def _redact(val: str) -> str:
    """Return a safe representation: never shows more than the last 2 chars."""
    if not val:
        return "(not set)"
    if len(val) <= 4:
        return "***"
    return f"***{val[-2:]}"


def _resolve_policy_path(override: Optional[Path]) -> Tuple[Path, str]:
    """
    Resolve the policy path the same way the runtime does.

    Priority: CLI ``--policy`` flag → POLICY_PATH env → compiled default in config.
    Falls back gracefully if ``app`` is not yet importable.
    """
    if override is not None:
        return override, "--policy flag"
    try:
        from app import config as _cfg  # deferred: honours any env changes made before this call
        source = "POLICY_PATH env" if os.environ.get("POLICY_PATH") else "default"
        return _cfg.POLICY_PATH, source
    except ImportError:
        fallback = Path("policies/default.yaml")
        return fallback, "fallback default (app not importable)"


def _get_db_path() -> Path:
    try:
        from app import config as _cfg
        return _cfg.DB_PATH
    except ImportError:
        return Path("audit.db")


# ── ENV checks ────────────────────────────────────────────────────────────────

def check_python_version() -> Check:
    vi = sys.version_info
    ver = f"{vi.major}.{vi.minor}.{vi.micro}"
    plat = sys.platform
    if vi < (3, 11):
        return _fail(
            "python-version", "ENV",
            f"Python {ver} on {plat} — requires >= 3.11",
            fix="Install Python 3.11+: https://www.python.org/downloads/",
            version=ver, platform=plat,
        )
    return _pass("python-version", "ENV", f"Python {ver} on {plat}", version=ver, platform=plat)


def check_filesystem_encoding() -> Check:
    enc = sys.getfilesystemencoding() or "unknown"
    normalised = enc.lower().replace("-", "").replace("_", "")
    if normalised not in ("utf8",):
        return _warn(
            "filesystem-enc", "ENV",
            f"Filesystem encoding is {enc!r} — non-UTF-8 locales cause UnicodeDecodeError "
            "when opening policy files without explicit encoding",
            fix="export LANG=C.UTF-8  # restart your shell after setting",
            encoding=enc,
        )
    return _pass("filesystem-enc", "ENV", f"UTF-8 ({enc})", encoding=enc)


def check_locale() -> Check:
    lang = os.environ.get("LANG", "")
    lc_all = os.environ.get("LC_ALL", "")
    lc_ctype = os.environ.get("LC_CTYPE", "")
    effective = lc_all or lang or lc_ctype
    # Known ASCII-only locales that will break UTF-8 file reads on some platforms.
    if effective.upper() in ("C", "POSIX") or effective.lower() in ("c", "posix"):
        return _warn(
            "locale", "ENV",
            f"Locale {effective!r} implies ASCII — policy files containing non-ASCII "
            "characters (e.g. en-dash in comments) may fail to load",
            fix="export LANG=C.UTF-8",
            LANG=lang, LC_ALL=lc_all,
        )
    if not effective:
        return _warn(
            "locale", "ENV",
            "No LANG/LC_ALL/LC_CTYPE set — system default locale may be ASCII on some platforms",
            fix="export LANG=C.UTF-8",
            LANG=lang, LC_ALL=lc_all,
        )
    return _pass("locale", "ENV", f"Locale: {effective!r}", LANG=lang, LC_ALL=lc_all)


def check_auth_enabled() -> Check:
    raw = os.environ.get("AUTH_ENABLED", "true")
    enabled = raw.lower() not in ("0", "false", "no")
    if not enabled:
        return _warn(
            "auth-enabled", "ENV",
            f"AUTH_ENABLED={raw!r} — authentication is disabled; "
            "never deploy in this state",
            fix="export AUTH_ENABLED=true",
            value=raw,
        )
    return _pass("auth-enabled", "ENV", "AUTH_ENABLED=true", value=raw)


def check_aegis_admin_key() -> Check:
    val = os.environ.get("AEGIS_ADMIN_KEY", "")
    if not val:
        gen_cmd = (
            "python3 -c \""
            "import secrets,base64; "
            "print('aegis_'+base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))"
            "\""
        )
        return _warn(
            "aegis-admin-key", "ENV",
            "AEGIS_ADMIN_KEY not set — no admin key will be bootstrapped on first startup",
            fix=f"export AEGIS_ADMIN_KEY=$({gen_cmd})",
            set=False,
        )
    return _pass(
        "aegis-admin-key", "ENV",
        f"AEGIS_ADMIN_KEY set ({_redact(val)})",
        set=True,
    )


def check_mock_mode() -> Check:
    mock_raw = os.environ.get("MOCK_MODE", "true")
    is_mock = mock_raw.lower() in ("1", "true", "yes")
    if not is_mock:
        api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
        endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
        missing = [k for k, v in [
            ("AZURE_OPENAI_API_KEY", api_key),
            ("AZURE_OPENAI_ENDPOINT", endpoint),
        ] if not v]
        if missing:
            return _warn(
                "mock-mode", "ENV",
                f"MOCK_MODE=false but {', '.join(missing)} not set — provider calls will fail",
                fix=f"export {missing[0]}=<value>",
                MOCK_MODE=mock_raw, missing=missing,
            )
        return _pass(
            "mock-mode", "ENV",
            f"MOCK_MODE=false, Azure credentials present ({_redact(api_key)})",
            MOCK_MODE=mock_raw,
        )
    return _pass("mock-mode", "ENV", "MOCK_MODE=true (no real API calls)", MOCK_MODE=mock_raw)


def check_rate_limit() -> Check:
    raw = os.environ.get("RATE_LIMIT_RPM", "60")
    try:
        val = int(raw)
    except ValueError:
        return _fail(
            "rate-limit", "ENV",
            f"RATE_LIMIT_RPM={raw!r} is not a valid integer",
            fix="export RATE_LIMIT_RPM=60",
            raw=raw,
        )
    if val <= 0:
        return _warn(
            "rate-limit", "ENV",
            f"RATE_LIMIT_RPM={val} — rate limiting effectively disabled",
            fix="export RATE_LIMIT_RPM=60",
            value=val,
        )
    return _pass("rate-limit", "ENV", f"RATE_LIMIT_RPM={val}", value=val)


def run_env_checks() -> List[Check]:
    return [
        check_python_version(),
        check_filesystem_encoding(),
        check_locale(),
        check_auth_enabled(),
        check_aegis_admin_key(),
        check_mock_mode(),
        check_rate_limit(),
    ]


# ── POLICY checks ─────────────────────────────────────────────────────────────

def check_policy_path(override: Optional[Path] = None) -> Check:
    path, source = _resolve_policy_path(override)
    return _pass(
        "policy-path", "POLICY",
        f"{path}  (via {source})",
        path=str(path), source=source,
    )


def check_policy_exists(override: Optional[Path] = None) -> Check:
    path, _ = _resolve_policy_path(override)
    if not path.exists():
        return _fail(
            "policy-exists", "POLICY",
            f"Policy file not found: {path}",
            fix=f"Create {path} or set POLICY_PATH to an existing file",
            path=str(path),
        )
    if not path.is_file():
        return _fail(
            "policy-exists", "POLICY",
            f"{path} exists but is not a regular file",
            path=str(path),
        )
    return _pass("policy-exists", "POLICY", "File exists", path=str(path))


def check_policy_utf8(override: Optional[Path] = None) -> Check:
    """
    Verify the policy file can be read as UTF-8.

    This catches the known regression where ``open(path)`` without an explicit
    encoding raises ``UnicodeDecodeError`` on non-UTF-8 locales when the file
    contains multibyte characters (e.g. an en-dash in a YAML comment).
    """
    path, _ = _resolve_policy_path(override)
    if not path.exists():
        return _fail(
            "policy-utf8", "POLICY",
            f"Cannot check encoding — file not found: {path}",
            path=str(path),
        )
    try:
        with open(path, encoding="utf-8") as fh:
            fh.read()
        return _pass("policy-utf8", "POLICY", "File is valid UTF-8", path=str(path))
    except UnicodeDecodeError as e:
        return _fail(
            "policy-utf8", "POLICY",
            f"File is not valid UTF-8 at byte {e.start}: {e.reason}",
            fix=(
                f"Re-save {path.name} as UTF-8. "
                "Common culprit: non-ASCII characters in YAML comments "
                "(e.g. en-dash \u2013 U+2013). Replace with ASCII hyphens."
            ),
            path=str(path), byte_offset=e.start,
        )
    except OSError as e:
        return _fail(
            "policy-utf8", "POLICY",
            f"Cannot read file: {e}",
            path=str(path),
        )


def check_policy_yaml(override: Optional[Path] = None) -> Check:
    import yaml  # pyyaml — always available (listed in project deps)
    path, _ = _resolve_policy_path(override)
    if not path.exists():
        return _fail(
            "policy-yaml", "POLICY",
            f"Cannot parse YAML — file not found: {path}",
            path=str(path),
        )
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        if not isinstance(raw, dict):
            return _fail(
                "policy-yaml", "POLICY",
                "YAML parsed but top-level value is not a mapping",
                fix="Ensure the policy file has a top-level dict structure",
                path=str(path),
            )
        return _pass(
            "policy-yaml", "POLICY",
            f"YAML parsed successfully — top-level keys: {sorted(raw.keys())}",
            keys=sorted(raw.keys()),
        )
    except yaml.YAMLError as e:
        return _fail(
            "policy-yaml", "POLICY",
            f"YAML parse error: {e}",
            fix=f"Fix YAML syntax in {path}",
            path=str(path),
        )


def check_policy_schema(override: Optional[Path] = None) -> Check:
    """
    Validate the policy YAML against the Pydantic schema defined in app.policy.

    Reuses the existing Policy model directly — no logic is duplicated here.
    The module-level ``_policy`` singleton in app.policy is NOT modified;
    we instantiate a throw-away Policy object for validation only.
    """
    import yaml
    path, _ = _resolve_policy_path(override)
    if not path.exists():
        return _fail(
            "policy-schema", "POLICY",
            f"Cannot validate schema — file not found: {path}",
        )
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        if not isinstance(raw, dict):
            return _fail("policy-schema", "POLICY", "Top-level YAML is not a mapping")
        from app.policy import Policy  # reuse existing model
        from pydantic import ValidationError
        try:
            Policy(**raw)
        except ValidationError as e:
            errors = e.errors()
            first = errors[0]
            loc = ".".join(str(x) for x in first["loc"])
            return _fail(
                "policy-schema", "POLICY",
                f"Schema error at {loc!r}: {first['msg']}",
                fix=f"Check the {loc!r} field in {path.name}",
                path=str(path), error_count=len(errors),
            )
        return _pass("policy-schema", "POLICY", "Pydantic schema valid", path=str(path))
    except ImportError as e:
        return _warn(
            "policy-schema", "POLICY",
            f"Cannot import app.policy for schema check: {e}",
            fix="Ensure app package is installed: pip install -e .",
        )
    except Exception as e:
        return _fail(
            "policy-schema", "POLICY",
            f"{type(e).__name__}: {e}",
            path=str(path),
        )


def check_semantic_config(override: Optional[Path] = None) -> Check:
    """Check semantic injection config is sane when the feature is enabled."""
    import yaml
    path, _ = _resolve_policy_path(override)
    if not path.exists():
        return _fail(
            "semantic-cfg", "POLICY",
            f"Cannot check semantic config — file not found: {path}",
        )
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        if not isinstance(raw, dict):
            return _fail("semantic-cfg", "POLICY", "Cannot parse policy YAML")
        inj = raw.get("injection", {})
        enabled = bool(inj.get("semantic_enabled", False))
        if not enabled:
            return _pass(
                "semantic-cfg", "POLICY",
                "semantic_enabled=false (disabled — threshold check skipped)",
                enabled=False,
            )
        threshold = inj.get("semantic_threshold", 80)
        try:
            tval = int(threshold)
        except (TypeError, ValueError):
            return _fail(
                "semantic-cfg", "POLICY",
                f"semantic_threshold={threshold!r} is not an integer",
                fix="Set semantic_threshold to an integer in [0, 100]",
            )
        if not (0 <= tval <= 100):
            return _fail(
                "semantic-cfg", "POLICY",
                f"semantic_threshold={tval} is outside the valid range [0, 100]",
                fix="Set semantic_threshold to a value between 0 and 100",
                threshold=tval,
            )
        return _pass(
            "semantic-cfg", "POLICY",
            f"semantic_enabled=true, semantic_threshold={tval} (valid)",
            enabled=True, threshold=tval,
        )
    except Exception as e:
        return _fail("semantic-cfg", "POLICY", f"{type(e).__name__}: {e}")


def run_policy_checks(override: Optional[Path] = None) -> List[Check]:
    return [
        check_policy_path(override),
        check_policy_exists(override),
        check_policy_utf8(override),
        check_policy_yaml(override),
        check_policy_schema(override),
        check_semantic_config(override),
    ]


# ── DATABASE checks ───────────────────────────────────────────────────────────

def check_db_dir_writable() -> Check:
    db = _get_db_path()
    parent = db.parent
    if not parent.exists():
        return _fail(
            "db-dir-exists", "DATABASE",
            f"DB parent directory does not exist: {parent}",
            fix=f"mkdir -p {parent}",
            path=str(db),
        )
    if not os.access(str(parent), os.W_OK):
        return _fail(
            "db-dir-writable", "DATABASE",
            f"DB parent directory is not writable: {parent}",
            fix=f"chmod u+w {parent}",
            path=str(db),
        )
    return _pass(
        "db-dir-writable", "DATABASE",
        f"Parent dir {parent} is writable",
        path=str(db),
    )


def check_db_connect() -> Check:
    db = _get_db_path()
    if not db.exists():
        parent = db.parent
        if parent.exists() and os.access(str(parent), os.W_OK):
            return _pass(
                "db-connect", "DATABASE",
                "DB file not yet created — will be initialised on first server startup",
                path=str(db), exists=False,
            )
        return _warn(
            "db-connect", "DATABASE",
            f"DB file does not exist and parent dir is not writable: {parent}",
            fix=f"mkdir -p {parent}",
            path=str(db),
        )
    try:
        conn = sqlite3.connect(str(db))
        conn.execute("SELECT 1")
        conn.close()
        return _pass("db-connect", "DATABASE", "SQLite connection OK (SELECT 1)", path=str(db))
    except Exception as e:
        return _fail(
            "db-connect", "DATABASE",
            f"Cannot connect to SQLite DB: {e}",
            fix=f"Check that {db} is a valid SQLite file (not corrupted or locked)",
            path=str(db),
        )


def check_db_schema() -> Check:
    db = _get_db_path()
    if not db.exists():
        return _warn(
            "db-schema", "DATABASE",
            "DB file not yet created — run the server once to initialise schema",
            fix="uvicorn app.main:app  # startup calls init_db()",
            path=str(db),
        )
    try:
        conn = sqlite3.connect(str(db))
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        conn.close()
        existing = {r[0] for r in rows}
        required = {"audit_events", "gateway_state"}
        missing = required - existing
        if missing:
            return _warn(
                "db-schema", "DATABASE",
                f"Tables not yet created: {sorted(missing)} "
                "— run the server to initialise",
                fix="uvicorn app.main:app  # startup runs init_db()",
                tables=sorted(existing), missing=sorted(missing),
            )
        return _pass(
            "db-schema", "DATABASE",
            f"Required tables present: {sorted(required)}",
            tables=sorted(existing),
        )
    except Exception as e:
        return _fail(
            "db-schema", "DATABASE",
            f"Cannot inspect DB schema: {e}",
            path=str(db),
        )


def run_db_checks() -> List[Check]:
    return [
        check_db_dir_writable(),
        check_db_connect(),
        check_db_schema(),
    ]


# ── IMPORT checks ─────────────────────────────────────────────────────────────

def _do_import(name: str) -> Any:
    """
    Thin wrapper around ``importlib.import_module`` — extracted so that tests
    can monkeypatch it to simulate import failures without touching sys.modules.
    """
    return importlib.import_module(name)


def check_import_app_main() -> Check:
    """
    Verify that ``app.main`` can be imported without raising.

    This catches the known regression where a non-UTF-8 locale causes
    ``UnicodeDecodeError`` when the policy YAML file is opened without an
    explicit encoding argument.
    """
    try:
        mod = _do_import("app.main")
        if mod is None:
            return _fail(
                "import-app", "IMPORT",
                "app.main resolved to None — import system is in a broken state",
                fix="pip install -e .  # then check for circular imports",
            )
        return _pass("import-app", "IMPORT", "app.main imported without errors")
    except UnicodeDecodeError as e:
        return _fail(
            "import-app", "IMPORT",
            f"UnicodeDecodeError: {e.reason} at byte {e.start}",
            fix=(
                "Likely cause: a source file is opened without explicit encoding "
                "on a non-UTF-8 locale. "
                "Fix: use open(..., encoding='utf-8') everywhere. "
                "Or set: export LANG=C.UTF-8"
            ),
            exception="UnicodeDecodeError", byte=e.start,
        )
    except ImportError as e:
        return _fail(
            "import-app", "IMPORT",
            f"ImportError: {e}",
            fix="Ensure all dependencies are installed: pip install -e '.[dev]'",
            exception="ImportError",
        )
    except Exception as e:
        return _fail(
            "import-app", "IMPORT",
            f"{type(e).__name__}: {e}",
            fix="Check application startup logs for details",
            exception=type(e).__name__,
        )


def run_import_checks() -> List[Check]:
    return [check_import_app_main()]


# ── Aggregation and serialisation ─────────────────────────────────────────────

def run_all_checks(policy_override: Optional[Path] = None) -> List[Check]:
    """Run all checks in canonical section order and return the full list."""
    results: List[Check] = []
    results.extend(run_env_checks())
    results.extend(run_policy_checks(policy_override))
    results.extend(run_db_checks())
    results.extend(run_import_checks())
    return results


def overall_status(checks: List[Check]) -> Status:
    if any(c.status == Status.FAIL for c in checks):
        return Status.FAIL
    if any(c.status == Status.WARN for c in checks):
        return Status.WARN
    return Status.PASS


def exit_code(checks: List[Check]) -> int:
    """Map overall status to exit code: 0=OK, 1=warn, 2=fail."""
    s = overall_status(checks)
    return {Status.FAIL: 2, Status.WARN: 1, Status.PASS: 0}[s]


def to_json_dict(checks: List[Check], code: int) -> Dict[str, Any]:
    """
    Serialise check results into a JSON-compatible dict.

    Schema
    ------
    {
      "version": str,
      "status": "pass" | "warn" | "fail",
      "checks": [{id, section, status, message, fix, meta}, ...],
      "summary": {pass, warn, fail, total},
      "exit_code": int
    }
    """
    from aegis import __version__
    s = overall_status(checks)
    return {
        "version": __version__,
        "status": s.value,
        "checks": [
            {
                "id": c.id,
                "section": c.section,
                "status": c.status.value,
                "message": c.message,
                "fix": c.fix,
                "meta": c.meta,
            }
            for c in checks
        ],
        "summary": {
            "pass": sum(1 for c in checks if c.status == Status.PASS),
            "warn": sum(1 for c in checks if c.status == Status.WARN),
            "fail": sum(1 for c in checks if c.status == Status.FAIL),
            "total": len(checks),
        },
        "exit_code": code,
    }
