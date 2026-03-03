"""
API key storage and management.

Security model
--------------
- Raw API keys are NEVER stored in the database.  Only SHA-256(key) is stored.
- A key is generated as: "aegis_" + base64url(32 random bytes), no padding.
- The plaintext key is returned ONCE at creation time and never again.
- key_hash is indexed UNIQUE to guarantee no collision goes undetected.

Scopes
------
  user   — may call /v1/* endpoints
  admin  — may call /admin/* endpoints (implies user capabilities)

Bootstrap
---------
On startup, bootstrap_admin_key() checks whether AEGIS_ADMIN_KEY is set.
If it is, and no admin key with that hash exists, it inserts one.
This allows a zero-API-call first-run setup via environment variable.

Security disclaimer
-------------------
API keys grant full access within their scope.  Protect them as you would
passwords.  Use rotate_key() to replace a compromised key.  Keys are
transmitted over TLS only — ensure the gateway is never served over plain HTTP.
"""
import base64
import hashlib
import json
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app import config


# ── Connection helper ─────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# ── Schema ────────────────────────────────────────────────────────────────────

def init_auth_db() -> None:
    """Create authentication tables. Idempotent."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id         TEXT PRIMARY KEY,
                key_hash   TEXT NOT NULL UNIQUE,
                name       TEXT NOT NULL,
                scopes     TEXT NOT NULL,
                is_active  INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_used  TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ak_hash ON api_keys(key_hash)"
        )
        conn.commit()


# ── Key generation ────────────────────────────────────────────────────────────

def generate_key() -> str:
    """
    Generate a cryptographically random API key.
    Format: aegis_<base64url(32 bytes)>  (no padding, 49 total chars)
    """
    raw = secrets.token_bytes(32)
    suffix = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"aegis_{suffix}"


def hash_key(raw_key: str) -> str:
    """Return SHA-256(raw_key) as a lowercase hex string."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


# ── CRUD ──────────────────────────────────────────────────────────────────────

def create_key(name: str, scopes: List[str]) -> Tuple[str, str]:
    """
    Create a new API key.

    Returns (plaintext_key, key_id).
    The plaintext key is the ONLY time it is available; store it securely.
    """
    raw = generate_key()
    key_id = str(uuid.uuid4())
    key_hash = hash_key(raw)
    now = datetime.now(timezone.utc).isoformat()

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO api_keys (id, key_hash, name, scopes, is_active, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (key_id, key_hash, name, json.dumps(scopes), now),
        )
        conn.commit()

    return raw, key_id


def lookup_key(raw_key: str) -> Optional[Dict[str, Any]]:
    """
    Look up a key by its plaintext value.  Returns a dict of key metadata,
    or None if the key is not found.

    The caller must check is_active before granting access.
    """
    kh = hash_key(raw_key)
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, name, scopes, is_active, created_at, last_used "
            "FROM api_keys WHERE key_hash = ?",
            (kh,),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "name": row["name"],
        "scopes": json.loads(row["scopes"]),
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
        "last_used": row["last_used"],
    }


def update_last_used(key_id: str) -> None:
    """Record the current timestamp as last_used for the given key_id."""
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute(
            "UPDATE api_keys SET last_used = ? WHERE id = ?",
            (now, key_id),
        )
        conn.commit()


def list_keys() -> List[Dict[str, Any]]:
    """
    Return all keys (active and inactive) without revealing key_hash.
    """
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, name, scopes, is_active, created_at, last_used "
            "FROM api_keys ORDER BY created_at ASC"
        ).fetchall()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "scopes": json.loads(row["scopes"]),
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
            "last_used": row["last_used"],
        }
        for row in rows
    ]


def rotate_key(key_id: str) -> Tuple[str, str]:
    """
    Generate a new secret for an existing key record, invalidating the old one.

    Returns (new_plaintext_key, key_id).
    The old key is immediately invalidated upon commit.
    """
    raw = generate_key()
    new_hash = hash_key(raw)
    now = datetime.now(timezone.utc).isoformat()

    with _connect() as conn:
        updated = conn.execute(
            "UPDATE api_keys SET key_hash = ?, created_at = ?, last_used = NULL "
            "WHERE id = ?",
            (new_hash, now, key_id),
        ).rowcount
        conn.commit()

    if updated == 0:
        raise ValueError(f"Key {key_id!r} not found")
    return raw, key_id


def disable_key(key_id: str) -> None:
    """Mark a key as inactive. Inactive keys return HTTP 403."""
    with _connect() as conn:
        updated = conn.execute(
            "UPDATE api_keys SET is_active = 0 WHERE id = ?", (key_id,)
        ).rowcount
        conn.commit()
    if updated == 0:
        raise ValueError(f"Key {key_id!r} not found")


def _has_admin_key() -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM api_keys "
            "WHERE is_active = 1 AND scopes LIKE '%admin%'"
        ).fetchone()
    return row[0] > 0


def bootstrap_admin_key() -> Optional[str]:
    """
    If AEGIS_ADMIN_KEY is set and no admin key with that hash exists,
    insert it as an admin key.

    Returns the key_id of the bootstrapped key, or None if nothing was done.
    The raw key value comes from the environment — it is never generated here.
    """
    raw = config.AEGIS_ADMIN_KEY
    if not raw:
        return None

    kh = hash_key(raw)
    with _connect() as conn:
        existing = conn.execute(
            "SELECT id FROM api_keys WHERE key_hash = ?", (kh,)
        ).fetchone()
        if existing:
            return existing["id"]  # Already inserted.

    _, key_id = _insert_with_known_hash(kh, "bootstrap-admin", ["admin", "user"])
    return key_id


def _insert_with_known_hash(
    key_hash: str, name: str, scopes: List[str]
) -> Tuple[str, str]:
    """Insert a key record with a pre-computed hash. Used by bootstrap only."""
    key_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO api_keys (id, key_hash, name, scopes, is_active, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (key_id, key_hash, name, json.dumps(scopes), now),
        )
        conn.commit()
    return key_hash, key_id
