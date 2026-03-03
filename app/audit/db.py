"""
Audit logging to a local SQLite database.

Every decision made by /v1/chat and /v1/tools/execute is written to the
`audit_events` table with a tamper-evident hash chain.

Schema migration
----------------
On startup, init_db() will:
  1. Create tables if absent (safe for fresh installs).
  2. Add `prev_hash` / `event_hash` columns to audit_events if they are
     missing (safe for existing databases — no data is removed).
  3. Backfill chain hashes for any rows that have an empty event_hash.

Atomic writes
-------------
log_event() uses BEGIN IMMEDIATE to serialize concurrent writes and ensure
the prev_hash → event_hash linkage is never broken by a race.
"""
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from app import config
from app.audit import chain as audit_chain
from app.audit.models import AuditEvent


# ── Connection factory ────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    """Open a new connection to the configured database."""
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    # WAL mode: readers don't block writers and vice-versa.
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# ── Schema helpers ────────────────────────────────────────────────────────────

def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def _create_base_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            id            TEXT    PRIMARY KEY,
            ts            TEXT    NOT NULL,
            endpoint      TEXT    NOT NULL,
            request_json  TEXT    NOT NULL,
            response_json TEXT    NOT NULL,
            decision      TEXT    NOT NULL,
            reason_codes  TEXT    NOT NULL,
            risk_score    INTEGER NOT NULL,
            prev_hash     TEXT    NOT NULL DEFAULT '',
            event_hash    TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ae_event_hash ON audit_events(event_hash)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ae_ts ON audit_events(ts)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS gateway_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            ts    TEXT NOT NULL
        )
        """
    )


def _migrate_chain_columns(conn: sqlite3.Connection) -> None:
    """Add prev_hash / event_hash to audit_events if they are absent."""
    if not _column_exists(conn, "audit_events", "prev_hash"):
        conn.execute(
            "ALTER TABLE audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''"
        )
    if not _column_exists(conn, "audit_events", "event_hash"):
        conn.execute(
            "ALTER TABLE audit_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT ''"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ae_event_hash ON audit_events(event_hash)"
        )


def _backfill_chain() -> None:
    """
    Assign hash-chain values to any existing rows whose event_hash is empty.

    This runs inside a single BEGIN IMMEDIATE transaction to prevent partial
    backfill if the process is interrupted. It is idempotent — safe to call
    on a database where backfill is already complete.
    """
    # Use a dedicated connection with autocommit so we control the transaction.
    conn = sqlite3.connect(str(config.DB_PATH), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        empty_count: int = conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE event_hash = ''"
        ).fetchone()[0]
        if empty_count == 0:
            return  # Nothing to do.

        # Fetch ALL rows in chronological order so we can re-thread the chain
        # correctly even in a partially-migrated database.
        all_rows = conn.execute(
            "SELECT rowid, id, ts, endpoint, request_json, response_json, "
            "decision, reason_codes, risk_score, prev_hash, event_hash "
            "FROM audit_events ORDER BY ts ASC, rowid ASC"
        ).fetchall()

        # Find the index of the first row with an empty hash.
        first_empty_idx: int = next(
            (i for i, r in enumerate(all_rows) if r["event_hash"] == ""), 0
        )

        # The chain tip just before the first empty row.
        running_hash: str = (
            all_rows[first_empty_idx - 1]["event_hash"]
            if first_empty_idx > 0
            else ""
        )

        conn.execute("BEGIN IMMEDIATE")
        for row in all_rows[first_empty_idx:]:
            if row["event_hash"] != "":
                # Row already has a valid hash — advance pointer, skip update.
                running_hash = row["event_hash"]
                continue

            fields = {
                "id": row["id"],
                "ts": row["ts"],
                "endpoint": row["endpoint"],
                "request_json": row["request_json"],
                "response_json": row["response_json"],
                "decision": row["decision"],
                "reason_codes": row["reason_codes"],
                "risk_score": row["risk_score"],
                "prev_hash": running_hash,
            }
            new_hash = audit_chain.compute_hash(
                running_hash, audit_chain.canonical_payload(fields)
            )
            conn.execute(
                "UPDATE audit_events SET prev_hash = ?, event_hash = ? WHERE id = ?",
                (running_hash, new_hash, row["id"]),
            )
            running_hash = new_hash
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


# ── Public init ───────────────────────────────────────────────────────────────

def init_db() -> None:
    """
    Idempotent startup routine:
      1. Create all tables that do not exist.
      2. Migrate audit_events to add chain columns if absent.
      3. Backfill chain hashes for any unchained rows.
    """
    with _connect() as conn:
        _create_base_tables(conn)
        _migrate_chain_columns(conn)
        conn.commit()
    _backfill_chain()


# ── Key-value state ───────────────────────────────────────────────────────────

def get_state(key: str) -> Optional[str]:
    """Return the persisted value for *key*, or None if absent."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT value FROM gateway_state WHERE key = ?", (key,)
        ).fetchone()
    return row["value"] if row else None


def set_state(key: str, value: str) -> None:
    """Upsert a key/value pair into gateway_state."""
    ts = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO gateway_state (key, value, ts) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, ts = excluded.ts
            """,
            (key, value, ts),
        )
        conn.commit()


# ── Audit event writing (atomic hash chain) ───────────────────────────────────

def log_event(
    endpoint: str,
    request_data: dict,
    response_data: dict,
    decision: str,
    reason_codes: List[str],
    risk_score: int,
) -> str:
    """
    Persist an audit event with a chained hash.

    The read-of-prev-hash and the insert are wrapped in BEGIN IMMEDIATE so
    no other writer can interleave, preserving chain integrity.

    Returns the newly created event UUID.
    """
    event_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()
    request_json = json.dumps(request_data)
    response_json = json.dumps(response_data)
    reason_codes_json = json.dumps(reason_codes)

    conn = sqlite3.connect(str(config.DB_PATH), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        conn.execute("BEGIN IMMEDIATE")

        # Read the chain tip.
        tip_row = conn.execute(
            "SELECT event_hash FROM audit_events "
            "ORDER BY ts DESC, rowid DESC LIMIT 1"
        ).fetchone()
        prev_hash: str = tip_row["event_hash"] if tip_row else ""

        # Canonical payload for hashing.
        payload_fields = {
            "id": event_id,
            "ts": ts,
            "endpoint": endpoint,
            "request_json": request_json,
            "response_json": response_json,
            "decision": decision,
            "reason_codes": reason_codes_json,
            "risk_score": risk_score,
            "prev_hash": prev_hash,
        }
        event_hash = audit_chain.compute_hash(
            prev_hash, audit_chain.canonical_payload(payload_fields)
        )

        conn.execute(
            """
            INSERT INTO audit_events
                (id, ts, endpoint, request_json, response_json,
                 decision, reason_codes, risk_score, prev_hash, event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id, ts, endpoint, request_json, response_json,
                decision, reason_codes_json, risk_score, prev_hash, event_hash,
            ),
        )
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()

    return event_id


# ── Audit event reading ───────────────────────────────────────────────────────

def _row_to_event(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        id=row["id"],
        ts=row["ts"],
        endpoint=row["endpoint"],
        request_json=row["request_json"],
        response_json=row["response_json"],
        decision=row["decision"],
        reason_codes=json.loads(row["reason_codes"]),
        risk_score=row["risk_score"],
        prev_hash=row["prev_hash"] if "prev_hash" in row.keys() else "",
        event_hash=row["event_hash"] if "event_hash" in row.keys() else "",
    )


def get_events(limit: int = 50) -> List[AuditEvent]:
    """Return the *limit* most-recent audit events, newest first."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_events ORDER BY ts DESC, rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row_to_event(r) for r in rows]


def get_events_in_window(since: datetime) -> List[AuditEvent]:
    """Return all audit events with ts >= *since*, oldest first."""
    since_iso = since.isoformat()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_events WHERE ts >= ? ORDER BY ts ASC, rowid ASC",
            (since_iso,),
        ).fetchall()
    return [_row_to_event(r) for r in rows]


def get_event_by_id(event_id: str) -> Optional[AuditEvent]:
    """Fetch a single audit event by UUID. Returns None if not found."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM audit_events WHERE id = ?", (event_id,)
        ).fetchone()
    return _row_to_event(row) if row is not None else None
