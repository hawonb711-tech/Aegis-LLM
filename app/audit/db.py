"""
Audit logging to a local SQLite database.

Every decision made by /v1/chat and /v1/tools/execute is written to the
`audit_events` table.  The table is created on first use (init_db).
"""
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from app import config
from app.audit.models import AuditEvent


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they do not already exist."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id           TEXT    PRIMARY KEY,
                ts           TEXT    NOT NULL,
                endpoint     TEXT    NOT NULL,
                request_json TEXT    NOT NULL,
                response_json TEXT   NOT NULL,
                decision     TEXT    NOT NULL,
                reason_codes TEXT    NOT NULL,
                risk_score   INTEGER NOT NULL
            )
            """
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
        conn.commit()


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


def log_event(
    endpoint: str,
    request_data: dict,
    response_data: dict,
    decision: str,
    reason_codes: List[str],
    risk_score: int,
) -> str:
    """
    Persist an audit event.  Returns the newly created event UUID.
    """
    event_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_events
                (id, ts, endpoint, request_json, response_json, decision, reason_codes, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                ts,
                endpoint,
                json.dumps(request_data),
                json.dumps(response_data),
                decision,
                json.dumps(reason_codes),
                risk_score,
            ),
        )
        conn.commit()

    return event_id


def get_events(limit: int = 50) -> List[AuditEvent]:
    """Return the *limit* most-recent audit events, newest first."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_events ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()

    return [
        AuditEvent(
            id=row["id"],
            ts=row["ts"],
            endpoint=row["endpoint"],
            request_json=row["request_json"],
            response_json=row["response_json"],
            decision=row["decision"],
            reason_codes=json.loads(row["reason_codes"]),
            risk_score=row["risk_score"],
        )
        for row in rows
    ]


def get_event_by_id(event_id: str) -> Optional[AuditEvent]:
    """Fetch a single audit event by UUID.  Returns None if not found."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM audit_events WHERE id = ?", (event_id,)
        ).fetchone()

    if row is None:
        return None

    return AuditEvent(
        id=row["id"],
        ts=row["ts"],
        endpoint=row["endpoint"],
        request_json=row["request_json"],
        response_json=row["response_json"],
        decision=row["decision"],
        reason_codes=json.loads(row["reason_codes"]),
        risk_score=row["risk_score"],
    )
