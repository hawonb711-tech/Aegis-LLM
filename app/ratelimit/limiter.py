"""
Per-API-key fixed-window rate limiter backed by SQLite.

Algorithm
---------
  window_key = (key_id, floor(utc_time, 1 minute))
  On each request:
    1. BEGIN IMMEDIATE  (acquire write lock before any read)
    2. INSERT ... ON CONFLICT DO UPDATE SET count = count + 1
    3. SELECT current count
    4. COMMIT
    5. If count > limit -> 429

Using BEGIN IMMEDIATE ensures the read-modify-write is atomic even when
multiple async tasks hit the same window simultaneously (single uvicorn
worker with asyncio; extend to EXCLUSIVE for multi-process deployments).

The Retry-After header is always 60 seconds (end of the current window at
worst).  Old windows are not pruned automatically; a maintenance job or
startup routine can DELETE WHERE window_start < (now - 2 minutes).
"""
import sqlite3
from datetime import datetime, timezone
from typing import Tuple

from app import config


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(config.DB_PATH), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _current_window() -> str:
    """Return an ISO-8601 string truncated to the current UTC minute."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M+00:00")


def init_ratelimit_db() -> None:
    """Create rate_limit_counters table if absent. Idempotent."""
    with sqlite3.connect(str(config.DB_PATH)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rate_limit_counters (
                key_id       TEXT NOT NULL,
                window_start TEXT NOT NULL,
                count        INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (key_id, window_start)
            )
            """
        )
        conn.commit()


def check_and_increment(key_id: str, limit: int) -> Tuple[bool, int, int, int]:
    """
    Atomically increment the counter for *key_id* in the current window,
    then check whether the result exceeds *limit*.

    Returns (allowed, current_count, limit, retry_after_seconds).
      allowed         — False means the caller should return HTTP 429.
      current_count   — value after this increment.
      limit           — the configured per-minute limit.
      retry_after     — seconds until the current window resets (always <= 60).
    """
    window = _current_window()
    retry_after = 60  # Conservative: client should wait for the next window.

    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            INSERT INTO rate_limit_counters (key_id, window_start, count)
            VALUES (?, ?, 1)
            ON CONFLICT(key_id, window_start)
            DO UPDATE SET count = count + 1
            """,
            (key_id, window),
        )
        row = conn.execute(
            "SELECT count FROM rate_limit_counters "
            "WHERE key_id = ? AND window_start = ?",
            (key_id, window),
        ).fetchone()
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()

    count: int = row["count"]
    return count <= limit, count, limit, retry_after


def cleanup_old_windows(keep_minutes: int = 5) -> int:
    """
    Delete rate_limit_counters entries older than *keep_minutes*.
    Returns the number of rows deleted.  Safe to call from a background task.
    """
    now = datetime.now(timezone.utc)
    cutoff = now.strftime(
        f"%Y-%m-%dT%H:%M+00:00"
    )
    # Build cutoff by subtracting keep_minutes via string comparison on ISO format.
    # Simpler: just delete where window_start < (now - keep_minutes as ISO).
    from datetime import timedelta
    cutoff_dt = now - timedelta(minutes=keep_minutes)
    cutoff_iso = cutoff_dt.strftime("%Y-%m-%dT%H:%M+00:00")

    with sqlite3.connect(str(config.DB_PATH)) as conn:
        result = conn.execute(
            "DELETE FROM rate_limit_counters WHERE window_start < ?",
            (cutoff_iso,),
        )
        deleted = result.rowcount
        conn.commit()
    return deleted
