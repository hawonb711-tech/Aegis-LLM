"""
Tamper-evident audit log — hash chain implementation.

Security note
-------------
This provides tamper-EVIDENCE, not tamper-PROOF protection.

An adversary with write access to the SQLite file can recompute the entire
chain after modifying records.  The value is detecting post-hoc modifications
that have NOT been accompanied by a full chain recomputation — the most common
scenario (e.g., direct DB edits by an insider, or accidental corruption).

For stronger guarantees, periodically export the latest `event_hash` (the chain
tip) to an external append-only store (SIEM, S3 with object lock, CloudWatch
Logs, etc.).  A mismatch between the external anchor and the local chain tip
proves tampering even against an adversary who controls the local SQLite file.

Chain algorithm
---------------
  event_payload = canonical_json(all event fields except event_hash)
  event_hash    = SHA-256(prev_hash + "\\n" + event_payload), hex-encoded
  prev_hash     = event_hash of the chronologically previous row, or "" for row 1
"""
import hashlib
import json
import sqlite3
from typing import Any, Callable, Dict, Optional, Tuple


def canonical_payload(fields: Dict[str, Any]) -> str:
    """
    Return a deterministic, whitespace-free JSON encoding of *fields*.

    Keys are sorted alphabetically.  ensure_ascii=False preserves UTF-8 so the
    hash is not sensitive to codec differences between systems.
    """
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, payload: str) -> str:
    """
    Return SHA-256(prev_hash + "\\n" + payload) as a lowercase hex string.
    """
    data = (prev_hash + "\n" + payload).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _fields_for_hash(row: sqlite3.Row) -> Dict[str, Any]:
    """
    Extract the payload fields used for hashing from a database row.

    These must be exactly the fields captured at write time in log_event().
    The event_hash column itself is excluded (it IS the hash of everything else).
    """
    return {
        "id": row["id"],
        "ts": row["ts"],
        "endpoint": row["endpoint"],
        "request_json": row["request_json"],
        "response_json": row["response_json"],
        "decision": row["decision"],
        "reason_codes": row["reason_codes"],
        "risk_score": row["risk_score"],
        "prev_hash": row["prev_hash"],
    }


def verify_audit_chain(
    conn_factory: Callable[[], sqlite3.Connection],
    limit: Optional[int] = None,
) -> Tuple[bool, Optional[str], str]:
    """
    Walk the audit chain in chronological order and verify every hash link.

    Returns a 3-tuple:
      ok            — True if the full chain is intact
      first_bad_id  — UUID of the first broken event (None when ok=True)
      reason        — human-readable description of the outcome

    The *limit* argument bounds how many rows are scanned (None = all rows).
    This is safe to call at any time without holding any lock.
    """
    conn = conn_factory()
    try:
        sql = (
            "SELECT id, ts, endpoint, request_json, response_json, "
            "decision, reason_codes, risk_score, prev_hash, event_hash "
            "FROM audit_events "
            "ORDER BY ts ASC, rowid ASC"
        )
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        rows = conn.execute(sql).fetchall()
    finally:
        conn.close()

    if not rows:
        return True, None, "Chain is empty — nothing to verify"

    expected_prev = ""
    for row in rows:
        stored_prev: str = row["prev_hash"]
        stored_hash: str = row["event_hash"]

        # Skip rows that were never backfilled (pre-migration data with empty hash).
        # Once a row has a hash it must be valid.
        if not stored_hash:
            expected_prev = ""
            continue

        if stored_prev != expected_prev:
            return (
                False,
                row["id"],
                f"prev_hash mismatch on event {row['id']!r}: "
                f"expected {expected_prev!r}, got {stored_prev!r}",
            )

        expected_hash = compute_hash(stored_prev, canonical_payload(_fields_for_hash(row)))
        if stored_hash != expected_hash:
            return (
                False,
                row["id"],
                f"event_hash mismatch on event {row['id']!r}: "
                f"stored={stored_hash[:16]}… recomputed={expected_hash[:16]}… — record was tampered",
            )

        expected_prev = stored_hash

    return True, None, f"Chain intact — {len(rows)} event(s) verified"
