"""
Tests for the tamper-evident audit log hash chain.

All tests use an isolated per-test SQLite database (via the `test_client`
fixture which patches config.DB_PATH to a temp file and runs the lifespan).
No network calls are made.
"""
import sqlite3

from app.audit import db as audit_db
from app.audit import chain as audit_chain
from app.audit.db import _connect as audit_connect


# ── Helper ────────────────────────────────────────────────────────────────────

def _log(n: int = 1, decision: str = "ALLOW", risk: int = 0) -> list[str]:
    """Insert *n* audit events and return their IDs."""
    return [
        audit_db.log_event(
            endpoint="/v1/chat",
            request_data={"messages": [{"role": "user", "content": f"msg {i}"}]},
            response_data={"decision": decision},
            decision=decision,
            reason_codes=[],
            risk_score=risk,
        )
        for i in range(n)
    ]


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_empty_chain_is_ok(test_client):
    """An empty audit log verifies successfully."""
    ok, bad_id, reason = audit_chain.verify_audit_chain(audit_connect)
    assert ok is True
    assert bad_id is None
    assert "empty" in reason.lower()


def test_single_event_chain_ok(test_client):
    """A single event should produce a valid chain (prev_hash='')."""
    _log(1)
    ok, bad_id, reason = audit_chain.verify_audit_chain(audit_connect)
    assert ok is True
    assert bad_id is None


def test_multiple_events_chain_ok(test_client):
    """Three events inserted in sequence should all verify correctly."""
    _log(3)
    ok, bad_id, reason = audit_chain.verify_audit_chain(audit_connect)
    assert ok is True
    assert "3" in reason  # reason contains event count


def test_each_event_has_unique_hash(test_client):
    """Every event_hash should be distinct (no duplicate hashes)."""
    ids = _log(5)
    conn = audit_connect()
    rows = conn.execute("SELECT event_hash FROM audit_events").fetchall()
    conn.close()
    hashes = [r["event_hash"] for r in rows]
    assert len(hashes) == len(set(hashes)), "Duplicate event_hash found"


def test_first_event_prev_hash_empty(test_client):
    """The very first event must have prev_hash='' (genesis of the chain)."""
    _log(1)
    conn = audit_connect()
    row = conn.execute(
        "SELECT prev_hash FROM audit_events ORDER BY ts ASC, rowid ASC LIMIT 1"
    ).fetchone()
    conn.close()
    assert row["prev_hash"] == ""


def test_chained_prev_hash_links(test_client):
    """Each event's prev_hash must equal the event_hash of the preceding row."""
    _log(4)
    conn = audit_connect()
    rows = conn.execute(
        "SELECT prev_hash, event_hash FROM audit_events ORDER BY ts ASC, rowid ASC"
    ).fetchall()
    conn.close()
    for i, row in enumerate(rows):
        if i == 0:
            assert row["prev_hash"] == ""
        else:
            assert row["prev_hash"] == rows[i - 1]["event_hash"]


def test_tampered_request_json_detected(test_client):
    """Directly modifying request_json must cause verify to return ok=False."""
    _log(3)
    # Tamper the second event's request_json.
    conn = audit_connect()
    target_id = conn.execute(
        "SELECT id FROM audit_events ORDER BY ts ASC, rowid ASC LIMIT 1 OFFSET 1"
    ).fetchone()["id"]
    conn.execute(
        "UPDATE audit_events SET request_json = ? WHERE id = ?",
        ('{"tampered": true}', target_id),
    )
    conn.commit()
    conn.close()

    ok, bad_id, reason = audit_chain.verify_audit_chain(audit_connect)
    assert ok is False
    assert bad_id == target_id
    assert "tampered" in reason.lower()


def test_tampered_event_hash_detected(test_client):
    """Directly zeroing an event_hash must break the chain for the next event."""
    _log(3)
    conn = audit_connect()
    # Zero out the first event's hash; the second event's prev_hash will mismatch.
    first_id = conn.execute(
        "SELECT id FROM audit_events ORDER BY ts ASC, rowid ASC LIMIT 1"
    ).fetchone()["id"]
    conn.execute(
        "UPDATE audit_events SET event_hash = 'deadbeef' WHERE id = ?",
        (first_id,),
    )
    conn.commit()
    conn.close()

    ok, bad_id, reason = audit_chain.verify_audit_chain(audit_connect)
    assert ok is False


def test_verify_via_http_endpoint(test_client):
    """GET /admin/audit/verify must return ok=True for a clean chain."""
    _log(2)
    resp = test_client.get("/admin/audit/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["first_bad_id"] is None


def test_verify_via_http_endpoint_with_limit(test_client):
    """limit query parameter restricts how many events are verified."""
    _log(5)
    resp = test_client.get("/admin/audit/verify?limit=2")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_backfill_on_startup(isolated_db, monkeypatch):
    """
    Rows inserted without hashes (simulating a pre-migration database) must be
    backfilled correctly by init_db().
    """
    import app.config as cfg
    import app.policy as policy_mod
    import app.incident.state as inc_state

    monkeypatch.setattr(cfg, "AUTH_ENABLED", False)
    monkeypatch.setattr(policy_mod, "_policy", None)
    monkeypatch.setattr(policy_mod, "_active_mode", "default")
    monkeypatch.setattr(inc_state, "_current_state", inc_state.IncidentState.NORMAL)

    # Seed a DB that looks like a pre-migration state: valid rows but no hashes.
    import uuid, json
    from datetime import datetime, timezone

    db_path = str(cfg.DB_PATH)
    # First run init_db to create the schema.
    audit_db.init_db()

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    for i in range(3):
        conn.execute(
            "INSERT INTO audit_events "
            "(id, ts, endpoint, request_json, response_json, decision, "
            " reason_codes, risk_score, prev_hash, event_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', '')",
            (
                str(uuid.uuid4()),
                datetime.now(timezone.utc).isoformat(),
                "/v1/chat",
                json.dumps({"msg": f"pre {i}"}),
                json.dumps({"decision": "ALLOW"}),
                "ALLOW",
                "[]",
                0,
            ),
        )
    conn.commit()
    conn.close()

    # Re-run init_db — should backfill the three empty-hash rows.
    audit_db.init_db()

    # Now verify.
    ok, bad_id, reason = audit_chain.verify_audit_chain(audit_connect)
    assert ok is True, f"Backfill failed: {reason}"
