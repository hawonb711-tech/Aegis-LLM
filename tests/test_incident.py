"""
Tests for the deterministic incident state machine.

All tests run against an isolated in-process SQLite database.
The `test_client` fixture (AUTH_ENABLED=False) is used so the HTTP endpoints
are accessible without key management overhead.
"""
import time

import pytest

from app.audit import db as audit_db
from app.incident.state import IncidentState, evaluate_incident_state, get_current_state
from app.policy import IncidentPolicy


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_policy(**kwargs) -> IncidentPolicy:
    """Build a test IncidentPolicy, defaulting to low thresholds."""
    defaults = dict(
        window_seconds=3600,
        high_risk_min=60,
        promote_on_blocks=3,
        promote_on_pi_events=2,
        promote_on_high_risk=2,
        cooldown_seconds=1,           # short so demotion tests don't have to wait long
        stability_window_seconds=1,   # short stability window
    )
    defaults.update(kwargs)
    return IncidentPolicy(**defaults)


def _block(n: int = 1, risk: int = 0) -> None:
    """Insert *n* BLOCK audit events."""
    for _ in range(n):
        audit_db.log_event(
            endpoint="/v1/chat",
            request_data={"messages": [{"role": "user", "content": "inject"}]},
            response_data={"decision": "BLOCK"},
            decision="BLOCK",
            reason_codes=["PI-001"],
            risk_score=risk,
        )


def _allow(n: int = 1, risk: int = 0) -> None:
    """Insert *n* ALLOW audit events."""
    for _ in range(n):
        audit_db.log_event(
            endpoint="/v1/chat",
            request_data={"messages": [{"role": "user", "content": "hello"}]},
            response_data={"decision": "ALLOW"},
            decision="ALLOW",
            reason_codes=[],
            risk_score=risk,
        )


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_initial_state_is_normal(test_client):
    """With no events, state should remain NORMAL."""
    policy = _make_policy()
    state = evaluate_incident_state(policy)
    assert state == IncidentState.NORMAL


def test_below_threshold_stays_normal(test_client):
    """BLOCK events below the promotion threshold do not change state."""
    # Also raise pi_events threshold: _block() inserts PI-001 reason codes.
    policy = _make_policy(promote_on_blocks=5, promote_on_pi_events=999)
    _block(4)  # one below threshold
    state = evaluate_incident_state(policy)
    assert state == IncidentState.NORMAL


def test_blocks_trigger_strict(test_client):
    """Reaching promote_on_blocks BLOCKs should promote to STRICT."""
    policy = _make_policy(promote_on_blocks=3)
    _block(3)
    state = evaluate_incident_state(policy)
    assert state == IncidentState.STRICT


def test_pi_events_trigger_strict(test_client):
    """PI-001 events reaching promote_on_pi_events should promote to STRICT."""
    policy = _make_policy(promote_on_pi_events=2, promote_on_blocks=999)
    # Insert BLOCK events with PI-001 codes (already done by _block with reason_codes=["PI-001"])
    _block(2)
    state = evaluate_incident_state(policy)
    assert state == IncidentState.STRICT


def test_high_risk_events_trigger_strict(test_client):
    """High risk_score events reaching promote_on_high_risk should promote to STRICT."""
    policy = _make_policy(
        promote_on_high_risk=2,
        promote_on_blocks=999,
        promote_on_pi_events=999,
        high_risk_min=60,
    )
    _allow(2, risk=80)  # high-risk ALLOW events
    state = evaluate_incident_state(policy)
    assert state == IncidentState.STRICT


def test_state_persists_in_db(test_client):
    """After promotion, get_current_state() should reflect STRICT."""
    policy = _make_policy(promote_on_blocks=2)
    _block(2)
    evaluate_incident_state(policy)
    assert get_current_state() == IncidentState.STRICT


def test_promotion_recorded_in_transitions_table(test_client):
    """A transition to STRICT must be persisted in incident_transitions."""
    from app.incident.state import _connect as inc_connect
    policy = _make_policy(promote_on_blocks=2)
    _block(2)
    evaluate_incident_state(policy)

    conn = inc_connect()
    row = conn.execute(
        "SELECT to_state FROM incident_transitions ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert row is not None
    assert row["to_state"] == "STRICT"


def test_strict_to_normal_demotion(test_client):
    """After cooldown and a clean stability window, state demotes to NORMAL."""
    # Use very short cooldown/stability window so test runs quickly.
    policy = _make_policy(
        promote_on_blocks=2,
        cooldown_seconds=1,
        stability_window_seconds=1,
        high_risk_min=60,
    )

    # Promote to STRICT.
    _block(2)
    state = evaluate_incident_state(policy)
    assert state == IncidentState.STRICT

    # Wait for cooldown + stability window.
    time.sleep(1.1)

    # No further high-risk events in stability window — should demote.
    state = evaluate_incident_state(policy)
    assert state == IncidentState.NORMAL


def test_no_demotion_before_cooldown(test_client):
    """With cooldown_seconds=60, state stays STRICT immediately after promotion."""
    policy = _make_policy(
        promote_on_blocks=2,
        cooldown_seconds=60,
        stability_window_seconds=1,
    )
    _block(2)
    evaluate_incident_state(policy)  # -> STRICT

    # Attempt immediate demotion (cooldown not elapsed).
    state = evaluate_incident_state(policy)
    assert state == IncidentState.STRICT


def test_override_force_strict(test_client):
    """Admin override can force state to STRICT with no events."""
    from app.incident.state import apply_override

    new_state, tid = apply_override(
        target_state=IncidentState.STRICT,
        ttl_seconds=None,
        reason="test override",
    )
    assert new_state == IncidentState.STRICT
    assert get_current_state() == IncidentState.STRICT


def test_override_force_normal(test_client):
    """Admin override can force state back to NORMAL from STRICT."""
    from app.incident.state import apply_override

    # First promote.
    policy = _make_policy(promote_on_blocks=2)
    _block(2)
    evaluate_incident_state(policy)
    assert get_current_state() == IncidentState.STRICT

    # Override back to NORMAL.
    apply_override(IncidentState.NORMAL, ttl_seconds=None, reason="manual reset")
    assert get_current_state() == IncidentState.NORMAL


def test_override_with_ttl_blocks_evaluation(test_client):
    """
    When an active TTL override is in effect, evaluate_incident_state()
    must not change the state even if promotion thresholds are met.
    """
    from app.incident.state import apply_override

    policy = _make_policy(promote_on_blocks=2)

    # Force NORMAL with a 30-second TTL — even with BLOCKs, it should not promote.
    apply_override(IncidentState.NORMAL, ttl_seconds=30, reason="hold normal")

    _block(10)  # Way over threshold
    state = evaluate_incident_state(policy)
    assert state == IncidentState.NORMAL  # Override is still active


def test_http_get_incident(test_client):
    """GET /admin/incident must return current state details."""
    resp = test_client.get("/admin/incident")
    assert resp.status_code == 200
    data = resp.json()
    assert data["state"] == "NORMAL"
    assert "override_active" in data


def test_http_post_incident_override(test_client):
    """POST /admin/incident/override must set state to STRICT."""
    resp = test_client.post(
        "/admin/incident/override",
        json={"state": "STRICT", "reason": "test"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["state"] == "STRICT"
    assert "transition_id" in data


def test_http_post_incident_override_invalid_state(test_client):
    """POST /admin/incident/override with unknown state returns 400."""
    resp = test_client.post(
        "/admin/incident/override",
        json={"state": "UNKNOWN", "reason": "test"},
    )
    assert resp.status_code == 400


def test_events_outside_window_not_counted(test_client):
    """Events older than window_seconds must not trigger promotion."""
    import sqlite3
    from datetime import datetime, timedelta, timezone
    import app.config as cfg

    # Insert events with an old timestamp directly.
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    conn = sqlite3.connect(str(cfg.DB_PATH))
    conn.row_factory = sqlite3.Row
    import uuid, json
    conn.execute(
        "INSERT INTO audit_events "
        "(id, ts, endpoint, request_json, response_json, decision, "
        " reason_codes, risk_score, prev_hash, event_hash) "
        "VALUES (?, ?, '/v1/chat', '{}', '{}', 'BLOCK', '[]', 0, '', '')",
        (str(uuid.uuid4()), old_ts),
    )
    conn.commit()
    conn.close()

    # A 1-hour window should not count the 2-hour-old event.
    policy = _make_policy(window_seconds=3600, promote_on_blocks=1)
    state = evaluate_incident_state(policy)
    assert state == IncidentState.NORMAL
