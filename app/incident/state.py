"""
Deterministic incident state machine.

States
------
  NORMAL  — baseline operation; standard thresholds apply.
  STRICT  — incident mode; tightened thresholds, all HTTP egress denied.

Promotion (NORMAL -> STRICT)
----------------------------
Triggered when ANY of the following counts, measured over the rolling
`window_seconds` of recent audit events, exceeds its configured threshold:
  - BLOCK decisions           >= promote_on_blocks
  - PI-001 / PI-SEM-001 hits  >= promote_on_pi_events
  - high-risk-score events    >= promote_on_high_risk

Demotion (STRICT -> NORMAL)
----------------------------
Triggered when ALL of the following are true:
  - Time since the last STRICT promotion >= cooldown_seconds
  - No high-risk events in the trailing stability_window_seconds

Overrides
---------
An operator can force a state transition via POST /admin/incident/override.
An override with a TTL expires deterministically based on UTC wall time stored
in gateway_state; evaluate_incident_state() enforces the expiry.

Traceability
------------
Every state transition is written to the `incident_transitions` table and also
persisted as a normal audit event so it appears in the hash chain.
"""
import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from app import config
from app.audit import chain as audit_chain


class IncidentState(str, Enum):
    NORMAL = "NORMAL"
    STRICT = "STRICT"


# Module-level cache — authoritative in-process state.
_current_state: IncidentState = IncidentState.NORMAL


# ── Connection helper ─────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# ── Schema ────────────────────────────────────────────────────────────────────

def init_incident_db() -> None:
    """Create incident tables if absent. Idempotent."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_transitions (
                id               TEXT PRIMARY KEY,
                ts               TEXT NOT NULL,
                from_state       TEXT NOT NULL,
                to_state         TEXT NOT NULL,
                reason           TEXT NOT NULL,
                counters_json    TEXT NOT NULL,
                window_start     TEXT NOT NULL,
                window_end       TEXT NOT NULL,
                policy_hash      TEXT NOT NULL,
                override_expires TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_it_ts ON incident_transitions(ts)"
        )
        conn.commit()


# ── Restore on startup ────────────────────────────────────────────────────────

def restore_state() -> None:
    """
    Restore in-process state from the database.
    Called during lifespan startup so a restart does not silently reset STRICT.
    """
    global _current_state
    _current_state = IncidentState.NORMAL  # Safe default.

    with _connect() as conn:
        row = conn.execute(
            "SELECT value FROM gateway_state WHERE key = 'incident_state'"
        ).fetchone()
    if row and row["value"] in (s.value for s in IncidentState):
        _current_state = IncidentState(row["value"])


# ── Public accessors ──────────────────────────────────────────────────────────

def get_current_state() -> IncidentState:
    return _current_state


def get_state_details() -> Dict[str, Any]:
    """Return the current state plus the most-recent transition record."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM incident_transitions ORDER BY ts DESC LIMIT 1"
        ).fetchone()
        override_row = conn.execute(
            "SELECT value FROM gateway_state WHERE key = 'incident_override_expires'"
        ).fetchone()

    details: Dict[str, Any] = {
        "state": _current_state.value,
        "last_transition": dict(row) if row else None,
        "override_active": False,
        "override_expires": None,
    }
    if override_row:
        expires_str: str = override_row["value"]
        if expires_str:
            expires_dt = datetime.fromisoformat(expires_str)
            now = datetime.now(timezone.utc)
            if expires_dt > now:
                details["override_active"] = True
                details["override_expires"] = expires_str
    return details


# ── Internal helpers ──────────────────────────────────────────────────────────

def _policy_hash() -> str:
    """SHA-256 of the current policy's canonical JSON (first 16 chars for brevity)."""
    try:
        from app.policy import get_policy
        payload = audit_chain.canonical_payload(get_policy().model_dump())
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
    except RuntimeError:
        return "policy-not-loaded"


def _override_is_active() -> bool:
    """Return True if a valid, non-expired override is in effect."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT value FROM gateway_state WHERE key = 'incident_override_expires'"
        ).fetchone()
    if not row or not row["value"]:
        return False
    expires_dt = datetime.fromisoformat(row["value"])
    return datetime.now(timezone.utc) < expires_dt


def _record_transition(
    from_state: IncidentState,
    to_state: IncidentState,
    reason: str,
    counters: Dict[str, Any],
    window_start: datetime,
    window_end: datetime,
    override_expires: Optional[str] = None,
) -> str:
    """Persist a transition to incident_transitions and gateway_state."""
    transition_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()
    phash = _policy_hash()

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO incident_transitions
                (id, ts, from_state, to_state, reason, counters_json,
                 window_start, window_end, policy_hash, override_expires)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transition_id, ts,
                from_state.value, to_state.value,
                reason, json.dumps(counters),
                window_start.isoformat(), window_end.isoformat(),
                phash, override_expires,
            ),
        )
        conn.execute(
            """
            INSERT INTO gateway_state (key, value, ts) VALUES ('incident_state', ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, ts = excluded.ts
            """,
            (to_state.value, ts),
        )
        conn.commit()

    # Also write into the audit hash chain so the transition is tamper-evident.
    from app.audit import db as audit_db  # local import to avoid circular
    audit_db.log_event(
        endpoint="SYSTEM/incident/transition",
        request_data={"from_state": from_state.value, "reason": reason, "counters": counters},
        response_data={"to_state": to_state.value, "transition_id": transition_id, "policy_hash": phash},
        decision="STATE_CHANGE",
        reason_codes=[],
        risk_score=0,
    )
    return transition_id


def _apply_to_policy_mode(state: IncidentState) -> None:
    """Sync the policy active_mode with the incident state."""
    from app.policy import set_active_mode
    from app.audit import db as audit_db

    mode = "strict" if state == IncidentState.STRICT else "default"
    set_active_mode(mode)
    audit_db.set_state("active_mode", mode)


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate_incident_state(policy: Any) -> IncidentState:
    """
    Evaluate whether a state transition is warranted based on recent audit events.

    Call this at the start of each user-facing request.  All decisions are based
    on timestamps stored in audit_events — not in-memory counters — so behavior
    is fully deterministic across restarts.

    *policy* is an IncidentPolicy instance (app.policy.IncidentPolicy).
    Returns the current IncidentState after any transition.
    """
    global _current_state

    if _override_is_active():
        return _current_state

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=policy.window_seconds)

    from app.audit import db as audit_db  # local import to avoid circular
    events = audit_db.get_events_in_window(window_start)

    blocks = sum(1 for e in events if e.decision == "BLOCK")
    pi_events = sum(
        1 for e in events
        if any(rc in e.reason_codes for rc in ("PI-001", "PI-SEM-001"))
    )
    high_risk = sum(1 for e in events if e.risk_score >= policy.high_risk_min)

    counters = {
        "blocks": blocks,
        "pi_events": pi_events,
        "high_risk": high_risk,
        "window_seconds": policy.window_seconds,
    }

    if _current_state == IncidentState.NORMAL:
        promote = False
        reasons: List[str] = []
        if blocks >= policy.promote_on_blocks:
            promote = True
            reasons.append(f"blocks={blocks}>={policy.promote_on_blocks}")
        if pi_events >= policy.promote_on_pi_events:
            promote = True
            reasons.append(f"pi_events={pi_events}>={policy.promote_on_pi_events}")
        if high_risk >= policy.promote_on_high_risk:
            promote = True
            reasons.append(f"high_risk={high_risk}>={policy.promote_on_high_risk}")

        if promote:
            reason_str = "Promoted to STRICT: " + ", ".join(reasons)
            _current_state = IncidentState.STRICT
            _record_transition(
                IncidentState.NORMAL, IncidentState.STRICT,
                reason_str, counters, window_start, now,
            )
            _apply_to_policy_mode(IncidentState.STRICT)

    elif _current_state == IncidentState.STRICT:
        # Demotion: need cooldown AND a clean stability window.
        with _connect() as conn:
            last_row = conn.execute(
                "SELECT ts FROM incident_transitions "
                "WHERE to_state = 'STRICT' ORDER BY ts DESC LIMIT 1"
            ).fetchone()

        if last_row is None:
            # No recorded promotion — state was restored from DB without history.
            # Be conservative: stay STRICT.
            return _current_state

        promoted_at = datetime.fromisoformat(last_row["ts"])
        # Ensure promoted_at is timezone-aware.
        if promoted_at.tzinfo is None:
            promoted_at = promoted_at.replace(tzinfo=timezone.utc)

        time_in_strict = (now - promoted_at).total_seconds()
        if time_in_strict < policy.cooldown_seconds:
            return _current_state  # Cooldown not elapsed.

        stability_start = now - timedelta(seconds=policy.stability_window_seconds)
        stable_events = audit_db.get_events_in_window(stability_start)
        high_risk_in_stability = sum(
            1 for e in stable_events
            if e.risk_score >= policy.high_risk_min
        )

        if high_risk_in_stability == 0:
            reason_str = (
                f"Demoted to NORMAL: cooldown={time_in_strict:.0f}s >= "
                f"{policy.cooldown_seconds}s, no high-risk events in "
                f"stability window={policy.stability_window_seconds}s"
            )
            _current_state = IncidentState.NORMAL
            _record_transition(
                IncidentState.STRICT, IncidentState.NORMAL,
                reason_str, counters, stability_start, now,
            )
            _apply_to_policy_mode(IncidentState.NORMAL)

    return _current_state


# ── Override ──────────────────────────────────────────────────────────────────

def apply_override(
    target_state: IncidentState,
    ttl_seconds: Optional[int],
    reason: str,
) -> Tuple[IncidentState, str]:
    """
    Force-set the incident state, optionally with a TTL.

    Returns (new_state, transition_id).
    While the override TTL is active, evaluate_incident_state() will not
    override the forced state.
    """
    global _current_state

    from_state = _current_state
    now = datetime.now(timezone.utc)
    override_expires: Optional[str] = None

    if ttl_seconds is not None and ttl_seconds > 0:
        expires_dt = now + timedelta(seconds=ttl_seconds)
        override_expires = expires_dt.isoformat()
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO gateway_state (key, value, ts) VALUES
                    ('incident_override_expires', ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, ts = excluded.ts
                """,
                (override_expires, now.isoformat()),
            )
            conn.commit()
    else:
        # No TTL — clear any existing override expiry.
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO gateway_state (key, value, ts) VALUES
                    ('incident_override_expires', '', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, ts = excluded.ts
                """,
                (now.isoformat(),),
            )
            conn.commit()

    _current_state = target_state
    transition_id = _record_transition(
        from_state, target_state,
        f"Admin override: {reason}",
        {},
        now, now,
        override_expires,
    )
    _apply_to_policy_mode(target_state)
    return target_state, transition_id
