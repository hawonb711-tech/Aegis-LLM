"""
AI Security Gateway — FastAPI application entry point.

Endpoints
---------
User scope (/v1/*):
  POST /v1/chat              — guarded chat completions proxy
  POST /v1/tools/execute     — guarded tool execution (stubbed)
  GET  /v1/audit/events      — retrieve recent audit log entries
  POST /v1/replay/{id}       — re-run a stored request through the gateway
  GET  /v1/audit/metrics     — operational metrics for last N events
  POST /v1/policy/mode       — switch active policy mode
  POST /v1/policy/auto       — adaptive policy agent (auto-escalate)

Admin scope (/admin/*):
  GET  /admin/audit/events   — full audit event list (admin)
  GET  /admin/audit/verify   — verify the tamper-evident hash chain
  GET  /admin/incident       — current incident state + last transition
  POST /admin/incident/override — force-set incident state (with optional TTL)
  GET  /admin/keys           — list all API keys (no hashes)
  POST /admin/keys           — create a new API key
  POST /admin/keys/{id}/rotate  — rotate (replace) a key's secret
  POST /admin/keys/{id}/disable — deactivate a key
"""
import json
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from app import config
from app.audit import chain as audit_chain
from app.audit import db as audit_db
from app.auth import api_keys
from app.auth.deps import AuthenticatedKey, require_admin, require_user
from app.firewall.tools import check_tool
from app.guards.dlp import apply_dlp
from app.guards.injection import check_injection
from app.incident import state as incident_state
from app.incident.state import IncidentState
from app.policy import (
    get_active_mode,
    get_effective_policy,
    get_policy,
    load_policy,
    set_active_mode,
)
from app.providers.azure_openai import call_provider
from app.ratelimit import limiter


# ── Startup / shutdown ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_policy(config.POLICY_PATH)

    # Init all DB tables (idempotent; includes migration + backfill).
    audit_db.init_db()
    api_keys.init_auth_db()
    limiter.init_ratelimit_db()
    incident_state.init_incident_db()

    # Restore persisted gateway state.
    incident_state.restore_state()
    saved_mode = audit_db.get_state("active_mode")
    if saved_mode:
        set_active_mode(saved_mode)

    # Bootstrap admin key from environment if set.
    api_keys.bootstrap_admin_key()

    yield


app = FastAPI(
    title="Aegis-LLM — AI Security Gateway",
    description=(
        "Policy-driven Zero-Trust Gateway that protects agentic AI systems "
        "from prompt injection, data leakage, and unsafe tool usage."
    ),
    version="0.2.0",
    lifespan=lifespan,
)


# ── Request / Response schemas ────────────────────────────────────────────────

class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[Message]
    tools: Optional[List[Dict[str, Any]]] = []
    metadata: Optional[Dict[str, Any]] = {}


class ChatResponse(BaseModel):
    id: str
    decision: str
    reason_codes: List[str]
    risk_score: int
    message: Message
    tool_calls: List[Dict[str, Any]] = []


class ToolExecuteRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = {}


class ToolExecuteResponse(BaseModel):
    id: str
    decision: str
    reason_codes: List[str]
    risk_score: int = 0
    result: Optional[Dict[str, Any]] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _concat_messages(messages: List[Message]) -> str:
    return " ".join(m.content for m in messages)


# ── POST /v1/chat ─────────────────────────────────────────────────────────────

@app.post("/v1/chat", response_model=ChatResponse)
async def chat(
    req: ChatRequest,
    _key: AuthenticatedKey = Depends(require_user),
) -> ChatResponse:
    """
    Guarded chat completions endpoint.

    Pipeline:
      1. Incident state evaluation  — may switch active policy to strict
      2. Injection guard            — block if risk_score >= threshold
      3. Inbound DLP                — redact sensitive data before forwarding
      4. Provider call              — forward to LLM (mock by default)
      5. Outbound DLP               — redact sensitive data in the reply
    """
    policy = get_effective_policy()
    incident_state.evaluate_incident_state(policy.incident)
    policy = get_effective_policy()  # re-fetch after possible mode change

    req_dict = req.model_dump()

    # ── 1. Injection guard ────────────────────────────────────────────────
    full_text = _concat_messages(req.messages)
    inj = check_injection(full_text, policy.injection)

    if inj.decision == "BLOCK":
        resp = ChatResponse(
            id=str(uuid.uuid4()),
            decision="BLOCK",
            reason_codes=inj.reason_codes,
            risk_score=inj.risk_score,
            message=Message(
                role="assistant",
                content="Request blocked: prompt injection attempt detected.",
            ),
        )
        audit_db.log_event(
            endpoint="/v1/chat",
            request_data=req_dict,
            response_data=resp.model_dump(),
            decision="BLOCK",
            reason_codes=inj.reason_codes,
            risk_score=inj.risk_score,
        )
        return resp

    # ── 2. Inbound DLP ────────────────────────────────────────────────────
    all_reason_codes: List[str] = list(inj.reason_codes)
    risk_score = inj.risk_score
    overall_decision = "ALLOW"
    redacted_messages: List[Message] = []

    for msg in req.messages:
        dlp = apply_dlp(msg.content, policy.dlp)
        redacted_messages.append(Message(role=msg.role, content=dlp.redacted_text))
        if dlp.decision in ("REDACT", "BLOCK"):
            if dlp.decision == "BLOCK" or overall_decision == "ALLOW":
                overall_decision = dlp.decision
            for rc in dlp.reason_codes:
                if rc not in all_reason_codes:
                    all_reason_codes.append(rc)

    if overall_decision == "BLOCK":
        resp = ChatResponse(
            id=str(uuid.uuid4()),
            decision="BLOCK",
            reason_codes=all_reason_codes,
            risk_score=risk_score,
            message=Message(
                role="assistant",
                content="Request blocked: sensitive data detected in message.",
            ),
        )
        audit_db.log_event(
            endpoint="/v1/chat",
            request_data=req_dict,
            response_data=resp.model_dump(),
            decision="BLOCK",
            reason_codes=all_reason_codes,
            risk_score=risk_score,
        )
        return resp

    # ── 3. Provider call ──────────────────────────────────────────────────
    provider_messages = [{"role": m.role, "content": m.content} for m in redacted_messages]
    provider_resp = call_provider(provider_messages, req.tools or [])

    # ── 4. Outbound DLP ───────────────────────────────────────────────────
    out_dlp = apply_dlp(provider_resp.content, policy.dlp)
    if out_dlp.decision in ("REDACT", "BLOCK"):
        if out_dlp.decision == "BLOCK" or overall_decision == "ALLOW":
            overall_decision = out_dlp.decision
        for rc in out_dlp.reason_codes:
            if rc not in all_reason_codes:
                all_reason_codes.append(rc)

    resp = ChatResponse(
        id=str(uuid.uuid4()),
        decision=overall_decision,
        reason_codes=all_reason_codes,
        risk_score=risk_score,
        message=Message(role="assistant", content=out_dlp.redacted_text),
        tool_calls=provider_resp.tool_calls,
    )
    audit_db.log_event(
        endpoint="/v1/chat",
        request_data=req_dict,
        response_data=resp.model_dump(),
        decision=overall_decision,
        reason_codes=all_reason_codes,
        risk_score=risk_score,
    )
    return resp


# ── POST /v1/tools/execute ────────────────────────────────────────────────────

@app.post("/v1/tools/execute", response_model=ToolExecuteResponse)
async def tool_execute(
    req: ToolExecuteRequest,
    _key: AuthenticatedKey = Depends(require_user),
) -> ToolExecuteResponse:
    """
    Guarded tool execution endpoint.

    Pipeline:
      1. Incident state evaluation  — may switch active policy to strict
      2. Firewall check             — verify tool + target domain against allowlist
      3. Outbound DLP               — inspect url + body for sensitive data
      4. Stub response              — no real network calls
    """
    policy = get_effective_policy()
    incident_state.evaluate_incident_state(policy.incident)
    policy = get_effective_policy()

    req_dict = req.model_dump()

    # ── 1. Firewall ───────────────────────────────────────────────────────
    fw = check_tool(req.tool, req.arguments, policy.tools)

    if fw.decision == "TOOL_DENY":
        resp = ToolExecuteResponse(
            id=str(uuid.uuid4()),
            decision="TOOL_DENY",
            reason_codes=fw.reason_codes,
            result={"error": fw.reason},
        )
        audit_db.log_event(
            endpoint="/v1/tools/execute",
            request_data=req_dict,
            response_data=resp.model_dump(),
            decision="TOOL_DENY",
            reason_codes=fw.reason_codes,
            risk_score=0,
        )
        return resp

    # ── 2. Outbound DLP (url + body) ─────────────────────────────────────
    url = str(req.arguments.get("url") or "")
    body = str(req.arguments.get("body") or "")
    dlp = apply_dlp(f"{url} {body}", policy.dlp)

    if dlp.decision == "BLOCK":
        resp = ToolExecuteResponse(
            id=str(uuid.uuid4()),
            decision="BLOCK",
            reason_codes=dlp.reason_codes,
            result={"error": "Tool request blocked: sensitive data detected in arguments"},
        )
        audit_db.log_event(
            endpoint="/v1/tools/execute",
            request_data=req_dict,
            response_data=resp.model_dump(),
            decision="BLOCK",
            reason_codes=dlp.reason_codes,
            risk_score=0,
        )
        return resp

    stub = {
        "status": 200,
        "body": (
            f"[STUBBED] Tool '{req.tool}' call to '{url}' "
            "was validated and stubbed — no real network request was made."
        ),
        "headers": {},
    }
    final_decision = dlp.decision
    resp = ToolExecuteResponse(
        id=str(uuid.uuid4()),
        decision=final_decision,
        reason_codes=dlp.reason_codes,
        result=stub,
    )
    audit_db.log_event(
        endpoint="/v1/tools/execute",
        request_data=req_dict,
        response_data=resp.model_dump(),
        decision=final_decision,
        reason_codes=dlp.reason_codes,
        risk_score=0,
    )
    return resp


# ── GET /v1/audit/events ──────────────────────────────────────────────────────

@app.get("/v1/audit/events")
async def get_audit_events(
    limit: int = 50,
    _key: AuthenticatedKey = Depends(require_user),
) -> Dict[str, Any]:
    """Return the *limit* most-recent audit events (default 50)."""
    events = audit_db.get_events(limit=limit)
    return {"events": [e.model_dump() for e in events], "count": len(events)}


# ── POST /v1/replay/{event_id} ────────────────────────────────────────────────

@app.post("/v1/replay/{event_id}")
async def replay_event(
    event_id: str,
    _key: AuthenticatedKey = Depends(require_user),
) -> Any:
    """Re-run the original request for a stored audit event."""
    event = audit_db.get_event_by_id(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail=f"Audit event '{event_id}' not found")

    req_data = json.loads(event.request_json)
    endpoint = event.endpoint

    if endpoint == "/v1/chat":
        return await chat(ChatRequest(**req_data), _key=_key)

    if endpoint == "/v1/tools/execute":
        return await tool_execute(ToolExecuteRequest(**req_data), _key=_key)

    raise HTTPException(
        status_code=400,
        detail=f"Replay not supported for endpoint '{endpoint}'",
    )


# ── GET /v1/audit/metrics ─────────────────────────────────────────────────────

@app.get("/v1/audit/metrics")
async def audit_metrics(
    _key: AuthenticatedKey = Depends(require_user),
) -> Dict[str, Any]:
    """Aggregate the last 50 audit events into operational metrics."""
    events = audit_db.get_events(limit=50)
    n = len(events)
    if n == 0:
        return {
            "window": 0, "block_rate": 0.0, "redact_rate": 0.0,
            "avg_risk_score": 0.0, "top_reason_codes": [],
            "current_policy_mode": get_active_mode(),
        }
    code_counts: Counter = Counter(rc for e in events for rc in e.reason_codes)
    return {
        "window": n,
        "block_rate": round(sum(1 for e in events if e.decision == "BLOCK") / n, 4),
        "redact_rate": round(sum(1 for e in events if e.decision == "REDACT") / n, 4),
        "avg_risk_score": round(sum(e.risk_score for e in events) / n, 2),
        "top_reason_codes": [{"code": c, "count": k} for c, k in code_counts.most_common(5)],
        "current_policy_mode": get_active_mode(),
    }


# ── POST /v1/policy/mode ──────────────────────────────────────────────────────

class PolicyModeRequest(BaseModel):
    mode: str


@app.post("/v1/policy/mode")
async def set_policy_mode(
    req: PolicyModeRequest,
    _key: AuthenticatedKey = Depends(require_user),
) -> Dict[str, Any]:
    """Manually switch the active policy mode and persist it to DB."""
    from_mode = get_active_mode()
    try:
        set_active_mode(req.mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_db.set_state("active_mode", req.mode)
    return {
        "switched": from_mode != req.mode,
        "from": from_mode,
        "to": req.mode,
        "persisted": True,
    }


# ── POST /v1/policy/auto ──────────────────────────────────────────────────────

class PolicyAutoRequest(BaseModel):
    window: int = 20
    pi_threshold: int = 3


@app.post("/v1/policy/auto")
async def policy_auto(
    req: PolicyAutoRequest,
    _key: AuthenticatedKey = Depends(require_user),
) -> Dict[str, Any]:
    """Adaptive Policy Agent: auto-escalate to strict on repeated PI events."""
    events = audit_db.get_events(limit=req.window)
    pi_count = sum(1 for e in events if "PI-001" in e.reason_codes)
    from_mode = get_active_mode()
    switched = False
    if pi_count >= req.pi_threshold and from_mode != "strict":
        set_active_mode("strict")
        audit_db.set_state("active_mode", "strict")
        switched = True
    return {
        "switched": switched,
        "from": from_mode,
        "to": get_active_mode(),
        "pi_count": pi_count,
        "window": len(events),
        "pi_threshold": req.pi_threshold,
    }


# ── Admin: audit ──────────────────────────────────────────────────────────────

@app.get("/admin/audit/events")
async def admin_audit_events(
    limit: int = 100,
    _key: AuthenticatedKey = Depends(require_admin),
) -> Dict[str, Any]:
    """Return up to *limit* most-recent audit events (admin view)."""
    events = audit_db.get_events(limit=limit)
    return {"events": [e.model_dump() for e in events], "count": len(events)}


@app.get("/admin/audit/verify")
async def admin_audit_verify(
    limit: Optional[int] = None,
    _key: AuthenticatedKey = Depends(require_admin),
) -> Dict[str, Any]:
    """Verify the tamper-evident hash chain over all (or the last N) audit events."""
    from app.audit.db import _connect as _audit_connect
    ok, first_bad_id, reason = audit_chain.verify_audit_chain(
        conn_factory=_audit_connect,
        limit=limit,
    )
    return {
        "ok": ok,
        "first_bad_id": first_bad_id,
        "reason": reason,
    }


# ── Admin: incident state ─────────────────────────────────────────────────────

@app.get("/admin/incident")
async def admin_incident_get(
    _key: AuthenticatedKey = Depends(require_admin),
) -> Dict[str, Any]:
    """Return the current incident state and the most recent state transition."""
    return incident_state.get_state_details()


class IncidentOverrideRequest(BaseModel):
    state: str
    ttl_seconds: Optional[int] = None
    reason: str = "manual admin override"


@app.post("/admin/incident/override")
async def admin_incident_override(
    req: IncidentOverrideRequest,
    _key: AuthenticatedKey = Depends(require_admin),
) -> Dict[str, Any]:
    """Force-set incident state, with optional TTL in seconds."""
    try:
        target = IncidentState(req.state.upper())
    except ValueError:
        valid = [s.value for s in IncidentState]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid state '{req.state}'. Valid values: {valid}",
        )
    new_state, transition_id = incident_state.apply_override(
        target_state=target,
        ttl_seconds=req.ttl_seconds,
        reason=req.reason,
    )
    return {
        "state": new_state.value,
        "transition_id": transition_id,
        "ttl_seconds": req.ttl_seconds,
        "reason": req.reason,
    }


# ── Admin: API key management ─────────────────────────────────────────────────

class CreateKeyRequest(BaseModel):
    name: str
    scopes: List[str] = ["user"]


@app.get("/admin/keys")
async def admin_list_keys(
    _key: AuthenticatedKey = Depends(require_admin),
) -> Dict[str, Any]:
    """List all API keys (metadata only; hashes are never returned)."""
    keys = api_keys.list_keys()
    return {"keys": keys, "count": len(keys)}


@app.post("/admin/keys", status_code=201)
async def admin_create_key(
    req: CreateKeyRequest,
    _key: AuthenticatedKey = Depends(require_admin),
) -> Dict[str, Any]:
    """
    Create a new API key. The plaintext key is returned ONCE in this response
    and is never stored or retrievable again. Store it securely.
    """
    valid_scopes = {"user", "admin"}
    invalid = set(req.scopes) - valid_scopes
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scopes: {sorted(invalid)}. Valid: {sorted(valid_scopes)}",
        )
    plaintext, key_id = api_keys.create_key(req.name, req.scopes)
    return {
        "key": plaintext,
        "key_id": key_id,
        "name": req.name,
        "scopes": req.scopes,
        "warning": "Store this key securely — it will not be shown again.",
    }


@app.post("/admin/keys/{key_id}/rotate")
async def admin_rotate_key(
    key_id: str,
    _key: AuthenticatedKey = Depends(require_admin),
) -> Dict[str, Any]:
    """
    Rotate a key's secret. The old secret is immediately invalidated.
    Returns the new plaintext key (shown only once).
    """
    try:
        new_plaintext, _ = api_keys.rotate_key(key_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {
        "key": new_plaintext,
        "key_id": key_id,
        "warning": "Store this key securely — it will not be shown again.",
    }


@app.post("/admin/keys/{key_id}/disable")
async def admin_disable_key(
    key_id: str,
    _key: AuthenticatedKey = Depends(require_admin),
) -> Dict[str, Any]:
    """Deactivate a key. Disabled keys return HTTP 403 on future requests."""
    try:
        api_keys.disable_key(key_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"key_id": key_id, "disabled": True}
