"""
AI Security Gateway — FastAPI application entry point.

Endpoints
---------
POST /v1/chat            — guarded chat completions proxy
POST /v1/tools/execute   — guarded tool execution (stubbed, no real network)
GET  /v1/audit/events    — retrieve recent audit log entries
POST /v1/replay/{id}     — re-run a stored request through the gateway
"""
import json
import uuid
from contextlib import asynccontextmanager
from collections import Counter
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app import config
from app.audit import db as audit_db
from app.firewall.tools import check_tool
from app.guards.dlp import apply_dlp
from app.guards.injection import check_injection
from app.policy import (load_policy, get_policy,
                        get_effective_policy, get_active_mode, set_active_mode)
from app.providers.azure_openai import call_provider


# ── Startup / shutdown ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_policy(config.POLICY_PATH)
    audit_db.init_db()
    saved_mode = audit_db.get_state("active_mode")
    if saved_mode:
        set_active_mode(saved_mode)
    yield


app = FastAPI(
    title="AI Security Gateway",
    description=(
        "Policy-driven Zero-Trust Gateway that protects agentic AI systems "
        "from prompt injection, data leakage, and unsafe tool usage."
    ),
    version="0.1.0",
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
    decision: str                    # ALLOW | BLOCK | REDACT
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
    decision: str                    # ALLOW | REDACT | BLOCK | TOOL_DENY
    reason_codes: List[str]
    risk_score: int = 0
    result: Optional[Dict[str, Any]] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _concat_messages(messages: List[Message]) -> str:
    """Flatten all message content into a single string for guard evaluation."""
    return " ".join(m.content for m in messages)


# ── POST /v1/chat ─────────────────────────────────────────────────────────────

@app.post("/v1/chat", response_model=ChatResponse)
async def chat(req: ChatRequest) -> ChatResponse:
    """
    Guarded chat completions endpoint.

    Pipeline:
      1. Injection guard  — block if risk_score >= threshold
      2. Inbound DLP      — redact sensitive data in messages before forwarding
      3. Provider call    — forward (possibly redacted) messages to the LLM
      4. Outbound DLP     — redact any sensitive data in the assistant reply
    """
    policy = get_effective_policy()
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
    all_reason_codes: List[str] = list(inj.reason_codes)  # empty unless we add PI codes on ALLOW
    risk_score = inj.risk_score
    overall_decision = "ALLOW"
    redacted_messages: List[Message] = []

    for msg in req.messages:
        dlp = apply_dlp(msg.content, policy.dlp)
        redacted_messages.append(Message(role=msg.role, content=dlp.redacted_text))
        if dlp.decision in ("REDACT", "BLOCK"):
            # Escalate: ALLOW < REDACT < BLOCK
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

    # ── 4. Outbound DLP on assistant response ─────────────────────────────
    out_dlp = apply_dlp(provider_resp.content, policy.dlp)
    if out_dlp.decision in ("REDACT", "BLOCK"):
        if out_dlp.decision == "BLOCK" or overall_decision == "ALLOW":
            overall_decision = out_dlp.decision
        for rc in out_dlp.reason_codes:
            if rc not in all_reason_codes:
                all_reason_codes.append(rc)

    final_content = out_dlp.redacted_text

    resp = ChatResponse(
        id=str(uuid.uuid4()),
        decision=overall_decision,
        reason_codes=all_reason_codes,
        risk_score=risk_score,
        message=Message(role="assistant", content=final_content),
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
async def tool_execute(req: ToolExecuteRequest) -> ToolExecuteResponse:
    """
    Guarded tool execution endpoint.

    Pipeline:
      1. Firewall check   — verify tool + target domain against allowlist
      2. Outbound DLP     — inspect url + body for sensitive data before dispatch
      3. Stub response    — return a safe placeholder; NO real network calls
    """
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

    # ── 3. Stub response (no real network) ────────────────────────────────
    stub = {
        "status": 200,
        "body": (
            f"[STUBBED] Tool '{req.tool}' call to '{url}' "
            "was validated and stubbed — no real network request was made."
        ),
        "headers": {},
    }

    final_decision = dlp.decision  # ALLOW or REDACT
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
async def get_audit_events(limit: int = 50) -> Dict[str, Any]:
    """Return the *limit* most-recent audit events (default 50)."""
    events = audit_db.get_events(limit=limit)
    return {"events": [e.model_dump() for e in events], "count": len(events)}


# ── POST /v1/replay/{event_id} ────────────────────────────────────────────────

@app.post("/v1/replay/{event_id}")
async def replay_event(event_id: str) -> Any:
    """
    Re-run the original request for a stored audit event through the full
    gateway pipeline.  A new audit entry is created for the replay.
    The original event is never mutated.
    """
    event = audit_db.get_event_by_id(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail=f"Audit event '{event_id}' not found")

    req_data = json.loads(event.request_json)
    endpoint = event.endpoint

    if endpoint == "/v1/chat":
        return await chat(ChatRequest(**req_data))

    if endpoint == "/v1/tools/execute":
        return await tool_execute(ToolExecuteRequest(**req_data))

    raise HTTPException(
        status_code=400,
        detail=f"Replay not supported for endpoint '{endpoint}'",
    )


# ── GET /v1/audit/metrics ─────────────────────────────────────────────────────

@app.get("/v1/audit/metrics")
async def audit_metrics() -> Dict[str, Any]:
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
        "block_rate":     round(sum(1 for e in events if e.decision == "BLOCK")  / n, 4),
        "redact_rate":    round(sum(1 for e in events if e.decision == "REDACT") / n, 4),
        "avg_risk_score": round(sum(e.risk_score for e in events) / n, 2),
        "top_reason_codes": [{"code": c, "count": k} for c, k in code_counts.most_common(5)],
        "current_policy_mode": get_active_mode(),
    }


# ── POST /v1/policy/mode ──────────────────────────────────────────────────────

class PolicyModeRequest(BaseModel):
    mode: str


@app.post("/v1/policy/mode")
async def set_policy_mode(req: PolicyModeRequest) -> Dict[str, Any]:
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
async def policy_auto(req: PolicyAutoRequest) -> Dict[str, Any]:
    """
    Adaptive Policy Agent: if PI-001 events in the last *window* reach
    *pi_threshold*, automatically escalate to 'strict' mode and persist.
    Idempotent — re-calling in strict mode returns switched=false.
    """
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
