# Architecture — Aegis-LLM

This document describes the internal structure of the Aegis-LLM gateway: how components relate, how a request flows through the system, and where state is stored.

---

## High-level component map

```
aegis/                  CLI layer (typer)
  cli.py                Entry point; commands: doctor, simulate, serve, run
  doctor.py             Health checks (ENV / POLICY / DATABASE / IMPORT)
  simulate.py           Offline guard pipeline trace (no network, no DB writes)
  serve.py              uvicorn wrapper
  run_env.py            OPENAI_* env var injection helpers

app/                    Runtime (FastAPI / ASGI)
  main.py               Request routing; guard pipeline orchestration
  config.py             Env var reading (POLICY_PATH, DB_PATH, MOCK_MODE, …)
  policy.py             Policy load, validation, mode management
  guards/
    injection.py        Phrase-based injection scoring + optional TF-IDF layer
    dlp.py              Two-pass DLP (regex → keywords)
    semantic_injection.py  TF-IDF cosine similarity (disabled by default)
  firewall/
    tools.py            Tool name + domain allowlist check
  audit/
    db.py               SQLite writes; hash-chain linkage; schema migration
    chain.py            SHA-256 chain: canonical_payload, compute_hash, verify_audit_chain
    models.py           AuditEvent pydantic model
  auth/
    api_keys.py         Key creation, hashing (bcrypt), rotation, disable
    deps.py             FastAPI dependency: require_user / require_admin
  incident/
    state.py            NORMAL/STRICT state machine; promotion/demotion; override
  providers/
    azure_openai.py     Azure OpenAI client + mock mode
  ratelimit/
    limiter.py          Per-key rate limiting (RPM); SQLite-backed counters

policies/
  default.yaml          Bundled default policy

tests/                  pytest test suite
```

---

## Request lifecycle — POST /v1/chat

```
Caller
  │
  ▼
FastAPI router  ─── require_user (bearer token check)
  │
  ▼
incident_state.evaluate_incident_state(policy.incident)
  │  reads audit_events window; may promote/demote and update gateway_state
  │
  ▼
policy = get_effective_policy()
  │  returns base policy or strict-overlay copy depending on active mode
  │
  ├─ check_injection(full_text, policy.injection)
  │    phrase score ≥ threshold? → BLOCK + log + return
  │
  ├─ apply_dlp(msg.content, policy.dlp) per message  [inbound]
  │    regex pass → keyword pass → redacted_messages
  │    BLOCK escalation? → log + return
  │
  ├─ call_provider(redacted_messages, tools)
  │    MOCK_MODE=true → echo stub
  │    MOCK_MODE=false → Azure OpenAI chat completions
  │
  ├─ apply_dlp(provider_resp.content, policy.dlp)  [outbound]
  │    same patterns; upgrades overall_decision if needed
  │
  └─ audit_db.log_event(...)
       BEGIN IMMEDIATE; read chain tip; compute hash; INSERT; COMMIT
```

The pipeline is **strictly sequential**. Each stage may modify the data the next stage receives, so parallelisation is not possible without breaking correctness (inbound DLP output is the provider's input; outbound DLP applies to the provider's output).

**Escalation rule:** decision severity only increases — `ALLOW < REDACT < BLOCK`. Once BLOCK is set, no subsequent guard can downgrade it.

---

## Request lifecycle — POST /v1/tools/execute

```
Caller
  │
  ▼
FastAPI router  ─── require_user
  │
  ├─ incident_state.evaluate_incident_state(policy.incident)
  │
  ├─ check_tool(tool_name, arguments, policy.tools)
  │    unknown name → TOOL_DENY (TOOL-002)
  │    domain not in allowlist → TOOL_DENY (TOOL-001)
  │    strict mode: allowed_domains=[] → always TOOL_DENY
  │
  ├─ apply_dlp(url + body, policy.dlp)  [outbound args]
  │    BLOCK → deny + log + return
  │
  └─ stub response + audit_db.log_event(...)
       no real network call is made
```

---

## Data stores

### SQLite (`audit.db`)

| Table | Purpose |
|-------|---------|
| `audit_events` | Append-only log; every gateway decision; hash chain |
| `gateway_state` | Key-value pairs: `active_mode`, `incident_state`, `incident_override_expires` |
| `incident_transitions` | Full record of every NORMAL↔STRICT transition |
| `api_keys` | API key metadata + bcrypt hash (plaintext never stored) |
| `rate_limit_counters` | Per-key per-minute request counts |

**WAL mode** is enabled on every connection so readers and writers do not block each other.

**Hash chain** — `log_event` uses `BEGIN IMMEDIATE` to serialize concurrent writers. Each row stores `prev_hash` (chain tip at write time) and `event_hash = SHA-256(prev_hash + "\n" + canonical_json(all other fields))`.

### In-process state

| Variable | Location | Description |
|----------|----------|-------------|
| `_policy` | `app/policy.py` | Loaded base policy singleton |
| `_active_mode` | `app/policy.py` | `"default"` or `"strict"` |
| `_current_state` | `app/incident/state.py` | `IncidentState.NORMAL` or `IncidentState.STRICT` |

These are module-level singletons. Startup restores `_active_mode` and `_current_state` from `gateway_state`. In a multi-process deployment each worker has independent in-process state; the SQLite file is the shared source of truth on startup.

---

## Policy system

```
policies/default.yaml
       │
  load_policy(path)
       │
  _policy  (singleton)
       │
  get_effective_policy()  ← called on every request
       │
       ├── _active_mode == "default"  → return base policy unchanged
       └── _active_mode == "strict"   → deep copy + apply _STRICT_OVERRIDES
                                          injection.block_threshold: 60 → 30
                                          dlp.keyword_action: "redact" (no change for default)
                                          tools.http_fetch.allowed_domains: [] (deny all)
```

Mode switches take effect on the **next request** — no restart required. Mode is persisted to `gateway_state` so it survives restarts.

---

## Incident state machine

```
       NORMAL  ────────────────────────────────────────────► STRICT
                  Promotion triggers (any one in window):
                  - BLOCK decisions >= promote_on_blocks (default 3)
                  - PI-001/PI-SEM-001 events >= promote_on_pi_events (default 2)
                  - high-risk-score events >= promote_on_high_risk (default 5)

       STRICT  ────────────────────────────────────────────► NORMAL
                  Demotion requires ALL:
                  - Time in STRICT >= cooldown_seconds (default 600s)
                  - No high-risk events in stability_window_seconds (default 300s)
```

`evaluate_incident_state()` is called at the start of each `/v1/chat` and `/v1/tools/execute` request. It queries the audit log window — not in-memory counters — so behavior is deterministic across restarts. Every transition is recorded in `incident_transitions` and also written to the audit hash chain.

Operators can force a transition via `POST /admin/incident/override` with an optional TTL. While a TTL override is active, `evaluate_incident_state()` does not override the forced state.

---

## CLI commands and their relationship to the runtime

| Command | Imports runtime? | Writes DB? | Network? |
|---------|-----------------|------------|---------|
| `aegis doctor` | Yes (import check) | No | No |
| `aegis simulate` | Yes (guards only) | No | No |
| `aegis serve` | Yes (full app) | Yes (on requests) | Yes (provider) |
| `aegis run` | No | No | No |

`aegis simulate` imports `app.guards.injection` and `app.guards.dlp` directly, bypassing the FastAPI app and the database. It runs the same guard logic as the runtime but produces only a trace object.

---

## Key design decisions

For the reasoning behind each decision see [DESIGN.md](../DESIGN.md):

1. Runtime policy overrides (no restart required for mode switch)
2. SQLite for persisted state (no external dependency)
3. Strict mode uses redact for DLP keywords, not block (service continuity)
4. Default-deny tool firewall (explicit allowlist required for every egress target)
