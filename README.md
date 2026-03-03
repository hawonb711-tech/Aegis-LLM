# AI Security Gateway

A **Security-First AI Control Plane** — a lightweight, policy-driven Zero-Trust
Gateway that sits in front of your agentic AI systems and enforces:

- **Prompt-injection detection** — blocks requests that try to hijack the LLM.
- **Data Leak Prevention (DLP)** — redacts or blocks emails, phone numbers, API
  keys, and secret tokens in both inbound user messages and outbound LLM replies.
- **Tool firewall** — validates every tool call against a domain allowlist before
  it can reach the network.
- **Immutable audit log** — every decision is written to SQLite with full
  request/response payloads for post-incident review.
- **Replay** — re-run any stored event through the current policy set to test
  policy changes against historical traffic.

```
User / Agent
     │
     ▼
┌────────────────────────────────┐
│       AI Security Gateway      │
│                                │
│  ┌──────────────────────────┐  │
│  │  1. Injection Guard      │  │  → BLOCK if risk ≥ threshold
│  ├──────────────────────────┤  │
│  │  2. DLP Guard (inbound)  │  │  → redact before forwarding
│  ├──────────────────────────┤  │
│  │  3. LLM Provider         │  │  → Azure OpenAI / Mock
│  ├──────────────────────────┤  │
│  │  4. DLP Guard (outbound) │  │  → redact LLM reply
│  ├──────────────────────────┤  │
│  │  5. Tool Firewall        │  │  → TOOL_DENY if domain ∉ allowlist
│  ├──────────────────────────┤  │
│  │  6. Audit Logger         │  │  → SQLite
│  └──────────────────────────┘  │
└────────────────────────────────┘
```

---

## Project Structure

```
ai-sec-gateway/
├── app/
│   ├── main.py          # FastAPI endpoints
│   ├── config.py        # Env-var configuration
│   ├── policy.py        # YAML policy loader + Pydantic validator
│   ├── guards/
│   │   ├── injection.py # Prompt injection detection
│   │   └── dlp.py       # Data leak prevention (redact / block)
│   ├── firewall/
│   │   └── tools.py     # Tool call domain allowlist
│   ├── audit/
│   │   ├── db.py        # SQLite read/write helpers
│   │   └── models.py    # AuditEvent Pydantic model
│   └── providers/
│       └── azure_openai.py  # Azure OpenAI + Mock provider
├── policies/
│   └── default.yaml     # Editable security policy
├── examples/
│   └── demo_client.py   # 4 demo scenarios + audit tail
├── tests/
│   ├── test_guards.py   # Injection + DLP unit tests
│   └── test_policy.py   # Policy load/validation tests
└── pyproject.toml
```

---

## Quick Start

### 1. Install dependencies

```bash
cd ai-sec-gateway
pip install -e ".[dev]"
```

Or with `uv` (faster):
```bash
uv pip install -e ".[dev]"
```

### 2. Configure environment

```bash
# Safe demo mode — no Azure credentials needed (default: true)
export MOCK_MODE=true

# To use a real Azure OpenAI deployment instead:
export MOCK_MODE=false
export AZURE_OPENAI_API_KEY="your-key"
export AZURE_OPENAI_ENDPOINT="https://<resource>.openai.azure.com"
export AZURE_OPENAI_DEPLOYMENT="gpt-4o"
export AZURE_OPENAI_API_VERSION="2024-05-01-preview"
```

### 3. Start the gateway

```bash
uvicorn app.main:app --reload
```

The server starts at **http://localhost:8000**.
Interactive docs: **http://localhost:8000/docs**

### 4. Run the demo

In a second terminal:

```bash
python examples/demo_client.py
```

Expected output summary:

| Scenario | Input | Expected Decision | Codes |
|---|---|---|---|
| 1 | "What is the capital of France?" | `ALLOW` | — |
| 2 | "Ignore previous instructions…" | `BLOCK` | PI-001 |
| 3 | Message containing `PSH_SECRET_123` + email | `REDACT` | DLP-001, DLP-002 |
| 4 | `http_fetch` → `https://evil.com/…` | `TOOL_DENY` | TOOL-001 |

### 5. Run the test suite

```bash
pytest -v
```

---

## API Reference

### `POST /v1/chat`

Guarded chat completions proxy.

**Request**
```json
{
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user",   "content": "What is 2+2?"}
  ],
  "tools": [],
  "metadata": {}
}
```

**Response**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "decision": "ALLOW",
  "reason_codes": [],
  "risk_score": 0,
  "message": {"role": "assistant", "content": "4"},
  "tool_calls": []
}
```

Possible `decision` values: `ALLOW`, `BLOCK`, `REDACT`.

---

### `POST /v1/tools/execute`

Validates a tool invocation and returns a **stubbed** response.
No real network requests are ever made.

**Request**
```json
{
  "tool": "http_fetch",
  "arguments": {
    "url": "https://api.example.com/data",
    "method": "GET",
    "headers": {},
    "body": ""
  }
}
```

**Response**
```json
{
  "id": "...",
  "decision": "ALLOW",
  "reason_codes": [],
  "result": {
    "status": 200,
    "body": "[STUBBED] Tool 'http_fetch' call to '...' was validated and stubbed.",
    "headers": {}
  }
}
```

Possible `decision` values: `ALLOW`, `REDACT`, `BLOCK`, `TOOL_DENY`.

---

### `GET /v1/audit/events?limit=50`

Returns the most recent audit events from SQLite.

---

### `POST /v1/replay/{event_id}`

Re-runs a stored audit event through the current policy.
Creates a **new** audit entry; the original is never mutated.

---

## Policy Configuration

Edit `policies/default.yaml` to tune the security controls.
The gateway validates the file on startup and **fails fast** if it is invalid.

### Injection policy

```yaml
injection:
  phrases:
    - "ignore previous instructions"
    - "jailbreak"
    # add more…
  risk_per_hit: 30       # score per matched phrase
  base_score: 0
  block_threshold: 60    # BLOCK when score >= this (e.g. 2 hits)
```

### DLP policy

```yaml
dlp:
  keywords:
    - "PSH_SECRET"       # plain-text substring match (case-insensitive)
  keyword_action: "redact"   # or "block"
  keyword_reason_code: "DLP-001"

  patterns:
    - name: "email"
      regex: '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
      action: "redact"
      reason_code: "DLP-001"
    - name: "us_ssn"
      regex: '\b\d{3}-\d{2}-\d{4}\b'
      action: "block"      # block the entire request
      reason_code: "DLP-002"
```

### Tool firewall

```yaml
tools:
  http_fetch:
    allowed_domains:
      - "api.example.com"   # exact + sub-domain matching
      - "httpbin.org"
    deny_reason_code: "TOOL-001"
```

---

## Reason Codes

| Code | Guard | Meaning |
|------|-------|---------|
| `PI-001` | Injection | Prompt injection pattern(s) detected |
| `DLP-001` | DLP | Keyword or email/phone pattern matched |
| `DLP-002` | DLP | Secret-token or SSN pattern matched (higher severity) |
| `TOOL-001` | Firewall | `http_fetch` target domain not in allowlist |
| `TOOL-002` | Firewall | Unregistered tool name |

---

## Threat Model (MVP)

### In scope

| Threat | Defence |
|--------|---------|
| **Direct prompt injection** — user tries to override system instructions | Injection guard: phrase matching + risk scoring |
| **Indirect prompt injection** — tool output contains injected instructions | Same injection guard applied to all inbound text |
| **Data exfiltration via messages** — user embeds secrets in chat | DLP guard on inbound messages |
| **Data exfiltration via LLM reply** — LLM accidentally repeats secrets | DLP guard on outbound assistant content |
| **SSRF / tool abuse** — agent calls arbitrary URLs | Tool firewall domain allowlist |
| **Audit evasion** — no visibility into what the agent did | Immutable SQLite audit log, every decision recorded |
| **Policy misconfiguration** — broken YAML deployed silently | Fail-fast validator at startup |

### Out of scope (MVP)

- **Authentication / authorisation** — no API-key or JWT enforcement on the
  gateway itself (add a reverse proxy or FastAPI middleware for production).
- **Rate limiting** — no per-client throttling.
- **Semantic / ML-based injection detection** — only rule-based phrase matching;
  adversarial paraphrasing can evade it.
- **Encrypted audit log** — events are stored in plaintext SQLite.
- **Multi-tenant isolation** — single policy applies to all callers.
- **Real network sandboxing** — tool calls are stubbed; integrating a real HTTP
  client with egress filtering is left for production hardening.
- **Adversarial robustness** — the DLP guard uses regex; sophisticated obfuscation
  (Unicode lookalike characters, Base64, etc.) is not detected.

### Production hardening checklist

- [ ] Add JWT / API-key middleware to the gateway.
- [ ] Encrypt the SQLite database at rest.
- [ ] Add an ML-based anomaly score alongside the rule-based score.
- [ ] Integrate a real HTTP sandbox (e.g. a restricted egress proxy) for tool
      calls instead of stubs.
- [ ] Centralise audit logs to a SIEM (ship SQLite rows to OpenSearch / Splunk).
- [ ] Introduce per-tenant policy namespacing.
- [ ] Add rate limiting and circuit-breaker patterns.
