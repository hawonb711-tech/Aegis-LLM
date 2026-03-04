# Aegis-LLM

A policy-driven security gateway that sits between an application and an LLM provider, enforcing guardrails on every inbound prompt and outbound response.

---

## Problem

- **Prompt injection:** adversarial instructions embedded in user input or tool output redirect model behaviour.
- **Data exfiltration:** models with access to secrets may echo them in completions or encode them in tool call arguments.
- **Unsafe tool invocation:** agentic systems that can call external URLs need an explicit domain allowlist enforced at the gateway, not inside individual tool implementations.

---

## Non-goals (MVP)

- No TLS termination — use a reverse proxy.
- No multi-tenant policy namespacing — one policy applies to all callers.
- No semantic injection detection — the injection guard is phrase-based only.
- No Unicode / encoding-attack detection (Base64, homoglyphs).
- No real network sandboxing — tool calls are stubbed; egress filtering is left for production integration.

---

## MVP scope

The gateway validates every chat request through an injection guard and a two-pass DLP guard, redacting or blocking as configured. Tool calls are checked against an explicit domain allowlist. Policy mode (default / strict) can be switched live without restart and survives process restarts via SQLite. Every decision is appended to a tamper-evident audit log. Auth (Bearer tokens, bcrypt-hashed), rate limiting, and an adaptive incident state machine are included.

---

## Quickstart

**Requirements:** Python 3.11+

```bash
# 1. Install
git clone <repo-url> aegis-llm && cd aegis-llm
pip install -e ".[dev]"

# 2. Run diagnostics
aegis doctor

# 3. Start (mock mode — no credentials needed)
export MOCK_MODE=true
aegis serve

# 4. Send a request (separate terminal)
curl -s -X POST http://localhost:8088/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"What is the capital of France?"}]}'
```

Interactive API docs: http://localhost:8088/docs

**Azure OpenAI:**
```bash
export MOCK_MODE=false
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_ENDPOINT="https://<resource>.openai.azure.com"
export AZURE_OPENAI_DEPLOYMENT="gpt-4o"
export AZURE_OPENAI_API_VERSION="2024-05-01-preview"
aegis serve
```

---

## CLI

| Command | Description |
|---------|-------------|
| `aegis doctor` | Health checks: ENV / POLICY / DATABASE / IMPORT |
| `aegis simulate` | Offline guard pipeline trace — no network, no DB writes |
| `aegis serve` | Start the gateway via uvicorn |
| `aegis run` | Run a command with `OPENAI_BASE_URL` injected |

All commands support `--help`. See [docs/RUNBOOK.md](docs/RUNBOOK.md) for operational procedures.

---

## Running tests

```bash
pytest -v
```

All tests are pure-Python unit tests. No server or external service needed.

---

## Documentation

| Document | Contents |
|----------|----------|
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Attack scenarios, mitigations, residual risk, trust boundaries |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component map, request lifecycle, data stores |
| [docs/GUARDS.md](docs/GUARDS.md) | Injection guard, DLP guard, tool firewall — algorithms and reason codes |
| [docs/POLICY.md](docs/POLICY.md) | YAML schema reference, strict-mode overrides, env vars |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Starting, mode switching, incident response, audit verification |
| [DESIGN.md](DESIGN.md) | Reasoning behind key architectural decisions |
| [SECURITY.md](SECURITY.md) | Known limitations and hardening checklist |

---

## Reason codes

| Code | Guard | Condition |
|------|-------|-----------|
| `PI-001` | Injection | Phrase score ≥ block threshold |
| `PI-SEM-001` | Injection | TF-IDF semantic score ≥ semantic threshold (when enabled) |
| `DLP-001` | DLP | Email, phone, or keyword match |
| `DLP-002` | DLP | Secret-token pattern or SSN match |
| `TOOL-001` | Firewall | `http_fetch` target domain not in allowlist |
| `TOOL-002` | Firewall | Unregistered tool name |

---

## Limitations

- Phrase-based injection detection; paraphrased payloads that avoid listed phrases are not caught.
- DLP patterns do not detect encoding attacks (Base64, homoglyphs, HTML entities).
- SQLite state is local to each process; multi-instance deployments need a shared store.
- Audit log is plaintext SQLite; the hash chain detects casual tampering but not recomputation by an attacker with DB write access.
- Tool calls are stubbed; no real HTTP egress filtering is implemented.

---

## Roadmap

1. Gateway authentication hardening — per-key rate limits, key expiry.
2. Semantic injection scoring — embedding distance as a complementary signal to phrase matching.
3. Structured output validation — JSON schema enforcement on tool arguments and LLM-generated structured responses.
4. Centralised audit export — ship chain tip to an external append-only store on rotation.
5. Real tool sandboxing — route `http_fetch` through an isolated egress proxy.
