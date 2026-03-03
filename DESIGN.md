# Aegis-LLM — Design Notes

This document records the reasoning behind key architectural decisions.
It is intended for reviewers and future contributors, not end users.

---

## 1. Why policy overrides are applied at runtime rather than at load time

The naive approach to supporting multiple policy modes is to maintain
separate YAML files and reload the process when switching. This has two
problems:

- **Operational friction.** A restart involves downtime and loses in-flight
  requests. In an incident scenario, the last thing an operator wants is
  to restart the gateway.

- **Tight coupling between deployment and policy.** If the active mode
  is encoded in a config file, changing it requires a file write and
  process restart. This conflates two concerns: what the policy says
  (static YAML) and what the current operational posture is (runtime
  state).

Aegis-LLM separates these. The YAML defines the base policy; the runtime
`_active_mode` variable selects which overlay to apply. `get_effective_policy()`
is called per-request and applies overrides on top of a deep copy of the base
policy. The cost is a shallow object copy per request; in practice this is
negligible compared to LLM round-trip latency.

The concrete consequence: switching from `default` to `strict` takes a
single API call and is reflected on the very next request, without touching
files or restarting processes.

```
policies/default.yaml      _STRICT_OVERRIDES (code)
        │                          │
        └──────────┬───────────────┘
                   │
           get_effective_policy()   ← called per request
                   │
           active policy object
```

---

## 2. Why policy mode state is persisted in SQLite

The active mode is runtime state, not configuration. It changes in
response to events (an operator command, an automated trigger) and must
survive process restarts — otherwise a server crash or deployment during
an incident would silently reset the posture to `default`.

Options considered:

| Option | Problem |
|--------|---------|
| Environment variable | Cannot be updated without restarting the process or using a sidecar. |
| Separate config file | Requires file-system write access and introduces a second source of truth alongside the YAML. |
| External key-value store (Redis, etcd) | Adds a required infrastructure dependency for a single boolean. |
| Same SQLite database already used for audit | No new dependency; the database file is already opened on every request. |

SQLite was chosen because:
1. It is already a runtime dependency (audit logging).
2. A `gateway_state` key/value table is trivially added via `CREATE TABLE IF NOT EXISTS`.
3. The upsert (`INSERT … ON CONFLICT DO UPDATE`) is a single atomic write.
4. The read on startup is a single indexed lookup by primary key.

The trade-off is that SQLite does not replicate across processes. In a
multi-instance deployment, each replica would maintain its own state and
a load balancer could route requests to instances with different active
modes. For MVP scope this is acceptable; a production deployment would
replace this with a shared store.

---

## 3. Why strict mode uses redact (not block) for DLP keyword hits

In `default` mode, a DLP keyword match (`api_key`, `PSH_SECRET`, etc.)
triggers a redaction — the sensitive substring is replaced with
`[REDACTED]` and the request is served. This is appropriate for user
messages where the user may be legitimately discussing credential
management without intending to exfiltrate a live secret.

The original design set `keyword_action: "block"` in strict mode. This
was revised for two reasons:

**Service continuity.** Blocking on any keyword hit would cause
legitimate operational queries — a developer asking "why did my api_key
rotation fail?" — to return HTTP 200 with a BLOCK body, making the
gateway appear broken from the client's perspective during an incident.
This is exactly when operators need the system to be predictable.

**Defence-in-depth ordering.** The keyword list catches partial matches
that the regex patterns may not. If a user message contains a live secret,
the regex pattern (e.g. `\b[A-Z][A-Z0-9]{2,}_[A-Z0-9][A-Z0-9_]{2,}\b`)
is the first-pass detector and redacts the value before forwarding. The
keyword list is a secondary net. Blocking at the keyword level is
disproportionate to the risk differential between the two passes.

**What strict mode does instead.** In strict mode, the meaningful
escalation is on the injection guard (threshold drops from 60 → 30,
making a single suspicious phrase sufficient to BLOCK) and on the tool
firewall (all HTTP egress is denied regardless of domain). These are the
controls that matter most during an active incident involving a suspected
prompt injection campaign.

The design rule is: **block when you can attribute the risk precisely;
redact when you can mitigate the risk without disrupting service.**

---

## 4. Why the tool firewall uses default-deny

The standard posture for network firewalls is default-deny: only
explicitly listed destinations are reachable. The same principle applies
here, for the same reason.

An agentic system's tool invocations are not fully enumerable at design
time. New tools get added, tool implementations change, and model
behaviour drifts. If the firewall allowed any domain not on a deny list,
a single omission — forgetting to add `evil.com` — would be exploitable.
An allowlist forces the operator to make an explicit decision for every
external destination.

Concretely, the gateway enforces:

```python
# firewall/tools.py
if _domain_allowed(hostname, policy.http_fetch.allowed_domains):
    return FirewallResult(decision="ALLOW", ...)

return FirewallResult(decision="TOOL_DENY", reason_codes=["TOOL-001"], ...)
```

Unknown tool names (anything other than `http_fetch` in the current
policy) also return `TOOL_DENY` with `TOOL-002`. This means adding a
new tool requires both an implementation and an explicit firewall entry —
the gate and the policy must both change.

In `strict` mode, `allowed_domains` is overridden to `[]`, making the
firewall deny all HTTP egress regardless of what the YAML says. This is
intentional: during a suspected incident, stopping all outbound model-
initiated network calls is a higher priority than preserving tool
functionality.

---

## Guard pipeline — implementation notes

The guard pipeline in `app/main.py` is intentionally sequential, not
concurrent. Each stage may modify the data that the next stage receives:

```
1. check_injection(full_text)     → decision: BLOCK or continue
2. apply_dlp(msg.content)         → redacted_messages (modified input)
3. call_provider(redacted_messages) → provider_response
4. apply_dlp(provider_response)   → final_content (modified output)
5. check_tool(tool, arguments)    → decision: TOOL_DENY or continue
```

If stages 2 and 4 were parallelised, stage 4 would need access to the
provider response that stage 3 has not yet produced. The sequential order
is a functional requirement, not a performance choice.

The DLP guard itself runs patterns before keywords within each pass (see
`guards/dlp.py`). This ensures that a regex match on a full token (e.g.
`PSH_SECRET_123`) replaces the entire token before the keyword `PSH_SECRET`
can partially match the already-redacted output.

---

## Policy validation — fail-fast at startup

All policy loading goes through Pydantic models with explicit validators:

- `block_threshold` must be > 0
- `risk_per_hit` must be ≥ 0
- Every DLP pattern `action` must be `"redact"` or `"block"`
- Every DLP pattern `regex` must compile without error
- `keyword_action` must be `"redact"` or `"block"`

If the YAML is invalid, `load_policy()` raises before the FastAPI
application finishes starting. This is intentional: a misconfigured
gateway that starts silently applying wrong rules is more dangerous than
a gateway that refuses to start.

---

## What this design does not solve

- **Semantic attacks.** A paraphrased injection payload that avoids all
  listed phrases will pass the injection guard. Phrase-based scoring is
  a useful first layer but not a complete defence.
- **Timing attacks on DLP.** The time to process a request varies with
  the number of regex matches. An adversary who can observe response
  latency could infer whether a given input triggered the DLP guard.
- **Policy file integrity.** If an attacker can write to
  `policies/default.yaml`, they can set `block_threshold` to a very high
  value and effectively disable injection detection. The policy file
  should be treated as a trusted configuration artifact and protected
  accordingly.
