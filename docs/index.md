# Aegis-LLM Documentation

Reference material for the Aegis-LLM security gateway.

| Document | What it covers |
|----------|---------------|
| [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, attack scenarios, mitigations, residual risk, and trust boundaries |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Component overview, request lifecycle, data stores, and module map |
| [GUARDS.md](GUARDS.md) | Injection guard, DLP guard, and tool firewall — algorithms, reason codes, and escalation rules |
| [POLICY.md](POLICY.md) | YAML schema reference, strict-mode overrides, environment variables, and policy resolution order |
| [RUNBOOK.md](RUNBOOK.md) | Day-2 operations: starting the gateway, mode switching, incident response, API key management, audit verification |

For code-level reasoning behind key decisions see [DESIGN.md](../DESIGN.md).
For known limitations and hardening checklist see [SECURITY.md](../SECURITY.md).
