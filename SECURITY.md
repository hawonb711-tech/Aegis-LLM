# Security Policy

## Project status

Aegis-LLM is a **research MVP**. It was built to demonstrate a
security-first architecture for agentic LLM control planes and to serve
as a foundation for further work. It is not production-hardened and
should not be deployed publicly without the hardening steps described
below.

---

## Known limitations

The following limitations are known and accepted for MVP scope.

### No gateway authentication
The API endpoints have no authentication layer. Any client that can
reach port 8000 can issue requests and switch policy modes. Before
exposing this service on a network, add authentication middleware
(API key, JWT, mutual TLS) or place it behind an authenticated reverse
proxy.

### Rule-based injection detection only
The injection guard scores requests based on a configurable phrase list.
A determined adversary who knows the phrase list (or who paraphrases
known phrases) can construct payloads that score below the block
threshold. The guard is a useful first layer, not a complete defence
against a skilled attacker.

### DLP does not handle encoding or obfuscation
The DLP patterns operate on the raw string content of messages. Secrets
that are Base64-encoded, URL-percent-encoded, split across tokens, or
represented with Unicode lookalike characters will not be detected.

### SQLite state is not replicated
Policy mode is persisted to a local SQLite file. In a multi-process or
multi-host deployment, each instance maintains its own state. A mode
switch via `POST /v1/policy/mode` affects only the instance that
received the request.

### Audit log is plaintext
The `audit_events` table stores full request and response payloads in
plaintext JSON. If a request contains sensitive data that was not caught
by DLP (for example, due to an encoding bypass), that data will appear
in the audit log. Protect the database file with filesystem permissions
and consider encryption at rest for production use.

### Tool calls are stubbed
The tool execution endpoint validates and logs tool calls but does not
make real network requests. Integrating a real HTTP client with egress
filtering requires additional work and is not covered by this codebase.

### No rate limiting
There is no per-client or global rate limiting. The gateway can be
exhausted by a high volume of requests.

---

## Responsible disclosure

If you identify a security issue in this codebase, please:

1. **Do not open a public GitHub issue** for vulnerabilities that could
   affect users of this project or downstream systems.
2. Send a description of the issue to the repository maintainer via
   GitHub's private security advisory feature, or by direct message.
3. Include: a description of the vulnerability, reproduction steps, and
   your assessment of impact.
4. Allow reasonable time (14 days) for acknowledgement before public
   disclosure.

Because this is a research MVP, the scope of what constitutes a
"security issue" is limited. We are primarily interested in:

- Logic errors in guard ordering or escalation rules that would allow a
  bypass in a deployed system.
- Incorrect DLP redaction that silently fails to remove sensitive data.
- Dependency vulnerabilities in the packages listed in `pyproject.toml`.

We are not in scope for: performance issues, UI concerns, or issues that
only apply if the attacker already has write access to the host.

---

## Hardening checklist (before any production use)

- [ ] Add authentication middleware to all API endpoints.
- [ ] Restrict network access to the gateway to trusted callers only.
- [ ] Encrypt the SQLite database file at rest.
- [ ] Set filesystem permissions on `policies/default.yaml` to prevent
      unauthorised modification.
- [ ] Replace phrase-based injection scoring with an additional semantic
      signal (embedding distance, fine-tuned classifier).
- [ ] Implement rate limiting per API key.
- [ ] Add structured logging to a centralised SIEM instead of local SQLite.
- [ ] Rotate and scope the Azure OpenAI API key to minimum necessary
      permissions.
- [ ] Run the gateway process as a non-root user in a minimal container.
