# Policy Reference — Aegis-LLM

This document describes the policy YAML schema, how the policy is loaded and validated, the strict-mode overrides, and how the active policy is resolved at runtime.

---

## Policy file format

The default policy is at `policies/default.yaml`. A custom path can be specified via the `POLICY_PATH` environment variable or the `--policy` flag on any CLI command.

The full schema with all fields and their types:

```yaml
injection:
  phrases: List[str]           # phrases that indicate injection attempts (lowercase)
  risk_per_hit: int            # score added per matched phrase (>= 0)
  base_score: int              # baseline score applied before phrase matching
  block_threshold: int         # block when risk_score >= this value (must be > 0)
  semantic_enabled: bool       # enable TF-IDF semantic layer (default: false)
  semantic_threshold: int      # semantic score (0-100) to emit PI-SEM-001 (default: 80)

dlp:
  keywords: List[str]          # plain-text strings; case-insensitive matching
  keyword_action: str          # "redact" or "block"
  keyword_reason_code: str     # reason code emitted on keyword match

  patterns:
    - name: str                # human-readable label (not used in matching)
      regex: str               # Python re-compatible regular expression
      action: str              # "redact" or "block"
      reason_code: str         # reason code emitted on pattern match

tools:
  http_fetch:
    allowed_domains: List[str]  # exact hostnames or domain suffixes
    deny_reason_code: str       # reason code emitted on domain deny

incident:
  window_seconds: int           # rolling window for promotion counters (default: 300)
  high_risk_min: int            # risk_score >= this counts as "high risk" (default: 60)
  promote_on_blocks: int        # BLOCK decisions in window -> STRICT (default: 3)
  promote_on_pi_events: int     # PI-001/PI-SEM-001 hits in window -> STRICT (default: 2)
  promote_on_high_risk: int     # high-risk events in window -> STRICT (default: 5)
  cooldown_seconds: int         # minimum time in STRICT before demotion (default: 600)
  stability_window_seconds: int # no high-risk events in this window -> demote (default: 300)
```

---

## Default policy values

| Section | Field | Default | Notes |
|---------|-------|---------|-------|
| injection | block_threshold | 60 | Two phrase hits trigger a block |
| injection | risk_per_hit | 30 | |
| injection | base_score | 0 | |
| injection | semantic_enabled | false | TF-IDF layer disabled |
| injection | semantic_threshold | 80 | Ignored when disabled |
| dlp | keyword_action | redact | |
| dlp | keyword_reason_code | DLP-001 | |
| dlp.patterns[us_ssn] | action | block | SSN match is a hard block |
| tools.http_fetch | allowed_domains | 4 domains | See default.yaml |
| incident | window_seconds | 300 | 5-minute rolling window |
| incident | promote_on_blocks | 3 | |
| incident | promote_on_pi_events | 2 | |
| incident | cooldown_seconds | 600 | 10 minutes in STRICT before demotion |

---

## Validation

Policy validation runs at startup (or when `aegis doctor` runs its `POLICY` checks). The Pydantic models enforce:

| Constraint | Field |
|------------|-------|
| `block_threshold > 0` | `injection.block_threshold` |
| `risk_per_hit >= 0` | `injection.risk_per_hit` |
| `semantic_threshold in [0, 100]` | `injection.semantic_threshold` |
| `action in ("redact", "block")` | `dlp.patterns[*].action`, `dlp.keyword_action` |
| `regex` compiles without error | `dlp.patterns[*].regex` |
| All `incident.*` fields > 0 | All incident thresholds |

A validation failure causes the gateway to refuse to start (or `aegis doctor` to report a FAIL check). This is intentional — a misconfigured gateway that silently applies wrong rules is more dangerous than one that fails visibly.

---

## Strict mode overrides

`strict` mode applies hardcoded overrides on top of the base policy. The YAML file is never modified. Overrides take effect on the next request after the mode switch.

| Field | Default mode | Strict mode | Effect |
|-------|--------------|-------------|--------|
| `injection.block_threshold` | 60 (from YAML) | **30** | A single phrase hit triggers BLOCK |
| `dlp.keyword_action` | redact (from YAML) | redact | No change (service continuity, see DESIGN.md §3) |
| `tools.http_fetch.allowed_domains` | from YAML | **[]** | All HTTP egress denied |

Source: `app/policy.py:_STRICT_OVERRIDES`

---

## Policy resolution at runtime

`get_effective_policy()` is called per-request:

```
_active_mode == "default"
  → return _policy  (base singleton, no copy)

_active_mode == "strict"
  → p = _policy.model_copy(deep=True)
  → apply _STRICT_OVERRIDES to p
  → return p
```

The deep copy ensures strict overrides on one request do not affect concurrent requests that are mid-pipeline.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POLICY_PATH` | `policies/default.yaml` | Path to the active policy YAML |
| `DB_PATH` | `audit.db` | Path to the SQLite database |
| `MOCK_MODE` | `true` | `false` to use real Azure OpenAI |
| `AUTH_ENABLED` | `true` | `false` to disable Bearer token auth (dev only) |
| `AEGIS_ADMIN_KEY` | — | Bootstraps an admin API key on startup |
| `AZURE_OPENAI_API_KEY` | — | Required when `MOCK_MODE=false` |
| `AZURE_OPENAI_ENDPOINT` | — | Required when `MOCK_MODE=false` |
| `AZURE_OPENAI_DEPLOYMENT` | — | Required when `MOCK_MODE=false` |
| `AZURE_OPENAI_API_VERSION` | — | Required when `MOCK_MODE=false` |
| `RATE_LIMIT_RPM` | `60` | Per-key requests per minute limit |

---

## Policy path resolution order

All CLI commands and the runtime resolve the policy file in the same priority order:

1. `--policy PATH` flag (CLI only)
2. `POLICY_PATH` environment variable
3. `app.config.POLICY_PATH` compiled default (`policies/default.yaml`)

The `--policy` flag sets `POLICY_PATH` in `os.environ` before the server or checks run, so env-var-aware code always sees the override.

---

## Adding a custom policy

1. Copy `policies/default.yaml` to `policies/my-policy.yaml`.
2. Edit the values you want to change.
3. Validate before deployment: `aegis doctor --policy policies/my-policy.yaml`
4. Start with: `aegis serve --policy policies/my-policy.yaml`

The policy file must remain valid YAML with all required fields present. Optional fields (`semantic_enabled`, `incident.*`) use safe defaults when absent.
