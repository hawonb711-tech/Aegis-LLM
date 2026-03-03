"""
Central configuration loaded from environment variables.
All tunables live here so nothing is scattered across modules.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

POLICY_PATH: Path = Path(os.getenv("POLICY_PATH", str(BASE_DIR / "policies" / "default.yaml")))
DB_PATH: Path = Path(os.getenv("DB_PATH", str(BASE_DIR / "audit.db")))

# ── Mock mode ────────────────────────────────────────────────────────────────
# Set MOCK_MODE=true to skip real Azure OpenAI calls (default: true for safety)
MOCK_MODE: bool = os.getenv("MOCK_MODE", "true").lower() in ("1", "true", "yes")

# ── Azure OpenAI ─────────────────────────────────────────────────────────────
AZURE_OPENAI_API_KEY: str = os.getenv("AZURE_OPENAI_API_KEY", "")
AZURE_OPENAI_ENDPOINT: str = os.getenv("AZURE_OPENAI_ENDPOINT", "")
AZURE_OPENAI_DEPLOYMENT: str = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
AZURE_OPENAI_API_VERSION: str = os.getenv("AZURE_OPENAI_API_VERSION", "2024-05-01-preview")

# ── Auth ─────────────────────────────────────────────────────────────────────
# If set, this plaintext key is hashed and seeded as an admin key on first run
# (only when the api_keys table has no admin keys). Never logged, never stored raw.
AEGIS_ADMIN_KEY: str = os.getenv("AEGIS_ADMIN_KEY", "")

# Set to "false" only for local dev/test — never in production.
AUTH_ENABLED: bool = os.getenv("AUTH_ENABLED", "true").lower() not in ("0", "false", "no")

# ── Rate limiting ─────────────────────────────────────────────────────────────
# Per-key fixed-window rate limits (requests per minute).
RATE_LIMIT_RPM: int = int(os.getenv("RATE_LIMIT_RPM", "60"))
