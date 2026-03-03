"""
FastAPI authentication and rate-limit dependencies.

Usage
-----
    from app.auth.deps import require_user, require_admin, AuthenticatedKey

    @app.get("/v1/something")
    async def my_endpoint(key: AuthenticatedKey = Depends(require_user)):
        ...

Scope hierarchy
---------------
  user   — may call /v1/* endpoints
  admin  — may call /admin/* endpoints (and implicitly all user endpoints)

When AUTH_ENABLED=False (local dev/test), all requests receive a synthetic
bypass token with both scopes so that existing test suites work unchanged.
"""
from dataclasses import dataclass, field
from typing import List, Optional

from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader

from app import config
from app.auth import api_keys
from app.ratelimit import limiter


# Exposes "X-API-Key" in the OpenAPI schema (auto_error=False so we can
# return 401 rather than 422 when the header is missing).
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@dataclass
class AuthenticatedKey:
    """Injected into endpoint handlers after successful auth + rate-limit check."""
    key_id: str
    name: str
    scopes: List[str] = field(default_factory=list)


def _make_scope_dep(required_scope: str):
    """
    Return a FastAPI dependency function that validates the key has *required_scope*.

    Using a factory ensures each scope variant is a distinct callable —
    FastAPI's dependency cache treats them as separate dependencies.
    """
    async def _dependency(
        raw_key: Optional[str] = Depends(_api_key_header),
    ) -> AuthenticatedKey:
        # ── Dev bypass ────────────────────────────────────────────────────
        if not config.AUTH_ENABLED:
            return AuthenticatedKey(
                key_id="dev-bypass",
                name="dev-bypass",
                scopes=["admin", "user"],
            )

        # ── Presence check ────────────────────────────────────────────────
        if not raw_key:
            raise HTTPException(
                status_code=401,
                detail="Missing API key. Supply the X-API-Key header.",
            )

        # ── Key lookup ────────────────────────────────────────────────────
        key_info = api_keys.lookup_key(raw_key)
        if key_info is None:
            raise HTTPException(status_code=401, detail="Invalid API key.")

        if not key_info["is_active"]:
            raise HTTPException(status_code=403, detail="API key is disabled.")

        # ── Scope check ───────────────────────────────────────────────────
        if required_scope not in key_info["scopes"]:
            raise HTTPException(
                status_code=403,
                detail=f"API key missing required scope '{required_scope}'.",
            )

        # ── Rate limiting ─────────────────────────────────────────────────
        allowed, count, rpm_limit, retry_after = limiter.check_and_increment(
            key_info["id"], config.RATE_LIMIT_RPM
        )
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded ({count}/{rpm_limit} rpm).",
                headers={"Retry-After": str(retry_after)},
            )

        # ── Record last-used ──────────────────────────────────────────────
        api_keys.update_last_used(key_info["id"])

        return AuthenticatedKey(
            key_id=key_info["id"],
            name=key_info["name"],
            scopes=key_info["scopes"],
        )

    # Give each generated function a unique __name__ so FastAPI keeps them
    # as separate dependency nodes in its dependency graph.
    _dependency.__name__ = f"require_{required_scope}"
    return _dependency


require_user: "Depends" = _make_scope_dep("user")
require_admin: "Depends" = _make_scope_dep("admin")
