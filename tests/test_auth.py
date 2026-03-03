"""
Tests for API key authentication and per-key rate limiting.

Uses the `admin_key_and_client` fixture (AUTH_ENABLED=True) to exercise
the full auth stack including scope enforcement and fixed-window rate limits.
"""
import pytest


# ── 401 / 403 / 429 response scenarios ───────────────────────────────────────

def test_missing_key_returns_401(admin_key_and_client):
    """Request with no X-API-Key header must return 401."""
    client, admin_key, user_key = admin_key_and_client
    resp = client.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert resp.status_code == 401


def test_invalid_key_returns_401(admin_key_and_client):
    """Request with a garbage key must return 401."""
    client, admin_key, user_key = admin_key_and_client
    resp = client.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
        headers={"X-API-Key": "aegis_notavalidkey1234567890abcdef"},
    )
    assert resp.status_code == 401


def test_user_key_allows_v1_chat(admin_key_and_client):
    """A valid user-scope key must be accepted on /v1/chat."""
    client, admin_key, user_key = admin_key_and_client
    resp = client.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
        headers={"X-API-Key": user_key},
    )
    assert resp.status_code == 200


def test_user_key_denied_on_admin_endpoint(admin_key_and_client):
    """A user-scope key must be rejected (403) on /admin/* endpoints."""
    client, admin_key, user_key = admin_key_and_client
    resp = client.get("/admin/keys", headers={"X-API-Key": user_key})
    assert resp.status_code == 403


def test_admin_key_allows_admin_endpoint(admin_key_and_client):
    """An admin-scope key must be accepted on /admin/keys."""
    client, admin_key, user_key = admin_key_and_client
    resp = client.get("/admin/keys", headers={"X-API-Key": admin_key})
    assert resp.status_code == 200


def test_admin_key_also_allows_v1_endpoint(admin_key_and_client):
    """An admin key (which has 'user' scope) can call /v1/chat."""
    client, admin_key, user_key = admin_key_and_client
    resp = client.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
        headers={"X-API-Key": admin_key},
    )
    assert resp.status_code == 200


def test_disabled_key_returns_403(admin_key_and_client):
    """A disabled key must return 403."""
    from app.auth import api_keys

    client, admin_key, user_key = admin_key_and_client
    key_info = api_keys.lookup_key(user_key)
    api_keys.disable_key(key_info["id"])

    resp = client.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
        headers={"X-API-Key": user_key},
    )
    assert resp.status_code == 403


def test_rate_limit_returns_429(admin_key_and_client, monkeypatch):
    """Exceeding RATE_LIMIT_RPM in the same window must return 429."""
    import app.config as cfg
    monkeypatch.setattr(cfg, "RATE_LIMIT_RPM", 3)

    client, admin_key, user_key = admin_key_and_client

    # First 3 requests should succeed.
    for _ in range(3):
        resp = client.post(
            "/v1/chat",
            json={"messages": [{"role": "user", "content": "hi"}]},
            headers={"X-API-Key": user_key},
        )
        assert resp.status_code == 200

    # 4th request must be rate-limited.
    resp = client.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "hi"}]},
        headers={"X-API-Key": user_key},
    )
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


def test_rate_limit_is_per_key(admin_key_and_client, monkeypatch):
    """Rate limit is per-key: exhausting one key does not affect another."""
    import app.config as cfg
    monkeypatch.setattr(cfg, "RATE_LIMIT_RPM", 2)

    client, admin_key, user_key = admin_key_and_client

    # Exhaust user_key.
    for _ in range(2):
        client.post(
            "/v1/chat",
            json={"messages": [{"role": "user", "content": "x"}]},
            headers={"X-API-Key": user_key},
        )
    resp = client.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "x"}]},
        headers={"X-API-Key": user_key},
    )
    assert resp.status_code == 429

    # admin_key should still work.
    resp = client.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "x"}]},
        headers={"X-API-Key": admin_key},
    )
    assert resp.status_code == 200


# ── Key CRUD via HTTP endpoints ───────────────────────────────────────────────

def test_list_keys_returns_existing(admin_key_and_client):
    """GET /admin/keys must list the keys we created in the fixture."""
    client, admin_key, user_key = admin_key_and_client
    resp = client.get("/admin/keys", headers={"X-API-Key": admin_key})
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] >= 2  # admin + user key
    # key_hash must not appear in the response.
    for k in data["keys"]:
        assert "key_hash" not in k


def test_create_key_returns_plaintext_once(admin_key_and_client):
    """POST /admin/keys must return the plaintext key exactly once."""
    client, admin_key, user_key = admin_key_and_client
    resp = client.post(
        "/admin/keys",
        json={"name": "ci-runner", "scopes": ["user"]},
        headers={"X-API-Key": admin_key},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["key"].startswith("aegis_")
    assert data["key_id"]
    assert "warning" in data


def test_create_key_invalid_scope_returns_400(admin_key_and_client):
    """POST /admin/keys with an unknown scope must return 400."""
    client, admin_key, user_key = admin_key_and_client
    resp = client.post(
        "/admin/keys",
        json={"name": "bad", "scopes": ["superadmin"]},
        headers={"X-API-Key": admin_key},
    )
    assert resp.status_code == 400


def test_rotate_key_old_key_invalid(admin_key_and_client):
    """After rotating, the old plaintext key must no longer authenticate."""
    from app.auth import api_keys

    client, admin_key, user_key = admin_key_and_client
    user_info = api_keys.lookup_key(user_key)

    resp = client.post(
        f"/admin/keys/{user_info['id']}/rotate",
        headers={"X-API-Key": admin_key},
    )
    assert resp.status_code == 200
    new_key = resp.json()["key"]
    assert new_key != user_key

    # Old key should now return 401.
    resp = client.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "hi"}]},
        headers={"X-API-Key": user_key},
    )
    assert resp.status_code == 401

    # New key should work.
    resp = client.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "hi"}]},
        headers={"X-API-Key": new_key},
    )
    assert resp.status_code == 200


def test_disable_key_via_http(admin_key_and_client):
    """POST /admin/keys/{id}/disable must deactivate the key."""
    from app.auth import api_keys

    client, admin_key, user_key = admin_key_and_client
    user_info = api_keys.lookup_key(user_key)

    resp = client.post(
        f"/admin/keys/{user_info['id']}/disable",
        headers={"X-API-Key": admin_key},
    )
    assert resp.status_code == 200
    assert resp.json()["disabled"] is True

    # Key must now return 403.
    resp = client.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "hi"}]},
        headers={"X-API-Key": user_key},
    )
    assert resp.status_code == 403


def test_rotate_nonexistent_key_returns_404(admin_key_and_client):
    """POST /admin/keys/{id}/rotate for a non-existent key must return 404."""
    client, admin_key, user_key = admin_key_and_client
    resp = client.post(
        "/admin/keys/00000000-0000-0000-0000-000000000000/rotate",
        headers={"X-API-Key": admin_key},
    )
    assert resp.status_code == 404


def test_disable_nonexistent_key_returns_404(admin_key_and_client):
    """POST /admin/keys/{id}/disable for a non-existent key must return 404."""
    client, admin_key, user_key = admin_key_and_client
    resp = client.post(
        "/admin/keys/00000000-0000-0000-0000-000000000000/disable",
        headers={"X-API-Key": admin_key},
    )
    assert resp.status_code == 404


def test_bootstrap_admin_key_from_env(isolated_db, monkeypatch):
    """AEGIS_ADMIN_KEY env var bootstraps a working admin key on first run."""
    import app.config as cfg
    import app.policy as policy_mod
    import app.incident.state as inc_state
    from app.auth import api_keys

    test_key = "aegis_testbootstrapkey0000000000000000000000000000"
    monkeypatch.setattr(cfg, "AUTH_ENABLED", True)
    monkeypatch.setattr(cfg, "AEGIS_ADMIN_KEY", test_key)
    monkeypatch.setattr(policy_mod, "_policy", None)
    monkeypatch.setattr(policy_mod, "_active_mode", "default")
    monkeypatch.setattr(inc_state, "_current_state", inc_state.IncidentState.NORMAL)

    from app.main import app as fastapi_app
    from fastapi.testclient import TestClient
    with TestClient(fastapi_app) as client:
        # The bootstrap key should authenticate as admin.
        resp = client.get("/admin/keys", headers={"X-API-Key": test_key})
        assert resp.status_code == 200
