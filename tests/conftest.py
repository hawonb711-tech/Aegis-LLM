"""
Shared pytest fixtures for integration tests.

Design
------
- `isolated_db`        — patches config.DB_PATH to a per-test temp file
- `test_client`        — TestClient with AUTH_ENABLED=False (dev bypass)
- `admin_key_and_client` — TestClient with AUTH_ENABLED=True + pre-created keys

The three existing test modules (test_guards, test_policy, test_semantic) are
pure-unit tests that do not use any of these fixtures and are not affected.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def isolated_db(monkeypatch, tmp_path):
    """Redirect every sqlite3 open to a fresh per-test database."""
    db = tmp_path / "test_aegis.db"
    import app.config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", db)
    return db


@pytest.fixture
def test_client(isolated_db, monkeypatch):
    """
    Synchronous TestClient with AUTH_ENABLED=False.

    The FastAPI lifespan runs on entry, initialising all DB tables.
    All module-level singletons are reset via monkeypatch so tests are
    fully independent of each other.
    """
    import app.config as cfg
    import app.policy as policy_mod
    import app.incident.state as inc_state

    monkeypatch.setattr(cfg, "AUTH_ENABLED", False)
    monkeypatch.setattr(policy_mod, "_policy", None)
    monkeypatch.setattr(policy_mod, "_active_mode", "default")
    monkeypatch.setattr(inc_state, "_current_state", inc_state.IncidentState.NORMAL)

    from app.main import app as fastapi_app
    with TestClient(fastapi_app) as client:
        yield client


@pytest.fixture
def admin_key_and_client(isolated_db, monkeypatch):
    """
    TestClient with AUTH_ENABLED=True and pre-created admin + user keys.

    Yields (client, admin_plaintext_key, user_plaintext_key).
    """
    import app.config as cfg
    import app.policy as policy_mod
    import app.incident.state as inc_state
    from app.auth import api_keys

    monkeypatch.setattr(cfg, "AUTH_ENABLED", True)
    monkeypatch.setattr(cfg, "RATE_LIMIT_RPM", 10)
    monkeypatch.setattr(policy_mod, "_policy", None)
    monkeypatch.setattr(policy_mod, "_active_mode", "default")
    monkeypatch.setattr(inc_state, "_current_state", inc_state.IncidentState.NORMAL)

    from app.main import app as fastapi_app
    with TestClient(fastapi_app) as client:
        # Lifespan has run — DB tables exist.
        admin_key, _ = api_keys.create_key("test-admin", ["admin", "user"])
        user_key, _ = api_keys.create_key("test-user", ["user"])
        yield client, admin_key, user_key
