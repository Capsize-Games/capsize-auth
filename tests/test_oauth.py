"""Tests for OAuth provider configuration and the capabilities endpoint.

The capabilities endpoint is the only OAuth route that belongs to the
core: the login/callback routes are application-owned because they create
accounts and issue tokens.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from uwuchat_auth_core import oauth as google_oauth_mod
from uwuchat_auth_core import twitch_oauth as twitch_oauth_mod

_MODULES_TO_RESTORE = (
    "uwuchat_auth_core.oauth",
    "uwuchat_auth_core.twitch_oauth",
    "uwuchat_auth_core.oauth_capabilities_routes",
)


@pytest.fixture(autouse=True)
def _restore_oauth_modules() -> Generator[None, None, None]:
    """Reload OAuth modules back to real-env state after each test.

    Tests that call ``importlib.reload()`` leave the modules reflecting
    test-specific env vars; without this, a later test that reads
    ``OAUTH_CONFIGURED`` (directly or transitively) sees stale state.
    """
    keys = (
        "AIRUNNER_GOOGLE_CLIENT_ID",
        "AIRUNNER_GOOGLE_CLIENT_SECRET",
        "AIRUNNER_TWITCH_CLIENT_ID",
        "AIRUNNER_TWITCH_CLIENT_SECRET",
    )
    originals = {key: os.environ.get(key) for key in keys}

    yield

    for key, value in originals.items():
        _restore_env(key, value)
    for name in _MODULES_TO_RESTORE:
        importlib.reload(importlib.import_module(name))


def _restore_env(key: str, value: str | None) -> None:
    """Set or delete an env var, matching the original state."""
    if value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value


def _capabilities_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Build a minimal app that includes the capabilities router."""
    from uwuchat_auth_core import oauth_capabilities_routes

    monkeypatch.delenv("AIRUNNER_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AIRUNNER_GOOGLE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AIRUNNER_TWITCH_CLIENT_ID", raising=False)
    monkeypatch.delenv("AIRUNNER_TWITCH_CLIENT_SECRET", raising=False)

    importlib.reload(google_oauth_mod)
    importlib.reload(twitch_oauth_mod)
    importlib.reload(oauth_capabilities_routes)

    app = FastAPI()
    app.include_router(
        oauth_capabilities_routes.router,
        prefix="/api/v1/auth",
    )
    return TestClient(app)


def test_capabilities_returns_false_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capabilities report false and never leak credential values."""
    response = _capabilities_client(monkeypatch).get(
        "/api/v1/auth/oauth/capabilities"
    )
    assert response.status_code == 200
    body = response.json()
    assert body == {"google": False, "twitch": False}
    for key in body:
        assert "client_id" not in key.lower()
        assert "secret" not in key.lower()


def test_capabilities_returns_true_when_google_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capabilities report google=true when Google is configured."""
    monkeypatch.setenv("AIRUNNER_GOOGLE_CLIENT_ID", "test-id")
    monkeypatch.setenv("AIRUNNER_GOOGLE_CLIENT_SECRET", "test-secret")
    monkeypatch.delenv("AIRUNNER_TWITCH_CLIENT_ID", raising=False)
    monkeypatch.delenv("AIRUNNER_TWITCH_CLIENT_SECRET", raising=False)

    from uwuchat_auth_core import oauth_capabilities_routes

    importlib.reload(google_oauth_mod)
    importlib.reload(twitch_oauth_mod)
    importlib.reload(oauth_capabilities_routes)

    app = FastAPI()
    app.include_router(
        oauth_capabilities_routes.router, prefix="/api/v1/auth"
    )
    body = TestClient(app).get(
        "/api/v1/auth/oauth/capabilities"
    ).json()
    assert body["google"] is True
    assert body["twitch"] is False


def test_capabilities_returns_true_when_twitch_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capabilities report twitch=true when Twitch is configured."""
    monkeypatch.delenv("AIRUNNER_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AIRUNNER_GOOGLE_CLIENT_SECRET", raising=False)
    monkeypatch.setenv("AIRUNNER_TWITCH_CLIENT_ID", "test-id")
    monkeypatch.setenv("AIRUNNER_TWITCH_CLIENT_SECRET", "test-secret")

    from uwuchat_auth_core import oauth_capabilities_routes

    importlib.reload(google_oauth_mod)
    importlib.reload(twitch_oauth_mod)
    importlib.reload(oauth_capabilities_routes)

    app = FastAPI()
    app.include_router(
        oauth_capabilities_routes.router, prefix="/api/v1/auth"
    )
    body = TestClient(app).get(
        "/api/v1/auth/oauth/capabilities"
    ).json()
    assert body["google"] is False
    assert body["twitch"] is True


def test_auth_url_none_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_google_auth_url returns None when credentials are absent."""
    monkeypatch.delenv("AIRUNNER_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AIRUNNER_GOOGLE_CLIENT_SECRET", raising=False)
    importlib.reload(google_oauth_mod)
    assert google_oauth_mod.get_google_auth_url() is None


def test_auth_url_built_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_google_auth_url builds a consent URL with a signed state."""
    monkeypatch.setenv("AIRUNNER_GOOGLE_CLIENT_ID", "test-id")
    monkeypatch.setenv("AIRUNNER_GOOGLE_CLIENT_SECRET", "test-secret")
    importlib.reload(google_oauth_mod)

    url = google_oauth_mod.get_google_auth_url("PROMO")
    assert url is not None
    assert url.startswith(google_oauth_mod.GOOGLE_AUTH_URL + "?")
    assert "client_id=test-id" in url
    assert "state=" in url
