"""Functional tests for the JWT authentication middleware.

Unlike the source suite — whose middleware tests all skipped without an
external PostgreSQL — these run against the bundled SQLite reference
backend, so the middleware contract is actually exercised.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from uwuchat_auth_core.jwt import create_access_token, create_refresh_token
from uwuchat_auth_core.middleware import DEFAULT_PUBLIC_PATHS, register
from uwuchat_auth_core.models import Account
from uwuchat_auth_core.storage import get_backend


def _make_account(
    backend,
    account_id: int,
    **overrides: object,
) -> None:
    """Insert an account row so status checks find it."""
    with backend.public_session_scope() as session:
        session.add(
            Account(
                id=account_id,
                email=f"user{account_id}@example.test",
                username=f"user{account_id}",
                tenant_schema=backend.tenant_schema_for_key(
                    f"user{account_id}"
                ),
                **overrides,
            )
        )


def _minimal_app(public_paths=None) -> FastAPI:
    """Build a minimal app with the auth middleware and a route."""
    app = FastAPI()

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/v1/protected")
    async def protected_route():
        return {"tenant": get_backend().get_tenant_key()}

    if public_paths is None:
        register(app)
    else:
        register(app, public_paths=public_paths)
    return app


def test_no_auth_header_rejected(_db) -> None:
    """A request with no Authorization header gets 401."""
    response = TestClient(_minimal_app()).get("/api/v1/protected")
    assert response.status_code == 401
    assert "Missing or invalid Authorization header" in response.text


def test_health_endpoint_no_auth(_db) -> None:
    """The /health endpoint is public."""
    response = TestClient(_minimal_app()).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_invalid_token_rejected(_db) -> None:
    """A garbage Bearer token gets 401."""
    response = TestClient(_minimal_app()).get(
        "/api/v1/protected",
        headers={"Authorization": "Bearer not-a-valid-jwt"},
    )
    assert response.status_code == 401
    assert "Invalid or expired token" in response.text


def test_refresh_token_rejected_on_protected_route(_db) -> None:
    """A refresh token is rejected on an access-token route."""
    response = TestClient(_minimal_app()).get(
        "/api/v1/protected",
        headers={"Authorization": f"Bearer {create_refresh_token(1)}"},
    )
    assert response.status_code == 401
    assert "Invalid or expired token" in response.text


def test_valid_token_attaches_tenant_context(_db) -> None:
    """A valid access token activates the tenant context for the route."""
    _make_account(_db, 1)
    token = create_access_token(1, "tenant_userscope")
    response = TestClient(_minimal_app()).get(
        "/api/v1/protected",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["tenant"] == "userscope"


def test_tenant_context_cleared_after_request(_db) -> None:
    """The tenant context does not leak once the request finishes."""
    _make_account(_db, 1)
    client = TestClient(_minimal_app())
    token = create_access_token(1, "tenant_userscope")
    client.get(
        "/api/v1/protected",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_backend().get_tenant_key() is None


def test_extra_public_path_can_be_added(_db) -> None:
    """A caller-supplied path joins the public set."""
    paths = DEFAULT_PUBLIC_PATHS | {"/api/v1/embed/text"}
    result = TestClient(_minimal_app(paths)).post(
        "/api/v1/embed/text", json={"texts": ["hello"]}
    )
    # The route does not exist on the minimal app, but reaching the
    # router (404) rather than the middleware's 401 proves it was public.
    assert result.status_code == 404


def test_query_param_token_rejected_on_plain_http(_db) -> None:
    """A ?token= token is only honoured on WebSocket upgrades."""
    _make_account(_db, 1)
    token = create_access_token(1, "tenant_userscope")
    response = TestClient(_minimal_app()).get(
        f"/api/v1/protected?token={token}"
    )
    assert response.status_code == 401


def test_deleted_account_rejected(_db) -> None:
    """A deleted account's access token is rejected (fail closed)."""
    _make_account(_db, 1, deleted=True)
    token = create_access_token(1, "tenant_userscope")
    response = TestClient(_minimal_app()).get(
        "/api/v1/protected",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert "Account not found" in response.text


def test_banned_account_rejected(_db) -> None:
    """A banned account gets 403."""
    _make_account(_db, 1, is_banned=True)
    token = create_access_token(1, "tenant_userscope")
    response = TestClient(_minimal_app()).get(
        "/api/v1/protected",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert "banned" in response.text


def test_stale_token_version_rejected(_db) -> None:
    """A token older than the account's token_version is revoked."""
    _make_account(_db, 1, token_version=5)
    token = create_access_token(1, "tenant_userscope", token_version=0)
    response = TestClient(_minimal_app()).get(
        "/api/v1/protected",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert "revoked" in response.text
