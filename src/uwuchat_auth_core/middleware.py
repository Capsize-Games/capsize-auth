"""JWT authentication middleware.

Extracts and validates the Bearer token on every request except the
public paths, then sets ``request.state.account_id`` and activates the
tenant context through the installed
:class:`~uwuchat_auth_core.storage.AuthStorageBackend`.  Failures return
401/403 before the route runs.

The middleware also fails closed on a deleted, banned or suspended
account and rejects access tokens older than the account's
``token_version`` (logout / password change revocation).
"""

from __future__ import annotations

from typing import Iterable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from uwuchat_auth_core.account_status import (
    STATUS_BANNED,
    STATUS_DELETED,
    STATUS_SUSPENDED,
    check_account_status,
)
from uwuchat_auth_core.crypto.dek_cache import (
    cache_get,
    cache_touch,
    reset_user_dek,
    set_user_dek,
)
from uwuchat_auth_core.jwt import decode_token
from uwuchat_auth_core.limiter import limiter
from uwuchat_auth_core.storage import get_backend

DEFAULT_PUBLIC_PATHS: frozenset[str] = frozenset({
    "/health",
    "/api/v1/health",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/refresh",
    "/api/v1/auth/verify",
    "/api/v1/auth/oauth/google/login",
    "/api/v1/auth/oauth/google/callback",
    "/api/v1/auth/oauth/twitch/login",
    "/api/v1/auth/oauth/twitch/callback",
    "/api/v1/auth/oauth/capabilities",
    "/api/v1/auth/oauth/exchange",
})
"""Paths reachable without a token.  Override per application."""

_SUSPENDED_SAFE_PREFIXES = (
    "/api/v1/auth/me",
    "/api/v1/auth/refresh",
    "/api/v1/auth/logout",
    "/api/v1/auth/verify",
)

_STATUS_MESSAGES: dict[str, tuple[int, str]] = {
    STATUS_DELETED: (401, "Account not found"),
    STATUS_BANNED: (403, "Account banned"),
    STATUS_SUSPENDED: (
        403,
        "Your account has been suspended. Please contact support.",
    ),
}


def _error(status_code: int, message: str) -> JSONResponse:
    """Return a JSON error response in the middleware's shape."""
    return JSONResponse(
        status_code=status_code,
        content={"error": message},
    )


def _is_suspended_safe_path(path: str) -> bool:
    """Return True for auth endpoints suspended users may still use."""
    return any(path.startswith(p) for p in _SUSPENDED_SAFE_PREFIXES)


def _extract_token(request: Request) -> str | None:
    """Return the request's bearer token, or ``None``.

    The ``?token=`` fallback is accepted only on WebSocket upgrades:
    browsers cannot set headers on the handshake.  Plain HTTP requests
    must use the Authorization header, since a query-string token leaks
    into proxy logs, history and Referer headers.
    """
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    if (
        request.scope.get("type") == "websocket"
        and request.query_params.get("token")
    ):
        return request.query_params["token"]
    return None


def _tenant_key_for(payload: dict) -> str | None:
    """Resolve the raw tenant key carried by an access token."""
    schema = payload.get("tenant", "")
    key = get_backend().tenant_key_from_schema(schema)
    return key or None


def _guard_status(request: Request, payload: dict, account_id: int):
    """Return an error response when the account/token is not valid.

    Returns ``None`` when the request may proceed.  Fails closed with a
    503 when the status lookup itself fails.
    """
    try:
        status, db_version = check_account_status(account_id)
    except RuntimeError:
        return _error(
            503,
            "Service temporarily unavailable — please try again shortly.",
        )

    entry = _STATUS_MESSAGES.get(status or "")
    if entry is not None:
        code, message = entry
        blocked = status != STATUS_SUSPENDED or not _is_suspended_safe_path(
            request.url.path
        )
        if blocked:
            return _error(code, message)

    if int(payload.get("ver", 0)) < db_version:
        return _error(
            401, "Token has been revoked (logout or password change)"
        )
    return None


async def _auth_middleware_impl(
    request: Request,
    call_next,
    public_paths: Iterable[str],
):
    """Run the auth middleware for one request."""
    if request.url.path in public_paths or request.method == "OPTIONS":
        return await call_next(request)

    token = _extract_token(request)
    if token is None:
        return _error(401, "Missing or invalid Authorization header")

    payload = decode_token(token, expected_type="access")
    if payload is None:
        return _error(401, "Invalid or expired token")

    tenant_key = _tenant_key_for(payload)
    if tenant_key is None:
        return _error(401, "Token missing tenant context")

    account_id = int(payload["sub"])
    request.state.account_id = account_id

    backend = get_backend()
    tenant_token = backend.set_tenant_key(tenant_key)
    dek = cache_get(account_id)
    dek_token = set_user_dek(dek) if dek is not None else None
    if dek is not None:
        cache_touch(account_id)

    try:
        response = _guard_status(request, payload, account_id)
        if response is not None:
            return response
        return await call_next(request)
    finally:
        # Neither the DEK nor the tenant context may leak to the next
        # request handled on this worker's thread.
        if dek_token is not None:
            reset_user_dek(dek_token)
        backend.reset_tenant_key(tenant_token)


def register(
    app: FastAPI,
    public_paths: Iterable[str] = DEFAULT_PUBLIC_PATHS,
) -> None:
    """Register the rate limiter and JWT middleware on *app*.

    Args:
        app: the FastAPI application.
        public_paths: paths that bypass authentication.
    """
    app.state.limiter = limiter
    app.add_exception_handler(
        RateLimitExceeded, _rate_limit_exceeded_handler
    )
    app.add_middleware(SlowAPIMiddleware)

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        return await _auth_middleware_impl(
            request, call_next, public_paths
        )


__all__ = ["DEFAULT_PUBLIC_PATHS", "register"]
