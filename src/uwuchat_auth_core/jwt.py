"""JWT token utilities built on PyJWT.

Configuration (see :mod:`uwuchat_auth_core._env` for the variable prefix):

``<PREFIX>JWT_SECRET``
    Signing secret.  Required — the module refuses to import without a
    real secret unless ``<PREFIX>ALLOW_DEV_JWT_SECRET=1`` is set.

``<PREFIX>JWT_ACCESS_TTL`` / ``<PREFIX>JWT_REFRESH_TTL`` /
``<PREFIX>VERIFICATION_TOKEN_TTL`` / ``<PREFIX>OAUTH_STATE_TTL`` /
``<PREFIX>OAUTH_HANDOFF_TTL``
    Token lifetimes in seconds.
"""

from __future__ import annotations

import datetime

import jwt

from uwuchat_auth_core._env import env, env_int

_DEV_FALLBACK_SECRET = "dev-jwt-secret-do-not-use-in-production"

_JWT_ALGORITHM = "HS256"
_ACCESS_TOKEN_TTL = env_int("JWT_ACCESS_TTL", 900)  # 15 min
_REFRESH_TOKEN_TTL = env_int("JWT_REFRESH_TTL", 604800)  # 7 days
_VERIFICATION_TOKEN_TTL = env_int("VERIFICATION_TOKEN_TTL", 86400)
_OAUTH_STATE_TTL = env_int("OAUTH_STATE_TTL", 600)  # 10 min
_OAUTH_HANDOFF_TTL = env_int("OAUTH_HANDOFF_TTL", 60)


def _resolve_secret() -> str:
    """Return the configured signing secret, or raise a helpful error."""
    raw = env("JWT_SECRET").strip()
    if raw and raw != _DEV_FALLBACK_SECRET:
        return raw
    if env("ALLOW_DEV_JWT_SECRET") == "1":
        return _DEV_FALLBACK_SECRET
    raise RuntimeError(
        "JWT_SECRET is unset or equals the hardcoded dev fallback.  Set it "
        "to a strong random secret, or set ALLOW_DEV_JWT_SECRET=1 to "
        "explicitly opt into the dev fallback (local development only — "
        "never in production).  Generate one with: "
        'python -c "import secrets; print(secrets.token_hex(32))"'
    )


_JWT_SECRET = _resolve_secret()


def _encode(payload: dict) -> str:
    """Sign *payload* with the configured secret."""
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


def _now() -> datetime.datetime:
    """Return the current time as an aware UTC datetime."""
    return datetime.datetime.now(datetime.timezone.utc)


def _claims(ttl: int, token_type: str, **extra: object) -> dict:
    """Build an iat/exp-stamped claim set."""
    now = _now()
    return {
        "iat": now,
        "exp": now + datetime.timedelta(seconds=ttl),
        "type": token_type,
        **extra,
    }


def create_access_token(
    account_id: int,
    tenant_schema: str,
    token_version: int = 0,
) -> str:
    """Return a short-lived JWT access token."""
    return _encode(
        _claims(
            _ACCESS_TOKEN_TTL,
            "access",
            sub=str(account_id),
            tenant=tenant_schema,
            ver=int(token_version),
        )
    )


def create_refresh_token(account_id: int, token_version: int = 0) -> str:
    """Return a longer-lived JWT refresh token."""
    return _encode(
        _claims(
            _REFRESH_TOKEN_TTL,
            "refresh",
            sub=str(account_id),
            ver=int(token_version),
        )
    )


def create_oauth_state_token(extra: dict | None = None) -> str:
    """Return a signed, short-lived CSRF state token for OAuth.

    Stateless by design: nothing is stored server-side, so the flow works
    across worker processes and the state self-expires.  ``extra`` claims
    are merged into the payload so they round-trip through the provider.
    """
    import secrets as _secrets

    return _encode(
        _claims(
            _OAUTH_STATE_TTL,
            "oauth_state",
            jti=_secrets.token_urlsafe(16),
            **(extra or {}),
        )
    )


def create_oauth_handoff_token(account_id: int) -> str:
    """Return a very short-lived one-time code for the OAuth redirect.

    The browser receives this instead of real tokens and exchanges it via
    POST, so long-lived credentials never reach URLs, logs or history.
    """
    return _encode(
        _claims(_OAUTH_HANDOFF_TTL, "oauth_handoff", sub=str(account_id))
    )


def create_verification_token(account_id: int) -> str:
    """Return a short-lived JWT for email verification (type ``verify``)."""
    return _encode(
        _claims(
            _VERIFICATION_TOKEN_TTL,
            "verify",
            sub=str(account_id),
        )
    )


def decode_token(
    token: str,
    expected_type: str | None = None,
) -> dict | None:
    """Decode and validate a JWT.

    Returns the payload on success, or ``None`` when the token is
    invalid, expired, or its ``type`` claim does not match
    *expected_type* (when provided).
    """
    try:
        payload: dict = jwt.decode(
            token,
            _JWT_SECRET,
            algorithms=[_JWT_ALGORITHM],
        )
    except jwt.PyJWTError:
        return None
    if expected_type is not None and payload.get("type") != expected_type:
        return None
    return payload


__all__ = [
    "create_access_token",
    "create_oauth_handoff_token",
    "create_oauth_state_token",
    "create_refresh_token",
    "create_verification_token",
    "decode_token",
]
