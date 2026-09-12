"""Twitch OAuth 2.0 helpers.

Configuration (see :mod:`uwuchat_auth_core._env` for the variable prefix):

``<PREFIX>TWITCH_CLIENT_ID`` / ``<PREFIX>TWITCH_CLIENT_SECRET``
    Twitch application credentials.  When either is missing the module
    degrades gracefully and the sign-in button does not appear.

``<PREFIX>SITE_URL``
    Public-facing site URL used to build the callback redirect.

Helix API helpers that are not part of the login flow live in
:mod:`uwuchat_auth_core.twitch_helix`.
"""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urlencode

import httpx

from uwuchat_auth_core._env import env

logger = logging.getLogger(__name__)

CLIENT_ID = env("TWITCH_CLIENT_ID").strip()
CLIENT_SECRET = env("TWITCH_CLIENT_SECRET").strip()
SITE_URL = env("SITE_URL", "http://localhost:5173").strip().rstrip("/")

OAUTH_CONFIGURED = bool(CLIENT_ID and CLIENT_SECRET)

CALLBACK_PATH = "/api/v1/auth/oauth/twitch/callback"
"""Path the consuming application must mount for the redirect to work."""

# Twitch OAuth endpoints
TWITCH_AUTH_URL = "https://id.twitch.tv/oauth2/authorize"
TWITCH_TOKEN_URL = "https://id.twitch.tv/oauth2/token"
TWITCH_VALIDATE_URL = "https://id.twitch.tv/oauth2/validate"
TWITCH_USERS_URL = "https://api.twitch.tv/helix/users"

LOGIN_SCOPES = ["user:read:email"]
LINK_SCOPES = ["user:read:email"]


class TwitchUserInfo:
    """Normalised user info returned from Twitch."""

    __slots__ = ("twitch_id", "email", "display_name", "avatar_url")

    def __init__(
        self,
        twitch_id: str,
        email: str,
        display_name: str,
        avatar_url: str,
    ) -> None:
        """Store the normalised profile fields."""
        self.twitch_id = twitch_id
        self.email = email
        self.display_name = display_name
        self.avatar_url = avatar_url


# ── CSRF state (same stateless signed-token pattern as Google) ───────


def generate_state() -> str:
    """Generate a signed, short-lived CSRF state parameter."""
    from uwuchat_auth_core.jwt import create_oauth_state_token

    return create_oauth_state_token()


def consume_state(state: str) -> bool:
    """Return True when *state* is a valid, unexpired OAuth state."""
    from uwuchat_auth_core.jwt import decode_token

    return bool(decode_token(state, expected_type="oauth_state"))


# ── URLs ─────────────────────────────────────────────────────────────


def callback_url() -> str:
    """Return the absolute callback URL for this provider."""
    return f"{SITE_URL}{CALLBACK_PATH}"


def get_twitch_auth_url(
    scopes: Optional[list[str]] = None,
) -> Optional[str]:
    """Return the Twitch consent URL, or ``None`` when not configured."""
    if not OAUTH_CONFIGURED:
        logger.warning(
            "Twitch OAuth not configured — set TWITCH_CLIENT_ID and "
            "TWITCH_CLIENT_SECRET to enable."
        )
        return None

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": callback_url(),
        "response_type": "code",
        "scope": " ".join(scopes or LOGIN_SCOPES),
        "state": generate_state(),
        "force_verify": "true",
    }
    return f"{TWITCH_AUTH_URL}?{urlencode(params)}"


def get_callback_uri() -> str:
    """Return the callback path this provider listens on."""
    return CALLBACK_PATH


# ── Token exchange ───────────────────────────────────────────────────


def _user_info_from(
    user: dict,
    login_name: str,
    fallback_id: str,
) -> Optional[TwitchUserInfo]:
    """Build a :class:`TwitchUserInfo` from a Helix user payload."""
    email = user.get("email", "").strip().lower()
    if not email:
        logger.error("Twitch OAuth: no email in Helix response")
        return None
    return TwitchUserInfo(
        twitch_id=user.get("id", fallback_id),
        email=email,
        display_name=user.get("display_name", login_name) or email.split("@")[0],
        avatar_url=user.get("profile_image_url", ""),
    )


async def _fetch_user(
    client: httpx.AsyncClient,
    access_token: str,
) -> tuple[str, str, dict] | None:
    """Validate *access_token* and return ``(id, login, user)``."""
    validate_resp = await client.get(
        TWITCH_VALIDATE_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    validate_resp.raise_for_status()
    validate_data = validate_resp.json()

    user_resp = await client.get(
        TWITCH_USERS_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Client-Id": CLIENT_ID,
        },
    )
    user_resp.raise_for_status()
    users = user_resp.json().get("data", [])
    if not users:
        logger.error("Twitch OAuth: no user data from Helix")
        return None
    return (
        validate_data.get("user_id", ""),
        validate_data.get("login", ""),
        users[0],
    )


async def exchange_code(code: str) -> Optional[TwitchUserInfo]:
    """Exchange an authorization code for user info from Twitch."""
    if not OAUTH_CONFIGURED:
        return None

    token_data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": callback_url(),
        "grant_type": "authorization_code",
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            token_resp = await client.post(
                TWITCH_TOKEN_URL, data=token_data
            )
            token_resp.raise_for_status()
            access_token = token_resp.json().get("access_token")
            if not access_token:
                logger.error("Twitch OAuth: no access_token in response")
                return None

            fetched = await _fetch_user(client, access_token)
            if fetched is None:
                return None
            fallback_id, login_name, user = fetched
            return _user_info_from(user, login_name, fallback_id)

    except httpx.HTTPError as exc:
        logger.exception("Twitch OAuth HTTP error: %s", exc)
        return None
    except Exception:
        logger.exception("Twitch OAuth unexpected error")
        return None


__all__ = [
    "CALLBACK_PATH",
    "LINK_SCOPES",
    "LOGIN_SCOPES",
    "OAUTH_CONFIGURED",
    "TwitchUserInfo",
    "callback_url",
    "consume_state",
    "exchange_code",
    "generate_state",
    "get_callback_uri",
    "get_twitch_auth_url",
]
