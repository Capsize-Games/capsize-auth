"""Google OAuth 2.0 helpers.

Configuration (see :mod:`uwuchat_auth_core._env` for the variable prefix):

``<PREFIX>GOOGLE_CLIENT_ID`` / ``<PREFIX>GOOGLE_CLIENT_SECRET``
    Google OAuth credentials.  When either is missing the module degrades
    gracefully — :data:`OAUTH_CONFIGURED` is False and the sign-in button
    simply does not appear.

``<PREFIX>SITE_URL``
    Public-facing site URL used to build the callback redirect.
"""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urlencode

import httpx

from uwuchat_auth_core._env import env

logger = logging.getLogger(__name__)

CLIENT_ID = env("GOOGLE_CLIENT_ID").strip()
CLIENT_SECRET = env("GOOGLE_CLIENT_SECRET").strip()
SITE_URL = env("SITE_URL", "http://localhost:5173").strip().rstrip("/")

OAUTH_CONFIGURED = bool(CLIENT_ID and CLIENT_SECRET)

CALLBACK_PATH = "/api/v1/auth/oauth/google/callback"
"""Path the consuming application must mount for the redirect to work."""

# Google OAuth endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

SCOPES = ["openid", "email", "profile"]


class GoogleUserInfo:
    """Normalised user info returned from Google's userinfo endpoint."""

    __slots__ = ("google_id", "email", "name", "verified_email")

    def __init__(
        self,
        google_id: str,
        email: str,
        name: str,
        verified_email: bool,
    ) -> None:
        """Store the normalised profile fields."""
        self.google_id = google_id
        self.email = email
        self.name = name
        self.verified_email = verified_email


# ── CSRF state (stateless, signed, multi-worker safe) ────────────────


def generate_state(extra: Optional[dict] = None) -> str:
    """Generate a signed, short-lived CSRF state parameter."""
    from uwuchat_auth_core.jwt import create_oauth_state_token

    return create_oauth_state_token(extra=extra)


def consume_state(state: str) -> bool:
    """Return True when *state* is a valid, unexpired OAuth state."""
    from uwuchat_auth_core.jwt import decode_token

    return bool(decode_token(state, expected_type="oauth_state"))


def decode_oauth_state(state: str) -> Optional[dict]:
    """Return the decoded state payload, or ``None`` when invalid."""
    from uwuchat_auth_core.jwt import decode_token

    return decode_token(state, expected_type="oauth_state")


# ── URLs ─────────────────────────────────────────────────────────────


def callback_url() -> str:
    """Return the absolute callback URL for this provider."""
    return f"{SITE_URL}{CALLBACK_PATH}"


def get_google_auth_url(promo_code: str = "") -> Optional[str]:
    """Return the Google consent URL, or ``None`` when not configured."""
    if not OAUTH_CONFIGURED:
        logger.warning(
            "Google OAuth not configured — set GOOGLE_CLIENT_ID and "
            "GOOGLE_CLIENT_SECRET to enable."
        )
        return None

    extra = {"promo_code": promo_code} if promo_code else None
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": callback_url(),
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": generate_state(extra=extra),
        "access_type": "offline",
        "prompt": "consent",
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def get_callback_uri() -> str:
    """Return the callback path this provider listens on."""
    return CALLBACK_PATH


# ── Token exchange ───────────────────────────────────────────────────


def _user_info_from(payload: dict) -> Optional[GoogleUserInfo]:
    """Build a :class:`GoogleUserInfo` from a userinfo payload."""
    email = payload.get("email", "").strip().lower()
    if not email:
        logger.error("Google OAuth: no email in userinfo response")
        return None
    return GoogleUserInfo(
        google_id=payload.get("id", ""),
        email=email,
        name=payload.get("name", "").strip() or email.split("@")[0],
        verified_email=payload.get("verified_email", False),
    )


async def exchange_code(code: str) -> Optional[GoogleUserInfo]:
    """Exchange an authorization code for user info from Google."""
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
            token_resp = await client.post(GOOGLE_TOKEN_URL, data=token_data)
            token_resp.raise_for_status()
            access_token = token_resp.json().get("access_token")
            if not access_token:
                logger.error("Google OAuth: no access_token in response")
                return None

            user_resp = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_resp.raise_for_status()
            return _user_info_from(user_resp.json())

    except httpx.HTTPError as exc:
        logger.exception("Google OAuth HTTP error: %s", exc)
        return None
    except Exception:
        logger.exception("Google OAuth unexpected error")
        return None


__all__ = [
    "CALLBACK_PATH",
    "OAUTH_CONFIGURED",
    "GoogleUserInfo",
    "callback_url",
    "consume_state",
    "decode_oauth_state",
    "exchange_code",
    "generate_state",
    "get_callback_uri",
    "get_google_auth_url",
]
