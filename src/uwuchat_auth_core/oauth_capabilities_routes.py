"""OAuth capabilities endpoint — reports which providers are configured.

Mount at the application's auth prefix.  Returns a public map of
``provider → bool`` so a frontend can decide whether to render OAuth
sign-in buttons without any credential value ever leaving the server.
This endpoint is intentionally unauthenticated: it exposes only whether
a provider is enabled, never a ``client_id`` or secret.
"""

from __future__ import annotations

from fastapi import APIRouter

from uwuchat_auth_core.oauth import OAUTH_CONFIGURED as GOOGLE_CONFIGURED
from uwuchat_auth_core.twitch_oauth import (
    OAUTH_CONFIGURED as TWITCH_CONFIGURED,
)

router = APIRouter()


@router.get("/oauth/capabilities", summary="OAuth provider status")
async def oauth_capabilities() -> dict:
    """Return which OAuth providers are currently configured."""
    return {
        "google": GOOGLE_CONFIGURED,
        "twitch": TWITCH_CONFIGURED,
    }


__all__ = ["router"]
