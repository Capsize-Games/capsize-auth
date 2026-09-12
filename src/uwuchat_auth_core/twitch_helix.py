"""Twitch Helix API helpers (non-login calls).

These calls need an app access token rather than the user's token, so
they are kept out of :mod:`uwuchat_auth_core.twitch_oauth` (which owns
the login flow).
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from uwuchat_auth_core.twitch_oauth import (
    CLIENT_ID,
    CLIENT_SECRET,
    OAUTH_CONFIGURED,
    TWITCH_TOKEN_URL,
    TWITCH_USERS_URL,
)

logger = logging.getLogger(__name__)

SCHEDULE_URL = "https://api.twitch.tv/helix/schedule"


async def get_app_access_token() -> Optional[str]:
    """Return an app access token via the client-credentials grant."""
    if not OAUTH_CONFIGURED:
        return None

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                TWITCH_TOKEN_URL,
                data={
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "grant_type": "client_credentials",
                },
            )
            resp.raise_for_status()
            return resp.json().get("access_token")
    except Exception:
        logger.exception("Failed to get Twitch app access token")
        return None


async def get_channel_schedule(
    broadcaster_id: str,
) -> Optional[dict]:
    """Return a broadcaster's upcoming Helix schedule, or ``None``."""
    if not OAUTH_CONFIGURED:
        return None

    token = await get_app_access_token()
    if token is None:
        return None

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                SCHEDULE_URL,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Client-Id": CLIENT_ID,
                },
                params={"broadcaster_id": broadcaster_id},
            )
            resp.raise_for_status()
            return resp.json().get("data")
    except Exception:
        logger.exception(
            "Failed to fetch schedule for broadcaster=%s",
            broadcaster_id,
        )
        return None


async def get_user_by_id(
    twitch_id: str,
    access_token: str,
) -> Optional[dict]:
    """Return a Twitch user by ID using a user access token."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                TWITCH_USERS_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Client-Id": CLIENT_ID,
                },
                params={"id": twitch_id},
            )
            resp.raise_for_status()
            users = resp.json().get("data", [])
            return users[0] if users else None
    except Exception:
        logger.exception("Twitch get_user_by_id failed")
        return None


__all__ = [
    "get_app_access_token",
    "get_channel_schedule",
    "get_user_by_id",
]
