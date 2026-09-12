"""Enumeration of the authentication providers an account can use."""

from __future__ import annotations

from enum import Enum


class AuthProvider(str, Enum):
    """How an account authenticates.

    Values are persisted in ``accounts.auth_provider``, so they are part
    of the storage contract — do not rename them.
    """

    LOCAL = "local"
    GOOGLE = "google"
    STEAM = "steam"
    TWITCH = "twitch"


__all__ = ["AuthProvider"]
