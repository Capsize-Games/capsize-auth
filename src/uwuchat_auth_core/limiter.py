"""Shared ``slowapi`` rate-limiter instance for the auth routes."""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
"""Process-wide limiter; the middleware registers its storage + handler."""

__all__ = ["limiter"]
