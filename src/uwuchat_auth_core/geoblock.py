"""Region-based access blocking for registration and login.

The blocked country list comes from ``<PREFIX>BLOCKED_COUNTRY_CODES``
(comma-separated ISO 3166-1 alpha-2 codes).  When that variable is unset
the default is the EU/EEA plus the UK and the other jurisdictions with a
GDPR-equivalent "special category data" regime.  Set the variable to a
single value such as ``ZZ`` to block nothing.

IP resolution lives in :mod:`uwuchat_auth_core.geoip`; this module holds
only the policy.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import Request as FastAPIRequest

from uwuchat_auth_core._env import env
from uwuchat_auth_core.geoip import extract_client_ip, is_private_ip
from uwuchat_auth_core.geoip import lookup_country as _lookup_country

logger = logging.getLogger(__name__)

# EU-27 (without the UK) plus the EEA-but-non-EU states, which are bound
# by a materially identical regime via the EEA agreement.
EU_EEA_CODES: frozenset[str] = frozenset({
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE",
    "NO", "IS", "LI",
})

UK_CODES: frozenset[str] = frozenset({"GB"})

# Non-EU/EEA jurisdictions whose law defaults special-category data to
# prohibited absent consent, rather than merely requiring consent:
# CH (revised FADP), KR (PIPA), BR (LGPD), CN (PIPL).
#
# Deliberately excluded: JP (APPI), IN (DPDP Act), CA (PIPEDA) — those
# are consent-based without a default prohibition, so they are handled by
# an explicit consent flow rather than a hard block.
OTHER_STRICT_CODES: frozenset[str] = frozenset({"CH", "KR", "BR", "CN"})

DEFAULT_BLOCKED_MESSAGE = (
    "This service is not available in your region. We are currently "
    "unable to accept users from the regions listed in the geoblock "
    "policy."
)
"""Message returned when a request is blocked.

Override with ``<PREFIX>GEOBLOCK_MESSAGE`` to use your own product copy.
"""


def blocked_message() -> str:
    """Return the configured block message."""
    return env("GEOBLOCK_MESSAGE", DEFAULT_BLOCKED_MESSAGE)


def blocked_country_codes() -> frozenset[str]:
    """Return the configured set of blocked ISO country codes."""
    raw = env("BLOCKED_COUNTRY_CODES").strip()
    if raw:
        return frozenset(
            c.strip().upper() for c in raw.split(",") if c.strip()
        )
    return EU_EEA_CODES | UK_CODES | OTHER_STRICT_CODES


async def resolve_country(request: FastAPIRequest) -> str | None:
    """Return the ISO country code for the request's client IP.

    This is the single IP→country entry point for the package.  Returns
    ``None`` for private/reserved or missing IPs and for failed lookups;
    callers treat ``None`` as "unknown region".
    """
    client_ip = extract_client_ip(request)
    if not client_ip or is_private_ip(client_ip):
        return None

    country = await asyncio.to_thread(_lookup_country, client_ip)
    if country is None:
        logger.warning(
            "Geoblock lookup failed for %s — allowing access", client_ip
        )
    return country


async def check_geoblock(request: FastAPIRequest) -> str | None:
    """Return a block message when the client is in a blocked region.

    Returns ``None`` when access is allowed — including for private and
    reserved addresses (loopback, LAN, unknown clients).
    """
    country = await resolve_country(request)
    if country is None:
        return None
    if country in blocked_country_codes():
        logger.info("Geoblock rejected access from %s", country)
        return blocked_message()
    return None


__all__ = [
    "DEFAULT_BLOCKED_MESSAGE",
    "EU_EEA_CODES",
    "OTHER_STRICT_CODES",
    "UK_CODES",
    "blocked_country_codes",
    "blocked_message",
    "check_geoblock",
    "resolve_country",
]
