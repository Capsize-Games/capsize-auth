"""IP → country lookup with a small in-memory cache.

Uses the free ``ip-api.com`` endpoint (no API key; 45 requests/minute),
so results are cached per process to stay inside that limit.  IP-based
geolocation is inherently imperfect (VPNs, proxies) — that is an accepted
limitation, and no VPN detection is attempted.
"""

from __future__ import annotations

import ipaddress
import logging
import time

import httpx
from fastapi import Request as FastAPIRequest

from uwuchat_auth_core._env import env

logger = logging.getLogger(__name__)

LOOKUP_URL = "http://ip-api.com/json/{ip}?fields=countryCode"
CACHE_TTL_SECONDS = 300

# Headers checked for the real client IP behind a reverse proxy, ordered
# by decreasing trust — the outermost proxy's header is last.
_FORWARDED_HEADERS = ("x-forwarded-for", "x-real-ip")

TRUSTED_PROXY_CIDRS: tuple[str, ...] = tuple(
    c.strip()
    for c in env("TRUSTED_PROXY_CIDRS", "172.16.0.0/12,10.0.0.0/8").split(",")
    if c.strip()
)
"""Immediate peers whose forwarded headers are honoured.

Set ``<PREFIX>TRUSTED_PROXY_CIDRS`` to your reverse proxy's network.
Any client outside these ranges cannot spoof ``X-Forwarded-For``.
"""

_cache: dict[str, tuple[str, float]] = {}


def is_private_ip(ip: str) -> bool:
    """Return True for loopback, private, link-local or reserved IPs."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(addr.is_loopback or addr.is_private or addr.is_link_local)


def is_trusted_proxy(ip: str) -> bool:
    """Return True when *ip* falls inside a trusted proxy CIDR."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in TRUSTED_PROXY_CIDRS:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def extract_client_ip(request: FastAPIRequest) -> str | None:
    """Return the real client IP for *request*.

    Forwarded headers are honoured only when the immediate peer is a
    trusted proxy — otherwise any client could spoof them.  The first
    address in ``X-Forwarded-For`` is the real client, by that header's
    standard prepending semantics.
    """
    peer_host = request.client.host if request.client is not None else None
    if not peer_host or not is_trusted_proxy(peer_host):
        return peer_host

    for header in _FORWARDED_HEADERS:
        value = request.headers.get(header, "").strip()
        if value:
            first = value.split(",")[0].strip()
            if first:
                return first
    return peer_host


def lookup_country(ip: str) -> str | None:
    """Return the ISO country code for *ip*, or ``None`` on failure.

    Blocking — callers should offload to a thread.  *ip* is validated
    here before being interpolated into the request URL.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        logger.debug("Rejecting malformed IP for geolocation: %r", ip)
        return None

    now = time.time()
    cached = _cache.get(ip)
    if cached is not None and cached[1] > now:
        return cached[0]

    try:
        # The URL template is a fixed literal and *ip* was validated as a
        # well-formed address above, so it cannot escape the host path.
        resp = httpx.get(
            LOOKUP_URL.format(ip=ip),
            headers={"User-Agent": "uwuchat-auth-core/0.1"},
            timeout=5,
        )
        resp.raise_for_status()
        country = resp.json().get("countryCode", "")
        if country:
            _cache[ip] = (country, now + CACHE_TTL_SECONDS)
        return country or None
    except Exception as exc:
        logger.debug("IP geolocation failed for %s: %s", ip, exc)
        return None


def reset_cache() -> None:
    """Clear the in-memory lookup cache (test helper)."""
    _cache.clear()


__all__ = [
    "CACHE_TTL_SECONDS",
    "LOOKUP_URL",
    "TRUSTED_PROXY_CIDRS",
    "extract_client_ip",
    "is_private_ip",
    "is_trusted_proxy",
    "lookup_country",
    "reset_cache",
]
