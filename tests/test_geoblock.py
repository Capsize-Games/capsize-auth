"""Tests for the geoblock policy and the IP helpers it depends on."""

from __future__ import annotations

import asyncio

import pytest
from starlette.requests import Request

from uwuchat_auth_core import geoblock, geoip


def _request(
    headers: dict[str, str] | None = None,
    peer: str | None = "10.0.0.1",
) -> Request:
    """Build a minimal ASGI request for IP resolution tests."""
    raw = [
        (k.lower().encode(), v.encode())
        for k, v in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": raw,
        "client": (peer, 1234) if peer else None,
    }
    return Request(scope)


def test_default_blocked_set_is_eu_eea_uk_and_strict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no override the default policy applies."""
    monkeypatch.delenv("AIRUNNER_BLOCKED_COUNTRY_CODES", raising=False)
    blocked = geoblock.blocked_country_codes()
    assert {"DE", "FR", "GB", "NO", "CH", "KR"} <= blocked
    assert "US" not in blocked


def test_blocked_set_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit list replaces the default policy."""
    monkeypatch.setenv("AIRUNNER_BLOCKED_COUNTRY_CODES", "zz, us")
    assert geoblock.blocked_country_codes() == frozenset({"ZZ", "US"})


def test_empty_string_keeps_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """A blank setting is treated as unset."""
    monkeypatch.setenv("AIRUNNER_BLOCKED_COUNTRY_CODES", "   ")
    assert "DE" in geoblock.blocked_country_codes()


def test_block_message_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Applications can supply their own block copy."""
    monkeypatch.setenv("AIRUNNER_GEOBLOCK_MESSAGE", "Not here.")
    assert geoblock.blocked_message() == "Not here."


def test_private_ips_recognised() -> None:
    """Loopback, RFC1918 and link-local addresses are private."""
    for ip in ("127.0.0.1", "10.1.2.3", "192.168.1.9", "::1", "fe80::1"):
        assert geoip.is_private_ip(ip) is True
    assert geoip.is_private_ip("8.8.8.8") is False
    assert geoip.is_private_ip("not-an-ip") is False


def test_forwarded_header_ignored_for_untrusted_peer() -> None:
    """A public peer cannot spoof its address via X-Forwarded-For."""
    request = _request(
        {"X-Forwarded-For": "1.2.3.4"},
        peer="203.0.113.9",
    )
    assert geoip.extract_client_ip(request) == "203.0.113.9"


def test_forwarded_header_honoured_for_trusted_proxy() -> None:
    """A trusted proxy's X-Forwarded-For first hop is used."""
    request = _request(
        {"X-Forwarded-For": "1.2.3.4, 10.0.0.7"},
        peer="10.0.0.5",
    )
    assert geoip.extract_client_ip(request) == "1.2.3.4"


def test_missing_client_returns_none() -> None:
    """A request with no client address resolves to None."""
    assert geoip.extract_client_ip(_request(peer=None)) is None


def test_check_geoblock_returns_message_for_blocked_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A blocked country yields the block message."""

    async def _blocked(_request) -> str:
        return "DE"

    monkeypatch.setattr(geoblock, "resolve_country", _blocked)
    message = asyncio.run(geoblock.check_geoblock(_request()))
    assert message == geoblock.DEFAULT_BLOCKED_MESSAGE


def test_check_geoblock_allows_unblocked_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unblocked country (and an unknown region) is allowed."""

    async def _us(_request) -> str:
        return "US"

    async def _unknown(_request) -> None:
        return None

    monkeypatch.setattr(geoblock, "resolve_country", _us)
    assert asyncio.run(geoblock.check_geoblock(_request())) is None

    monkeypatch.setattr(geoblock, "resolve_country", _unknown)
    assert asyncio.run(geoblock.check_geoblock(_request())) is None
