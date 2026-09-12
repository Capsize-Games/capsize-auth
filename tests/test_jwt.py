"""Unit tests for JWT token creation and validation."""

from __future__ import annotations

import base64
import json
from unittest.mock import patch

from uwuchat_auth_core.jwt import (
    create_access_token,
    create_refresh_token,
    create_verification_token,
    decode_token,
)


def test_access_token_round_trip() -> None:
    """Create → decode preserves all claims."""
    token = create_access_token(42, "tenant_abc123", token_version=1)
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "42"
    assert payload["tenant"] == "tenant_abc123"
    assert payload["ver"] == 1
    assert payload["type"] == "access"


def test_refresh_token_round_trip() -> None:
    """Refresh tokens have the correct type and claims."""
    token = create_refresh_token(99, token_version=3)
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "99"
    assert payload["ver"] == 3
    assert payload["type"] == "refresh"


def test_verification_token_round_trip() -> None:
    """Verification tokens have type 'verify'."""
    token = create_verification_token(7)
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "7"
    assert payload["type"] == "verify"


def test_decode_invalid_token_returns_none() -> None:
    """A garbage string is not a valid JWT."""
    assert decode_token("not-a-jwt") is None


def test_decode_empty_token_returns_none() -> None:
    """An empty string is not a valid JWT."""
    assert decode_token("") is None


def test_wrong_type_rejected() -> None:
    """A token whose type does not match expected_type is rejected."""
    token = create_refresh_token(1)
    assert decode_token(token, expected_type="access") is None


def test_tampered_signature_rejected() -> None:
    """A token with a modified signature is rejected."""
    token = create_access_token(1, "tenant_xyz")
    # Replace the last 8 chars of the signature; a single-char flip can
    # occasionally still produce valid padding.
    head, sig = token.rsplit(".", 1)
    assert decode_token(f"{head}.{sig[:-8]}DEADBEEF") is None


def test_tampered_payload_rejected() -> None:
    """A token with a modified payload is rejected."""
    token = create_access_token(1, "tenant_xyz")
    header, payload_b64, sig = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==="))
    payload["sub"] = "999"  # tampered account ID
    new_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload).encode())
        .rstrip(b"=")
        .decode()
    )
    assert decode_token(f"{header}.{new_payload_b64}.{sig}") is None


def test_access_token_expiry() -> None:
    """An expired access token is rejected."""
    with patch("uwuchat_auth_core.jwt._ACCESS_TOKEN_TTL", -1):
        token = create_access_token(1, "tenant_xyz")
    assert decode_token(token) is None


def test_token_issued_for_tenant_a_has_correct_tenant() -> None:
    """Access tokens carry the tenant schema they were issued for."""
    payload = decode_token(create_access_token(5, "tenant_alpha"))
    assert payload is not None
    assert payload["tenant"] == "tenant_alpha"
