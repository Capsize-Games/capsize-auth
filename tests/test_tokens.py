"""Signed tokens and opaque secrets."""

import time

import pytest

from capsize_auth.tokens import (
    ACCESS,
    REFRESH,
    TokenSigner,
    TokenTTLs,
    hash_token,
    new_token,
)
from capsize_auth.tokens.opaque import matches

SECRET = "0" * 32


def signer(**ttl: int) -> TokenSigner:
    return TokenSigner(secret=SECRET, ttls=TokenTTLs(**ttl))


def test_a_short_secret_is_refused() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        TokenSigner(secret="too-short")


def test_a_token_round_trips() -> None:
    issued = signer().issue(ACCESS, "42", ver=3)
    claims = signer().decode(issued, ACCESS)
    assert claims is not None
    assert claims["sub"] == "42"
    assert claims["ver"] == 3


def test_a_token_of_the_wrong_kind_is_refused() -> None:
    issued = signer().issue(REFRESH, "42")
    assert signer().decode(issued, ACCESS) is None


def test_another_secret_cannot_decode_it() -> None:
    issued = signer().issue(ACCESS, "42")
    assert TokenSigner(secret="1" * 32).decode(issued, ACCESS) is None


def test_an_expired_token_is_refused() -> None:
    issued = signer(access=-1).issue(ACCESS, "42")
    time.sleep(0.01)
    assert signer().decode(issued, ACCESS) is None


def test_an_unknown_kind_has_no_lifetime() -> None:
    with pytest.raises(ValueError, match="no lifetime"):
        signer().issue("invented", "42")


def test_issuer_and_audience_are_enforced() -> None:
    strict = TokenSigner(secret=SECRET, issuer="a", audience="b")
    issued = strict.issue(ACCESS, "42")
    assert strict.decode(issued, ACCESS) is not None
    assert TokenSigner(secret=SECRET).decode(issued, ACCESS) is None


def test_an_opaque_token_carries_its_prefix_and_hash() -> None:
    token = new_token(prefix="sfh_pat_")
    assert token.plaintext.startswith("sfh_pat_")
    assert token.hashed == hash_token(token.plaintext)
    assert matches(token.plaintext, token.hashed)
    assert not matches(token.plaintext + "x", token.hashed)


def test_opaque_tokens_do_not_repeat() -> None:
    assert new_token().plaintext != new_token().plaintext
