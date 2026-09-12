"""Unit tests for argon2id password hashing."""

from __future__ import annotations

from uwuchat_auth_core.passwords import (
    dummy_verify,
    hash_password,
    verify_password,
)


def test_hash_password_produces_different_output() -> None:
    """Each call produces a unique hash (the salt is random)."""
    pw = "correct-horse-battery-staple"
    assert hash_password(pw) != hash_password(pw)


def test_verify_password_round_trip() -> None:
    """hash → verify returns True for the correct password."""
    pw = "my-secret-password"
    assert verify_password(pw, hash_password(pw)) is True


def test_verify_password_rejects_wrong_password() -> None:
    """verify_password returns False for an incorrect password."""
    assert verify_password("wrong-password", hash_password("real")) is False


def test_verify_password_rejects_empty() -> None:
    """verify_password returns False for an empty string."""
    assert verify_password("", hash_password("some-password")) is False


def test_hash_is_not_plaintext() -> None:
    """The stored hash never contains the plaintext password."""
    pw = "sensitive-password"
    assert pw not in hash_password(pw)


def test_hash_is_not_trivially_reversible() -> None:
    """Different passwords produce structurally different hashes."""
    assert hash_password("alpha-bravo-charlie") != hash_password(
        "delta-echo-foxtrot"
    )


def test_dummy_verify_does_not_raise() -> None:
    """dummy_verify completes without raising (timing safety)."""
    dummy_verify()
