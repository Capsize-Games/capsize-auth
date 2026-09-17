"""Hashing, verification, and the enumeration-resistance helper."""

from capsize_auth.passwords import (
    dummy_verify,
    hash_password,
    verify_password,
)


def test_hash_is_salted_per_call() -> None:
    assert hash_password("correct horse") != hash_password("correct horse")


def test_verify_accepts_the_right_password() -> None:
    assert verify_password("correct horse", hash_password("correct horse"))


def test_verify_rejects_the_wrong_password() -> None:
    assert not verify_password("wrong", hash_password("correct horse"))


def test_verify_rejects_a_malformed_hash() -> None:
    assert not verify_password("anything", "not-an-argon2-hash")


def test_dummy_verify_is_callable_and_silent() -> None:
    assert dummy_verify() is None


def test_needs_rehash_is_false_for_a_current_hash() -> None:
    from capsize_auth.passwords import needs_rehash

    assert not needs_rehash(hash_password("correct horse"))


def test_needs_rehash_is_true_for_an_unusable_hash() -> None:
    from capsize_auth.passwords import needs_rehash

    # An unreadable stored hash cannot be kept: treat it as needing replacement
    # rather than leaving an account pinned to something unverifiable.
    assert needs_rehash("not-an-argon2-hash")
