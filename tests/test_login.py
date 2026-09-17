"""The password sign-in decision."""

from capsize_auth.accounts import (
    BAD_PASSWORD,
    NO_ACCOUNT,
    NO_PASSWORD_SET,
    NOT_USABLE,
    OK,
    Principal,
    check_password_login,
    status,
)
from capsize_auth.passwords import hash_password

PASSWORD = "quartz-lantern-9-drifting"


def principal(state: str = status.ACTIVE) -> Principal:
    return Principal(id="7", email="a@example.com", status=state)


def test_a_correct_password_signs_in() -> None:
    outcome = check_password_login(
        PASSWORD, principal(), hash_password(PASSWORD)
    )
    assert outcome.ok
    assert outcome.result == OK


def test_an_unknown_account_is_refused() -> None:
    outcome = check_password_login(PASSWORD, None, None)
    assert outcome.result == NO_ACCOUNT
    assert not outcome.ok


def test_a_wrong_password_is_refused() -> None:
    outcome = check_password_login(
        "wrong", principal(), hash_password(PASSWORD)
    )
    assert outcome.result == BAD_PASSWORD


def test_an_oauth_only_account_has_no_password_to_check() -> None:
    outcome = check_password_login(PASSWORD, principal(), None)
    assert outcome.result == NO_PASSWORD_SET


def test_a_suspended_account_is_refused_after_the_password_check() -> None:
    # Ordering matters: checking status first would let an attacker learn an
    # account is suspended without knowing its password.
    outcome = check_password_login(
        PASSWORD, principal(status.SUSPENDED), hash_password(PASSWORD)
    )
    assert outcome.result == NOT_USABLE


def test_a_banned_account_is_refused() -> None:
    outcome = check_password_login(
        PASSWORD, principal(status.BANNED), hash_password(PASSWORD)
    )
    assert outcome.result == NOT_USABLE
