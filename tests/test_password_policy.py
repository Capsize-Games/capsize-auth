"""The strength policy and its configurability."""

import pytest

from capsize_auth.password_policy import (
    DEFAULT,
    PasswordPolicy,
    PasswordValidationError,
    validate_password_strength,
)

STRONG = "quartz-lantern-9-drifting"


def test_a_strong_password_passes() -> None:
    assert validate_password_strength(STRONG).is_valid


def test_a_short_password_is_refused_before_scoring() -> None:
    outcome = validate_password_strength("ab3$")
    assert not outcome.is_valid
    assert "at least 8 characters" in outcome.reason


def test_a_weak_password_is_refused_with_guidance() -> None:
    outcome = validate_password_strength("password123")
    assert not outcome.is_valid
    # The point of carrying zxcvbn's feedback is that the reason is
    # actionable, not that it is merely negative.
    assert outcome.reason != "Password is too weak."


def test_thresholds_are_configurable() -> None:
    lenient = PasswordPolicy(min_length=4, min_score=0)
    assert lenient.validate("abcd").is_valid


def test_check_raises_for_a_refused_password() -> None:
    with pytest.raises(PasswordValidationError):
        DEFAULT.check("short")
