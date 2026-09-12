"""Unit tests for the shared password-strength policy."""

from __future__ import annotations

from uwuchat_auth_core.password_policy import (
    MIN_PASSWORD_LENGTH,
    MIN_ZXCVBN_SCORE,
    PasswordValidationError,
    validate_password_strength,
)


def test_strong_passphrase_accepted() -> None:
    """A long, high-entropy passphrase passes the policy."""
    result = validate_password_strength(
        "correct-horse-battery-staple-sunshine-42"
    )
    assert result.is_valid is True
    assert result.score >= MIN_ZXCVBN_SCORE


def test_reasonably_strong_password_accepted() -> None:
    """A mixed-character password of length >= 12 typically scores >= 3."""
    assert validate_password_strength("Tr0ub4dor&3Mango!").is_valid is True


def test_common_password_rejected() -> None:
    """A top-10k-common password is rejected."""
    result = validate_password_strength("password123")
    assert result.is_valid is False
    assert "too weak" in result.reason.lower()
    assert result.score < MIN_ZXCVBN_SCORE


def test_repetitive_password_rejected() -> None:
    """A low-entropy repeated string is rejected."""
    result = validate_password_strength("aaaaaaaa")
    assert result.is_valid is False
    assert result.score < MIN_ZXCVBN_SCORE


def test_short_common_word_rejected() -> None:
    """A short dictionary word is rejected as too weak."""
    assert validate_password_strength("letmein").is_valid is False


def test_too_short_password_rejected_before_zxcvbn() -> None:
    """A password under the length floor is rejected before zxcvbn runs."""
    result = validate_password_strength("a" * (MIN_PASSWORD_LENGTH - 1))
    assert result.is_valid is False
    assert "at least" in result.reason.lower()
    assert result.score == 0


def test_exactly_min_length_not_rejected_by_length_floor() -> None:
    """Exactly MIN_PASSWORD_LENGTH is not rejected by the length check."""
    result = validate_password_strength("a" * MIN_PASSWORD_LENGTH)
    assert "at least" not in result.reason.lower()


def test_rejection_reason_includes_feedback() -> None:
    """When zxcvbn rejects, the reason carries its feedback."""
    result = validate_password_strength("abc123")
    assert result.is_valid is False
    assert result.reason


def test_password_validation_error_reason() -> None:
    """PasswordValidationError stores the reason string."""
    err = PasswordValidationError("test reason")
    assert err.reason == "test reason"
    assert str(err) == "test reason"
