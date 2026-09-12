"""Shared password-strength policy using zxcvbn entropy estimation.

Every call site that accepts a new or changed password (register, admin
create, change-password, reset-confirm) uses this single policy so none
can drift onto a length-only check.

Policy
------
* Minimum length: 8 characters (checked first, cheapest).
* Minimum zxcvbn score: 3 on the 0–4 scale (reject 0–2).
* The rejection reason includes zxcvbn's warning and suggestions so the
  user knows *why* to fix it.
"""

from __future__ import annotations

from typing import NamedTuple

MIN_ZXCVBN_SCORE: int = 3
"""Minimum acceptable zxcvbn score (0–4 scale)."""

MIN_PASSWORD_LENGTH: int = 8
"""Absolute minimum password length, checked before zxcvbn."""


class PasswordValidationError(ValueError):
    """Raised when a password fails the strength policy.

    *reason* is a user-facing string built from zxcvbn feedback.
    """

    def __init__(self, reason: str) -> None:
        """Store the user-facing *reason* alongside the message."""
        super().__init__(reason)
        self.reason = reason


class ValidationResult(NamedTuple):
    """Outcome of :func:`validate_password_strength`."""

    is_valid: bool
    reason: str
    score: int
    warning: str
    suggestions: list[str]


def _too_short() -> ValidationResult:
    """Return the rejection result for a below-floor password."""
    return ValidationResult(
        is_valid=False,
        reason=(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        ),
        score=0,
        warning="",
        suggestions=[],
    )


def _weak_result(result: dict) -> ValidationResult:
    """Build a rejection result from zxcvbn feedback."""
    feedback = result.get("feedback", {})
    warning = feedback.get("warning", "")
    suggestions = feedback.get("suggestions", [])

    parts: list[str] = ["Password is too weak."]
    if warning:
        parts.append(warning)
    if suggestions:
        parts.append(" ".join(suggestions))

    return ValidationResult(
        is_valid=False,
        reason=" ".join(parts),
        score=result.get("score", 0),
        warning=warning or "",
        suggestions=suggestions or [],
    )


def validate_password_strength(password: str) -> ValidationResult:
    """Validate *password* against the strength policy.

    Returns a :class:`ValidationResult`; callers raise
    :class:`PasswordValidationError` (or their own HTTP exception) when
    ``is_valid`` is False.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return _too_short()

    import zxcvbn

    result = zxcvbn.zxcvbn(password)
    if result.get("score", 0) >= MIN_ZXCVBN_SCORE:
        return ValidationResult(
            is_valid=True,
            reason="",
            score=result.get("score", 0),
            warning="",
            suggestions=[],
        )
    return _weak_result(result)


__all__ = [
    "MIN_PASSWORD_LENGTH",
    "MIN_ZXCVBN_SCORE",
    "PasswordValidationError",
    "ValidationResult",
    "validate_password_strength",
]
