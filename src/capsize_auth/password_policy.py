"""Password-strength policy, with the thresholds as configuration.

Every call site that accepts a new or changed password -- register, admin
create, change password, confirm reset -- runs the same policy, so none can
drift onto a length-only check.

The policy is an object rather than module constants because deployments
legitimately differ: a service for a general audience and an internal admin
tool do not need the same floor. :data:`DEFAULT` is the recommended setting
and is what the module-level helper uses.

zxcvbn is imported on first use, not at module import. Loading its frequency
dictionaries costs noticeable start-up time, and an application that never
accepts a password should not pay it.
"""

from dataclasses import dataclass
from typing import Any, NamedTuple

#: Minimum acceptable zxcvbn score on its 0-4 scale.
MIN_ZXCVBN_SCORE = 3
#: Absolute minimum length, checked before zxcvbn because it is cheaper.
MIN_PASSWORD_LENGTH = 8


class PasswordValidationError(ValueError):
    """Raised when a password fails the strength policy."""

    def __init__(self, reason: str) -> None:
        """Store the user-facing ``reason`` alongside the message."""
        super().__init__(reason)
        self.reason = reason


class ValidationResult(NamedTuple):
    """Outcome of a strength check."""

    is_valid: bool
    reason: str
    score: int
    warning: str
    suggestions: list[str]


@dataclass(frozen=True)
class PasswordPolicy:
    """The thresholds a password is held to."""

    min_length: int = MIN_PASSWORD_LENGTH
    min_score: int = MIN_ZXCVBN_SCORE

    def validate(self, password: str) -> ValidationResult:
        """Return whether ``password`` satisfies this policy."""
        if len(password) < self.min_length:
            return _too_short(self.min_length)
        result = _score(password)
        if int(result.get("score", 0)) >= self.min_score:
            return ValidationResult(True, "", int(result["score"]), "", [])
        return _weak(result)

    def check(self, password: str) -> None:
        """Raise :class:`PasswordValidationError` when ``password`` fails."""
        outcome = self.validate(password)
        if not outcome.is_valid:
            raise PasswordValidationError(outcome.reason)


#: The recommended policy.
DEFAULT = PasswordPolicy()


def _score(password: str) -> dict[str, Any]:
    """Return zxcvbn's analysis of ``password``."""
    import zxcvbn

    result: dict[str, Any] = zxcvbn.zxcvbn(password)
    return result


def _too_short(minimum: int) -> ValidationResult:
    """Return the rejection for a password below the length floor."""
    return ValidationResult(
        is_valid=False,
        reason=f"Password must be at least {minimum} characters",
        score=0,
        warning="",
        suggestions=[],
    )


def _weak(result: dict[str, Any]) -> ValidationResult:
    """Build a rejection carrying zxcvbn's own feedback.

    The warning and suggestions are included so the person is told *why* it
    was refused; "password too weak" with no guidance produces another weak
    password.
    """
    feedback = result.get("feedback") or {}
    warning = str(feedback.get("warning") or "")
    suggestions = list(feedback.get("suggestions") or [])
    parts = ["Password is too weak."]
    if warning:
        parts.append(warning)
    if suggestions:
        parts.append(" ".join(suggestions))
    return ValidationResult(
        is_valid=False,
        reason=" ".join(parts),
        score=int(result.get("score", 0)),
        warning=warning,
        suggestions=suggestions,
    )


def validate_password_strength(password: str) -> ValidationResult:
    """Validate ``password`` against :data:`DEFAULT`."""
    return DEFAULT.validate(password)
