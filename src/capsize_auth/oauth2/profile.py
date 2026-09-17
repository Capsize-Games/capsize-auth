"""One normalised shape for every provider's idea of a user.

Providers disagree about almost everything: the subject is ``sub`` for an
OpenID Connect provider and ``id`` for GitHub, the username is ``login``,
``username`` or ``preferred_username``, and the avatar is ``picture`` or
``avatar_url``. Rather than teach the host application those differences, a
provider declares where its fields live and this is what comes out.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class OAuthProfile:
    """A provider's account, mapped onto common field names."""

    #: Which provider this came from, e.g. ``github``.
    provider: str
    #: The provider's stable, immutable identifier for the account. Never
    #: the email: people change those, and some providers let them be
    #: reassigned.
    subject: str
    email: str = ""
    #: Whether the provider states it verified the address. An unverified
    #: address must not be treated as proof of control.
    email_verified: bool = False
    username: str = ""
    display_name: str = ""
    avatar_url: str = ""
    #: The untouched payload, for a host that needs a field this does not
    #: model. Treat it as provider data, not as trusted input.
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProfileMap:
    """Where each normalised field lives in a provider's payload.

    Each entry is a tuple of candidate paths tried in order, so one map can
    cover a provider that renamed a field between API versions. A path may be
    dotted to reach into a nested object (``data.attributes.email``).
    """

    subject: tuple[str, ...] = ("sub", "id")
    email: tuple[str, ...] = ("email",)
    email_verified: tuple[str, ...] = ("email_verified", "verified_email")
    username: tuple[str, ...] = (
        "preferred_username",
        "login",
        "username",
        "nickname",
    )
    display_name: tuple[str, ...] = ("name", "display_name", "global_name")
    avatar_url: tuple[str, ...] = ("picture", "avatar_url", "avatar")


def pluck(payload: dict[str, Any], paths: tuple[str, ...]) -> object:
    """Return the first present value among ``paths``, or None."""
    for path in paths:
        value = _walk(payload, path)
        if value is not None and value != "":
            return value
    return None


def _walk(payload: dict[str, Any], path: str) -> object:
    """Return the value at a dotted ``path``, or None when absent.

    A numeric segment indexes a list, so a provider that wraps its user in a
    single-element array (Twitch does) is reachable as ``data.0.email``.
    """
    current: object = payload
    for part in path.split("."):
        current = _step(current, part)
        if current is None:
            return None
    return current


def _step(current: object, part: str) -> object:
    """Return one path segment applied to ``current``, or None."""
    if isinstance(current, dict):
        return current.get(part)
    if isinstance(current, list) and part.isdigit():
        index = int(part)
        return current[index] if index < len(current) else None
    return None


def build_profile(
    provider: str, payload: dict[str, Any], mapping: ProfileMap
) -> OAuthProfile:
    """Map a provider's userinfo ``payload`` onto an :class:`OAuthProfile`."""
    subject = pluck(payload, mapping.subject)
    if subject is None:
        raise ValueError(
            f"{provider}: userinfo response carried no subject claim"
        )
    email = pluck(payload, mapping.email) or ""
    return OAuthProfile(
        provider=provider,
        subject=str(subject),
        email=str(email).strip().lower(),
        email_verified=bool(pluck(payload, mapping.email_verified)),
        username=str(pluck(payload, mapping.username) or ""),
        display_name=str(pluck(payload, mapping.display_name) or ""),
        avatar_url=str(pluck(payload, mapping.avatar_url) or ""),
        raw=payload,
    )
