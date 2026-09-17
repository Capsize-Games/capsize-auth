"""Signed JWT issuance and validation, configured explicitly.

The module this replaced read its secret from the environment *at import
time* and raised if it was missing, which made the library impossible to
import in a test that had not arranged the environment first, and tied every
consumer to one variable-naming scheme. A signer is an ordinary object here:
construct it with a secret, hand it to whatever needs it, and use a second
one with a different secret when a second audience needs isolation.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from capsize_auth.tokens import kinds

#: The only algorithm accepted, on issue and on decode. Pinning it is what
#: stops an attacker presenting an ``alg: none`` token.
ALGORITHM = "HS256"

#: Refuse a secret shorter than this: an HS256 key below the hash's own
#: block size is the one configuration mistake that silently weakens
#: everything built on it.
MIN_SECRET_LENGTH = 32


@dataclass(frozen=True)
class TokenTTLs:
    """How long each kind of signed token stays valid, in seconds."""

    access: int = 900
    refresh: int = 604800
    state: int = 600
    handoff: int = 60
    verify: int = 86400

    def for_kind(self, kind: str) -> int:
        """Return the lifetime configured for ``kind``."""
        mapping = {
            kinds.ACCESS: self.access,
            kinds.REFRESH: self.refresh,
            kinds.STATE: self.state,
            kinds.HANDOFF: self.handoff,
            kinds.VERIFY: self.verify,
        }
        if kind not in mapping:
            raise ValueError(f"no lifetime configured for {kind!r}")
        return mapping[kind]


@dataclass
class TokenSigner:
    """Issues and validates the signed tokens of one audience."""

    secret: str
    ttls: TokenTTLs = field(default_factory=TokenTTLs)
    #: Optional ``iss``/``aud`` claims, checked on decode when set.
    issuer: str | None = None
    audience: str | None = None

    def __post_init__(self) -> None:
        """Reject a secret too short to sign with."""
        if len(self.secret) < MIN_SECRET_LENGTH:
            raise ValueError(
                "signing secret must be at least "
                f"{MIN_SECRET_LENGTH} characters; generate one with "
                "python -c \"import secrets; print(secrets.token_hex(32))\""
            )

    def issue(self, kind: str, subject: str, **extra: object) -> str:
        """Return a signed token of ``kind`` for ``subject``."""
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iat": now,
            "exp": now + timedelta(seconds=self.ttls.for_kind(kind)),
            "type": kind,
            "sub": subject,
            **extra,
        }
        if self.issuer:
            claims["iss"] = self.issuer
        if self.audience:
            claims["aud"] = self.audience
        return jwt.encode(claims, self.secret, algorithm=ALGORITHM)

    def decode(self, token: str, expected: str) -> dict[str, Any] | None:
        """Return the claims of a valid ``expected``-type token, else None."""
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                self.secret,
                algorithms=[ALGORITHM],
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["exp", "iat", "type", "sub"]},
            )
        except jwt.PyJWTError:
            return None
        if claims.get("type") != expected:
            return None
        return claims
