"""PKCE (RFC 7636) verifier and challenge generation.

Required for any client that cannot keep a secret -- a desktop application, a
CLI, a single-page app. The client keeps the verifier, sends only its hash,
and an attacker who intercepts the authorization code cannot redeem it.
"""

import base64
import hashlib
import secrets
from dataclasses import dataclass

#: The transform this library uses. ``plain`` is legal in the RFC and
#: deliberately not offered: it provides no protection.
METHOD = "S256"


@dataclass(frozen=True)
class PkcePair:
    """A verifier kept by the client and the challenge sent to the server."""

    verifier: str
    challenge: str
    method: str = METHOD


def _b64(raw: bytes) -> str:
    """Return base64url of ``raw`` without padding, as the RFC requires."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def challenge_for(verifier: str) -> str:
    """Return the S256 challenge derived from ``verifier``."""
    return _b64(hashlib.sha256(verifier.encode("ascii")).digest())


def generate() -> PkcePair:
    """Return a fresh verifier and its challenge."""
    verifier = _b64(secrets.token_bytes(32))
    return PkcePair(verifier=verifier, challenge=challenge_for(verifier))


def verify(verifier: str, challenge: str) -> bool:
    """Return whether ``verifier`` produces ``challenge``."""
    return secrets.compare_digest(challenge_for(verifier), challenge)
