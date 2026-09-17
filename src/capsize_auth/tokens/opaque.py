"""Opaque, high-entropy secrets stored only as a hash.

Used for anything the holder presents back to us and that must be revocable
on demand: password-reset links, personal access tokens, session cookies.
Unlike a JWT these carry no claims, which is the point -- revoking one is a
row update rather than a blocklist.

They are not passwords. A slow key-derivation function would buy nothing
against a 256-bit random value, so the stored form is a plain SHA-256: cheap
to check, and useless to an attacker holding only a database copy.
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass

#: Bytes of entropy in a generated token, before URL-safe encoding.
TOKEN_BYTES = 32


@dataclass(frozen=True)
class OpaqueToken:
    """A freshly minted secret and the hash to store in its place."""

    #: Shown to the holder exactly once, then never recoverable.
    plaintext: str
    #: What the database keeps.
    hashed: str


def hash_token(plaintext: str) -> str:
    """Return the stored form of ``plaintext``."""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def new_token(prefix: str = "") -> OpaqueToken:
    """Return a new secret, optionally prefixed for recognisability.

    A prefix such as ``sfh_pat_`` lets a leaked credential be identified at
    a glance -- by its owner, by a secret scanner, or in a support request --
    without revealing the random part.
    """
    body = secrets.token_urlsafe(TOKEN_BYTES)
    plaintext = f"{prefix}{body}" if prefix else body
    return OpaqueToken(plaintext=plaintext, hashed=hash_token(plaintext))


def matches(plaintext: str, hashed: str) -> bool:
    """Return whether ``plaintext`` hashes to ``hashed``.

    Compared with :func:`hmac.compare_digest` so a wrong guess cannot be
    narrowed down by how long the comparison took.
    """
    return hmac.compare_digest(hash_token(plaintext), hashed)
