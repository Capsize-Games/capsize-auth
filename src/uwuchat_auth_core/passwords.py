"""Password hashing using argon2id (via ``argon2-cffi``).

Argon2id is the OWASP-recommended password hashing algorithm.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

_hasher = PasswordHasher(
    time_cost=3,  # Number of iterations
    memory_cost=65536,  # 64 MiB
    parallelism=4,  # Number of threads
    hash_len=32,  # Length of the hash in bytes
    salt_len=16,  # Length of the salt in bytes
)

_DUMMY_PASSWORD = "dummy-password-for-constant-time-compare"

# Precomputed hash of a throwaway value.  Verifying against it spends
# roughly the same CPU as a real check, so response timing does not
# reveal which emails are registered.
_DUMMY_HASH = _hasher.hash(_DUMMY_PASSWORD)


def hash_password(password: str) -> str:
    """Return an argon2id hash of *password*."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Return whether *password* matches the stored *password_hash*."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


def dummy_verify() -> None:
    """Burn a verify cycle to mask account-existence timing differences."""
    try:
        _hasher.verify(_DUMMY_HASH, _DUMMY_PASSWORD)
    except (VerifyMismatchError, VerificationError):
        pass


__all__ = ["dummy_verify", "hash_password", "verify_password"]
