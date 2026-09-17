"""Password hashing with argon2id, the OWASP-recommended choice.

The parameters below are the ones this code shipped with; changing them
changes the cost of every future hash and leaves existing hashes verifiable,
since argon2 encodes its parameters in the hash string.
"""

from contextlib import suppress

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

#: Every failure mode of a verify that means "this password does not match".
#:
#: ``InvalidHashError`` is included deliberately and is easy to miss: it
#: subclasses ``ValueError``, *not* ``VerificationError``, so catching the
#: latter two leaves it propagating. A stored hash that is truncated, corrupt,
#: or produced by a different algorithm -- exactly what a half-finished
#: migration from another scheme leaves behind -- would then raise out of the
#: sign-in path and return a server error instead of refusing the attempt.
_VERIFY_FAILURES = (
    VerifyMismatchError,
    VerificationError,
    InvalidHashError,
)

_DUMMY_PASSWORD = "dummy-password-for-constant-time-compare"

# Precomputed hash of a throwaway value. Verifying against it spends roughly
# the same CPU as a real check, so response timing does not reveal which
# addresses are registered.
_DUMMY_HASH = _hasher.hash(_DUMMY_PASSWORD)


def hash_password(password: str) -> str:
    """Return an argon2id hash of ``password``."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Return whether ``password`` matches ``password_hash``.

    Never raises for a bad password or an unusable stored hash: a sign-in
    path has one answer for all of them.
    """
    try:
        return _hasher.verify(password_hash, password)
    except _VERIFY_FAILURES:
        return False


def needs_rehash(password_hash: str) -> bool:
    """Return whether ``password_hash`` was made with weaker parameters.

    Call it after a successful verify: when it is true, re-hash the password
    the caller just proved they know and store the result. That is the only
    moment the plaintext is available, so it is the only moment the cost
    parameters can be raised for an existing account.
    """
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def dummy_verify() -> None:
    """Burn a verify cycle to mask account-existence timing differences."""
    with suppress(*_VERIFY_FAILURES):
        _hasher.verify(_DUMMY_HASH, _DUMMY_PASSWORD)
