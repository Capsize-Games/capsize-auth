"""Fernet-based data encryption with key rotation and edge-key support.

Configuration (see :mod:`uwuchat_auth_core._env` for the prefix):

``<PREFIX>DATA_ENCRYPTION_KEYS``
    Comma-separated Fernet keys.  The first is used to encrypt; every key
    is tried when decrypting, so a key can be rotated by prepending the
    new key without losing access to existing ciphertext.

``<PREFIX>BASE_PATH``
    Optional application data directory.  When set, a persistent Fernet
    key is read (or generated once, mode ``0600``) at
    ``<BASE_PATH>/fernet_edge.key`` for single-machine deployments.
    Multi-tenant / cloud deployments must leave this unset and rely on a
    per-user key instead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from cryptography.fernet import Fernet, InvalidToken

from uwuchat_auth_core._env import env

KEYS_ENV = "DATA_ENCRYPTION_KEYS"
"""Suffix (with :func:`env`'s prefix) of the keyring variable."""

BASE_PATH_ENV = "BASE_PATH"
"""Suffix (with :func:`env`'s prefix) of the data-directory variable."""


class DataEncryptionError(RuntimeError):
    """Raised when the keyring is missing or a payload cannot be read."""


def _parse_keys(raw: str) -> list[bytes]:
    """Split a comma-separated key list into raw key bytes."""
    keys: list[bytes] = []
    for part in (raw or "").split(","):
        key = part.strip()
        if not key:
            continue
        try:
            keys.append(key.encode("utf-8"))
        except Exception:
            continue
    return keys


def generate_fernet_key() -> str:
    """Return a new base64 Fernet key as a string."""
    return Fernet.generate_key().decode("utf-8")


@dataclass(frozen=True)
class Keyring:
    """One encrypt key plus every key that may decrypt old data."""

    encrypt_key: bytes
    decrypt_keys: tuple[bytes, ...]

    def fernet_for_encrypt(self) -> Fernet:
        """Return the Fernet used for new ciphertext."""
        return Fernet(self.encrypt_key)

    def fernet_for_decrypt(self) -> Iterable[Fernet]:
        """Yield each decrypt candidate, newest first."""
        for k in self.decrypt_keys:
            yield Fernet(k)


def get_keyring(required: bool = True) -> Optional[Keyring]:
    """Build a keyring from the environment.

    Raises:
        DataEncryptionError: when *required* and no keys are configured.
    """
    raw = env(KEYS_ENV, "").strip()
    keys = _parse_keys(raw)
    if not keys:
        if required:
            raise DataEncryptionError(
                f"{KEYS_ENV} is not set; refusing to store encrypted data"
            )
        return None
    return Keyring(encrypt_key=keys[0], decrypt_keys=tuple(keys))


def encrypt_bytes(data: bytes) -> bytes:
    """Encrypt *data* with the current encrypt key."""
    if data is None:
        raise DataEncryptionError("encrypt_bytes received None")
    keyring = get_keyring(required=True)
    assert keyring is not None
    return keyring.fernet_for_encrypt().encrypt(data)


def decrypt_bytes(token: bytes) -> bytes:
    """Decrypt *token*, trying every configured key."""
    if token is None:
        raise DataEncryptionError("decrypt_bytes received None")
    keyring = get_keyring(required=True)
    assert keyring is not None

    last_err: Exception | None = None
    for fernet in keyring.fernet_for_decrypt():
        try:
            return fernet.decrypt(token)
        except InvalidToken as exc:
            last_err = exc
            continue

    raise DataEncryptionError(
        "Failed to decrypt payload with provided keys"
    ) from last_err


def is_encryption_active() -> bool:
    """Return True when a keyring is configured."""
    return get_keyring(required=False) is not None


# ── Persistent edge/local key ────────────────────────────────────────

_EDGE_KEY_FILENAME = "fernet_edge.key"
_edge_keyring: Keyring | None = None


def get_edge_keyring() -> Keyring | None:
    """Return the persistent edge keyring, or ``None`` when unconfigured.

    Reads or generates ``<BASE_PATH>/fernet_edge.key``.  Returns ``None``
    when ``BASE_PATH`` is unset — cloud/multi-tenant deployments must
    never use a single shared key.
    """
    global _edge_keyring

    if _edge_keyring is not None:
        return _edge_keyring

    base = env(BASE_PATH_ENV, "").strip()
    if not base:
        return None

    key_path = Path(base) / _EDGE_KEY_FILENAME
    try:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            key_bytes = key_path.read_text().strip().encode("ascii")
        else:
            key_bytes = Fernet.generate_key()
            key_path.write_text(key_bytes.decode("ascii"))
            # The key file is a secret — owner-only.
            key_path.chmod(0o600)
    except OSError:
        return None

    _edge_keyring = Keyring(
        encrypt_key=key_bytes,
        decrypt_keys=(key_bytes,),
    )
    return _edge_keyring


def _reset_edge_keyring_for_tests() -> None:
    """Clear the cached edge keyring (test-only)."""
    global _edge_keyring
    _edge_keyring = None


__all__ = [
    "BASE_PATH_ENV",
    "KEYS_ENV",
    "DataEncryptionError",
    "Keyring",
    "decrypt_bytes",
    "encrypt_bytes",
    "generate_fernet_key",
    "get_edge_keyring",
    "get_keyring",
    "is_encryption_active",
]
