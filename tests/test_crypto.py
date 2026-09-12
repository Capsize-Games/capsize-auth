"""Tests for the bundled Fernet keyring and the DEK cache."""

from __future__ import annotations

from cryptography.fernet import Fernet

import pytest

from uwuchat_auth_core.crypto import data_encryption as de
from uwuchat_auth_core.crypto import dek_cache


@pytest.fixture(autouse=True)
def _isolate_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep keyring/key-cache state from leaking between tests."""
    de._reset_edge_keyring_for_tests()
    monkeypatch.delenv("AIRUNNER_DATA_ENCRYPTION_KEYS", raising=False)
    monkeypatch.delenv("AIRUNNER_BASE_PATH", raising=False)


def test_missing_keys_raise() -> None:
    """Encrypting with no configured keyring is a hard error."""
    with pytest.raises(de.DataEncryptionError):
        de.get_keyring(required=True)


def test_missing_keys_optional_returns_none() -> None:
    """A non-required lookup returns None instead of raising."""
    assert de.get_keyring(required=False) is None
    assert de.is_encryption_active() is False


def test_encrypt_decrypt_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ciphertext decrypts back to the original plaintext."""
    monkeypatch.setenv("AIRUNNER_DATA_ENCRYPTION_KEYS", Fernet.generate_key().decode())
    assert de.is_encryption_active() is True
    token = de.encrypt_bytes(b"secret payload")
    assert token != b"secret payload"
    assert de.decrypt_bytes(token) == b"secret payload"


def test_key_rotation_decrypts_old_ciphertext(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rotated keyring still decrypts data written with the old key."""
    old_key = Fernet.generate_key().decode()
    new_key = Fernet.generate_key().decode()

    monkeypatch.setenv("AIRUNNER_DATA_ENCRYPTION_KEYS", old_key)
    token = de.encrypt_bytes(b"written before rotation")

    monkeypatch.setenv("AIRUNNER_DATA_ENCRYPTION_KEYS", f"{new_key},{old_key}")
    assert de.decrypt_bytes(token) == b"written before rotation"


def test_foreign_key_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ciphertext from an unknown key cannot be decrypted."""
    monkeypatch.setenv("AIRUNNER_DATA_ENCRYPTION_KEYS", Fernet.generate_key().decode())
    foreign = Fernet(Fernet.generate_key()).encrypt(b"nope")
    with pytest.raises(de.DataEncryptionError):
        de.decrypt_bytes(foreign)


def test_generate_fernet_key_is_valid() -> None:
    """Generated keys are usable by Fernet."""
    key = de.generate_fernet_key()
    assert Fernet(key.encode()).decrypt(Fernet(key.encode()).encrypt(b"x")) == b"x"


def test_edge_keyring_absent_without_base_path() -> None:
    """No BASE_PATH means no edge keyring (cloud deployments)."""
    assert de.get_edge_keyring() is None


def test_edge_keyring_generated_and_persisted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """The edge key is generated once and reused across calls."""
    monkeypatch.setenv("AIRUNNER_BASE_PATH", str(tmp_path))
    keyring = de.get_edge_keyring()
    assert keyring is not None

    key_file = tmp_path / "fernet_edge.key"
    assert key_file.exists()
    assert oct(key_file.stat().st_mode)[-3:] == "600"

    de._reset_edge_keyring_for_tests()
    assert de.get_edge_keyring().encrypt_key == keyring.encrypt_key


def test_dek_cache_set_get_evict() -> None:
    """The DEK cache stores, reads and evicts entries."""
    dek_cache.cache_set(1, b"dek-one")
    assert dek_cache.cache_get(1) == b"dek-one"
    assert dek_cache.cache_touch(1) is True
    dek_cache.cache_evict(1)
    assert dek_cache.cache_get(1) is None
    assert dek_cache.cache_touch(1) is False


def test_dek_cache_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    """An entry past its TTL is not returned."""
    dek_cache._dek_cache.set(2, b"dek-two", ttl=-1)
    assert dek_cache.cache_get(2) is None


def test_dek_scope_restores_context() -> None:
    """dek_scope restores the previous DEK, including None."""
    with dek_cache.dek_scope(b"request-dek"):
        assert dek_cache.get_user_dek() == b"request-dek"
    assert dek_cache.get_user_dek() is None
