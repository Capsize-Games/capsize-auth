"""Tests for the storage seam and the reference backend."""

from __future__ import annotations

import pytest

from uwuchat_auth_core import (
    AuthCoreNotConfigured,
    clear_backend,
    get_backend,
    set_backend,
)
from uwuchat_auth_core.models import Account
from uwuchat_auth_core.reference import SqliteAuthStorageBackend

from .test_middleware import _make_account


def test_get_backend_raises_when_unset() -> None:
    """Using the core with no backend installed is a loud error."""
    clear_backend()
    with pytest.raises(AuthCoreNotConfigured):
        get_backend()


def test_reference_backend_satisfies_protocol(_db) -> None:
    """The reference backend implements the full protocol."""
    from uwuchat_auth_core.storage import AuthStorageBackend

    assert isinstance(_db, AuthStorageBackend)


def test_tenant_key_round_trip(_db) -> None:
    """A key maps to a schema and back again."""
    schema = _db.tenant_schema_for_key("Alice Jones")
    assert schema == "tenant_alice_jones"
    assert _db.tenant_key_from_schema(schema) == "alice_jones"


def test_uuid_keys_are_compact(_db) -> None:
    """UUID-shaped keys lose their dashes, matching schema limits."""
    key = "6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8"
    schema = _db.tenant_schema_for_key(key)
    assert schema == "tenant_" + key.replace("-", "")


def test_empty_key_falls_back_to_anonymous(_db) -> None:
    """A blank key still resolves to a usable schema name."""
    assert _db.tenant_schema_for_key("") == "tenant_anonymous"


def test_tenant_key_context_is_restored(_db) -> None:
    """reset_tenant_key restores the previous context value."""
    token = _db.set_tenant_key("alice")
    assert _db.get_tenant_key() == "alice"
    _db.reset_tenant_key(token)
    assert _db.get_tenant_key() is None


def test_public_and_tenant_scopes_both_yield_a_session(_db) -> None:
    """Both session scopes see the same single reference database."""
    _make_account(_db, 7)
    for scope in (_db.public_session_scope, _db.session_scope):
        with scope() as session:
            assert session.query(Account).count() == 1


def test_set_backend_replaces_instance(_backend) -> None:
    """set_backend installs the supplied instance."""
    replacement = SqliteAuthStorageBackend()
    try:
        set_backend(replacement)
        assert get_backend() is replacement
    finally:
        replacement.dispose()
