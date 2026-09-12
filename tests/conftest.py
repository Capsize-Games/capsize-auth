"""Shared fixtures for the auth-core test suite.

The suite runs standalone: a SQLite reference backend is installed for
every test, so no external database or application code is required.
"""

from __future__ import annotations

import os

import pytest

from uwuchat_auth_core import clear_backend, set_backend
from uwuchat_auth_core.reference import SqliteAuthStorageBackend

_TEST_JWT_SECRET = "test-secret-" + "a" * 40


def pytest_configure(config: pytest.Config) -> None:
    """Provide a strong JWT secret before any module imports it.

    ``uwuchat_auth_core.jwt`` validates its secret at import time, which
    happens during collection — earlier than any fixture runs.
    """
    os.environ.setdefault("AIRUNNER_JWT_SECRET", _TEST_JWT_SECRET)
    os.environ.setdefault("AIRUNNER_ALLOW_DEV_JWT_SECRET", "0")


@pytest.fixture(autouse=True)
def _backend():
    """Install a fresh in-memory reference backend for each test."""
    backend = SqliteAuthStorageBackend()
    set_backend(backend)
    yield backend
    clear_backend()
    backend.dispose()


@pytest.fixture(autouse=True)
def _clear_rate_limits() -> None:
    """Reset the in-memory rate limiter before every test."""
    from limits.storage.memory import MemoryStorage

    from uwuchat_auth_core.limiter import limiter

    limiter._storage = MemoryStorage()


@pytest.fixture()
def _db(_backend: SqliteAuthStorageBackend) -> SqliteAuthStorageBackend:
    """Alias kept so the tests read the same as the source suite."""
    return _backend
