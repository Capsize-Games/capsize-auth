"""Tests for the configurable environment-variable prefix."""

from __future__ import annotations

import pytest

from uwuchat_auth_core._env import (
    DEFAULT_PREFIX,
    env,
    env_int,
    env_prefix,
)


def test_default_prefix_is_airunner(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no override the package reads AIRunner-named variables."""
    monkeypatch.delenv("AUTH_CORE_ENV_PREFIX", raising=False)
    monkeypatch.setenv("AIRUNNER_EXAMPLE_SETTING", "value")
    assert env_prefix() == DEFAULT_PREFIX
    assert env("EXAMPLE_SETTING") == "value"


def test_prefix_override_reads_own_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A standalone app can use its own variable names."""
    monkeypatch.setenv("AUTH_CORE_ENV_PREFIX", "MYAPP_")
    monkeypatch.setenv("MYAPP_JWT_SECRET", "own-secret")
    monkeypatch.setenv("AIRUNNER_JWT_SECRET", "legacy-secret")
    assert env_prefix() == "MYAPP_"
    assert env("JWT_SECRET") == "own-secret"


def test_prefix_normalised(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lowercase / dash-separated prefixes are normalised."""
    monkeypatch.setenv("AUTH_CORE_ENV_PREFIX", "my-app")
    assert env_prefix() == "MY_APP_"


def test_blank_prefix_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty override does not produce an unprefixed lookup."""
    monkeypatch.setenv("AUTH_CORE_ENV_PREFIX", "   ")
    assert env_prefix() == DEFAULT_PREFIX


def test_env_int_parses_and_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """env_int parses numbers and treats junk/absent values as default."""
    monkeypatch.setenv("AIRUNNER_SOME_TTL", "42")
    assert env_int("SOME_TTL", 7) == 42
    monkeypatch.setenv("AIRUNNER_SOME_TTL", "not-a-number")
    assert env_int("SOME_TTL", 7) == 7
    monkeypatch.delenv("AIRUNNER_SOME_TTL")
    assert env_int("SOME_TTL", 7) == 7
