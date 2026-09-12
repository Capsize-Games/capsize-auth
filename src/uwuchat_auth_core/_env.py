"""Environment-variable naming for the auth core.

Every setting in this package is read through :func:`env`, which applies a
single configurable prefix.  The default prefix is ``AIRUNNER_`` so the
package can be dropped into an existing AIRunner deployment without
renaming anything; a standalone consumer sets ``AUTH_CORE_ENV_PREFIX``
(for example ``UWUCHAT_``) to read its own variable names instead::

    AUTH_CORE_ENV_PREFIX=UWUCHAT_   ->   UWUCHAT_JWT_SECRET
    (unset)                         ->   AIRUNNER_JWT_SECRET

This indirection is the only reason the package can be published without
an ``airunner`` dependency and still preserve the original variable names
for the deployment it came from.
"""

from __future__ import annotations

import os

PREFIX_ENV_VAR = "AUTH_CORE_ENV_PREFIX"
"""Name of the variable that overrides the setting prefix."""

DEFAULT_PREFIX = "AIRUNNER_"
"""Prefix applied when ``AUTH_CORE_ENV_PREFIX`` is unset."""


def env_prefix() -> str:
    """Return the active setting prefix, always ending in an underscore."""
    raw = os.environ.get(PREFIX_ENV_VAR)
    if raw is None:
        return DEFAULT_PREFIX
    cleaned = raw.strip().upper().replace("-", "_")
    if not cleaned:
        return DEFAULT_PREFIX
    return cleaned if cleaned.endswith("_") else cleaned + "_"


def env(name: str, default: str = "") -> str:
    """Return the configured value of *name*, or *default* when unset."""
    return os.environ.get(env_prefix() + name, default)


def env_int(name: str, default: int) -> int:
    """Return *name* as an ``int``, falling back to *default*."""
    raw = env(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


__all__ = [
    "DEFAULT_PREFIX",
    "PREFIX_ENV_VAR",
    "env",
    "env_int",
    "env_prefix",
]
