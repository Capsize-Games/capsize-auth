"""Storage/tenancy seam between the auth core and the host application.

Everything in this package that needs a database session, a tenant
namespace, or a schema-provisioning side effect goes through one object
implementing :class:`AuthStorageBackend`.  The host application installs
its implementation once at startup::

    from uwuchat_auth_core import set_backend
    from myapp.auth_backend import MyAuthStorageBackend

    set_backend(MyAuthStorageBackend(...))

The core never imports the host application, so the same auth logic runs
unchanged against any session/tenancy implementation.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "AuthCoreNotConfigured",
    "AuthStorageBackend",
    "clear_backend",
    "get_backend",
    "set_backend",
]


class AuthCoreNotConfigured(RuntimeError):
    """Raised when auth-core functionality is used with no backend set."""


@runtime_checkable
class AuthStorageBackend(Protocol):
    """The host-application seam required by the auth core.

    Implementations must be safe to call from multiple threads and must
    restore any context-variable state they set (see
    :meth:`set_tenant_key` / :meth:`reset_tenant_key`) exactly as the
    ``contextvars`` module does — the token returned by
    :meth:`set_tenant_key` is what :meth:`reset_tenant_key` receives.
    """

    def public_session_scope(self) -> AbstractContextManager[Any]:
        """Yield a session bound to the shared (non-tenant) schema.

        The ``accounts`` and ``password_reset_tokens`` tables live here
        so they can be queried before tenant context exists (login).
        """
        ...

    def session_scope(self) -> AbstractContextManager[Any]:
        """Yield a session bound to the currently active tenant's schema."""
        ...

    def tenant_schema_for_key(self, key: str | None) -> str:
        """Return the fully-qualified schema name for a raw tenant key."""
        ...

    def tenant_key_from_schema(self, schema: str | None) -> str | None:
        """Recover the raw tenant key from a schema name (inverse above)."""
        ...

    def set_tenant_key(self, key: str | None) -> Any:
        """Activate *key* for the current context; return a reset token."""
        ...

    def reset_tenant_key(self, token: Any) -> None:
        """Restore the context state captured in *token*."""
        ...

    def get_tenant_key(self) -> str | None:
        """Return the tenant key active in the current context, if any."""
        ...

    def provision_tenant(self, tenant_schema: str) -> None:
        """Create *tenant_schema* and any per-tenant defaults.

        Called when an account is created for a schema that does not yet
        exist.  Implementations that never materialise schemas (single
        database deployments) may make this a no-op.
        """
        ...


_backend: AuthStorageBackend | None = None


def set_backend(backend: AuthStorageBackend) -> None:
    """Install the process-wide storage backend."""
    global _backend
    _backend = backend


def clear_backend() -> None:
    """Remove the installed backend (test teardown / shutdown)."""
    global _backend
    _backend = None


def get_backend() -> AuthStorageBackend:
    """Return the installed backend.

    Raises:
        AuthCoreNotConfigured: when no backend has been installed.
    """
    if _backend is None:
        raise AuthCoreNotConfigured(
            "No AuthStorageBackend installed — call "
            "uwuchat_auth_core.set_backend(...) during application startup."
        )
    return _backend
