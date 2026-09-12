"""Reference :class:`AuthStorageBackend` implementation.

This is a complete, working backend for a **single-database** deployment
(SQLite by default, but any SQLAlchemy URL works).  It exists so the
package's own test suite can run with no external services, and so a
consuming application has a concrete, readable example of the contract it
must satisfy.

It is intentionally *not* a schema-per-tenant backend: every tenant shares
one database, so both session scopes hand out the same session and
:meth:`provision_tenant` is a no-op.  Tenant keys still resolve to
schema-shaped names so JWT ``tenant`` claims keep the same shape as a
multi-tenant deployment.
"""

from __future__ import annotations

import contextlib
import re
from contextvars import ContextVar, Token
from typing import Any, Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from uwuchat_auth_core.base import Base

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SLUG_RE = re.compile(r"[^a-z0-9]+")

DEFAULT_SCHEMA_PREFIX = "tenant_"
"""Prefix applied to tenant keys when resolving schema names."""


class SqliteAuthStorageBackend:
    """Single-database reference backend.

    Args:
        url: SQLAlchemy URL.  In-memory SQLite gets a ``StaticPool`` so
            the same database is visible to every thread (FastAPI runs
            handlers off the main thread).
        schema_prefix: Prefix used when mapping tenant keys to
            schema-shaped names.
        create_schema: Create the tables on construction.
    """

    def __init__(
        self,
        url: str = "sqlite+pysqlite:///:memory:",
        schema_prefix: str = DEFAULT_SCHEMA_PREFIX,
        create_schema: bool = True,
    ) -> None:
        self._engine = create_engine(url, **self._engine_kwargs(url))
        self._session_factory = sessionmaker(bind=self._engine, future=True)
        self._schema_prefix = schema_prefix
        self._tenant_key: ContextVar[str | None] = ContextVar(
            "auth_core_reference_tenant_key",
            default=None,
        )
        if create_schema:
            Base.metadata.create_all(self._engine)

    @staticmethod
    def _engine_kwargs(url: str) -> dict[str, Any]:
        """Return engine kwargs; memory SQLite needs a shared pool."""
        if url.startswith("sqlite") and ":memory:" in url:
            from sqlalchemy.pool import StaticPool

            return {
                "poolclass": StaticPool,
                "connect_args": {"check_same_thread": False},
            }
        return {}

    # ── Sessions ─────────────────────────────────────────────────────

    @contextlib.contextmanager
    def public_session_scope(self) -> Iterator[Session]:
        """Yield a session, committing on success."""
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def session_scope(self) -> Any:
        """Yield a session for the active tenant (same database here)."""
        return self.public_session_scope()

    # ── Tenant naming ────────────────────────────────────────────────

    def tenant_schema_for_key(self, key: str | None) -> str:
        """Return the schema-shaped name for a raw tenant key."""
        raw = (key or "").strip().lower()
        if _UUID_RE.match(raw):
            return f"{self._schema_prefix}{raw.replace('-', '')}"
        slug = _SLUG_RE.sub("_", raw).strip("_") or "anonymous"
        return f"{self._schema_prefix}{slug}"

    def tenant_key_from_schema(self, schema: str | None) -> str | None:
        """Strip the schema prefix back off a schema name."""
        raw = (schema or "").strip()
        if not raw:
            return None
        prefix = self._schema_prefix
        if prefix and raw.startswith(prefix):
            raw = raw[len(prefix):]
        return raw or None

    # ── Tenant context ───────────────────────────────────────────────

    def set_tenant_key(self, key: str | None) -> Token[str | None]:
        """Activate *key* for the current context."""
        cleaned = (key or "").strip()
        return self._tenant_key.set(cleaned or None)

    def reset_tenant_key(self, token: Token[str | None]) -> None:
        """Restore the context state captured in *token*."""
        self._tenant_key.reset(token)

    def get_tenant_key(self) -> str | None:
        """Return the tenant key active in the current context."""
        return self._tenant_key.get()

    # ── Provisioning ─────────────────────────────────────────────────

    def provision_tenant(self, tenant_schema: str) -> None:
        """No-op: a single-database deployment has nothing to create."""

    # ── Lifecycle ────────────────────────────────────────────────────

    def dispose(self) -> None:
        """Release the connection pool (test teardown)."""
        self._engine.dispose()


__all__ = ["DEFAULT_SCHEMA_PREFIX", "SqliteAuthStorageBackend"]
