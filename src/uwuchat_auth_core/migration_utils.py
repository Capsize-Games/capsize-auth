"""Idempotency helpers for the auth-core Alembic migrations.

The ``accounts`` and ``password_reset_tokens`` tables live in the shared
schema.  A multi-tenant provisioner may run the full migration set once
per schema, and Alembic can traverse the auth revision more than once in
a single ``upgrade("heads")`` pass (multiple disconnected roots sharing
one upgrade).  A naive ``op.create_table(...)`` then fails with
``DuplicateTable`` and aborts provisioning.

Guarding each migration with these checks makes the chain safe to
re-apply: a second pass becomes a no-op.  The checks read the live bind,
so they reflect DDL already committed in the same transaction.

Requires the optional ``alembic`` dependency (``pip install
uwuchat-auth-core[migrations]``).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


def has_table(table_name: str) -> bool:
    """Return True when *table_name* exists in the bind's current schema."""
    inspector = sa.inspect(op.get_bind())
    return inspector.has_table(table_name)


def has_column(table_name: str, column_name: str) -> bool:
    """Return True when *table_name* already has *column_name*."""
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table_name):
        return False
    return any(
        col["name"] == column_name
        for col in inspector.get_columns(table_name)
    )


__all__ = ["has_column", "has_table"]
