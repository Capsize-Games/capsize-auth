"""SQLAlchemy declarative base used by the auth-core models.

The models in this package are deliberately plain SQLAlchemy: the host
application owns the engine, the session factory and schema resolution
(see :mod:`uwuchat_auth_core.storage`), so no manager/metaclass layer is
needed here.
"""

from __future__ import annotations

import datetime

from sqlalchemy import Boolean, Column, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()
"""Declarative base for every model in this package."""


class BaseModel(Base):
    """Shared abstract base: soft-delete flag plus creation timestamps."""

    __abstract__ = True

    created_at = Column(
        DateTime,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    updated_at = Column(
        DateTime,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        onupdate=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    deleted = Column(Boolean, nullable=False, default=False)


__all__ = ["Base", "BaseModel"]
