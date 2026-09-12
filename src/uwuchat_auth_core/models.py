"""Auth-core SQLAlchemy models.

Only :class:`Account` lives here; the password-reset token model lives in
:mod:`uwuchat_auth_core.password_reset_token`.  Both belong to the shared
(public) schema so they can be queried before tenant context exists —
during login, for example.

The ``accounts`` table carries the billing columns (``stripe_*``,
``trial_used``, …) exactly as the source application defined them.  They
are retained deliberately: dropping columns would make a ported database
structurally diverge from the table this core was extracted from.  They
are inert unless an application's billing layer reads them.
"""

from __future__ import annotations

import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    JSON,
    Numeric,
    String,
    Text,
)

from uwuchat_auth_core.auth_provider import AuthProvider
from uwuchat_auth_core.base import BaseModel


def _utcnow() -> datetime.datetime:
    """Return the current time as an aware UTC datetime."""
    return datetime.datetime.now(datetime.timezone.utc)


class Account(BaseModel):
    """Authentication account — one row per registered user.

    Lives outside tenant schemas so it can be queried before tenant
    context is established (e.g. during login).
    """

    __tablename__ = "accounts"
    __public_schema__ = True

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, unique=True, nullable=False, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    # Nullable for OAuth-only accounts.
    password_hash = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)
    is_suspended = Column(Boolean, nullable=False, default=False)
    is_banned = Column(Boolean, nullable=True)
    ban_reason = Column(String, nullable=True)
    tenant_schema = Column(String, unique=True, nullable=False)
    created_at = Column(
        DateTime,
        # Callable default — evaluated per insert.  A bare value would be
        # frozen at import time and stamp every row with process start.
        default=_utcnow,
    )
    last_login = Column(DateTime, nullable=True)

    # ── OAuth identity ───────────────────────────────────────────────
    google_id = Column(String, nullable=True, unique=True)
    steam_id = Column(String, nullable=True, unique=True)
    twitch_id = Column(String, nullable=True, unique=True)
    auth_provider = Column(
        String,
        nullable=False,
        default=AuthProvider.LOCAL.value,
    )

    # Bumped to revoke every outstanding refresh token (logout-everywhere).
    token_version = Column(Integer, nullable=False, default=0)

    # ── Terms-of-service agreement ───────────────────────────────────
    tos_agreed = Column(Boolean, nullable=False, default=False)
    age_confirmed = Column(Boolean, nullable=False, default=False)
    entertainment_confirmed = Column(Boolean, nullable=False, default=False)
    tos_agreed_at = Column(DateTime, nullable=True)
    tos_agreed_ip = Column(String(64), nullable=True)

    # ── Sensitive-data consent ───────────────────────────────────────
    # Required only in jurisdictions with consent-based privacy regimes
    # that lack GDPR's default-prohibition posture.
    sensitive_data_consent_agreed = Column(
        Boolean, nullable=False, default=False
    )
    sensitive_data_consent_at = Column(DateTime, nullable=True)
    sensitive_data_consent_ip = Column(String(64), nullable=True)

    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    deleted = Column(Boolean, nullable=False, default=False)

    # ── Billing columns (owned by a separate billing concern) ────────
    stripe_customer_id = Column(String, nullable=True, unique=True)
    stripe_subscription_id = Column(String, nullable=True)
    stripe_subscription_status = Column(String, nullable=True)
    stripe_subscription_tier = Column(String, nullable=True)
    stripe_current_period_end = Column(DateTime, nullable=True)
    last_tier_change_at = Column(DateTime, nullable=True)
    trial_used = Column(Boolean, nullable=False, default=False)
    # Prepaid balance.  Numeric, never Float — sub-cent costs must not
    # drift across many small debits.
    code_credits_usd = Column(Numeric(10, 4), nullable=False, default=0)

    # ── Per-user key envelope ────────────────────────────────────────
    # The data-encryption key is wrapped with a key derived from the
    # password.  Null for OAuth-only accounts and for legacy rows that
    # have not logged in since the envelope migration.
    wrapped_dek = Column(Text, nullable=True)
    dek_kdf_salt = Column(String(64), nullable=True)
    dek_kdf_params = Column(JSON, nullable=True)
    dek_version = Column(Integer, nullable=False, default=1)


__all__ = ["Account"]
