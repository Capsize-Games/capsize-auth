"""Account status lookup used by the auth middleware.

Kept in its own module so the middleware can be read as pure control flow
and so the single accounts-table query has one home.
"""

from __future__ import annotations

from uwuchat_auth_core.models import Account
from uwuchat_auth_core.storage import get_backend

STATUS_DELETED = "deleted"
STATUS_BANNED = "banned"
STATUS_SUSPENDED = "suspended"


def check_account_status(account_id: int) -> tuple[str | None, int]:
    """Return ``(status, token_version)`` for an account ID.

    *status* is ``'deleted'``, ``'banned'``, ``'suspended'`` or ``None``
    (active).  *token_version* is the account's current version, used to
    revoke tokens issued before a logout or password change.

    Raises:
        RuntimeError: when the database is unreachable.  Callers MUST
            fail closed (503) rather than let a potentially banned or
            deleted account through.
    """
    backend = get_backend()
    try:
        with backend.public_session_scope() as session:
            account = (
                session.query(Account)
                .filter(Account.id == account_id)
                .first()
            )
            if account is None or account.deleted:
                return STATUS_DELETED, 0
            status: str | None = None
            if account.is_banned:
                status = STATUS_BANNED
            elif account.is_suspended:
                status = STATUS_SUSPENDED
            return status, int(account.token_version or 0)
    except Exception as exc:
        raise RuntimeError(
            "Database unreachable during account-status check for "
            f"account {account_id}"
        ) from exc


__all__ = [
    "STATUS_BANNED",
    "STATUS_DELETED",
    "STATUS_SUSPENDED",
    "check_account_status",
]
