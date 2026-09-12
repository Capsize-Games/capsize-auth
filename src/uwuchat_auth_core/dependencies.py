"""FastAPI dependencies built on the auth middleware.

The middleware validates the token and populates
``request.state.account_id``; these dependencies enforce presence and,
for :func:`require_superuser`, the account's ``is_superuser`` flag.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from uwuchat_auth_core.models import Account
from uwuchat_auth_core.storage import get_backend


async def require_auth(request: Request) -> int:
    """Return the authenticated account ID.

    Raises:
        HTTPException: 401 when the middleware did not authenticate.
    """
    account_id = getattr(request.state, "account_id", None)
    if account_id is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )
    return account_id


def _load_account(account_id: int) -> Account | None:
    """Return the account row for *account_id*, or ``None``."""
    with get_backend().public_session_scope() as session:
        return (
            session.query(Account)
            .filter(Account.id == account_id)
            .first()
        )


async def require_superuser(
    account_id: int = Depends(require_auth),
) -> int:
    """Return the account ID, requiring ``is_superuser``.

    Raises:
        HTTPException: 401 when unauthenticated, 403 when the account is
            not a superuser.
    """
    account = _load_account(account_id)
    if not (account and account.is_superuser):
        raise HTTPException(
            status_code=403,
            detail="Superuser privileges required",
        )
    return account_id


__all__ = ["require_auth", "require_superuser"]
