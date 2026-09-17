"""The authenticating subject and the sign-in decision.

This package holds no database code. A host application maps its own account
row onto a :class:`~capsize_auth.accounts.principal.Principal` and keeps
ownership of storage, migrations, and identifier types.
"""

from capsize_auth.accounts import status
from capsize_auth.accounts.login import (
    BAD_PASSWORD,
    NO_ACCOUNT,
    NO_PASSWORD_SET,
    NOT_USABLE,
    OK,
    LoginOutcome,
    check_password_login,
)
from capsize_auth.accounts.principal import Principal

__all__ = [
    "BAD_PASSWORD",
    "NOT_USABLE",
    "NO_ACCOUNT",
    "NO_PASSWORD_SET",
    "OK",
    "LoginOutcome",
    "Principal",
    "check_password_login",
    "status",
]
