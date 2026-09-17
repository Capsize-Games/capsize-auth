"""The password sign-in decision, as one pure function.

Kept free of I/O on purpose: the host application does its own lookup, hands
over what it found, and gets back a verdict. That keeps this usable from a
sync Django view and an async FastAPI route alike, and it makes the ordering
rules -- which are the part that is easy to get wrong -- testable without a
database.

Two of those rules matter more than they look:

* **A missing account still burns a verify cycle.** Returning early on an
  unknown email makes sign-in measurably faster for addresses that are not
  registered, which turns the login form into an account-existence oracle.
* **The reason is not told to the user.** The outcome distinguishes a wrong
  password from a suspended account so the *caller* can log it, but a
  sign-in form should say one thing for all of them.
"""

from dataclasses import dataclass

from capsize_auth.accounts.principal import Principal
from capsize_auth.passwords import dummy_verify, verify_password

#: Outcomes.
OK = "ok"
NO_ACCOUNT = "no_account"
BAD_PASSWORD = "bad_password"
NOT_USABLE = "not_usable"
NO_PASSWORD_SET = "no_password_set"


@dataclass(frozen=True)
class LoginOutcome:
    """The verdict on one password sign-in attempt."""

    result: str
    principal: Principal | None = None

    @property
    def ok(self) -> bool:
        """Return whether the attempt should be allowed."""
        return self.result == OK


def check_password_login(
    password: str,
    principal: Principal | None,
    password_hash: str | None,
) -> LoginOutcome:
    """Return the verdict for ``password`` against a looked-up account.

    ``principal`` is None when no account matched, and ``password_hash`` is
    None for an account that has only ever signed in through a provider.
    """
    if principal is None:
        dummy_verify()
        return LoginOutcome(NO_ACCOUNT)
    if not password_hash:
        dummy_verify()
        return LoginOutcome(NO_PASSWORD_SET, principal)
    if not verify_password(password, password_hash):
        return LoginOutcome(BAD_PASSWORD, principal)
    if not principal.usable:
        return LoginOutcome(NOT_USABLE, principal)
    return LoginOutcome(OK, principal)
