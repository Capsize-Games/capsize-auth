"""The authenticated subject, as this library needs to see it.

Deliberately not an ORM model. The library this was extracted from shipped its
own ``accounts`` table, which meant adopting the extraction also meant
adopting that application's billing columns, its tenant scheme, and its
primary-key type. A :class:`Principal` is instead what a host application maps
*its own* row onto for the duration of a call, so the library needs no
database, no migrations, and no opinion about how accounts are stored.
"""

from dataclasses import dataclass

from capsize_auth.accounts import status as status_mod


@dataclass(frozen=True)
class Principal:
    """One account, viewed as an authenticating subject."""

    #: The host's identifier, stringified. An integer primary key, a UUID and
    #: an external id all work; it ends up in the token's ``sub`` claim.
    id: str
    email: str = ""
    username: str = ""
    status: str = status_mod.ACTIVE
    #: Incremented by the host to invalidate every token already issued to
    #: this account -- what "sign out everywhere" and a password change do.
    #: A token whose ``ver`` claim is behind this is refused.
    token_version: int = 0
    is_admin: bool = False

    @property
    def usable(self) -> bool:
        """Return whether this account may authenticate."""
        return status_mod.usable(self.status)
