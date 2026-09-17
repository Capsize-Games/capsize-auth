"""Account states, and the single rule for whether one may sign in."""

#: Normal.
ACTIVE = "active"
#: Temporarily blocked. Sign-in is refused; the account's content stays.
SUSPENDED = "suspended"
#: Permanently blocked by a moderation decision.
BANNED = "banned"
#: Erased, or scheduled for erasure. Treated as absent everywhere.
DELETED = "deleted"

#: Every state a caller may store.
ALL = (ACTIVE, SUSPENDED, BANNED, DELETED)

#: The states that refuse authentication.
BLOCKED = (SUSPENDED, BANNED, DELETED)


def usable(status: str) -> bool:
    """Return whether an account in ``status`` may authenticate."""
    return status == ACTIVE
