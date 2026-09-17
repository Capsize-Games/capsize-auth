"""The ``type`` claim values this library issues and validates.

Every signed token carries one, and :meth:`TokenSigner.decode` refuses a
token whose type is not the one the caller asked for. Without that check a
short-lived state token would be accepted anywhere an access token is, which
is the classic confused-deputy bug in a hand-rolled JWT layer.
"""

#: A short-lived credential authorizing API calls.
ACCESS = "access"
#: A longer-lived credential whose only power is minting access tokens.
REFRESH = "refresh"
#: CSRF protection for an OAuth2 authorization request.
STATE = "oauth_state"
#: A very short-lived one-time code handed to a browser after OAuth, so
#: real credentials never travel in a URL, a log, or browser history.
HANDOFF = "oauth_handoff"
#: Proof that the holder controls an email address.
VERIFY = "verify"
