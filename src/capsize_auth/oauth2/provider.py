"""A provider described as data rather than as a module of its own.

The library this was extracted from had one module per provider, each with
its client id read from the environment at import time. Adding a provider
meant writing a module; supporting two deployments with different providers
meant editing code. Here a provider is a frozen description -- endpoints,
scopes, and where its fields live -- so a host application can add one
without this package changing, which is the point of
:mod:`capsize_auth.oauth2.presets` being ordinary values.
"""

from dataclasses import dataclass, field
from typing import Literal

from capsize_auth.oauth2.profile import ProfileMap

#: How the userinfo request carries the access token. Nearly every provider
#: accepts a bearer header; a few older ones only read a query parameter.
AuthStyle = Literal["header", "query"]


@dataclass(frozen=True)
class OAuth2Provider:
    """Everything needed to run the authorization-code flow somewhere."""

    #: Stable short name, persisted alongside the account's subject.
    id: str
    display_name: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scopes: tuple[str, ...] = ()
    mapping: ProfileMap = field(default_factory=ProfileMap)
    #: Extra query parameters the authorization request needs (Google's
    #: ``access_type``, a provider's ``response_mode``, and so on).
    authorize_params: dict[str, str] = field(default_factory=dict)
    userinfo_auth: AuthStyle = "header"
    #: Some providers omit a private email from userinfo and expose it on a
    #: second endpoint. When set, it is fetched only if the first response
    #: carried no address.
    emails_url: str | None = None
    #: Separator for the ``scope`` parameter. The spec says space; a few
    #: providers require commas and reject spaces.
    scope_separator: str = " "
    supports_pkce: bool = True
    #: Whether the token request must be sent with client credentials in the
    #: Authorization header rather than the form body.
    basic_auth_token_request: bool = False

    def scope_value(self) -> str:
        """Return the ``scope`` parameter for this provider."""
        return self.scope_separator.join(self.scopes)
