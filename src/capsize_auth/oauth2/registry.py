"""The set of providers a deployment has actually enabled.

A deployment enables a provider by registering credentials for it. Nothing is
enabled implicitly: a preset existing in this package is not the same as a
deployment offering it, which is what lets a sign-in page render exactly the
buttons that will work.
"""

from dataclasses import dataclass

from capsize_auth.oauth2.client import OAuth2Client
from capsize_auth.oauth2.errors import ProviderNotConfiguredError
from capsize_auth.oauth2.presets import PRESETS
from capsize_auth.oauth2.provider import OAuth2Provider


@dataclass(frozen=True)
class ProviderInfo:
    """What a sign-in page needs to render one provider's button."""

    id: str
    display_name: str


class ProviderRegistry:
    """Holds the configured providers for one application."""

    def __init__(self, redirect_uri_template: str) -> None:
        """Take the callback URL shape, with a ``{provider}`` placeholder.

        For example ``https://hub.example.net/oauth/{provider}/callback``.
        Keeping one template here means a new provider needs no new route and
        no new configuration value.
        """
        if "{provider}" not in redirect_uri_template:
            raise ValueError(
                "redirect_uri_template must contain '{provider}': "
                f"got {redirect_uri_template!r}"
            )
        self._template = redirect_uri_template
        self._clients: dict[str, OAuth2Client] = {}

    def register(
        self,
        provider: OAuth2Provider,
        client_id: str,
        client_secret: str,
    ) -> None:
        """Enable ``provider`` with the given credentials."""
        if not client_id or not client_secret:
            raise ValueError(
                f"{provider.id}: both client_id and client_secret are "
                "required to enable a provider"
            )
        self._clients[provider.id] = OAuth2Client(
            provider=provider,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=self.redirect_uri(provider.id),
        )

    def register_preset(
        self, provider_id: str, client_id: str, client_secret: str
    ) -> None:
        """Enable a bundled preset by its id."""
        provider = PRESETS.get(provider_id)
        if provider is None:
            known = ", ".join(sorted(PRESETS))
            raise ValueError(
                f"no bundled preset named {provider_id!r}; known: {known}. "
                "Register a custom OAuth2Provider instead."
            )
        self.register(provider, client_id, client_secret)

    def redirect_uri(self, provider_id: str) -> str:
        """Return the callback URL for ``provider_id``."""
        return self._template.format(provider=provider_id)

    def client(self, provider_id: str) -> OAuth2Client:
        """Return the configured client for ``provider_id``."""
        found = self._clients.get(provider_id)
        if found is None:
            raise ProviderNotConfiguredError(
                f"provider {provider_id!r} is not enabled on this deployment"
            )
        return found

    def available(self) -> list[ProviderInfo]:
        """Return the enabled providers, for rendering a sign-in page."""
        return [
            ProviderInfo(
                id=client.provider.id,
                display_name=client.provider.display_name,
            )
            for client in self._clients.values()
        ]

    def __contains__(self, provider_id: object) -> bool:
        """Return whether ``provider_id`` is enabled."""
        return provider_id in self._clients
