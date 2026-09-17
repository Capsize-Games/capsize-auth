"""Failures the authorization-code flow can produce."""


class OAuth2Error(Exception):
    """Base class for a failure during an OAuth2 exchange."""


class ProviderNotConfiguredError(OAuth2Error):
    """A provider was asked for that has no credentials installed."""


class ExchangeFailedError(OAuth2Error):
    """The provider refused the authorization code, or returned no token."""


class ProfileUnavailableError(OAuth2Error):
    """The access token worked but no usable profile came back."""
