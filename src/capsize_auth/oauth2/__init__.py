"""Generic OAuth2 authorization-code support.

A provider is data (:class:`~capsize_auth.oauth2.provider.OAuth2Provider`),
one client runs the flow for all of them
(:class:`~capsize_auth.oauth2.client.OAuth2Client`), and a deployment declares
which it has enabled
(:class:`~capsize_auth.oauth2.registry.ProviderRegistry`). Adding a provider
this package has never heard of requires no change to this package.
"""

from capsize_auth.oauth2.client import OAuth2Client
from capsize_auth.oauth2.errors import (
    ExchangeFailedError,
    OAuth2Error,
    ProfileUnavailableError,
    ProviderNotConfiguredError,
)
from capsize_auth.oauth2.pkce import PkcePair, challenge_for, generate
from capsize_auth.oauth2.presets import PRESETS
from capsize_auth.oauth2.profile import OAuthProfile, ProfileMap
from capsize_auth.oauth2.provider import OAuth2Provider
from capsize_auth.oauth2.registry import ProviderInfo, ProviderRegistry

__all__ = [
    "PRESETS",
    "ExchangeFailedError",
    "OAuth2Client",
    "OAuth2Error",
    "OAuth2Provider",
    "OAuthProfile",
    "PkcePair",
    "ProfileMap",
    "ProfileUnavailableError",
    "ProviderInfo",
    "ProviderNotConfiguredError",
    "ProviderRegistry",
    "challenge_for",
    "generate",
]
