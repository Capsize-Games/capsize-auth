"""Which providers a deployment has enabled."""

import pytest

from capsize_auth.oauth2 import (
    ProviderNotConfiguredError,
    ProviderRegistry,
)
from capsize_auth.oauth2.presets import PRESETS

TEMPLATE = "https://hub.example.net/oauth/{provider}/callback"


def registry() -> ProviderRegistry:
    return ProviderRegistry(TEMPLATE)


def test_a_template_without_the_placeholder_is_refused() -> None:
    with pytest.raises(ValueError, match="must contain"):
        ProviderRegistry("https://hub.example.net/callback")


def test_a_registered_preset_becomes_available() -> None:
    hub = registry()
    hub.register_preset("github", "id", "secret")
    assert "github" in hub
    assert [p.id for p in hub.available()] == ["github"]
    assert hub.client("github").redirect_uri == (
        "https://hub.example.net/oauth/github/callback"
    )


def test_an_unregistered_provider_is_not_offered() -> None:
    with pytest.raises(ProviderNotConfiguredError):
        registry().client("github")


def test_an_unknown_preset_names_the_known_ones() -> None:
    with pytest.raises(ValueError, match="github"):
        registry().register_preset("myspace", "id", "secret")


def test_credentials_are_required() -> None:
    with pytest.raises(ValueError, match="client_id and client_secret"):
        registry().register_preset("github", "id", "")


def test_every_bundled_preset_can_be_registered() -> None:
    hub = registry()
    for provider_id in PRESETS:
        hub.register_preset(provider_id, "id", "secret")
    assert len(hub.available()) == len(PRESETS)
