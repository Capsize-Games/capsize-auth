"""Mapping each provider's payload onto one normalised shape."""

import pytest

from capsize_auth.oauth2.presets import DISCORD, GITHUB, GOOGLE, TWITCH
from capsize_auth.oauth2.profile import ProfileMap, build_profile, pluck


def test_github_uses_id_and_login() -> None:
    profile = build_profile(
        "github",
        {"id": 5150, "login": "octocat", "name": "The Octocat"},
        GITHUB.mapping,
    )
    assert profile.subject == "5150"
    assert profile.username == "octocat"
    assert profile.display_name == "The Octocat"


def test_google_uses_the_openid_subject() -> None:
    profile = build_profile(
        "google",
        {"sub": "10769", "email": "A@Example.COM", "email_verified": True},
        GOOGLE.mapping,
    )
    assert profile.subject == "10769"
    # Addresses are compared case-insensitively everywhere downstream, so
    # they are normalised once, here.
    assert profile.email == "a@example.com"
    assert profile.email_verified


def test_discord_prefers_the_global_name() -> None:
    profile = build_profile(
        "discord",
        {"id": "80351", "username": "nelly", "global_name": "Nelly"},
        DISCORD.mapping,
    )
    assert profile.display_name == "Nelly"


def test_twitch_is_read_out_of_its_data_array() -> None:
    profile = build_profile(
        "twitch",
        {"data": [{"id": "44322", "login": "dallas", "email": "d@e.tv"}]},
        TWITCH.mapping,
    )
    assert profile.subject == "44322"
    assert profile.email == "d@e.tv"


def test_a_payload_with_no_subject_is_refused() -> None:
    with pytest.raises(ValueError, match="no subject"):
        build_profile("github", {"login": "nobody"}, GITHUB.mapping)


def test_pluck_falls_through_to_the_next_candidate() -> None:
    assert pluck({"login": "b"}, ("sub", "login")) == "b"


def test_pluck_treats_empty_as_absent() -> None:
    paths = ProfileMap().display_name
    assert pluck({"name": "", "display_name": "x"}, paths) == "x"


def test_pluck_survives_a_missing_branch() -> None:
    assert pluck({"a": 1}, ("a.b.c",)) is None
    assert pluck({"data": []}, ("data.0.id",)) is None
