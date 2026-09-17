"""The authorization-code flow, against a scripted provider."""

from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from capsize_auth.oauth2 import (
    ExchangeFailedError,
    OAuth2Client,
    ProfileUnavailableError,
)
from capsize_auth.oauth2.presets import GITHUB, GOOGLE, TWITCH

REDIRECT = "https://hub.example.net/oauth/github/callback"


def client(handler: object, provider: object = GITHUB) -> OAuth2Client:
    return OAuth2Client(
        provider=provider,
        client_id="cid",
        client_secret="csecret",
        redirect_uri=REDIRECT,
        transport=httpx.MockTransport(handler),
    )


def test_the_authorize_url_carries_the_expected_parameters() -> None:
    url = client(lambda request: httpx.Response(200)).authorize_url(
        "state-value", code_challenge="chal"
    )
    query = parse_qs(urlparse(url).query)
    assert urlparse(url).netloc == "github.com"
    assert query["client_id"] == ["cid"]
    assert query["redirect_uri"] == [REDIRECT]
    assert query["response_type"] == ["code"]
    assert query["state"] == ["state-value"]
    assert query["code_challenge"] == ["chal"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["scope"] == ["read:user user:email"]


def test_pkce_is_omitted_for_a_provider_that_does_not_support_it() -> None:
    provider = GITHUB.__class__(**{**GITHUB.__dict__, "supports_pkce": False})
    url = client(lambda r: httpx.Response(200), provider).authorize_url(
        "s", code_challenge="chal"
    )
    assert "code_challenge" not in parse_qs(urlparse(url).query)


def github_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/login/oauth/access_token":
        assert request.headers["accept"] == "application/json"
        body = parse_qs(request.content.decode())
        assert body["code"] == ["the-code"]
        assert body["client_secret"] == ["csecret"]
        return httpx.Response(200, json={"access_token": "at"})
    if request.url.path == "/user":
        assert request.headers["authorization"] == "Bearer at"
        return httpx.Response(200, json={"id": 5150, "login": "octocat"})
    if request.url.path == "/user/emails":
        return httpx.Response(
            200,
            json=[
                {"email": "second@e.com", "primary": False, "verified": True},
                {"email": "hidden@e.com", "primary": True, "verified": True},
            ],
        )
    raise AssertionError(f"unexpected request to {request.url}")


async def test_a_full_exchange_yields_a_profile() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("access_token"):
            body = parse_qs(request.content.decode())
            assert body["code_verifier"] == ["the-verifier"]
        return github_handler(request)

    profile = await client(handler).complete(
        "the-code", code_verifier="the-verifier"
    )
    assert profile.provider == "github"
    assert profile.subject == "5150"
    assert profile.username == "octocat"
    # GitHub omits a private primary address from /user, so the verified
    # list is the fallback -- and the primary one wins over the other.
    assert profile.email == "hidden@e.com"
    assert profile.email_verified


async def test_an_unverified_fallback_address_is_not_accepted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user/emails":
            return httpx.Response(
                200,
                json=[
                    {
                        "email": "x@e.com",
                        "primary": True,
                        "verified": False,
                    }
                ],
            )
        return github_handler(request)

    profile = await client(handler).complete("the-code")
    assert profile.email == ""


async def test_a_refused_code_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "bad_verification_code"})

    with pytest.raises(ExchangeFailedError, match="returned 400"):
        await client(handler).complete("stale")


async def test_a_token_response_without_a_token_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"scope": "read:user"})

    with pytest.raises(ExchangeFailedError, match="no access_token"):
        await client(handler).complete("the-code")


async def test_a_failing_userinfo_call_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("access_token"):
            return httpx.Response(200, json={"access_token": "at"})
        return httpx.Response(401, json={"message": "Bad credentials"})

    with pytest.raises(ProfileUnavailableError, match="userinfo returned 401"):
        await client(handler).complete("the-code")


async def test_a_provider_without_an_emails_url_keeps_an_empty_address() -> (
    None
):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "at"})
        return httpx.Response(200, json={"sub": "10769"})

    profile = await client(handler, GOOGLE).complete("the-code")
    assert profile.email == ""


async def test_twitch_is_read_through_its_data_array() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth2/token":
            return httpx.Response(200, json={"access_token": "at"})
        return httpx.Response(
            200, json={"data": [{"id": "44322", "login": "dallas"}]}
        )

    profile = await client(handler, TWITCH).complete("the-code")
    assert profile.subject == "44322"
