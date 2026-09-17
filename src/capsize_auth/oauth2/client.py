"""The authorization-code flow, driven entirely from a provider description.

One implementation serves every provider. Two behaviours are worth knowing
about because they are where providers differ most:

* **Token requests ask for JSON.** Some providers (GitHub) default to a
  form-encoded response body and only return JSON when asked, so the
  ``Accept`` header is always sent.
* **A missing email is retried against a second endpoint.** GitHub keeps a
  private primary address out of its userinfo response, so a provider may
  declare ``emails_url``; it is only fetched when the first response carried
  no address, and only a *verified* address is accepted from it.
"""

import logging
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlencode

import httpx

from capsize_auth.oauth2.errors import (
    ExchangeFailedError,
    ProfileUnavailableError,
)
from capsize_auth.oauth2.profile import OAuthProfile, build_profile
from capsize_auth.oauth2.provider import OAuth2Provider

logger = logging.getLogger(__name__)

#: Every outbound call is bounded: a provider that hangs must not hold a
#: request open indefinitely.
TIMEOUT_SECONDS = 15.0


@dataclass
class OAuth2Client:
    """Runs the authorization-code flow for one configured provider."""

    provider: OAuth2Provider
    client_id: str
    client_secret: str
    redirect_uri: str
    #: Substituted in tests, and available to a host that needs its own
    #: retry, proxy, or certificate policy on outbound provider calls.
    transport: httpx.AsyncBaseTransport | None = None

    def authorize_url(
        self,
        state: str,
        code_challenge: str | None = None,
        **extra: str,
    ) -> str:
        """Return the URL to send the user's browser to."""
        params: dict[str, str] = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "state": state,
            **self.provider.authorize_params,
            **extra,
        }
        if self.provider.scopes:
            params["scope"] = self.provider.scope_value()
        if code_challenge and self.provider.supports_pkce:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.provider.authorize_url}?{urlencode(params)}"

    async def complete(
        self, code: str, code_verifier: str | None = None
    ) -> OAuthProfile:
        """Exchange ``code`` and return the provider's profile."""
        async with httpx.AsyncClient(
            timeout=TIMEOUT_SECONDS, transport=self.transport
        ) as http:
            token = await self._exchange(http, code, code_verifier)
            return await self._profile(http, token)

    async def _exchange(
        self,
        http: httpx.AsyncClient,
        code: str,
        code_verifier: str | None,
    ) -> str:
        """Return the access token for ``code``."""
        response = await http.post(
            self.provider.token_url,
            data=self._token_request(code, code_verifier),
            headers={"Accept": "application/json"},
            auth=self._token_auth(),
        )
        if response.status_code >= 400:
            raise ExchangeFailedError(
                f"{self.provider.id}: token endpoint returned "
                f"{response.status_code}"
            )
        token = self._read_token(response)
        if not token:
            raise ExchangeFailedError(
                f"{self.provider.id}: token response carried no access_token"
            )
        return token

    def _token_request(
        self, code: str, code_verifier: str | None
    ) -> dict[str, str]:
        """Return the form body for the token request."""
        body: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
        }
        if not self.provider.basic_auth_token_request:
            body["client_secret"] = self.client_secret
        if code_verifier:
            body["code_verifier"] = code_verifier
        return body

    def _token_auth(self) -> httpx.Auth | httpx._client.UseClientDefault:
        """Return HTTP basic credentials when the provider requires them."""
        if self.provider.basic_auth_token_request:
            return httpx.BasicAuth(self.client_id, self.client_secret)
        return httpx.USE_CLIENT_DEFAULT

    @staticmethod
    def _read_token(response: httpx.Response) -> str:
        """Return the access token from a token response body."""
        try:
            payload = response.json()
        except ValueError:
            return ""
        if not isinstance(payload, dict):
            return ""
        return str(payload.get("access_token") or "")

    async def _profile(
        self, http: httpx.AsyncClient, token: str
    ) -> OAuthProfile:
        """Fetch and normalise the provider's account for ``token``."""
        payload = await self._userinfo(http, token)
        try:
            profile = build_profile(
                self.provider.id, payload, self.provider.mapping
            )
        except ValueError as error:
            raise ProfileUnavailableError(str(error)) from error
        if profile.email or not self.provider.emails_url:
            return profile
        return await self._with_fallback_email(http, token, profile)

    async def _userinfo(
        self, http: httpx.AsyncClient, token: str
    ) -> dict[str, Any]:
        """Return the provider's userinfo payload."""
        headers = {"Accept": "application/json"}
        params: dict[str, str] = {}
        if self.provider.userinfo_auth == "header":
            headers["Authorization"] = f"Bearer {token}"
        else:
            params["access_token"] = token
        response = await http.get(
            self.provider.userinfo_url, headers=headers, params=params
        )
        if response.status_code >= 400:
            raise ProfileUnavailableError(
                f"{self.provider.id}: userinfo returned "
                f"{response.status_code}"
            )
        payload = response.json()
        if not isinstance(payload, dict):
            raise ProfileUnavailableError(
                f"{self.provider.id}: userinfo was not a JSON object"
            )
        return payload

    async def _with_fallback_email(
        self,
        http: httpx.AsyncClient,
        token: str,
        profile: OAuthProfile,
    ) -> OAuthProfile:
        """Return ``profile`` with an address from the secondary endpoint."""
        address = await self._verified_email(http, token)
        if not address:
            return profile
        return replace(profile, email=address, email_verified=True)

    async def _verified_email(
        self, http: httpx.AsyncClient, token: str
    ) -> str:
        """Return the provider's verified primary address, or empty."""
        url = self.provider.emails_url
        if url is None:
            return ""
        response = await http.get(
            url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            },
        )
        if response.status_code >= 400:
            logger.warning(
                "%s: email endpoint returned %s",
                self.provider.id,
                response.status_code,
            )
            return ""
        return _primary_verified(response.json())


def _primary_verified(payload: object) -> str:
    """Return the verified primary address in an email-list payload."""
    if not isinstance(payload, list):
        return ""
    verified = [
        row
        for row in payload
        if isinstance(row, dict) and row.get("verified")
    ]
    primary = [row for row in verified if row.get("primary")]
    chosen = primary or verified
    if not chosen:
        return ""
    return str(chosen[0].get("email") or "").strip().lower()
