"""Ready-made descriptions of providers with public, documented endpoints.

These are values, not a closed set: a host application may add its own
:class:`~capsize_auth.oauth2.provider.OAuth2Provider` and register it exactly
like one of these. Endpoints here were taken from each provider's own
documentation; a preset is a convenience, and a deployment is still
responsible for reading the terms of the provider it enables.

Scopes are the minimum each provider needs to return a stable subject and an
email address, and no more.
"""

from capsize_auth.oauth2.profile import ProfileMap
from capsize_auth.oauth2.provider import OAuth2Provider

GITHUB = OAuth2Provider(
    id="github",
    display_name="GitHub",
    authorize_url="https://github.com/login/oauth/authorize",
    token_url="https://github.com/login/oauth/access_token",
    userinfo_url="https://api.github.com/user",
    # A GitHub account's primary address is private by default and absent
    # from /user, so the verified list is fetched as a fallback.
    emails_url="https://api.github.com/user/emails",
    scopes=("read:user", "user:email"),
    mapping=ProfileMap(subject=("id",), username=("login",)),
)

GOOGLE = OAuth2Provider(
    id="google",
    display_name="Google",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    token_url="https://oauth2.googleapis.com/token",
    userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
    scopes=("openid", "email", "profile"),
    mapping=ProfileMap(subject=("sub",)),
)

GITLAB = OAuth2Provider(
    id="gitlab",
    display_name="GitLab",
    authorize_url="https://gitlab.com/oauth/authorize",
    token_url="https://gitlab.com/oauth/token",
    userinfo_url="https://gitlab.com/api/v4/user",
    scopes=("read_user",),
    mapping=ProfileMap(subject=("id",), username=("username",)),
)

DISCORD = OAuth2Provider(
    id="discord",
    display_name="Discord",
    authorize_url="https://discord.com/oauth2/authorize",
    token_url="https://discord.com/api/oauth2/token",
    userinfo_url="https://discord.com/api/users/@me",
    scopes=("identify", "email"),
    mapping=ProfileMap(
        subject=("id",),
        username=("username",),
        display_name=("global_name", "username"),
        email_verified=("verified",),
    ),
)

TWITCH = OAuth2Provider(
    id="twitch",
    display_name="Twitch",
    authorize_url="https://id.twitch.tv/oauth2/authorize",
    token_url="https://id.twitch.tv/oauth2/token",
    userinfo_url="https://api.twitch.tv/helix/users",
    scopes=("user:read:email",),
    mapping=ProfileMap(
        subject=("data.0.id",),
        email=("data.0.email",),
        username=("data.0.login",),
        display_name=("data.0.display_name",),
        avatar_url=("data.0.profile_image_url",),
    ),
)

MICROSOFT = OAuth2Provider(
    id="microsoft",
    display_name="Microsoft",
    authorize_url=(
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    ),
    token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
    userinfo_url="https://graph.microsoft.com/oidc/userinfo",
    scopes=("openid", "email", "profile"),
    mapping=ProfileMap(subject=("sub",)),
)

ORCID = OAuth2Provider(
    id="orcid",
    display_name="ORCID",
    authorize_url="https://orcid.org/oauth/authorize",
    token_url="https://orcid.org/oauth/token",
    userinfo_url="https://orcid.org/oauth/userinfo",
    # ORCID's basic scope returns an identifier and a name, and deliberately
    # not an email: a researcher's address is private unless they publish it.
    # A deployment relying on this provider needs its own address collection.
    scopes=("openid",),
    mapping=ProfileMap(subject=("sub",)),
)

#: Every bundled preset, keyed by provider id.
PRESETS: dict[str, OAuth2Provider] = {
    provider.id: provider
    for provider in (
        GITHUB,
        GOOGLE,
        GITLAB,
        DISCORD,
        TWITCH,
        MICROSOFT,
        ORCID,
    )
}
