"""Authentication primitives that make no assumptions about your application.

What this package deliberately does **not** do, because each one is what made
its predecessor hard to reuse:

* **No database.** No models, no migrations, no session handling, no opinion
  about primary-key types. A host maps its own account row onto a
  :class:`~capsize_auth.accounts.principal.Principal` when it needs one.
* **No environment variables.** Nothing here reads ``os.environ``, so there is
  no prefix to configure and no import that fails because a variable was
  unset. Secrets and thresholds are constructor arguments.
* **No web framework.** ``httpx`` is used to call a provider's endpoints; no
  framework is imported, so the same code serves Django, Flask, FastAPI, a
  worker, or a test.
* **No closed provider list.** A provider is data, so one this package has
  never heard of needs no change to this package.

The pieces:

``capsize_auth.passwords``
    argon2id hashing, and a constant-time dummy verify so a sign-in form
    cannot be used to enumerate registered addresses.
``capsize_auth.password_policy``
    Strength policy with configurable thresholds, built on zxcvbn.
``capsize_auth.tokens``
    Signed JWTs through an explicitly configured signer, plus opaque
    single-use secrets stored only as a hash.
``capsize_auth.oauth2``
    The authorization-code flow with PKCE, driven from provider descriptions,
    with presets for several common providers.
``capsize_auth.accounts``
    The authenticating subject and the password sign-in decision, as pure
    functions.
"""

from capsize_auth.accounts import (
    LoginOutcome,
    Principal,
    check_password_login,
)
from capsize_auth.oauth2 import (
    OAuth2Client,
    OAuth2Provider,
    OAuthProfile,
    ProviderRegistry,
)
from capsize_auth.password_policy import (
    PasswordPolicy,
    PasswordValidationError,
    validate_password_strength,
)
from capsize_auth.passwords import (
    dummy_verify,
    hash_password,
    verify_password,
)
from capsize_auth.tokens import OpaqueToken, TokenSigner, TokenTTLs

__all__ = [
    "LoginOutcome",
    "OAuth2Client",
    "OAuth2Provider",
    "OAuthProfile",
    "OpaqueToken",
    "PasswordPolicy",
    "PasswordValidationError",
    "Principal",
    "ProviderRegistry",
    "TokenSigner",
    "TokenTTLs",
    "check_password_login",
    "dummy_verify",
    "hash_password",
    "validate_password_strength",
    "verify_password",
]

__version__ = "0.1.0"
