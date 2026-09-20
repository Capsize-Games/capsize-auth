# capsize-auth

## Fleet boundary

This package owns authentication policy: password verification, token claims,
OAuth provider mappings, PKCE, and security-sensitive error behavior. Hosts
own account storage, secret delivery, sessions, web integration, and logging.
The support matrix and release gate are documented in
[`docs/FLEET_CONSOLIDATION.md`](docs/FLEET_CONSOLIDATION.md).

Authentication primitives for Python applications: argon2id password hashing
and a strength policy, signed JWTs and opaque revocable tokens, and the OAuth2
authorization-code flow with PKCE against any provider.

```bash
pip install capsize-auth
```

## What it does not assume

The package has no database layer, defines no tables, reads no environment
variables, and imports no web framework. Secrets and thresholds are
constructor arguments; accounts stay in the host application's own schema.

That is a deliberate boundary, not a missing feature. It means the same code
runs in a Django view, a FastAPI route, a worker, or a test, and that adding a
provider this package has never heard of requires no change to this package.

## Passwords

```python
from capsize_auth import hash_password, verify_password
from capsize_auth.password_policy import DEFAULT, PasswordValidationError

DEFAULT.check(new_password)            # raises PasswordValidationError
stored = hash_password(new_password)
verify_password(attempt, stored)       # True / False, never raises
```

`verify_password` returns False for a wrong password *and* for a stored hash
that is corrupt, truncated, or produced by another algorithm — the state a
half-finished migration from another scheme leaves behind. `needs_rehash`
reports when a verified password should be re-hashed at the current cost
parameters, which is the only moment the plaintext is available to do it.

The policy is built on zxcvbn and carries its warning and suggestions into the
rejection reason, so the person is told why. Thresholds are configurable:

```python
from capsize_auth.password_policy import PasswordPolicy

policy = PasswordPolicy(min_length=12, min_score=3)
```

zxcvbn is imported on first use. An application that never accepts a password
does not pay its dictionary-loading start-up cost.

## Sign-in

`check_password_login` is the sign-in decision as a pure function: the host
looks the account up, passes what it found, and gets a verdict.

```python
from capsize_auth import Principal, check_password_login

row = my_db.find_by_email(email)       # your model, your primary key
principal = Principal(
    id=str(row.id), email=row.email, status=row.status,
    token_version=row.token_version,
)
outcome = check_password_login(password, principal, row.password_hash)
if outcome.ok:
    ...
```

Pass `principal=None` when no account matched. The function still spends a
verify cycle, because returning early on an unknown address makes sign-in
measurably faster for addresses that are not registered — which turns the
login form into an account-existence oracle.

The outcome distinguishes a wrong password from a suspended account so the
caller can log the difference. A sign-in form should still say one thing for
all of them.

## Tokens

Two kinds, for different jobs.

**Signed JWTs** carry claims and are checked without a database read:

```python
from capsize_auth import TokenSigner, TokenTTLs
from capsize_auth.tokens import ACCESS

signer = TokenSigner(secret=os.environ["JWT_SECRET"], ttls=TokenTTLs())
token = signer.issue(ACCESS, subject=principal.id, ver=principal.token_version)
claims = signer.decode(token, ACCESS)   # None when invalid, expired, or
                                        # of a different type
```

The algorithm is pinned on both issue and decode, a secret shorter than 32
characters is refused at construction, and `decode` rejects a token whose
`type` claim is not the one asked for — without that check, a short-lived
OAuth state token would be accepted anywhere an access token is.

**Opaque tokens** carry nothing and are revoked by deleting a row. Use them
for password-reset links, personal access tokens, and session cookies:

```python
from capsize_auth.tokens import new_token

token = new_token(prefix="app_pat_")
store(token.hashed)          # the database never holds a usable credential
show_once(token.plaintext)
```

## OAuth2

A provider is data. One client runs the flow for all of them.

```python
from capsize_auth.oauth2 import ProviderRegistry, generate

providers = ProviderRegistry("https://example.net/oauth/{provider}/callback")
providers.register_preset("github", client_id, client_secret)
providers.register_preset("google", client_id, client_secret)

# Sign-in page: render exactly the buttons that will work.
providers.available()      # [ProviderInfo(id='github', ...), ...]

pkce = generate()
url = providers.client("github").authorize_url(
    state=state, code_challenge=pkce.challenge,
)
# ... after the redirect comes back:
profile = await providers.client("github").complete(code, pkce.verifier)
profile.subject, profile.email, profile.email_verified, profile.username
```

Bundled presets: GitHub, Google, GitLab, Discord, Twitch, Microsoft, ORCID.
They are ordinary values, and a preset existing here is not the same as a
deployment offering it — enabling a provider means registering credentials,
and reading that provider's terms.

Providers disagree about nearly everything, so a provider declares where its
fields live and `OAuthProfile` is what comes out: `sub` or `id` for the
subject, `login` or `username` or `preferred_username` for the username, a
single-element `data` array for Twitch. Two behaviours worth knowing:

- Token requests always send `Accept: application/json`, because some
  providers otherwise return a form-encoded body.
- A provider may declare a second endpoint for addresses it keeps out of
  userinfo (GitHub hides a private primary address). It is fetched only when
  the first response carried none, and only a **verified** address is taken
  from it.

To add a provider, build an `OAuth2Provider` and register it like a preset.

PKCE (S256) is generated and verified here; `plain` is legal in RFC 7636 and
deliberately not offered, because it provides no protection.

## Requirements

Python 3.11+. Depends on `argon2-cffi`, `pyjwt`, `httpx`, and `zxcvbn`.

## History

Extracted from the authentication layer of UwUChat and generalised. The
extraction it started from shipped its own `accounts` table, read every
setting from a prefixed environment variable at import time, and had one
module per provider; git history records that starting point. Removed in the
process: the application's own account model and tenant-schema machinery, the
FastAPI middleware and dependencies built on it, geoblocking and the Twitch
API client (deployment and application concerns rather than auth primitives),
and the per-account envelope-encryption helpers. Those remain in the history
of the repository this was forked from.

## Licence

MIT. See [LICENSE](LICENSE).
