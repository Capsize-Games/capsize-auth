# uwuchat-auth-core

Reusable authentication primitives — JWT issuance and validation, argon2id
password hashing and policy, password-reset tokens, Google/Twitch OAuth,
geoblocking, rate limiting, and the JWT auth middleware — extracted so they
run in **any** FastAPI application.

The whole package is standalone. It has no dependency on, and no import of,
the application it was extracted from: the one integration point is a
storage interface you implement.

```python
from uwuchat_auth_core import set_backend
from myapp.auth_backend import MyAuthStorageBackend

set_backend(MyAuthStorageBackend())
```

---

## What you must implement: `AuthStorageBackend`

`uwuchat_auth_core.storage.AuthStorageBackend` is a `typing.Protocol`. It is
the only thing the auth core needs from your application: database sessions,
tenant/namespace resolution, and a provisioning hook.

| Method | Responsibility |
|---|---|
| `public_session_scope()` | Context manager yielding a session bound to the **shared** schema — the one holding `accounts` and `password_reset_tokens`. Used during login, before any tenant context exists. |
| `session_scope()` | Context manager yielding a session bound to the **active tenant's** schema. |
| `tenant_schema_for_key(key)` | Map a raw tenant key to a fully-qualified schema name (e.g. `alice` → `tenant_alice`). |
| `tenant_key_from_schema(schema)` | Inverse of the above. Called on every authenticated request to turn the JWT's `tenant` claim back into a key. |
| `set_tenant_key(key)` | Activate the tenant for the current context. Return an opaque reset token (a `contextvars.Token` in the bundled reference backend). |
| `reset_tenant_key(token)` | Restore the context state captured in that token. Must always be called in a `finally`. |
| `get_tenant_key()` | Return the tenant key active in the current context, or `None`. |
| `provision_tenant(schema)` | Create the schema and any per-tenant defaults. Called when an account is created for a schema that does not exist yet. A single-database deployment may make this a no-op. |

Sessions returned by the scope methods must be ordinary SQLAlchemy
`Session` objects — the core queries its own models
(`uwuchat_auth_core.models.Account`, `PasswordResetToken`) directly.

A complete, working example is bundled as
`uwuchat_auth_core.reference.SqliteAuthStorageBackend` (a single-database
SQLite implementation). It is what this package's own test suite uses, and
it is the shortest path to understanding the contract:

```python
from uwuchat_auth_core.reference import SqliteAuthStorageBackend

set_backend(SqliteAuthStorageBackend("sqlite+pysqlite:///auth.db"))
```

### Multi-tenant hints

* `public_session_scope()` should set the search path to the shared schema;
  `session_scope()` to `tenant_schema_for_key(get_tenant_key())`.
* Keep `set_tenant_key` / `reset_tenant_key` on `contextvars` (not
  thread-locals) — the middleware sets them per request and resets them in a
  `finally`, and a long-lived worker thread may serve many tenants in
  sequence.
* `provision_tenant` is where your migration runner belongs: it must be
  idempotent, because it can be called more than once for the same schema.

---

## Using the pieces

```python
from fastapi import FastAPI

from uwuchat_auth_core.middleware import DEFAULT_PUBLIC_PATHS, register
from uwuchat_auth_core.oauth_capabilities_routes import router as oauth_router

app = FastAPI()

# Rate limiting + JWT auth.  Paths the middleware must not protect are
# caller-supplied; the default set covers the auth endpoints this package
# owns.
register(app, public_paths=DEFAULT_PUBLIC_PATHS | {"/api/v1/embed/text"})

app.include_router(oauth_router, prefix="/api/v1/auth")
```

Available modules:

| Module | Contents |
|---|---|
| `uwuchat_auth_core.jwt` | Access/refresh/verification/OAuth-state/OAuth-handoff tokens, `decode_token`. |
| `uwuchat_auth_core.passwords` | argon2id hashing, constant-time `dummy_verify`. |
| `uwuchat_auth_core.password_policy` | zxcvbn + length-floor strength policy. |
| `uwuchat_auth_core.password_reset_token` | The `password_reset_tokens` model. |
| `uwuchat_auth_core.models` | The `accounts` model. |
| `uwuchat_auth_core.middleware` | JWT middleware, tenant/DEK context, status + token-version enforcement. |
| `uwuchat_auth_core.dependencies` | `require_auth`, `require_superuser`. |
| `uwuchat_auth_core.oauth` / `twitch_oauth` / `twitch_helix` | Provider config, CSRF state, token exchange, Helix helpers. |
| `uwuchat_auth_core.oauth_capabilities_routes` | `/oauth/capabilities` router. |
| `uwuchat_auth_core.geoblock` / `geoip` | Region blocking policy and IP→country lookup. |
| `uwuchat_auth_core.limiter` | The shared `slowapi` limiter instance. |
| `uwuchat_auth_core.crypto.data_encryption` | Fernet keyring with key rotation and an optional on-disk edge key. |
| `uwuchat_auth_core.crypto.dek_cache` | Process-local, TTL-bound per-user data-encryption-key cache. |
| `uwuchat_auth_core.migration_utils` | Idempotency probes for Alembic migrations (extra: `migrations`). |
| `uwuchat_auth_core.reference` | The reference `AuthStorageBackend`. |

---

## Configuration

Every setting is read through `uwuchat_auth_core._env.env`, which applies a
single configurable prefix:

| `AUTH_CORE_ENV_PREFIX` | Variable read for `env("JWT_SECRET")` |
|---|---|
| unset (default) | `AIRUNNER_JWT_SECRET` |
| `UWUCHAT_` | `UWUCHAT_JWT_SECRET` |

The default prefix (`AIRUNNER_`) keeps the package a drop-in replacement
for the deployment it was extracted from. Set `AUTH_CORE_ENV_PREFIX` to
read your own names.

Recognised settings (names shown without the prefix):

| Setting | Meaning |
|---|---|
| `JWT_SECRET` | Signing secret. Required; `ALLOW_DEV_JWT_SECRET=1` opts into a dev fallback. |
| `JWT_ACCESS_TTL`, `JWT_REFRESH_TTL`, `VERIFICATION_TOKEN_TTL`, `OAUTH_STATE_TTL`, `OAUTH_HANDOFF_TTL` | Token lifetimes in seconds. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `TWITCH_CLIENT_ID`, `TWITCH_CLIENT_SECRET` | OAuth credentials; missing means that provider is disabled. |
| `SITE_URL` | Public site URL used to build OAuth callback URLs. |
| `BLOCKED_COUNTRY_CODES` | Comma-separated ISO codes; unset means the EU/EEA + UK + strict-regime default. |
| `TRUSTED_PROXY_CIDRS` | Peers whose `X-Forwarded-For` is honoured (default `172.16.0.0/12,10.0.0.0/8`). |
| `GEOBLOCK_MESSAGE` | User-facing message returned for a blocked region. |
| `DATA_ENCRYPTION_KEYS` | Comma-separated Fernet keys; first encrypts, all decrypt. |
| `BASE_PATH` | Optional data directory; enables the persistent edge key. |

---

## What is deliberately **not** here

* **The application's HTTP routes.** Registration, login, refresh, profile,
  account deletion and the OAuth *callback* routes are owned by the
  application: they compose account creation, provisioning, billing and
  product hooks. This package supplies the primitives and the middleware
  those routes sit behind.
* **Billing / promotions / waitlist.** Subscription state, promo codes and
  waitlist gating are product concerns, not authentication.

## Tests

```bash
pip install -e '.[test]'
python -m pytest
```

The suite needs no external services: it installs the bundled SQLite
reference backend for every test.

## License

MIT.
