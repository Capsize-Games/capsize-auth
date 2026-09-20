# Fleet consolidation audit

## Boundary and support matrix

`capsize-auth` is an independent Python 3.11+ authentication library owned by
Capsize-Games. It provides framework-agnostic password policy and Argon2id
verification, signed and opaque tokens, and provider-described OAuth2 with
PKCE. It has no database, account schema, environment-backed configuration,
web framework, or deployment service.

The host application owns account lookup, persistence, secret delivery,
session/cookie policy, provider enablement, and user-facing error handling. The
library's public security boundary is constructor-supplied values and its
documented return/error shapes.

| Capability | Supported contract | Security-sensitive behavior |
| --- | --- | --- |
| Passwords | Argon2id hash/verify, configurable zxcvbn policy, rehash detection | Corrupt/foreign hashes return `False`; unknown-account login still performs a dummy verify to reduce timing disclosure. |
| Signed tokens | JWT `HS256`, typed claims, configurable TTLs, optional issuer/audience | Algorithm is pinned on issue/decode; short secrets are rejected; invalid/expired/wrong-type tokens return `None`. |
| Opaque tokens | Random plaintext plus stored hash | Callers receive plaintext for one-time delivery; the host stores only the hash. |
| OAuth2 | Authorization-code flow, provider mappings, optional Basic token auth, PKCE S256 | JSON token acceptance, verified-primary-email fallback, provider registry enablement, and no `plain` PKCE mode are explicit. |
| Runtime | Python `>=3.11` | No import-time secret reads, network calls, account tables, or web middleware. |

## Dependency direction and dispositions

`capsize-auth` is above `capsize-commons` in the dependency DAG: auth policy
belongs here; commons may provide only generic primitives and must not import
this package. The current checkout has no `capsize_commons` import. A bounded
scan of the Capsize project checkouts found no direct consumer import to
migrate in this PR, so no duplicated helper was removed and no consumer claim
is made.

| Surface | Disposition | Evidence and decision |
| --- | --- | --- |
| Password/token/OAuth policy | retain-local | These are the domain layer and are the reason this package exists. Public APIs and security tests remain here. |
| HTTP transport | retain-local | OAuth providers use `httpx.AsyncClient` with a 15-second bound and provider-specific request/auth/email fallback behavior; no generic retry replacement has exact parity evidence. |
| Configuration/secrets | not-applicable | Constructor arguments are intentional; host applications own environment, secret stores, and account schemas. |
| Logging | retain-local | OAuth fallback-email failures use the package logger; account/audit logging belongs to the host and is not silently centralized. |
| Database/session persistence | not-applicable | No tables, sessions, cookies, or account storage are defined here. |
| Web/API/health | not-applicable | No framework, routes, middleware, readiness probe, or deployment process exists. |
| Tooling/release | adopt | `capsize.json`, `justfile`, `uv.lock`, and clean public/private CI commands make the existing package contract explicit. |
| Consumer migrations | blocked/retain-local | No direct consumer import was found in the checked project roots; product-specific auth/session flows must prove parity before extraction or replacement. |

## Compatibility, release, and rollback

The public API remains unchanged: password helpers, `Principal`/login outcomes,
`TokenSigner`/`TokenTTLs`, opaque tokens, `ProviderRegistry`, OAuth provider
profiles, and the exception types retain their current shapes. The existing 54
tests cover credential timing behavior, secret length, JWT algorithm/type/TTL
rules, PKCE, verified email selection, provider registration, and OAuth error
translation.

The package metadata declares version `0.1.0`. No runtime migration or helper
removal is proposed. Trusted publishing remains governed by hq#23; this PR
does not publish, tag, or claim a release. Once consumers and a published
artifact are identified, each migration must be a separate PR with a parity
fixture and rollback to the prior package/consumer dependency.

Rollback is to revert the focused metadata/documentation commit; the existing
library API and consumers remain unchanged.

## Dependency provenance

Runtime dependencies are public PyPI packages: `argon2-cffi>=23.1`,
`httpx>=0.27`, `pyjwt>=2.8`, and `zxcvbn>=4.4`. Development dependencies are
public PyPI `pytest>=8.2`, `pytest-asyncio>=0.23`, `ruff>=0.5`, and
`mypy>=1.10`. `uv.lock` records the resolved graph; no private Git dependency
or deployment credential is added.
