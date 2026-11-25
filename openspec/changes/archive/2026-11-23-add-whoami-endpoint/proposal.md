# Proposal

## Why

Browser applications such as Portal hold only an opaque `HttpOnly` session cookie under the Phantom Token Pattern and cannot inspect who is currently signed in (see [#103](https://github.com/canonical/secure-token-service/issues/103)). At the same time, the OIDC callback discards profile and tenancy claims while setting a different session expiration than OpenID 2.0 logins (see [#104](https://github.com/canonical/secure-token-service/issues/104)).

## What Changes

- Add `GET /auth/me` to return the authenticated user's minimal public identity (`id`, and optional `email`, `name`, and `tenant`) using direct session-cookie authentication.
- Return `401 Unauthorized` with `{ "authenticated": false }` when the session cookie is missing, invalid, expired, or revoked, and `503 Service Unavailable` when the session store is unreachable.
- Enforce `Cache-Control: no-store`, `Vary: Cookie`, and `X-Content-Type-Options: nosniff` on `GET /auth/me` responses so responses stay authoritative and never leak through shared caches.
- Extract and store normalized identity and tenancy claims (`sub`, `email`, `name` with `given_name` + `family_name` fallback, `given_name`, `preferred_username`, and a configurable `tenant` claim) during OIDC logins, matching OpenID 2.0 claim normalization and propagating them into internal JWTs.
- Unify session expiration (`Session.ExpiresAt`) across OIDC, OpenID 2.0, and session extension to match the configured session lifetime (`SESSION_EXPIRY`).

## Non-goals

- Multi-session listing and revocation endpoints (covered in the separate `add-session-crud` change).
- Cross-origin CORS configuration for browser callers on separate origins (this change assumes same-origin access behind a reverse proxy).
- Exposing upstream OAuth2 access tokens, ID tokens, refresh tokens, or unfiltered raw claim maps to browser clients.
- Stateless cookie-embedded user profiles or client-side caching windows that weaken immediate revocation.
- In-application rate limiting (deployment ingress or gateway handles rate limiting).

## Success Metrics

- Browser clients resolve the active user identity in a single same-origin `GET /auth/me` call with zero calls to PostgreSQL or upstream identity providers.
- Revoked or expired sessions return `401 Unauthorized` with `{ "authenticated": false }` immediately on the next `GET /auth/me` call.
- Both OIDC and OpenID 2.0 logins populate consistent normalized claims and identical session expiration semantics derived from `SESSION_EXPIRY`.
- Zero upstream tokens or unlisted claims appear in `GET /auth/me` responses across unit and integration tests.

## Capabilities

### New Capabilities

- `session-whoami`: Exposes `GET /auth/me` so browser clients verify authentication state and read minimal public user identity (`id`, and optional `email`, `name`, and `tenant`) directly from the active session cookie.

### Modified Capabilities

- `claims-normalization`: Extends normalized claim extraction to OIDC logins (including `name`, `given_name`, and a configurable `tenant` claim), preserves optional extended claims on OpenID 2.0 logins, and unifies session expiration semantics across both providers.

## Impact

- **HTTP API**: Adds `GET /auth/me` in [internal/http/server.go](../../../../internal/http/server.go) and updates [docs/api/openapi.yaml](../../../../docs/api/openapi.yaml).
- **Authentication & Config**: Updates OIDC and OpenID callbacks in [internal/http/server.go](../../../../internal/http/server.go), OpenID extraction in [internal/auth/openid/ubuntuone.go](../../../../internal/auth/openid/ubuntuone.go), session extension in [cmd/sts/extend_sessions.go](../../../../cmd/sts/extend_sessions.go), and configuration in [internal/config/config.go](../../../../internal/config/config.go) (optional `OIDC_TENANT_CLAIM`).
- **Downstream JWTs**: Normalized `name` and `tenant` claims stored in `Session.Claims` automatically propagate through `ExchangeSession` in [internal/grpc/server.go](../../../../internal/grpc/server.go).
- **Backward Compatibility**: Additive and non-breaking. In-flight sessions created before deployment omit optional `name` and `tenant` until the user signs in again.
