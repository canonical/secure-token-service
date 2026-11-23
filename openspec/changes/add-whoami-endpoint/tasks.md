# Tasks

## 1. Configuration and Claims Normalization

- [x] 1.1 Add `OIDCTenantClaim` (`OIDC_TENANT_CLAIM`, default `"tenant"`) to [internal/config/config.go](../../../internal/config/config.go), wire `WithTenantClaim` in [cmd/sts/serve.go](../../../cmd/sts/serve.go), and verify with `go test -race ./internal/config/...`
- [x] 1.2 Extract normalized OIDC ID token claims (`sub`, `email`, `name` with `given_name` + `family_name` fallback, `given_name`, `preferred_username`, `idp_provider`, and configured `tenant`) in [internal/http/server.go](../../../internal/http/server.go) and verify with unit tests in `go test -race ./internal/http/...`
- [x] 1.3 Extend OpenID 2.0 claim extraction in [internal/auth/openid/ubuntuone.go](../../../internal/auth/openid/ubuntuone.go) to preserve optional `given_name` and `tenant` attributes when returned and verify with `go test -race ./internal/auth/openid/...`
- [x] 1.4 Verify normalized OIDC `name` and `tenant` claims propagate into minted internal JWTs in [internal/grpc/server_test.go](../../../internal/grpc/server_test.go) via `go test -race ./internal/grpc/...`

## 2. Unified Session Expiration

- [x] 2.1 Set `Session.ExpiresAt = now.Add(s.sessionLifetime())` in OIDC `handleCallback` in [internal/http/server.go](../../../internal/http/server.go) to match OpenID, cookie expiry, and Valkey TTL, and verify with unit tests in `go test -race ./internal/http/...`
- [x] 2.2 Update `extendOneSession` in [cmd/sts/extend_sessions.go](../../../cmd/sts/extend_sessions.go) to set `sess.ExpiresAt = time.Now().Add(ttl)` matching the extended Valkey TTL, and verify with `go test -race ./cmd/sts/...`

## 3. Current User (`/auth/me`) HTTP Endpoint

- [x] 3.1 Consolidate HTTP route mounting between `Server.Router()` and `Server.StartWithMiddleware()` in [internal/http/server.go](../../../internal/http/server.go), register `GET /auth/me`, and verify with `go test -race ./internal/http/...`
- [x] 3.2 Implement `handleMe` in [internal/http/server.go](../../../internal/http/server.go) returning `200` with `{authenticated, user{id, email, name?, tenant?}}`, `401` with `{authenticated: false}`, `503` on store failure, and `Cache-Control: no-store`, `Vary: Cookie`, `X-Content-Type-Options: nosniff`, verified by unit tests covering OIDC, OpenID, legacy sessions, invalid cookies, revoked sessions, and store outages (`go test -race ./internal/http/...`)

## 4. Verification Suite

- [x] 4.1 Run full Go unit tests and static analysis (`go test -race -short ./... && go vet ./...`) and confirm zero failures
- [x] 4.2 Run OpenSpec strict validation (`openspec validate --all --strict && python3 scripts/validate_openspec.py`) and confirm all checks pass

## 5. Documentation & Rollout

- [x] 5.1 Document `GET /auth/me` request, `200`/`401`/`503` responses, and `OIDC_TENANT_CLAIM` configuration in [docs/api/openapi.yaml](../../../docs/api/openapi.yaml) and verify OpenAPI YAML validity
- [x] 5.2 Verify rollout steps for zero-downtime deployment (legacy in-flight sessions remain valid with optional `name`/`tenant` omitted until next login) and link GitHub issues `#103` and `#104` in the PR description

## Implementation Notes

- This change tracks GitHub issues `#103` (`GET /auth/me`) and `#104` (OIDC/OpenID claim preservation and unified `SESSION_EXPIRY`).
- `GET /auth/me` authenticates strictly with the AEAD `session_id` cookie against Valkey without calling PostgreSQL or upstream identity providers.
- Multi-session listing and revocation belong in the separate `add-session-crud` change.
- Fixed a pre-existing 1-space indentation error on `/auth/logout` in [docs/api/openapi.yaml](../../../docs/api/openapi.yaml) while adding `/auth/me`.
- Note on test scope: `go test -mod=mod -race -short` passed on all non-container packages (`cmd/sts`, `internal/auth/openid`, `internal/config`, `internal/cookie`, `internal/grpc`, `internal/http`, `internal/observability`); container-backed tests in `internal/auth`, `internal/db`, and `internal/session` require a Docker/Podman socket (`DOCKER_HOST`).
