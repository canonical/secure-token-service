# Proposal

## Why

The service signs and verifies tokens with the `github.com/lestrrat-go/jwx/v2` library, which is two major versions behind upstream (`v4.6.0`). The v2 line is in maintenance mode and its JWKS fetching/caching stack no longer exists in v4, so staying on v2 accumulates unpatched parser and cryptographic code paths. This is not a CVE fix — current vulnerability scans (trivy, govulncheck) show the pinned v2.1.6 is clean — it is a maintainability and security-hygiene upgrade to a supported major version.

## What Changes

- Upgrade the token signing/verification library from `github.com/lestrrat-go/jwx/v2` v2.1.6 to `github.com/lestrrat-go/jwx/v4` v4.6.0.
- Replace the removed v2 JWKS cache with the upstream companion fetching/caching module so the service keeps proactively refreshing the upstream identity provider's published keys.
- Adapt the key manager that publishes the service's own signing keys to the v4 key API.
- No change to observable product behavior: the JWKS publication endpoint, token verification rules, and key refresh cadence stay identical.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `openid-provider-login`: records the previously implicit behavior contract of the local JWKS publication endpoint that the key manager serves; the upgrade itself changes no observable behavior.

## Impact

- **Code**: `internal/auth/hydra.go`, `internal/auth/token.go`, `internal/http/interfaces.go`, and their tests (`internal/auth/hydra_test.go`, `internal/grpc/integration_test.go`, `internal/http/server_test.go`).
- **Dependencies**: `github.com/lestrrat-go/jwx/v2` → `github.com/lestrrat-go/jwx/v4` v4.6.0; new companion module `github.com/jwx-go/jwkfetch/v4` for JWKS fetching/caching; `github.com/lestrrat-go/option` upgraded v1 → v3 and `github.com/lestrrat-go/httprc` v1 → v3 as transitive requirements.
- **APIs/systems**: no external API, schema, or configuration changes. **BREAKING** only for Go consumers of this module's internal packages (the v2 import path disappears), which has no runtime impact on the shipped binary.

## Non-goals

- No change to token claims, token lifetimes, verification rules, or refresh cadence semantics.
- No migration of `github.com/golang-jwt/jwt/v5` or any other dependency (handled by the separate dependency-refresh PR).
- No functional redesign of key rotation or JWKS caching policy.

## Success Metrics

- `go build ./...`, `go vet ./...`, and the unit/integration test suite pass (excluding environment-dependent testcontainers runs).
- `trivy fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed` reports zero findings for the new module set.
- Zero behavioral regressions: existing JWKS endpoint, verification, and refresh tests pass unmodified in intent.
- v2 module fully removed from `go.mod`/`go.sum`.
