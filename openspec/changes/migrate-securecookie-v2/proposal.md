# Proposal: Migrate securecookie to v2

## Why

The service pins `github.com/chmike/securecookie` v1.3.5. The v1 line is superseded by v2, which removes legacy options and enforces secure cookie attributes by default. This is not a CVE fix: current trivy and govulncheck scans show no known vulnerabilities in v1.3.5. We migrate now as security-hygiene and maintainability work so the service stays on the maintained major version and inherits its stronger cookie hardening.

## What Changes

- Upgrade `github.com/chmike/securecookie` from v1.3.5 to `github.com/chmike/securecookie/v2` v2.0.1 in `go.mod` and `.benchmark/go.mod`, and adapt all call sites in `internal/cookie` and `.benchmark`.
- **BREAKING**: All cookie names gain the mandatory `__Host-` prefix (`session_id` becomes `__Host-session_id`, `oauth_state` becomes `__Host-oauth_state`, `oauth_nonce` becomes `__Host-oauth_nonce`). Cookies minted before the upgrade are unreadable after deploy: in-flight OAuth flows fail once and active sessions are dropped, forcing re-login. We accept a clean cutover with no dual-read compatibility shim.
- **BREAKING**: The `Secure` attribute is now always set on service-issued cookies. The dynamic per-request `Secure` evaluation (TLS / `X-Forwarded-Proto` detection) is removed. Local development over plain HTTP can no longer set or read these cookies in the browser; developers must use a TLS-terminating proxy or localhost exception.
- Adopt the v2 key store: cookie encryption keys derive from the 32-byte secret and rotate every two days, with the previous 200 periods still accepted for decoding.
- Cookie expiry moves to cookie issuance time (mandatory `Max-Age` at cookie-object creation) instead of validation-time-only checks.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `standardized-cookies`: Cookie names, the `Secure` attribute contract, and expiry semantics change at the spec level. The dynamic `Secure` flag requirement is removed; a static secure-by-default requirement and the `__Host-` prefix requirement replace it.

## Impact

- **Code**: `internal/cookie/cookie.go` (CookieManager, Encode, Decode, cookie set/clear helpers), `internal/cookie/cookie_test.go`, `.benchmark/benchmark_test.go`, `.benchmark/go.mod`, `go.mod`, `go.sum`. HTTP handlers that read the session cookie by name (`internal/http/home.go`, `internal/http/server.go`) switch to the prefixed name.
- **Dependencies**: `github.com/chmike/securecookie` v1.3.5 replaced by `github.com/chmike/securecookie/v2` v2.0.1.
- **Operations**: Deploying this change invalidates all existing session and OAuth state cookies. Users must re-authenticate; in-flight logins fail once. No data migration is needed.
- **Local development**: Plain-HTTP development flows no longer work for cookie-based login because cookies are always `Secure`. Developers must use HTTPS (for example a TLS-terminating proxy) or browser localhost exceptions.

## Non-goals

- No dual-read or fallback support for pre-upgrade (unprefixed) cookies.
- No re-introduction of `SameSite=None` or `Domain` attributes; v2 removed them and the service does not need cross-site or cross-subdomain cookies.
- No other dependency upgrades; the broader dependency refresh is handled by a separate change (PR #82).

## Success Metrics

- `go build ./...`, `go vet ./...`, and `go test -short ./...` pass on the change branch.
- `trivy fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed` reports zero findings for `go.mod`.
- No remaining references to `github.com/chmike/securecookie` v1 in `go.mod`, `go.sum`, or source.
- Post-deploy, authentication flows complete successfully on HTTPS with `__Host-` prefixed cookies.
