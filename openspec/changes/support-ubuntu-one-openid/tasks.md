# Tasks: Support Ubuntu One OpenID and Standardized Cookie Generation

## 1. Configuration & Domain Models

- [ ] 1.1 Add Ubuntu One OpenID configuration fields (`UBUNTU_ONE_OPENID_URL`, `UBUNTU_ONE_REALM`, `DEFAULT_AUTH_PROVIDER`) to `internal/config/config.go`. Unit test: verify environment variable parsing and defaults in `config_test.go`.
- [ ] 1.2 Extend `session.Session` struct in `internal/session/store.go` with `Provider string` and `Claims map[string]any` fields. Unit test: verify JSON serialization and deserialization in Valkey session store tests.

## 2. Standardized Cookie Generation

- [ ] 2.1 Refactor `CookieManager` in `internal/cookie/cookie.go` and update `internal/http/interfaces.go` to add `SetSessionCookie(w, r, sessionID, expiresAt)` and `ClearSessionCookie(w, r)`. Unit test: verify attributes `HttpOnly: true`, `SameSite: Lax`, and correct `Path: "/"` in `cookie_test.go`.
- [ ] 2.2 Implement dynamic `Secure` cookie flag evaluation based on `r.TLS != nil` or `X-Forwarded-Proto == "https"`. Unit test: verify `Secure` is present on TLS/proxy requests and omitted on plain HTTP in `cookie_test.go`.
- [ ] 2.3 Generalize state cookie management with `SetAuthState` / `GetAuthState` to store `provider`, `return_to`, and state token securely. Unit test: roundtrip state encryption and decoding in `cookie_test.go`.

## 3. Ubuntu One OpenID Provider Client

- [ ] 3.1 Implement OpenID 2.0 URL generator for Ubuntu One in `internal/auth/openid/ubuntuone.go` requesting Simple Registration (SREG 1.1) and Attribute Exchange (AX 1.0) schemas for email, nickname, and fullname. Unit test: verify query parameters, SREG, and AX schemas.
- [ ] 3.2 Implement OpenID 2.0 direct verification (`check_authentication`) via HTTP POST in `internal/auth/openid/ubuntuone.go`. Unit test: verify handling of `is_valid:true`, `is_valid:false`, cancellation, and error responses using `httptest.Server`.
- [ ] 3.3 Implement OpenID claims extraction and normalization in `internal/auth/openid/ubuntuone.go`, extracting attributes from SREG 1.1 and AX 1.0 extensions, producing a normalized map and selecting `UserID` via `email` -> `nickname` -> `claimed_id` fallback. Unit test: test claims extraction under full, partial, and minimal attribute responses.

## 4. HTTP Presentation & Presentation Routing

- [ ] 4.1 Update `handleLogin` in `internal/http/server.go` to accept optional `?provider=openid|oidc` query parameter, record provider in state cookie, and redirect to the selected provider. Unit test: test `handleLogin` with default, explicit OIDC, explicit OpenID, and invalid provider in `server_test.go`.
- [ ] 4.2 Add `handleOpenIDCallback` in `internal/http/server.go` (registered at `GET /auth/openid/callback`) dedicated to verifying Ubuntu One OpenID responses, creating sessions, and issuing standardized cookies, leaving `/auth/callback` pure OIDC. Unit test: mock OpenID provider verification and verify session creation in `server_test.go`.
- [ ] 4.3 Update `handleCallback`, `handleOpenIDCallback`, and `handleLogout` in `internal/http/server.go` to use `cookieManager.SetSessionCookie` and `cookieManager.ClearSessionCookie`. Unit test: verify cookie headers on login, callbacks, and logout in `server_test.go`.

## 5. Token Minting & gRPC Integration

- [ ] 5.1 Update `ExchangeSession` in `internal/grpc/server.go` to merge `sess.Claims` into the internal JWT claims map prior to calling `MintToken`. Unit test: verify that minted JWT contains extracted OpenID attributes in `server_test.go`.

## 6. Documentation & Rollout

- [ ] 6.1 Update OpenAPI specification in `docs/api/openapi.yaml` to include the `provider` query parameter on `/auth/login` and document standardized cookie attributes.
- [ ] 6.2 Update `.env.example` and `README.md` with configuration instructions for Ubuntu One OpenID.
- [ ] 6.3 Run end-to-end integration verification with Docker Compose validating both OIDC and Ubuntu One flows.

## Verification Suite

- Unit test suite: `go test -v -race ./internal/...`
- OpenSpec validation: `openspec validate support-ubuntu-one-openid --strict`
- Linting and vulnerability check: `golangci-lint run ./...` and `govulncheck ./...`

## Implementation Notes

- **Canonical SSO Protocol Compatibility (SREG 1.1)**: Canonical SSO (`login.ubuntu.com/+openid` and `sso.iam.test.canonical.com/+openid`, powered by Launchpad's identity provider) specifically responds to OpenID Simple Registration (SREG 1.1: `openid.ns.sreg=http://openid.net/extensions/sreg/1.1`) with `openid.sreg.required=email,nickname` and `openid.sreg.optional=fullname`. When only Attribute Exchange (AX 1.0) is requested, Canonical SSO does not release identity attributes, resulting in empty email claims. STS requests both SREG 1.1 and AX 1.0 in authorization requests and inspects both namespaces upon callback verification, prioritizing SREG to ensure the user's verified email is populated into `sub` and `email` for downstream microservice parity.
