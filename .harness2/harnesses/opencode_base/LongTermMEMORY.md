# Long-Term Architectural Memory — Secure Token Service (`c3`)

## 1. Service Identity & Stack
- **Service**: Secure Token Service — Go 1.26 identity and token-translation service implementing the Phantom Token Pattern (ADR-004).
- **Storage & Cryptography**:
  - **PostgreSQL (`internal/db`, `internal/keymanager`)**: Stores active and rotated ECDSA P-256 (`ES256`) signing keys in `hydra_jwk`.
  - **Valkey (`internal/session`)**: Stores user sessions (`SessionID`, `UserID`, `Provider`, `Claims`, `ExpiresAt`).
  - **ChaCha20-Poly1305 AEAD (`internal/cookie`)**: `CookieManager` encrypts and authenticates `session_id`, `oauth_state`, and `oauth_nonce` cookies via `chmike/securecookie`.

## 2. Capability & Change Map (`openspec/`)
- **`artifact-security-gate`** (`openspec/specs/artifact-security-gate/spec.md`):
  - Enforces pre-build Go vulnerability scanning (`make govulncheck`), 3-architecture static binary compilation (`linux/amd64`, `linux/arm64`, `linux/riscv64` verified via `file` for `x86-64`, `aarch64`, `RISC-V`), and Trivy container candidate scanning (`_rock-scan.yaml`) prior to multi-architecture (`amd64`, `arm64`) promotion (`_rock-promote.yaml` with `skopeo copy --all` in `canonical/identity-team` `v1.17.1`).
- **`m2m-token-exchange`** (`openspec/specs/m2m-token-exchange/spec.md`):
  - Adds `rpc ExchangeToken(ExchangeTokenRequest) returns (ExchangeResponse)` in `api/proto/v1/sts.proto` and `internal/grpc/server.go`.
  - `HydraTokenVerifier` (`internal/auth/hydra.go`) maintains a preemptive background JWKS cache (`jwkfetch.NewCache` in `lestrrat-go/jwx/v4`) with `Close() error` lifecycle cleanup, 5s clock skew tolerance (`5 * time.Second`), and `< 60s` near-expiry rejection (`ErrTokenExpiringSoon`).
  - Enforces 64 KB (`65536` bytes) max token size (`codes.InvalidArgument`), clamps TTL to `min(configured_expiry, remaining_validity)`, and maps machine claims to `sub: <client_id>` and `email: <client_id>@serviceaccount.local`.
- **`session-whoami` & `session-management` & `claims-normalization`** (`openspec/specs/`):
  - `GET /auth/me` returns minimal public identity (`{authenticated, user{id, email?, name?, tenant?}}`) with `Cache-Control: no-store`, `Vary: Cookie`, and `X-Content-Type-Options: nosniff`.
  - `GET /auth/sessions`, `DELETE /auth/sessions/{session_id}`, and `DELETE /auth/sessions` (`?exclude_current=true`) provide cookie-authenticated self-service session CRUD (`Store.DeleteUserSession` via `SISMEMBER` + `DEL` + `SREM`), `http.NewCrossOriginProtection()` guarding `POST /auth/logout` and `DELETE /auth/sessions*`, and parameterized `http.route` metrics.
  - `normalizeOIDCClaims` extracts normalized OIDC profile claims + `OIDC_TENANT_CLAIM` (default `tenant`), ignores `email` when `email_verified` is present and not `true`/`"true"`, resolves `UserID` strictly from verified `email` across OIDC and OpenID 2.0 (no runtime fallback, failing closed when missing or unverified), unifies `Session.ExpiresAt` to `SESSION_EXPIRY` (UTC), and `KeyManager.MintToken` enforces registered `iss`/`sub`/`aud`/`iat`/`exp` precedence.
- **`support-multi-arch-rocks-and-pipelines`** (`openspec/changes/support-multi-arch-rocks-and-pipelines/`):
  - `Makefile` (`BINARY_ARCHS?=amd64 arm64 riscv64`, `build-all`) compiles 3 binary architectures; `rockcraft.yaml`, `Dockerfile`, `build.sh`, `skaffold.yaml`, and `.github/workflows/ci.yaml` package and publish 2 container rock architectures (`amd64`, `arm64`).
- **`support-ubuntu-one-openid`** (`openspec/changes/support-ubuntu-one-openid/`):
  - `GET /auth/login?provider=oidc|openid` (case-insensitive, default `oidc`) and isolated `GET /auth/openid/callback` (`internal/http/server.go`).
  - `internal/auth/openid/ubuntuone.go` requests SREG 1.1 + AX 1.0 attributes (`email`, `nickname`, `fullname`), verifies via POST `openid.mode=check_authentication`, and validates `openid.response_nonce` (5-minute skew + replay check).
  - `CookieManager` (`internal/cookie/cookie.go`) centralizes `SetSessionCookie` and `ClearSessionCookie` (`HttpOnly: true`, `SameSite: Lax`, `Path: "/"`, dynamic `Secure`).
