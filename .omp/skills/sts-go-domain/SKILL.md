---
name: sts-go-domain
description: Domain practitioner knowledge for the Secure Token Service Go 1.26 architecture, Phantom Token Pattern, ES256 JWT minting, Ory Hydra M2M exchange, Ubuntu One OpenID 2.0, CookieManager, and multi-arch Rockcraft builds. Use when aligning OpenSpec artifacts with STS code.
license: Apache-2.0
---

# Secure Token Service Go 1.26 Domain Reference

Use this skill when authoring or verifying OpenSpec specifications, designs, tasks, or Go implementation code in `secure-token-service`.

## 1. Core Architecture & Trust Model (Phantom Token Pattern)

- **Browser / Human Flow (`internal/http`, `internal/cookie`, `internal/session`)**:
  - Clients authenticate via `/auth/login?provider=oidc|openid` (default `oidc`, case-insensitive).
  - OIDC callback is handled at `GET /auth/callback`; Ubuntu One OpenID 2.0 callback is isolated at `GET /auth/openid/callback` for clean future sunsetting.
  - Ubuntu One OpenID (`internal/auth/openid/ubuntuone.go`) requests both Simple Registration (`SREG 1.1`) and Attribute Exchange (`AX 1.0`) for `email`, `nickname`, and `fullname`, verifies assertions statelessly via HTTP POST `openid.mode=check_authentication`, extracts attributes strictly from `openid.signed`, and validates `openid.response_nonce` within a 5-minute skew window with replay protection.
  - `CookieManager` (`internal/cookie/cookie.go`) is the single authority for `session_id`, `oauth_state`, and `oauth_nonce` cookies using ChaCha20-Poly1305 AEAD (`chmike/securecookie`), `HttpOnly: true`, `SameSite: Lax`, `Path: "/"`, and dynamic `Secure` evaluation (`r.TLS != nil` or `X-Forwarded-Proto == "https"`).
  - Sessions are persisted in Valkey (`internal/session/store.go`) with `UserID` (OIDC `sub` requiring verified `email`, or OpenID 2.0 short `u1_sso_id` extracted from signed HTTPS `openid.claimed_id` `/+id/<short_id>` requiring signed `email`, with no runtime fallback, failing closed when missing or invalid; `Session.ValidateIdentity()` is enforced across HTTP, gRPC, and `extend-sessions`), `Provider`, unified UTC `ExpiresAt` (`SESSION_EXPIRY`), and normalized `Claims` (including short `u1_sso_id` and configurable `OIDC_TENANT_CLAIM` / `OIDC_U1_SSO_ID_CLAIM`).
  - Self-service browser endpoints: `GET /auth/me` (minimal `{authenticated, user}` exposing short `u1_sso_id` and omitting `id` for OpenID 2.0), `GET /auth/sessions` (TTL-derived `expires_at` and lazy pruning), `DELETE /auth/sessions/{session_id}` (`DeleteUserSession` via `SISMEMBER` + `DEL` + `SREM`, `404` on foreign/missing), and `DELETE /auth/sessions` (`?exclude_current=true`), with Go stdlib `http.NewCrossOriginProtection()` guarding `POST /auth/logout` and `DELETE /auth/sessions*` and `Cache-Control: no-store`.
- **Internal Mesh Token Exchange (`internal/grpc`, `internal/auth`, `internal/keymanager`, `api/proto/v1/sts.proto`)**:
  - `ExchangeSession`: validates `Session.ValidateIdentity()` and swaps opaque session cookies for short-lived ES256 internal JWTs (OIDC: `sub: Session.UserID`, `email`, optional short `u1_sso_id`; OpenID 2.0: `sub` omitted, `email`, short `u1_sso_id`; invalid/legacy sessions rejected with `Unauthenticated`; `KeyManager.MintToken` applies registered claims after custom claims and deletes `sub` when subject is empty) signed by `KeyManager` (keys persisted in PostgreSQL `hydra_jwk`).
  - `ExchangeToken`: swaps upstream Ory Hydra OAuth2 Client Credentials access tokens for internal ES256 STS JWTs:
    - Rejects empty or oversized (`> 65,536` bytes / 64 KB) tokens with `codes.InvalidArgument`.
    - Verifies upstream signatures against preemptively cached Hydra JWKS (`HydraTokenVerifier` in `internal/auth/hydra.go` using `lestrrat-go/jwx/v2/jwk.Cache` and `Close() error` lifecycle cleanup).
    - Enforces 5-second clock skew tolerance (`5 * time.Second`) and rejects tokens with `< 60s` remaining lifetime (`ErrTokenExpiringSoon`) with `codes.Unauthenticated`.
    - Clamps minted internal token TTL to `min(configured_expiry, remaining_upstream_validity)`.
    - Maps machine identity to `sub: <client_id>` and synthetic email `<client_id>@serviceaccount.local` (validating printable non-control characters `<= 256` chars).

## 2. Build, Packaging & Release Gate Invariants (`artifact-security-gate` & `multi-arch-artifacts`)

- **3-Architecture Go Binary Compilation**:
  - `Makefile` (`make build-all`) and `.github/workflows/unittest.yaml` compile static Go binaries (`CGO_ENABLED=0`) for `linux/amd64`, `linux/arm64`, and `linux/riscv64` and verify their ELF headers (`x86-64`, `aarch64`, `RISC-V`) alongside `make govulncheck` and `make test`.
- **2-Architecture Container & Rock Packaging**:
  - `rockcraft.yaml`, `Dockerfile`, `build.sh`, `skaffold.yaml`, and `.github/workflows/ci.yaml` build and publish OCI container rocks strictly for `amd64` and `arm64`.
  - Release tags publish `<version>-candidate` multi-architecture OCI manifest lists, run Trivy vulnerability scans (`_rock-scan.yaml`), and promote both architectures via `skopeo copy --all` (`_rock-promote.yaml` in `canonical/identity-team` `v1.17.1`) to `stable` and `<version>` only when zero blocking vulnerabilities exist.

## 3. Verification Commands

```bash
python3 scripts/validate_openspec.py
python3 scripts/check_openspec_drift.py
openspec validate --all --strict
```
