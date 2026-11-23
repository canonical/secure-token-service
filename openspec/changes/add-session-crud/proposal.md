# Proposal

## Why

Signed-in users can currently log out only from their active browser session and have no self-service way to inspect all open sessions or revoke individual or all sessions. Meanwhile, `GET /auth/sessions` exists only as a `501 Not Implemented` placeholder in the HTTP router.

## What Changes

- Implement `GET /auth/sessions` to list all active sessions belonging to the authenticated caller, returning minimal safe metadata (`session_id`, `provider`, `created_at`, `expires_at`, and `is_current`).
- Implement `DELETE /auth/sessions/{session_id}` to revoke a single session owned by the caller, clearing the session cookie if the revoked session is the caller's current session.
- Implement `DELETE /auth/sessions` to revoke all sessions owned by the caller and clear the session cookie, with an optional `?exclude_current=true` query parameter to revoke only other sessions.
- Authenticate all session-management endpoints directly with the AEAD `session_id` cookie, enforce strict session ownership checks, and enforce same-origin CSRF checks on `DELETE` requests.
- Derive accurate session expiration timestamps from the session store TTL and lazily prune expired session identifiers from the per-user session index.
- Record parameterized route patterns (instead of raw paths containing session UUIDs) in HTTP metrics middleware to prevent Prometheus cardinality explosion.

## Non-goals

- Current-user profile inspection (`GET /auth/me`, covered in the separate `add-whoami-endpoint` change).
- Cross-user administrative session listing or revocation over HTTP (cross-user revocation remains on gRPC `RevokeUserSessions`).
- Capturing or exposing client IP addresses, device names, or `User-Agent` strings in v1 session listings.
- Cross-origin CORS support for browser clients on separate origins (this change assumes same-origin access behind a reverse proxy).
- Immediate invalidation of already-minted internal short-lived JWTs (per [ADR-004](../../../docs/adr/004-phantom-token-pattern.md), existing JWTs remain valid until their short expiry).

## Success Metrics

- Authenticated users list all open sessions and identify their current session (`is_current: true`) via `GET /auth/sessions`.
- Revoking one session or all sessions removes the target records from the session store immediately, preventing subsequent `ExchangeSession` and `GET /auth/me` calls from succeeding for revoked sessions.
- Cross-user revocation attempts always fail with `404 Not Found` without revealing whether another user's session ID exists.
- Cross-site `DELETE` requests fail with `403 Forbidden`, and HTTP metrics emit bounded route labels (`/auth/sessions/{session_id}`).

## Capabilities

### New Capabilities

- `session-management`: Provides self-service HTTP CRUD endpoints (`GET /auth/sessions`, `DELETE /auth/sessions/{session_id}`, `DELETE /auth/sessions`) for users to view and revoke their own active sessions.

### Modified Capabilities

## Impact

- **HTTP API**: Replaces the `501` stub for `GET /auth/sessions` and adds `DELETE /auth/sessions` and `DELETE /auth/sessions/{session_id}` in [internal/http/server.go](../../../internal/http/server.go), plus updates [docs/api/openapi.yaml](../../../docs/api/openapi.yaml).
- **Session Store**: Adds per-user session listing (with TTL-derived expiration and stale-ID pruning) and selective revocation methods to [internal/session/store.go](../../../internal/session/store.go).
- **Observability**: Updates `HTTPMetricsMiddleware` in [internal/observability/metrics.go](../../../internal/observability/metrics.go) to report route templates rather than raw URL paths.
- **Backward Compatibility**: Replaces the unimplemented `501` stub at `GET /auth/sessions` with the authenticated self-service endpoint; existing `/auth/login`, `/auth/logout`, and gRPC `RevokeUserSessions` behaviors remain unchanged.
