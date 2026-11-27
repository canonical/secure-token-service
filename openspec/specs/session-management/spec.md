# session-management Specification

## Purpose
Defines self-service HTTP endpoints (`GET /auth/sessions`, `DELETE /auth/sessions/{session_id}`, and `DELETE /auth/sessions`) so signed-in users can view all of their open sessions and revoke a single session or all sessions using their active session cookie.

## Requirements

### Requirement: Self-service active session listing
When an authenticated user calls `GET /auth/sessions` with a valid `session_id` cookie passing session identity validation, the system SHALL return `200 OK` listing active sessions indexed under the caller's provider-specific `UserID` (OIDC `sub` or OpenID short `u1_sso_id`). Each item SHALL contain only `session_id`, `provider`, `created_at`, `expires_at` (derived from store TTL), and `is_current`, with `Cache-Control: no-store`, `Vary: Cookie`, and `X-Content-Type-Options: nosniff`.

#### Scenario: User lists multiple open sessions
- **WHEN** a user with two active OIDC sessions sends `GET /auth/sessions` using session A's valid cookie
- **THEN** the system returns `200 OK` with both sessions containing `session_id`, `provider`, `created_at`, `expires_at`, and `is_current`
- **THEN** session A has `is_current: true`, session B has `is_current: false`, and no upstream tokens or other users' sessions appear

#### Scenario: Expired sessions excluded and lazily pruned
- **WHEN** the user's session index contains an expired session ID alongside an active session
- **THEN** the system omits the expired session from the `GET /auth/sessions` response
- **THEN** the system removes the stale session ID from the user's session index

#### Scenario: Unauthenticated or invalid-identity session listing
- **WHEN** a client sends `GET /auth/sessions` without a valid active `session_id` cookie or with a legacy/inconsistent session failing identity validation
- **THEN** the system returns `401 Unauthorized` with a JSON error response

#### Scenario: Session store unavailable during listing
- **WHEN** the session store fails with a connectivity or timeout error during `GET /auth/sessions`
- **THEN** the system returns `503 Service Unavailable` with a JSON error response

### Requirement: Single-session revocation
When an authenticated user calls `DELETE /auth/sessions/{session_id}`, the system SHALL verify that the caller owns the target session and delete only that session from the store. If the target session does not exist or belongs to another user, the system SHALL return `404 Not Found`. If the target is the caller's current session, the system SHALL also clear the `session_id` cookie.

#### Scenario: Revoke another session owned by the caller
- **WHEN** a user sends `DELETE /auth/sessions/{other_id}` for another active session they own
- **THEN** the system deletes `{other_id}` from the session store and removes it from the user's session index
- **THEN** the system returns `200 OK` (or `204 No Content`) and leaves the caller's current session and cookie intact

#### Scenario: Revoke the caller's current session
- **WHEN** a user sends `DELETE /auth/sessions/{current_id}` matching their active `session_id` cookie
- **THEN** the system deletes `{current_id}` from the session store and clears the `session_id` cookie using standardized cookie attributes

#### Scenario: Revoke non-existent or foreign session
- **WHEN** a user sends `DELETE /auth/sessions/{target_id}` for a session ID that does not exist or belongs to a different user
- **THEN** the system does not delete any session and returns `404 Not Found` without revealing whether the session ID exists

#### Scenario: Unauthenticated single-session revocation
- **WHEN** a client sends `DELETE /auth/sessions/{session_id}` without a valid active `session_id` cookie
- **THEN** the system returns `401 Unauthorized`

### Requirement: Bulk session revocation
When an authenticated user calls `DELETE /auth/sessions`, the system SHALL revoke all sessions owned by that user and clear the `session_id` cookie. When the query parameter `exclude_current=true` is provided, the system SHALL revoke all other sessions owned by that user while preserving the caller's current session and cookie.

#### Scenario: Revoke all sessions by default
- **WHEN** a user with three active sessions sends `DELETE /auth/sessions` without `exclude_current`
- **THEN** the system deletes all three sessions from the store, clears the `session_id` cookie, and returns `200 OK` with `revoked_count: 3`

#### Scenario: Revoke all other sessions while keeping current session
- **WHEN** a user with three active sessions sends `DELETE /auth/sessions?exclude_current=true`
- **THEN** the system deletes the two non-current sessions and removes them from the user's session index
- **THEN** the caller's current session remains active, no `Set-Cookie` clear header is sent, and the system returns `200 OK` with `revoked_count: 2`

#### Scenario: Invalid exclude_current query parameter
- **WHEN** a user sends `DELETE /auth/sessions?exclude_current=notabool`
- **THEN** the system rejects the request with `400 Bad Request` without revoking any sessions

#### Scenario: Unauthenticated bulk revocation
- **WHEN** a client sends `DELETE /auth/sessions` without a valid active `session_id` cookie
- **THEN** the system returns `401 Unauthorized`

### Requirement: Same-origin CSRF protection for session revocation
Before processing state-changing cookie routes (`POST /auth/logout`, `DELETE /auth/sessions`, and `DELETE /auth/sessions/{session_id}`), the system SHALL enforce cross-origin protection using Go's `http.NewCrossOriginProtection` and reject cross-origin browser requests with `403 Forbidden`, while allowing same-origin browser requests and non-browser requests omitting `Sec-Fetch-Site` and `Origin`.

#### Scenario: Browser same-origin request accepted
- **WHEN** a browser sends `DELETE /auth/sessions` with `Sec-Fetch-Site: same-origin` and a valid `session_id` cookie
- **THEN** the system allows the request to proceed to session revocation

#### Scenario: Cross-site or cross-origin browser request rejected
- **WHEN** a browser sends `DELETE /auth/sessions` with `Sec-Fetch-Site: cross-site` or `Sec-Fetch-Site: same-site`
- **THEN** the system rejects the request with `403 Forbidden` without revoking any sessions

#### Scenario: Fallback Origin check when Sec-Fetch-Site is absent
- **WHEN** a request omits `Sec-Fetch-Site` and sends an `Origin` header whose host does not match the request host
- **THEN** the system rejects the request with `403 Forbidden`

#### Scenario: Non-browser request omitting both headers allowed
- **WHEN** a CLI client sends `DELETE /auth/sessions/{id}` with a valid `session_id` cookie and neither `Sec-Fetch-Site` nor `Origin`
- **THEN** the system allows the request to proceed

### Requirement: Bounded route observability and session key contract
The system SHALL record HTTP metrics for `/auth/sessions/{session_id}` using the parameterized route template instead of raw session IDs. Breaking change: sessions are indexed per provider by `UserID` (OIDC `sub` or OpenID short `u1_sso_id`), so `/auth/sessions*` and gRPC `RevokeUserSessions` operate on that provider-specific `UserID` rather than email, and invalid/legacy sessions SHALL be rejected with `401 Unauthorized`.

#### Scenario: Single-session revocation emits parameterized route metric
- **WHEN** a client calls `DELETE /auth/sessions/550e8400-e29b-41d4-a716-446655440000`
- **THEN** HTTP server metrics record `http.route="/auth/sessions/{session_id}"` rather than the raw UUID path

#### Scenario: Logout and gRPC revocation follow provider-specific UserID contract
- **WHEN** session CRUD endpoints and gRPC `RevokeUserSessions` are invoked
- **THEN** same-origin browser and non-browser `POST /auth/logout` requests succeed (cross-origin browser requests return `403 Forbidden`) and gRPC `RevokeUserSessions` revokes sessions indexed under the provided OIDC `sub` or OpenID short `u1_sso_id`
