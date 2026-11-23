# Spec Delta

## Purpose

Defines self-service HTTP endpoints (`GET /auth/sessions`, `DELETE /auth/sessions/{session_id}`, and `DELETE /auth/sessions`) so signed-in users can view all of their open sessions and revoke a single session or all sessions using their active session cookie.

## ADDED Requirements

### Requirement: Self-service active session listing
When an authenticated user calls `GET /auth/sessions` with a valid `session_id` cookie, the system SHALL return `200 OK` with a JSON object listing all active sessions owned by that user. Each item SHALL contain only `session_id`, `provider`, `created_at`, `expires_at` (derived from active store TTL), and `is_current`, with `Cache-Control: no-store`, `Vary: Cookie`, and `X-Content-Type-Options: nosniff`.

#### Scenario: User lists multiple open sessions
- **WHEN** a user with two active sessions sends `GET /auth/sessions` using session A's valid cookie
- **THEN** the system returns `200 OK` with both sessions containing `session_id`, `provider`, `created_at`, `expires_at`, and `is_current`
- **THEN** session A has `is_current: true`, session B has `is_current: false`, and no upstream tokens or other users' sessions appear

#### Scenario: Expired sessions excluded and lazily pruned
- **WHEN** the user's session index contains an expired session ID alongside an active session
- **THEN** the system omits the expired session from the `GET /auth/sessions` response
- **THEN** the system removes the stale session ID from the user's session index

#### Scenario: Unauthenticated session listing
- **WHEN** a client sends `GET /auth/sessions` without a valid active `session_id` cookie
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
Before processing `DELETE /auth/sessions` or `DELETE /auth/sessions/{session_id}`, the system SHALL enforce same-origin checks and reject cross-origin requests with `403 Forbidden`. The system SHALL accept `Sec-Fetch-Site: same-origin`, fall back to verifying that `Origin` matches the request host when `Sec-Fetch-Site` is absent, and allow non-browser requests omitting both headers.

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

### Requirement: Bounded route observability and backward compatibility
The system SHALL record HTTP metrics for `/auth/sessions/{session_id}` using the parameterized route template instead of raw session IDs to avoid unbounded metric cardinality. Replacing the `501 Not Implemented` placeholder at `GET /auth/sessions` SHALL preserve existing `/auth/login`, `/auth/logout`, and gRPC `RevokeUserSessions` behavior.

#### Scenario: Single-session revocation emits parameterized route metric
- **WHEN** a client calls `DELETE /auth/sessions/550e8400-e29b-41d4-a716-446655440000`
- **THEN** HTTP server metrics record `http.route="/auth/sessions/{session_id}"` rather than the raw UUID path

#### Scenario: Existing authentication and gRPC revocation contracts unchanged
- **WHEN** the session CRUD endpoints are enabled
- **THEN** `POST /auth/logout` and gRPC `RevokeUserSessions` continue to operate with full backward compatibility
