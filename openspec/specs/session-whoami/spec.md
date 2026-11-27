# session-whoami Specification

## Purpose
Defines the browser-facing `GET /auth/me` endpoint so same-origin web clients can check authentication state and read minimal public user identity directly from the active session cookie without exposing tokens or weakening immediate revocation.

## Requirements

### Requirement: Cookie-authenticated current user lookup
Breaking change: when a client calls `GET /auth/me` with a valid `session_id` cookie, the system SHALL validate the cookie and session identity contract without requiring a JWT and return `200 OK` with `authenticated: true` and minimal public user fields (optional `id`, `email`, `name`, `tenant`, and short `u1_sso_id`). `user.id` SHALL match JWT `sub` (OIDC `sub`) and SHALL be omitted for OpenID 2.0 sessions.

#### Scenario: Authenticated OIDC session with full profile, tenant, and u1_sso_id
- **WHEN** a browser sends `GET /auth/me` with a valid `session_id` cookie for an OIDC session containing `sub`, `email`, short `u1_sso_id`, `name`, and `tenant`
- **THEN** the system returns `200 OK` with `Content-Type: application/json`
- **THEN** the JSON body contains `authenticated: true` and `user` with `id` (OIDC `sub`), `email`, `u1_sso_id`, `name`, and `tenant`

#### Scenario: Authenticated Ubuntu One OpenID session omits id and tenant
- **WHEN** a browser sends `GET /auth/me` with a valid `session_id` cookie for an Ubuntu One OpenID session that has short `u1_sso_id`, `email`, and `name` but no `tenant`
- **THEN** the system returns `200 OK` with `Content-Type: application/json` and `user` containing `u1_sso_id`, `email`, and `name`
- **THEN** both `id` and `tenant` keys are omitted from `user`

#### Scenario: Minimal OIDC session omits absent optional fields
- **WHEN** a browser sends `GET /auth/me` with a valid OIDC session containing only `sub` and `email`
- **THEN** the system returns `200 OK` with `authenticated: true` and `user` containing `id` and `email`
- **THEN** optional fields `name`, `tenant`, and `u1_sso_id` are omitted without error

### Requirement: Unauthenticated and degraded-store handling
When `GET /auth/me` receives a missing, malformed, tampered, or expired `session_id` cookie, a missing or revoked session, or a legacy/inconsistent session failing identity validation, the system SHALL return `401 Unauthorized` with JSON `{ "authenticated": false }` and SHALL NOT modify cookies. If the session store is unreachable, the system SHALL return `503 Service Unavailable`.

#### Scenario: Missing session cookie
- **WHEN** a client sends `GET /auth/me` without a `session_id` cookie
- **THEN** the system returns `401 Unauthorized` with `{ "authenticated": false }` without querying the session store

#### Scenario: Malformed or tampered session cookie
- **WHEN** a client sends `GET /auth/me` with a corrupted or forged `session_id` cookie
- **THEN** the system rejects the cookie during AEAD verification without querying the session store
- **THEN** the system returns `401 Unauthorized` with `{ "authenticated": false }` and sends no `Set-Cookie` header

#### Scenario: Revoked or expired session
- **WHEN** a client sends `GET /auth/me` with a valid cookie whose session was deleted or expired in the session store
- **THEN** the system returns `401 Unauthorized` with `{ "authenticated": false }`

#### Scenario: Legacy or inconsistent session record rejected
- **WHEN** a client sends `GET /auth/me` with a cookie referencing a legacy claimless OIDC session, mismatched `sub`/`u1_sso_id`, or URL-formatted `u1_sso_id`
- **THEN** the system returns `401 Unauthorized` with `{ "authenticated": false }` and sends no `Set-Cookie` header

#### Scenario: Session store unavailable
- **WHEN** the session store returns a connectivity or timeout error during `GET /auth/me`
- **THEN** the system returns `503 Service Unavailable` with a JSON error payload rather than `401 Unauthorized`

### Requirement: Response security and non-cacheability
The system SHALL set `Cache-Control: no-store`, `Vary: Cookie`, and `X-Content-Type-Options: nosniff` on every `GET /auth/me` response. The system MUST NOT include upstream access tokens, ID tokens, refresh tokens, `session_id`, or unlisted raw claims in the response body.

#### Scenario: Security and cache headers on response
- **WHEN** any client calls `GET /auth/me` (authenticated or unauthenticated)
- **THEN** the response includes `Cache-Control: no-store`, `Vary: Cookie`, and `X-Content-Type-Options: nosniff`

#### Scenario: Sensitive tokens and extra claims excluded
- **WHEN** a session contains upstream OAuth2 tokens (`access_token`, `id_token`, `refresh_token`) and additional claims such as `nickname` or `preferred_username`
- **THEN** the `GET /auth/me` response contains only `authenticated` and the minimal `user` fields (optional `id`, `email`, `name`, `tenant`, and `u1_sso_id`)
