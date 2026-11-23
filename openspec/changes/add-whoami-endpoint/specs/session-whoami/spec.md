# Spec Delta

## Purpose

Defines the browser-facing `GET /auth/me` endpoint so same-origin web clients can check authentication state and read minimal public user identity directly from the active session cookie without exposing tokens or weakening immediate revocation.

## ADDED Requirements

### Requirement: Cookie-authenticated current user lookup
When a client calls `GET /auth/me` with a valid `session_id` cookie, the system SHALL validate the cookie against the active session store without requiring a JWT and SHALL return `200 OK` with `authenticated: true` and minimal public user fields (`id`, `email`, and optional `name` and `tenant`). The `id` field SHALL match the `sub` minted by `ExchangeSession`.

#### Scenario: Authenticated OIDC session with full profile and tenant
- **WHEN** a browser sends `GET /auth/me` with a valid `session_id` cookie for an OIDC session containing `email`, `name`, and `tenant`
- **THEN** the system returns `200 OK` with `Content-Type: application/json`
- **THEN** the JSON body contains `authenticated: true` and `user` with `id`, `email`, `name`, and `tenant`

#### Scenario: Authenticated Ubuntu One OpenID session without tenant
- **WHEN** a browser sends `GET /auth/me` with a valid `session_id` cookie for an Ubuntu One OpenID session that has `email` and `name` but no `tenant`
- **THEN** the system returns `200 OK` with `authenticated: true` and `user` containing `id`, `email`, and `name`
- **THEN** the `tenant` key is omitted from `user`

#### Scenario: OpenID session identified without email
- **WHEN** a browser sends `GET /auth/me` for an Ubuntu One OpenID session whose `UserID` fell back to `nickname` or `claimed_id` with no `email`
- **THEN** the system returns `200 OK` with `authenticated: true` and `user.id` set to the session `UserID`
- **THEN** the `email` key is omitted from `user`

#### Scenario: Legacy in-flight session without normalized claims
- **WHEN** a browser sends `GET /auth/me` with a valid session created before OIDC claim normalization rolled out (`Claims` is empty)
- **THEN** the system returns `200 OK` with `authenticated: true`, `user.id` set to `UserID`, and `user.email` set when `UserID` is an email address
- **THEN** optional fields `name` and `tenant` are omitted without error

### Requirement: Unauthenticated and degraded-store handling
When `GET /auth/me` receives a missing, malformed, tampered, or expired `session_id` cookie, or a cookie referencing a missing or revoked session, the system SHALL return `401 Unauthorized` with JSON `{ "authenticated": false }` and SHALL NOT modify cookies. If the session store is unreachable, the system SHALL return `503 Service Unavailable`.

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

#### Scenario: Session store unavailable
- **WHEN** the session store returns a connectivity or timeout error during `GET /auth/me`
- **THEN** the system returns `503 Service Unavailable` with a JSON error payload rather than `401 Unauthorized`

### Requirement: Response security and non-cacheability
The system SHALL set `Cache-Control: no-store`, `Vary: Cookie`, and `X-Content-Type-Options: nosniff` on every `GET /auth/me` response. The system MUST NOT include upstream access tokens, ID tokens, refresh tokens, `session_id`, or unlisted raw claims in the response body.

#### Scenario: Security and cache headers on response
- **WHEN** any client calls `GET /auth/me` (authenticated or unauthenticated)
- **THEN** the response includes `Cache-Control: no-store`, `Vary: Cookie`, and `X-Content-Type-Options: nosniff`

#### Scenario: Sensitive tokens and extra claims excluded
- **WHEN** a session contains upstream OAuth2 tokens (`access_token`, `id_token`, `refresh_token`) and additional claims such as `nickname` or `claimed_id`
- **THEN** the `GET /auth/me` response contains only `authenticated` and the minimal `user` fields (`id`, `email`, optional `name` and `tenant`)
