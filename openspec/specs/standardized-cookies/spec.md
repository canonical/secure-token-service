# standardized-cookies Specification

## Purpose
Standardizes the generation, attributes, and clearing of all authentication and session cookies across the service to eliminate configuration drift, prevent cross-site scripting (XSS) and cross-site request forgery (CSRF), and ensure proper behavior across both HTTPS and local development environments.

For architectural diagrams and component details, see [Architecture Design: Standardized Cookie Pipeline](../../changes/archive/2026-10-29-support-ubuntu-one-openid/design.md#standardized-cookie-architecture).

## Requirements

### Requirement: Host-prefixed cookie names
The system SHALL issue every authentication and session cookie with the `__Host-` name prefix, `Path: "/"`, `HttpOnly: true`, `Secure: true`, and no `Domain` attribute. The system SHALL reject pre-upgrade cookies that lack the `__Host-` prefix.

#### Scenario: Login sets prefixed session cookie
- **WHEN** user authentication succeeds via either OIDC or OpenID
- **THEN** the system issues a `Set-Cookie` header for `__Host-session_id` with `Path: "/"`, `HttpOnly`, `Secure`, and no `Domain` attribute

#### Scenario: Pre-upgrade cookie is not honored
- **WHEN** a client presents an unprefixed `session_id`, `oauth_state`, or `oauth_nonce` cookie minted before the upgrade
- **THEN** the system does not authenticate or resume state from that cookie and starts a fresh flow

### Requirement: Static secure cookie attributes
The system SHALL always set the `Secure` attribute on service-issued cookies, independent of the incoming request transport. This is a **breaking change**: plain-HTTP deployments and local development without TLS can no longer set or read these cookies.

#### Scenario: Request over HTTPS sets Secure flag
- **WHEN** an authentication or session cookie is generated for any request
- **THEN** the emitted `Set-Cookie` header contains `; Secure`

#### Scenario: Plain HTTP request still sets Secure flag
- **WHEN** an authentication or session cookie is generated for a plain HTTP request without secure forward headers
- **THEN** the emitted `Set-Cookie` header still contains `; Secure`, and local development requires HTTPS or a browser localhost exception

### Requirement: Centralized session cookie issuance
All session cookies (`__Host-session_id`) set by the service SHALL be constructed through `CookieManager`. Handcrafted `http.Cookie` definitions for session management in HTTP handlers SHALL NOT be permitted. The session cookie value SHALL be encrypted and authenticated using authenticated encryption (AEAD). **Breaking change**: the session cookie carries a `Max-Age` derived from the session lifetime instead of an `Expires` timestamp.

#### Scenario: Successful login sets standardized session cookie
- **WHEN** user authentication succeeds via either OIDC or OpenID
- **THEN** the system issues a `Set-Cookie` header for `__Host-session_id` configured with `HttpOnly: true`, `Secure: true`, `SameSite: Lax`, `Path: "/"`, and `Max-Age` aligned with the session lifetime
- **THEN** the cookie value is encrypted and tamper-proof

#### Scenario: Session cookie value expires after the configured lifetime
- **WHEN** a client presents a session cookie value older than the configured session lifetime
- **THEN** the system rejects the value and treats the request as unauthenticated

#### Scenario: Session cookie value with no lifetime limit
- **WHEN** the system decodes a session cookie value with the lifetime check disabled
- **THEN** the system accepts values up to the maximum cookie lifetime of 400 days enforced by the cookie library

### Requirement: Standardized cookie clearing on logout
When a user logs out, the system SHALL clear the session cookie through `CookieManager` using standardized attributes (`Path: "/"`, `HttpOnly: true`, `Secure: true`, `SameSite: Lax`) with an expiration timestamp in the past.

#### Scenario: Logout clears session cookie cleanly
- **WHEN** a client sends `POST /auth/logout` with an active session cookie
- **THEN** the session is removed from storage
- **THEN** the response includes a `Set-Cookie` header for `__Host-session_id` with empty value and an expired timestamp

### Requirement: Authentication state and nonce cookie cleanup
After processing an authentication callback (whether successful or failed), the system SHALL clear the `__Host-oauth_state` and `__Host-oauth_nonce` cookies via `CookieManager` with the standardized attributes (`Path: "/"`, `HttpOnly: true`, `Secure: true`, `SameSite: Lax`) and an expiration timestamp in the past.

#### Scenario: Successful authentication callback clears state and nonce cookies
- **WHEN** an authentication callback is processed successfully
- **THEN** the system clears the `__Host-oauth_state` and `__Host-oauth_nonce` cookies via `CookieManager` using standardized attributes and expired timestamps

#### Scenario: Failed authentication callback clears state and nonce cookies
- **WHEN** an authentication callback fails verification, receives an error, or encounters an invalid state
- **THEN** the system clears the `__Host-oauth_state` and `__Host-oauth_nonce` cookies via `CookieManager` using standardized attributes and expired timestamps before returning the error response
