# claims-normalization Specification

## Purpose
Establishes a uniform claims extraction and normalization pipeline across upstream identity providers, mapping OIDC (`sub`, verified `email`, optional short `u1_sso_id`) and Ubuntu One OpenID 2.0 (short `u1_sso_id` and signed `email`, omitting `sub`) into normalized session records and downstream internal ES256 JWTs.

For architectural diagrams and component details, see [Architecture Design: Claims Normalization and Mapping](../../changes/archive/2026-10-29-support-ubuntu-one-openid/design.md#claims-normalization-and-parity-strategy).

## Requirements

### Requirement: Upstream claims extraction and substitution
When authenticating via Ubuntu One OpenID, the system SHALL extract claims strictly from `openid.signed` SREG 1.1 and AX 1.0 fields (`email`, `nickname`, `fullname`, optional `given_name`) and extract the short `u1_sso_id` from signed HTTPS `openid.claimed_id` (`https://<host>/+id/<short_id>`). Legacy `claimed_id`, `openid.identity` fallback, `identifier_select`, and unsigned parameters SHALL be omitted.

#### Scenario: OpenID assertion contains full attributes
- **WHEN** Ubuntu One returns a signed assertion with `claimed_id` `https://login.ubuntu.com/+id/Xb6LTdm`, email `alice@canonical.com`, nickname `alice`, and fullname `Alice Smith` via SREG or AX
- **THEN** the system maps these into normalized claims `u1_sso_id: "Xb6LTdm"`, `email: "alice@canonical.com"`, `nickname: "alice"`, and `name: "Alice Smith"`
- **THEN** the legacy `claimed_id` claim is omitted and the normalized claims are stored in the session record

#### Scenario: OpenID assertion with subset of attributes
- **WHEN** Ubuntu One returns a signed assertion containing `claimed_id`, email, and fullname but omitting nickname and given_name
- **THEN** the system only extracts the available claims without failure
- **THEN** the available claims (`u1_sso_id`, `email`, `name`) are preserved in the session

#### Scenario: OpenID assertion includes optional given_name
- **WHEN** an OpenID 2.0 provider returns a signed AX `first_name` attribute alongside standard attributes
- **THEN** the system stores normalized `given_name` in the session claims and ignores any unsigned query parameters

### Requirement: Single-source user identifier resolution
Breaking change from email-keyed sessions: for OIDC logins, the system SHALL resolve `UserID` strictly from `sub` while requiring verified `email` (`email_verified` not false/invalid). For OpenID 2.0 logins, `UserID` SHALL be the short `u1_sso_id` from signed HTTPS `openid.claimed_id` (`/+id/<short_id>`, rejecting `openid.identity` fallback and `identifier_select`) while requiring signed `email`. Missing or invalid required claims SHALL fail closed.

#### Scenario: OIDC user identified by sub with verified email
- **WHEN** an OIDC ID token contains `sub` and a verified `email`
- **THEN** the session `UserID` is set to `sub` and `email` is stored in normalized session claims

#### Scenario: OIDC response missing sub rejects login
- **WHEN** an OIDC ID token omits `sub` (even if verified `email`, `preferred_username`, or `nickname` is present)
- **THEN** the system rejects session creation without falling back

#### Scenario: Unverified OIDC email rejects login
- **WHEN** an OIDC ID token contains `email` alongside `email_verified: false`, `"false"`, or `nil` (even if `sub`, `preferred_username`, or `nickname` is present)
- **THEN** the system omits `email` from normalized claims and rejects session creation without falling back

#### Scenario: OpenID user identified by signed claimed_id short ID with signed email
- **WHEN** an OpenID 2.0 assertion contains signed `openid.claimed_id` `https://login.ubuntu.com/+id/Xb6LTdm` and signed `email`
- **THEN** the session `UserID` is set to `"Xb6LTdm"` and both `u1_sso_id: "Xb6LTdm"` and `email` are stored in normalized claims

#### Scenario: OpenID response missing email or invalid claimed_id rejects login
- **WHEN** an OpenID assertion omits signed `email`, omits signed `openid.claimed_id` (even if `openid.identity` is signed), uses `identifier_select`, or lacks a valid `https://<host>/+id/<short_id>` identifier
- **THEN** the system rejects session creation without falling back

### Requirement: Internal JWT claim propagation
Breaking change: when `ExchangeSession` is called with a valid session cookie, the system SHALL validate the session identity contract and mint an ES256 JWT with `email`, optional short `u1_sso_id`, profile, and tenancy. OIDC sessions SHALL emit `sub = Session.UserID`; OpenID 2.0 sessions SHALL omit `sub` and strip legacy `claimed_id`. Legacy, claimless, or inconsistent sessions SHALL fail closed with gRPC `Unauthenticated`.

#### Scenario: gRPC session exchange for Ubuntu One OpenID omits sub
- **WHEN** `ExchangeSession` is invoked for a valid session created via Ubuntu One OpenID
- **THEN** the minted internal JWT contains standard claims (`iss`, `aud`, `iat`, `exp`) with `sub` omitted and custom claims carrying `email`, short `u1_sso_id`, `nickname`, and `name`

#### Scenario: gRPC session exchange for OIDC emits sub, email, and optional u1_sso_id
- **WHEN** `ExchangeSession` is invoked for a valid OIDC session with `sub`, `email`, short `u1_sso_id`, and `tenant`
- **THEN** the minted internal JWT sets `sub` to the OIDC `sub` claim and propagates `email`, `u1_sso_id`, profile claims, and `tenant`

#### Scenario: Legacy or inconsistent session rejected on ExchangeSession
- **WHEN** `ExchangeSession` is invoked for a session with an unsupported/empty provider, claimless OIDC record, mismatched `sub`/`u1_sso_id`, missing `email`, or URL-formatted `u1_sso_id`
- **THEN** the system rejects the exchange with gRPC `Unauthenticated` requiring re-authentication

### Requirement: OIDC identity and tenancy claim extraction
When authenticating via OIDC, the system SHALL extract standard claims (`sub`, `email`, `name`, `given_name`, `preferred_username`, `nickname`), `OIDC_TENANT_CLAIM` (default `tenant`), and `OIDC_U1_SSO_ID_CLAIM` (default `u1_sso_id`, validated as a short ID without `/` or `:`) into normalized session claims. Absent `name` SHALL be composed from `given_name` and `family_name`; malformed optional claims SHALL be ignored.

#### Scenario: OIDC ID token contains profile, default tenant, and default u1_sso_id claims
- **WHEN** an OIDC ID token includes `sub`, `email`, `u1_sso_id: "Xb6LTdm"`, `name`, `given_name`, `preferred_username`, `nickname`, and `tenant: "canonical"`
- **THEN** the system stores those normalized claims and `idp_provider: "oidc"` in the session record
- **THEN** `ExchangeSession` propagates those normalized claims into minted internal JWTs with `sub` set to the OIDC `sub`

#### Scenario: Custom configured tenancy and U1SSO claim names
- **WHEN** `OIDC_TENANT_CLAIM` is set to `org` and `OIDC_U1_SSO_ID_CLAIM` is set to `ubuntu_one_id`, and the verified ID token contains `org: "engineering"` and `ubuntu_one_id: "Xb6LTdm"`
- **THEN** the system stores `tenant: "engineering"` and `u1_sso_id: "Xb6LTdm"` in the normalized session claims

#### Scenario: Invalid URL-formatted OIDC u1_sso_id is ignored
- **WHEN** an OIDC ID token supplies a URL or colon-containing value for `OIDC_U1_SSO_ID_CLAIM` alongside valid `sub` and verified `email`
- **THEN** the system ignores the invalid `u1_sso_id` claim and still creates the session without error

#### Scenario: Missing name falls back to given_name and family_name
- **WHEN** an OIDC ID token omits `name` but includes `given_name: "Alice"` and `family_name: "Smith"`
- **THEN** the system stores `name: "Alice Smith"` and `given_name: "Alice"` in the normalized session claims

#### Scenario: OIDC ID token omits optional profile, tenancy, and U1SSO claims
- **WHEN** an OIDC ID token provides only `sub` and verified `email` and omits `name`, tenancy, and U1SSO claims
- **THEN** the system creates the session without error and omits absent optional claims from the session record

### Requirement: Unified session expiration across providers
Both OIDC and OpenID 2.0 authentication callbacks SHALL set the session record `expires_at` timestamp from the configured session lifetime (`SESSION_EXPIRY`), matching the session store TTL and `session_id` cookie expiration. Session extension commands SHALL update `expires_at` to match the extended store TTL.

#### Scenario: OIDC callback uses configured session lifetime
- **WHEN** a user completes OIDC login with an upstream access token expiring in 15 minutes and `SESSION_EXPIRY` set to 24 hours
- **THEN** the system sets `Session.ExpiresAt`, the session store TTL, and the `session_id` cookie expiration to 24 hours from login time

#### Scenario: OpenID callback uses configured session lifetime
- **WHEN** a user completes Ubuntu One OpenID 2.0 login with `SESSION_EXPIRY` set to 24 hours
- **THEN** the system sets `Session.ExpiresAt`, the session store TTL, and the `session_id` cookie expiration to 24 hours from login time

#### Scenario: Session extension updates session expiration
- **WHEN** an operator runs session extension with a 48-hour TTL on an active session
- **THEN** the system updates both the session store TTL and `Session.ExpiresAt` to 48 hours from the refresh time
