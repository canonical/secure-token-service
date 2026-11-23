# Spec Delta

## Purpose

Extends normalized identity and tenancy claim extraction to OIDC logins, preserves optional extended attributes on OpenID 2.0 logins, and unifies session expiration semantics across both identity providers and session extension workflows.

## ADDED Requirements

### Requirement: OIDC identity and tenancy claim extraction
When authenticating via OIDC, the system SHALL extract available standard claims (`sub`, `email`, `name`, `given_name`, `preferred_username`) and the configured tenancy claim (`OIDC_TENANT_CLAIM`, defaulting to `tenant`) from the verified ID token into normalized session claims. If `name` is absent, the system SHALL compose `name` from `given_name` and `family_name`.

#### Scenario: OIDC ID token contains profile and default tenant claims
- **WHEN** an OIDC ID token includes `sub`, `email`, `name`, `given_name`, `preferred_username`, and `tenant: "canonical"`
- **THEN** the system stores those normalized claims and `idp_provider: "oidc"` in the session record
- **THEN** `ExchangeSession` propagates those normalized claims into minted internal JWTs

#### Scenario: Custom configured tenancy claim name
- **WHEN** `OIDC_TENANT_CLAIM` is set to `org` and the verified ID token contains `org: "engineering"`
- **THEN** the system stores `tenant: "engineering"` in the normalized session claims

#### Scenario: Missing name falls back to given_name and family_name
- **WHEN** an OIDC ID token omits `name` but includes `given_name: "Alice"` and `family_name: "Smith"`
- **THEN** the system stores `name: "Alice Smith"` and `given_name: "Alice"` in the normalized session claims

#### Scenario: OIDC ID token omits optional profile and tenancy claims
- **WHEN** an OIDC ID token provides only `email` and omits `name` and the configured tenancy claim
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

## MODIFIED Requirements

### Requirement: Upstream claims extraction and substitution
When authenticating via Ubuntu One OpenID, the system SHALL extract available claims from verified SREG 1.1 and AX 1.0 extensions (`email`, `nickname`, `fullname`, and optional `given_name` and `tenant`), prioritizing SREG over AX. The system SHALL store available normalized claims in the session and omit absent optional attributes without failing login.

#### Scenario: OpenID assertion contains full attributes
- **WHEN** Ubuntu One returns an assertion with email `alice@canonical.com`, nickname `alice`, and fullname `Alice Smith` via SREG or AX
- **THEN** the system maps these into normalized claims `email: "alice@canonical.com"`, `nickname: "alice"`, and `name: "Alice Smith"`
- **THEN** the claims are stored in the session record

#### Scenario: OpenID assertion with subset of attributes
- **WHEN** Ubuntu One returns an assertion containing nickname and fullname but omitting email and tenant
- **THEN** the system only extracts the available claims without failure
- **THEN** the available claims are preserved in the session

#### Scenario: OpenID assertion includes optional given_name or tenant
- **WHEN** an OpenID 2.0 provider returns AX `first_name` or a tenancy attribute alongside standard attributes
- **THEN** the system stores normalized `given_name` and `tenant` in the session claims
