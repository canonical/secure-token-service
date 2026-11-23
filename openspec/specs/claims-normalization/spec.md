# claims-normalization Specification

## Purpose
Establishes a uniform claims extraction and fallback pipeline across upstream identity providers, allowing attributes from Ubuntu One OpenID assertions (such as email, nickname, and fullname) to be mapped and substituted in place of OIDC claims, stored in the session, and minted into downstream internal JWTs.

For architectural diagrams and component details, see [Architecture Design: Claims Normalization and Mapping](../../changes/archive/2026-10-29-support-ubuntu-one-openid/design.md#claims-normalization-and-parity-strategy).

## Requirements

### Requirement: Upstream claims extraction and substitution
When authenticating via Ubuntu One OpenID, the system SHALL extract available claims strictly from fields covered by `openid.signed` in verified SREG 1.1 and AX 1.0 extensions (`email`, `nickname`, `fullname`, and optional `given_name`), prioritizing SREG over AX. Unsigned parameters SHALL be ignored.

#### Scenario: OpenID assertion contains full attributes
- **WHEN** Ubuntu One returns a signed assertion with email `alice@canonical.com`, nickname `alice`, and fullname `Alice Smith` via SREG or AX
- **THEN** the system maps these into normalized claims `email: "alice@canonical.com"`, `nickname: "alice"`, and `name: "Alice Smith"`
- **THEN** the claims are stored in the session record

#### Scenario: OpenID assertion with subset of attributes
- **WHEN** Ubuntu One returns a signed assertion containing nickname and fullname but omitting email
- **THEN** the system only extracts the available claims without failure
- **THEN** the available claims are preserved in the session

#### Scenario: OpenID assertion includes optional given_name
- **WHEN** an OpenID 2.0 provider returns a signed AX `first_name` attribute alongside standard attributes
- **THEN** the system stores normalized `given_name` in the session claims and ignores any unsigned query parameters

### Requirement: User identifier selection hierarchy
For OIDC logins, the system SHALL resolve `UserID` strictly from verified `email` (when `email_verified` is not false/invalid) or `oidc:<sub>`, never falling back to mutable `nickname` or `preferred_username`. For OpenID 2.0 logins, the system SHALL resolve `UserID` from `email`, then `nickname`, then `claimed_id`. If none can be established, session creation SHALL fail.

#### Scenario: User identified by email
- **WHEN** an identity response contains a valid email address
- **THEN** the session `UserID` is set to the email address

#### Scenario: Fallback to nickname when email absent
- **WHEN** an OpenID response contains a nickname but no email address
- **THEN** the session `UserID` is set to the nickname

#### Scenario: Fallback to claimed_id when nickname and email absent
- **WHEN** an OpenID response contains only the OpenID `claimed_id`
- **THEN** the session `UserID` is set to the `claimed_id`

#### Scenario: Unverified OIDC email falls back to prefixed subject identifier
- **WHEN** an OIDC ID token contains `email` alongside `email_verified: false` (even if `preferred_username` or `nickname` is present)
- **THEN** the system omits `email` from normalized claims and sets `UserID` to `oidc:<sub>`

### Requirement: Internal JWT claim propagation
When an API Gateway calls `ExchangeSession` over gRPC with a valid session cookie, the system SHALL mint an internal ES256 JWT containing all normalized claims stored within the session record.

#### Scenario: gRPC session exchange reflects normalized claims
- **WHEN** `ExchangeSession` is invoked for a session created via Ubuntu One OpenID
- **THEN** the minted internal JWT contains standard claims (`iss`, `sub`, `aud`, `iat`, `exp`) and custom claims reflecting the extracted OpenID attributes (`email`, `nickname`, `name`)

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
