# claims-normalization Specification

## Purpose
Establishes a uniform claims extraction and fallback pipeline across upstream identity providers, allowing attributes from Ubuntu One OpenID assertions (such as email, nickname, and fullname) to be mapped and substituted in place of OIDC claims, stored in the session, and minted into downstream internal JWTs.

For architectural diagrams and component details, see [Architecture Design: Claims Normalization and Mapping](../../design.md#claims-normalization-and-parity-strategy).

## ADDED Requirements

### Requirement: Upstream claims extraction and substitution
When authenticating via Ubuntu One OpenID, the system SHALL extract all available claims from the verified OpenID Simple Registration (SREG 1.1) and Attribute Exchange (AX 1.0) extensions, including `email`, `nickname`, and `fullname`. SREG attributes SHALL be prioritized for Canonical SSO / Ubuntu One compatibility, falling back to AX attributes. These claims SHALL be mapped to normalized identity fields and used in place of standard OIDC claims.

#### Scenario: OpenID assertion contains full attributes
- **WHEN** Ubuntu One returns an assertion with email `alice@canonical.com`, nickname `alice`, and fullname `Alice Smith` via SREG or AX
- **THEN** the system maps these into normalized claims `email: "alice@canonical.com"`, `nickname: "alice"`, and `name: "Alice Smith"`
- **THEN** the claims are stored in the session record

#### Scenario: OpenID assertion with subset of attributes
- **WHEN** Ubuntu One returns an assertion containing nickname and fullname but omitting email
- **THEN** the system only extracts the available claims without failure
- **THEN** the available claims are preserved in the session

### Requirement: User identifier selection hierarchy
The system SHALL establish the session's primary user identity (`UserID`) based on a prioritized hierarchy:
1. `email` (if available in either OIDC token or OpenID assertion)
2. `nickname` / `preferred_username` (if email is unavailable)
3. `claimed_id` / `sub` (unique subject identifier fallback)

If none of these identifiers can be established, the system SHALL reject session creation with an error.

#### Scenario: User identified by email
- **WHEN** an identity response contains a valid email address
- **THEN** the session `UserID` is set to the email address

#### Scenario: Fallback to nickname when email absent
- **WHEN** an OpenID response contains a nickname but no email address
- **THEN** the session `UserID` is set to the nickname

#### Scenario: Fallback to claimed_id when nickname and email absent
- **WHEN** an OpenID response contains only the OpenID `claimed_id`
- **THEN** the session `UserID` is set to the `claimed_id`

### Requirement: Internal JWT claim propagation
When an API Gateway calls `ExchangeSession` over gRPC with a valid session cookie, the system SHALL mint an internal ES256 JWT containing all normalized claims stored within the session record.

#### Scenario: gRPC session exchange reflects normalized claims
- **WHEN** `ExchangeSession` is invoked for a session created via Ubuntu One OpenID
- **THEN** the minted internal JWT contains standard claims (`iss`, `sub`, `aud`, `iat`, `exp`) and custom claims reflecting the extracted OpenID attributes (`email`, `nickname`, `name`)
