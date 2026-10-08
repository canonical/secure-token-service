# Spec Delta

## Purpose
Enables automated services and machine clients authenticated via Ory Hydra OAuth2 Client Credentials to exchange upstream bearer access tokens for standard internal STS JWTs signed by STS's active ES256 key, ensuring uniform cryptography, auditability, and zero-trust identity propagation across the internal ecosystem.

For visual architecture modeling, see [Archify Architecture Design (Dark Theme)](../../../../.archify/architecture-secure-token-service-20261008-154500/secure-token-service.html) and capture [Visual Check Dark PNG](../../../../.archify/architecture-secure-token-service-20261008-154500/visual-check/secure-token-service.visual-check.1440x900.dark.png).

## ADDED Requirements

### Requirement: gRPC Token Exchange Endpoint
The SecurityTokenService gRPC API SHALL expose an `ExchangeToken` RPC accepting an `ExchangeTokenRequest` containing an upstream access token string and returning an `ExchangeResponse` containing a signed internal JWT and its remaining validity duration in seconds.

#### Scenario: Valid upstream token presented
- **WHEN** an authenticated proxy or gateway calls `ExchangeToken` with a valid upstream IdP access token
- **THEN** STS returns an `ExchangeResponse` with a signed internal ES256 JWT in `access_token` and the token validity duration in `expires_in`
- **THEN** the gRPC status code is `OK` (0)

### Requirement: Input Token Validation and Verification
The system SHALL validate the incoming token string in `ExchangeTokenRequest` and cryptographically verify its signature against the configured upstream IdP (Ory Hydra) JWKS. The system SHALL reject incoming tokens exceeding 65,536 bytes (64 KB) prior to cryptographic parsing to mitigate Denial of Service (DoS) attacks. If the token is empty, oversized, malformed, or fails cryptographic verification, the RPC SHALL reject the request immediately.

#### Scenario: Empty token rejected
- **WHEN** `ExchangeToken` is invoked with an empty or whitespace-only token string
- **THEN** STS rejects the call with gRPC status `InvalidArgument` (3) and a descriptive error message

#### Scenario: Oversized token rejected
- **WHEN** `ExchangeToken` is invoked with a token string exceeding 65,536 bytes (64 KB)
- **THEN** STS rejects the call with gRPC status `InvalidArgument` (3) and a message indicating the token exceeds the maximum permitted size

#### Scenario: Malformed token rejected
- **WHEN** `ExchangeToken` is invoked with an invalid or corrupted JWT string
- **THEN** STS rejects the call with gRPC status `Unauthenticated` (16)

#### Scenario: Cryptographic signature mismatch rejected
- **WHEN** `ExchangeToken` is invoked with a token signed by an untrusted key or with an invalid signature
- **THEN** STS rejects the call with gRPC status `Unauthenticated` (16)

### Requirement: Preemptive Upstream JWKS Synchronization
The system SHALL maintain an in-memory cache of upstream IdP public keys refreshed preemptively on a background schedule, rather than waiting for key lookup misses or signature failures.

#### Scenario: Preemptive cache hit
- **WHEN** an incoming token is received with a valid `kid` published in the upstream JWKS
- **THEN** STS verifies the token signature against the preemptively cached key set without making a blocking HTTP roundtrip

### Requirement: Token Expiration Threshold and Clamping
The system SHALL reject any upstream token with less than 60 seconds of remaining lifetime. For valid tokens meeting this threshold, STS SHALL calculate the minted token expiration as `min(configured_sts_expiry, remaining_seconds)` so the internal token never outlives the upstream credential. When evaluating `exp` and `iat`, STS SHALL account for a 5-second clock skew tolerance to prevent premature token rejections caused by minor time synchronization variance between IdP and STS.

#### Scenario: Upstream token expiring in less than 60 seconds rejected
- **WHEN** an upstream token is presented whose expiration time (`exp`) is less than 60 seconds from the current time (accounting for clock skew tolerance)
- **THEN** STS rejects the call with gRPC status `Unauthenticated` (16) and message indicating near-expiry

#### Scenario: Upstream token lifetime exceeds default STS TTL
- **WHEN** an upstream token has 3600 seconds of remaining lifetime and STS configured TTL is 300 seconds
- **THEN** the minted internal JWT is issued with an expiration duration of 300 seconds
- **THEN** `expires_in` in the response is 300

#### Scenario: Upstream token lifetime is shorter than default STS TTL
- **WHEN** an upstream token has 180 seconds of remaining lifetime and STS configured TTL is 300 seconds
- **THEN** the minted internal JWT is issued with an expiration duration of 180 seconds
- **THEN** `expires_in` in the response is 180

### Requirement: Machine Subject and Claims Translation
The system SHALL translate machine claims from the upstream token into the standard internal STS token schema. The subject (`sub`) SHALL be set to the machine client identifier (`client_id` or `sub`). The system SHALL validate extracted client identity (`client_id` or `sub`): it must be non-empty, must not exceed 256 characters, and must contain only printable non-control characters (no ASCII control characters or newlines). If validation fails, STS SHALL reject the call with gRPC status `InvalidArgument` (3). The `email` claim SHALL be populated with a synthetic email formatted as `<client_id>@serviceaccount.local` for downstream service compatibility.

#### Scenario: Machine client identity mapped to sub and synthetic email
- **WHEN** a valid upstream token with client identifier `backup-worker-daemon` is exchanged
- **THEN** the minted internal STS JWT has `sub` set to `backup-worker-daemon`
- **THEN** the minted internal STS JWT has `email` set to `backup-worker-daemon@serviceaccount.local`
- **THEN** the minted internal STS JWT contains the configured STS issuer (`iss`) and audience (`aud`)

#### Scenario: Invalid machine subject rejected
- **WHEN** an upstream token contains a `client_id` or `sub` exceeding 256 characters or containing ASCII control characters/newlines
- **THEN** STS rejects the call with gRPC status `InvalidArgument` (3)

### Requirement: Backward Compatibility Preservation
The introduction of `ExchangeToken` SHALL NOT alter or degrade existing session exchange (`ExchangeSession`) or user session revocation (`RevokeUserSessions`) endpoints. Existing clients using session cookies SHALL experience no behavioral changes.

#### Scenario: Existing ExchangeSession requests execute normally
- **WHEN** a client calls `ExchangeSession` with a valid session cookie
- **THEN** STS exchanges the session cookie and returns an internal JWT with human user claims as before
