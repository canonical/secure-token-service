# Spec Delta

## ADDED Requirements

### Requirement: Local JWKS publication endpoint
The system SHALL serve its public signing keys as a standards-compliant JWK Set document at `/.well-known/jwks.json` without requiring authentication. The document SHALL include every active and retired public signing key, each carrying `kty`, `kid`, `use`, and `alg` metadata, so verifiers can validate tokens signed with rotated keys.

#### Scenario: JWKS document published
- **WHEN** an unauthenticated client requests `/.well-known/jwks.json`
- **THEN** the system returns a JWK Set containing all active and retired public keys with `kty`, `kid`, `use`, and `alg` fields

#### Scenario: Cached JWKS served with store fallback
- **WHEN** the JWKS document has been cached and the cache is available
- **THEN** the system serves the cached document, and if the cache is unavailable or empty the system reads the keys from the database

### Requirement: Backward compatibility during library upgrade
The migration to the new token library major version SHALL NOT change any observable behavior: JWKS document format, token verification rules, refresh cadence, and error responses remain identical. No configuration, schema, or API migration is required.

#### Scenario: Existing verifiers keep working after upgrade
- **WHEN** the service is deployed with the upgraded library
- **THEN** previously issued tokens still verify against the published JWKS and the JWKS document format is unchanged

## MODIFIED Requirements

(none)

## REMOVED Requirements

(none)
