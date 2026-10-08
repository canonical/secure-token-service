# openid-provider-login Specification

## Purpose
Enables users and client applications to initiate authentication with either the standard OIDC provider or the Ubuntu One OpenID 2.0 provider via a dedicated query parameter on the `/auth/login` endpoint, and handles the subsequent callback and signature verification via a dedicated `/auth/openid/callback` endpoint.

For architectural diagrams and component details, see [Architecture Design: Ubuntu One OpenID & Standardized Cookie Generation](../../design.md#end-to-end-architecture).

## ADDED Requirements

### Requirement: Provider selection at login
The `/auth/login` endpoint SHALL accept an optional `provider` query parameter indicating which upstream identity provider to use for authentication. Supported values SHALL be `oidc` and `openid`. The provider query parameter matching SHALL be case-insensitive (`openid`, `OPENID`, `oidc`, `OIDC`). If omitted, the system SHALL default to `oidc` to maintain backward compatibility. If an unsupported provider is requested, the system SHALL respond with HTTP 400 Bad Request returning a JSON body containing `error` and `message` fields.

#### Scenario: Initiate login with default provider
- **WHEN** a client sends `GET /auth/login` with no provider parameter
- **THEN** the system sets an encrypted state cookie recording `provider: "oidc"`
- **THEN** the system redirects the client to the configured OIDC provider authorization URL with HTTP 302 and `redirect_uri` pointing to `/auth/callback`

#### Scenario: Initiate login with Ubuntu One OpenID provider
- **WHEN** a client sends `GET /auth/login?provider=openid`
- **THEN** the system sets an encrypted state cookie recording `provider: "openid"`
- **THEN** the system redirects the client to `https://login.ubuntu.com/+openid` with OpenID 2.0 parameters specifying `openid.return_to` as `/auth/openid/callback` and requesting Simple Registration (SREG 1.1) and Attribute Exchange (AX 1.0) attributes for email, nickname, and fullname

#### Scenario: Initiate login with case-insensitive provider parameter
- **WHEN** a client sends `GET /auth/login?provider=OPENID`
- **THEN** the system normalizes the provider to `openid`
- **THEN** the system sets an encrypted state cookie recording `provider: "openid"`
- **THEN** the system redirects the client to `https://login.ubuntu.com/+openid` with OpenID 2.0 parameters

#### Scenario: Request login with unsupported provider
- **WHEN** a client sends `GET /auth/login?provider=saml`
- **THEN** the system returns HTTP 400 Bad Request with a JSON body containing `error` and `message` fields explaining the unsupported provider

### Requirement: Dedicated Ubuntu One OpenID callback verification
The `/auth/openid/callback` endpoint SHALL be dedicated exclusively to verifying OpenID 2.0 authentication responses from Ubuntu One. The endpoint SHALL NOT handle OIDC callbacks. Verification SHALL be performed directly against Ubuntu One via an HTTP POST containing `openid.mode=check_authentication`. If verification succeeds, a user session SHALL be established and the user SHALL be redirected to the validated `return_to` destination. If verification fails, cancellation is received, or parameters are invalid, the system SHALL respond with HTTP 400 Bad Request formatted as a JSON body containing `error` and `message` fields.

#### Scenario: Successful Ubuntu One callback verification
- **WHEN** the browser returns to `/auth/openid/callback` with valid OpenID 2.0 response parameters and a valid state cookie indicating `provider: "openid"`
- **THEN** the system sends a direct `check_authentication` request to Ubuntu One
- **THEN** upon receiving `is_valid:true`, the system creates a user session with `UserID` matching the user's verified email and redirects to the safe `return_to` URL

#### Scenario: User cancellation or authentication failure at Ubuntu One
- **WHEN** Ubuntu One returns an OpenID cancellation (`openid.mode=cancel`) or invalid signature to `/auth/openid/callback`
- **THEN** the system rejects the authentication and returns HTTP 400 Bad Request with a JSON body containing `error` and `message` fields without creating a session

#### Scenario: Missing or mismatched state cookie on OpenID callback
- **WHEN** a request arrives at `/auth/openid/callback` without a valid encrypted state cookie
- **THEN** the system rejects the request with HTTP 400 Bad Request with a JSON body containing `error` and `message` fields

### Requirement: Response nonce timestamp validation and replay protection
The `/auth/openid/callback` endpoint SHALL validate the `openid.response_nonce` parameter to prevent replay attacks. The timestamp in `openid.response_nonce` SHALL be validated to be within 5 minutes of the server clock. The system SHALL reject responses with duplicate or previously seen nonces, responding with HTTP 400 Bad Request formatted as a JSON body containing `error` and `message` fields.

#### Scenario: Callback with valid response nonce
- **WHEN** `/auth/openid/callback` receives an assertion with an `openid.response_nonce` containing a timestamp within 5 minutes of the server clock and a nonce that has not been previously seen
- **THEN** nonce validation succeeds and callback verification proceeds

#### Scenario: Callback with expired response nonce timestamp
- **WHEN** `/auth/openid/callback` receives an assertion with an `openid.response_nonce` whose timestamp deviates by more than 5 minutes from the server clock
- **THEN** the system rejects the request with HTTP 400 Bad Request with a JSON body containing `error` and `message` fields

#### Scenario: Callback with duplicate response nonce
- **WHEN** `/auth/openid/callback` receives an assertion with an `openid.response_nonce` that has already been verified previously
- **THEN** the system rejects the replay attempt with HTTP 400 Bad Request with a JSON body containing `error` and `message` fields
