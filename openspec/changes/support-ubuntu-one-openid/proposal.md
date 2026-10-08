# Proposal: Support Ubuntu One OpenID and Standardized Cookie Generation

## Why

Currently, the Secure Token Service (Janus) only supports OpenID Connect (OIDC) through a single upstream identity provider. Canonical services and environments frequently require authentication via Canonical's Ubuntu One SSO (`login.ubuntu.com/+openid`), which operates using the OpenID 2.0 protocol. Furthermore, cookie creation logic is currently fragmented between `CookieManager` and inline HTTP response handling in `server.go`, leading to inconsistent security flags (such as hardcoded `Secure: true` and missing `SameSite` settings).

Introducing Ubuntu One OpenID provider support via dedicated login and callback endpoints, standardizing cookie generation, and normalizing token claims allows seamless identity federation across both OIDC and OpenID 2.0 while maintaining identical external cookie and internal JWT contracts for downstream microservices.

## What Changes

- **Provider Switching in `/auth/login`**: Add support for a `provider` query parameter (e.g. `GET /auth/login?provider=openid` vs `?provider=oidc`), defaulting to `oidc` for backwards compatibility.
- **Dedicated OpenID Callback Endpoint (`/auth/openid/callback`)**: Introduce an isolated callback endpoint for Ubuntu One OpenID 2.0 verification. This cleanly isolates OpenID handling from the existing OIDC callback (`/auth/callback`), ensuring trivial deprecation and removal in the future when OpenID is sunset.
- **Ubuntu One OpenID 2.0 Integration**: Implement an OpenID 2.0 relying party client specifically for Ubuntu One (`https://login.ubuntu.com/+openid`), requesting basic identity attributes (email, nickname, fullname) via Simple Registration (SREG 1.1) and Attribute Exchange (AX 1.0) and verifying signatures directly via `check_authentication`.
- **Downstream Token & Cookie Parity**: Downstream microservices and external clients receive identical cookies and internal JWT contracts regardless of whether authentication was completed through OIDC or OpenID. The internal JWT `sub` and `email` claims are populated with the user's email address.
- **Standardized Cookie Generation**: Centralize all cookie construction, formatting, and clearing in `CookieManager`, guaranteeing consistent attributes (`HttpOnly: true`, `SameSite: Lax`, dynamic `Secure` based on TLS/proxy detection, standard `Path: "/"`).

## Non-goals

- Implementing Launchpad team checks or access gating; authentication is plain and binary (authenticated vs unauthenticated).
- Supporting stateful Diffie-Hellman association caching for OpenID 2.0; stateless direct verification (`check_authentication`) is used for simplicity and cloud scalability.
- Modifying downstream gRPC `ExchangeSession` contracts or JWT formats; internal JWTs remain identical between providers.
- Supporting multi-domain cookie scopes (`COOKIE_DOMAIN`) at this stage.

## Success Metrics

- Users can log in via Ubuntu One by visiting `/auth/login?provider=openid` and successfully authenticate via `/auth/openid/callback` before redirecting to `return_to`.
- Downstream microservices exchanging the session cookie over gRPC receive the exact same JWT claims structure (`sub: email`, `email: email`) regardless of whether OIDC or Ubuntu One was used.
- 100% of cookies (`session_id`, `oauth_state`, `oauth_nonce`) set by the service adhere to standardized security attributes (`HttpOnly`, `SameSite=Lax`, dynamic `Secure` flag).
- When Ubuntu One support is eventually retired, deleting `/auth/openid/callback` leaves the primary OIDC flow untouched.

## Capabilities

### New Capabilities
- `openid-provider-login`: Multi-provider login flow with dedicated `/auth/openid/callback` handling and direct OpenID 2.0 verification against Ubuntu One.
- `standardized-cookies`: Unified cookie management for session, state, and nonce cookies with uniform security attributes.
- `claims-normalization`: Uniform claims extraction and fallback mechanisms that populate session state and internal JWTs with provider parity.

### Modified Capabilities
<!-- No existing capabilities in openspec/specs/ are modified -->

## Impact

- **HTTP API (`internal/http`)**: `/auth/login` accepts `provider` parameter; new endpoint `GET /auth/openid/callback` registered; `/auth/callback` remains dedicated to OIDC.
- **Cookie Layer (`internal/cookie`, `internal/http/interfaces.go`)**: `CookieManager` becomes the single authority for creating and clearing session and auth cookies.
- **Session Layer (`internal/session`)**: `Session` struct extended to store provider type and extracted claim dictionary.
- **Token Minting (`internal/grpc`)**: `ExchangeSession` continues to mint internal ES256 JWTs adhering to the existing `sub: email`, `email: email` contract.
- **Configuration (`internal/config`)**: New environment variables for Ubuntu One OpenID URL and realm.
- **Documentation**: OpenAPI spec (`docs/api/openapi.yaml`) updated to reflect the new login query parameter, `/auth/openid/callback` endpoint, and cookie attributes.
