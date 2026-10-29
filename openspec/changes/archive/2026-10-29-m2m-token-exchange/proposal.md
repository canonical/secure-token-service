# Proposal: Machine-to-Machine (M2M) Token Exchange via gRPC

## Why
Currently, the Secure Token Service (STS) only supports human user authentication by exchanging opaque browser session cookies for internal ES256 JWTs via `ExchangeSession`. Automated services, background daemons, and CLI tools authenticate using OAuth2 Client Credentials issued by Ory Hydra. Microservices in our ecosystem must only accept and verify internal STS JWTs signed by STS's active ES256 key, ensuring uniform cryptography, auditability, and claim structure. STS requires a dedicated gRPC token exchange endpoint (`ExchangeToken`) to swap upstream Hydra access tokens for internal STS tokens without compromising the internal trust model.

## What Changes
- Add `rpc ExchangeToken(ExchangeTokenRequest) returns (ExchangeResponse)` to `api/proto/v1/sts.proto`.
- Introduce `ExchangeTokenRequest` message containing the raw upstream IdP access token.
- Implement `ExchangeToken` in the gRPC server (`internal/grpc/server.go`) to validate incoming bearer tokens, translate machine identity claims, and mint standard internal STS JWTs signed by the active ES256 key.
- Align internal token expiration with upstream token lifetime to prevent privilege extension beyond upstream token expiry.
- Instrument the new RPC with OpenTelemetry distributed tracing, Prometheus metrics, and structured Zap logging.

## Non-goals
- Managing OAuth2 client registrations or secrets (handled upstream by Ory Hydra).
- Issuing OAuth2 client credentials or hosting OAuth2 `/token` grant endpoints directly in STS.
- Handling authorization policy evaluation or bypassing OpenFGA checks for machine accounts (evaluated downstream in `authorization-service`).
- Long-lived session management or database session storage for machine tokens (machine token exchanges are stateless).

## Success Metrics
- 100% of valid Hydra client credentials tokens presented to `ExchangeToken` successfully translate into valid internal STS JWTs signed by the active ES256 key.
- 0% authorization bypass: machine tokens output predictable subject claims (`sub`) that downstream authorization engines evaluate against standard relation tuples.
- Exchange latency overhead for machine tokens remains under 5ms (p99) at peak load.
- Seamless compatibility: Downstream microservices verify machine requests using identical JWKS verification logic as user session requests.

## Capabilities

### New Capabilities
- `m2m-token-exchange`: Enables downstream API gateways and proxies to swap upstream IdP access tokens (originating from OAuth2 Client Credentials flows) for standard internal STS JWTs signed by STS.

### Modified Capabilities
None. Existing session-based authentication (`ExchangeSession`) and session revocation (`RevokeUserSessions`) remain completely unchanged.

## Impact
- **APIs**: Extends `SecurityTokenService` gRPC service with one new RPC (`ExchangeToken`). Backward-compatible addition to Protobuf v1.
- **Dependencies**: No external network dependencies introduced for stateless claim translation; utilizes existing `KeyManager` and cryptographic signing pipeline.
- **Downstream Services**: `authorization-service` and Envoy/Istio custom auth policies can authenticate machine clients via client credentials bearer tokens.
