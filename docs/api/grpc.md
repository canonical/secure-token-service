# gRPC API Documentation

The Secure Token Service provides a gRPC API for session-to-JWT and M2M token exchanges, used by API gateways (e.g., Envoy, Istio) to implement authorization and the Phantom Token Pattern.

## Service Definition

**Proto file**: [`api/proto/v1/sts.proto`](../../api/proto/v1/sts.proto)

```protobuf
syntax = "proto3";

package sts.v1;

import "google/protobuf/timestamp.proto";

option go_package = "github.com/canonical/secure-token-service/api/proto/v1;stsv1";

// SecurityTokenService defines the interface for the Secure Token Service.
service SecurityTokenService {
  // ExchangeSession swaps an opaque session_id for a customized internal JWT.
  rpc ExchangeSession(ExchangeRequest) returns (ExchangeResponse);

  // ExchangeToken swaps an upstream IdP access token (e.g., Hydra client credentials)
  // for an internal STS JWT adhering to the ecosystem contract.
  rpc ExchangeToken(ExchangeTokenRequest) returns (ExchangeResponse);

  // RevokeUserSessions forces a logout for a specific user, invalidating all sessions.
  rpc RevokeUserSessions(RevokeUserRequest) returns (RevokeUserResponse);
}

message ExchangeRequest {
  string session_cookie = 1;
}

message ExchangeTokenRequest {
  string token = 1; // Raw upstream IdP access token (JWT)
}

message ExchangeResponse {
  string access_token = 1; // Signed Internal JWT
  int64 expires_in = 2;    // Seconds until expiration
}

message RevokeUserRequest {
  string user_id = 1;
}

message RevokeUserResponse {
  bool success = 1;
}
```

## ExchangeSession RPC

### Purpose
Exchanges an opaque session cookie for a signed internal JWT containing user identity and claims.

### Request
```json
{
  "session_cookie": "base64-encoded-session-id"
}
```

**Fields**:
- `session_cookie` (string, required): The value of the `session_id` cookie, base64-encoded

### Response (Success)
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InN0cy1rZXktYWJjMTIzIn0...",
  "expires_in": 3600
}
```

**Fields**:
- `access_token` (string): ES256-signed internal JWT with user claims
- `expires_in` (int64): Seconds until JWT expiration

**JWT Claims Example**:
```json
{
  "sub": "user-uuid-1234",
  "iss": "https://sts.example.com",
  "aud": "internal-services",
  "exp": 1234567890,
  "iat": 1234567800,
  "jti": "jwt-uuid-5678",
  "session_id": "session-uuid-abcd",
  "email": "user@example.com"
}
```

### Error Responses

| gRPC Status | Condition | Description |
|-------------|-----------|-------------|
| `INVALID_ARGUMENT` | Missing or empty `session_cookie` | Request validation failed |
| `UNAUTHENTICATED` | Invalid cookie format | Cookie decoding failed |
| `NOT_FOUND` | Session not found | Session doesn't exist or expired |
| `INTERNAL` | JWT minting failed | Internal error creating JWT |

---

## ExchangeToken RPC

### Purpose
Exchanges an upstream IdP access token (issued via OAuth2 client credentials grant, e.g. Ory Hydra) for an internal STS JWT adhering to the internal microservices ecosystem contract.

### Flow
1. API gateway or proxy extracts client credentials access token (`Bearer <token>`).
2. Calls `ExchangeToken` RPC with the raw upstream token string.
3. STS validates token signature against pre-cached upstream IdP JWKS (e.g. Hydra JWKS).
4. STS validates token expiration and rejects tokens with less than 60 seconds of validity remaining (`Unauthenticated`).
5. STS extracts machine client identity (`client_id` or `sub`).
6. STS mints an internal ES256 JWT:
   - `sub`: `<client_id>`
   - `email`: `<client_id>@serviceaccount.local` (synthetic email)
   - `exp`: Clamped to `min(configured_sts_expiry, upstream_remaining_validity)`
7. STS returns internal JWT and remaining TTL (`expires_in` seconds).

### Request
```json
{
  "token": "eyJhbGciOiJSUzI1NiIs..."
}
```

**Fields**:
- `token` (string, required): Upstream IdP access token (JWT)

### Response (Success)
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InN0cy1rZXktYWJjMTIzIn0...",
  "expires_in": 600
}
```

**Fields**:
- `access_token` (string): ES256-signed internal STS JWT
- `expires_in` (int64): Seconds until internal JWT expires (clamped to upstream TTL)

**Minted JWT Claims Example**:
```json
{
  "sub": "service-client-123",
  "iss": "https://sts.example.com",
  "aud": "internal-services",
  "exp": 1728410000,
  "iat": 1728409400,
  "jti": "jwt-uuid-9876",
  "email": "service-client-123@serviceaccount.local"
}
```

### Error Responses

| gRPC Status | Condition | Description |
|-------------|-----------|-------------|
| `INVALID_ARGUMENT` | Empty/whitespace token, token exceeding 64 KB, invalid/oversized subject claim (>256 chars or control characters), nil request, or token missing `sub`/`client_id` claim | Request validation failed |
| `UNAUTHENTICATED` | Token expired, remaining validity < 60s, invalid signature, or untrusted issuer | Token validation failed |
| `UNAVAILABLE` | Upstream IdP JWKS endpoint unreachable or key set empty | Upstream service error |
| `UNIMPLEMENTED` | Token verifier not configured on STS server | Service configuration error |
| `INTERNAL` | Internal ES256 key manager failure | Server internal error |

---

## Example: grpcurl

**Install grpcurl**:
```bash
# macOS
brew install grpcurl

# Linux
curl -sSL "https://github.com/fullstorydev/grpcurl/releases/download/v1.8.9/grpcurl_1.8.9_linux_x86_64.tar.gz" | tar -xz -C /usr/local/bin
```

**Enable gRPC reflection**:
```bash
# In secure-token-service configuration
GRPC_REFLECTION_ENABLED=true
```

**List services**:
```bash
grpcurl -plaintext localhost:9090 list
```

Output:
```
grpc.reflection.v1.ServerReflection
grpc.reflection.v1alpha.ServerReflection
sts.v1.SecurityTokenService
```

**Describe service**:
```bash
grpcurl -plaintext localhost:9090 describe sts.v1.SecurityTokenService
```

**Call ExchangeSession**:
```bash
grpcurl -plaintext \
  -d '{"session_cookie": "base64-encoded-session-id"}' \
  localhost:9090 \
  sts.v1.SecurityTokenService/ExchangeSession
```

**Call ExchangeToken (M2M)**:
```bash
grpcurl -plaintext \
  -d '{"token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}' \
  localhost:9090 \
  sts.v1.SecurityTokenService/ExchangeToken
```

**Example Success Response**:
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": "600"
}
```

**Example Error Response**:
```
ERROR:
  Code: Unauthenticated
  Message: token has less than 60s remaining validity
```

---

## Integration Examples

### Envoy External Auth Filter

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      grpc_service:
        envoy_grpc:
          cluster_name: sts_cluster
        timeout: 0.5s
      transport_api_version: V3
```

**Note**: STS implements its native `SecurityTokenService` gRPC definition. Use an authorization gateway or custom ext_authz translation service to invoke `ExchangeSession` or `ExchangeToken`.

### Custom API Gateway (Go)

```go
import (
    stsv1 "github.com/canonical/secure-token-service/api/proto/v1"
    "google.golang.org/grpc"
)

// Connect to STS gRPC
conn, err := grpc.Dial("sts.example.com:9090", grpc.WithTransportCredentials(...))
client := stsv1.NewSecurityTokenServiceClient(conn)

// 1. M2M Token Exchange:
bearerToken := extractBearerToken(r.Header.Get("Authorization"))
resp, err := client.ExchangeToken(ctx, &stsv1.ExchangeTokenRequest{
    Token: bearerToken,
})
if err != nil {
    // Handle unauthenticated / invalid token
}
upstreamReq.Header.Set("Authorization", "Bearer " + resp.AccessToken)

// 2. Cookie Session Exchange:
sessionCookie, err := r.Cookie("session_id")
resp, err := client.ExchangeSession(ctx, &stsv1.ExchangeRequest{
    SessionCookie: sessionCookie.Value,
})
if err != nil {
    // Handle invalid session
}
upstreamReq.Header.Set("Authorization", "Bearer " + resp.AccessToken)
```

## Performance & Caching

### Latency
- **Session Exchange**: 5-15ms (session lookup from Valkey + JWT minting)
- **Token Exchange**: <1ms (in-memory preemptive JWKS verification + JWT minting)

### Upstream JWKS Caching
Upstream IdP public keys are fetched at STS startup and kept refreshed periodically in a background goroutine using a sliding cache window, ensuring zero latency penalty for public key retrieval on incoming RPC requests.

## Observability & Metrics

### Prometheus / OpenTelemetry Metrics
- `grpc_server_handled_total{grpc_method="ExchangeSession",grpc_code="OK"}` - Successful session exchanges
- `grpc_server_handled_total{grpc_method="ExchangeToken",grpc_code="OK"}` - Successful M2M token exchanges
- `sts_tokens_minted_total` - Total count of internal JWTs minted
- `sts_m2m_token_clamped_ttl_seconds` (`sts.m2m.token.clamped_ttl`) - Histogram measuring clamped TTL values assigned to M2M tokens

## Security Notes

1. **TLS**: Production deployments MUST use TLS for gRPC (mTLS recommended)
2. **Network isolation**: gRPC port (9090) should be internal-only, not exposed to public internet
3. **Minimum Expiration Clamping**: Upstream tokens with remaining validity under 60 seconds are rejected outright to prevent issuing tokens that expire mid-flight
4. **Synthetic Identity**: Client credentials tokens are assigned a synthetic email `<client_id>@serviceaccount.local` for compatibility with internal services requiring an email claim
5. **Maximum Token Size**: Tokens exceeding 64 KB are rejected with `INVALID_ARGUMENT` to prevent memory exhaustion and DoS attacks
6. **Machine Claim Validation**: Upstream `sub` and `client_id` claims must be non-empty strings, at most 256 characters, and free of control characters or newlines
7. **Clock Skew Tolerance**: Upstream JWT verification tolerates up to 5 seconds of clock skew leeway

## References

- [gRPC Core Concepts](https://grpc.io/docs/what-is-grpc/core-concepts/)
- [grpcurl Documentation](https://github.com/fullstorydev/grpcurl)
- [Envoy External Authorization](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter)
