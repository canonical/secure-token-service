# gRPC API Documentation

The Secure Token Service provides a gRPC API for session-to-JWT exchange, used by API gateways (e.g., Envoy, Nginx) to implement the Phantom Token Pattern.

## Service Definition

**Proto file**: [`api/proto/v1/session.proto`](../../api/proto/v1/session.proto)

```protobuf
syntax = "proto3";

package session.v1;

service SessionService {
  // Exchange a session cookie for an internal JWT
  rpc ExchangeSession(ExchangeSessionRequest) returns (ExchangeSessionResponse);
}

message ExchangeSessionRequest {
  string session_cookie = 1;  // Encoded session cookie value
}

message ExchangeSessionResponse {
  string internal_jwt = 1;    // RS256-signed JWT
  string user_id = 2;          // User identifier from session
  int64 expires_at = 3;        // Unix timestamp when JWT expires
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
  "internal_jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImpudXMta2V5LWFiYzEyMyJ9...",
  "user_id": "user-uuid-1234",
  "expires_at": 1234567890
}
```

**Fields**:
- `internal_jwt` (string): RS256-signed JWT with user claims
- `user_id` (string): User identifier from the session
- `expires_at` (int64): Unix timestamp when JWT expires

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

### Example: grpcurl

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
session.v1.SessionService
```

**Describe service**:
```bash
grpcurl -plaintext localhost:9090 describe session.v1.SessionService
```

**Call ExchangeSession**:
```bash
grpcurl -plaintext \
  -d '{"session_cookie": "base64-encoded-session-id"}' \
  localhost:9090 \
  session.v1.SessionService/ExchangeSession
```

**Example Success Response**:
```json
{
  "internal_jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user_id": "01234567-89ab-cdef-0123-456789abcdef",
  "expires_at": "1234567890"
}
```

**Example Error Response**:
```
ERROR:
  Code: NotFound
  Message: session not found
```

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

**Note**: Janus does not yet implement Envoy's `CheckRequest` RPC. Use a translation layer or custom ext_authz service.

### Custom API Gateway (Go)

```go
import (
    pb "github.com/canonical/secure-token-service/api/proto/v1"
    "google.golang.org/grpc"
)

// Connect to Janus gRPC
conn, err := grpc.Dial("sts.example.com:9090", grpc.WithTransportCredentials(...))
client := pb.NewSessionServiceClient(conn)

// Extract session cookie from HTTP request
sessionCookie, err := r.Cookie("session_id")

// Exchange for JWT
resp, err := client.ExchangeSession(ctx, &pb.ExchangeSessionRequest{
    SessionCookie: sessionCookie.Value,
})

// Forward JWT to upstream service
upstreamReq.Header.Set("X-Internal-Authorization", "Bearer " + resp.InternalJwt)
```

## Performance Considerations

### Latency
- **Typical**: 5-15ms (session lookup from Valkey + JWT minting)
- **Cached session**: ~5ms
- **Cold cache**: ~15ms (includes database query)

### Caching Strategy
Gateways should cache JWT responses:
- **Key**: Session ID
- **TTL**: JWT expiry - current time (or 5 minutes, whichever is shorter)
- **Invalidation**: On 401 response from upstream

**Example (Envoy)**:
```yaml
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
  authorization_response:
    allowed_upstream_headers:
      patterns:
        - exact: X-Internal-Authorization
```

## Monitoring

### Metrics (Prometheus)
- `grpc_server_handled_total{grpc_method="ExchangeSession",grpc_code="OK"}` - Successful exchanges
- `grpc_server_handled_total{grpc_method="ExchangeSession",grpc_code="NotFound"}` - Session not found
- `grpc_server_handling_seconds` - RPC latency

### Alerts
- High error rate (>5% NotFound) → Session store issues or session expiry misconfiguration
- High latency (p99 > 50ms) → Valkey performance degradation

## Security Notes

1. **TLS**: Production deployments MUST use TLS for gRPC (mTLS recommended)
2. **Network isolation**: gRPC port (9090) should be internal-only, not exposed to public internet
3. **Rate limiting**: Implement rate limiting at gateway to prevent session enumeration
4. **Logging**: Log session exchange failures for security auditing

## References

- [gRPC Core Concepts](https://grpc.io/docs/what-is-grpc/core-concepts/)
- [grpcurl Documentation](https://github.com/fullstorydev/grpcurl)
- [Envoy External Authorization](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter)
