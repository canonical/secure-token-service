# Session Service (Janus)

A Security Token Service implementing the Phantom Token Pattern for secure session management.

## Overview

Janus acts as a Policy Enforcement Point (PEP) that:
- Exchanges insecure tokens for secure, opaque HttpOnly cookies
- Mints internal JWTs signed with RS256
- Maintains session state in Redis/Valkey
- Provides gRPC interface for microservices
- Exposes JWKS endpoint for JWT verification

## Architecture

```
┌─────────────┐         ┌──────────────┐         ┌────────────────┐
│   Browser   │────────▶│    Janus     │────────▶│  Microservices │
│  (External) │         │  (PEP/STS)   │         │  (Trust Zone)  │
└─────────────┘         └──────────────┘         └────────────────┘
     │                         │
     │ HttpOnly Cookie         │ Internal JWT
     │ (Opaque Session)        │ (Signed RS256)
     │                         │
     └─────────────────────────┘
```

## Components

### Key Manager (`internal/auth/token.go`)
- Generates/loads RSA key pairs
- Mints internal JWTs signed with RS256
- Provides public key for JWKS endpoint

### Session Store (`internal/session/store.go`)
- Redis/Valkey-based session storage
- Maps opaque session IDs to upstream tokens
- Tracks user sessions for revocation

### gRPC Server (`internal/grpc/server.go`)
- **ExchangeSession**: Swaps session ID for internal JWT
- **RevokeUserSessions**: Invalidates all user sessions

### HTTP Server (`internal/http/server.go`)
- OIDC flow endpoints (stubs): `/auth/login`, `/auth/callback`, `/auth/logout`
- JWKS endpoint: `/.well-known/jwks.json`

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://localhost:5432/janus?sslmode=disable` | PostgreSQL connection |
| `CACHE_ADDR` | `localhost:6379` | Cache (Redis/Valkey) address |
| `CACHE_PASSWORD` | `""` | Cache password |
| `CACHE_DB` | `0` | Cache database |
| `HTTP_PORT` | `8080` | HTTP server port |
| `GRPC_PORT` | `9090` | gRPC server port |
| `PRIVATE_KEY_PATH` | `./keys/private.pem` | RSA private key path |
| `PUBLIC_KEY_PATH` | `./keys/public.pem` | RSA public key path |
| `JWT_ISSUER` | `session-service` | JWT issuer claim |
| `JWT_AUDIENCE` | `internal-services` | JWT audience claim |
| `JWT_EXPIRY` | `3600` | JWT expiry (seconds) |

## Building

```bash
go build -o bin/janus ./cmd/janus
```

## Running

```bash
# Start Redis (required)
docker run -p 6379:6379 redis:latest

# Run Janus
./bin/janus
```

## Testing

```bash
# Run all tests
go test ./... -v

# Run specific package tests
go test ./internal/auth -v
go test ./internal/session -v
```

## API Reference

### gRPC Service

**Service**: `sts.v1.SecurityTokenService`

#### ExchangeSession

Exchanges an opaque session ID for an internal JWT.

**Request**:
```protobuf
message ExchangeRequest {
  string session_id = 1;
}
```

**Response**:
```protobuf
message ExchangeResponse {
  string access_token = 1; // Signed Internal JWT
  int64 expires_in = 2;    // Seconds until expiration
}
```

#### RevokeUserSessions

Revokes all sessions for a user.

**Request**:
```protobuf
message RevokeUserRequest {
  string user_id = 1;
}
```

**Response**:
```protobuf
message RevokeUserResponse {
  bool success = 1;
}
```

### HTTP Endpoints

#### GET /.well-known/jwks.json

Returns the JSON Web Key Set for JWT verification.

**Response**:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "janus-key-1",
      "n": "<base64url>",
      "e": "<base64url>"
    }
  ]
}
```

## Security Considerations

1. **gRPC Authentication**: Implement interceptor to validate caller identity
2. **Network Policies**: Restrict gRPC access to authorized services only
3. **Token Encryption**: Upstream tokens stored encrypted in Redis
4. **HttpOnly Cookies**: Prevent XSS access to session tokens
5. **Key Rotation**: Implement periodic RSA key rotation (TODO)

## TODO

- [ ] Implement OIDC login flow (`/auth/login`, `/auth/callback`)
- [ ] Add token refresh/rotation logic
- [ ] Implement gRPC authentication interceptor
- [ ] Add PostgreSQL persistence layer
- [ ] Add metrics and monitoring
- [ ] Implement key rotation
- [ ] Add rate limiting
- [ ] Integration tests with full stack

## License

Copyright Canonical Ltd.