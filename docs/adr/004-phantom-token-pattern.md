# ADR-004: Phantom Token Pattern

**Status**: Accepted  
**Date**: 2026-01-27  
**Deciders**: Development Team, Security Team  

##Context

Microservices architectures face a security challenge: how to securely pass user identity between services without exposing sensitive tokens or requiring every service to validate against external identity providers.

## Decision

We implement the **Phantom Token Pattern** where:
1. External clients receive **opaque session cookies**
2. API Gateway exchanges cookies for **internal JWTs** via gRPC
3. Internal services validate JWTs using **local JWKS**

## Rationale

### Security - Defense in Depth

**External Layer (Browser ↔ Gateway)**:
- Opaque session IDs in HttpOnly cookies
- No JWT visible to end users or browser
- Cookie theft gives attacker only a session ID (revocable)
- No information leakage from JWT claims

**Internal Layer (Gateway ↔ Services)**:
- Short-lived JWTs (configurable expiry)
- Signed with ES256 (ECDSA with P-256 curve)
- Services verify locally (no network call to Janus)
- Each request gets fresh JWT with current session state

### Performance

**Reduced Latency**:
- Services verify JWTs locally (crypto operation only)
- No network hop to session store for every request
- JWKS cached locally by services (CDN pattern)

**Scalability**:
- Stateless verification at service layer
- Session store (Valkey) accessed only by Gateway + Janus
- Services don't need direct access to external IdP

### Revocation

**Immediate Session Termination**:
```
POST /auth/logout
→ Delete session from Valkey
→ Next gateway request fails (session not found)
→ No new JWTs issued
```

**Existing JWTs**:
- Still valid until expiry (design trade-off)
- Expiry kept short (recommended: 5-15 minutes)
- For critical operations, services can call-back to Janus for session validation

### Separation of Concerns

```
┌─────────────────────────────────────────────────┐
│ Browser: Only sees opaque cookie                │
│ • No JWT parsing logic needed                   │
│ • HttpOnly, Secure, SameSite protection        │
└─────────────────────────────────────────────────┘
                      │
                      ↓
┌─────────────────────────────────────────────────┐
│ API Gateway (e.g., Envoy, Nginx)                │
│ • Exchange: cookie → JWT (gRPC to Janus)       │
│ • Forward: JWT in X-Internal-Authorization      │
│ • No session storage dependency                 │
└─────────────────────────────────────────────────┘
                      │
                      ↓
┌─────────────────────────────────────────────────┐
│ Internal Services                                │
│ • Verify JWT signature (local JWKS)            │
│ • Extract claims (user_id, roles, etc.)        │
│ • Optionally check expiry, audience, etc.      │
└─────────────────────────────────────────────────┘
```

## Alternatives Considered

### Shared Session Store
- ✅ Simple centralized state
- ❌ Every service needs session store access (coupling)
- ❌ Network latency on every request
- ❌ Session store becomes single point of failure

### Pass-through JWT
- ✅ Stateless end-to-end
- ❌ JWT visible to browser (information leakage)
- ❌ Cannot revoke (must wait for expiry)
- ❌ XSS can steal JWT

### OAuth2 Bearer Tokens
- ✅ Industry standard
- ❌ Requires services to validate with IdP (latency, coupling)
- ❌ Browser manages tokens (XSS risk)
- ❌ Revocation requires token introspection endpoint

### mTLS with Client Certificates
- ✅ Strong authentication
- ❌ Certificate management complexity
- ❌ Difficult for browser-based clients
- ❌ Doesn't carry user identity in standard format

## Consequences

### Positive
- Strong security boundaries (opaque external, verifiable internal)
- High performance (local JWT verification)
- Revocable sessions (delete from Valkey)
- Services are decoupled from session storage
- Works with any browser (standard cookies)

### Negative
- Gateway becomes critical path (mitigated: highly available)
- JWTs valid until expiry even if session revoked (mitigated: short TTL)
- Slightly more complex than pure stateless JWT

### Trade-offs
- **Revocation granularity**: Session-level only (acceptable for most use cases)
- **Gateway dependency**: Acceptable for centralized auth enforcement
- **JWT expiry window**: Must balance latency vs revocation responsiveness

## Implementation Notes

### gRPC Contract
```protobuf
service SessionService {
  rpc ExchangeSession(ExchangeSessionRequest) returns (ExchangeSessionResponse);
}

message ExchangeSessionRequest {
  string session_cookie = 1;
}

message ExchangeSessionResponse {
  string internal_jwt = 1;
  string user_id = 2;
  int64 expires_at = 3;
}
```

### JWT Claims
```json
{
  "sub": "user-uuid",
  "iss": "https://sts.example.com",
  "aud": "internal-services",
  "exp": 1234567890,
  "iat": 1234567800,
  "jti": "jwt-uuid",
  "session_id": "session-uuid",
  "email": "user@example.com"
}
```

### Recommended JWT Expiry
- **Production**: 5-15 minutes
- **Development**: 1 hour (easier debugging)
- **High-security**: 1-5 minutes + refresh on each request

## Security Considerations

### XSS Protection
- Cookies: `HttpOnly, Secure, SameSite=Lax`
- JWTs: Never stored in browser (server-to-server only)

### CSRF Protection
- State parameter in OIDC flow
- `SameSite=Lax` on cookies

### Session Fixation
- Generate new session ID on login
- Invalidate old session on logout

## References

- [OAuth 2.0 Phantom Token Pattern](https://curity.io/resources/learn/phantom-token-pattern/)
- [IETF Draft: OAuth Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
