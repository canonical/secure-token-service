# ADR-001: Cookie Library Choice

**Status**: Accepted  
**Date**: 2026-02-11  
**Deciders**: Development Team  
**

Context**: Janus handles security-critical session cookies containing user authentication state. The library chosen must provide authenticated encryption to prevent tampering and information leakage.

## Decision

We chose **`github.com/chmike/securecookie`** over **`github.com/gorilla/securecookie`**.

## Rationale

### Performance
- **2-3x faster** encoding/decoding compared to Gorilla based on benchmarks
- Lower memory allocations per operation
- Important for high-throughput session operations

### Security
- Uses **ChaCha20-Poly1305** AEAD cipher (modern, fast authenticated encryption)
- Gorilla uses HMAC-SHA256 + AES-CTB (older, more complex approach)
- ChaCha20 better suited for software-only environments (no AES-NI dependency)

### API Simplicity
- Cleaner, more straightforward API
- Fewer configuration options = less room for misconfiguration
- Better error handling with explicit error returns

### Maintenance
- Actively maintained
- Smaller codebase (easier to audit)
- No external dependencies beyond Go stdlib + crypto

## Alternatives Considered

### gorilla/securecookie
- ✅ Well-established, widely used
- ❌ Slower performance
- ❌ More complex API
- ❌ Older cryptographic primitives

### Custom implementation
- ✅ Full control
- ❌ High security risk (easy to get crypto wrong)
- ❌ Maintenance burden
- ❌ No proven track record

## Consequences

### Positive
- Faster cookie operations improve request latency
- Modern cryptography provides better security guarantees
- Simpler codebase reduces complexity

### Negative
- Less widely adopted than Gorilla (smaller community)
- Team unfamiliarity (mitigated by simpler API)

### Neutral
- Migration from Gorilla requires cookie re-generation (acceptable: sessions expire anyway)

## Implementation Notes

```go
// Cookie manager using chmike/securecookie
type CookieManager struct {
    key          []byte
    sessionCk    *securecookie.Obj
    oauthStateCk *securecookie.Obj
    oauthNonceCk *securecookie.Obj
}
```

Configuration via environment variables:
- `COOKIE_KEY` - 32-byte key for ChaCha20-Poly1305 AEAD (authenticated encryption with associated data)

## References

- [chmike/securecookie GitHub](https://github.com/chmike/securecookie)
- [gorilla/securecookie GitHub](https://github.com/gorilla/securecookie)
- [ChaCha20-Poly1305 RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)
- Performance benchmarks: `internal/cookie/cookie_test.go`
