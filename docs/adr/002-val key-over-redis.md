# ADR-002: Cache Choice - Valkey over Redis

**Status**: Accepted  
**Date**: 2026-01-28  
**Deciders**: Development Team  

## Context

Janus requires a fast, in-memory key-value store for session storage and JWKS caching. Redis has been the traditional choice, but Valkey emerged as an open-source fork.

## Decision

We chose **Valkey** as our caching layer instead of Redis.

## Rationale

### Open Source Governance
- **Valkey**: Linux Foundation project, truly open-source (BSD-3-Clause)
- **Redis**: Moved to dual-licensing (SSPL/RSALv2), restrictive for cloud providers
- Long-term sustainability and community governance matter for infrastructure

### API Compatibility
- Valkey is a **drop-in replacement** for Redis
- Uses Redis protocol (RESP)
- Existing Redis clients work without modification
- Easy migration path if needed

### Performance
- **Equivalent** to Redis 7.x (same codebase origin)
- No performance degradation
- Same data structures and commands

### Library Support
- Official Go client: `github.com/valkey-io/valkey-go`
- Compatibility adapter: `valkeycompat` for Redis client migration
- Growing ecosystem with active development

### Future-Proofing
- Active development and community contributions
- No vendor lock-in or licensing concerns
- Cloud provider support increasing

## Alternatives Considered

### Redis
- ✅ Mature, well-established
- ✅ Extensive documentation and tooling
- ❌ Licensing concerns (SSPL restrictive)
- ❌ Uncertain long-term open-source direction

### Memcached
- ✅ Simple, fast
- ❌ No persistence
- ❌ Limited data structures
- ❌ No built-in replication

### DragonflyDB
- ✅ High performance
- ✅ Redis-compatible
- ❌ Newer, less proven
- ❌ Different architecture (unknown production characteristics)

## Consequences

### Positive
- Future-proof licensing (no SSPL concerns)
- Strong open-source governance
- API compatibility with Redis ecosystem
- Active community and development

### Negative
- Smaller ecosystem compared to Redis (currently)
- Less mature tooling and monitoring integrations
- Team unfamiliarity (mitigated by API compatibility)

### Neutral
- Configuration identical to Redis
- Ops teams can use Redis knowledge

## Implementation Notes

### Session Storage
```go
// Valkey client for session management
valkeyClient, err := valkeygo.NewClient(valkeygo.ClientOption{
    InitAddress: []string{cfg.CacheAddr},
    Password:    cfg.CachePassword,
    SelectDB:    cfg.CacheDB,
})

// Compatibility adapter for Redis-like API
client := valkeycompat.NewAdapter(valkeyClient)
```

### JWKS Caching
```go
// Native Valkey client for JWKS caching
cacheClient, err := session.NewValkeyClient(
    cfg.CacheAddr,
    cfg.CachePassword,
    cfg.CacheDB,
)
```

### Environment Variables
- `CACHE_ADDR` - Valkey server address (default: `localhost:6379`)
- `CACHE_PASSWORD` - Optional authentication
- `CACHE_DB` - Database number (default: `0`)

## Migration Path

If reverting to Redis becomes necessary:
1. Change connection string to Redis endpoint
2. No code changes required (protocol-compatible)
3. Valkey → Redis migration is seamless

## References

- [Valkey Project](https://valkey.io/)
- [Valkey GitHub](https://github.com/valkey-io/valkey)
- [valkey-go client](https://github.com/valkey-io/valkey-go)
- [Redis licensing change announcement](https://redis.com/blog/redis-adopts-dual-source-available-licensing/)
