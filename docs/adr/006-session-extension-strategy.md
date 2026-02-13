# ADR-006: Session Extension Strategy

**Status**: Accepted  
**Date**: 2026-02-13  
**Deciders**: Development Team  

## Context

Sessions are stored in Valkey with a TTL matching the JWT expiry. When sessions approach expiration, users are forced to re-authenticate via the OIDC provider. For long-running workflows or administrative maintenance windows, it is desirable to extend session lifetimes without requiring user interaction, provided the session holds a valid refresh token.

The OIDC `offline_access` scope grants refresh tokens that can be used to obtain new access and ID tokens from the upstream identity provider without user interaction.

## Decision

We implement **CLI-based session extension** with two commands:

1. **`sts extend-sessions`**: Scans all active sessions, refreshes tokens, extends TTLs
2. **`sts extend-session --id <session-id>`**: Refreshes a single session by ID

Both commands:
- Use the stored `refresh_token` to obtain new tokens via `oauth2.TokenSource`
- Update the session with new `access_token`, `id_token`, `refresh_token`, and `expires_at`
- Extend the Valkey TTL using a functional options pattern on `Store.Set`
- Support `--dry-run` for safe inspection and `--ttl` to override the default TTL

## Rationale

### Why CLI Commands (Not Automatic)

- **Explicit control**: Administrators decide when to extend sessions
- **Audit trail**: CLI invocations are logged and traceable
- **No background goroutines**: Avoids complexity of background refresh loops in the server process
- **Cron-compatible**: Can be scheduled via cron for periodic extension if desired

```bash
# Extend all sessions every 30 minutes
*/30 * * * * /usr/bin/sts extend-sessions --ttl 3600
```

### Why Functional Options on Store.Set

Instead of adding a new `SetWithTTL` method, we use Go's functional options pattern:

```go
type SetOption func(*SetOptions)

func WithTTL(ttl time.Duration) SetOption {
    return func(o *SetOptions) { o.TTL = &ttl }
}

// Existing callers unchanged:
store.Set(ctx, session)

// Extension with custom TTL:
store.Set(ctx, session, WithTTL(2 * time.Hour))
```

**Benefits**:
- Backward compatible — existing callers need no changes
- Extensible — future options (e.g., `WithEncryption`) can be added without interface changes
- Single method to maintain

### Token Refresh Flow

```
┌─────────────────┐
│ Get session from │
│ Valkey store     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     No refresh token
│ Has refresh      │────────────────────▶ Skip (log warning)
│ token?           │
└────────┬────────┘
         │ Yes
         ▼
┌─────────────────┐     Token refresh failed
│ oauth2.Token    │────────────────────▶ Log error, continue
│ Source.Token()  │
└────────┬────────┘
         │ Success
         ▼
┌─────────────────┐
│ Update session:  │
│ - access_token   │
│ - id_token       │
│ - refresh_token  │
│ - expires_at     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ store.Set(ctx,   │
│   session,       │
│   WithTTL(ttl))  │
└─────────────────┘
```

## Alternatives Considered

### Automatic Background Refresh in Server Process
- ✅ No manual intervention needed
- ❌ Adds complexity and goroutine lifecycle management
- ❌ Harder to monitor and debug
- ❌ Resource consumption in multi-replica deployments

### Sliding Window TTL (Extend on Every Access)
- ✅ Sessions never expire while active
- ❌ Doesn't refresh upstream tokens (access token may be stale)
- ❌ Security concern — sessions can live indefinitely

### Separate Refresh Microservice
- ✅ Separation of concerns
- ❌ Over-engineered for current scale
- ❌ Additional deployment complexity

## Consequences

### Positive
- Explicit, auditable session lifecycle management
- Refresh tokens used properly — upstream tokens stay valid
- Backward-compatible Store interface change
- Cron-schedulable for automation

### Negative
- Requires OIDC provider credentials when running CLI
- Sessions that expire between cron runs will not be refreshed
- Adds a scanning operation against Valkey (mitigated by SCAN cursor)

## Implementation Checklist

- [x] Functional options on `Store.Set` (`WithTTL`)
- [x] `Store.ListAllExpiring` method for expiring session scanning
- [x] `sts extend-sessions` CLI command
- [x] `sts extend-session --id` CLI command
- [x] Kubernetes CronJob for scheduled extension
- [x] Unit tests
- [ ] Documentation updates

## References

- [OAuth 2.0 Refresh Tokens - RFC 6749 §6](https://datatracker.ietf.org/doc/html/rfc6749#section-6)
- [Go Functional Options Pattern](https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis)
- Implementation: `cmd/sts/extend_sessions.go`
