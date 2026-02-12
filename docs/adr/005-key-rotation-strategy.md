# ADR-005: Key Rotation Strategy

**Status**: Accepted  
**Date**: 2026-02-02  
**Deciders**: Development Team, Security Team  

## Context

RS256 JWT signing requires private keys. Compromised keys or security best practices require periodic rotation. Rotation must not cause service interruption or invalidate existing valid JWTs.

## Decision

We implement **gradual key rotation** with:
1. **Active key**: Used for signing new JWTs
2. **Retired keys**: Kept for verification during rotation window
3. **Atomic database transaction**: Guarantees consistency
4. **JWKS endpoint**: Returns both active and retired public keys

## Rationale

### Zero-Downtime Rotation

**Timeline**:
```
T0: Rotation triggered
│
├─ Transaction: Retire current active → Insert new active
│  (Atomic - both or neither)
│
├─ JWKS cache invalidated
│  (Valkey key deleted)
│
├─ Services fetch new JWKS
│  (Contains both old + new public keys)
│
└─ Old JWTs still valid (until expiry)
   New JWTs signed with new key
```

**No Service Disruption**:
- Services verify JWTs using JWKS (contains all public keys)
- Old JWTs verify against retired public key
- New JWTs verify against active public key
- Gradual migration as JWTs expire naturally

### Atomic State Transition

```go
func (r *PostgresJWKSRepository) RotateKey(ctx context.Context, newKey *JWKSKey) error {
    return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
        // Step 1: Move active → retired
        _, err := tx.Exec(ctx, `
            UPDATE hydra_jwk 
            SET sid = 'public.retired' 
            WHERE sid = 'public'
        `)
        
        // Step 2: Insert new active
        _, err = tx.Exec(ctx, `
            INSERT INTO hydra_jwk (sid, kid, version, keydata, created_at)
            VALUES ($1, $2, $3, $4, $5)
        `, "public", newKey.KID, 0, newKey.KeyData, time.Now())
        
        return err
        // Commit or rollback - atomic
    })
}
```

**Guarantees**:
- ✅ Never have zero active keys
- ✅ Never have partially-rotated state visible
-  ✅ Retired keys immediately available for verification
- ✅ Rollback on any error

### Verification Policy

**Services use standard JWKS verification**:
1. Parse JWT, extract `kid` (key ID) from header
2. Lookup public key in JWKS by `kid`
3. Verify signature with public key
4. Check expiry, audience, issuer

**No service code changes needed for rotation**.

## Key Lifecycle

### Key States

```
┌──────────┐     Rotation      ┌───────────┐     Manual       ┌─────────┐
│  Active  │ ─────────────────▶│  Retired  │ ──── Delete ───▶│ Deleted │
│ sid=public│                   │sid=public.│                 │   (N/A)  │
└──────────┘                    │  retired  │                 └─────────┘
     │                          └───────────┘
     │                               │
     │                               │
     └───── Used for signing ────────┘
             Used for verification
```

### Retention Policy

**Retired Keys**:
- Kept until all JWTs signed with them have expired
- **Recommended**: Keep for `2 * max_jwt_ttl`
- **Example**: JWT TTL = 15min → Keep retired keys for 30min minimum

**Manual Cleanup**:
```bash
# CLI command to delete old retired keys
./sts delete-retired-keys --older-than 1h
```

## Rotation Triggers

### Scheduled Rotation
```bash
# Cron job (monthly)
0 2 1 * * /usr/bin/sts rotate-key
```

### Emergency Rotation
```bash
# Manual trigger (key compromise)
./sts rotate-key --emergency
```

### Automated Triggers (Future)
- [ ] Rotate on deployment
- [ ] Rotate on schedule (e.g., every 30 days)
- [ ] Rotate on security alert

## Cache Invalidation

**After rotation, JWKS cache must be invalidated**:

```go
// In rotate-key command
if err := keyManager.InvalidateJWKSCache(ctx); err != nil {
    log.Printf("Warning: Failed to invalidate JWKS cache")
    // Non-fatal: cache will expire naturally (TTL=10min)
} else {
    log.Println("✓ JWKS cache invalidated")
}
```

**Fallback**: Even if invalidation fails, cache expires within TTL (default 10 minutes).

## Alternatives Considered

### Immediate Key Deletion
- ❌ Invalidates all existing JWTs immediately
- ❌ Service disruption
- ❌ Users forced to re-authenticate

### Key Expiry in JWT
- ✅ Automatic invalidation
- ❌ Requires clock synchronization
- ❌ Cannot revoke before expiry

### Single Active Key Only
- ✅ Simpler
- ❌ Rotation requires brief service downtime
- ❌ Coordination nightmare with multiple services

### External KMS Rotation
- ✅ Managed key lifecycle
- ❌ External dependency
- ❌ Latency for every signing operation
- ❌ Overkill for public key material

## Consequences

### Positive
- Zero-downtime rotation
- No service coordination needed
- Atomic state transitions (PostgreSQL)
- Old JWTs remain valid during transition

### Negative
- Retired keys consume database space (minimal)
- Manual cleanup required eventually
- Cache invalidation not guaranteed (mitigated by TTL)

### Trade-offs
- Keep retired keys for 24 hours (conservative)
- vs immediate deletion (risky)

## Implementation Checklist

- [x] Atomic rotation transaction
- [x] JWKS endpoint returns all keys
- [x] Cache invalidation after rotation
- [x] CLI tool for rotation (`sts rotate-key`)
- [ ] Automated scheduled rotation (cron)
- [ ] Monitoring/alerting for rotation failures
- [ ] Cleanup tool for old retired keys

## Monitoring

### Metrics to Track
- `jwks_rotation_total` - Count of rotations
- `jwks_rotation_failures` - Failed rotations
- `jwks_active_keys_count` - Should always be 1
- `jwks_retired_keys_count` - Track accumulation
- `jwks_cache_invalidation_failures` - Cache invalidation issues

### Alerts
- **Critical**: No active keys found
- **Warning**: Rotation failure
- **Info**: Retired keys > 10 (cleanup needed)

## References

- [JWKS Key Rotation - Auth0](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- Implementation: `cmd/sts/rotate_key.go`
