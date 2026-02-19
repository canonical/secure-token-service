# ADR-003: PostgreSQL for JWKS Storage

**Status**: Accepted  
**Date**: 2026-01-27  
**Deciders**: Development Team  

## Context

JWKS (JSON Web Key Sets) need durable, consistent storage for JWT signing keys. Key rotation requires atomic operations to maintain service availability during transitions.

## Decision

We chose **PostgreSQL** as the storage backend for JWKS keys.

## Rationale

### ACID Guarantees
- **Atomicity**: Key rotation is atomic (retire old + insert new in single transaction)
- **Consistency**: No partial updates visible during rotation
- **Durability**: Keys survive crashes and restarts
- **Isolation**: Concurrent operations don't corrupt key state

### Rel

ational Model Fit
- Natural schema for key versioning:
  ```sql
  CREATE TABLE hydra_jwk (
      sid VARCHAR(255) NOT NULL,        -- "public" or "public.retired"
      kid VARCHAR(255) NOT NULL,        -- key ID
      version INTEGER NOT NULL,
      keydata JSONB NOT NULL,           -- full JWK including private key
      created_at TIMESTAMP NOT NULL,
      PRIMARY KEY (sid, kid)
  );
  ```
- Simple queries for active vs retired keys
- Easy key lifecycle management

### Atomic Key Rotation
```go
func (r *PostgresJWKSRepository) RotateKey(ctx context.Context, newKey *JWKSKey) error {
    tx, _ := r.pool.Begin(ctx)
    defer tx.Rollback(ctx)
    
    // Retire all active keys
    tx.Exec(ctx, `UPDATE hydra_jwk SET sid = 'public.retired' WHERE sid = 'public'`)
    
    // Insert new active key
    tx.Exec(ctx, `INSERT INTO hydra_jwk ...`, newKey)
    
    return tx.Commit(ctx) // Atomic commit
}
```

### Operational Simplicity
- Single database for application (sessions could use PostgreSQL too if needed)
- Standard backup/restore procedures
- Well-understood monitoring and tuning
- Existing PostgreSQL expertise in team

### Query Performance
- JWKS queries are **rare and cacheable**:
  - Active key: 1 query on service startup
  - All keys: Cached in Valkey (10-minute TTL)
  - Rotation: Infrequent (monthly or on-demand)
- PostgreSQL overhead acceptable for this use case

## Alternatives Considered

### Valkey/Redis
- ✅ Fast reads
- ❌ No ACID transactions (key rotation risky)
- ❌ Persistence not primary design goal
- ❌ Data loss possible on crashes

### Filesystem (JSON files)
- ✅ Simple
- ❌ No atomic updates
- ❌ Difficult to manage in multi-instance deployments
- ❌ No audit trail

### Vault/KMS
- ✅ Purpose-built for secrets
- ❌ Operational complexity
- ❌ External dependency
- ❌ Overkill for this use case (keys are public anyway)

### etcd
- ✅ Strong consistency
- ❌ Additional infrastructure component
- ❌ Less familiar to team
- ❌ More complex than needed

## Consequences

### Positive
- Guaranteed key consistency across instances
- Safe key rotation without downtime
- Simple schema and queries
- Standard PostgreSQL operational procedures
- Easy debugging and introspection

### Negative
- Slightly higher latency than in-memory (mitigated by caching)
- Requires PostgreSQL running (already required for other reasons)

### Neutral
- keys stored as JSONB (flexible, queryable)
- Migration path to other databases possible if needed

## Implementation Notes

### Schema Hydra Compatibility
Using `hydra_jwk` table name for potential future Ory Hydra integration:
```sql
-- Active keys: sid = "public"
-- Retired keys: sid = "public.retired"
SELECT * FROM hydra_jwk WHERE sid LIKE 'public%' ORDER BY created_at DESC;
```

### Caching Strategy
Database queries cached in Valkey:
- **Cache Key**: `jwks:all`
- **TTL**: 10 minutes (configurable via `JWKS_CACHE_TTL`)
- **Invalidation**: Automatic on key rotation

### Connection Pooling
```go
// pgxpool for connection management
pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
```

Standard pool settings ensure negligible overhead for JWKS queries.

## References

- [JWKS RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)
- [PostgreSQL ACID](https://www.postgresql.org/docs/current/transaction-iso.html)
- [Ory Hydra JWKS design](https://github.com/ory/hydra)
