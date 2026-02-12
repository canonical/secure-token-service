# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records documenting key technical decisions made in the Secure Token Service (Janus) project.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [001](./001-cookie-library-choice.md) | Cookie Library Choice | Accepted | 2026-02-11 |
| [002](./002-valkey-over-redis.md) | Cache Choice - Valkey over Redis | Accepted | 2026-01-28 |
| [003](./003-postgresql-for-jwks.md) | PostgreSQL for JWKS Storage | Accepted | 2026-01-27 |
| [004](./004-phantom-token-pattern.md) | Phantom Token Pattern | Accepted | 2026-01-27 |
| [005](./005-key-rotation-strategy.md) | Key Rotation Strategy | Accepted | 2026-02-02 |

## ADR Format

Each ADR follows this structure:
- **Status**: Proposed, Accepted, Deprecated, Superseded
- **Date**: When the decision was made
- **Context**: The problem or situation requiring a decision
- **Decision**: What was decided
- **Rationale**: Why this decision was made
- **Alternatives Considered**: Other options that were evaluated
- **Consequences**: Positive, negative, and neutral impacts
- **Implementation Notes**: Technical details and code examples

## Creating New ADRs

1. Create file: `docs/adr/NNN-short-title.md`
2. Use the format from existing ADRs
3. Add entry to this README
4. Submit for review

## References

- [Michael Nygard's ADR template](https://github.com/joelparkerhenderson/architecture-decision-record)
- [ADR GitHub Organization](https://adr.github.io/)
