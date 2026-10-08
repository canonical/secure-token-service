# Machine-to-Machine (M2M) Token Exchange

This OpenSpec change defines and tracks the implementation of machine-to-machine (M2M) token exchange in the Secure Token Service (STS). It introduces the `ExchangeToken` gRPC endpoint to enable downstream proxies and authorization gateways (e.g., Envoy external authorization) to swap upstream IdP OAuth2 access tokens (issued via Ory Hydra Client Credentials flow) for signed internal STS JWTs (ES256).

## Documentation Artifacts

- [**Proposal**](proposal.md) — Motivation, problem statement, business value, and capabilities.
- [**Design**](design.md) — Technical architecture, sequence diagrams, key decisions, risks, and telemetry.
- [**Specification**](specs/m2m-token-exchange/spec.md) — Formal requirements and acceptance test scenarios for `ExchangeToken`.
- [**Tasks**](tasks.md) — Step-by-step implementation, observability, and verification checklist.

## Architecture Modeling

- [**Archify Design (Interactive HTML)**](../../../.archify/architecture-secure-token-service-20261008-154500/secure-token-service.html)
- [**Archify Visual Check (Dark Theme)**](../../../.archify/architecture-secure-token-service-20261008-154500/visual-check/secure-token-service.visual-check.1440x900.dark.png)
- [**Archify Candidate Specification**](../../../.archify/architecture-secure-token-service-20261008-154500/candidate.json)
