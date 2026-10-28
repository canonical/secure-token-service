# Secure Token Service (Janus) — Agent & OpenSpec Harness (`harness2`)

This repository uses **OpenSpec (`spec-driven` schema)** paired with **Google `harness2`** (Recursive Agent Harnessing) for specification-driven Go 1.26 engineering.

## 1. Always-On Operational Protocol (`c1`)

1. **Inspect Before Editing**:
   - Check active OpenSpec changes in `openspec/changes/` and baseline specifications in `openspec/specs/`.
   - Read `openspec/config.yaml` for artifact rules (`proposal.md`, `specs/*/spec.md`, `design.md`, `tasks.md`).
2. **Execute Deterministic Verification (`c7`)**:
   - Always run both verification scripts before concluding any OpenSpec or code task:
     - `python3 scripts/validate_openspec.py`
     - `python3 scripts/check_openspec_drift.py`
   - Run `openspec validate --all --strict` to verify strict schema compliance with zero warnings.
3. **Preserve Strict OpenSpec Invariants (`c6`)**:
   - **Non-placeholder `## Purpose`**: Every main spec (`openspec/specs/*/spec.md`) and delta spec (`openspec/changes/*/specs/*/spec.md`) MUST start with a concise `## Purpose` section (never leave `TBD` or `TODO`).
   - **Strict Requirement Length (`<= 500` chars)**: Keep every `### Requirement:` body paragraph to 500 characters or fewer using `SHALL` / `MUST`; move edge cases and detailed branches into `#### Scenario:` (`- **WHEN**` / `- **THEN**`) blocks or split compound requirements.
   - **Valid Relative Links**: Every relative Markdown link in `proposal.md`, `design.md`, `tasks.md`, and `specs/*/spec.md` must resolve relative to that file's parent directory (`../../../` from `openspec/changes/<id>/*.md`, `../../../../../` from `openspec/changes/<id>/specs/<cap>/spec.md`).
   - **Structured `tasks.md`**: Include numbered checkbox items (`- [x] N.M ...`) in both `Verification Suite` and `Documentation & Rollout`, and replace template placeholders in `## Implementation Notes` with concrete architectural notes.

## 2. Domain Architecture Memory (`c3`)

- **Service**: Secure Token Service (Janus) — Go 1.26 microservice implementing the Phantom Token Pattern (ADR-004).
- **Human Authentication (`internal/http`, `internal/cookie`, `internal/auth/openid`, `internal/session`)**:
  - `GET /auth/login?provider=oidc|openid` (default `oidc`, case-insensitive) routes to OIDC (`/auth/callback`) or Ubuntu One OpenID 2.0 (`/auth/openid/callback`, SREG 1.1 + AX 1.0, stateless `check_authentication`, 5-minute `openid.response_nonce` replay protection).
  - `CookieManager` (`internal/cookie/cookie.go`) issues ChaCha20-Poly1305 AEAD cookies (`session_id`, `oauth_state`, `oauth_nonce`) with `HttpOnly: true`, `SameSite: Lax`, `Path: "/"`, and dynamic `Secure`.
- **Token Exchange (`internal/grpc`, `internal/auth/hydra.go`, `api/proto/v1/sts.proto`)**:
  - `ExchangeSession` swaps Valkey sessions for ES256 internal JWTs (`sub: email`, `email: email`).
  - `ExchangeToken` verifies Ory Hydra OAuth2 Client Credentials JWTs against a preemptive JWKS cache (`HydraTokenVerifier`), rejects tokens `> 64 KB` (`InvalidArgument`) or `< 60s` remaining validity (`Unauthenticated`, 5s skew tolerance), clamps TTL to `min(configured_expiry, remaining_validity)`, and maps `sub: <client_id>`, `email: <client_id>@serviceaccount.local`.
- **Multi-Arch & Security Gate (`Makefile`, `rockcraft.yaml`, `.github/workflows/`)**:
  - Go binaries compile for 3 architectures (`amd64`, `arm64`, `riscv64` via `make build-all`); Rockcraft OCI images build, scan (Trivy), and promote (`skopeo copy --all`) for 2 architectures (`amd64`, `arm64`).

## 3. On-Demand Skills (`c6`) & Subagents (`c5`)

- When authoring, updating, or fixing OpenSpec proposals, designs, tasks, or spec deltas to satisfy `openspec validate --all --strict` and `openspec/config.yaml`, load the `openspec-strict-authoring` skill.
- When detecting drift between code changes, pull requests, or Go packages and OpenSpec specifications in `openspec/specs/` or `openspec/changes/`, load the `openspec-detect-drift` skill.
- When aligning OpenSpec artifacts with Secure Token Service Go 1.26 packages, JWT cryptography, Ubuntu One OpenID, CookieManager, or Rockcraft CI pipelines, load the `sts-go-domain` skill.
- Delegate deep specification audits to `sub_agents/openspec_spec_auditor/AGENT.md` and security boundary reviews to `sub_agents/sts_security_reviewer/AGENT.md`.
