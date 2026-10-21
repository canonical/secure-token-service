---
name: openspec-strict-authoring
description: Author, validate, and remediate OpenSpec specifications and change artifacts under strict schema rules. Use when creating or editing proposal.md, design.md, tasks.md, or specs/*/spec.md in openspec/.
license: Apache-2.0
---

# OpenSpec Strict Authoring & Remediation Skill

Use this skill whenever creating, updating, or auditing OpenSpec artifacts (`openspec/specs/*/spec.md` and `openspec/changes/<id>/*`) in the Secure Token Service (Janus) repository.

## 1. Mandatory Deterministic Verification Loop (`c7`)

Before and after modifying any file under `openspec/`, run the repository's deterministic validators:

```bash
python3 scripts/validate_openspec.py
python3 scripts/check_openspec_drift.py
```

Both commands MUST exit with code `0` (`all_checks_ok: true`) before you finish your task.

## 2. Strict OpenSpec CLI Rules (`openspec validate --all --strict`)

The `openspec validate --all --strict` CLI enforces structural constraints that non-strict validation (`openspec validate --all`) only reports as warnings:

1. **Non-Placeholder `## Purpose` in Main and Delta Specs**:
   - Every `openspec/specs/<capability>/spec.md` and `openspec/changes/<id>/specs/<capability>/spec.md` MUST begin with a `## Purpose` section explaining the capability's architectural responsibility in 1–3 concise sentences.
   - Never leave `TBD`, `TODO`, or `TBD - created by archiving change ...` in `## Purpose`.
2. **Requirement Paragraph Length (`<= 500` characters)**:
   - In every `### Requirement: <Title>` block, the normative requirement paragraph (between the `### Requirement:` heading and the first `#### Scenario:` heading) MUST be **500 characters or fewer**.
   - Use normative keywords (`SHALL` or `MUST`).
   - Move detailed parameter values, HTTP status payloads, or multi-step branch cases into `#### Scenario:` blocks (`- **WHEN** ...` / `- **THEN** ...`) or split compound requirements into focused single-behavior requirements.

## 3. Repository Contract Rules (`openspec/config.yaml`)

### `proposal.md`
- Must include all six sections:
  - `## Why`
  - `## What Changes`
  - `## Non-goals`
  - `## Success Metrics`
  - `## Capabilities` (`### New Capabilities` and `### Modified Capabilities`)
  - `## Impact`

### `design.md`
- Reference `proposal.md` in `## Context` rather than repeating motivation prose.
- Include `## Goals / Non-Goals`, a `mermaid` architecture or sequence diagram (` ```mermaid `), numbered architectural decisions with rationale and alternatives, `## Risks & Trade-offs` (or `## Risks / Trade-offs`), and observability/security considerations.

### `tasks.md`
- Group tasks under numbered `## N. <Area>` headings with markdown checkboxes (`- [ ] N.M` or `- [x] N.M`).
- Every task item must end with a concrete verification step (e.g., `go test -race ./...`, `openspec validate --all --strict`).
- Must include:
  - `Verification Suite` section containing numbered checkbox items (`- [x] N.M ...`).
  - `Documentation & Rollout` section containing numbered checkbox items (`- [x] N.M ...`).
  - `## Implementation Notes` containing concrete architectural or implementation notes (never leave the raw template placeholder `*(Deviations from original plan...)*` once tasks are checked off).

## 4. Relative Link Resolution Rule

Every relative Markdown link `[label](relative/path)` in `proposal.md`, `design.md`, `tasks.md`, and `specs/*/spec.md` is resolved relative to the **directory containing that Markdown file**, NOT the repository root:

- From `openspec/changes/<id>/proposal.md`, `design.md`, or `tasks.md` (3 levels deep):
  - Prefix repository-root paths with `../../../` (e.g., `[Makefile](../../../Makefile)`, `[internal/grpc/server.go](../../../internal/grpc/server.go)`).
- From `openspec/changes/<id>/specs/<cap>/spec.md` (5 levels deep):
  - Prefix repository-root paths with `../../../../../` (e.g., `[candidate.json](../../../../../.archify/architecture-secure-token-service-20261008-154500/candidate.json)`).
  - Prefix sibling change artifacts with `../../` (e.g., `[design.md](../../design.md)`).
