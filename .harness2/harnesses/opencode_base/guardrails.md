# Guardrails & Skill Autotriggers (`c6`)

## Hard Guardrails
1. **Never Skip Strict Validation**: Every edit to `openspec/**` MUST pass `python3 scripts/validate_openspec.py` and `python3 scripts/check_openspec_drift.py` before completion.
2. **Never Exceed 500 Characters in Requirement Text**: The normative paragraph under `### Requirement: <Title>` (before the first `#### Scenario:`) MUST be `<= 500` characters so `openspec validate --strict` passes with zero warnings.
3. **Never Leave Placeholder `## Purpose` or `## Implementation Notes`**: Replace `TBD` / `TODO` purpose text and template implementation note placeholders with accurate domain descriptions.
4. **Never Write Broken Relative Links**: Resolve all Markdown links relative to the directory of the file containing the link (`../../../` from `openspec/changes/<id>/*.md`, `../../../../../` from `openspec/changes/<id>/specs/<cap>/spec.md`).

## Skill Triggers
- When authoring, validating, or remediating OpenSpec specifications and change artifacts under strict schema rules, load the `openspec-strict-authoring` skill.
- When detecting drift between code changes and OpenSpec specifications in `openspec/specs/` or `openspec/changes/`, load the `openspec-detect-drift` skill.
- When aligning OpenSpec artifacts with Secure Token Service Go 1.26 architecture, Phantom Token Pattern, ES256 JWT minting, Ory Hydra M2M exchange, Ubuntu One OpenID 2.0, CookieManager, or multi-arch Rockcraft builds, load the `sts-go-domain` skill.
