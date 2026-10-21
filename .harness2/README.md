# Google `harness2` × OpenSpec Integration for Secure Token Service (STS)

This directory configures [`google-research/harness2`](https://github.com/google-research/harness2) (*Recursive Agent Harnessing for an Open World*) to operate natively over the local **OpenSpec** specification-driven workflow in `secure-token-service`.

## Architecture: Two-Level Recursive Harnessing (`c1..c8`)

`harness2` treats the entire agent harness as an explicit, versioned, validator-checked directory tree (`Tree = dict[str, str]`) spanning eight component types (`c1..c8`):

| Component | Purpose | OpenCode Path (`.harness2/harnesses/opencode_base/`) | Codex / Repo-Root Path (`.harness2/harnesses/codex_base/` & Repo Root) |
| :--- | :--- | :--- | :--- |
| **`c1`** | System Prompt | `systemprompt.md` | Folded into `AGENTS.md` |
| **`c2`** | Workspace Rules | `AGENTS.md` (`<= 24,000` chars combined `c1+c2`) | `AGENTS.md` (`<= 8,000` chars cap) |
| **`c3` / `c6`** | Domain & Invariant Skills | `skills/{openspec-strict-authoring,sts-go-domain,openspec-detect-drift}/SKILL.md` | `.agents/skills/{openspec-strict-authoring,sts-go-domain,openspec-detect-drift}/SKILL.md` |
| **`c4`** | Subagents | `sub_agents/{openspec_spec_auditor,sts_security_reviewer}/AGENT.md` | `sub_agents/{openspec_spec_auditor,sts_security_reviewer}/AGENT.md` |
| **`c5`** | Slash Commands | `commands/{openspec-check,openspec-drift}.md` | Folded into `AGENTS.md` |
| **`c7`** | Deterministic Verification Scripts | `scripts/{validate_openspec.py,check_openspec_drift.py}` | `scripts/{validate_openspec.py,check_openspec_drift.py}` |
| **`c8`** | Lifecycle Hooks / Plugins | `plugin/openspec_guard.ts` | `.codex/hooks.json` |

### Orthogonal Improvement Dimensions (`INV` vs `DOM`)

During each recursive pass, `harness2` decomposes harness adaptation into two orthogonal axes before composing them:

1. **`INV` (Task-Agnostic OpenSpec Invariants)**:
   - Enforces `openspec validate --strict` and `openspec/config.yaml` structural contracts.
   - Enforces `<= 500` character requirement bodies (`### Requirement:` up to the first `#### Scenario:`).
   - Enforces relative Markdown link depth resolution (`../../../` from `openspec/changes/<id>/*.md`, `../../../../../` from `openspec/changes/<id>/specs/<cap>/spec.md`).
   - Enforces numbered checkbox formatting (`1. [x] ...` or `- [x] 7.1 ...`) in `Verification Suite` and `Documentation & Rollout`.
2. **`DOM` (STS Go 1.26 Domain Practitioner Knowledge)**:
   - Maps OpenSpec capabilities (`artifact-security-gate`, `m2m-token-exchange`, `support-multi-arch-rocks-and-pipelines`, `support-ubuntu-one-openid`) to the Go 1.26 source tree (`internal/auth/`, `internal/grpc/`, `internal/http/`, `internal/cookie/`, `api/sts/v1/sts.proto`, `rockcraft.yaml`, `.github/workflows/`).
   - Eliminates archive `TBD` purpose placeholders and template `Implementation Notes` by synthesizing accurate architectural prose.

## Quickstart Commands

```bash
# 1. Validate all c1..c8 harness trees (opencode_seed, opencode_base, codex_base)
PYTHONPATH=.harness2 python3 -m openspec_harness.cli validate-harnesses

# 2. Audit OpenSpec specs & changes (strict CLI + config.yaml contracts + code drift)
PYTHONPATH=.harness2 python3 -m openspec_harness.cli audit

# 3. Run the two-level harness2 recursive sweep (parallel & sequential modes, k=1,2)
PYTHONPATH=.harness2 python3 -m openspec_harness.cli sweep --substrate oc --modes parallel,sequential --k 1,2

# 4. Apply INV+DOM OpenSpec remediations to the live repository
PYTHONPATH=.harness2 python3 -m openspec_harness.cli remediate

# 5. Run the test suite (upstream harness2 tests + OpenSpec integration tests)
PYTHONPATH=.harness2 pytest .harness2/tests -v
```
