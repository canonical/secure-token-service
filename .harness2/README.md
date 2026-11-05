# OpenSpec Harness2 Toolkit — STS configuration

This directory holds the STS-specific pieces of the shared OpenSpec harness
setup:

- `harnesses/` — the `c1..c8` agent harness trees (`opencode_seed`, `opencode_base`, `omp_seed`, `omp_base`)
- `tests/` — STS-specific tests for the harness surfaces and the declarative configs
- `requirements.txt` — the **pinned** shared toolkit dependency

The generic engines (`openspec_harness`: validation + drift + cli, plus the
`harness2` core) are **not vendored here** — they are consumed from
[`canonical/identity-team`](https://github.com/canonical/identity-team)
(`tools/openspec-harness`) at the `identity-team` release tag pinned in
[`requirements.txt`](./requirements.txt) (currently `v1.19.0`, cut by the
standard release-please workflow).
All repository-specific values stay **declarative**:

- `openspec/config.yaml` → `validation:` settings (`max_requirement_chars`, `require_mermaid_in_design`, `proposal_sections`, `design_sections`, `tasks_checkbox_sections`)
- `openspec/drift-checks.yaml` → per-spec/change code-to-spec drift checks (`id`, `path`, `needles` / `regex`)

`scripts/validate_openspec.py` and `scripts/check_openspec_drift.py` are thin
shims over `openspec_harness.validation:main` / `openspec_harness.drift:main`
from the installed package; the harness trees carry no duplicate script
copies.

## Pulling Dependencies

```bash
# Install the pinned shared toolkit (openspec-harness from canonical/identity-team)
make harness2-deps
# equivalent to:
python3 -m pip install -r .harness2/requirements.txt
```

To upgrade the toolkit, bump the tag in `.harness2/requirements.txt` and
re-run `make harness2-deps`.

## Architecture: Two-Level Recursive Harnessing (`c1..c8`)

`harness2` treats the entire agent harness as an explicit, versioned, validator-checked directory tree (`Tree = dict[str, str]`) spanning eight component types (`c1..c8`):

| Component | Purpose | OpenCode Path (`.harness2/harnesses/opencode_base/`) | OMP Path (`.harness2/harnesses/omp_base/` & Repo `.omp/`) | Antigravity / Repo-Root Path |
| :--- | :--- | :--- | :--- | :--- |
| **`c1`** | System Prompt / Context | `systemprompt.md` | `.omp/AGENTS.md` | Folded into `AGENTS.md` |
| **`c2`** | Workspace / Sticky Rules | `guardrails.md` (`<= 24,000` chars combined) | `.omp/RULES.md` (`<= 24,000` chars combined) | `AGENTS.md` |
| **`c3` / `c6`** | Domain & Invariant Skills | `skills/{openspec-strict-authoring,sts-go-domain,openspec-detect-drift}/SKILL.md` | `.omp/skills/{openspec-strict-authoring,sts-go-domain,openspec-detect-drift}/SKILL.md` | `.agents/skills/{openspec-strict-authoring,sts-go-domain,openspec-detect-drift}/SKILL.md` |
| **`c4`** | Subagents | `sub_agents/{openspec_spec_auditor,sts_security_reviewer}/AGENT.md` | `sub_agents/.../AGENT.md` & `.omp/agents/{openspec_spec_auditor,sts_security_reviewer}.md` | `sub_agents/{openspec_spec_auditor,sts_security_reviewer}/AGENT.md` |
| **`c5`** | Slash Commands | `commands/{openspec-check,openspec-drift}.md` | `.omp/commands/{openspec-check,openspec-drift}.md` | Folded into `AGENTS.md` |
| **`c7`** | Deterministic Verification Scripts | `scripts/{validate_openspec.py,check_openspec_drift.py}` | `scripts/{validate_openspec.py,check_openspec_drift.py}` | `scripts/{validate_openspec.py,check_openspec_drift.py}` |
| **`c8`** | Lifecycle Hooks / Extensions | `plugin/openspec_guard.ts` | `.omp/extensions/openspec_guard.ts` | `.agents/hooks.json` |

## Quickstart Commands

```bash
# 0. Install the pinned shared toolkit (once, and after every pin bump)
make harness2-deps

# 1. Validate all c1..c8 harness trees (opencode_seed, opencode_base, omp_seed, omp_base)
make harness2-validate

# 2. Audit OpenSpec specs & changes (strict CLI + config.yaml contracts + code drift)
make harness2-audit

# 3. Run the test suite (STS-specific harness surface + config tests)
make harness2-test
```

## Onboarding Another Repository

See the shared toolkit's
[`README`](https://github.com/canonical/identity-team/blob/main/tools/openspec-harness/README.md)
for the full consumer guide (`openspec-harness init`, declarative configs,
and the reusable `_openspec-validate.yaml` CI workflow). The short version:

```bash
npx @fission-ai/openspec init      # if openspec/ does not exist yet
openspec-harness init              # scaffolds drift-checks.yaml, scripts/ shims, Makefile target
openspec-harness audit             # verify locally
```

For CI, call the reusable workflow with both pins set to the release tag:

```yaml
jobs:
  openspec-validate:
    uses: canonical/identity-team/.github/workflows/_openspec-validate.yaml@v1.19.0
    with:
      drift-config: openspec/drift-checks.yaml
      toolkit-ref: v1.19.0
```
