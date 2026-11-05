# OpenSpec Harness2 Toolkit (shared, config-driven)

This directory packages the shared, repository-agnostic OpenSpec tooling:
the `openspec_harness` package (validation + drift + adapter + init), the
`harness2` recursive-harnessing core, and this repository's `c1..c8` agent
harness trees. All repository-specific values are **declarative**:

- `openspec/config.yaml` → `validation:` settings (`max_requirement_chars`, `require_mermaid_in_design`, `proposal_sections`, `design_sections`, `tasks_checkbox_sections`)
- `openspec/drift-checks.yaml` → per-spec/change code-to-spec drift checks (`id`, `path`, `needles` / `regex`)

`scripts/validate_openspec.py` and `scripts/check_openspec_drift.py` are thin
shims over `openspec_harness.validation:main` / `openspec_harness.drift:main`;
the harness trees carry no duplicate script copies.

## Original: Google `harness2` × OpenSpec Integration for Secure Token Service (STS)

This configures [`google-research/harness2`](https://github.com/google-research/harness2) (*Recursive Agent Harnessing for an Open World*) to operate natively over the local **OpenSpec** specification-driven workflow in `secure-token-service`.

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
## Onboarding & Pulling Dependencies

### 1. Prerequisites

- **Python `>= 3.11`** (with `pip`, `pipx`, or `uv`)
- **Node.js `>= 20` / `npx`** (for `@fission-ai/openspec` strict schema validation)
- *(Optional)* `pytest >= 8.0` for running the test suite

### 2. Pulling the Shared `openspec-harness` Dependency

The generic toolkit is published in [`canonical/identity-team`](https://github.com/canonical/identity-team) under `tools/openspec-harness`. Pull and install it directly from git (pin to `@main`, a release tag, or a commit SHA):

```bash
# Install into your active virtualenv / Python environment
pip install "openspec-harness @ git+https://github.com/canonical/identity-team.git@main#subdirectory=tools/openspec-harness"

# Or install isolated CLI entrypoints via pipx / uv
pipx install "openspec-harness @ git+https://github.com/canonical/identity-team.git@main#subdirectory=tools/openspec-harness"
uv tool install "openspec-harness @ git+https://github.com/canonical/identity-team.git@main#subdirectory=tools/openspec-harness"

# For local development inside this repository (editable install with test deps)
pip install -e ".harness2[dev]"
```

Installing the package exposes three console entrypoints:
- `openspec-validate` (`openspec_harness.validation:main`)
- `openspec-drift` (`openspec_harness.drift:main`)
- `openspec-harness` (`openspec_harness.cli:main` — subcommands: `init`, `validate-harnesses`, `audit`)

### 3. Onboarding a New Repository

From the root of an adopting `canonical/` repository:

```bash
# 1. Initialize OpenSpec if openspec/ does not exist yet
npx @fission-ai/openspec init

# 2. Scaffold the declarative manifests, scripts/ shims, and Makefile targets (idempotent)
openspec-harness init
```

`openspec-harness init` scaffolds the following per-repository pieces (skipping any file that already exists):
- `openspec/drift-checks.yaml` — declarative code-to-spec drift checks (`id`, `path`, `needles` / `regex`, `must_exist`)
- `scripts/validate_openspec.py` & `scripts/check_openspec_drift.py` — executable shims delegating to `openspec_harness.validation:main` and `openspec_harness.drift:main`
- `Makefile` — appends `harness2-validate`, `harness2-audit`, and `harness2-test` targets

Next, customize the declarative configs for your service:
1. **(Optional) Configure validation rules in `openspec/config.yaml`**:
   ```yaml
   validation:
     max_requirement_chars: 500
     require_mermaid_in_design: true
     proposal_sections: [Why, What Changes, Non-goals, Success Metrics, Capabilities, Impact]
     design_sections: [Context, Goals, Risks]
     tasks_checkbox_sections: [Verification Suite, Documentation & Rollout]
   ```
2. **Populate `openspec/drift-checks.yaml`** with your capability/change IDs and source file `needles` / `regex` invariants.
3. **Verify locally**:
   ```bash
   openspec-harness audit
   # or via the scaffolded shims / Makefile:
   make harness2-audit
   ```

*(Domain skills such as `<service>-domain` and domain security reviewers remain repo-local by design.)*

### 4. Onboarding CI with the Reusable Workflow

Call the shared workflow from `canonical/identity-team` in `.github/workflows/ci.yaml` (or `.github/workflows/openspec.yaml`):

```yaml
jobs:
  openspec-validate:
    uses: canonical/identity-team/.github/workflows/_openspec-validate.yaml@main
    with:
      drift-config: openspec/drift-checks.yaml
      python-version: "3.13"
```

The reusable workflow installs `openspec-harness` from `canonical/identity-team`, runs `openspec-validate`, runs `openspec-drift`, and executes `npx @fission-ai/openspec validate --all --strict`.

## Quickstart Commands (In-Tree / STS)

```bash
# 1. Validate all c1..c8 harness trees (opencode_seed, opencode_base, omp_seed, omp_base)
PYTHONPATH=.harness2 python3 -m openspec_harness.cli validate-harnesses

# 2. Audit OpenSpec specs & changes (strict CLI + config.yaml contracts + code drift)
PYTHONPATH=.harness2 python3 -m openspec_harness.cli audit

# 3. Run the test suite (config-driven unit tests + OpenSpec integration tests)
PYTHONPATH=.harness2 pytest .harness2/tests -v
```
