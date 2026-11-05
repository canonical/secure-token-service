"""End-to-end tests for the Google harness2 + OpenSpec configuration in secure-token-service."""

from __future__ import annotations

import json
from pathlib import Path

from harness2.core import tree as harness_tree
from harness2.substrate.omp import OMP_SURFACE
from harness2.substrate.opencode import OPENCODE_SURFACE
from openspec_harness import RUNTIME_SCRIPTS

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS2_DIR = REPO_ROOT / ".harness2"


def test_c1_to_c8_harness_surfaces_valid() -> None:
    """Every configured OpenSpec harness tree (`opencode_seed`, `opencode_base`, `omp_seed`,
    `omp_base`) must validate cleanly under `harness2.core.tree.validate` with zero off-surface
    rejected files, and the repo-root `.omp` and Antigravity surfaces must be present and valid.
    """
    for name, surface in (
        ("opencode_seed", OPENCODE_SURFACE),
        ("opencode_base", OPENCODE_SURFACE),
        ("omp_seed", OMP_SURFACE),
        ("omp_base", OMP_SURFACE),
    ):
        hdir = HARNESS2_DIR / "harnesses" / name
        rejected: list[str] = []
        t = harness_tree.read_tree(surface, hdir, rejected=rejected)
        assert not rejected, f"{name} had off-surface files: {rejected}"
        # The c7 scripts are materialised from scripts/ (single source of truth);
        # harness trees carry no duplicate copies.
        census = harness_tree.validate(
            surface,
            t,
            allow_subagents=True,
            reserved_scripts=harness_tree.RESERVED_SCRIPTS | RUNTIME_SCRIPTS,
        )
        assert census["scripts"] == 0, f"{name} carries duplicate c7 scripts: {census}"
    # Verify repo-root AGENTS.md + .agents/hooks.json + .agents/skills + sub_agents + scripts
    assert (REPO_ROOT / "AGENTS.md").is_file()
    assert (REPO_ROOT / ".agents" / "skills" / "openspec-detect-drift" / "SKILL.md").is_file()
    assert (REPO_ROOT / ".agents" / "skills" / "openspec-strict-authoring" / "SKILL.md").is_file()
    assert (REPO_ROOT / ".agents" / "skills" / "sts-go-domain" / "SKILL.md").is_file()
    assert (REPO_ROOT / "sub_agents" / "openspec_spec_auditor" / "AGENT.md").is_file()
    assert (REPO_ROOT / "sub_agents" / "sts_security_reviewer" / "AGENT.md").is_file()
    assert (REPO_ROOT / "scripts" / "validate_openspec.py").is_file()
    assert (REPO_ROOT / "scripts" / "check_openspec_drift.py").is_file()

    hooks_path = REPO_ROOT / ".agents" / "hooks.json"
    assert hooks_path.is_file()
    hooks_cfg = json.loads(hooks_path.read_text(encoding="utf-8"))
    assert "openspec-guard" in hooks_cfg
    assert "PostToolUse" in hooks_cfg["openspec-guard"]
    assert "Stop" in hooks_cfg["openspec-guard"]

    # Verify repo-root native .omp surface
    assert (REPO_ROOT / ".omp" / "AGENTS.md").is_file()
    assert (REPO_ROOT / ".omp" / "RULES.md").is_file()
    assert (REPO_ROOT / ".omp" / "skills" / "openspec-detect-drift" / "SKILL.md").is_file()
    assert (REPO_ROOT / ".omp" / "skills" / "openspec-strict-authoring" / "SKILL.md").is_file()
    assert (REPO_ROOT / ".omp" / "skills" / "sts-go-domain" / "SKILL.md").is_file()
    assert (REPO_ROOT / ".omp" / "agents" / "openspec_spec_auditor.md").is_file()
    assert (REPO_ROOT / ".omp" / "agents" / "sts_security_reviewer.md").is_file()
    assert (REPO_ROOT / ".omp" / "commands" / "openspec-check.md").is_file()
    assert (REPO_ROOT / ".omp" / "commands" / "openspec-drift.md").is_file()
    assert (REPO_ROOT / ".omp" / "extensions" / "openspec_guard.ts").is_file()

    # Validate repo-root .omp + sub_agents + scripts against OMP_SURFACE
    repo_omp_tree = harness_tree.read_tree(OMP_SURFACE, REPO_ROOT)
    census = harness_tree.validate(OMP_SURFACE, repo_omp_tree, allow_subagents=True)
    assert census["skills"] == 3
    assert census["sub_agents"] == 2
    assert census["plugins"] == 1
    assert census["scripts"] >= 2
