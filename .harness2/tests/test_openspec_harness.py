"""End-to-end tests for the Google harness2 + OpenSpec configuration in secure-token-service."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest
from harness2.core import tree as harness_tree
from harness2.substrate.omp import OMP_SURFACE
from harness2.substrate.opencode import OPENCODE_SURFACE
from openspec_harness.adapter import RUNTIME_SCRIPTS

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS2_DIR = REPO_ROOT / ".harness2"


def _load_stop_hook_module():
    script_path = REPO_ROOT / "scripts" / "openspec_stop_hook.py"
    spec = importlib.util.spec_from_file_location("openspec_stop_hook", script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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

    # Ensure OMP guard copies remain aligned and contain loop-prevention guards
    repo_omp_guard = (REPO_ROOT / ".omp" / "extensions" / "openspec_guard.ts").read_text(encoding="utf-8")
    base_omp_guard = (
        HARNESS2_DIR / "harnesses" / "omp_base" / ".omp" / "extensions" / "openspec_guard.ts"
    ).read_text(encoding="utf-8")
    assert repo_omp_guard == base_omp_guard
    assert "blockedOnce" in repo_omp_guard
    assert "continuationActive" in repo_omp_guard
    assert "stop_hook_active" in repo_omp_guard


@pytest.mark.parametrize(
    "payload",
    [
        {"continuationActive": True, "terminationReason": "NO_TOOL_CALL"},
        {"executionNum": 1, "terminationReason": "NO_TOOL_CALL"},
        {"stop_hook_active": True, "terminationReason": "NO_TOOL_CALL"},
        {"stopHookActive": True, "terminationReason": "NO_TOOL_CALL"},
        {"terminationReason": "USER_CANCELED"},
        {"terminationReason": "ERROR"},
        {"terminationReason": "MAX_INVOCATIONS"},
        {"terminationReason": "MAX_FORCED_INVOCATIONS"},
        {"terminationReason": "MAX_TOKEN_BUDGET_EXCEEDED"},
        {"terminationReason": "NO_TOOL_CALL", "error": "tool execution failed"},
    ],
)
def test_stop_hook_allows_without_looping_even_when_checks_fail(
    tmp_path: Path, payload: dict[str, object]
) -> None:
    """Stop hook must allow exit on continuation/non-normal termination even if validators fail."""
    mod = _load_stop_hook_module()
    # tmp_path has no scripts/, so running checks would fail if not short-circuited.
    result = mod.evaluate_stop_hook(payload, tmp_path)
    assert result == {"decision": "allow"}


def test_stop_hook_prompts_once_on_initial_failure_then_allows(tmp_path: Path) -> None:
    """Initial normal stop with failing checks requests continuation once; subsequent stop allows."""
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    (scripts_dir / "validate_openspec.py").write_text("import sys; sys.exit(0)\n", encoding="utf-8")
    (scripts_dir / "check_openspec_drift.py").write_text("import sys; sys.exit(1)\n", encoding="utf-8")

    mod = _load_stop_hook_module()
    first = mod.evaluate_stop_hook(
        {"executionNum": 0, "continuationActive": False, "terminationReason": "NO_TOOL_CALL"},
        tmp_path,
    )
    assert first["decision"] == "continue"
    assert "check_openspec_drift.py" in first["reason"]

    second = mod.evaluate_stop_hook(
        {"executionNum": 1, "continuationActive": True, "terminationReason": "NO_TOOL_CALL"},
        tmp_path,
    )
    assert second == {"decision": "allow"}


def test_hooks_json_stop_command_end_to_end_prevents_loop() -> None:
    """Running the exact Stop hook command from `.agents/hooks.json` parses stdin JSON safely."""
    hooks_cfg = json.loads((REPO_ROOT / ".agents" / "hooks.json").read_text(encoding="utf-8"))
    stop_cmd = hooks_cfg["openspec-guard"]["Stop"][0]["command"]
    assert "openspec_stop_hook.py" in stop_cmd

    # Simulate a continuation stop invoked from `.agents/` (Antigravity sets CWD to hooks.json dir).
    proc = subprocess.run(
        ["sh", "-c", stop_cmd],
        cwd=str(REPO_ROOT / ".agents"),
        input=json.dumps({"executionNum": 1, "continuationActive": True, "terminationReason": "NO_TOOL_CALL"}),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.strip()) == {"decision": "allow"}

    # Simulate an initial normal stop when all OpenSpec checks pass.
    proc_ok = subprocess.run(
        ["sh", "-c", stop_cmd],
        cwd=str(REPO_ROOT / ".agents"),
        input=json.dumps({"executionNum": 0, "continuationActive": False, "terminationReason": "NO_TOOL_CALL"}),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc_ok.returncode == 0, proc_ok.stderr
    assert json.loads(proc_ok.stdout.strip()) == {"decision": "allow"}
