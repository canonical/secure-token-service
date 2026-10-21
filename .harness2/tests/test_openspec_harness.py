"""End-to-end tests for the Google harness2 + OpenSpec configuration in secure-token-service."""

from __future__ import annotations

from pathlib import Path

from harness2.core import judge, report, schedule
from harness2.core import tree as harness_tree
from harness2.substrate.codex import CODEX_SURFACE
from harness2.substrate.opencode import OPENCODE_SURFACE

from openspec_harness.adapter import OpenSpecAdapter
from openspec_harness.proposer import OpenSpecScriptedProposer
from openspec_harness.remediate import apply_dom_remediations, apply_inv_remediations

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS2_DIR = REPO_ROOT / ".harness2"


def test_c1_to_c8_harness_surfaces_valid() -> None:
    """Every configured OpenSpec harness tree (`opencode_seed`, `opencode_base`, `codex_base`)
    plus the repo-root Codex surface must validate cleanly under `harness2.core.tree.validate`
    with zero off-surface rejected files.
    """
    for name, surface in (
        ("opencode_seed", OPENCODE_SURFACE),
        ("opencode_base", OPENCODE_SURFACE),
        ("codex_base", CODEX_SURFACE),
    ):
        hdir = HARNESS2_DIR / "harnesses" / name
        rejected: list[str] = []
        t = harness_tree.read_tree(surface, hdir, rejected=rejected)
        assert not rejected, f"{name} had off-surface files: {rejected}"
        harness_tree.validate(surface, t, allow_subagents=True)
        assert "scripts/validate_openspec.py" in t

    # Verify repo-root AGENTS.md + .agents/skills + sub_agents + .codex/hooks.json + scripts
    repo_tree = harness_tree.read_tree(CODEX_SURFACE, REPO_ROOT)
    harness_tree.validate(CODEX_SURFACE, repo_tree, allow_subagents=True)
    assert ".agents/skills/openspec-detect-drift/SKILL.md" in repo_tree
    assert ".agents/skills/openspec-strict-authoring/SKILL.md" in repo_tree
    assert ".agents/skills/sts-go-domain/SKILL.md" in repo_tree
    assert "sub_agents/openspec_spec_auditor/AGENT.md" in repo_tree
    assert "sub_agents/sts_security_reviewer/AGENT.md" in repo_tree


def test_orthogonal_inv_and_dom_remediation(tmp_path: Path) -> None:
    """`INV` and `DOM` remediations target orthogonal failure modes and compose to 100% pass."""
    adapter = OpenSpecAdapter(REPO_ROOT, runs_root=tmp_path / "runs")

    # 1. Seed base (no INV, no DOM) on m2m-token-exchange has 2 failures (1 INV links + 1 DOM notes)
    base_run = adapter.execute("m2m-token-exchange", None, "test/base")
    base_score = adapter.score(base_run, "m2m-token-exchange")
    assert base_score is not None
    assert not base_score["all_pass"]
    assert base_score["n_passed"] == 15
    assert base_score["n_criteria"] == 17

    # 2. Full composed harness (INV + DOM) resolves all 17/17 checks
    full_run = adapter.execute(
        "m2m-token-exchange",
        HARNESS2_DIR / "harnesses" / "opencode_base",
        "test/full",
    )
    full_score = adapter.score(full_run, "m2m-token-exchange")
    assert full_score is not None
    assert full_score["all_pass"]
    assert full_score["n_passed"] == 17
    assert full_score["n_criteria"] == 17


def test_two_level_recursion_and_library_transfer(tmp_path: Path) -> None:
    """Running a k=1 parallel + sequential sweep over two OpenSpec tasks populates the
    domain experience library (`INDEX.md` + `EXPERIENCE.md`) and achieves 100% pass rate.
    """
    runs_root = tmp_path / "runs"
    lib_root = runs_root / "library"
    adapter = OpenSpecAdapter(REPO_ROOT, substrate_name="oc", runs_root=runs_root)
    prop = OpenSpecScriptedProposer(REPO_ROOT, substrate_name="oc")

    rep = schedule.run_sweep(
        1,
        adapter=adapter,
        prop=prop,
        runs_root=runs_root,
        library_root=lib_root,
        modes=("agg", "seq"),
        max_tasks=2,
    )
    assert rep["domains"][0]["done"] == 2
    assert rep["domains"][0]["failed"] == 0

    # Verify library INDEX.md and EXPERIENCE.md were created for the first task
    index_md = lib_root / "agg" / "openspec-sts" / "INDEX.md"
    assert index_md.is_file()
    assert "artifact-security-gate" in index_md.read_text(encoding="utf-8")

    # Judge the selections and verify 100% score
    selections = []
    for tid in ("artifact-security-gate", "m2m-token-exchange"):
        ns = schedule.Namespace("openspec", "oc", "agg", 1)
        summary = ns.task_dir(runs_root, tid) / "summary.json"
        assert summary.is_file()
        import json

        data = json.loads(summary.read_text(encoding="utf-8"))
        for mode in ("agg", "seq"):
            selections.append(data["selections"][mode])

    scored = judge.judge_selections(adapter, selections)
    summaries = report.summarise(scored)
    for s in summaries:
        assert s.score == 100.0
        assert s.all_pass == 100.0
