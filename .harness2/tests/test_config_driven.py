"""Tests for the manifest-driven adapter and the shared config-driven engines."""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from openspec_harness import OpenSpecAdapter
from openspec_harness.adapter import RUNTIME_SCRIPTS, load_harness_manifest
from openspec_harness.drift import check_drift, load_drift_config
from openspec_harness.init import init_repository
from openspec_harness.validation import load_validation_settings, validate_workspace

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_openspec_config_validation_block_parsed() -> None:
    """`openspec/config.yaml` carries the strict `validation:` settings the
    generic engine reads, and the fixture baseline stays in sync."""
    for cfg in (
        REPO_ROOT / "openspec" / "config.yaml",
        REPO_ROOT / ".harness2" / "fixtures" / "openspec_baseline" / "openspec" / "config.yaml",
    ):
        data = yaml.safe_load(cfg.read_text(encoding="utf-8"))
        v = data["validation"]
        assert v["max_requirement_chars"] == 500
        assert v["require_mermaid_in_design"] is True
        assert "Why" in v["proposal_sections"]
        assert "Verification Suite" in v["tasks_checkbox_sections"]

    settings = load_validation_settings(REPO_ROOT)
    assert settings["max_requirement_chars"] == 500
    assert settings["require_mermaid_in_design"] is True


def test_validation_settings_defaults_without_config() -> None:
    """A repository without `openspec/config.yaml` inherits the strict defaults."""
    empty = Path("/tmp/openspec-harness-empty-repo")
    shutil.rmtree(empty, ignore_errors=True)
    empty.mkdir(parents=True)
    try:
        (empty / "openspec").mkdir()
        settings = load_validation_settings(empty)
        assert settings == load_validation_settings(Path("/nonexistent"))
        assert settings["max_requirement_chars"] == 500
        assert settings["require_mermaid_in_design"] is True
        assert len(settings["proposal_sections"]) == 6
    finally:
        shutil.rmtree(empty, ignore_errors=True)


def test_drift_config_declarative_and_config_driven() -> None:
    """`openspec/drift-checks.yaml` drives `check_drift` end to end: the same
    12 checks pass via `--config` as via the scripts/ shim."""
    cfg_path = REPO_ROOT / "openspec" / "drift-checks.yaml"
    data = load_drift_config(cfg_path)
    assert data["version"] == 1
    assert set(data["checks"]) >= {
        "artifact-security-gate",
        "m2m-token-exchange",
        "support-multi-arch-rocks-and-pipelines",
        "support-ubuntu-one-openid",
    }

    report = check_drift(REPO_ROOT, config_path=cfg_path)
    assert report["checks_total"] == 12
    assert report["all_checks_ok"], report["findings"]

    scoped = check_drift(REPO_ROOT, target_id="m2m-token-exchange", config_path=cfg_path)
    assert scoped["checks_total"] == 3
    assert {c["id"].split(":", 1)[0] for c in scoped["checks"]} == {"m2m-token-exchange"}


def test_harness_manifest_drives_adapter() -> None:
    """`openspec/harness.yaml` is the single source of adapter state: tasks,
    domain, and repo symlinks come from the manifest, not the adapter code."""
    manifest = load_harness_manifest(REPO_ROOT)
    assert manifest["domain"] == "openspec-sts"
    assert "api" in manifest["repo_symlinks"]
    assert set(manifest["tasks"]) == {
        "artifact-security-gate",
        "m2m-token-exchange",
        "support-multi-arch-rocks-and-pipelines",
        "support-ubuntu-one-openid",
    }

    adapter = OpenSpecAdapter(REPO_ROOT, runs_root=Path("/tmp/x-runs"))
    assert adapter.domain == manifest["domain"]
    assert adapter.tasks() == list(manifest["tasks"].keys())
    assert adapter.task_prompt("m2m-token-exchange") == manifest["tasks"]["m2m-token-exchange"]["prompt"]
    assert adapter.spec.reserved_scripts == RUNTIME_SCRIPTS


def test_validate_workspace_matches_config_drift_totals() -> None:
    """The config-driven engines produce the same totals the audit command reports."""
    v = validate_workspace(REPO_ROOT, repo_root=REPO_ROOT)
    assert v["all_checks_ok"], v["findings"]
    d = check_drift(REPO_ROOT)
    assert d["all_checks_ok"], d["findings"]
    assert v["checks_total"] == 42
    assert d["checks_total"] == 12


def test_init_scaffolds_missing_pieces_idempotently(tmp_path: Path) -> None:
    """`init` generates the per-repo pieces into a bare repo, keeps existing
    files untouched, and its manifest validates."""
    repo = tmp_path / "example-service"
    (repo / "openspec" / "changes" / "add-login").mkdir(parents=True)
    (repo / "Makefile").write_text("build:\n\tgo build ./...\n", encoding="utf-8")

    written = init_repository(repo)
    names = {p.name for p in written}
    assert {"drift-checks.yaml", "harness.yaml", "validate_openspec.py", "check_openspec_drift.py"} <= names
    assert "harness2-audit:" in (repo / "Makefile").read_text(encoding="utf-8")

    # Idempotent: a second run writes nothing and keeps file contents.
    again = init_repository(repo)
    assert again == []

    # The scaffolded manifest validates against the loader.
    manifest = load_harness_manifest(repo)
    assert manifest["domain"] == "openspec-example-service"
    assert "add-login" in manifest["tasks"]