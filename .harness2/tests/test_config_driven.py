"""STS-specific tests for the shared config-driven engines (installed from
canonical/identity-team; the engine's own packaged suite lives there)."""

from __future__ import annotations

from pathlib import Path

import yaml

from openspec_harness.drift import check_drift, load_drift_config
from openspec_harness.validation import load_validation_settings, validate_workspace

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_openspec_config_validation_block_parsed() -> None:
    """`openspec/config.yaml` carries the strict `validation:` settings the
    generic engine reads."""
    data = yaml.safe_load((REPO_ROOT / "openspec" / "config.yaml").read_text(encoding="utf-8"))
    v = data["validation"]
    assert v["max_requirement_chars"] == 500
    assert v["require_mermaid_in_design"] is True
    assert "Why" in v["proposal_sections"]
    assert "Verification Suite" in v["tasks_checkbox_sections"]

    settings = load_validation_settings(REPO_ROOT)
    assert settings["max_requirement_chars"] == 500
    assert settings["require_mermaid_in_design"] is True


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


def test_validate_workspace_matches_config_drift_totals() -> None:
    """The config-driven engines produce the same totals the audit command reports."""
    v = validate_workspace(REPO_ROOT, repo_root=REPO_ROOT)
    assert v["all_checks_ok"], v["findings"]
    d = check_drift(REPO_ROOT)
    assert d["all_checks_ok"], d["findings"]
    assert v["checks_total"] == 42
    assert d["checks_total"] == 12
