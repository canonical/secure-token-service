"""CLI entrypoint for Google's harness2 + OpenSpec integration."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from harness2.core import tree as harness_tree
from harness2.substrate.omp import OMP_SURFACE
from harness2.substrate.opencode import OPENCODE_SURFACE

from . import RUNTIME_SCRIPTS


def _repo_root() -> Path:
    return Path.cwd()


def _census(surface: harness_tree.SurfaceSpec, t: harness_tree.Tree) -> dict[str, int]:
    counts = {
        "files": len(t),
        "always_on_chars": len(harness_tree.always_on_text(surface, t)),
        "skills": 0,
        "sub_agents": 0,
        "commands": 0,
        "scripts": 0,
        "plugins": 0,
        "hooks": 0,
    }
    skill_prefix = surface.skill_dir + "/"
    plugin_prefix = (surface.plugin_dir + "/") if surface.plugin_dir else None
    for rel in t:
        if rel.startswith(skill_prefix) and rel.endswith("/SKILL.md"):
            counts["skills"] += 1
        elif rel.startswith("sub_agents/") and rel.endswith("/AGENT.md"):
            counts["sub_agents"] += 1
        elif rel.startswith("commands/") and rel.endswith(".md"):
            counts["commands"] += 1
        elif rel.startswith("scripts/"):
            counts["scripts"] += 1
        elif plugin_prefix and rel.startswith(plugin_prefix):
            counts["plugins"] += 1
        elif surface.hooks_file and rel == surface.hooks_file:
            counts["hooks"] += 1
    return counts


def cmd_validate_harnesses(args: argparse.Namespace) -> int:
    root = _repo_root()
    h2 = root / ".harness2" / "harnesses"
    targets = [
        ("opencode_seed", h2 / "opencode_seed", OPENCODE_SURFACE),
        ("opencode_base", h2 / "opencode_base", OPENCODE_SURFACE),
        ("omp_seed", h2 / "omp_seed", OMP_SURFACE),
        ("omp_base", h2 / "omp_base", OMP_SURFACE),
    ]
    rows = []
    for name, path, surface in targets:
        rejected: list[str] = []
        t = harness_tree.read_tree(surface, path, rejected=rejected)
        if rejected:
            print(f"[FAIL] {name}: off-surface files: {rejected}", file=sys.stderr)
            return 1
        harness_tree.validate(
            surface,
            t,
            allow_subagents=True,
            reserved_scripts=harness_tree.RESERVED_SCRIPTS | RUNTIME_SCRIPTS,
        )
        c = _census(surface, t)
        rows.append({"name": name, "surface": surface.name, "cap": surface.always_on_max, **c})

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print("harness2 c1..c8 Surface Validation")
        print("=" * 72)
        for r in rows:
            print(
                f"  [PASS] {r['name']:<15} ({r['surface']:<8}) | "
                f"always-on: {r['always_on_chars']:>5,}/{r['cap']:,} chars | "
                f"files={r['files']} skills={r['skills']} sub_agents={r['sub_agents']} "
                f"scripts={r['scripts']} plugins={r['plugins']} hooks={r['hooks']}"
            )
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    from .drift import check_drift
    from .validation import validate_workspace

    root = Path(args.repo_root).resolve() if args.repo_root else _repo_root()
    target_root = Path(args.root).resolve() if args.root else root
    v = validate_workspace(target_root, repo_root=root, target_id=args.item)
    d = check_drift(root, target_id=args.item)
    ok = bool(v["all_checks_ok"] and d["all_checks_ok"])
    if args.json:
        print(json.dumps({"validation": v, "drift": d, "ok": ok}, indent=2))
        return 0 if ok else 1

    v_status = "OK" if v["all_checks_ok"] else "FAILED"
    print(
        f"[validate_openspec] {v_status}: {v['checks_ok']}/{v['checks_total']} checks succeeded "
        f"(target={v['target_id']})"
    )
    for f in v["findings"]:
        print(f"  - {f}")
    print()
    d_status = "OK" if d["all_checks_ok"] else "DRIFT_DETECTED"
    print(
        f"[check_openspec_drift] {d_status}: {d['checks_ok']}/{d['checks_total']} "
        f"code-to-spec checks aligned (config={d['config']})"
    )
    for f in d["findings"]:
        print(f"  - {f}")
    return 0 if ok else 1


def cmd_init(args: argparse.Namespace) -> int:
    from .init import init_repository

    repo = Path(args.root).resolve() if getattr(args, "root", None) else _repo_root()
    written = init_repository(repo)
    print(f"Scaffolded {len(written)} file(s) under {repo}.")
    print("Next: edit openspec/drift-checks.yaml checks.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="openspec-harness",
        description="Google harness2 recursive agent harness for OpenSpec",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Scaffold OpenSpec harness config for this repository")
    p_init.add_argument("--root", type=str, default=None, help="Repository root (default: current directory)")
    p_init.set_defaults(func=cmd_init)

    p_val = sub.add_parser("validate-harnesses", help="Validate c1..c8 harness surfaces")
    p_val.add_argument("--json", action="store_true")
    p_val.set_defaults(func=cmd_validate_harnesses)

    p_aud = sub.add_parser("audit", help="Run deterministic OpenSpec strict + code-drift checks")
    p_aud.add_argument("--root", type=str, default=None)
    p_aud.add_argument("--repo-root", type=str, default=None, help="Repository root (default: current directory)")
    p_aud.add_argument("--item", type=str, default=None)
    p_aud.add_argument("--json", action="store_true")
    p_aud.set_defaults(func=cmd_audit)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
