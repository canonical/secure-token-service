#!/usr/bin/env python3
"""Deterministic OpenSpec code-to-spec drift analyzer for Secure Token Service (Janus).

Used as a harness2 c7 verification script (`python3 scripts/check_openspec_drift.py`)
to verify that OpenSpec capabilities and change specifications align with the Go 1.26
codebase, Protobuf contracts, Rockcraft packaging, and CI workflows.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _file_contains(root: Path, rel_path: str, needles: tuple[str, ...]) -> tuple[bool, list[str]]:
    p = root / rel_path
    if not p.is_file():
        return False, [f"missing file {rel_path}"]
    text = p.read_text(encoding="utf-8", errors="replace")
    missing = [n for n in needles if n not in text]
    return not missing, [f"{rel_path} missing '{m}'" for m in missing]


def check_drift(repo_root: Path, *, target_id: str | None = None) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    checks: list[dict[str, Any]] = []

    def add_check(cid: str, task: str, rel_path: str, needles: tuple[str, ...]) -> None:
        if target_id and target_id != task:
            return
        ok, missing = _file_contains(repo_root, rel_path, needles)
        checks.append(
            {
                "id": f"{task}:{cid}",
                "ok": ok,
                "detail": (
                    f"{rel_path} satisfies {cid}"
                    if ok
                    else f"Drift in {task} ({cid}): {'; '.join(missing)}"
                ),
            }
        )

    # 1. artifact-security-gate
    add_check(
        "pr_vuln_and_elf_gate",
        "artifact-security-gate",
        ".github/workflows/unittest.yaml",
        ("make govulncheck", "make build-all", "x86-64", "aarch64", "RISC-V"),
    )
    add_check(
        "candidate_scan_and_promote_gate",
        "artifact-security-gate",
        ".github/workflows/ci.yaml",
        ("_rock-scan.yaml", "_rock-promote.yaml", "gh-publish-candidate"),
    )

    # 2. m2m-token-exchange
    add_check(
        "proto_exchange_token_rpc",
        "m2m-token-exchange",
        "api/proto/v1/sts.proto",
        ("rpc ExchangeToken", "ExchangeTokenRequest", "ExchangeResponse"),
    )
    add_check(
        "hydra_preemptive_jwks_verifier",
        "m2m-token-exchange",
        "internal/auth/hydra.go",
        ("HydraTokenVerifier", "jwk.NewCache", "ErrTokenExpiringSoon", "5 * time.Second"),
    )
    add_check(
        "grpc_exchange_token_handler",
        "m2m-token-exchange",
        "internal/grpc/server.go",
        ("ExchangeToken", "65536", "@serviceaccount.local", "codes.InvalidArgument", "codes.Unauthenticated"),
    )

    # 3. support-multi-arch-rocks-and-pipelines
    add_check(
        "makefile_three_arch_binaries",
        "support-multi-arch-rocks-and-pipelines",
        "Makefile",
        ("BINARY_ARCHS?=amd64 arm64 riscv64", "build-all:"),
    )
    add_check(
        "rockcraft_two_arch_platforms",
        "support-multi-arch-rocks-and-pipelines",
        "rockcraft.yaml",
        ("amd64:", "arm64:", "CRAFT_ARCH_BUILD_FOR"),
    )
    add_check(
        "skaffold_and_dockerfile_multiarch",
        "support-multi-arch-rocks-and-pipelines",
        "skaffold.yaml",
        ("linux/amd64", "linux/arm64"),
    )

    # 4. support-ubuntu-one-openid
    add_check(
        "ubuntu_one_openid_client",
        "support-ubuntu-one-openid",
        "internal/auth/openid/ubuntuone.go",
        ("check_authentication", "openid.ns.sreg", "openid.ns.ax", "response_nonce"),
    )
    add_check(
        "standardized_cookie_manager",
        "support-ubuntu-one-openid",
        "internal/cookie/cookie.go",
        ("SetSessionCookie", "ClearSessionCookie", "SameSiteLaxMode", "X-Forwarded-Proto"),
    )
    add_check(
        "http_openid_callback_route",
        "support-ubuntu-one-openid",
        "internal/http/server.go",
        ("/auth/openid/callback", "handleOpenIDCallback", "handleLogin"),
    )
    add_check(
        "openapi_provider_and_callback_contract",
        "support-ubuntu-one-openid",
        "docs/api/openapi.yaml",
        ("/auth/openid/callback", "provider"),
    )

    total = len(checks)
    ok_count = sum(1 for c in checks if c["ok"])
    failed = [c for c in checks if not c["ok"]]
    return {
        "repo_root": str(repo_root),
        "target_id": target_id or "all",
        "checks_total": total,
        "checks_ok": ok_count,
        "checks_failed": len(failed),
        "all_checks_ok": total > 0 and len(failed) == 0,
        "checks": checks,
        "findings": [c["detail"] for c in failed],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check OpenSpec specs against STS Go codebase for drift.")
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument("--target", default=None, help="Optional single spec or change id")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--quiet", action="store_true", help="Only output on failure")
    args = parser.parse_args(argv)

    report = check_drift(Path(args.repo_root), target_id=args.target)
    if args.json:
        print(json.dumps(report, indent=2))
    elif not args.quiet or not report["all_checks_ok"]:
        status = "OK" if report["all_checks_ok"] else "DRIFT_DETECTED"
        print(
            f"[check_openspec_drift] {status}: {report['checks_ok']}/{report['checks_total']} code-to-spec checks aligned"
        )
        for f in report["findings"]:
            print(f"  - {f}")
    return 0 if report["all_checks_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
