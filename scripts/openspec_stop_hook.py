#!/usr/bin/env python3
"""Antigravity / agent Stop-hook guard for OpenSpec validation and drift checks.

Reads the Stop-hook JSON payload from stdin and outputs a JSON decision
(`{"decision": "allow"}` or `{"decision": "continue", "reason": "..."}`) on
stdout.

Loop prevention:
- Always returns `allow` when `continuationActive` is true, `stop_hook_active` /
  `stopHookActive` is true, `executionNum > 0`, `error` is non-empty, or
  `terminationReason` is present and not `"NO_TOOL_CALL"` (e.g. `USER_CANCELED`,
  `ERROR`, `MAX_INVOCATIONS`, `MAX_FORCED_INVOCATIONS`,
  `MAX_TOKEN_BUDGET_EXCEEDED`).
- Consequently, this hook can ask the agent to continue at most once per turn
  and will never cause an infinite loop on pre-existing drift or read-only
  (explore) sessions.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

CONTINUE_REASON = (
    "OpenSpec validation or code-to-spec drift checks failed. "
    "Run python3 scripts/validate_openspec.py and python3 scripts/check_openspec_drift.py "
    "and resolve all errors before finishing."
)

DEFAULT_CHECK_TIMEOUT_SECS = 20


def _parse_payload(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _should_allow_without_checks(payload: dict[str, Any]) -> bool:
    """Return True when the Stop hook must allow termination to avoid loops."""
    if payload.get("continuationActive") is True:
        return True
    if payload.get("stop_hook_active") is True or payload.get("stopHookActive") is True:
        return True

    exec_num = payload.get("executionNum")
    if isinstance(exec_num, (int, float)) and not isinstance(exec_num, bool) and exec_num > 0:
        return True

    if str(payload.get("error") or "").strip():
        return True

    term_reason = str(payload.get("terminationReason") or "").strip()
    if term_reason and term_reason != "NO_TOOL_CALL":
        return True

    return False


def _run_check(cmd: list[str], cwd: Path, timeout: int = DEFAULT_CHECK_TIMEOUT_SECS) -> bool:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def evaluate_stop_hook(
    payload: dict[str, Any],
    repo_root: Path,
    *,
    timeout: int = DEFAULT_CHECK_TIMEOUT_SECS,
) -> dict[str, str]:
    """Evaluate whether the agent may stop, enforcing single-continuation loop safety."""
    if _should_allow_without_checks(payload):
        return {"decision": "allow"}

    validate_ok = _run_check(
        [sys.executable, str(repo_root / "scripts" / "validate_openspec.py"), "--quiet"],
        cwd=repo_root,
        timeout=timeout,
    )
    drift_ok = validate_ok and _run_check(
        [sys.executable, str(repo_root / "scripts" / "check_openspec_drift.py"), "--quiet"],
        cwd=repo_root,
        timeout=timeout,
    )

    if validate_ok and drift_ok:
        return {"decision": "allow"}
    return {"decision": "continue", "reason": CONTINUE_REASON}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OpenSpec Stop hook with loop prevention.")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root containing scripts/validate_openspec.py and scripts/check_openspec_drift.py.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_CHECK_TIMEOUT_SECS,
        help="Per-check subprocess timeout in seconds.",
    )
    args = parser.parse_args(argv)

    raw_stdin = "" if sys.stdin.isatty() else sys.stdin.read()
    payload = _parse_payload(raw_stdin)
    result = evaluate_stop_hook(payload, args.repo_root.resolve(), timeout=args.timeout)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
