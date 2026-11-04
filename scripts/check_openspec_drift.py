#!/usr/bin/env python3
"""Deterministic OpenSpec code-to-spec drift checker for the STS repository.

Thin shim over `openspec_harness.drift` (the declarative engine reading
`openspec/drift-checks.yaml`), kept at `scripts/` so the `make harness2-*`
targets, CI, and the harness2 `c7` surface can keep invoking
`python3 scripts/check_openspec_drift.py` unchanged.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PKG_ROOT = _REPO_ROOT / ".harness2"
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from openspec_harness.drift import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))