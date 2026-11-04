#!/usr/bin/env python3
"""Deterministic OpenSpec structural, strict-CLI, and link validator for the STS repository.

Thin shim over `openspec_harness.validation` (the generic, config-driven engine
reading `validation:` from `openspec/config.yaml`), kept at `scripts/` so the
`make harness2-*` targets, CI, and the harness2 `c7` surface can keep invoking
`python3 scripts/validate_openspec.py` unchanged.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PKG_ROOT = _REPO_ROOT / ".harness2"
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from openspec_harness.validation import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))