#!/usr/bin/env python3
"""Deterministic OpenSpec code-to-spec drift checker for the STS repository.

Thin shim over the shared `openspec_harness` package (installed from
`canonical/identity-team`, pinned in `.harness2/requirements.txt`), kept at
`scripts/` so the `make harness2-*` targets, CI, and the harness2 `c7`
surface can keep invoking `python3 scripts/check_openspec_drift.py`
unchanged.
"""

from __future__ import annotations

import sys

try:
    from openspec_harness.drift import main
except ImportError:  # pragma: no cover
    sys.exit(
        "openspec-harness is not installed: run `make harness2-deps` "
        "(python3 -m pip install -r .harness2/requirements.txt)"
    )

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
