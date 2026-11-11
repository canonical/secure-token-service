---
name: openspec-drift
description: Check code-to-spec alignment between OpenSpec specifications and the Go 1.26 STS implementation.
---

Run `python3 scripts/check_openspec_drift.py` and `python3 scripts/validate_openspec.py`, cross-check `## Purpose` and `## Implementation Notes` against `internal/`, `api/proto/v1/sts.proto`, `rockcraft.yaml`, and `.github/workflows/`, and remediate any detected drift.
