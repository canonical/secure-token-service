# Tool Routing & Verification Guidance (`c4`)

## 1. OpenSpec & Deterministic Verification Tools (`c7`)
- **Strict Structural & Link Validator**:
  ```bash
  python3 scripts/validate_openspec.py
  ```
  Runs `openspec validate --all --strict --json`, verifies all `openspec/config.yaml` section contracts, checks requirement body lengths (`<= 500` chars), checks `## Purpose` sections for placeholders, and verifies that every relative Markdown link resolves on disk.
- **Code-to-Spec Drift Detector**:
  ```bash
  python3 scripts/check_openspec_drift.py
  ```
  Cross-checks OpenSpec requirements against Go packages (`internal/auth`, `internal/cookie`, `internal/grpc`, `internal/http`, `internal/session`), Protobuf definitions (`api/proto/v1/sts.proto`), `Makefile`, `rockcraft.yaml`, and `.github/workflows/`.
- **OpenSpec CLI**:
  - `openspec validate --all --strict --json`: Strict validation across all specs and changes.
  - `openspec status --change <id> --json`: Inspect artifact completion status for a change.

## 2. Go 1.26 Build & Test Tools
- `make test-short`: Run unit tests with `-short -cover`.
- `make build-all`: Cross-compile static Linux binaries for `amd64`, `arm64`, and `riscv64`.
- `make vet` / `make lint`: Run `go vet ./...` and `golangci-lint run`.
