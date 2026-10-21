# Proposal: Multi-Architecture Binary and Container Rock Support

## Why

The Secure Token Service now builds its Go binary and container rock only for `amd64`. Operators who run Kubernetes clusters on `arm64` nodes need native `arm64` container images, and developers need early verification that the Go binary compiles cleanly on `amd64`, `arm64`, and `riscv64`.

## What Changes

- **Multi-Architecture Go Binary Compilation**: Parameterize `GOOS` and `GOARCH` in `Makefile` and verify in `.github/workflows/unittest.yaml` (`make build-all`) that the Go binary compiles for all three architectures: `amd64`, `arm64`, and `riscv64`.
- **Two-Architecture Container Rock Definition**: Add `arm64` alongside `amd64` in the `platforms` map of `rockcraft.yaml` and pass `GOARCH="${CRAFT_ARCH_BUILD_FOR}"` to the Go build step.
- **Dynamic CI Rock Build Matrix**: Add a `get-architectures` job in `.github/workflows/ci.yaml` that reads the two supported rock platforms (`amd64` and `arm64`) from `rockcraft.yaml` and runs `_rock-build.yaml` in a matrix.
- **Multi-Architecture Manifest Publication**: Update `gh-publish-branch` and `gh-publish-candidate` in `.github/workflows/ci.yaml` to omit the single-rock input so `_rock-gh-publish.yaml` publishes a multi-architecture OCI manifest list for `amd64` and `arm64`.
- **Container and Local Tooling Alignment**: Parameterize `TARGETOS` and `TARGETARCH` in `Dockerfile`, detect the host architecture dynamically in `build.sh`, and configure `linux/amd64` and `linux/arm64` in `skaffold.yaml`.

## Non-goals

- We do not build or publish container images or rocks for `riscv64` (only the Go binary compiles for `riscv64`).
- We do not change the runtime business logic, HTTP endpoints, or gRPC APIs of the Secure Token Service.
- We do not replace `rockcraft`, `skopeo`, or `trivy` in the continuous integration workflows.

## Success Metrics

- The `unittest.yaml` workflow (`make build-all`) compiles the Go binary for all three target architectures (`amd64`, `arm64`, and `riscv64`) with zero errors on every pull request.
- The CI pipeline builds, tests, and publishes native container rocks for the two supported image architectures (`amd64` and `arm64`) under one multi-architecture OCI manifest tag in GHCR.
- Developers on `amd64` and `arm64` hosts run `make build`, `make build-all`, and `./build.sh` without manual script edits.

## Capabilities

### New Capabilities
- `multi-arch-artifacts`: Defines requirements for three-architecture Go binary compilation (`amd64`, `arm64`, `riscv64`) and two-architecture container image packaging and publication (`amd64`, `arm64`).

### Modified Capabilities
- `artifact-security-gate`: Multi-architecture binary build verification (`amd64`, `arm64`, `riscv64`) and manifest-preserving candidate promotion (`amd64` and `arm64`) to `stable` and `<version>` tags.

## Impact

- **Rock Configuration**: [rockcraft.yaml](../../../rockcraft.yaml) (`platforms` for `amd64` and `arm64`, and `parts.go-build.override-build`).
- **CI Workflows**: [.github/workflows/ci.yaml](../../../.github/workflows/ci.yaml) and [.github/workflows/unittest.yaml](../../../.github/workflows/unittest.yaml).
- **Build & Developer Tooling**: [Makefile](../../../Makefile), [Dockerfile](../../../Dockerfile), [build.sh](../../../build.sh), and [skaffold.yaml](../../../skaffold.yaml).
- **Upstream Reusable Workflows**: `canonical/identity-team` (`_rock-build.yaml`, `_rock-gh-publish.yaml`, `_rock-scan.yaml`, `_rock-promote.yaml`).
