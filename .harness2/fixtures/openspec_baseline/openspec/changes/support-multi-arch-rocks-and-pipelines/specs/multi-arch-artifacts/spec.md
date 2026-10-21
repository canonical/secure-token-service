# multi-arch-artifacts Specification

## Purpose

This specification defines how the Secure Token Service compiles Go binaries for `amd64`, `arm64`, and `riscv64`, and how it packs and publishes OCI container images for the two supported image architectures (`amd64` and `arm64`). It maintains full backward compatibility with existing `amd64` deployments.

## ADDED Requirements

### Requirement: Three-architecture Go binary compilation
The build system (`Makefile` and `.github/workflows/unittest.yaml`) SHALL compile static Go binaries (`CGO_ENABLED=0`) for `linux/amd64`, `linux/arm64`, and `linux/riscv64` and verify their ELF target architectures (`x86-64`, `aarch64`, and `RISC-V`) on every pull request and branch push.

#### Scenario: Pull request compiles binaries for amd64, arm64, and riscv64
- **WHEN** `.github/workflows/unittest.yaml` runs on a pull request or push event
- **THEN** the workflow runs `make build-all` and compiles `./cmd/sts` for `amd64`, `arm64`, and `riscv64`
- **AND** the workflow verifies each binary's ELF architecture with `file` (`x86-64`, `aarch64`, `RISC-V`)
- **AND** the steps exit with code `0`

#### Scenario: Architecture-specific compilation error fails unit test workflow
- **WHEN** a code change introduces a package or syscall that fails to compile for `amd64`, `arm64`, or `riscv64` or produces an unexpected ELF target
- **THEN** the `make build-all` or binary verification step exits with a non-zero code
- **AND** the workflow blocks the pull request before container image builds start

### Requirement: Two-architecture container image and Rockcraft definition
The container packaging configuration (`rockcraft.yaml`, `Dockerfile`, `build.sh`, and `skaffold.yaml`) SHALL support only the `amd64` and `arm64` image architectures. The `rockcraft.yaml` manifest SHALL declare `amd64` and `arm64` under `platforms` and pass `GOARCH="${CRAFT_ARCH_BUILD_FOR}"` and `CGO_ENABLED=0` to the `go-build` part. This requirement preserves backward compatibility for existing `amd64` deployments.

#### Scenario: Pack rock for amd64 target
- **WHEN** Rockcraft packs the project for the `amd64` platform
- **THEN** the `go-build` part compiles a static `linux/amd64` ELF binary at `/usr/bin/app`
- **AND** Rockcraft outputs `secure-token-service_<version>_amd64.rock`

#### Scenario: Pack rock for arm64 target
- **WHEN** Rockcraft packs the project for the `arm64` platform
- **THEN** the `go-build` part compiles a static `linux/arm64` ELF binary at `/usr/bin/app`
- **AND** Rockcraft outputs `secure-token-service_<version>_arm64.rock`

#### Scenario: Local build script detects and validates host architecture dynamically
- **WHEN** a developer runs `./build.sh` on an `amd64` or `arm64` Linux host
- **THEN** `build.sh` resolves the host architecture via `dpkg --print-architecture` (or `ARCH` override), validates that `ARCH` is `amd64` or `arm64`, and rejects unsupported rock architectures (such as `riscv64`) with a non-zero exit code
- **AND** `build.sh` loads `secure-token-service_<version>_<arch>.rock` without manual script edits

### Requirement: Dynamic CI rock build matrix for supported image architectures
The continuous integration workflow (`.github/workflows/ci.yaml`) SHALL read the platform keys (`amd64` and `arm64`) from `rockcraft.yaml` in a `get-architectures` job. The `build` job SHALL run `_rock-build.yaml` in a matrix for each supported image platform after `unit-test` succeeds.

#### Scenario: Matrix build runs for amd64 and arm64
- **WHEN** a pull request or branch push triggers `.github/workflows/ci.yaml` and `unit-test` passes
- **THEN** `get-architectures` outputs `["amd64","arm64"]` from `rockcraft.yaml`
- **AND** the `build` job starts parallel rock builds for `amd64` and `arm64`

#### Scenario: Unit test failure skips all matrix rock builds
- **WHEN** the `unit-test` job fails on a pull request or push event
- **THEN** the `build` matrix job does not start for any architecture

#### Scenario: Invalid platform configuration fails architecture discovery
- **WHEN** `rockcraft.yaml` omits the `platforms` map or contains invalid YAML syntax
- **THEN** the `get-architectures` job fails with a non-zero exit code
- **AND** the pipeline stops before the `build` job starts

### Requirement: Multi-architecture OCI manifest publication and promotion
The `gh-publish-branch` and `gh-publish-candidate` jobs in `.github/workflows/ci.yaml` SHALL collect the `amd64` and `arm64` rock artifacts from the `build` matrix and publish a multi-architecture OCI manifest list to GHCR.

#### Scenario: Main branch push publishes multi-architecture manifest list
- **WHEN** a commit merges to `main` and both `amd64` and `arm64` matrix `build` jobs succeed
- **THEN** `gh-publish-branch` pushes the `amd64` and `arm64` images to GHCR
- **AND** `gh-publish-branch` creates a multi-architecture OCI manifest list for `latest` and `<sha>`

#### Scenario: Release tag publishes and scans multi-architecture candidate manifest
- **WHEN** a release tag `vX.Y.Z` triggers `.github/workflows/ci.yaml` and all matrix `build` jobs succeed
- **THEN** `gh-publish-candidate` publishes a multi-architecture OCI manifest list for `vX.Y.Z-candidate`
- **AND** the `scan` job checks the candidate image before the `promote` job updates `stable` and `vX.Y.Z`

#### Scenario: Single architecture build failure blocks manifest publication
- **WHEN** the `arm64` matrix job fails while the `amd64` matrix job succeeds
- **THEN** the `build` stage fails
- **AND** the pipeline skips `gh-publish-branch` and `gh-publish-candidate`
