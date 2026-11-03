# artifact-security-gate Specification

## Purpose
The artifact security gate guarantees that no container image or release artifact is published to `stable` with known un-triaged security vulnerabilities, enforces shift-left Go vulnerability and multi-architecture binary checks before container builds, and runs continuous scheduled scans on published artifacts.

## Requirements

### Requirement: Pull request vulnerability pre-check
The test verification workflow SHALL run static vulnerability analysis on Go dependencies and verify `linux/amd64` (`x86-64`), `linux/arm64` (`aarch64`), and `linux/riscv64` (`RISC-V`) ELF binaries before starting container builds. Any reachable high or critical vulnerability or binary build/architecture mismatch SHALL fail the workflow and skip image builds.

#### Scenario: Clean dependencies in pull request
- **WHEN** a pull request has no known vulnerable Go dependencies and builds and verifies ELF binaries for `linux/amd64` (`x86-64`), `linux/arm64` (`aarch64`), and `linux/riscv64` (`RISC-V`)
- **THEN** vulnerability and binary build checks exit with code `0`
- **THEN** the workflow proceeds to build the container rock artifacts for the supported image architectures (`amd64` and `arm64`)

#### Scenario: Vulnerability detected in pull request
- **WHEN** a pull request introduces a dependency with a known reachable vulnerability
- **THEN** vulnerability checks exit with a non-zero exit code
- **THEN** the container rock build matrix jobs (`amd64` and `arm64`) do not run

### Requirement: Release quarantine and pre-release tagging
When a release PR is merged, the release automation SHALL create the GitHub Release marked as a pre-release (`prerelease: true`) and SHALL NOT mark it as latest or stable.

#### Scenario: Release cut marks pre-release
- **WHEN** an automated release PR is merged into main
- **THEN** release automation cuts a release with `prerelease: true`
- **THEN** the release is not marked as the latest stable release in GitHub

### Requirement: Candidate artifact scanning and promotion gate
The release pipeline SHALL publish `amd64` and `arm64` artifacts to candidate tags (`<version>-candidate`, `<version>-candidate-amd64`, `<version>-candidate-arm64`) and scan the candidate image before promoting to `stable`. Promotion to `stable` and `<version>` (via `skopeo copy --all` preserving both architectures) and release graduation SHALL occur ONLY after a clean scan.

#### Scenario: Clean candidate promoted to stable
- **WHEN** the candidate container image scan completes with zero blocking vulnerabilities
- **THEN** the promotion job copies the complete `amd64` and `arm64` OCI manifest list to `stable` and `<version>` in the container registry (verified via `docker manifest inspect`)
- **THEN** the GitHub Release updates to `prerelease: false` and marks the release as latest

#### Scenario: Vulnerable candidate blocked from promotion
- **WHEN** the candidate container image scan detects an un-triaged blocking vulnerability
- **THEN** the security scan job fails with a non-zero exit code
- **THEN** the workflow does NOT tag the image as `stable` in the container registry
- **THEN** the GitHub Release remains quarantined as a pre-release

### Requirement: Continuous security scanning of published artifacts
The CI system SHALL execute scheduled vulnerability scans against the active `stable` container image and the default branch to detect newly disclosed CVEs.

#### Scenario: Scheduled scan on stable image
- **WHEN** the scheduled security workflow triggers
- **THEN** the scanner evaluates `ghcr.io/canonical/secure-token-service:stable` for newly disclosed vulnerabilities
- **THEN** any findings are published to the repository security advisory system
