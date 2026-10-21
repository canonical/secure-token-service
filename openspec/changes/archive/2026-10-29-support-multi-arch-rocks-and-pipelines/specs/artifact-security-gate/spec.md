# Spec Delta

## Purpose
Extends the Secure Token Service artifact security gate to verify three-architecture static Go binary compilation (`linux/amd64`, `linux/arm64`, `linux/riscv64`) before container builds and preserve multi-architecture (`amd64`, `arm64`) OCI manifest lists during Trivy-gated candidate promotion.

## MODIFIED Requirements

### Requirement: Pull request vulnerability pre-check
The test verification workflow SHALL run static Go dependency vulnerability analysis and compile and verify static ELF binaries for `linux/amd64` (`x86-64`), `linux/arm64` (`aarch64`), and `linux/riscv64` (`RISC-V`) before starting container image builds. If any reachable vulnerability is detected or any target binary fails compilation or ELF verification, the workflow SHALL fail and skip container rock builds.

#### Scenario: Clean dependencies in pull request
- **WHEN** a pull request has no known vulnerable Go dependencies and builds and verifies ELF binaries for `linux/amd64` (`x86-64`), `linux/arm64` (`aarch64`), and `linux/riscv64` (`RISC-V`)
- **THEN** vulnerability and binary build checks exit with code `0`
- **THEN** the workflow proceeds to build the container rock artifacts for the supported image architectures (`amd64` and `arm64`)

#### Scenario: Vulnerability detected in pull request
- **WHEN** a pull request introduces a dependency with a known reachable vulnerability
- **THEN** vulnerability checks exit with a non-zero exit code
- **THEN** the container rock build matrix jobs (`amd64` and `arm64`) do not run

### Requirement: Candidate artifact scanning and promotion gate
The release pipeline SHALL publish `amd64` and `arm64` container artifacts under `<version>-candidate` tags and complete vulnerability scans before promoting to `stable`. Promotion to `stable` and `<version>` and GitHub Release graduation SHALL occur ONLY when the candidate scan reports zero blocking vulnerabilities, copying both `amd64` and `arm64` manifests in the OCI manifest list via `skopeo copy --all`.

#### Scenario: Clean candidate promoted to stable
- **WHEN** the candidate container image scan completes with zero blocking vulnerabilities
- **THEN** the promotion job copies the complete `amd64` and `arm64` OCI manifest list to `stable` and `<version>` in the container registry (verified via `docker manifest inspect`)
- **THEN** the GitHub Release updates to `prerelease: false` and marks the release as latest

#### Scenario: Vulnerable candidate blocked from promotion
- **WHEN** the candidate container image scan detects an un-triaged blocking vulnerability
- **THEN** the security scan job fails with a non-zero exit code
- **THEN** the workflow does NOT tag the image as `stable` in the container registry
- **THEN** the GitHub Release remains quarantined as a pre-release
