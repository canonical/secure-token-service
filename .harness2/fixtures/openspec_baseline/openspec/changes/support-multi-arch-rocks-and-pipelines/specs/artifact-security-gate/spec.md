# Spec Delta

## MODIFIED Requirements

### Requirement: Pull request vulnerability pre-check
The test verification workflow SHALL execute static vulnerability analysis on Go dependencies and build and verify the ELF machine architecture of the Go binary for `linux/amd64`, `linux/arm64`, and `linux/riscv64` before initiating container image builds. If any high or critical vulnerability with a reachable execution path is detected, or if any of the three binary architectures fails to build or match its target ELF architecture (`x86-64`, `aarch64`, `RISC-V`), the workflow SHALL terminate with an error and skip container image construction.

#### Scenario: Clean dependencies in pull request
- **WHEN** a pull request has no known vulnerable Go dependencies and builds and verifies ELF binaries for `linux/amd64` (`x86-64`), `linux/arm64` (`aarch64`), and `linux/riscv64` (`RISC-V`)
- **THEN** vulnerability and binary build checks exit with code `0`
- **THEN** the workflow proceeds to build the container rock artifacts for the supported image architectures (`amd64` and `arm64`)

#### Scenario: Vulnerability detected in pull request
- **WHEN** a pull request introduces a dependency with a known reachable vulnerability
- **THEN** vulnerability checks exit with a non-zero exit code
- **THEN** the container rock build matrix jobs (`amd64` and `arm64`) do not run

### Requirement: Candidate artifact scanning and promotion gate
The release pipeline SHALL publish multi-architecture container artifacts (`amd64` and `arm64`) under temporary candidate tags (`<version>-candidate`, `<version>-candidate-amd64`, and `<version>-candidate-arm64`) and run security scans against the candidate image before publishing to `stable`. Promotion to `stable` and `<version>` and graduation of the GitHub Release to a non-prerelease state SHALL occur ONLY when the security scan completes with zero blocking vulnerabilities. Promotion SHALL copy both `amd64` and `arm64` manifests in the OCI manifest list (`skopeo copy --all`, tracked upstream in [`canonical/identity-team#156`](https://github.com/canonical/identity-team/pull/156)).

#### Scenario: Clean candidate promoted to stable
- **WHEN** the candidate container image scan completes with zero blocking vulnerabilities
- **THEN** the promotion job copies the complete `amd64` and `arm64` OCI manifest list to `stable` and `<version>` in the container registry (verified via `docker manifest inspect`)
- **THEN** the GitHub Release updates to `prerelease: false` and marks the release as latest

#### Scenario: Vulnerable candidate blocked from promotion
- **WHEN** the candidate container image scan detects an un-triaged blocking vulnerability
- **THEN** the security scan job fails with a non-zero exit code
- **THEN** the workflow does NOT tag the image as `stable` in the container registry
- **THEN** the GitHub Release remains quarantined as a pre-release
