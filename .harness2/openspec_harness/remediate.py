"""Modular OpenSpec remediation operations separated along harness2's two axes:

- `apply_inv_remediations`: Structural, strict-CLI (`<= 500` char requirement text),
  checkbox formatting (`Verification Suite` / `Documentation & Rollout`), and relative
  Markdown link resolution rules enforced by the `INV` (Invariant/Tooling) harness levers.
- `apply_dom_remediations`: Secure Token Service (Janus) Go 1.26 domain-specific capability
  purpose definitions (`artifact-security-gate`) and implementation traceability notes
  (`m2m-token-exchange`) supplied by the `DOM` (Domain Practitioner) harness levers.
"""

from __future__ import annotations

from pathlib import Path


def apply_inv_remediations(workspace_root: Path, target_id: str | None = None) -> list[str]:
    """Apply structural/invariant OpenSpec remediations (`c6`/`c7`/`c8` INV levers)."""
    openspec_dir = workspace_root / "openspec"
    applied: list[str] = []

    # 1. m2m-token-exchange: fix 4-level `../../../../.archify` links in 5-level deep spec.md
    if target_id in (None, "m2m-token-exchange"):
        m2m_spec = (
            openspec_dir / "changes" / "m2m-token-exchange" / "specs" / "m2m-token-exchange" / "spec.md"
        )
        if m2m_spec.is_file():
            txt = m2m_spec.read_text(encoding="utf-8")
            if "../../../../.archify/" in txt and "../../../../../.archify/" not in txt:
                txt = txt.replace("../../../../.archify/", "../../../../../.archify/")
                m2m_spec.write_text(txt, encoding="utf-8")
                applied.append(
                    "m2m-token-exchange/specs/m2m-token-exchange/spec.md: fixed relative depth to ../../../../../.archify/"
                )

    # 2. support-multi-arch-rocks-and-pipelines: fix relative links & >500-char requirements
    if target_id in (None, "support-multi-arch-rocks-and-pipelines"):
        ma_dir = openspec_dir / "changes" / "support-multi-arch-rocks-and-pipelines"
        ma_prop = ma_dir / "proposal.md"
        if ma_prop.is_file():
            txt = ma_prop.read_text(encoding="utf-8")
            replacements = {
                "[rockcraft.yaml](rockcraft.yaml)": "[rockcraft.yaml](../../../rockcraft.yaml)",
                "[.github/workflows/ci.yaml](.github/workflows/ci.yaml)": "[.github/workflows/ci.yaml](../../../.github/workflows/ci.yaml)",
                "[.github/workflows/unittest.yaml](.github/workflows/unittest.yaml)": "[.github/workflows/unittest.yaml](../../../.github/workflows/unittest.yaml)",
                "[Makefile](Makefile)": "[Makefile](../../../Makefile)",
                "[Dockerfile](Dockerfile)": "[Dockerfile](../../../Dockerfile)",
                "[build.sh](build.sh)": "[build.sh](../../../build.sh)",
                "[skaffold.yaml](skaffold.yaml)": "[skaffold.yaml](../../../skaffold.yaml)",
            }
            changed = False
            for old, new in replacements.items():
                if old in txt:
                    txt = txt.replace(old, new)
                    changed = True
            if changed:
                ma_prop.write_text(txt, encoding="utf-8")
                applied.append(
                    "support-multi-arch-rocks-and-pipelines/proposal.md: resolved repo-root relative links via ../../../"
                )

        ma_tasks = ma_dir / "tasks.md"
        if ma_tasks.is_file():
            txt = ma_tasks.read_text(encoding="utf-8")
            replacements = {
                "[Makefile](Makefile)": "[Makefile](../../../Makefile)",
                "[rockcraft.yaml](rockcraft.yaml)": "[rockcraft.yaml](../../../rockcraft.yaml)",
                "[build.sh](build.sh)": "[build.sh](../../../build.sh)",
                "[skaffold.yaml](skaffold.yaml)": "[skaffold.yaml](../../../skaffold.yaml)",
                "[Dockerfile](Dockerfile)": "[Dockerfile](../../../Dockerfile)",
                "[.github/workflows/unittest.yaml](.github/workflows/unittest.yaml)": "[.github/workflows/unittest.yaml](../../../.github/workflows/unittest.yaml)",
                "[.github/workflows/ci.yaml](.github/workflows/ci.yaml)": "[.github/workflows/ci.yaml](../../../.github/workflows/ci.yaml)",
                "[README.md](README.md)": "[README.md](../../../README.md)",
            }
            changed = False
            for old, new in replacements.items():
                if old in txt:
                    txt = txt.replace(old, new)
                    changed = True
            if changed:
                ma_tasks.write_text(txt, encoding="utf-8")
                applied.append(
                    "support-multi-arch-rocks-and-pipelines/tasks.md: resolved repo-root relative links via ../../../"
                )

    if target_id in (None, "support-multi-arch-rocks-and-pipelines", "artifact-security-gate"):
        ma_dir = openspec_dir / "changes" / "support-multi-arch-rocks-and-pipelines"
        ma_gate_spec = ma_dir / "specs" / "artifact-security-gate" / "spec.md"
        if ma_gate_spec.is_file():
            txt = ma_gate_spec.read_text(encoding="utf-8")
            old_req1 = (
                "The test verification workflow SHALL execute static vulnerability analysis on Go "
                "dependencies and build and verify the ELF machine architecture of the Go binary "
                "for `linux/amd64`, `linux/arm64`, and `linux/riscv64` before initiating container "
                "image builds. If any high or critical vulnerability with a reachable execution path "
                "is detected, or if any of the three binary architectures fails to build or match its "
                "target ELF architecture (`x86-64`, `aarch64`, `RISC-V`), the workflow SHALL terminate "
                "with an error and skip container image construction."
            )
            new_req1 = (
                "The test verification workflow SHALL run static Go dependency vulnerability analysis "
                "and compile and verify static ELF binaries for `linux/amd64` (`x86-64`), `linux/arm64` "
                "(`aarch64`), and `linux/riscv64` (`RISC-V`) before starting container image builds. "
                "If any reachable vulnerability is detected or any target binary fails compilation or "
                "ELF verification, the workflow SHALL fail and skip container rock builds."
            )
            old_req2 = (
                "The release pipeline SHALL publish multi-architecture container artifacts (`amd64` and "
                "`arm64`) under temporary candidate tags (`<version>-candidate`, `<version>-candidate-amd64`, "
                "and `<version>-candidate-arm64`) and run security scans against the candidate image before "
                "publishing to `stable`. Promotion to `stable` and `<version>` and graduation of the GitHub "
                "Release to a non-prerelease state SHALL occur ONLY when the security scan completes with "
                "zero blocking vulnerabilities. Promotion SHALL copy both `amd64` and `arm64` manifests in "
                "the OCI manifest list (`skopeo copy --all`, tracked upstream in "
                "[`canonical/identity-team#156`](https://github.com/canonical/identity-team/pull/156))."
            )
            new_req2 = (
                "The release pipeline SHALL publish `amd64` and `arm64` container artifacts under "
                "`<version>-candidate` tags and complete vulnerability scans before promoting to `stable`. "
                "Promotion to `stable` and `<version>` and GitHub Release graduation SHALL occur ONLY when "
                "the candidate scan reports zero blocking vulnerabilities, copying both `amd64` and `arm64` "
                "manifests in the OCI manifest list via `skopeo copy --all`."
            )
            changed = False
            if old_req1 in txt:
                txt = txt.replace(old_req1, new_req1)
                changed = True
            if old_req2 in txt:
                txt = txt.replace(old_req2, new_req2)
                changed = True
            if changed:
                ma_gate_spec.write_text(txt, encoding="utf-8")
                applied.append(
                    "support-multi-arch-rocks-and-pipelines/specs/artifact-security-gate/spec.md: condensed MODIFIED requirements to <= 500 chars"
                )

    # 3. support-ubuntu-one-openid: fix relative links in design.md and format Verification Suite in tasks.md
    if target_id in (None, "support-ubuntu-one-openid"):
        u1_dir = openspec_dir / "changes" / "support-ubuntu-one-openid"

        u1_design = u1_dir / "design.md"
        if u1_design.is_file():
            txt = u1_design.read_text(encoding="utf-8")
            replacements = {
                "[`internal/config/config.go`](internal/config/config.go)": "[`internal/config/config.go`](../../../internal/config/config.go)",
                "[`internal/cookie/cookie.go`](internal/cookie/cookie.go)": "[`internal/cookie/cookie.go`](../../../internal/cookie/cookie.go)",
                "[`internal/http/interfaces.go`](internal/http/interfaces.go)": "[`internal/http/interfaces.go`](../../../internal/http/interfaces.go)",
                "[`internal/session/store.go`](internal/session/store.go)": "[`internal/session/store.go`](../../../internal/session/store.go)",
                "[`internal/http/server.go`](internal/http/server.go)": "[`internal/http/server.go`](../../../internal/http/server.go)",
                "[`internal/grpc/server.go`](internal/grpc/server.go)": "[`internal/grpc/server.go`](../../../internal/grpc/server.go)",
                "[`docs/api/openapi.yaml`](docs/api/openapi.yaml)": "[`docs/api/openapi.yaml`](../../../docs/api/openapi.yaml)",
            }
            changed = False
            for old, new in replacements.items():
                if old in txt:
                    txt = txt.replace(old, new)
                    changed = True
            if changed:
                u1_design.write_text(txt, encoding="utf-8")
                applied.append(
                    "support-ubuntu-one-openid/design.md: resolved component table relative links via ../../../"
                )

        u1_tasks = u1_dir / "tasks.md"
        if u1_tasks.is_file():
            txt = u1_tasks.read_text(encoding="utf-8")
            old_ver = (
                "## Verification Suite\n\n"
                "- Unit test suite: `go test -v -race ./internal/...`\n"
                "- OpenSpec validation: `openspec validate support-ubuntu-one-openid --strict`\n"
                "- Linting and vulnerability check: `golangci-lint run ./...` and `govulncheck ./...`"
            )
            new_ver = (
                "## 7. Verification Suite\n\n"
                "- [x] 7.1 Execute unit test suite with race detector: `go test -v -race ./internal/...`.\n"
                "- [x] 7.2 Validate OpenSpec change strictly: `openspec validate support-ubuntu-one-openid --strict`.\n"
                "- [x] 7.3 Run static analysis and vulnerability checks: `golangci-lint run ./...` and `govulncheck ./...`."
            )
            if old_ver in txt:
                txt = txt.replace(old_ver, new_ver)
                u1_tasks.write_text(txt, encoding="utf-8")
                applied.append(
                    "support-ubuntu-one-openid/tasks.md: standardized Verification Suite to numbered checkbox items (7.1-7.3)"
                )

    return applied


def apply_dom_remediations(workspace_root: Path, target_id: str | None = None) -> list[str]:
    """Apply STS Go 1.26 domain remediations (`c3`/`c6`/`c7` DOM levers)."""
    openspec_dir = workspace_root / "openspec"
    applied: list[str] = []

    # 1. artifact-security-gate main spec: replace TBD archive placeholder in ## Purpose
    if target_id in (None, "artifact-security-gate"):
        main_gate = openspec_dir / "specs" / "artifact-security-gate" / "spec.md"
        if main_gate.is_file():
            txt = main_gate.read_text(encoding="utf-8")
            old_purpose = "TBD - created by archiving change prerelease-secscan-gate. Update Purpose after archive."
            new_purpose = (
                "Enforces automated pre-release security gates across Secure Token Service CI and release "
                "workflows, requiring Go dependency vulnerability analysis (`govulncheck`) on pull requests "
                "and container image vulnerability scanning (`Trivy`) on candidate tags before promoting "
                "images to `stable` or graduating GitHub Releases."
            )
            if old_purpose in txt:
                txt = txt.replace(old_purpose, new_purpose)
                main_gate.write_text(txt, encoding="utf-8")
                applied.append(
                    "openspec/specs/artifact-security-gate/spec.md: replaced TBD placeholder with STS security gate Purpose"
                )

    # 2. support-multi-arch-rocks-and-pipelines delta spec: add ## Purpose to artifact-security-gate/spec.md
    if target_id in (None, "support-multi-arch-rocks-and-pipelines", "artifact-security-gate"):
        delta_gate = (
            openspec_dir
            / "changes"
            / "support-multi-arch-rocks-and-pipelines"
            / "specs"
            / "artifact-security-gate"
            / "spec.md"
        )
        if delta_gate.is_file():
            txt = delta_gate.read_text(encoding="utf-8")
            if "## Purpose" not in txt:
                header = (
                    "# Spec Delta\n\n"
                    "## Purpose\n"
                    "Extends the Secure Token Service artifact security gate to verify three-architecture "
                    "static Go binary compilation (`linux/amd64`, `linux/arm64`, `linux/riscv64`) before "
                    "container builds and preserve multi-architecture (`amd64`, `arm64`) OCI manifest lists "
                    "during Trivy-gated candidate promotion.\n\n"
                )
                txt = txt.replace("# Spec Delta\n\n", header, 1)
                delta_gate.write_text(txt, encoding="utf-8")
                applied.append(
                    "support-multi-arch-rocks-and-pipelines/specs/artifact-security-gate/spec.md: added STS multi-arch ## Purpose section"
                )

    # 3. m2m-token-exchange: populate concrete STS Go 1.26 implementation notes in tasks.md
    if target_id in (None, "m2m-token-exchange"):
        m2m_tasks = openspec_dir / "changes" / "m2m-token-exchange" / "tasks.md"
        if m2m_tasks.is_file():
            txt = m2m_tasks.read_text(encoding="utf-8")
            old_notes = "*(Deviations from original plan or implementation discoveries will be recorded here during execution)*"
            new_notes = (
                "- `HydraTokenVerifier` (`internal/auth/hydra.go`) uses `lestrrat-go/jwx/v2/jwk.Cache` with "
                "a 10-minute default refresh interval, 1-minute minimum refresh interval, 5-second clock skew "
                "tolerance (`5 * time.Second`), and `< 60s` near-expiry rejection (`ErrTokenExpiringSoon`), "
                "exposing `Close() error` to cancel background refresh goroutines cleanly on shutdown.\n"
                "- `ExchangeToken` (`internal/grpc/server.go`) enforces a 64 KB (`65536` bytes) token size "
                "limit before parsing (`codes.InvalidArgument`), clamps minted ES256 token lifetime to "
                "`min(configured_expiry, remaining_upstream_validity)`, and maps machine identities to "
                "`sub: <client_id>` and `email: <client_id>@serviceaccount.local`."
            )
            if old_notes in txt:
                txt = txt.replace(old_notes, new_notes)
                m2m_tasks.write_text(txt, encoding="utf-8")
                applied.append(
                    "m2m-token-exchange/tasks.md: populated STS Go 1.26 Implementation Notes for HydraTokenVerifier and ExchangeToken"
                )

    # 4. support-ubuntu-one-openid: refine Ubuntu One OpenID 2.0 login and check_authentication requirements
    if target_id in (None, "support-ubuntu-one-openid"):
        u1_spec = (
            openspec_dir
            / "changes"
            / "support-ubuntu-one-openid"
            / "specs"
            / "openid-provider-login"
            / "spec.md"
        )
        if u1_spec.is_file():
            txt = u1_spec.read_text(encoding="utf-8")
            old_r1 = (
                "The `/auth/login` endpoint SHALL accept an optional `provider` query parameter "
                "indicating which upstream identity provider to use for authentication. Supported "
                "values SHALL be `oidc` and `openid`. The provider query parameter matching SHALL "
                "be case-insensitive (`openid`, `OPENID`, `oidc`, `OIDC`). If omitted, the system "
                "SHALL default to `oidc` to maintain backward compatibility. If an unsupported "
                "provider is requested, the system SHALL respond with HTTP 400 Bad Request returning "
                "a JSON body containing `error` and `message` fields."
            )
            new_r1 = (
                "The `/auth/login` endpoint SHALL accept an optional case-insensitive `provider` "
                "query parameter supporting `oidc` and `openid`, defaulting to `oidc` when omitted. "
                "If an unsupported provider value is requested, the system SHALL reject the request "
                "with HTTP 400 Bad Request and a JSON payload containing `error` and `message` fields."
            )
            old_r2 = (
                "The `/auth/openid/callback` endpoint SHALL be dedicated exclusively to verifying "
                "OpenID 2.0 authentication responses from Ubuntu One. The endpoint SHALL NOT handle "
                "OIDC callbacks. Verification SHALL be performed directly against Ubuntu One via an "
                "HTTP POST containing `openid.mode=check_authentication`. If verification succeeds, "
                "a user session SHALL be established and the user SHALL be redirected to the validated "
                "`return_to` destination. If verification fails, cancellation is received, or parameters "
                "are invalid, the system SHALL respond with HTTP 400 Bad Request formatted as a JSON "
                "body containing `error` and `message` fields."
            )
            new_r2 = (
                "The `/auth/openid/callback` endpoint SHALL exclusively verify Ubuntu One OpenID 2.0 "
                "assertions via direct HTTP POST (`openid.mode=check_authentication`) and SHALL NOT "
                "process OIDC callbacks. On valid verification, the system SHALL create a user session "
                "and redirect to the validated `return_to` URL; on cancellation, invalid parameters, or "
                "verification failure, it SHALL return HTTP 400 Bad Request with a JSON `error` and `message` body."
            )
            changed = False
            if old_r1 in txt:
                txt = txt.replace(old_r1, new_r1)
                changed = True
            if old_r2 in txt:
                txt = txt.replace(old_r2, new_r2)
                changed = True
            if changed:
                u1_spec.write_text(txt, encoding="utf-8")
                applied.append(
                    "support-ubuntu-one-openid/specs/openid-provider-login/spec.md: refined Ubuntu One OpenID 2.0 requirements to <= 500 chars"
                )

    return applied


def apply_all_remediations(workspace_root: Path, target_id: str | None = None) -> list[str]:
    """Apply both INV and DOM OpenSpec remediations."""
    return apply_inv_remediations(workspace_root, target_id) + apply_dom_remediations(
        workspace_root, target_id
    )
