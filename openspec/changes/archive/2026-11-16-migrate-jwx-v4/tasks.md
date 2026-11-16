# Tasks

## 1. Dependency upgrade

- [x] 1.1 Replace `github.com/lestrrat-go/jwx/v2` with `github.com/lestrrat-go/jwx/v4` v4.6.0 and add `github.com/jwx-go/jwkfetch/v4` in `go.mod`, then run `go mod tidy` and verify `go build ./...` resolves all imports (compile errors in `internal/auth`, `internal/http`, `internal/grpc` are expected until task 2 lands and are fixed there).
  - Testing: `go mod tidy` exits clean; no other module version changes beyond the jwx major bump and its transitive requirements.

## 2. Code migration

- [x] 2.1 Port `internal/auth/hydra.go` to `jwkfetch/v4` `Cache` (per design.md Decisions 1-2): replace `jwk.NewCache`/`Register`/`Get`/`Refresh` with `jwkfetch.NewCache` + `Register(ctx, url, WithConstantInterval, WithMinInterval)` + `Lookup`/`Refresh` + `Shutdown` on `Close`; replace `key.Raw` with `jwk.Export[any]`; keep the `HydraTokenVerifier` public API and static-keyset behavior unchanged.
  - Testing: `go test -short -count=1 ./internal/auth/ -run TestHydraTokenVerifier` passes.
- [x] 2.2 Port `internal/auth/token.go` to the v4 key API: `jwk.FromRaw` → `jwk.Import[jwk.Key]`; keep `jwk.Parse`, `jwk.NewSet`, `key.Set` signatures.
  - Testing: `go test -short -count=1 ./internal/auth/` passes.
- [x] 2.3 Update the `github.com/lestrrat-go/jwx/v2/jwk` import path to `/v4/jwk` in `internal/http/interfaces.go`, `internal/auth/hydra_test.go`, `internal/grpc/integration_test.go`, and `internal/http/server_test.go`; regenerate mocks with `go generate ./...` (never `make mocks`) and remove any `vendor/` directory it creates.
  - Testing: `go build ./... && go vet ./...` clean.

## 3. Verification suite

- [x] 3.1 Run `go build ./... && go vet ./...` and confirm zero errors.
- [x] 3.2 Run `go test -short -count=1 ./...` and confirm all packages pass (testcontainers-based `internal/session` and `internal/db` failures from the missing local Docker daemon are environmental and expected).
- [x] 3.3 Run `trivy fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --quiet .` and confirm zero findings in `go.mod`.
- [x] 3.4 Run `openspec validate "migrate-jwx-v4"` and confirm the change validates clean.

## 4. Documentation & rollout

- [x] 4.1 Confirm the `openid-provider-login` spec delta in this change documents the JWKS endpoint/verifier behavior contract and the backward-compatibility statement (delivered artifact: `openspec/changes/migrate-jwx-v4/specs/openid-provider-login/spec.md`).
- [x] 4.2 Commit the code change plus the openspec change directory with a conventional-commit message and open the PR against `canonical/secure-token-service`, noting in the PR body that this is a maintainability/security-hygiene upgrade (no CVE) and that whichever of this PR and the dependency-refresh PR (#82) merges second needs a trivial `go.mod`/`go.sum` rebase.
- [x] 4.3 Rollback plan: revert the single merge commit if regressions appear; no data or config migration exists, so rollback is a plain revert and redeploy.

## Implementation Notes

- Implemented as planned. One refinement during apply: `jwkfetch.Cache.Register` defaults to `WithWaitReady(true)`, which makes registration fail when the first fetch fails; to preserve the v2 behavior (construction succeeds, best-effort warm-up, request-time retry) the code passes `WithWaitReady(false)` and keeps the explicit best-effort `Refresh` call from v2.
- `HydraTokenVerifier.Close` now also calls `jwkfetch.Cache.Shutdown` (required by the v4 library to stop background workers; v2 relied on context cancellation only). The v2 `WithRefreshWindow(refreshInterval/2)` knob has no v4 equivalent and was dropped per design Decision 2.
- `key.Raw(&v)` was removed in v4; replaced with the generic `jwk.Export[any](key)`. Accessor methods (`KeyID`, `Algorithm`, `KeyUsage`) now return `(T, bool)` in v4; test assertions updated accordingly.
- `go vet` required regenerating mocks (`go generate ./...`; mocks are gitignored). Verification: `go build ./... && go vet ./...` clean; `go test -short -count=1 ./...` passes except `internal/auth` (TestNewKeyManager / TestKeyManager_GetAllJWKS_CacheMiss), `internal/db`, and `internal/session` testcontainers tests, which panic on `MustExtractDockerHost` — no Docker daemon on this machine (environmental, identical on main). `trivy fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed` reports the same 4 pre-existing transitive findings as main (go-jose, klauspost/compress, moby/go-archive, golang.org/x/net via testcontainers); no new findings introduced.

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- Verify the archived result.
