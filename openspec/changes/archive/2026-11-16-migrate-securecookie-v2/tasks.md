# Tasks

## 1. Dependency upgrade

- [x] 1.1 Replace `github.com/chmike/securecookie` v1.4.1 with `github.com/chmike/securecookie/v2` v2.0.1 in `go.mod` and `.benchmark/go.mod`, then run `go mod tidy` in both modules and verify builds resolve.
- [x] 1.2 Run `trivy fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --quiet .` and verify zero findings in `go.mod`.

## 2. Cookie manager migration

- [x] 2.1 Migrate `internal/cookie/cookie.go` to the v2 API (`KeyStore`, mandatory `maxAge`, `Value`, `Delete`) and verify `go build ./...` passes.
- [x] 2.2 Remove dynamic `Secure` handling (`isSecureRequest`, `setSecureCookieValue` rewriting) and route all cookie set/clear operations through v2 objects per the spec.
- [x] 2.3 Export `cookie.SessionCookieName` (`__Host-session_id`) and update `internal/http/home.go` and `internal/http/server.go` to read it; verify `go vet ./...` passes.
- [x] 2.4 Update `internal/cookie/cookie_test.go` for prefixed names, static `Secure`, and `Max-Age` expiry; verify `go test -short -count=1 ./internal/cookie/...` passes.

## 3. Benchmark and interface alignment

- [x] 3.1 Migrate `.benchmark/benchmark_test.go` to the v2 API and verify `cd .benchmark && go test -bench=. -run=^$ -benchtime=1x ./...` passes.
- [x] 3.2 Run `go generate ./...` and verify regenerated mocks build; delete any stray `vendor/` directory.

## 4. Final verification suite

- [x] 4.1 Run `go build ./... && go vet ./...` and verify both pass.
- [x] 4.2 Run `go test -short -count=1 ./...` and verify all packages pass except docker-dependent testcontainers suites (`internal/session` valkey, `internal/db` postgres), which fail locally without a Docker daemon.
- [x] 4.3 Run `openspec validate migrate-securecookie-v2` and verify it passes.

## 5. Documentation and rollout

- [x] 5.1 Update `README.md` or developer docs with the HTTPS requirement for local development and verify the documented steps work.
- [x] 5.2 Open the PR with the breaking-change summary, migration notes, openspec change reference, and verification results.
- [x] 5.3 Note in the PR body that whichever of this PR or #82 merges second needs a trivial `go.mod`/`go.sum` rebase.

## Implementation Notes

- `go test -short -count=1 ./...` fails only in `internal/auth` (valkey cache), `internal/db` (postgres), and `internal/session` (valkey); all three panic in testcontainers setup because no Docker daemon is available locally. All other packages pass.
- Trivy reports 4 HIGH findings in `go.mod` (go-jose v4.1.5, klauspost/compress v1.18.3, moby/go-archive v0.2.0, golang.org/x/net v0.60.0). These exist identically on `main` and are unrelated to securecookie; the securecookie upgrade itself is clean. Broader dependency bumps are covered by PR #85.
- Benchmark loops were modernized to `for b.Loop()` while migrating `.benchmark/benchmark_test.go` to the v2 API.
