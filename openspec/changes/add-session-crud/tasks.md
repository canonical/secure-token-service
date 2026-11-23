# Tasks

## 1. Valkey Session Store Operations

- [x] 1.1 Add `ListUserSessions(ctx, userID)` to `session.Store` and `ValkeyStore` in [internal/session/store.go](../../../internal/session/store.go) with TTL-derived `ExpiresAt` and lazy `SREM` pruning of expired session IDs, and verify with unit/integration tests in `go test -race ./internal/session/...`
- [x] 1.2 Add `RevokeUserSessionsExcept(ctx, userID, keepSessionID)` to `session.Store` and `ValkeyStore` in [internal/session/store.go](../../../internal/session/store.go) returning the revoked session count, and verify with `go test -race ./internal/session/...`
- [x] 1.3 Update `ValkeyStore.Set` in [internal/session/store.go](../../../internal/session/store.go) so setting a shorter-TTL session never shrinks an existing longer TTL on `user_sessions:<userID>`, and verify with `go test -race ./internal/session/...`
- [x] 1.4 Regenerate or update session store mocks in [internal/http/mock_store.go](../../../internal/http/mock_store.go) and [cmd/sts/mock_store_test.go](../../../cmd/sts/mock_store_test.go) and verify compilation via `go test -run=^$ ./...`

## 2. HTTP Session CRUD Endpoints and CSRF Protection

- [x] 2.1 Implement the same-origin CSRF guard (`Sec-Fetch-Site: same-origin`, fallback `Origin` host check, allow when both headers absent) in [internal/http/server.go](../../../internal/http/server.go) and verify all branches via unit tests in `go test -race ./internal/http/...`
- [x] 2.2 Implement `GET /auth/sessions` in [internal/http/server.go](../../../internal/http/server.go) replacing the `501` stub, returning `{sessions: [{session_id, provider, created_at, expires_at, is_current}]}` with `Cache-Control: no-store`, `Vary: Cookie`, and `X-Content-Type-Options: nosniff`, verified by unit tests (`go test -race ./internal/http/...`)
- [x] 2.3 Implement `DELETE /auth/sessions/{session_id}` in [internal/http/server.go](../../../internal/http/server.go) enforcing CSRF check, ownership verification (`404` on foreign or missing session), and cookie clearing when revoking the current session, verified by unit tests (`go test -race ./internal/http/...`)
- [x] 2.4 Implement `DELETE /auth/sessions` in [internal/http/server.go](../../../internal/http/server.go) supporting optional `?exclude_current=true` (`400` on invalid boolean), cookie clearing on full revoke, and structured audit logging, verified by unit tests (`go test -race ./internal/http/...`)

## 3. Bounded Route Metrics Observability

- [x] 3.1 Update `HTTPMetricsMiddleware` in [internal/observability/metrics.go](../../../internal/observability/metrics.go) to record chi `RoutePattern()` instead of raw `r.URL.Path`, and verify parameterized route labeling (`/auth/sessions/{session_id}`) with `go test -race ./internal/observability/...`

## 4. Verification Suite

- [x] 4.1 Run full Go unit tests and static analysis (`go test -race -short ./... && go vet ./...`) and confirm zero failures
- [x] 4.2 Run OpenSpec strict validation (`openspec validate --all --strict && python3 scripts/validate_openspec.py`) and confirm all checks pass

## 5. Documentation & Rollout

- [x] 5.1 Document `GET /auth/sessions`, `DELETE /auth/sessions/{session_id}`, and `DELETE /auth/sessions` (including `?exclude_current=true` and `401`/`403`/`404`/`503` responses) in [docs/api/openapi.yaml](../../../docs/api/openapi.yaml) and verify OpenAPI YAML validity
- [x] 5.2 Confirm zero-downtime rollout behavior (existing `user_sessions:<userID>` sets prune stale IDs lazily on first listing; existing `POST /auth/logout` and gRPC `RevokeUserSessions` stay backward compatible)

## Implementation Notes

- All `/auth/sessions` HTTP endpoints are strictly self-service and cookie-authenticated; cross-user administrative revocation remains on gRPC `RevokeUserSessions`.
- `DELETE /auth/sessions/{session_id}` returns `404 Not Found` for both missing and foreign sessions to prevent a session-ID existence oracle.
- Current-user identity inspection (`GET /auth/me`) and OIDC/OpenID claim normalization belong in the separate `add-whoami-endpoint` change.
- Verification note: every Go package passed `-race -short` (`internal/session` verified with both in-memory RESP2 unit tests in `store_unit_test.go` and real Valkey testcontainers in `store_test.go`; `internal/db` ran with `-parallel=1` due to a pre-existing `goose.SetBaseFS` race in `internal/db/db.go:47` outside this change's scope).
