# Tasks: Machine-to-Machine (M2M) Token Exchange via gRPC

## 1. Protobuf Definition & Bindings

- [x] 1.1 Update `api/proto/v1/sts.proto` to define `ExchangeTokenRequest` and add `rpc ExchangeToken(ExchangeTokenRequest) returns (ExchangeResponse)` to `SecurityTokenService`. Verify by running `make proto` (or `protoc`) and checking generated Go bindings.
- [x] 1.2 Verify generated protobuf Go structures compile and pass existing unit tests with `go test ./...`.

## 2. Upstream IdP JWKS Preemptive Verifier

- [x] 2.1 Implement `HydraTokenVerifier` in `internal/auth/hydra.go` (or `internal/auth/verifier.go`) using `lestrrat-go/jwx/v2/jwk.Cache` to preemptively synchronize and refresh Hydra's JWKS on a background interval. Implement lifecycle management (`Close() error` / context cancellation) to prevent background goroutine leaks on shutdown. Verify with unit tests in `internal/auth/hydra_test.go` using a mock HTTP JWKS endpoint.
- [x] 2.2 Add token signature validation, expiration checking, clock skew tolerance (5s), and subject extraction logic. Ensure tokens with `< 60s` remaining lifetime are rejected. Verify with unit tests testing valid, expired, near-expired (<60s), malformed, and wrong-signature tokens.

## 3. gRPC Server Token Exchange Implementation

- [ ] 3.1 Implement `ExchangeToken` in `internal/grpc/server.go`. Wire `HydraTokenVerifier` into `Server` initialization and server shutdown lifecycle. Enforce maximum token size limit (64 KB) returning `InvalidArgument`. Verify with unit tests in `internal/grpc/server_test.go` for all status code paths (`OK`, `InvalidArgument`, `Unauthenticated`).
- [ ] 3.2 Implement machine claims mapping (`sub: client_id`, synthetic `email: client_id@serviceaccount.local`), claim sanitation (non-empty, <=256 chars, no control chars/newlines), and TTL clamping (`min(configured_expiry, remaining_upstream_validity)`). Verify claims and clamped expiration via unit tests decoding the minted JWT.
- [ ] 3.3 Wire verifier and server initialization into `cmd/sts/serve.go`. Verify server starts cleanly with `go test ./cmd/sts/...`.

## 4. Observability, Telemetry & Documentation

- [ ] 4.1 Add Prometheus metrics for `ExchangeToken` (RPC handled counter, exchange duration histogram, clamped TTL histogram) and OpenTelemetry spans. Verify metrics registration via unit tests in `internal/grpc/server_test.go`.
- [ ] 4.2 Update gRPC API documentation in `docs/api/grpc.md` and `README.md` documenting `ExchangeToken`, request/response payloads, and error conditions. Verify markdown links and formatting.
- [ ] 4.3 Add structured security audit logging (Zap) for token exchange events (successful exchanges and rejections with reason/code, client ID, clamped TTL, omitting raw tokens). Verify audit logs in unit tests.

## Verification Suite

- [ ] 5.1 Execute complete unit test suite across all packages: `go test -v -race ./...`.
- [ ] 5.2 Execute end-to-end integration test verifying `ExchangeToken` swaps a live mock Hydra JWT for an internal STS JWT signed with ES256 and verified against STS's own JWKS endpoint.
- [ ] 5.3 Run static analysis and linter: `golangci-lint run`.

## Documentation & Rollout

- [ ] 6.1 Publish updated Protobuf definitions and Go client bindings.
- [ ] 6.2 Coordinate deployment with `authorization-service` issue #100. STS `ExchangeToken` endpoint is backward-compatible and deployed prior to gateway/authz dual-authentication enablement.

## Implementation Notes

*(Deviations from original plan or implementation discoveries will be recorded here during execution)*
