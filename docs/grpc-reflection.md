# gRPC Reflection Implementation

## Summary

Added gRPC reflection service to the secure-token-service gRPC server, enabling service discovery and introspection without requiring proto files.

## Changes Made

### Modified Files

**`internal/grpc/server.go`**:
- Added `google.golang.org/grpc/reflection` import
- Registered reflection service in `Start()` method via `reflection.Register(s.server)`
- Updated log message to indicate reflection is enabled

### Benefits

1. **Service Discovery**: Tools like `grpcurl` can list and describe services without proto files
2. **Developer Experience**: Easier testing and debugging with `grpcurl` or other gRPC clients
3. **Documentation**: Service methods are self-describing via reflection
4. **Dynamic Clients**: Enables dynamic gRPC clients that don't need compile-time proto definitions

### Usage Examples

```bash
# List all available services
grpcurl -plaintext localhost:9090 list

# Output:
# grpc.reflection.v1alpha.ServerReflection
# sts.v1.SecurityTokenService

# Describe the STS service
grpcurl -plaintext localhost:9090 describe sts.v1.SecurityTokenService

# List methods
grpcurl -plaintext localhost:9090 list sts.v1.SecurityTokenService

# Output:
# sts.v1.SecurityTokenService.ExchangeSession
# sts.v1.SecurityTokenService.RevokeUserSessions

# Call a method with reflection
grpcurl -plaintext -d '{"session_id": "test-123"}' \
  localhost:9090 sts.v1.SecurityTokenService/ExchangeSession
```

### Testing

Build and run the service:
```bash
make build
./bin/sts serve
```

In another terminal, test reflection:
```bash
# Install grpcurl if needed
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List services
grpcurl -plaintext localhost:9090 list

# Should see:
# - grpc.reflection.v1alpha.ServerReflection
# - sts.v1.SecurityTokenService (once proto is properly registered)
```

### Notes

- Reflection is enabled by default for all environments
- For production, consider using a gRPC interceptor to restrict reflection to authorized clients

### Production Considerations

For production deployments, you may want to conditionally enable reflection:

```go
// Only enable reflection in dev/staging
if os.Getenv("ENABLE_GRPC_REFLECTION") == "true" {
    reflection.Register(s.server)
    log.Printf("gRPC reflection enabled")
}
```

This allows you to disable service introspection in production for security reasons while keeping it enabled for development and testing environments.
