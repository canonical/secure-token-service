# Secure Token Service (STS) - Janus (ID052)

A Security Token Service implementing the Phantom Token Pattern for secure session management and internal JWT issuance.

> **Specification**: [ID052 - Session Service (Janus)](https://docs.google.com/document/d/1jIt1WbS6CLxpFIW0hWhQUhX7xN2qr43_xOALT5zHoKs/edit?usp=sharing)

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [How It Works](#how-it-works)
- [Components](#components)
- [JWKS & Key Rotation](#jwks--key-rotation)
- [Configuration](#configuration)
- [Getting Started](#getting-started)
- [API Reference](#api-reference)
- [Security](#security)

---

## Overview

Janus is a **Policy Enforcement Point (PEP)** and **Security Token Service (STS)** that sits between external clients and internal microservices. It implements the **Phantom Token Pattern** to provide:

- **Session Management**: Exchanges OIDC tokens for opaque HttpOnly cookies
- **Token Translation**: Converts opaque session IDs to signed internal JWTs
- **JWT Issuance**: Mints RS256-signed JWTs for service-to-service communication
- **Key Management**: PostgreSQL-backed JWKS with atomic key rotation
- **Session Storage**: Valkey/Redis-based session persistence

---

## Architecture

### High-Level Overview

```mermaid
graph LR
    A[Browser/Client] -->|1. OIDC Login| B[Janus STS]
    B -->|2. HttpOnly Cookie| A
    A -->|3. Cookie + Request| C[API Gateway]
    C -->|4. gRPC: ExchangeSession| B
    B -->|5. Internal JWT| C
    C -->|6. JWT in Header| D[Microservices]
    D -->|7. Verify with JWKS| B
    
    B -.->|Session Data| E[(Valkey)]
    B -.->|JWKS Keys| F[(PostgreSQL)]
    
    style B fill:#4285f4,stroke:#333,stroke-width:3px,color:#fff
    style E fill:#dc143c,stroke:#333,stroke-width:2px,color:#fff
    style F fill:#336791,stroke:#333,stroke-width:2px,color:#fff
```

### System Components

```mermaid
graph TB
    subgraph "External Zone"
        Browser[Browser/Client]
    end
    
    subgraph "Janus STS (PEP)"
        HTTP[HTTP Server<br/>Port 8080]
        GRPC[gRPC Server<br/>Port 9090]
        KM[Key Manager]
        SM[Session Manager]
        
        HTTP --> SM
        GRPC --> SM
        GRPC --> KM
    end
    
    subgraph "Storage Layer"
        Valkey[(Valkey<br/>Sessions)]
        Postgres[(PostgreSQL<br/>JWKS)]
    end
    
    subgraph "Internal Services"
        MS1[Microservice A]
        MS2[Microservice B]
        MS3[Microservice N]
    end
    
    Browser -->|OIDC Flow| HTTP
    Browser -->|Requests with Cookie| MS1
    MS1 -->|gRPC: ExchangeSession| GRPC
    MS2 -->|gRPC: ExchangeSession| GRPC
    MS3 -->|GET /.well-known/jwks.json| HTTP
    
    SM -.->|Read/Write Sessions| Valkey
    KM -.->|Read JWKS| Postgres
    
    style HTTP fill:#4285f4,stroke:#333,stroke-width:2px,color:#fff
    style GRPC fill:#0f9d58,stroke:#333,stroke-width:2px,color:#fff
    style KM fill:#f4b400,stroke:#333,stroke-width:2px
    style SM fill:#db4437,stroke:#333,stroke-width:2px,color:#fff
```

---

## How It Works

### 1. OIDC Authentication Flow

```mermaid
sequenceDiagram
    participant Browser
    participant Janus
    participant OIDC as OIDC Provider<br/>(e.g., Kratos)
    participant Valkey
    
    Browser->>Janus: GET /auth/login?return_to=/dashboard
    Janus->>Janus: Generate state & nonce
    Janus->>Browser: Set encrypted cookies (state, nonce)
    Janus->>Browser: 302 Redirect to OIDC Provider
    
    Browser->>OIDC: User authenticates
    OIDC->>Browser: 302 Redirect with auth code
    
    Browser->>Janus: GET /auth/callback?code=...&state=...
    Janus->>Janus: Validate state
    Janus->>OIDC: Exchange code for tokens
    OIDC->>Janus: ID Token + Access Token
    Janus->>Janus: Verify ID Token (nonce, signature)
    
    Janus->>Valkey: Store session (ID → tokens + user info)
    Valkey-->>Janus: OK
    
    Janus->>Browser: Set HttpOnly Cookie (session_id)
    Janus->>Browser: 302 Redirect to /dashboard
```

### 2. Session Exchange Flow (Phantom Token Pattern)

```mermaid
sequenceDiagram
    participant Client as Browser
    participant Gateway as API Gateway
    participant Janus as Janus STS
    participant Valkey
    participant Postgres
    participant Service as Microservice
    
    Client->>Gateway: Request + Cookie (session_id)
    Gateway->>Janus: gRPC: ExchangeSession(session_id)
    
    Janus->>Valkey: Get session by ID
    Valkey-->>Janus: Session data (user_id, upstream_token, ...)
    
    Janus->>Postgres: GetLatestActiveKey()
    Postgres-->>Janus: Private key + KID
    
    Janus->>Janus: Mint JWT (RS256)<br/>Claims: sub, iss, aud, exp, custom
    Janus-->>Gateway: Internal JWT + expires_in
    
    Gateway->>Service: Request + Authorization: Bearer <JWT>
    Service->>Janus: GET /.well-known/jwks.json (cached)
    Janus->>Postgres: GetAllPublicKeys()
    Postgres-->>Janus: Active + retired keys
    Janus-->>Service: JWK Set
    
    Service->>Service: Verify JWT signature using JWKS
    Service-->>Gateway: Response
    Gateway-->>Client: Response
```

### 3. Key Rotation Flow

```mermaid
sequenceDiagram
    participant Admin
    participant CLI as rotate-key CLI
    participant Postgres
    
    Admin->>CLI: ./bin/sts rotate-key
    CLI->>CLI: Generate new RSA key pair (2048-bit)
    CLI->>CLI: Create JSONB entry<br/>(kid, public_pem, private_pem)
    
    CLI->>Postgres: BEGIN TRANSACTION
    CLI->>Postgres: UPDATE hydra_jwk SET sid='public.retired'<br/>WHERE sid='public'
    CLI->>Postgres: INSERT new key with sid='public'
    CLI->>Postgres: COMMIT
    
    Postgres-->>CLI: Success
    
    CLI->>Postgres: GetLatestActiveKey() [verify]
    Postgres-->>CLI: New key
    
    CLI-->>Admin: ✓ Rotation complete<br/>New KID: janus-key-xyz<br/>Old keys moved to retired set
    
    Note over Postgres: JWKS endpoint now returns:<br/>- 1 active key (signing)<br/>- N retired keys (verification)
```

---

## Components

### HTTP Server (`internal/http/server.go`)

**Endpoints**:
- `GET /auth/login` - Initiates OIDC flow
- `GET /auth/callback` - OIDC callback handler
- `POST /auth/logout` - Session termination
- `GET /auth/sessions` - List user sessions
- `GET /.well-known/jwks.json` - **Public JWKS endpoint** (all active + retired keys)

### gRPC Server (`internal/grpc/server.go`)

**Service**: `sts.v1.SecurityTokenService`

**Features**:
- **Reflection Enabled**: Service discovery via gRPC reflection (no proto files needed for clients)
- **Cookie-Based Authentication**: Accepts encoded session cookies for enhanced security
- Session-to-JWT exchange (Phantom Token Pattern)
- Bulk user session revocation

**Methods**:
- `ExchangeSession(session_cookie) → internal_jwt` - Decodes session cookie and exchanges for JWT
- `RevokeUserSessions(user_id) → success` - Bulk session revocation

**Session Cookie Flow**:
1. Client receives HttpOnly session cookie from HTTP authentication endpoint
2. Client sends encoded cookie to gRPC service
3. Service decodes cookie to extract session ID
4. Service retrieves session from Valkey
5. Service mints internal JWT with custom claims
6. Client uses JWT internally

**Usage with grpcurl**:
```bash
# List all services (reflection)
grpcurl -plaintext localhost:9090 list

# Describe a service
grpcurl -plaintext localhost:9090 describe sts.v1.SecurityTokenService

# Exchange session (requires encoded cookie)
grpcurl -plaintext -d '{"session_cookie": "encoded-cookie-value"}' \
  localhost:9090 sts.v1.SecurityTokenService/ExchangeSession

# Revoke user sessions
grpcurl -plaintext -d '{"user_id": "user-123"}' \
  localhost:9090 sts.v1.SecurityTokenService/RevokeUserSessions
```

**Testing**: See [`internal/grpc/server_test.go`](./internal/grpc/server_test.go) for comprehensive unit tests

### Key Manager (`internal/auth/token.go`)

**Responsibilities**:
- Generate RSA key pairs on first boot
- Fetch latest active key from PostgreSQL for signing
- Mint RS256-signed JWTs with custom claims
- Provide JWKS for verification

**Key Change**: `MintToken()` **always fetches the latest active key** from the database before signing, ensuring zero-downtime rotation.

### Session Store (`internal/session/store.go`)

**Implementation**: Valkey/Redis-backed storage

**Session Data**:
```go
type Session struct {
    ID              string
    UserID          string
    UpstreamToken   string  // Encrypted OIDC access token
    IDTokenRaw      string  // Original ID token
    ExpiresAt       time.Time
    CreatedAt       time.Time
}
```

### JWKS Repository (`internal/db/jwks_repository.go`)

**Database**: PostgreSQL with JSONB storage

**Methods**:
- `GetLatestActiveKey()` - Fetch newest key from `"public"` set
- `GetAllPublicKeys()` - Return all keys from `"public"` + `"public.retired"` sets
- `RotateKey(newKey)` - **Atomic transaction**: retire old keys, activate new key
- `SaveKey(key)` - Store new key with JSONB data
- `DeleteKey(sid, kid)` - Remove key (cleanup)

---

## JWKS & Key Rotation

### Database Schema

```sql
CREATE TABLE hydra_jwk (
    sid         VARCHAR(255) NOT NULL,   -- "public" or "public.retired"
    kid         VARCHAR(255) NOT NULL,   -- Key ID (UUID-based)
    version     INTEGER NOT NULL DEFAULT 0,
    keydata     JSONB NOT NULL,          -- Complete JWK + PEM data
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (sid, kid)
);

CREATE INDEX hydra_jwk_idx_id ON hydra_jwk (sid);
CREATE INDEX hydra_jwk_kid_idx ON hydra_jwk USING GIN (keydata);
```

### JSONB Key Structure

```json
{
  "kty": "RSA",
  "kid": "janus-key-a1b2c3d4",
  "use": "sig",
  "alg": "RS256",
  "private_pem": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "public_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

### Key Rotation

**Automated rotation** (recommended schedule: every 90 days):

```bash
./bin/sts rotate-key
```

**What happens**:
1. Generates new RSA key pair
2. Moves all active keys to `"public.retired"` set
3. Inserts new key into `"public"` set
4. Both keys available via JWKS endpoint during rotation period
5. JWTs minted with new key immediately
6. Old JWTs still valid until expiry (verifiable with retired keys)

**Zero Downtime**: Services continue to verify old JWTs while new tokens use the new key.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://localhost:5432/sts?sslmode=disable` | PostgreSQL connection for JWKS storage |
| `CACHE_ADDR` | `localhost:6379` | Valkey/Redis address for sessions |
| `CACHE_PASSWORD` | `""` | Cache authentication password |
| `CACHE_DB` | `0` | Cache database number |
| `HTTP_PORT` | `8080` | HTTP server port |
| `GRPC_PORT` | `9090` | gRPC server port |
| `JWT_ISSUER` | `session-service` | JWT `iss` claim |
| `JWT_AUDIENCE` | `internal-services` | JWT `aud` claim |
| `JWT_EXPIRY` | `3600` | JWT expiry in seconds |
| `OIDC_PROVIDER_URL` | - | OIDC provider discovery URL |
| `OIDC_CLIENT_ID` | - | OAuth2 client ID |
| `OIDC_CLIENT_SECRET` | - | OAuth2 client secret |
| `OIDC_REDIRECT_URL` | `http://localhost:8080/auth/callback` | OAuth2 redirect URI |
| `COOKIE_HASH_KEY` | - | 64-byte hex key for HMAC (required) |
| `COOKIE_BLOCK_KEY` | - | 32-byte hex key for AES (required) |

---

## Getting Started

### Prerequisites

- **Go 1.23+** (for local development)
- **Docker** & **Docker Compose** (for containerized deployment)
- **Kubernetes cluster** (for Skaffold deployment)
- **Skaffold** (optional, for Kubernetes development)
- **PostgreSQL 16+** (provided via Docker Compose or external)
- **Valkey 9+** or Redis 7+ (provided via Docker Compose or external)

---

### Setup Method 1: Docker Compose (Recommended for Quick Start)

Docker Compose provides the fastest way to run all services locally.

#### Step 1: Clone and Configure

```bash
# Clone the repository
git clone https://github.com/canonical/secure-token-service
cd secure-token-service

# Review docker-compose.yml and update OIDC configuration
# Edit OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_PROVIDER_URL
nano docker-compose.yml
```

#### Step 2: Start Services

```bash
# Start all services (PostgreSQL, Valkey, STS)
docker-compose up -d

# View logs
docker-compose logs -f secure-token-service

# Check service health
docker-compose ps
```

#### Step 3: Run Database Migrations

**Important**: Migrations must be run manually before first use.

```bash
# Run migrations inside the container
docker-compose exec secure-token-service ./bin/sts migrate

# Or run locally if you have access to the database
export DATABASE_URL="postgres://postgres:password@localhost:5432/sts?sslmode=disable"
./bin/sts migrate
```

#### Step 4: Verify Setup

```bash
# Check JWKS endpoint
curl http://localhost:8080/.well-known/jwks.json

# Check gRPC server (requires grpcurl)
grpcurl -plaintext localhost:9090 list

# View PostgreSQL JWKS table
docker-compose exec postgres psql -U postgres -d sts -c "SELECT sid, kid, created_at FROM hydra_jwk;"
```

#### Step 4: Perform Key Rotation (Optional)

```bash
# Enter the container
docker-compose exec secure-token-service sh

# Rotate the JWKS
./bin/sts rotate-key

# Exit container
exit
```

#### Stop Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (CAUTION: destroys data)
docker-compose down -v
```

**Services Available**:
- HTTP Server: `http://localhost:8080`
- gRPC Server: `localhost:9090`
- PostgreSQL: `localhost:5432` (user: `postgres`, password: `password`, database: `sts`)
- Valkey: `localhost:6379`

---

### Setup Method 2: Skaffold (Kubernetes Development)

Skaffold provides continuous development workflow with Kubernetes.

#### Prerequisites

```bash
# Install Skaffold
curl -Lo skaffold https://storage.googleapis.com/skaffold/releases/latest/skaffold-linux-amd64
chmod +x skaffold
sudo mv skaffold /usr/local/bin

# Verify Kubernetes cluster access
kubectl cluster-info

# Create namespace
kubectl create namespace sts-dev
kubectl config set-context --current --namespace=sts-dev
```

#### Step 0: Create GHCR Image Pull Secret (If Using Private Registry)

If your container image is hosted on GitHub Container Registry (GHCR) as a private image, create an image pull secret:

```bash
# Create a GitHub Personal Access Token (PAT) with read:packages scope
# Go to: https://github.com/settings/tokens/new
# Select scope: read:packages

# Create the image pull secret
kubectl create secret docker-registry ghcr-credentials \
  --docker-server=ghcr.io \
  --docker-username=YOUR_GITHUB_USERNAME \
  --docker-password=YOUR_GITHUB_PAT \
  --docker-email=YOUR_EMAIL \
  --namespace=sts-dev

# Verify secret was created
kubectl get secret ghcr-credentials -n sts-dev
```

**Alternative: Using a YAML manifest** (see [`k8s/ghcr-secret.yaml`](./k8s/ghcr-secret.yaml)):

```bash
# Encode your Docker config
cat > /tmp/docker-config.json << EOF
{
  "auths": {
    "ghcr.io": {
      "username": "YOUR_GITHUB_USERNAME",
      "password": "YOUR_GITHUB_PAT",
      "email": "YOUR_EMAIL"
    }
  }
}
EOF

# Base64 encode it
DOCKER_CONFIG=$(cat /tmp/docker-config.json | base64 -w0)

# Create secret YAML
cat > k8s/ghcr-secret.yaml << EOF
apiVersion: v1
kind: Secret
metadata:
  name: ghcr-credentials
  namespace: sts-dev
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: ${DOCKER_CONFIG}
EOF

# Apply the secret
kubectl apply -f k8s/ghcr-secret.yaml

# Clean up temporary file
rm /tmp/docker-config.json
```

**Note**: The service account ([`k8s/serviceaccount.yaml`](./k8s/serviceaccount.yaml)) is already configured to reference this secret via `imagePullSecrets`.

#### Step 1: Configure Secrets

Update Kubernetes secrets with your OIDC configuration:

```bash
# Edit k8s/secret.yaml with your credentials
nano k8s/secret.yaml

# Base64 encode your values
echo -n "your-oidc-client-id" | base64
echo -n "your-oidc-client-secret" | base64
echo -n "your-cookie-hash-key" | base64
echo -n "your-cookie-block-key" | base64
```

#### Step 2: Deploy with Skaffold

```bash
# Deploy with default profile (PostgreSQL + Valkey + STS)
skaffold dev

# Deploy with Istio profile (includes service mesh)
skaffold dev -p istio

# Build and deploy for production
skaffold run
```

**What Skaffold Does**:
1. Builds Docker image from Dockerfile
2. Deploys PostgreSQL via Helm chart (Bitnami) with persistent storage
3. Deploys Valkey via Helm chart (Bitnami)
4. Applies Kubernetes manifests from `k8s/` directory
5. Watches for code changes and automatically rebuilds/redeploys
6. Streams logs from all pods

**Database Credentials** (configured in [`k8s/secret.yaml`](./k8s/secret.yaml)):
- **Username**: `stsuser`
- **Password**: `stspassword` (⚠️ CHANGE IN PRODUCTION!)
- **Database**: `sts`
- **Service**: `postgresql:5432`
- **Connection String**: `postgres://stsuser:stspassword@postgresql:5432/sts?sslmode=disable`

#### Step 3: Run Database Migrations

**Important**: After deployment, run migrations before the service can function:

```bash
# Wait for PostgreSQL to be ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=postgresql --timeout=120s

# Run migrations
kubectl exec -it deployment/secure-token-service -- ./bin/sts migrate

# Verify migration
kubectl exec -it deployment/secure-token-service -- sh -c \
  'psql "$DATABASE_URL" -c "SELECT sid, kid, created_at FROM hydra_jwk;"'
```

#### Step 4: Access Services

```bash
# Port-forward HTTP server
kubectl port-forward svc/secure-token-service 8080:8080

# Port-forward gRPC server
kubectl port-forward svc/secure-token-service 9090:9090

# Access JWKS endpoint
curl http://localhost:8080/.well-known/jwks.json
```

#### Step 4: View Logs

```bash
# View STS logs
kubectl logs -f deployment/secure-token-service

# View Valkey logs
kubectl logs -f deployment/valkey

# View all logs
skaffold dev --tail
```

#### Cleanup

```bash
# Delete resources
skaffold delete

# Or manually
kubectl delete -f k8s/
helm uninstall valkey
```

**Istio Profile Features**:
- Ambient mesh mode (sidecarless)
- Gateway for HTTP traffic exposure
- Internal gRPC service mesh
- Mutual TLS between services

---

### Setup Method 3: Local Development (Native)

Run the service natively on your machine for development.

#### Step 1: Install Dependencies

```bash
# Install Go dependencies
make install-deps

# Install PostgreSQL (Ubuntu/Debian)
sudo apt-get install postgresql postgresql-contrib

# Install Valkey (or use Docker)
docker run -d -p 6379:6379 --name valkey valkey/valkey:9-alpine

# Install development tools
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

#### Step 2: Setup PostgreSQL

```bash
# Start PostgreSQL service
sudo systemctl start postgresql

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE sts;
CREATE USER stsuser WITH PASSWORD 'stspass';
GRANT ALL PRIVILEGES ON DATABASE sts TO stsuser;
EOF
```

#### Step 3: Run Migrations

**Important**: Run migrations before first start.

```bash
# Set database URL
export DATABASE_URL=postgres://stsuser:stspass@localhost:5432/sts?sslmode=disable

# Build the binary
make build

# Run migrations
./bin/sts migrate
```

#### Step 4: Configure Environment

Create a `.env` file or export variables:

```bash
# Create .env file
cat > .env << 'EOF'
# Database
DATABASE_URL=postgres://stsuser:stspass@localhost:5432/sts?sslmode=disable

# Cache
CACHE_ADDR=localhost:6379
CACHE_PASSWORD=
CACHE_DB=0

# Servers
HTTP_PORT=8080
GRPC_PORT=9090

# JWT
JWT_ISSUER=session-service
JWT_AUDIENCE=internal-services
JWT_EXPIRY=3600

# OIDC (update these!)
OIDC_PROVIDER_URL=https://your-oidc-provider.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URL=http://localhost:8080/auth/callback

# Cookies (generate secure random keys!)
COOKIE_HASH_KEY=$(openssl rand -hex 64)
COOKIE_BLOCK_KEY=$(openssl rand -hex 32)
EOF

# Load environment variables
export $(cat .env | xargs)
```

#### Step 4: Build and Run

```bash
# Build the binary
make build

# Run the service
./bin/sts serve

# Or combine
make run
```

#### Step 5: Development Workflow

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage

# Format code
make fmt

# Lint code
make lint

# Generate protobuf (if modified)
make proto

# Rotate JWKS
./bin/sts rotate-key
```

#### Step 6: Verify Setup

```bash
# In separate terminals:

# Terminal 1: Run service
./bin/sts serve

# Terminal 2: Test endpoints
curl http://localhost:8080/.well-known/jwks.json

# Install grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List gRPC services
grpcurl -plaintext localhost:9090 list

# Test session exchange (requires valid session_id)
grpcurl -plaintext -d '{"session_id": "test-session"}' \
  localhost:9090 sts.v1.SecurityTokenService/ExchangeSession
```

#### Debugging

```bash
# Run with debug logging
LOG_LEVEL=debug ./bin/sts serve

# Run with Delve debugger
dlv debug ./cmd/sts -- serve

# Profile CPU usage
go tool pprof http://localhost:6060/debug/pprof/profile

# View test coverage
make test-coverage
open coverage.html
```

---

### Common Tasks

#### Run Database Migrations

**Required**: Must be run before first use and when upgrading.

**Option 1: Manual Execution (Quick)**

```bash
# Docker Compose
docker-compose exec secure-token-service ./bin/sts migrate

# Kubernetes - Direct execution
kubectl exec -it deployment/secure-token-service -- ./bin/sts migrate

# Local
./bin/sts migrate

# With custom database URL
./bin/sts migrate --database-url="postgres://user:pass@host:5432/db"
```

**Option 2: Using Kubernetes CronJob Template**

The migration CronJob ([`k8s/migration-cronjob.yaml`](./k8s/migration-cronjob.yaml)) provides a managed way to run migrations:

```bash
# Run migration immediately (create Job from CronJob)
kubectl create job sts-migration-manual --from=cronjob/sts-migration

# Watch the migration job
kubectl logs -f job/sts-migration-manual

# Check job status
kubectl get jobs -l component=migration

# Enable automatic scheduled runs (edit schedule as needed)
kubectl patch cronjob sts-migration -p '{"spec":{"suspend":false}}'

# View CronJob status
kubectl get cronjob sts-migration
```

**CronJob Features**:
- ✓ Waits for PostgreSQL to be ready (init container)
- ✓ Idempotent migrations (safe to run multiple times)
- ✓ Suspended by default (manual trigger only)
- ✓ Configurable schedule (default: 2 AM daily)
- ✓ Automatic cleanup of old jobs
- ✓ Uses same credentials as main service

**Scheduling Options**:

```bash
# Run daily at 2 AM UTC (default)
schedule: "0 2 * * *"

# Run every 6 hours
schedule: "0 */6 * * *"

# Run weekly on Sunday at midnight
schedule: "0 0 * * 0"

# Run on the 1st of every month
schedule: "0 0 1 * *"
```

#### Rotate JWKS Keys

```bash
# Docker Compose
docker-compose exec secure-token-service ./bin/sts rotate-key

# Kubernetes
kubectl exec -it deployment/secure-token-service -- ./bin/sts rotate-key

# Local
./bin/sts rotate-key
```

#### View Database

```bash
# Docker Compose
docker-compose exec postgres psql -U postgres -d sts

# Kubernetes (if PostgreSQL is deployed)
kubectl exec -it postgres-0 -- psql -U postgres -d sts

# Local
psql -U stsuser -d sts

# Useful queries
SELECT sid, kid, created_at FROM hydra_jwk ORDER BY created_at DESC;
SELECT * FROM hydra_jwk WHERE sid = 'public';
```

#### Clear Sessions

```bash
# Valkey CLI (Docker Compose)
docker-compose exec valkey valkey-cli
> KEYS session:*
> FLUSHDB

# Kubernetes
kubectl exec -it deployment/valkey -- valkey-cli FLUSHDB
```

#### Update Configuration

```bash
# Docker Compose: Edit docker-compose.yml then
docker-compose up -d --force-recreate secure-token-service

# Kubernetes: Edit k8s/secret.yaml or k8s/deployment.yaml then
kubectl apply -f k8s/

# Local: Edit .env and reload
export $(cat .env | xargs)
./bin/sts serve
```

---

### Troubleshooting

#### Service Won't Start

```bash
# Check logs
docker-compose logs secure-token-service
kubectl logs -f deployment/secure-token-service
journalctl -u sts -f

# Common issues:
# 1. PostgreSQL not ready - wait for health check
# 2. Valkey connection failed - check CACHE_ADDR
# 3. Missing OIDC config - update environment variables
```

#### JWKS Endpoint Returns Empty

```bash
# Check if initial key was generated
psql -U postgres -d sts -c "SELECT * FROM hydra_jwk;"

# If empty, service didn't start properly - check logs
# Should see: "Database migrations completed" and "Key manager initialized"
```

#### gRPC Connection Refused

```bash
# Verify port is listening
netstat -tlnp | grep 9090
lsof -i :9090

# Check firewall
sudo ufw status
sudo ufw allow 9090
```

#### Session Exchange Fails

```bash
# Check Valkey connection
docker-compose exec valkey valkey-cli ping

# Verify session exists
valkey-cli GET session:your-session-id

# Check logs for authentication errors
```

---

---

## CLI Reference

The STS binary provides several commands for managing the service:

```bash
# Start the HTTP and gRPC servers
./bin/sts serve

# Run database migrations (required before first use)
./bin/sts migrate [--database-url=<url>]

# Rotate JWKS signing keys
./bin/sts rotate-key

# Show help for all commands
./bin/sts --help

# Show help for specific command
./bin/sts <command> --help
```

---

## API Reference

### gRPC Service

**Proto Definition**: [`api/proto/v1/sts.proto`](./api/proto/v1/sts.proto)

#### ExchangeSession

Exchanges an opaque session ID for an internal JWT.

**Request**:
```protobuf
message ExchangeRequest {
  string session_id = 1;
}
```

**Response**:
```protobuf
message ExchangeResponse {
  string access_token = 1;  // RS256-signed JWT
  int64 expires_in = 2;     // Seconds until expiration
}
```

**JWT Claims**:
```json
{
  "iss": "session-service",
  "sub": "user-uuid",
  "aud": "internal-services",
  "iat": 1612137600,
  "exp": 1612141200,
  "email": "user@example.com",
  "upstream_token": "..."
}
```

#### RevokeUserSessions

Revokes all sessions for a specific user.

**Request**:
```protobuf
message RevokeUserRequest {
  string user_id = 1;
}
```

**Response**:
```protobuf
message RevokeUserResponse {
  bool success = 1;
}
```

### HTTP Endpoints

#### GET /.well-known/jwks.json

Returns the JSON Web Key Set containing all public keys (active + retired) for JWT verification.

**Response**:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "janus-key-a1b2c3d4",
      "n": "<base64url-encoded-modulus>",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "janus-key-retired-xyz",
      "n": "<base64url-encoded-modulus>",
      "e": "AQAB"
    }
  ]
}
```

**Caching**: Services should cache JWKS with a TTL of 1 hour and refresh on verification failures.

---

## Security

### Threat Model

1. **Session Hijacking**: Mitigated by HttpOnly cookies, SameSite=Strict, Secure flag
2. **Token Leakage**: Internal JWTs never exposed to browser; opaque session IDs only
3. **Replay Attacks**: Short-lived JWTs (1 hour default), session revocation support
4. **Key Compromise**: Key rotation support, retired keys for verification only
5. **XSS Attacks**: HttpOnly cookies prevent JavaScript access to session tokens

### Best Practices

1. **Network Isolation**: Deploy Janus in trusted network, restrict gRPC access
2. **TLS Everywhere**: Use mTLS for gRPC, HTTPS for HTTP endpoints
3. **Key Rotation**: Rotate JWKS every 90 days (automated via cron)
4. **Session Expiry**: Align JWT expiry with upstream token expiry
5. **Audit Logging**: Log all session creation, exchange, and revocation events
6. **Rate Limiting**: Implement rate limits on `/auth/callback` and gRPC endpoints

### Production Checklist

- [ ] Configure strong `COOKIE_HASH_KEY` and `COOKIE_BLOCK_KEY` (cryptographically random)
- [ ] Enable PostgreSQL SSL mode (`sslmode=require`)
- [ ] Enable Valkey/Redis AUTH and TLS
- [ ] Set up automated JWKS rotation (cron job every 90 days)
- [ ] Configure gRPC authentication interceptor
- [ ] Implement network policies (restrict gRPC to authorized services)
- [ ] Enable audit logging for session operations
- [ ] Set up monitoring and alerting for failed authentications
- [ ] Configure backup and disaster recovery for PostgreSQL
- [ ] Review and harden OIDC scopes and claims

---

## License

Copyright 2025 Canonical Ltd.  
Licensed under AGPL-3.0

---

## Related Documentation

- [Specification (ID052)](https://docs.google.com/document/d/1jIt1WbS6CLxpFIW0hWhQUhX7xN2qr43_xOALT5zHoKs/edit?usp=sharing)
- [JWKS PostgreSQL Migration Walkthrough](./docs/jwks-migration.md)
- [Phantom Token Pattern](https://curity.io/resources/learn/phantom-token-pattern/)
- [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)