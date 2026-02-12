# Makefile for Session Service (Janus)

.PHONY: all build test clean run install-deps proto

# Variables
GO_BIN?=app
BINARY_PATH=bin/$(BINARY_NAME)
CMD_PATH=./cmd/sts
PROTO_PATH=api/proto/v1
GOFLAGS?=-ldflags=-w -ldflags=-s -a -buildvcs
CGO_ENABLED?=0
GO?=go

# Podman support - set DOCKER_HOST for testcontainers
# Usage: make test DOCKER_HOST=unix://$${XDG_RUNTIME_DIR}/podman/podman.sock
DOCKER_HOST?=

# Default target
all: build

# Install Go dependencies
install-deps:
	go mod download
	go mod tidy
	$(GO) mod download
	$(GO) mod tidy

# Mock generation - install mockgen and generate all mocks
mocks: vendor
	$(GO) install go.uber.org/mock/mockgen@latest
	# Generate all mocks via go:generate directives
	$(GO) generate ./...
.PHONY: mocks

# Run tests with coverage and parallelization (max 10 concurrent tests)
test: mocks vet
	@if [ -n "$(DOCKER_HOST)" ]; then \
		echo "Using DOCKER_HOST=$(DOCKER_HOST)"; \
		export DOCKER_HOST=$(DOCKER_HOST); \
	fi; \
	$(GO) test -v -p 10 -parallel 10 ./... -cover -coverprofile coverage_source.out
	# Generate JSON output for CI/CD
	@if [ -n "$(DOCKER_HOST)" ]; then export DOCKER_HOST=$(DOCKER_HOST); fi; \
	$(GO) test -v -p 10 -parallel 10 ./... -cover -coverprofile coverage_source.out -json > test_source.json
	# Filter out mock files from coverage
	cat coverage_source.out | grep -v "mock_*" | tee coverage.out
	cat test_source.json | grep -v "mock_*" | tee test.json
.PHONY: test

# Run tests with short flag (skips long-running tests, max 10 concurrent)
test-short: mocks vet
	@if [ -n "$(DOCKER_HOST)" ]; then export DOCKER_HOST=$(DOCKER_HOST); fi; \
	$(GO) test -v -p 10 -parallel 10 ./... -short -cover
.PHONY: test-short

# Run integration tests with parallelization (requires Docker/Podman)
test-integration: mocks
	@if [ -n "$(DOCKER_HOST)" ]; then export DOCKER_HOST=$(DOCKER_HOST); fi; \
	$(GO) test -v -p 10 -parallel 10 ./internal/auth ./internal/session ./internal/db -cover
.PHONY: test-integration

# Vet code
vet:
	$(GO) vet ./...
.PHONY: vet

# Vendor dependencies
vendor:
	$(GO) mod vendor
.PHONY: vendor

# Build the binary
build:
	$(GO) build -o $(GO_BIN) ./cmd/sts
.PHONY: build

# Run the service
run: build
# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -rf keys/
	@echo "Clean complete"

# Generate protobuf code (requires protoc)
proto:
	@echo "Generating protobuf code..."
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_PATH)/sts.proto
	@echo "Protobuf generation complete"

# Format code
fmt:
	go fmt ./...

# Lint code (requires golangci-lint)
lint:
	golangci-lint run

