# Makefile for Session Service (Janus)

.PHONY: all build build-all test clean run install-deps proto

# Variables
GO?=go
GO_BIN?=app
BINARY_PATH?=bin/$(GO_BIN)
BINARY_ARCHS?=amd64 arm64 riscv64
CMD_PATH=./cmd/sts
PROTO_PATH=api/proto/v1
CGO_ENABLED?=0
GOOS?=$(shell $(GO) env GOOS)
GOARCH?=$(shell $(GO) env GOARCH)
GO_TEST_PARALLEL?=10

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
	$(GO) test -v -p $(GO_TEST_PARALLEL) ./... -cover -coverprofile coverage_source.out
	# Generate JSON output for CI/CD
	@if [ -n "$(DOCKER_HOST)" ]; then export DOCKER_HOST=$(DOCKER_HOST); fi; \
	$(GO) test -v -p $(GO_TEST_PARALLEL) ./... -cover -coverprofile coverage_source.out -json > test_source.json
	# Filter out mock files from coverage
	cat coverage_source.out | grep -v "mock_*" | tee coverage.out
	cat test_source.json | grep -v "mock_*" | tee test.json
.PHONY: test

# Run tests with short flag (skips long-running tests, max 10 concurrent)
test-short: mocks vet
	@if [ -n "$(DOCKER_HOST)" ]; then export DOCKER_HOST=$(DOCKER_HOST); fi; \
	$(GO) test -v -p $(GO_TEST_PARALLEL) ./... -short -cover
.PHONY: test-short

# Run integration tests with parallelization (requires Docker/Podman)
test-integration: mocks
	@if [ -n "$(DOCKER_HOST)" ]; then export DOCKER_HOST=$(DOCKER_HOST); fi; \
	$(GO) test -v -p $(GO_TEST_PARALLEL) ./internal/auth ./internal/session ./internal/db -cover
.PHONY: test-integration

# Vet code
vet:
	$(GO) vet ./...
.PHONY: vet

# Vendor dependencies
vendor:
	$(GO) mod vendor
.PHONY: vendor

govulncheck: vendor
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	PATH="$$($(GO) env GOPATH)/bin:$$PATH" govulncheck ./...
.PHONY: govulncheck

# Build the binary
build:
	@echo "Building $(GO_BIN) ($(GOOS)/$(GOARCH))..."
	@mkdir -p bin
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -o $(BINARY_PATH) $(CMD_PATH)
	@echo "Build complete: $(BINARY_PATH)"
.PHONY: build

# Build binaries for all supported architectures (amd64, arm64, riscv64)
build-all:
	@mkdir -p bin
	@for arch in $(BINARY_ARCHS); do \
		echo "Building $(GO_BIN) (linux/$$arch)..."; \
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=$$arch $(GO) build -o bin/$(GO_BIN)-linux-$$arch $(CMD_PATH) || exit 1; \
		echo "Build complete: bin/$(GO_BIN)-linux-$$arch"; \
	done
.PHONY: build-all

# Run the service
run: build
	./$(BINARY_PATH) serve

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

# Google harness2 x OpenSpec targets
harness2-validate:
	PYTHONPATH=.harness2 python3 -m openspec_harness.cli validate-harnesses
.PHONY: harness2-validate

harness2-audit:
	PYTHONPATH=.harness2 python3 -m openspec_harness.cli audit
.PHONY: harness2-audit

harness2-sweep:
	PYTHONPATH=.harness2 python3 -m openspec_harness.cli sweep --substrate oc --modes parallel,sequential --k 1,2
.PHONY: harness2-sweep

harness2-remediate:
	PYTHONPATH=.harness2 python3 -m openspec_harness.cli remediate
.PHONY: harness2-remediate

harness2-test:
	PYTHONPATH=.harness2 pytest .harness2/tests -v
.PHONY: harness2-test


