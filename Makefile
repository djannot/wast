# WAST Makefile
# Web Application Security Testing CLI

# Variables
BINARY_NAME := wast
BUILD_DIR := bin
CMD_DIR := cmd/wast
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOVET := $(GOCMD) vet
GOFMT := gofmt

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

# Build for multiple platforms
.PHONY: build-all
build-all:
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./$(CMD_DIR)
	@echo "Build complete for all platforms"

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -timeout 20m -coverprofile=coverage.out ./...
	@echo "Tests complete"

# Run integration tests
.PHONY: test-integration
test-integration:
	@echo "Running integration tests..."
	$(GOTEST) -v -tags=integration -race ./internal/mcp/
	@echo "Integration tests complete"

# Run DVWA integration tests
.PHONY: test-dvwa
test-dvwa:
	@echo "Running DVWA integration tests..."
	@echo "Starting DVWA containers (this may take a minute)..."
	$(GOTEST) -v -tags=integration -race -timeout 15m ./test/integration/
	@echo "DVWA integration tests complete"

# Run Juice Shop integration tests
.PHONY: test-juiceshop
test-juiceshop:
	@echo "Running Juice Shop integration tests..."
	@echo "Starting Juice Shop container (this may take a minute)..."
	$(GOTEST) -v -tags=integration -race -timeout 15m ./test/integration/juiceshop/...
	@echo "Juice Shop integration tests complete"

# Run WebGoat integration tests
.PHONY: test-webgoat
test-webgoat:
	@echo "Running WebGoat integration tests..."
	@echo "Starting WebGoat container (this may take a minute)..."
	$(GOTEST) -v -tags=integration -race -timeout 15m ./test/integration/webgoat/...
	@echo "WebGoat integration tests complete"

# Run tests with coverage report
.PHONY: test-coverage
test-coverage: test
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run linters
.PHONY: lint
lint:
	@echo "Running linters..."
	$(GOVET) ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, skipping advanced linting"; \
	fi
	@echo "Lint complete"

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .
	@echo "Formatting complete"

# Check formatting
.PHONY: fmt-check
fmt-check:
	@echo "Checking code formatting..."
	@if [ -n "$$($(GOFMT) -l .)" ]; then \
		echo "Code is not formatted. Run 'make fmt' to fix."; \
		$(GOFMT) -l .; \
		exit 1; \
	fi
	@echo "Code formatting check passed"

# Download dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "Dependencies downloaded"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	@echo "Clean complete"

# Install the binary to GOPATH/bin
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME)..."
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	@echo "Installed to $(GOPATH)/bin/$(BINARY_NAME)"

# Run the application
.PHONY: run
run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

# Show help
.PHONY: help
help:
	@echo "WAST Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all              Build the binary (default)"
	@echo "  build            Build the binary"
	@echo "  build-all        Build for multiple platforms"
	@echo "  test             Run tests with coverage"
	@echo "  test-coverage    Generate HTML coverage report"
	@echo "  test-integration Run integration tests"
	@echo "  test-dvwa        Run DVWA integration tests"
	@echo "  test-juiceshop   Run Juice Shop integration tests"
	@echo "  test-webgoat     Run WebGoat integration tests"
	@echo "  lint             Run linters"
	@echo "  fmt              Format code"
	@echo "  fmt-check        Check code formatting"
	@echo "  deps             Download dependencies"
	@echo "  clean            Remove build artifacts"
	@echo "  install          Install binary to GOPATH/bin"
	@echo "  run              Build and run the application"
	@echo "  help             Show this help message"
