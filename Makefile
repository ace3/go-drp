# ─── Config ──────────────────────────────────────────────────────────────────
APP_NAME   := go-drp
BUILD_DIR  := bin
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    := -ldflags "-X main.version=$(VERSION) -w -s"
GOFLAGS    := -trimpath

# Detect OS for open command
OPEN := $(shell command -v xdg-open 2>/dev/null || echo open)

.DEFAULT_GOAL := help

# ─── Help ─────────────────────────────────────────────────────────────────────
.PHONY: help
help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ─── Build ────────────────────────────────────────────────────────────────────
.PHONY: build
build: ## Build binary for the current platform → bin/go-drp
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) .
	@echo "Built $(BUILD_DIR)/$(APP_NAME) (version=$(VERSION))"

.PHONY: build-all
build-all: ## Cross-compile for Linux/macOS/Windows (amd64 + arm64)
	@mkdir -p $(BUILD_DIR)
	@for os in linux darwin windows; do \
	  for arch in amd64 arm64; do \
	    ext=""; \
	    [ "$$os" = "windows" ] && ext=".exe"; \
	    output="$(BUILD_DIR)/$(APP_NAME)-$$os-$$arch$$ext"; \
	    echo "Building $$output..."; \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) $(LDFLAGS) -o "$$output" . || exit 1; \
	  done; \
	done
	@echo "All platform binaries in $(BUILD_DIR)/"

# ─── Run ──────────────────────────────────────────────────────────────────────
.PHONY: run
run: ## Run the gateway locally (requires .env or exported env vars)
	go run $(LDFLAGS) .

# ─── Test ─────────────────────────────────────────────────────────────────────
.PHONY: test
test: ## Run tests with race detector
	go test -v -race ./...

.PHONY: test-short
test-short: ## Run tests without -v (faster summary)
	go test -race ./...

.PHONY: coverage
coverage: ## Generate HTML coverage report → coverage.html
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"
	@$(OPEN) coverage.html 2>/dev/null || true

.PHONY: coverage-text
coverage-text: ## Print per-function coverage to stdout
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

# ─── Code Quality ─────────────────────────────────────────────────────────────
.PHONY: fmt
fmt: ## Format all Go source files
	go fmt ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint (install with: make install-tools)
	golangci-lint run ./...

.PHONY: check
check: fmt vet test ## fmt + vet + test (pre-commit gate)

# ─── Modules ──────────────────────────────────────────────────────────────────
.PHONY: tidy
tidy: ## Tidy and verify go.mod / go.sum
	go mod tidy
	go mod verify

# ─── Docker ───────────────────────────────────────────────────────────────────
.PHONY: docker-build
docker-build: ## Build Docker image tagged as go-drp:$(VERSION)
	docker build --build-arg VERSION=$(VERSION) -t $(APP_NAME):$(VERSION) -t $(APP_NAME):latest .

.PHONY: docker-run
docker-run: ## Run Docker image (reads from .env file)
	docker compose up

.PHONY: docker-down
docker-down: ## Stop and remove Docker containers
	docker compose down

.PHONY: docker-logs
docker-logs: ## Tail Docker container logs
	docker compose logs -f

# ─── Tools ────────────────────────────────────────────────────────────────────
.PHONY: install-tools
install-tools: ## Install development tools (golangci-lint)
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# ─── Clean ────────────────────────────────────────────────────────────────────
.PHONY: clean
clean: ## Remove build artefacts and coverage files
	rm -rf $(BUILD_DIR)/ coverage.out coverage.html
