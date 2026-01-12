# ============================================================================
# ATB (Agent Trust Broker) Development Makefile
# ============================================================================

.PHONY: help setup test test-opa test-go lint build run-opa run-broker run-upstream \
        certs clean docker-build docker-up docker-down fmt check \
        sdk-python-test sdk-go-test sdk-test dashboard-dev dashboard-build \
        load-spike load-breakpoint

# Default target
help:
	@echo "ATB Development Commands"
	@echo "========================"
	@echo ""
	@echo "Quick Start:"
	@echo "  make quickstart     - One-command setup for new developers"
	@echo ""
	@echo "Setup:"
	@echo "  make setup          - Install all dependencies"
	@echo "  make certs          - Generate local dev certificates"
	@echo ""
	@echo "SDKs:"
	@echo "  make sdk-test       - Run all SDK tests (Python + Go)"
	@echo "  make sdk-python-test - Run Python SDK tests"
	@echo "  make sdk-go-test    - Run Go SDK tests"
	@echo ""
	@echo "Dashboard:"
	@echo "  make dashboard-dev  - Start dashboard dev server"
	@echo "  make dashboard-build - Build dashboard for production"
	@echo ""
	@echo "Testing:"
	@echo "  make test           - Run all tests (OPA + Go)"
	@echo "  make test-opa       - Run OPA policy tests"
	@echo "  make test-go        - Run Go tests with race detection"
	@echo "  make test-e2e       - Run E2E tests (requires OPA)"
	@echo "  make test-integration - Run Go integration tests"
	@echo "  make coverage       - Run tests with coverage report"
	@echo "  make demo           - Interactive demo of risk tiers"
	@echo ""
	@echo "Load Testing:"
	@echo "  make load-test      - Run k6 load test (requires k6)"
	@echo "  make load-stress    - Run k6 stress test"
	@echo "  make load-soak      - Run k6 soak test (2 hours)"
	@echo "  make load-spike     - Run k6 spike test"
	@echo "  make load-breakpoint - Run k6 breakpoint test"
	@echo ""
	@echo "Development:"
	@echo "  make run-opa        - Start OPA server (localhost:8181)"
	@echo "  make run-upstream   - Start echo upstream server"
	@echo "  make run-broker     - Build and run the broker"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build   - Build Docker images"
	@echo "  make docker-up      - Start full stack (OPA, Upstream, Broker, AgentAuth)"
	@echo "  make docker-up-minimal - Start minimal stack (OPA + Upstream only)"
	@echo "  make docker-down    - Stop all containers"
	@echo "  make docker-logs    - Follow container logs"
	@echo ""
	@echo "SPIRE Demo:"
	@echo "  make spire-demo-up  - Start SPIRE demo environment"
	@echo "  make spire-demo-test - Run SPIFFE identity flow demo"
	@echo "  make spire-demo-down - Stop SPIRE demo"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint           - Run linters (OPA + Go)"
	@echo "  make fmt            - Format code (Go)"
	@echo "  make check          - Run all checks (lint + test)"
	@echo "  make validate       - Validate all configs and policies"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs           - Generate API documentation"
	@echo ""
	@echo "Build:"
	@echo "  make build          - Build Go binaries"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean          - Remove build artifacts"

# ============================================================================
# Variables
# ============================================================================

GO_DIR := atb-gateway-go
PY_DIR := atb-gateway-py
OPA_DIR := opa/policy
DEV_DIR := dev
SDK_PY_DIR := sdk/python
SDK_GO_DIR := sdk/go
DASHBOARD_DIR := dashboard
VENV := .venv

# Go build settings
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# ============================================================================
# Quick Start
# ============================================================================

quickstart:
	@./scripts/quickstart.sh

# ============================================================================
# Setup
# ============================================================================

setup: setup-go setup-python setup-tools setup-hooks
	@echo "✅ Development environment ready!"

setup-go:
	@echo "📦 Installing Go dependencies..."
	cd $(GO_DIR) && go mod download

setup-python:
	@echo "🐍 Setting up Python virtual environment..."
	@if [ ! -d "$(VENV)" ]; then python3 -m venv $(VENV); fi
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r $(PY_DIR)/requirements.txt
	$(VENV)/bin/pip install pyjwt cryptography  # For PoA minting

setup-tools:
	@echo "🔧 Checking required tools..."
	@which opa >/dev/null 2>&1 || echo "⚠️  OPA not found. Install with: brew install opa"
	@which go >/dev/null 2>&1 || echo "⚠️  Go not found. Install from: https://go.dev/dl/"
	@which docker >/dev/null 2>&1 || echo "⚠️  Docker not found. Install from: https://docker.com"
	@which helm >/dev/null 2>&1 || echo "⚠️  Helm not found. Install with: brew install helm"

setup-hooks:
	@echo "🪝 Setting up pre-commit hooks..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install; \
		echo "✅ Pre-commit hooks installed"; \
	else \
		echo "⚠️  pre-commit not found. Install with: brew install pre-commit"; \
		echo "   Then run: pre-commit install"; \
	fi

# ============================================================================
# Testing
# ============================================================================

test: test-opa test-go
	@echo "✅ All tests passed!"

test-opa:
	@echo "🔍 Running OPA policy tests..."
	opa test $(OPA_DIR)/ -v --v0-compatible

test-go:
	@echo "🔍 Running Go tests..."
	cd $(GO_DIR) && go test -v -race ./...

coverage: coverage-opa coverage-go

coverage-opa:
	@echo "📊 OPA coverage..."
	opa test $(OPA_DIR)/ --coverage --format=json --v0-compatible | jq '.coverage'

coverage-go:
	@echo "📊 Go coverage..."
	cd $(GO_DIR) && go test -v -race -coverprofile=coverage.out ./...
	cd $(GO_DIR) && go tool cover -func=coverage.out
	@echo "📄 HTML report: $(GO_DIR)/coverage.html"
	cd $(GO_DIR) && go tool cover -html=coverage.out -o coverage.html

# ============================================================================
# Linting
# ============================================================================

lint: lint-opa lint-go
	@echo "✅ Linting complete!"

lint-opa:
	@echo "🔍 Checking OPA policy syntax..."
	opa check $(OPA_DIR)/
	opa fmt --diff $(OPA_DIR)/*.rego

lint-go:
	@echo "🔍 Running Go linters..."
	cd $(GO_DIR) && go vet ./...
	@which golangci-lint >/dev/null 2>&1 && cd $(GO_DIR) && golangci-lint run || echo "⚠️  golangci-lint not installed"

fmt:
	@echo "🎨 Formatting code..."
	cd $(GO_DIR) && go fmt ./...
	opa fmt -w $(OPA_DIR)/*.rego

check: lint test
	@echo "✅ All checks passed!"

# ============================================================================
# Development Servers
# ============================================================================

run-opa:
	@echo "🚀 Starting OPA server on http://localhost:8181..."
	@echo "   Decision endpoint: http://localhost:8181/v1/data/atb/poa/decision"
	opa run --server --addr 127.0.0.1:8181 $(OPA_DIR)/poa.rego

run-upstream:
	@echo "🚀 Starting upstream echo server on http://localhost:9000..."
	$(VENV)/bin/python $(DEV_DIR)/upstream_echo.py

run-broker:
	@echo "🏗️  Building broker..."
	cd $(GO_DIR) && go build -o bin/broker ./cmd/broker
	@echo "🚀 Starting ATB broker..."
	cd $(GO_DIR) && ./bin/broker

# ============================================================================
# Certificates
# ============================================================================

certs:
	@echo "🔐 Generating local development certificates..."
	cd $(DEV_DIR)/certs && chmod +x gen_certs.sh && ./gen_certs.sh
	@echo "✅ Certificates generated in $(DEV_DIR)/certs/"

certs-poa:
	@echo "🔐 Generating PoA signing keys..."
	@mkdir -p $(DEV_DIR)
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $(DEV_DIR)/poa_rsa.key
	openssl rsa -pubout -in $(DEV_DIR)/poa_rsa.key -out $(DEV_DIR)/poa_rsa.pub
	@echo "✅ PoA keys generated: $(DEV_DIR)/poa_rsa.key, $(DEV_DIR)/poa_rsa.pub"

# ============================================================================
# Build
# ============================================================================

build: build-broker build-agentauth

build-broker:
	@echo "🏗️  Building broker..."
	cd $(GO_DIR) && CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -ldflags="-s -w" -o bin/broker ./cmd/broker

build-agentauth:
	@echo "🏗️  Building agentauth..."
	cd $(GO_DIR) && CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -ldflags="-s -w" -o bin/agentauth ./cmd/agentauth

# ============================================================================
# Docker
# ============================================================================

docker-build:
	@echo "🐳 Building Docker images..."
	docker build -f $(GO_DIR)/Dockerfile.broker -t atb-broker:latest $(GO_DIR)
	docker build -f $(GO_DIR)/Dockerfile.agentauth -t atb-agentauth:latest $(GO_DIR)

docker-up:
	@echo "🐳 Starting Docker Compose stack..."
	docker compose up -d
	@echo "✅ Services started:"
	@echo "   OPA:        http://localhost:8181"
	@echo "   Upstream:   http://localhost:9000"
	@echo "   Broker:     https://localhost:8443 (mTLS)"
	@echo "   AgentAuth:  http://localhost:8444"

docker-up-minimal:
	@echo "🐳 Starting minimal Docker Compose stack (OPA + Upstream only)..."
	docker compose -f docker-compose.minimal.yaml up -d
	@echo "✅ Services started:"
	@echo "   OPA:        http://localhost:8181"
	@echo "   Upstream:   http://localhost:9000"

docker-down:
	@echo "🐳 Stopping Docker Compose stack..."
	docker compose down
	docker compose -f docker-compose.minimal.yaml down 2>/dev/null || true
	@echo "✅ Services stopped"

docker-logs:
	docker compose logs -f

# ============================================================================
# E2E Testing & Demo
# ============================================================================

demo: ## Run interactive demo showing risk tiers (requires OPA running)
	@./dev/demo.sh

demo-scenarios: ## Run 10 interactive demo scenarios
	@chmod +x scripts/demo-scenarios.sh
	@./scripts/demo-scenarios.sh

test-e2e: ## Run end-to-end tests (requires OPA running)
	@./dev/test_e2e.sh

test-integration: ## Run Go integration tests (requires OPA running)
	@echo "🔍 Running Go integration tests..."
	cd $(GO_DIR) && go test -tags=integration -v ./cmd/broker

# ============================================================================
# Documentation
# ============================================================================

docs: ## Generate API documentation from OpenAPI specs
	@echo "📚 Generating API documentation..."
	@chmod +x ./scripts/gen_api_docs.sh
	@./scripts/gen_api_docs.sh

# ============================================================================
# Load Testing
# ============================================================================

load-test: ## Run k6 load test (requires k6)
	@echo "🔥 Running load test..."
	@which k6 >/dev/null 2>&1 || (echo "⚠️  k6 not found. Install with: brew install k6" && exit 1)
	k6 run tests/load/atb_load.js

load-stress: ## Run k6 stress test
	@echo "🔥 Running stress test..."
	@which k6 >/dev/null 2>&1 || (echo "⚠️  k6 not found. Install with: brew install k6" && exit 1)
	k6 run --config tests/load/stress.json tests/load/atb_load.js

load-soak: ## Run k6 soak test (2 hours)
	@echo "🔥 Running soak test (2 hours)..."
	@which k6 >/dev/null 2>&1 || (echo "⚠️  k6 not found. Install with: brew install k6" && exit 1)
	k6 run --config tests/load/soak.json tests/load/atb_load.js

load-spike: ## Run k6 spike test
	@echo "🔥 Running spike test..."
	@which k6 >/dev/null 2>&1 || (echo "⚠️  k6 not found. Install with: brew install k6" && exit 1)
	k6 run tests/load/spike_test.js

load-breakpoint: ## Run k6 breakpoint test to find system limits
	@echo "🔥 Running breakpoint test..."
	@which k6 >/dev/null 2>&1 || (echo "⚠️  k6 not found. Install with: brew install k6" && exit 1)
	k6 run tests/load/breakpoint_test.js

# ============================================================================
# SDK Development
# ============================================================================

sdk-test: sdk-python-test sdk-go-test ## Run all SDK tests
	@echo "✅ All SDK tests passed!"

sdk-python-test: ## Run Python SDK tests
	@echo "🐍 Running Python SDK tests..."
	cd $(SDK_PY_DIR) && $(CURDIR)/$(VENV)/bin/pip install -e ".[dev]" && $(CURDIR)/$(VENV)/bin/pytest tests/ -v

sdk-go-test: ## Run Go SDK tests
	@echo "🔍 Running Go SDK tests..."
	cd $(SDK_GO_DIR) && go mod tidy && go test -v -race ./...

sdk-python-build: ## Build Python SDK package
	@echo "📦 Building Python SDK..."
	cd $(SDK_PY_DIR) && pip install build && python -m build

# ============================================================================
# Dashboard
# ============================================================================

dashboard-install: ## Install dashboard dependencies
	@echo "📦 Installing dashboard dependencies..."
	cd $(DASHBOARD_DIR) && npm install

dashboard-dev: dashboard-install ## Start dashboard development server
	@echo "🚀 Starting dashboard on http://localhost:3000..."
	cd $(DASHBOARD_DIR) && npm run dev

dashboard-build: dashboard-install ## Build dashboard for production
	@echo "🏗️  Building dashboard..."
	cd $(DASHBOARD_DIR) && npm run build
	@echo "✅ Dashboard built in $(DASHBOARD_DIR)/dist/"

dashboard-preview: dashboard-build ## Preview production build
	cd $(DASHBOARD_DIR) && npm run preview

# ============================================================================
# SPIRE Demo
# ============================================================================

spire-demo-setup: ## Generate keys for SPIRE demo
	@echo "🔐 Generating SPIRE demo keys..."
	@chmod +x dev/spire-demo/scripts/gen-keys.sh
	@cd dev/spire-demo && ./scripts/gen-keys.sh

spire-demo-up: spire-demo-setup ## Start SPIRE demo environment
	@echo "🚀 Starting SPIRE demo environment..."
	@cd dev/spire-demo && docker compose up -d
	@echo "⏳ Waiting for SPIRE to initialize..."
	@sleep 10
	@echo "✅ SPIRE demo running!"
	@echo ""
	@echo "Next steps:"
	@echo "  make spire-demo-test    - Run the SPIFFE identity flow demo"
	@echo "  make spire-demo-logs    - View logs"
	@echo "  make spire-demo-down    - Stop the demo"

spire-demo-down: ## Stop SPIRE demo environment
	@echo "🛑 Stopping SPIRE demo..."
	@cd dev/spire-demo && docker compose down -v
	@echo "✅ SPIRE demo stopped!"

spire-demo-logs: ## View SPIRE demo logs
	@cd dev/spire-demo && docker compose logs -f

spire-demo-test: ## Test SPIRE server functionality
	@echo "🧪 Testing SPIRE server..."
	@cd dev/spire-demo && docker compose exec spire-server \
		/opt/spire/bin/spire-server healthcheck && echo "✅ SPIRE Server: Healthy"
	@echo ""
	@echo "📝 Generating join token..."
	@cd dev/spire-demo && docker compose exec spire-server \
		/opt/spire/bin/spire-server token generate \
		-spiffeID spiffe://atb.example.org/agent/test \
		-ttl 300
	@echo ""
	@echo "🔍 Testing OPA..."
	@curl -s http://localhost:8182/health > /dev/null && echo "✅ OPA: Healthy"
	@echo ""
	@echo "🌐 Testing upstream echo server..."
	@curl -s http://localhost:9001 | head -c 100 && echo "..."
	@echo ""
	@echo "✅ All SPIRE demo services are working!"

spire-demo-entries: ## List SPIRE workload entries
	@cd dev/spire-demo && docker compose exec spire-server \
		/opt/spire/bin/spire-server entry show \
		-socketPath /tmp/spire-server/private/api.sock

# ============================================================================
# Validation
# ============================================================================

validate: ## Validate all configuration and policy files
	@echo "🔍 Validating all configurations..."
	@chmod +x ./scripts/validate_all.sh
	@./scripts/validate_all.sh

# ============================================================================
# Cleanup
# ============================================================================

clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf $(GO_DIR)/bin/
	rm -rf $(GO_DIR)/coverage.out $(GO_DIR)/coverage.html
	rm -rf $(PY_DIR)/__pycache__/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -delete
	@echo "✅ Clean complete!"

clean-certs:
	@echo "🧹 Removing generated certificates..."
	rm -f $(DEV_DIR)/certs/ca.* $(DEV_DIR)/certs/server.* $(DEV_DIR)/certs/client.*
	rm -f $(DEV_DIR)/certs/client_ext.cnf
	rm -f $(DEV_DIR)/poa_rsa.*
	@echo "✅ Certificates removed!"

clean-all: clean clean-certs
	@echo "🧹 Removing virtual environment..."
	rm -rf $(VENV)
	@echo "✅ Full cleanup complete!"
