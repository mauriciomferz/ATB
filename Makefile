# ============================================================================
# ATB (Agent Trust Broker) Development Makefile
# ============================================================================

.PHONY: help setup test test-opa test-go lint build run-opa run-broker run-upstream \
        certs clean docker-build docker-up docker-down fmt check

# Default target
help:
	@echo "ATB Development Commands"
	@echo "========================"
	@echo ""
	@echo "Setup:"
	@echo "  make setup          - Install all dependencies"
	@echo "  make certs          - Generate local dev certificates"
	@echo ""
	@echo "Testing:"
	@echo "  make test           - Run all tests (OPA + Go)"
	@echo "  make test-opa       - Run OPA policy tests"
	@echo "  make test-go        - Run Go tests with race detection"
	@echo "  make coverage       - Run tests with coverage report"
	@echo ""
	@echo "Development:"
	@echo "  make run-opa        - Start OPA server (localhost:8181)"
	@echo "  make run-upstream   - Start echo upstream server"
	@echo "  make run-broker     - Build and run the broker"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint           - Run linters (OPA + Go)"
	@echo "  make fmt            - Format code (Go)"
	@echo "  make check          - Run all checks (lint + test)"
	@echo ""
	@echo "Build:"
	@echo "  make build          - Build Go binaries"
	@echo "  make docker-build   - Build Docker images"
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
VENV := .venv

# Go build settings
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# ============================================================================
# Setup
# ============================================================================

setup: setup-go setup-python setup-tools
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
