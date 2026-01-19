#!/usr/bin/env bash
# =============================================================================
# ATB Quick Start Script
# =============================================================================
# One-command setup for new developers.
#
# Usage:
#   ./scripts/quickstart.sh
#
# This script will:
#   1. Check prerequisites (Go, Python, OPA, Docker)
#   2. Set up Python virtual environment
#   3. Install pre-commit hooks
#   4. Generate dev certificates
#   5. Run all tests
#   6. Optionally start the local stack
#
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$REPO_ROOT"

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           ATB - Agent Trust Broker Quick Start               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# =============================================================================
# Check Prerequisites
# =============================================================================
echo -e "${YELLOW}Checking prerequisites...${NC}"

MISSING=()

# Check Go
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "${GREEN}✓ Go installed ($GO_VERSION)${NC}"
else
    MISSING+=("go")
    echo -e "${RED}✗ Go not found${NC}"
fi

# Check Python
if command -v python3 &> /dev/null; then
    PY_VERSION=$(python3 --version)
    echo -e "${GREEN}✓ Python installed ($PY_VERSION)${NC}"
else
    MISSING+=("python3")
    echo -e "${RED}✗ Python 3 not found${NC}"
fi

# Check OPA
if command -v opa &> /dev/null; then
    OPA_VERSION=$(opa version | head -1)
    echo -e "${GREEN}✓ OPA installed ($OPA_VERSION)${NC}"
else
    MISSING+=("opa")
    echo -e "${RED}✗ OPA not found${NC}"
    echo "   Install: brew install opa (macOS) or see https://www.openpolicyagent.org/docs/latest/#running-opa"
fi

# Check Docker (optional)
if command -v docker &> /dev/null; then
    echo -e "${GREEN}✓ Docker installed${NC}"
else
    echo -e "${YELLOW}⚠ Docker not found (optional, needed for docker-compose)${NC}"
fi

# Check OpenSSL
if command -v openssl &> /dev/null; then
    echo -e "${GREEN}✓ OpenSSL installed${NC}"
else
    MISSING+=("openssl")
    echo -e "${RED}✗ OpenSSL not found${NC}"
fi

# Check jq (for demo/test scripts)
if command -v jq &> /dev/null; then
    echo -e "${GREEN}✓ jq installed${NC}"
else
    echo -e "${YELLOW}⚠ jq not found (needed for demo/test scripts)${NC}"
    echo "   Install: brew install jq (macOS)"
fi

echo ""

if [ ${#MISSING[@]} -gt 0 ]; then
    echo -e "${RED}Missing required tools: ${MISSING[*]}${NC}"
    echo "Please install them and run this script again."
    exit 1
fi

# =============================================================================
# Setup Python Virtual Environment
# =============================================================================
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo -e "${GREEN}✓ Created .venv${NC}"
else
    echo -e "${GREEN}✓ .venv already exists${NC}"
fi

source .venv/bin/activate
pip install --quiet --upgrade pip

# Install Python dependencies
if [ -f "atb-gateway-py/requirements.txt" ]; then
    pip install --quiet -r atb-gateway-py/requirements.txt
    echo -e "${GREEN}✓ Installed atb-gateway-py dependencies${NC}"
fi

# Install dev dependencies
pip install --quiet pyjwt cryptography pre-commit
echo -e "${GREEN}✓ Installed dev dependencies${NC}"

# =============================================================================
# Install Pre-commit Hooks
# =============================================================================
echo ""
echo -e "${YELLOW}Installing pre-commit hooks...${NC}"

if [ -f ".pre-commit-config.yaml" ]; then
    pre-commit install --install-hooks 2>/dev/null || pre-commit install
    echo -e "${GREEN}✓ Pre-commit hooks installed${NC}"
else
    echo -e "${YELLOW}⚠ No .pre-commit-config.yaml found${NC}"
fi

# =============================================================================
# Generate Development Certificates
# =============================================================================
echo ""
echo -e "${YELLOW}Generating development certificates...${NC}"

if [ ! -f "dev/certs/ca.crt" ]; then
    if [ -f "dev/certs/gen_certs.sh" ]; then
        cd dev/certs && chmod +x gen_certs.sh && ./gen_certs.sh
        cd "$REPO_ROOT"
        echo -e "${GREEN}✓ Generated mTLS certificates${NC}"
    else
        echo -e "${YELLOW}⚠ Certificate generation script not found${NC}"
    fi
else
    echo -e "${GREEN}✓ Certificates already exist${NC}"
fi

# Generate PoA signing keys
if [ ! -f "dev/poa_rsa.key" ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out dev/poa_rsa.key 2>/dev/null
    openssl rsa -pubout -in dev/poa_rsa.key -out dev/poa_rsa.pub 2>/dev/null
    echo -e "${GREEN}✓ Generated PoA signing keys${NC}"
else
    echo -e "${GREEN}✓ PoA keys already exist${NC}"
fi

# =============================================================================
# Build Go Binaries
# =============================================================================
echo ""
echo -e "${YELLOW}Building Go binaries...${NC}"

cd atb-gateway-go
go build -o bin/broker ./cmd/broker
go build -o bin/agentauth ./cmd/agentauth
cd "$REPO_ROOT"
echo -e "${GREEN}✓ Built broker and agentauth${NC}"

# =============================================================================
# Run Tests
# =============================================================================
echo ""
echo -e "${YELLOW}Running tests...${NC}"

# OPA tests
echo "  Running OPA policy tests..."
opa test opa/policy/ -v
echo -e "${GREEN}✓ OPA tests passed${NC}"

# Go tests
echo "  Running Go tests..."
cd atb-gateway-go && go test -v ./... 2>&1 | tail -5
cd "$REPO_ROOT"
echo -e "${GREEN}✓ Go tests passed${NC}"

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete! 🎉                         ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                               ║"
echo "║  Quick Commands:                                              ║"
echo "║    make help          - Show all available commands          ║"
echo "║    make run-opa       - Start OPA server                     ║"
echo "║    make demo          - Run interactive demo                 ║"
echo "║    make docker-up     - Start full Docker stack              ║"
echo "║                                                               ║"
echo "║  Development:                                                 ║"
echo "║    make test          - Run all tests                        ║"
echo "║    make build         - Build binaries                       ║"
echo "║    make lint          - Run linters                          ║"
echo "║                                                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Ask if user wants to start the stack
echo ""
read -p "Would you like to start OPA and run the demo? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Starting OPA in background...${NC}"
    opa run --server --addr 127.0.0.1:8181 opa/policy/poa.rego &
    OPA_PID=$!
    sleep 2

    echo ""
    ./dev/demo.sh

    echo ""
    echo -e "${YELLOW}Stopping OPA...${NC}"
    kill $OPA_PID 2>/dev/null || true
    echo -e "${GREEN}Done!${NC}"
fi
