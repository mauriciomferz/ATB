#!/usr/bin/env bash
# =============================================================================
# Quick Demo Script for ATB
# =============================================================================
# Demonstrates the ATB workflow with different risk tiers.
#
# Prerequisites:
#   - make certs && make certs-poa
#   - make docker-up-minimal  (or make run-opa)
#
# Usage:
#   ./dev/demo.sh
#
# =============================================================================

set -euo pipefail

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
VENV="$REPO_ROOT/.venv"
OPA_URL="${OPA_URL:-http://localhost:8181}"

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           ATB - Agent Trust Broker Demo                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check OPA is running
if ! curl -s "$OPA_URL/health" > /dev/null 2>&1; then
    echo -e "${RED}❌ OPA not running. Start with: make docker-up-minimal${NC}"
    exit 1
fi

echo -e "${GREEN}✓ OPA is running at $OPA_URL${NC}"
echo ""

# Helper to query OPA
query_opa() {
    local input="$1"
    curl -s -X POST "$OPA_URL/v1/data/atb/poa/decision" \
        -H "Content-Type: application/json" \
        -d "{\"input\": $input}" | jq .
}

# =============================================================================
# Demo 1: Low-Risk Action (No PoA needed for safe paths)
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Demo 1: Low-Risk Safe Path (Health Check)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Request: GET /health"
echo ""
echo "OPA Decision:"
query_opa '{"method": "GET", "path": "/health"}'
echo ""

# =============================================================================
# Demo 2: Medium-Risk Action (Requires Single Approval)
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Demo 2: Medium-Risk Action (CRM Update - Requires Approval)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Action: crm.contact.update"
echo "Risk Tier: MEDIUM"
echo "Requirement: Single approver"
echo ""

echo -e "${RED}Without approval (DENIED):${NC}"
query_opa '{
  "claim": {
    "act": "crm.contact.update",
    "sub": "spiffe://example.org/agent",
    "exp": 9999999999,
    "iat": 1704067200,
    "jti": "demo-med-1",
    "leg": {
      "basis": "contract",
      "jurisdiction": "US",
      "accountable_party": {"type": "human", "id": "alice@example.com"}
    }
  },
  "method": "POST",
  "path": "/crm/contact"
}'
echo ""

echo -e "${GREEN}With approval (ALLOWED):${NC}"
query_opa '{
  "claim": {
    "act": "crm.contact.update",
    "sub": "spiffe://example.org/agent",
    "exp": 9999999999,
    "iat": 1704067200,
    "jti": "demo-med-2",
    "leg": {
      "basis": "contract",
      "jurisdiction": "US",
      "accountable_party": {"type": "human", "id": "alice@example.com"},
      "approval": {
        "approver": "bob@example.com",
        "timestamp": "2026-01-11T10:00:00Z"
      }
    }
  },
  "method": "POST",
  "path": "/crm/contact"
}'
echo ""

# =============================================================================
# Demo 3: High-Risk Action (Requires Dual Control)
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Demo 3: High-Risk Action (SAP Payment - Requires Dual Control)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Action: sap.payment.execute"
echo "Risk Tier: HIGH"
echo "Requirement: Two distinct approvers (dual control)"
echo ""

echo -e "${RED}With single approver (DENIED):${NC}"
query_opa '{
  "claim": {
    "act": "sap.payment.execute",
    "sub": "spiffe://example.org/agent",
    "exp": 9999999999,
    "iat": 1704067200,
    "jti": "demo-high-1",
    "leg": {
      "basis": "contract",
      "jurisdiction": "US",
      "accountable_party": {"type": "human", "id": "alice@example.com"},
      "approval": {
        "approver": "bob@example.com",
        "timestamp": "2026-01-11T10:00:00Z"
      }
    }
  },
  "method": "POST",
  "path": "/sap/payment"
}'
echo ""

echo -e "${GREEN}With dual control (ALLOWED):${NC}"
query_opa '{
  "claim": {
    "act": "sap.payment.execute",
    "sub": "spiffe://example.org/agent",
    "exp": 9999999999,
    "iat": 1704067200,
    "jti": "demo-high-2",
    "leg": {
      "basis": "contract",
      "jurisdiction": "US",
      "accountable_party": {"type": "human", "id": "alice@example.com"},
      "dual_control": {
        "approvers": [
          {"id": "bob@example.com", "timestamp": "2026-01-11T10:00:00Z"},
          {"id": "carol@example.com", "timestamp": "2026-01-11T10:05:00Z"}
        ]
      }
    }
  },
  "method": "POST",
  "path": "/sap/payment"
}'
echo ""

# =============================================================================
# Summary
# =============================================================================
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                     Demo Complete                             ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Risk Tiers:                                                  ║"
echo "║    LOW    - No approval needed (safe paths, read-only)       ║"
echo "║    MEDIUM - Single approver required                          ║"
echo "║    HIGH   - Dual control (2 distinct approvers)              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
