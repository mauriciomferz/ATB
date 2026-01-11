#!/usr/bin/env bash
# =============================================================================
# ATB End-to-End Test Script
# =============================================================================
# This script tests the ATB broker with various PoA scenarios.
#
# Prerequisites:
#   - make certs        (generate dev certificates)
#   - make certs-poa    (generate PoA signing keys)
#   - make docker-up    OR  make run-opa (OPA running on :8181)
#
# Usage:
#   ./dev/test_e2e.sh
#
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
VENV="$REPO_ROOT/.venv"
OPA_URL="${OPA_URL:-http://localhost:8181}"
BROKER_URL="${BROKER_URL:-https://localhost:8443}"

# Check prerequisites
check_prereqs() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check OPA
    if ! curl -s "$OPA_URL/health" > /dev/null 2>&1; then
        echo -e "${RED}❌ OPA not running at $OPA_URL${NC}"
        echo "   Start with: make run-opa OR make docker-up"
        exit 1
    fi
    echo -e "${GREEN}✓ OPA running${NC}"
    
    # Check certificates
    if [[ ! -f "$REPO_ROOT/dev/certs/client.crt" ]]; then
        echo -e "${RED}❌ Dev certificates not found${NC}"
        echo "   Generate with: make certs"
        exit 1
    fi
    echo -e "${GREEN}✓ Certificates exist${NC}"
    
    # Check PoA keys
    if [[ ! -f "$REPO_ROOT/dev/poa_rsa.key" ]]; then
        echo -e "${RED}❌ PoA signing keys not found${NC}"
        echo "   Generate with: make certs-poa"
        exit 1
    fi
    echo -e "${GREEN}✓ PoA keys exist${NC}"
    
    # Check Python venv
    if [[ ! -f "$VENV/bin/python" ]]; then
        echo -e "${RED}❌ Python venv not found${NC}"
        echo "   Create with: make setup"
        exit 1
    fi
    echo -e "${GREEN}✓ Python venv exists${NC}"
    
    echo ""
}

# Mint a PoA token
mint_poa() {
    local action="$1"
    local constraints="${2:-{}}"
    local leg="${3:-{\"basis\": \"contract\", \"ref\": \"internal\", \"jurisdiction\": \"US\", \"accountable_party\": {\"type\": \"human\", \"id\": \"user@example.com\"}}}"
    
    "$VENV/bin/python" "$REPO_ROOT/dev/mint_poa.py" \
        --priv "$REPO_ROOT/dev/poa_rsa.key" \
        --sub "spiffe://example.org/ns/default/sa/agent/connector" \
        --act "$action" \
        --con "$constraints" \
        --leg "$leg"
}

# Test OPA policy directly
test_opa_policy() {
    local test_name="$1"
    local input="$2"
    local expected_allow="$3"
    
    local response
    response=$(curl -s -X POST "$OPA_URL/v1/data/atb/poa/decision" \
        -H "Content-Type: application/json" \
        -d "{\"input\": $input}")
    
    local allowed
    allowed=$(echo "$response" | jq -r '.result.allow // false')
    
    if [[ "$allowed" == "$expected_allow" ]]; then
        echo -e "${GREEN}✓ $test_name${NC}"
        return 0
    else
        echo -e "${RED}✗ $test_name${NC}"
        echo "  Expected: allow=$expected_allow"
        echo "  Got: allow=$allowed"
        echo "  Response: $response"
        return 1
    fi
}

# =============================================================================
# Test Cases
# =============================================================================

echo "=============================================="
echo "ATB End-to-End Tests"
echo "=============================================="
echo ""

check_prereqs

PASS=0
FAIL=0

echo -e "${YELLOW}Testing OPA Policy Decisions...${NC}"
echo ""

# Test 1: Low-risk action should be allowed
if test_opa_policy \
    "Low-risk action (health check)" \
    '{"method": "GET", "path": "/health"}' \
    "true"; then
    ((PASS++))
else
    ((FAIL++))
fi

# Test 2: Low-risk action with valid PoA
if test_opa_policy \
    "Low-risk action with PoA" \
    '{"claim": {"act": "system.status.read", "sub": "spiffe://example.org/agent", "exp": 9999999999, "iat": 1704067200, "jti": "test-123", "leg": {"basis": "contract", "jurisdiction": "US", "accountable_party": {"type": "human", "id": "user@example.com"}}}, "method": "GET", "path": "/status"}' \
    "true"; then
    ((PASS++))
else
    ((FAIL++))
fi

# Test 3: Medium-risk action without approval should be denied
if test_opa_policy \
    "Medium-risk action without approval (should deny)" \
    '{"claim": {"act": "crm.contact.update", "sub": "spiffe://example.org/agent", "exp": 9999999999, "iat": 1704067200, "jti": "test-456", "leg": {"basis": "contract", "jurisdiction": "US", "accountable_party": {"type": "human", "id": "user@example.com"}}}, "method": "POST", "path": "/crm/contact"}' \
    "false"; then
    ((PASS++))
else
    ((FAIL++))
fi

# Test 4: Medium-risk action with approval should be allowed
if test_opa_policy \
    "Medium-risk action with approval" \
    '{"claim": {"act": "crm.contact.update", "sub": "spiffe://example.org/agent", "exp": 9999999999, "iat": 1704067200, "jti": "test-789", "leg": {"basis": "contract", "jurisdiction": "US", "accountable_party": {"type": "human", "id": "user@example.com"}, "approval": {"approver": "manager@example.com", "timestamp": "2026-01-11T10:00:00Z"}}}, "method": "POST", "path": "/crm/contact"}' \
    "true"; then
    ((PASS++))
else
    ((FAIL++))
fi

# Test 5: High-risk action without dual control should be denied
if test_opa_policy \
    "High-risk action without dual control (should deny)" \
    '{"claim": {"act": "sap.payment.execute", "sub": "spiffe://example.org/agent", "exp": 9999999999, "iat": 1704067200, "jti": "test-high-1", "leg": {"basis": "contract", "jurisdiction": "US", "accountable_party": {"type": "human", "id": "user@example.com"}, "approval": {"approver": "manager@example.com", "timestamp": "2026-01-11T10:00:00Z"}}}, "method": "POST", "path": "/sap/payment"}' \
    "false"; then
    ((PASS++))
else
    ((FAIL++))
fi

# Test 6: High-risk action with dual control should be allowed
if test_opa_policy \
    "High-risk action with dual control" \
    '{"claim": {"act": "sap.payment.execute", "sub": "spiffe://example.org/agent", "exp": 9999999999, "iat": 1704067200, "jti": "test-high-2", "leg": {"basis": "contract", "jurisdiction": "US", "accountable_party": {"type": "human", "id": "user@example.com"}, "dual_control": {"approvers": [{"id": "approver1@example.com", "timestamp": "2026-01-11T10:00:00Z"}, {"id": "approver2@example.com", "timestamp": "2026-01-11T10:01:00Z"}]}}}, "method": "POST", "path": "/sap/payment"}' \
    "true"; then
    ((PASS++))
else
    ((FAIL++))
fi

# Test 7: Missing legal basis should be denied
if test_opa_policy \
    "Missing legal basis (should deny)" \
    '{"claim": {"act": "system.status.read", "sub": "spiffe://example.org/agent", "exp": 9999999999, "iat": 1704067200, "jti": "test-noleg"}, "method": "GET", "path": "/status"}' \
    "false"; then
    ((PASS++))
else
    ((FAIL++))
fi

echo ""
echo "=============================================="
echo -e "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "=============================================="

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi

echo ""
echo -e "${GREEN}✅ All tests passed!${NC}"
