#!/bin/bash
# ATB Demo Scenarios - Interactive walkthrough of ATB capabilities
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
BROKER_URL="${BROKER_URL:-http://localhost:8080}"
AGENTAUTH_URL="${AGENTAUTH_URL:-http://localhost:8081}"
OPA_URL="${OPA_URL:-http://localhost:8181}"

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_scenario() {
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}Scenario $1: $2${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_step() {
    echo -e "\n${GREEN}▶ $1${NC}"
}

print_result() {
    if [ "$1" = "success" ]; then
        echo -e "${GREEN}✓ $2${NC}"
    else
        echo -e "${RED}✗ $2${NC}"
    fi
}

wait_for_enter() {
    echo ""
    read -p "Press Enter to continue..." </dev/tty
}

check_services() {
    print_header "Checking ATB Services"
    
    local all_ok=true
    
    # Check OPA
    print_step "Checking OPA..."
    if curl -s "$OPA_URL/health" > /dev/null 2>&1; then
        print_result "success" "OPA is healthy at $OPA_URL"
    else
        print_result "fail" "OPA is not responding at $OPA_URL"
        all_ok=false
    fi
    
    # Check Broker (if running)
    print_step "Checking Broker..."
    if curl -s "$BROKER_URL/healthz" > /dev/null 2>&1; then
        print_result "success" "Broker is healthy at $BROKER_URL"
    else
        echo -e "${YELLOW}⚠ Broker not running - some demos will be simulated${NC}"
    fi
    
    echo ""
    if [ "$all_ok" = false ]; then
        echo -e "${RED}Some services are not running. Start with: make docker-up${NC}"
        exit 1
    fi
}

# Scenario 1: Low Risk - Health Check
scenario_1() {
    print_scenario "1" "Low Risk Action - Health Check (Auto-Approved)"
    
    echo "This scenario demonstrates a LOW risk action that requires no human approval."
    echo ""
    echo "Action: health.check"
    echo "Risk Tier: LOW"
    echo "Approval Required: None (auto-approved)"
    
    wait_for_enter
    
    print_step "Creating PoA token request..."
    cat << 'EOF'
{
  "poa": {
    "jti": "poa-health-001",
    "iat": 1736700000,
    "exp": 1736700300,
    "iss": "urn:atb:agentauth",
    "sub": "spiffe://atb.demo/ns/agents/sa/monitor-agent",
    "legs": [
      {
        "leg_id": "leg-health-001",
        "action": "health.check",
        "target": "urn:connector:monitoring:health",
        "constraints": {
          "max_calls": 100,
          "ttl_seconds": 300
        }
      }
    ]
  }
}
EOF
    
    print_step "Querying OPA for policy decision..."
    
    RESPONSE=$(curl -s -X POST "$OPA_URL/v1/data/atb/poa/decision" \
        -H "Content-Type: application/json" \
        -d '{
            "input": {
                "poa": {
                    "legs": [{
                        "action": "health.check",
                        "target": "urn:connector:monitoring:health"
                    }]
                }
            }
        }')
    
    echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
    
    print_result "success" "LOW risk action auto-approved - no human approval needed"
}

# Scenario 2: Medium Risk - CRM Read
scenario_2() {
    print_scenario "2" "Medium Risk Action - CRM Customer Read"
    
    echo "This scenario demonstrates a MEDIUM risk action that would require"
    echo "single human approval in production."
    echo ""
    echo "Action: crm.customer.read"
    echo "Risk Tier: MEDIUM"
    echo "Approval Required: 1 approver"
    
    wait_for_enter
    
    print_step "Creating PoA token with approval chain..."
    cat << 'EOF'
{
  "poa": {
    "jti": "poa-crm-read-001",
    "iss": "urn:atb:agentauth",
    "sub": "spiffe://atb.demo/ns/agents/sa/sales-agent",
    "legs": [
      {
        "leg_id": "leg-crm-001",
        "action": "crm.customer.read",
        "target": "urn:connector:salesforce:customer",
        "constraints": {
          "customer_id": "CUST-12345",
          "fields": ["name", "email", "company"]
        },
        "approvals": [
          {
            "approver": "manager@example.com",
            "approved_at": "2026-01-12T10:00:00Z",
            "method": "slack"
          }
        ]
      }
    ]
  }
}
EOF
    
    print_step "Querying OPA for policy decision..."
    
    RESPONSE=$(curl -s -X POST "$OPA_URL/v1/data/atb/poa/decision" \
        -H "Content-Type: application/json" \
        -d '{
            "input": {
                "poa": {
                    "legs": [{
                        "action": "crm.customer.read",
                        "target": "urn:connector:salesforce:customer",
                        "approvals": [{"approver": "manager@example.com"}]
                    }]
                }
            }
        }')
    
    echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
    
    print_result "success" "MEDIUM risk action approved with 1 approver"
}

# Scenario 3: High Risk - Payment
scenario_3() {
    print_scenario "3" "High Risk Action - SAP Payment (Dual Control)"
    
    echo "This scenario demonstrates a HIGH risk action requiring dual control."
    echo ""
    echo "Action: sap.payment.create"
    echo "Risk Tier: HIGH"
    echo "Approval Required: 2 approvers (dual control)"
    echo "Amount: €50,000"
    
    wait_for_enter
    
    print_step "Creating PoA token with dual approval..."
    cat << 'EOF'
{
  "poa": {
    "jti": "poa-payment-001",
    "iss": "urn:atb:agentauth",
    "sub": "spiffe://atb.demo/ns/agents/sa/finance-agent",
    "legs": [
      {
        "leg_id": "leg-payment-001",
        "action": "sap.payment.create",
        "target": "urn:connector:sap:payment",
        "constraints": {
          "vendor_id": "VENDOR-789",
          "amount": 50000,
          "currency": "EUR",
          "payment_method": "wire_transfer"
        },
        "approvals": [
          {
            "approver": "controller@example.com",
            "approved_at": "2026-01-12T09:00:00Z",
            "method": "email"
          },
          {
            "approver": "cfo@example.com",
            "approved_at": "2026-01-12T09:30:00Z",
            "method": "teams"
          }
        ],
        "legal_basis": {
          "regulation": "SOX",
          "justification": "Approved vendor payment per PO-12345"
        }
      }
    ]
  }
}
EOF
    
    print_step "Querying OPA for policy decision..."
    
    RESPONSE=$(curl -s -X POST "$OPA_URL/v1/data/atb/poa/decision" \
        -H "Content-Type: application/json" \
        -d '{
            "input": {
                "poa": {
                    "legs": [{
                        "action": "sap.payment.create",
                        "target": "urn:connector:sap:payment",
                        "approvals": [
                            {"approver": "controller@example.com"},
                            {"approver": "cfo@example.com"}
                        ]
                    }]
                }
            }
        }')
    
    echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
    
    print_result "success" "HIGH risk action approved with dual control"
}

# Scenario 4: Denied - Missing Approval
scenario_4() {
    print_scenario "4" "Denied Action - Missing Approval"
    
    echo "This scenario demonstrates a HIGH risk action being DENIED"
    echo "due to insufficient approvals."
    echo ""
    echo "Action: sap.payment.create"
    echo "Risk Tier: HIGH"
    echo "Approvals Provided: 1 (requires 2)"
    
    wait_for_enter
    
    print_step "Creating PoA token with only 1 approval..."
    cat << 'EOF'
{
  "poa": {
    "legs": [{
      "action": "sap.payment.create",
      "target": "urn:connector:sap:payment",
      "approvals": [
        {"approver": "controller@example.com"}
      ]
      // Missing second approver!
    }]
  }
}
EOF
    
    print_step "Querying OPA for policy decision..."
    
    RESPONSE=$(curl -s -X POST "$OPA_URL/v1/data/atb/poa/decision" \
        -H "Content-Type: application/json" \
        -d '{
            "input": {
                "poa": {
                    "legs": [{
                        "action": "sap.payment.create",
                        "target": "urn:connector:sap:payment",
                        "approvals": [{"approver": "controller@example.com"}]
                    }]
                }
            }
        }')
    
    echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
    
    print_result "fail" "HIGH risk action DENIED - requires dual control (2 approvers)"
}

# Scenario 5: Expired Token
scenario_5() {
    print_scenario "5" "Denied Action - Expired PoA Token"
    
    echo "This scenario demonstrates rejection of an expired PoA token."
    echo ""
    echo "Token Expiry: 2026-01-11T23:59:59Z (yesterday)"
    echo "Current Time: 2026-01-12T12:00:00Z"
    
    wait_for_enter
    
    print_step "Creating expired PoA token..."
    cat << 'EOF'
{
  "poa": {
    "jti": "poa-expired-001",
    "iat": 1736553600,  // Jan 11, 2026 00:00:00
    "exp": 1736639999,  // Jan 11, 2026 23:59:59 (EXPIRED!)
    "legs": [{
      "action": "crm.customer.read",
      "target": "urn:connector:salesforce:customer"
    }]
  }
}
EOF
    
    print_step "Token validation would fail at the Broker..."
    echo ""
    echo "Error: Token expired at 2026-01-11T23:59:59Z"
    
    print_result "fail" "Action DENIED - PoA token has expired"
}

# Scenario 6: Multi-Leg Transaction
scenario_6() {
    print_scenario "6" "Multi-Leg Transaction - Read then Write"
    
    echo "This scenario demonstrates a multi-leg PoA covering multiple actions."
    echo ""
    echo "Leg 1: crm.customer.read (MEDIUM risk)"
    echo "Leg 2: erp.order.create (HIGH risk)"
    echo ""
    echo "The PoA authorizes both legs in a single token."
    
    wait_for_enter
    
    print_step "Creating multi-leg PoA token..."
    cat << 'EOF'
{
  "poa": {
    "jti": "poa-multileg-001",
    "sub": "spiffe://atb.demo/ns/agents/sa/order-agent",
    "legs": [
      {
        "leg_id": "leg-read-001",
        "action": "crm.customer.read",
        "target": "urn:connector:salesforce:customer",
        "constraints": {"customer_id": "CUST-999"},
        "approvals": [{"approver": "sales@example.com"}]
      },
      {
        "leg_id": "leg-order-001",
        "action": "erp.order.create",
        "target": "urn:connector:sap:order",
        "constraints": {
          "customer_id": "CUST-999",
          "items": [{"sku": "PROD-001", "qty": 10}]
        },
        "approvals": [
          {"approver": "sales@example.com"},
          {"approver": "logistics@example.com"}
        ]
      }
    ]
  }
}
EOF
    
    print_step "Both legs validated - transaction can proceed"
    print_result "success" "Multi-leg transaction authorized"
}

# Scenario 7: Rate Limited
scenario_7() {
    print_scenario "7" "Rate Limited - Too Many Requests"
    
    echo "This scenario demonstrates rate limiting protection."
    echo ""
    echo "Agent: claude-assistant"
    echo "Rate Limit: 100 requests/minute"
    echo "Current Count: 100 (limit reached)"
    
    wait_for_enter
    
    print_step "Simulating rate limit exceeded..."
    cat << 'EOF'
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1736700060
Retry-After: 45

{
  "error": "rate_limit_exceeded",
  "message": "Rate limit exceeded for agent claude-assistant",
  "limit": 100,
  "window": "1m",
  "retry_after": 45
}
EOF
    
    print_result "fail" "Request DENIED - rate limit exceeded"
}

# Scenario 8: Audit Trail
scenario_8() {
    print_scenario "8" "Audit Trail - Complete Action Log"
    
    echo "This scenario shows the audit trail generated for each action."
    echo ""
    
    wait_for_enter
    
    print_step "Sample audit event..."
    cat << 'EOF'
{
  "event_id": "evt-20260112-abc123",
  "timestamp": "2026-01-12T12:34:56.789Z",
  "event_type": "action.executed",
  "version": "1.0",
  
  "agent": {
    "spiffe_id": "spiffe://atb.demo/ns/agents/sa/finance-agent",
    "platform": "claude",
    "session_id": "sess-xyz789"
  },
  
  "action": {
    "name": "sap.payment.create",
    "target": "urn:connector:sap:payment",
    "risk_tier": "HIGH",
    "constraints": {
      "vendor_id": "VENDOR-789",
      "amount": 50000,
      "currency": "EUR"
    }
  },
  
  "authorization": {
    "poa_jti": "poa-payment-001",
    "approvers": [
      "controller@example.com",
      "cfo@example.com"
    ],
    "legal_basis": "SOX compliance"
  },
  
  "result": {
    "status": "success",
    "response_code": 200,
    "duration_ms": 234
  },
  
  "context": {
    "client_ip": "10.0.1.50",
    "broker_instance": "atb-broker-7d9f8c-abc12",
    "trace_id": "trace-123456789"
  }
}
EOF
    
    print_result "success" "Complete audit trail captured"
}

# Scenario 9: GDPR Data Access
scenario_9() {
    print_scenario "9" "GDPR Compliant - Data Subject Access"
    
    echo "This scenario shows GDPR-compliant data access with legal basis."
    echo ""
    echo "Action: Read customer PII"
    echo "Legal Basis: GDPR Art. 6(1)(b) - Contract performance"
    echo "Data Subject: customer@example.com"
    
    wait_for_enter
    
    print_step "Creating GDPR-compliant PoA..."
    cat << 'EOF'
{
  "poa": {
    "jti": "poa-gdpr-001",
    "sub": "spiffe://atb.demo/ns/agents/sa/support-agent",
    "legs": [{
      "action": "crm.customer.read_pii",
      "target": "urn:connector:salesforce:customer",
      "constraints": {
        "customer_email": "customer@example.com",
        "fields": ["name", "email", "address", "phone"],
        "purpose": "support_ticket_resolution"
      },
      "legal_basis": {
        "regulation": "GDPR",
        "article": "Art. 6(1)(b)",
        "justification": "Contract performance - resolving support ticket #12345",
        "data_subject_notified": true,
        "retention_days": 30
      },
      "approvals": [{
        "approver": "dpo@example.com",
        "approved_at": "2026-01-12T10:00:00Z"
      }]
    }]
  }
}
EOF
    
    print_result "success" "GDPR-compliant data access authorized with full audit trail"
}

# Scenario 10: Emergency Break Glass
scenario_10() {
    print_scenario "10" "Emergency Break Glass - Critical Override"
    
    echo "This scenario demonstrates emergency override with enhanced logging."
    echo ""
    echo "⚠️  BREAK GLASS ACTIVATED"
    echo ""
    echo "Reason: Production system outage"
    echo "Override Approver: on-call-engineer@example.com"
    echo "Incident: INC-2026-001"
    
    wait_for_enter
    
    print_step "Creating emergency override PoA..."
    cat << 'EOF'
{
  "poa": {
    "jti": "poa-emergency-001",
    "sub": "spiffe://atb.demo/ns/agents/sa/sre-agent",
    "emergency_override": true,
    "legs": [{
      "action": "infra.service.restart",
      "target": "urn:connector:k8s:deployment",
      "constraints": {
        "namespace": "production",
        "deployment": "api-gateway",
        "reason": "OOM crash loop"
      },
      "approvals": [{
        "approver": "on-call-engineer@example.com",
        "approved_at": "2026-01-12T03:15:00Z",
        "method": "pagerduty",
        "incident_id": "INC-2026-001"
      }],
      "break_glass": {
        "activated": true,
        "reason": "Production outage - API gateway crash loop",
        "incident_id": "INC-2026-001",
        "expires_at": "2026-01-12T04:15:00Z"
      }
    }]
  }
}
EOF
    
    echo ""
    echo -e "${RED}⚠️  BREAK GLASS EVENT LOGGED${NC}"
    echo "  - All actions enhanced audit"
    echo "  - Security team notified"
    echo "  - Post-incident review required"
    
    print_result "success" "Emergency action authorized with break glass override"
}

# Main menu
show_menu() {
    print_header "ATB Demo Scenarios"
    
    echo "Select a scenario to run:"
    echo ""
    echo -e "  ${GREEN}1${NC}) Low Risk - Health Check (auto-approved)"
    echo -e "  ${GREEN}2${NC}) Medium Risk - CRM Read (1 approver)"
    echo -e "  ${GREEN}3${NC}) High Risk - SAP Payment (dual control)"
    echo -e "  ${YELLOW}4${NC}) Denied - Missing Approval"
    echo -e "  ${YELLOW}5${NC}) Denied - Expired Token"
    echo -e "  ${GREEN}6${NC}) Multi-Leg Transaction"
    echo -e "  ${YELLOW}7${NC}) Rate Limited"
    echo -e "  ${CYAN}8${NC}) Audit Trail Example"
    echo -e "  ${CYAN}9${NC}) GDPR Compliant Access"
    echo -e "  ${RED}10${NC}) Emergency Break Glass"
    echo ""
    echo -e "  ${BOLD}a${NC}) Run all scenarios"
    echo -e "  ${BOLD}q${NC}) Quit"
    echo ""
}

run_all() {
    scenario_1
    wait_for_enter
    scenario_2
    wait_for_enter
    scenario_3
    wait_for_enter
    scenario_4
    wait_for_enter
    scenario_5
    wait_for_enter
    scenario_6
    wait_for_enter
    scenario_7
    wait_for_enter
    scenario_8
    wait_for_enter
    scenario_9
    wait_for_enter
    scenario_10
}

# Main
main() {
    check_services
    
    while true; do
        show_menu
        read -p "Enter choice: " choice </dev/tty
        
        case $choice in
            1) scenario_1 ;;
            2) scenario_2 ;;
            3) scenario_3 ;;
            4) scenario_4 ;;
            5) scenario_5 ;;
            6) scenario_6 ;;
            7) scenario_7 ;;
            8) scenario_8 ;;
            9) scenario_9 ;;
            10) scenario_10 ;;
            a|A) run_all ;;
            q|Q) echo "Goodbye!"; exit 0 ;;
            *) echo "Invalid choice" ;;
        esac
        
        wait_for_enter
    done
}

main "$@"
