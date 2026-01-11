#!/usr/bin/env bash
# =============================================================================
# ATB Developer CLI
# =============================================================================
# A unified CLI for common ATB development tasks.
#
# Usage:
#   ./scripts/atb.sh <command> [options]
#
# Commands:
#   start       Start local development environment
#   stop        Stop local development environment
#   test        Run tests
#   logs        View service logs
#   status      Check service status
#   mint        Mint a test PoA token
#   query       Query OPA policy
#   help        Show this help message
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
OPA_URL="${OPA_URL:-http://localhost:8181}"
BROKER_URL="${BROKER_URL:-http://localhost:8080}"

# =============================================================================
# Helper Functions
# =============================================================================

print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  ATB Developer CLI${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

print_help() {
    print_header
    echo ""
    echo "Usage: atb <command> [options]"
    echo ""
    echo "Commands:"
    echo "  start [full|minimal]  Start local development environment"
    echo "  stop                  Stop local development environment"
    echo "  restart               Restart all services"
    echo "  status                Check service status"
    echo "  logs [service]        View service logs (opa, broker, agentauth, upstream)"
    echo "  test [type]           Run tests (opa, go, e2e, integration, all)"
    echo "  mint <risk_tier>      Mint a test PoA token (LOW, MEDIUM, HIGH)"
    echo "  query <action>        Query OPA policy for an action"
    echo "  validate              Validate all configurations"
    echo "  demo                  Run interactive demo"
    echo "  help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  atb start             # Start full stack"
    echo "  atb start minimal     # Start OPA + upstream only"
    echo "  atb test opa          # Run OPA tests"
    echo "  atb mint LOW          # Mint a LOW risk token"
    echo "  atb query read:logs   # Query if read:logs is allowed"
    echo ""
}

check_docker() {
    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}Error: Docker is not running${NC}"
        exit 1
    fi
}

check_opa() {
    if ! curl -s "$OPA_URL/health" >/dev/null 2>&1; then
        echo -e "${RED}Error: OPA is not running at $OPA_URL${NC}"
        echo "Start with: atb start"
        exit 1
    fi
}

# =============================================================================
# Commands
# =============================================================================

cmd_start() {
    local mode="${1:-full}"
    check_docker
    
    echo -e "${GREEN}Starting ATB development environment (${mode})...${NC}"
    
    case "$mode" in
        full)
            docker compose -f "$REPO_ROOT/docker-compose.yaml" up -d
            ;;
        minimal)
            docker compose -f "$REPO_ROOT/docker-compose.minimal.yaml" up -d
            ;;
        *)
            echo -e "${RED}Unknown mode: $mode${NC}"
            echo "Use: start [full|minimal]"
            exit 1
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}Services started!${NC}"
    echo ""
    cmd_status
}

cmd_stop() {
    check_docker
    
    echo -e "${YELLOW}Stopping ATB services...${NC}"
    docker compose -f "$REPO_ROOT/docker-compose.yaml" down 2>/dev/null || true
    docker compose -f "$REPO_ROOT/docker-compose.minimal.yaml" down 2>/dev/null || true
    echo -e "${GREEN}Services stopped${NC}"
}

cmd_restart() {
    cmd_stop
    sleep 2
    cmd_start "${1:-full}"
}

cmd_status() {
    echo -e "${BLUE}Service Status:${NC}"
    echo ""
    
    # Check OPA
    if curl -s "$OPA_URL/health" >/dev/null 2>&1; then
        echo -e "  OPA:       ${GREEN}● Running${NC} ($OPA_URL)"
    else
        echo -e "  OPA:       ${RED}○ Stopped${NC}"
    fi
    
    # Check Broker
    if curl -s "$BROKER_URL/health" >/dev/null 2>&1; then
        echo -e "  Broker:    ${GREEN}● Running${NC} ($BROKER_URL)"
    else
        echo -e "  Broker:    ${RED}○ Stopped${NC}"
    fi
    
    # Check AgentAuth
    if curl -s "http://localhost:8082/health" >/dev/null 2>&1; then
        echo -e "  AgentAuth: ${GREEN}● Running${NC} (http://localhost:8082)"
    else
        echo -e "  AgentAuth: ${RED}○ Stopped${NC}"
    fi
    
    # Check Upstream
    if curl -s "http://localhost:9000/health" >/dev/null 2>&1; then
        echo -e "  Upstream:  ${GREEN}● Running${NC} (http://localhost:9000)"
    else
        echo -e "  Upstream:  ${RED}○ Stopped${NC}"
    fi
    
    echo ""
}

cmd_logs() {
    local service="${1:-}"
    check_docker
    
    if [ -z "$service" ]; then
        docker compose -f "$REPO_ROOT/docker-compose.yaml" logs -f
    else
        docker compose -f "$REPO_ROOT/docker-compose.yaml" logs -f "$service"
    fi
}

cmd_test() {
    local type="${1:-all}"
    
    case "$type" in
        opa)
            echo -e "${BLUE}Running OPA tests...${NC}"
            opa test "$REPO_ROOT/opa/policy/" -v --v0-compatible
            ;;
        go)
            echo -e "${BLUE}Running Go tests...${NC}"
            cd "$REPO_ROOT/atb-gateway-go" && go test -race -v ./...
            ;;
        e2e)
            echo -e "${BLUE}Running E2E tests...${NC}"
            "$REPO_ROOT/dev/test_e2e.sh"
            ;;
        integration)
            echo -e "${BLUE}Running integration tests...${NC}"
            cd "$REPO_ROOT/atb-gateway-go" && go test -tags=integration -v ./cmd/broker
            ;;
        all)
            cmd_test opa
            cmd_test go
            ;;
        *)
            echo -e "${RED}Unknown test type: $type${NC}"
            echo "Use: test [opa|go|e2e|integration|all]"
            exit 1
            ;;
    esac
    
    echo -e "${GREEN}Tests passed!${NC}"
}

cmd_mint() {
    local risk_tier="${1:-LOW}"
    
    echo -e "${BLUE}Minting PoA token (risk tier: $risk_tier)...${NC}"
    
    # Use the Python minting script
    if [ -f "$REPO_ROOT/.venv/bin/python" ]; then
        "$REPO_ROOT/.venv/bin/python" "$REPO_ROOT/dev/mint_poa.py" --risk-tier "$risk_tier"
    else
        python3 "$REPO_ROOT/dev/mint_poa.py" --risk-tier "$risk_tier"
    fi
}

cmd_query() {
    local action="${1:-}"
    
    if [ -z "$action" ]; then
        echo -e "${RED}Usage: atb query <verb:resource>${NC}"
        echo "Example: atb query read:logs"
        exit 1
    fi
    
    check_opa
    
    # Parse action (format: verb:resource)
    local verb="${action%%:*}"
    local resource="${action#*:}"
    
    echo -e "${BLUE}Querying OPA for: $verb $resource${NC}"
    
    local input=$(cat <<EOF
{
    "input": {
        "poa": {
            "sub": "test-agent",
            "iss": "atb-agentauth",
            "exp": $(($(date +%s) + 3600)),
            "iat": $(date +%s),
            "legs": [{
                "act": "$verb",
                "uri": "$resource"
            }]
        },
        "requested_action": {
            "verb": "$verb",
            "resource_uri": "$resource"
        },
        "context": {
            "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        }
    }
}
EOF
)
    
    curl -s -X POST "$OPA_URL/v1/data/poa/authorize" \
        -H "Content-Type: application/json" \
        -d "$input" | python3 -m json.tool
}

cmd_validate() {
    echo -e "${BLUE}Validating configurations...${NC}"
    "$REPO_ROOT/scripts/validate_all.sh"
}

cmd_demo() {
    "$REPO_ROOT/dev/demo.sh"
}

# =============================================================================
# Main
# =============================================================================

main() {
    local cmd="${1:-help}"
    shift || true
    
    case "$cmd" in
        start)      cmd_start "$@" ;;
        stop)       cmd_stop ;;
        restart)    cmd_restart "$@" ;;
        status)     cmd_status ;;
        logs)       cmd_logs "$@" ;;
        test)       cmd_test "$@" ;;
        mint)       cmd_mint "$@" ;;
        query)      cmd_query "$@" ;;
        validate)   cmd_validate ;;
        demo)       cmd_demo ;;
        help|--help|-h)
            print_help
            ;;
        *)
            echo -e "${RED}Unknown command: $cmd${NC}"
            echo "Run 'atb help' for usage"
            exit 1
            ;;
    esac
}

main "$@"
