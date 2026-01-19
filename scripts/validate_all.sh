#!/usr/bin/env bash
# =============================================================================
# Validate All Configuration and Policies
# =============================================================================
# This script validates all configuration files, policies, and schemas.
#
# Usage:
#   ./scripts/validate_all.sh
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0

echo "=============================================="
echo "ATB Configuration Validation"
echo "=============================================="
echo ""

# =============================================================================
# OPA Policy Validation
# =============================================================================
echo -e "${YELLOW}Validating OPA policies...${NC}"

if command -v opa &> /dev/null; then
    # Check syntax (with v0 compatibility for legacy policies)
    if opa check "$REPO_ROOT/opa/policy/"; then
        echo -e "${GREEN}✓ OPA policy syntax valid${NC}"
    else
        echo -e "${RED}✗ OPA policy syntax errors${NC}"
        ((ERRORS++))
    fi

    # Run tests
    if opa test "$REPO_ROOT/opa/policy/" -v > /dev/null 2>&1; then
        echo -e "${GREEN}✓ OPA policy tests pass${NC}"
    else
        echo -e "${RED}✗ OPA policy tests failed${NC}"
        ((ERRORS++))
    fi
else
    echo -e "${YELLOW}⚠ OPA not installed, skipping policy validation${NC}"
fi

echo ""

# =============================================================================
# Helm Chart Validation
# =============================================================================
echo -e "${YELLOW}Validating Helm chart...${NC}"

if command -v helm &> /dev/null; then
    if helm lint "$REPO_ROOT/charts/atb" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Helm chart is valid${NC}"
    else
        echo -e "${RED}✗ Helm chart validation failed${NC}"
        ((ERRORS++))
    fi

    # Template with different values (warnings only - may fail due to missing secrets/values)
    for values_file in values.yaml values-staging.yaml values-prod.yaml; do
        if [ -f "$REPO_ROOT/charts/atb/$values_file" ]; then
            if helm template atb "$REPO_ROOT/charts/atb" -f "$REPO_ROOT/charts/atb/$values_file" > /dev/null 2>&1; then
                echo -e "${GREEN}✓ Helm template with $values_file${NC}"
            else
                echo -e "${YELLOW}⚠ Helm template warning with $values_file (may require environment-specific values)${NC}"
            fi
        fi
    done
else
    echo -e "${YELLOW}⚠ Helm not installed, skipping chart validation${NC}"
fi

echo ""

# =============================================================================
# JSON Schema Validation
# =============================================================================
echo -e "${YELLOW}Validating JSON files...${NC}"

# Check JSON syntax
for json_file in "$REPO_ROOT"/config/*.json "$REPO_ROOT"/schemas/*.json; do
    if [ -f "$json_file" ]; then
        if python3 -c "import json; json.load(open('$json_file'))" 2>/dev/null; then
            echo -e "${GREEN}✓ $(basename $json_file) is valid JSON${NC}"
        else
            echo -e "${RED}✗ $(basename $json_file) is invalid JSON${NC}"
            ((ERRORS++))
        fi
    fi
done

echo ""

# =============================================================================
# YAML Validation
# =============================================================================
echo -e "${YELLOW}Validating YAML files...${NC}"

# Check YAML syntax
for yaml_file in "$REPO_ROOT"/.github/workflows/*.yaml "$REPO_ROOT"/.github/workflows/*.yml; do
    if [ -f "$yaml_file" ]; then
        if python3 -c "import yaml; yaml.safe_load(open('$yaml_file'))" 2>/dev/null; then
            echo -e "${GREEN}✓ $(basename $yaml_file) is valid YAML${NC}"
        else
            echo -e "${RED}✗ $(basename $yaml_file) is invalid YAML${NC}"
            ((ERRORS++))
        fi
    fi
done

echo ""

# =============================================================================
# Docker Compose Validation
# =============================================================================
echo -e "${YELLOW}Validating Docker Compose...${NC}"

if command -v docker &> /dev/null; then
    for compose_file in docker-compose.yaml docker-compose.minimal.yaml; do
        if [ -f "$REPO_ROOT/$compose_file" ]; then
            if docker compose -f "$REPO_ROOT/$compose_file" config --quiet 2>/dev/null; then
                echo -e "${GREEN}✓ $compose_file is valid${NC}"
            else
                echo -e "${RED}✗ $compose_file is invalid${NC}"
                ((ERRORS++))
            fi
        fi
    done
else
    echo -e "${YELLOW}⚠ Docker not installed, skipping compose validation${NC}"
fi

echo ""

# =============================================================================
# Go Module Validation
# =============================================================================
echo -e "${YELLOW}Validating Go modules...${NC}"

if command -v go &> /dev/null; then
    cd "$REPO_ROOT/atb-gateway-go"
    if go mod verify > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Go modules verified${NC}"
    else
        echo -e "${RED}✗ Go module verification failed${NC}"
        ((ERRORS++))
    fi

    if go vet ./... > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Go vet passed${NC}"
    else
        echo -e "${RED}✗ Go vet found issues${NC}"
        ((ERRORS++))
    fi
    cd "$REPO_ROOT"
else
    echo -e "${YELLOW}⚠ Go not installed, skipping module validation${NC}"
fi

echo ""

# =============================================================================
# OpenAPI Validation
# =============================================================================
echo -e "${YELLOW}Validating OpenAPI specs...${NC}"

for spec in openapi.yaml openapi-agentauth.yaml; do
    if [ -f "$REPO_ROOT/docs/$spec" ]; then
        # Basic YAML validation
        if python3 -c "import yaml; yaml.safe_load(open('$REPO_ROOT/docs/$spec'))" 2>/dev/null; then
            echo -e "${GREEN}✓ $spec is valid YAML${NC}"
        else
            echo -e "${RED}✗ $spec is invalid YAML${NC}"
            ((ERRORS++))
        fi
    fi
done

echo ""

# =============================================================================
# Summary
# =============================================================================
echo "=============================================="
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}All validations passed!${NC}"
    exit 0
else
    echo -e "${RED}$ERRORS validation(s) failed${NC}"
    exit 1
fi
