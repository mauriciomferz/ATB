#!/usr/bin/env bash
# =============================================================================
# Generate API Documentation from OpenAPI specs
# =============================================================================
# This script generates HTML documentation from OpenAPI specifications.
#
# Prerequisites:
#   npm install -g @redocly/cli
#   # Or use Docker: docker run --rm -v $PWD:/spec redocly/cli ...
#
# Usage:
#   ./scripts/gen_api_docs.sh
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
DOCS_DIR="$REPO_ROOT/docs"
OUTPUT_DIR="$REPO_ROOT/docs/api"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p "$OUTPUT_DIR"

echo -e "${YELLOW}Generating API documentation...${NC}"

# Check for redocly CLI
if command -v redocly &> /dev/null; then
    echo "Using redocly CLI..."
    
    # Generate Broker API docs
    redocly build-docs "$DOCS_DIR/openapi.yaml" \
        --output "$OUTPUT_DIR/broker.html" \
        --title "ATB Broker API"
    echo -e "${GREEN}✓ Generated $OUTPUT_DIR/broker.html${NC}"
    
    # Generate AgentAuth API docs
    redocly build-docs "$DOCS_DIR/openapi-agentauth.yaml" \
        --output "$OUTPUT_DIR/agentauth.html" \
        --title "ATB AgentAuth API"
    echo -e "${GREEN}✓ Generated $OUTPUT_DIR/agentauth.html${NC}"

elif command -v docker &> /dev/null; then
    echo "Using Docker..."
    
    # Generate Broker API docs
    docker run --rm \
        -v "$REPO_ROOT:/spec" \
        redocly/cli build-docs /spec/docs/openapi.yaml \
        --output /spec/docs/api/broker.html \
        --title "ATB Broker API"
    echo -e "${GREEN}✓ Generated $OUTPUT_DIR/broker.html${NC}"
    
    # Generate AgentAuth API docs
    docker run --rm \
        -v "$REPO_ROOT:/spec" \
        redocly/cli build-docs /spec/docs/openapi-agentauth.yaml \
        --output /spec/docs/api/agentauth.html \
        --title "ATB AgentAuth API"
    echo -e "${GREEN}✓ Generated $OUTPUT_DIR/agentauth.html${NC}"

else
    echo "Neither redocly nor docker found."
    echo "Install with: npm install -g @redocly/cli"
    echo "Or use Docker to run the command."
    exit 1
fi

# Create index page
cat > "$OUTPUT_DIR/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ATB API Documentation</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 20px;
            background: #f5f5f5;
        }
        h1 { color: #333; }
        .card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .card h2 { margin-top: 0; color: #2563eb; }
        .card p { color: #666; }
        .card a {
            display: inline-block;
            background: #2563eb;
            color: white;
            padding: 10px 20px;
            border-radius: 4px;
            text-decoration: none;
            margin-top: 10px;
        }
        .card a:hover { background: #1d4ed8; }
    </style>
</head>
<body>
    <h1>🔐 ATB API Documentation</h1>
    <p>Agent Trust Broker - Enterprise AI Agent Security Layer</p>
    
    <div class="card">
        <h2>Broker API</h2>
        <p>The main gateway for authorized AI agent requests. Validates PoA tokens and enforces risk-tiered policies.</p>
        <a href="broker.html">View Documentation →</a>
    </div>
    
    <div class="card">
        <h2>AgentAuth API</h2>
        <p>Token issuance service for AI agents. Issues PoA tokens with appropriate approval chains.</p>
        <a href="agentauth.html">View Documentation →</a>
    </div>
    
    <div class="card">
        <h2>Quick Links</h2>
        <p>
            <a href="../openapi.yaml" style="background: #6b7280;">Broker OpenAPI Spec</a>
            <a href="../openapi-agentauth.yaml" style="background: #6b7280;">AgentAuth OpenAPI Spec</a>
        </p>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}✓ Generated $OUTPUT_DIR/index.html${NC}"
echo ""
echo -e "${GREEN}API documentation generated successfully!${NC}"
echo "Open $OUTPUT_DIR/index.html to view."
