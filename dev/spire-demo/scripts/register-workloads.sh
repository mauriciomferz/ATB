#!/bin/bash
# Register ATB workloads with SPIRE Server

set -e

SOCKET="/tmp/spire-server/private/api.sock"

# Wait for SPIRE server to be ready
echo "Waiting for SPIRE server..."
sleep 5

# Get the agent SPIFFE ID (we'll use a wildcard parent for Docker)
PARENT_ID="spiffe://atb.example.org/spire/agent/join_token/demo-agent"

echo "Registering ATB workloads..."

# Create a node entry for the agent (using join token)
/opt/spire/bin/spire-server entry create \
  -socketPath "$SOCKET" \
  -spiffeID "spiffe://atb.example.org/spire/agent/join_token/demo-agent" \
  -selector "join_token:demo" \
  -node || true

# Register ATB Broker
echo "Registering ATB Broker..."
/opt/spire/bin/spire-server entry create \
  -socketPath "$SOCKET" \
  -spiffeID "spiffe://atb.example.org/atb/broker" \
  -parentID "$PARENT_ID" \
  -selector "unix:uid:0" \
  -ttl 600 || true

# Register ATB AgentAuth  
echo "Registering ATB AgentAuth..."
/opt/spire/bin/spire-server entry create \
  -socketPath "$SOCKET" \
  -spiffeID "spiffe://atb.example.org/atb/agentauth" \
  -parentID "$PARENT_ID" \
  -selector "unix:uid:0" \
  -ttl 600 || true

# Register Demo AI Agent
echo "Registering Demo AI Agent..."
/opt/spire/bin/spire-server entry create \
  -socketPath "$SOCKET" \
  -spiffeID "spiffe://atb.example.org/agents/demo-agent" \
  -parentID "$PARENT_ID" \
  -selector "unix:uid:0" \
  -ttl 600 || true

# Register CRM Connector Agent
echo "Registering CRM Connector..."
/opt/spire/bin/spire-server entry create \
  -socketPath "$SOCKET" \
  -spiffeID "spiffe://atb.example.org/connectors/crm" \
  -parentID "$PARENT_ID" \
  -selector "unix:uid:0" \
  -ttl 600 || true

# Register SAP Connector Agent
echo "Registering SAP Connector..."
/opt/spire/bin/spire-server entry create \
  -socketPath "$SOCKET" \
  -spiffeID "spiffe://atb.example.org/connectors/sap" \
  -parentID "$PARENT_ID" \
  -selector "unix:uid:0" \
  -ttl 600 || true

echo ""
echo "=== Registered Workload Entries ==="
/opt/spire/bin/spire-server entry show -socketPath "$SOCKET"

echo ""
echo "SPIRE workload registration complete!"
