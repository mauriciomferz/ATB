# SPIRE Demo Environment

This directory contains a SPIFFE/SPIRE demo environment for testing ATB workload identity.

## Quick Start

```bash
# From repo root
make spire-demo-up      # Start SPIRE + OPA + Echo server
make spire-demo-logs    # View logs
make spire-demo-down    # Stop everything
```

## What's Running

| Service | Port | Description |
|---------|------|-------------|
| `spire-server` | 8081 | SPIRE Server - trust domain authority |
| `opa` | 8182 | OPA policy engine |
| `upstream` | 9001 | Echo server (simulates enterprise API) |

## Testing SPIRE

### Generate a Join Token

```bash
# Generate a token for an agent
docker compose exec spire-server \
  /opt/spire/bin/spire-server token generate \
  -spiffeID spiffe://atb.example.org/agent/demo \
  -ttl 3600

# Output: Token: <uuid>
```

### Register a Workload

```bash
# Register a workload entry
docker compose exec spire-server \
  /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://atb.example.org/my-workload \
  -parentID spiffe://atb.example.org/agent/demo \
  -selector unix:uid:1000 \
  -ttl 3600
```

### List Entries

```bash
docker compose exec spire-server \
  /opt/spire/bin/spire-server entry show
```

## Test OPA

```bash
# Health check
curl http://localhost:8182/health

# Query a policy
curl -X POST http://localhost:8182/v1/data/atb/poa/decision \
  -H "Content-Type: application/json" \
  -d '{"input": {"poa": {"legs": []}}}'
```

## Test Echo Server

```bash
curl http://localhost:9001
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Docker Network                    │
├─────────────────────────────────────────────────────┤
│  ┌──────────────┐                                   │
│  │ SPIRE Server │ ← Trust domain: atb.example.org   │
│  │    :8081     │                                   │
│  └──────────────┘                                   │
│                                                     │
│  ┌──────────────┐    ┌──────────────┐               │
│  │     OPA      │    │   Upstream   │               │
│  │    :8182     │    │    :9001     │               │
│  └──────────────┘    └──────────────┘               │
└─────────────────────────────────────────────────────┘
```

## Configuration Files

- `conf/server/server.conf` - SPIRE Server configuration
- `conf/agent/agent.conf` - SPIRE Agent configuration (for future use)
- `keys/` - Generated Ed25519 keys for PoA signing

## Troubleshooting

### SPIRE Server Not Starting

```bash
# Check logs
docker compose logs spire-server

# Verify config
cat conf/server/server.conf
```

### OPA Policy Errors

```bash
# Check loaded policies
curl http://localhost:8182/v1/policies

# Test specific policy
curl -X POST http://localhost:8182/v1/data/atb/poa/decision \
  -H "Content-Type: application/json" \
  -d '{"input": {}}'
```

## Next Steps

To add the full ATB stack with SPIRE Agent:

1. Build ATB images: `make docker-build` (from repo root)
2. Extend this docker-compose with broker and agentauth services
3. Configure SPIRE Agent with proper join token workflow

See [docs/spiffe-integration.md](../../docs/spiffe-integration.md) for complete SPIFFE integration guide.
