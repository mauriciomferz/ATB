# SPIRE Demo Environment

This directory contains a complete SPIFFE/SPIRE demo for testing ATB with real workload identity.

## Quick Start

```bash
# 1. Generate keys
./scripts/gen-keys.sh

# 2. Start all services
docker compose up -d

# 3. Wait for registration (check logs)
docker compose logs -f spire-registration

# 4. Run the demo
docker compose exec demo-agent python3 /scripts/demo_spiffe_flow.py
```

## What's Included

### Services

| Service | Description |
|---------|-------------|
| `spire-server` | SPIRE Server - trust domain authority |
| `spire-agent` | SPIRE Agent - issues SVIDs to workloads |
| `spire-registration` | Registers workload entries |
| `broker` | ATB Broker with SPIFFE mTLS |
| `agentauth` | ATB AgentAuth with SPIFFE mTLS |
| `opa` | OPA policy engine |
| `upstream` | Echo server (simulates enterprise API) |
| `demo-agent` | Demo workload for testing |

### Files

```
dev/spire-demo/
├── docker-compose.yaml      # Service definitions
├── conf/
│   ├── server/server.conf   # SPIRE Server config
│   └── agent/agent.conf     # SPIRE Agent config
├── config/
│   └── connectors.json      # ATB connector config
├── keys/                    # Generated keys (gitignored)
└── scripts/
    ├── gen-keys.sh          # Key generation
    ├── register-workloads.sh # SPIRE registration
    └── demo_spiffe_flow.py  # Python demo script
```

## Demo Flow

The demo demonstrates:

1. **Workload Identity** - SPIRE issues X.509 SVIDs to workloads
2. **mTLS Authentication** - All services authenticate via SVID certificates
3. **PoA Token Flow** - Agent requests authorization with SPIFFE identity
4. **Policy Enforcement** - OPA validates actions based on identity

```
Demo Agent                AgentAuth                 Broker                 Upstream
    │                         │                        │                      │
    │──(1) Fetch X509 SVID────│                        │                      │
    │←─────────────────────────│                        │                      │
    │                         │                        │                      │
    │──(2) Request PoA (mTLS)─▶                        │                      │
    │←──PoA Token (sub=SPIFFE)│                        │                      │
    │                         │                        │                      │
    │──(3) API Request (mTLS + PoA)───────────────────▶│                      │
    │                         │                        │──(4) Validate──────▶ │
    │                         │                        │←─────Response────────│
    │←─────────────────────────────────Response────────│                      │
```

## Useful Commands

```bash
# View SPIRE Server logs
docker compose logs spire-server

# Check registered workload entries
docker compose exec spire-server \
  /opt/spire/bin/spire-server entry show \
  -socketPath /tmp/spire-server/private/api.sock

# Check agent health
docker compose exec spire-agent \
  /opt/spire/bin/spire-agent healthcheck

# Fetch current SVID
docker compose exec spire-agent \
  /opt/spire/bin/spire-agent api fetch x509 \
  -socketPath /tmp/spire-agent/public/api.sock

# View broker logs
docker compose logs broker

# Interactive shell in demo agent
docker compose exec demo-agent /bin/sh
```

## Cleanup

```bash
docker compose down -v
rm -rf keys/
```

## Troubleshooting

### "No such file or directory" for socket

The SPIRE agent socket isn't ready yet. Wait for the agent to start:

```bash
docker compose logs -f spire-agent
```

### "No identity issued"

The workload isn't registered in SPIRE. Check registration:

```bash
docker compose logs spire-registration
docker compose exec spire-server /opt/spire/bin/spire-server entry show
```

### Certificate errors

Regenerate keys:

```bash
rm -rf keys/ conf/server/dummy_upstream_ca.*
./scripts/gen-keys.sh
docker compose down -v
docker compose up -d
```
