# Getting Started with ATB

This guide will help you get ATB running locally in under 10 minutes.

## Prerequisites

- Docker and Docker Compose
- Go 1.21+ (for running tests)
- Python 3.9+ (optional, for Python examples)

## Quick Start (Docker Compose)

### 1. Clone and Setup

```bash
git clone https://github.com/mauriciomferz/ATB.git
cd ATB
make setup
```

### 2. Generate Development Certificates

```bash
make certs
make certs-poa
```

This creates:
- `dev/certs/` - TLS certificates for mTLS
- `dev/poa_rsa.key` - RSA key for signing PoA tokens

### 3. Start the Stack

```bash
make docker-up
```

This starts:
- **OPA** (port 8181) - Policy engine
- **Upstream Echo** (port 9000) - Test backend
- **Broker** (port 8443) - ATB gateway
- **AgentAuth** (port 8444) - PoA issuance service

### 4. Verify It's Running

```bash
# Check health
curl -k https://localhost:8443/health

# Check OPA policy
curl http://localhost:8181/v1/data/atb/poa
```

## Your First Request

### Step 1: Low-Risk Request (No PoA Required)

Low-risk actions like health checks work without authentication:

```bash
curl -k https://localhost:8443/health
# {"status":"ok"}
```

### Step 2: Request a PoA Token

For medium/high-risk actions, you need a Proof-of-Authorization (PoA) token:

```bash
# Request a challenge
curl -k -X POST https://localhost:8444/v1/challenge \
  -H "Content-Type: application/json" \
  -d '{
    "agent_spiffe_id": "spiffe://example.org/agent/demo",
    "action": "crm.contact.read",
    "constraints": {},
    "legal_basis": {
      "basis": "contract",
      "jurisdiction": "US",
      "accountable_party": {
        "type": "human",
        "id": "user@example.com"
      }
    }
  }'
```

Response:
```json
{
  "challenge_id": "ch_abc123",
  "expires_at": "2026-01-12T12:00:00Z",
  "requires_approval": true,
  "risk_tier": "medium"
}
```

### Step 3: Approve the Request

For medium-risk actions, one approver is needed:

```bash
curl -k -X POST https://localhost:8444/v1/challenge/ch_abc123/approve \
  -H "Content-Type: application/json" \
  -d '{
    "approver_id": "manager@example.com",
    "reason": "Approved for customer support case #1234"
  }'
```

Response includes the signed PoA token:
```json
{
  "poa": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2026-01-12T12:05:00Z"
}
```

### Step 4: Make an Authorized Request

Include the PoA token in the `X-Poa-Token` header:

```bash
curl -k https://localhost:8443/crm/contacts \
  -H "X-Poa-Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## Understanding Risk Tiers

| Tier | Actions | Approval | Examples |
|------|---------|----------|----------|
| **Low** | 50+ | None | Health checks, FAQ queries, status reads |
| **Medium** | 40+ | 1 approver | CRM updates, order management |
| **High** | 60+ | 2 approvers (dual control) | Payments, PII export, IAM changes |

## Running Tests

```bash
# Run all tests
make test

# Run OPA policy tests only
make test-opa

# Run Go tests only
make test-go

# Run E2E tests (requires Docker stack)
make test-e2e
```

## Interactive Demo

Try the interactive demo to see risk tiers in action:

```bash
make demo
```

## Next Steps

- [Architecture Guide](architecture.md) - Understand the system design
- [API Reference](openapi.yaml) - Full API documentation
- [Enterprise Actions](enterprise-actions.md) - Browse 145+ supported actions
- [Kubernetes Deployment](k8s-quickstart.md) - Deploy to production

## Troubleshooting

### Docker Compose Won't Start

```bash
# Clean up and rebuild
make docker-down
docker system prune -f
make docker-build
make docker-up
```

### Certificate Errors

```bash
# Regenerate certificates
rm -rf dev/certs dev/poa_rsa.*
make certs
make certs-poa
```

### OPA Policy Errors

```bash
# Check policy syntax
opa check --v0-compatible opa/policy/

# Run policy tests
opa test opa/policy/ -v --v0-compatible
```

See [Troubleshooting Guide](troubleshooting.md) for more solutions.
