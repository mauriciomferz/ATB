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
- **Upstream Echo** (port 9000) - Test backend (see note below)
- **AgentAuth** (port 8444) - PoA issuance service

> **Note:** Port 9000 may conflict with Zscaler or other corporate security software. If the upstream container fails to start, see the [Troubleshooting](#troubleshooting) section.

### 4. Verify It's Running

```bash
# Check AgentAuth health
curl http://localhost:8444/health

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
curl -X POST http://localhost:8444/v1/challenge \
  -H "Content-Type: application/json" \
  -d '{
    "agent_spiffe_id": "spiffe://example.org/agent/demo",
    "act": "crm.contact.read",
    "con": {},
    "leg": {
      "basis": "contract",
      "jurisdiction": "US",
      "accountable_party": {
        "type": "human",
        "id": "user@example.com"
      }
    }
  }'
```

> **Note:** Use `act`, `con`, and `leg` (not `action`, `constraints`, `legal_basis`).

Response:

```json
{
  "challenge_id": "chal_b2ihD73Vx5Oz548HlNnbMA",
  "expires_at": "2026-01-14T19:29:36Z",
  "requires_dual_control": false,
  "approvers_needed": 1,
  "approval_hint": "POST /v1/approve with challenge_id and approver identity"
}
```

### Step 3: Approve the Challenge

For medium-risk actions, one approver is needed:

```bash
curl -X POST http://localhost:8444/v1/approve \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_id": "chal_b2ihD73Vx5Oz548HlNnbMA",
    "approver": "manager@example.com"
  }'
```

Response:

```json
{
  "status": "approved",
  "approvers": [
    { "id": "manager@example.com", "approved_at": "2026-01-14T19:25:21Z" }
  ],
  "approvers_count": 1,
  "approvers_needed": 1,
  "fully_approved": true
}
```

### Step 4: Get the PoA Token (Mandate)

Once approved, retrieve the signed PoA token:

```bash
curl -X POST http://localhost:8444/v1/mandate \
  -H "Content-Type: application/json" \
  -d '{"challenge_id": "chal_b2ihD73Vx5Oz548HlNnbMA"}'
```

Response:

```json
{
  "token": "eyJhbGciOiJFZERTQSIsImtpZCI6Ii4uLiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2026-01-14T19:32:15Z",
  "jti": "poa_8rfNn1PxNgMzwewG-4fR0g",
  "dual_control_used": false,
  "approvers_count": 1
}
```

### Step 5: Make an Authorized Request

Include the PoA token in the `Authorization` header:

```bash
curl http://localhost:8080/crm/contacts \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIsImtpZCI6Ii4uLiIsInR5cCI6IkpXVCJ9..."
```

## Understanding Risk Tiers

| Tier       | Actions | Approval                   | Examples                                 |
| ---------- | ------- | -------------------------- | ---------------------------------------- |
| **Low**    | 50+     | None                       | Health checks, FAQ queries, status reads |
| **Medium** | 40+     | 1 approver                 | CRM updates, order management            |
| **High**   | 60+     | 2 approvers (dual control) | Payments, PII export, IAM changes        |

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

## Approval Dashboard

ATB includes a web-based dashboard for monitoring and approving requests:

```bash
# Start the dashboard
cd dashboard && npm install && npm run dev
```

Access at: http://localhost:3003

### Dashboard Pages

| Page      | URL          | Description                                  |
| --------- | ------------ | -------------------------------------------- |
| Dashboard | `/`          | Real-time metrics, charts, system health     |
| Audit Log | `/audit`     | Searchable authorization event history       |
| Approvals | `/approvals` | Pending approval queue for high-risk actions |
| Policies  | `/policies`  | OPA policy evaluation statistics             |
| Agents    | `/agents`    | Registered agent monitoring                  |

### Using the Approvals Page

1. Navigate to http://localhost:3003/approvals
2. View pending requests with risk tier indicators
3. Click a request to see full details
4. Approve or Reject with immediate enforcement

## Platform SDKs

Use the Python SDK for pre-built platform integrations:

```python
from atb.platforms import CopilotConnector, SalesforceConnector, SAPConnector

# Microsoft Copilot
copilot = CopilotConnector(tenant_id="...", client_id="...", client_secret="...")
identity = await copilot.authenticate()
result = await copilot.execute_action("calendar:create", {"title": "Meeting"})

# Salesforce Agentforce
salesforce = SalesforceConnector(instance_url="https://yourorg.salesforce.com", ...)

# SAP Joule
sap = SAPConnector(instance_url="https://your-sap.s4hana.cloud.sap", ...)
```

See [Python SDK Documentation](../sdk/python/README.md) for details.

## Next Steps

- [Architecture Guide](architecture.md) - Understand the system design
- [API Reference](openapi.yaml) - Full API documentation
- [Enterprise Actions](enterprise-actions.md) - Browse 145+ supported actions
- [Kubernetes Deployment](k8s-quickstart.md) - Deploy to production
- [Python SDK](../sdk/python/README.md) - Platform connectors for Copilot, Salesforce, SAP
- [Dashboard](../dashboard/README.md) - Monitoring UI and approval workflows
- [Policy Templates](../opa/policy/templates/README.md) - Pre-built OPA policies
- [OT/Industrial Edge](../spire/ot/README.md) - TPM attestation for industrial devices

## Troubleshooting

### Port 9000 Already in Use (Zscaler/Corporate VPN)

If you see this error:

```
Error response from daemon: ports are not available: exposing port TCP 0.0.0.0:9000
```

Port 9000 is likely used by Zscaler or similar corporate security software. Check with:

```bash
sudo lsof -i :9000
```

**Solution:** Edit `docker-compose.yaml` and change the upstream port mapping:

```yaml
upstream:
  ports:
    - "9001:9000" # Changed from 9000:9000
```

### TLS/SSL Connection Errors

If you see LibreSSL errors like:

```
curl: (35) LibreSSL/3.3.6: error:1404B42E:SSL routines
```

**Solution:** Use HTTP instead of HTTPS for local development:

```bash
# Instead of: curl -k https://localhost:8444/health
curl http://localhost:8444/health
```

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
