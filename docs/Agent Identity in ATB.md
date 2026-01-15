# Agent Identity in ATB

## Overview

Agents (AI/LLM agents) get their identity through a different flow than backend services. This guide explains how agent identity works in the Agent Trust Broker.

## Agent vs Service Identity

| Type                              | Identity Source | Format                                      | Purpose               |
| --------------------------------- | --------------- | ------------------------------------------- | --------------------- |
| **Services** (Broker, Connectors) | SPIRE           | `spiffe://example.org/ns/atb/sa/atb-broker` | mTLS between services |
| **Agents** (AI/LLM)               | AgentAuth       | `spiffe://example.org/agent/my-agent`       | PoA token binding     |

## How Agent Identity Works

```
┌─────────────────────────────────────────────────────────────────┐
│                     Agent Runtime                               │
│  (e.g., LangChain, AutoGPT, Custom Agent)                       │
│                                                                 │
│  Configured with: agent_spiffe_id = spiffe://example.org/agent/sales-bot
└─────────────────────────────────────────────────────────────────┘
                              │
                    1. Request PoA with agent_spiffe_id
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AgentAuth Service                          │
│  - Validates agent identity (via platform attestation)          │
│  - Issues PoA token with `sub` = agent's SPIFFE ID              │
└─────────────────────────────────────────────────────────────────┘
                              │
                    2. Returns PoA JWT with sub claim
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         PoA Token                               │
│  {                                                              │
│    "sub": "spiffe://example.org/agent/sales-bot",  ← Agent ID   │
│    "act": "crm.contact.read",                                   │
│    "leg": { "basis": "contract", ... },                         │
│    "exp": 1768419135                                            │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘
```

## Agent Registration Options

### Option 1: Platform-Attested Agents (Recommended)

If agents run in Kubernetes, register them with SPIRE just like services:

```bash
# Register an AI agent workload
spire-server entry create \
  -spiffeID spiffe://example.org/agent/sales-bot \
  -parentID spiffe://example.org/spire/agent/k8s_sat/k8s/<node-id> \
  -selector k8s:ns:agents \
  -selector k8s:sa:sales-bot-agent \
  -ttl 600
```

The agent's pod gets an SVID, which it presents to AgentAuth for PoA issuance.

### Option 2: Pre-Registered Agents (Simpler)

For agents not running in K8s, pre-register them in AgentAuth config:

```yaml
# agentauth-config.yaml
agents:
  - spiffe_id: "spiffe://example.org/agent/sales-bot"
    allowed_actions:
      - "crm.contact.read"
      - "crm.contact.create"
    max_risk_tier: "medium"

  - spiffe_id: "spiffe://example.org/agent/support-bot"
    allowed_actions:
      - "ticket.read"
      - "ticket.update"
    max_risk_tier: "low"
```

### Option 3: Dynamic Agent Registration (Enterprise)

For multi-tenant or dynamic agent spawning:

```bash
# Register a new agent dynamically
curl -X POST http://localhost:8444/v1/agents \
  -H "Content-Type: application/json" \
  -d '{
    "spiffe_id": "spiffe://example.org/agent/customer-123/bot-456",
    "allowed_actions": ["crm.contact.read"],
    "owner": "customer-123",
    "expires_at": "2026-02-01T00:00:00Z"
  }'
```

## Complete Flow: Agent Gets Identity and Acts

### Step 1: Agent requests a PoA for an action

```bash
curl -X POST http://localhost:8444/v1/challenge \
  -H "Content-Type: application/json" \
  -d '{
    "agent_spiffe_id": "spiffe://example.org/agent/sales-bot",
    "act": "crm.contact.read",
    "con": {"contact_id": "12345"},
    "leg": {
      "basis": "contract",
      "jurisdiction": "US",
      "accountable_party": {"type": "human", "id": "user@example.com"}
    }
  }'
```

**Response:**

```json
{
  "challenge_id": "chal_abc123",
  "requires_dual_control": false,
  "approvers_needed": 1,
  "expires_at": "2026-01-15T12:00:00Z"
}
```

### Step 2: Human approves (if required)

```bash
curl -X POST http://localhost:8444/v1/approve \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_id": "chal_abc123",
    "approver": "manager@example.com"
  }'
```

**Response:**

```json
{
  "status": "approved",
  "fully_approved": true,
  "approvers_count": 1,
  "approvers_needed": 1
}
```

### Step 3: Agent gets PoA token

```bash
curl -X POST http://localhost:8444/v1/mandate \
  -H "Content-Type: application/json" \
  -d '{"challenge_id": "chal_abc123"}'
```

**Response:**

```json
{
  "token": "eyJhbGciOiJFZERTQSIs...",
  "jti": "poa_xyz789",
  "expires_at": "2026-01-15T12:05:00Z"
}
```

### Step 4: Agent uses token to call backend

```bash
curl -X GET http://localhost:8080/api/contacts/12345 \
  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..."
```

## Identity Binding Security

The Broker validates that the PoA token's `sub` claim matches the caller:

```
Agent (sales-bot) → Broker → "Is token.sub == caller's SPIFFE ID?"
                              ↓
                    Yes: Forward to connector
                    No:  403 Forbidden (identity mismatch)
```

This prevents token theft—even if an attacker steals a PoA token, they can't use it without the matching agent identity.

## PoA Token Structure

```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "2tenzbK29nrK-Z6OHwlGyKVmsEqm8EK9ON6mTUkw_q0"
}
.
{
  "sub": "spiffe://example.org/agent/sales-bot",
  "act": "crm.contact.read",
  "con": {"contact_id": "12345"},
  "leg": {
    "basis": "contract",
    "jurisdiction": "US",
    "accountable_party": {
      "type": "human",
      "id": "user@example.com"
    }
  },
  "iss": "atb-agentauth",
  "exp": 1768419135,
  "iat": 1768418835,
  "jti": "poa_xyz789"
}
.
<EdDSA signature>
```

## Key Claims

| Claim | Description                           |
| ----- | ------------------------------------- |
| `sub` | Agent's SPIFFE ID (identity binding)  |
| `act` | The authorized action                 |
| `con` | Constraints/parameters for the action |
| `leg` | Legal basis (GDPR compliance)         |
| `iss` | Token issuer (AgentAuth)              |
| `exp` | Expiration timestamp                  |
| `jti` | Unique token ID (replay protection)   |

## Security Best Practices

1. **Short TTLs** - PoA tokens expire in 5 minutes by default
2. **Action-specific** - Each token authorizes exactly one action
3. **Bound to identity** - Tokens are cryptographically bound to agent SPIFFE ID
4. **Dual control** - High-risk actions require multiple approvers
5. **Audit logging** - All token issuance and usage is logged
6. **Replay protection** - JTI ensures tokens can't be reused

## Troubleshooting

### Agent identity not recognized

```bash
# Check if agent is registered
curl http://localhost:8444/v1/agents/spiffe://example.org/agent/my-agent
```

### Token rejected by Broker

```bash
# Decode and inspect the token
echo "<token>" | cut -d. -f2 | base64 -d | jq .
```

### SPIFFE ID mismatch

Ensure the agent's runtime SPIFFE ID matches what's in the PoA token's `sub` claim.
