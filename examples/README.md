# ATB Client Examples

This directory contains example client implementations for interacting with the ATB (Agent Trust Broker) API.

## Examples

| File | Language | Description |
|------|----------|-------------|
| [client_python.py](client_python.py) | Python | Python client with mTLS and PoA token minting |
| [client_go.go](client_go.go) | Go | Go client with mTLS and PoA token minting |

## Prerequisites

Before running the examples:

```bash
# From the repository root
make certs      # Generate mTLS certificates
make certs-poa  # Generate PoA signing keys

# Start the broker
make docker-up  # Or: make run-opa && make run-broker
```

## Running the Examples

### Python

```bash
# Install dependencies
pip install requests pyjwt cryptography

# Run from repository root
python examples/client_python.py
```

### Go

```bash
# Run from repository root
cd examples
go run client_go.go
```

## Example Output

Each example demonstrates three scenarios:

1. **Low-Risk Action** (system.status.read)
   - Auto-approved, no special requirements
   - Just needs a valid PoA token

2. **Medium-Risk Action** (crm.contact.update)
   - Requires single approver
   - Legal basis must include `approval` object

3. **High-Risk Action** (sap.payment.execute)
   - Requires dual control (2 approvers)
   - Legal basis must include `dual_control` object with 2 distinct approvers

## Configuration

All examples support environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ATB_BROKER_URL` | `https://localhost:8443` | ATB broker URL |
| `POA_KEY_PATH` | `dev/poa_rsa.key` | Path to PoA signing key |
| `CLIENT_CERT_PATH` | `dev/certs/client.crt` | Path to mTLS client certificate |
| `CLIENT_KEY_PATH` | `dev/certs/client.key` | Path to mTLS client key |
| `CA_CERT_PATH` | `dev/certs/ca.crt` | Path to CA certificate |

## PoA Token Structure

The Proof-of-Authorization (PoA) token is a JWT with these claims:

```json
{
  "sub": "spiffe://example.org/ns/default/sa/agent/connector",
  "act": "sap.payment.execute",
  "con": {
    "max_amount": 10000
  },
  "leg": {
    "basis": "contract",
    "jurisdiction": "US",
    "accountable_party": {
      "type": "human",
      "id": "alice@example.com"
    },
    "dual_control": {
      "approvers": [
        {"id": "approver1@example.com", "timestamp": "2026-01-11T10:00:00Z"},
        {"id": "approver2@example.com", "timestamp": "2026-01-11T10:05:00Z"}
      ]
    }
  },
  "iat": 1736589600,
  "exp": 1736589900,
  "jti": "unique-request-id"
}
```

## Troubleshooting

**"Connection refused"**
- Make sure the broker is running: `make docker-up` or `make run-broker`

**"Certificate error"**
- Regenerate certificates: `make certs`
- Check CA certificate matches: `openssl verify -CAfile dev/certs/ca.crt dev/certs/client.crt`

**"PoA validation failed"**
- Check PoA key matches what broker expects
- Ensure token hasn't expired (5 minute TTL)
- Verify SPIFFE ID in token matches certificate

**"Authorization denied"**
- Check the action's risk tier
- MEDIUM risk: add `approval` to legal basis
- HIGH risk: add `dual_control` with 2 approvers
