# ATB Dev Harness (local)

This folder provides a minimal **local** harness to exercise:
- mTLS client cert with a **SPIFFE URI SAN** (for the Go gateway)
- PoA minting (AAP-001 payload)
- OPA policy evaluation using `opa/policy/poa.rego`

## Quick Start (using Makefile)

From the repo root, you can use the Makefile for common tasks:

```bash
make setup          # Install dependencies
make certs          # Generate dev certificates
make certs-poa      # Generate PoA signing keys
make run-opa        # Start OPA server on :8181
make run-upstream   # Start echo upstream server
make run-broker     # Build and run the broker
```

## Manual Setup

### Prereqs
- `openssl`
- `opa` (downloaded locally) OR run OPA in a container
- Python 3 (to mint PoA)

### 1) Generate local CA + server/client certs
From repo root:

```bash
make certs
# Or manually:
cd dev/certs && ./gen_certs.sh
```

Outputs (generated):
- `dev/certs/ca.crt`
- `dev/certs/server.crt`, `dev/certs/server.key`
- `dev/certs/client.crt`, `dev/certs/client.key`

The client cert includes a SPIFFE URI SAN:
- `spiffe://example.org/ns/default/sa/agent/connector`

## 2) Start OPA with the policy
From repo root:

```bash
make run-opa
# Or manually:
opa run --server --addr 127.0.0.1:8181 opa/policy/poa.rego
```

Decision path:
- `http://127.0.0.1:8181/v1/data/atb/poa/decision`

## 3) Start a simple upstream echo server
From repo root:

```bash
make run-upstream
# Or manually:
.venv/bin/python dev/upstream_echo.py
```

This listens on `http://127.0.0.1:9000`.

## 4) Mint a PoA JWT (RS256)
Generate a local RSA keypair (one-time):

```bash
make certs-poa
# Or manually:
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out dev/poa_rsa.key
openssl rsa -pubout -in dev/poa_rsa.key -out dev/poa_rsa.pub
```

Mint a 5-minute PoA mandate:

```bash
.venv/bin/python dev/mint_poa.py \
    --priv dev/poa_rsa.key \
    --sub spiffe://example.org/ns/default/sa/agent/connector \
    --act sap.vendor.change \
    --con '{"dual_control": true, "liability_cap": 7000}' \
    --leg '{"basis": "contract", "ref": "internal"}'
```

## 5) Run the Go gateway and call it
From repo root:

```bash
export UPSTREAM_URL=http://127.0.0.1:9000
export OPA_DECISION_URL=http://127.0.0.1:8181/v1/data/atb/poa/decision
export TLS_CERT_FILE=dev/certs/server.crt
export TLS_KEY_FILE=dev/certs/server.key
export POA_VERIFY_PUBKEY_PEM="$(cat dev/poa_rsa.pub)"
export POA_MAX_TTL_SECONDS=300
cd atb-gateway-go && go build ./cmd/broker && ./broker
```

Or use the Makefile:

```bash
make run-broker
```

Call it with the SPIFFE client cert:

```bash
TOKEN=$(.venv/bin/python dev/mint_poa.py --priv dev/poa_rsa.key \
    --sub spiffe://example.org/ns/default/sa/agent/connector \
    --act sap.vendor.change \
    --con '{"dual_control": true, "liability_cap": 7000}' \
    --leg '{"basis": "contract", "ref": "internal"}')

curl -vk https://127.0.0.1:8443/sap/vendor/change \
    --cacert dev/certs/ca.crt \
    --cert dev/certs/client.crt \
    --key dev/certs/client.key \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"amount": 6000}'
```

### Quick deny checks
- Same request but `dual_control: false` + `amount: 6000` should deny.
- For Salesforce bulk export, try:
  - `act=salesforce.bulk.export`, `con.dataset_allowlist=["accounts"]`, `params.dataset="accounts"`, `row_count=5000`.
