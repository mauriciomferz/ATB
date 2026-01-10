# ATB Broker Gateway (Go) — Skeleton

This is a **Policy Enforcement Point (PEP)** skeleton for the Agent Tool Broker (ATB).

## What it does
- Accepts inbound tool calls over HTTPS (mTLS client cert required)
- Extracts a SPIFFE ID from the client certificate URI SAN (expects `spiffe://...`)
- Verifies a PoA JWT from `Authorization: Bearer ...` or `X-PoA-Token`
- Sends policy input to OPA (`OPA_DECISION_URL`) and enforces allow/deny
- Emits structured JSON audit events to stdout

## Run (dev)
1. Start OPA with the policy in `../opa/policy/poa.rego` loaded (example: `opa run --server ../opa/policy/poa.rego`).
2. Export required env vars:
   - `UPSTREAM_URL` (e.g., `http://localhost:9000`)
   - `POA_VERIFY_PUBKEY_PEM` (PEM public key for RS256 or EdDSA)
   - `TLS_CERT_FILE`, `TLS_KEY_FILE` (server cert/key for HTTPS)
   - Optional: `OPA_DECISION_URL` (default `http://localhost:8181/v1/data/atb/poa/decision`)
   - Optional: `POA_MAX_TTL_SECONDS` (default `300`, hard cap `900`)
3. Build/run:
   - `go build ./cmd/broker`
   - `./broker`

Notes:
- This skeleton requires a client cert and looks for a SPIFFE URI SAN. In a full SPIRE deployment you typically source SVIDs via the Workload API and use SPIFFE-aware mTLS utilities or service mesh integration.
