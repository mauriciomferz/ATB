# ATB Broker Gateway (Go) — Skeleton

This is a **Policy Enforcement Point (PEP)** skeleton for the Agent Tool Broker (ATB).

## What it does
- Accepts inbound tool calls over HTTPS (mTLS client cert required)
- Extracts a SPIFFE ID from the client certificate (expects `spiffe://...` URI SAN)
- Verifies a PoA JWT from `Authorization: Bearer ...` or `X-PoA-Token`
- Sends policy input to OPA (`OPA_DECISION_URL`) and enforces allow/deny
- Emits structured JSON audit events to stdout
- Exposes health endpoints on a separate HTTP listener (`/health`, `/ready`, `/metrics`)

## Run (dev)
1. Start OPA with the policy in `../opa/policy/poa.rego` loaded (example: `opa run --server ../opa/policy/poa.rego`).
2. Export required env vars:
   - `UPSTREAM_URL` (e.g., `http://localhost:9000`)
    - Choose one PoA verification mode:
       - Static key: `POA_VERIFY_PUBKEY_PEM` (PEM public key for RS256 or EdDSA)
       - JWKS (recommended with AgentAuth): `POA_JWKS_URL` (e.g., `http://agentauth:9090/.well-known/jwks.json`)
   - Choose one TLS mode:
     - File-based TLS (dev-friendly): `TLS_CERT_FILE`, `TLS_KEY_FILE` and (recommended) `TLS_CLIENT_CA_FILE`
     - SPIFFE Workload API (secret-less): `SPIFFE_ENDPOINT_SOCKET` (e.g., `unix:///spire-agent-socket/api.sock`)
   - Optional: `OPA_DECISION_URL` (default `http://localhost:8181/v1/data/atb/poa/decision`)
   - Optional: `OPA_HEALTH_URL` (defaults to the same host as `OPA_DECISION_URL` with path `/health`)
   - Optional: `POA_MAX_TTL_SECONDS` (default `300`, hard cap `900`)
    - Optional (JWKS): `POA_JWKS_CACHE_SECONDS` (default `300`)
   - Optional: `HTTP_LISTEN_ADDR` for health/metrics (default `:8080`)
3. Build/run:
   - `go build ./cmd/broker`
   - `./broker`

Notes:
- If `TLS_CLIENT_CA_FILE` is not set in file-based TLS mode, the gateway will accept (but not verify) client certificates (dev-only).
- In a full SPIRE deployment, prefer the Workload API mode (`SPIFFE_ENDPOINT_SOCKET`) and distribute trust bundles via SPIRE (or your mesh).
