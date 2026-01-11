# ATB Broker Gateway (Go) — Skeleton

This is a **Policy Enforcement Point (PEP)** skeleton for the Agent Tool Broker (ATB).

## What it does

- Accepts inbound tool calls over HTTPS (mTLS client cert required)
- Extracts a SPIFFE ID from the client certificate (expects `spiffe://...` URI SAN)
- Verifies a PoA JWT from `Authorization: Bearer ...` or `X-PoA-Token`
- Optionally allows low-risk requests without a PoA (policy-controlled)
- Sends policy input to OPA (`OPA_DECISION_URL`) and enforces allow/deny
- Emits structured JSON audit events to stdout
- Exposes health endpoints on a separate HTTP listener (`/health`, `/ready`, `/metrics`)

Audit schema and examples: see [docs/audit.md](../docs/audit.md).

## Run (dev)

1. Start OPA with the policy in `../opa/policy/poa.rego` loaded (example: `opa run --server ../opa/policy/poa.rego`).
2. Export required env vars:
   - `UPSTREAM_URL` (e.g., `http://localhost:9000`)
   - Choose one PoA verification mode:
     - Static key: `POA_VERIFY_PUBKEY_PEM` (PEM public key for RS256 or EdDSA)
     - JWKS (recommended with AgentAuth): `POA_JWKS_URL` (e.g., `http://localhost:9090/.well-known/jwks.json`)
   - Choose one TLS mode:
     - File-based TLS (dev-friendly): `TLS_CERT_FILE`, `TLS_KEY_FILE` and (recommended) `TLS_CLIENT_CA_FILE`
     - SPIFFE Workload API (secret-less): `SPIFFE_ENDPOINT_SOCKET` (e.g., `unix:///spire-agent-socket/workload-api.sock`)
   - Optional: `OPA_DECISION_URL` (default `http://localhost:8181/v1/data/atb/poa/decision`)
   - Optional: `OPA_HEALTH_URL` (defaults to the same host as `OPA_DECISION_URL` with path `/health`)
   - Optional: `POA_MAX_TTL_SECONDS` (default `300`, hard cap `900`)
   - Optional (JWKS): `POA_JWKS_CACHE_SECONDS` (default `300`)

- Optional: `ALLOW_UNMANDATED_LOW_RISK` (default `false`) — if `true`, the broker may allow low-risk requests without a PoA when OPA permits.
- Optional: `POA_SINGLE_USE` (default `false`) — if `true`, denies replay of the same PoA `jti` (best-effort, in-memory).
- Optional: `POA_REPLAY_CACHE_MAX` (default `10000`) — max in-memory PoA `jti` entries.
- Optional: `HTTP_LISTEN_ADDR` for health/metrics (default `:8080`)

### Platform identity (OIDC) verification

Validate agent-platform access tokens (e.g., Entra ID) before PoA verification:

- `PLATFORM_JWKS_URL` — JWKS endpoint for the IdP (e.g., `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys`)
- `PLATFORM_ISSUER` — expected `iss` claim (e.g., `https://sts.windows.net/{tenant}/`)
- `PLATFORM_AUDIENCE` — expected `aud` claim (your app/client ID)
- `PLATFORM_IDENTITY_REQUIRED` (default `false`) — if `true`, denies requests missing a valid platform token
- `PLATFORM_JWKS_CACHE_SECONDS` (default `300`)

The platform token is read from the `X-Platform-Token` header. When provided, claims (`sub`, `oid`, `appid`, `azp`, `iss`, `aud`) are included in OPA input as `input.platform` and in audit events as `platform_identity`.

### Audit sink (SIEM/Log Analytics)

Send audit events to a central sink in addition to stdout:

- `AUDIT_SINK_URL` — HTTP endpoint to POST audit events (e.g., Azure Log Analytics Data Collector API, Splunk HEC, or a custom webhook)
- `AUDIT_SINK_AUTH` — Authorization header value (e.g., `Bearer <token>`, `SharedKey <workspace-id>:<sig>`)
- `AUDIT_SINK_BATCH_SIZE` (default `100`) — events are batched before sending
- `AUDIT_SINK_FLUSH_SECONDS` (default `5`) — max seconds to buffer before flushing

Events are sent as a JSON array of audit objects. The sink is non-blocking; if the queue fills up (10,000 events), new events are dropped with a warning.

Example for Azure Log Analytics:
```bash
export AUDIT_SINK_URL="https://<workspace-id>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
export AUDIT_SINK_AUTH="SharedKey <workspace-id>:<signature>"
```

Example for Splunk HEC:
```bash
export AUDIT_SINK_URL="https://splunk.example.com:8088/services/collector/event"
export AUDIT_SINK_AUTH="Splunk <hec-token>"
```

3. Build/run:
   - `go build ./cmd/broker`
   - `./broker`

Notes:

- If `TLS_CLIENT_CA_FILE` is not set in file-based TLS mode, the gateway will accept (but not verify) client certificates (dev-only).
- In a full SPIRE deployment, prefer the Workload API mode (`SPIFFE_ENDPOINT_SOCKET`) and distribute trust bundles via SPIRE (or your mesh).

Optional request headers:

- `X-ATB-Action` (or legacy `X-Action`): provides the _intended action name_ so policy can validate it and (when present) cross-check it against the PoA `act` claim.

## Helm defaults (staging/prod)

When deploying via the Helm chart:

- `broker.tls.mode: spiffe` is set in staging/prod values (requires mounting the Workload API socket via the SPIFFE CSI driver).
- If `broker.env.POA_JWKS_URL` is empty and `agentauth.enabled=true`, the chart defaults the broker’s `POA_JWKS_URL` to the in-cluster AgentAuth JWKS endpoint.

## CI

The GitHub Actions workflow runs dependency vulnerability scans before deploying:

- Go: `govulncheck`
- Python: `pip-audit`
