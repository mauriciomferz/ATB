# ATB AgentAuth (Go) — PoA Issuance Skeleton

This is a minimal Proof-of-Authorization (PoA) issuance service skeleton intended to represent the **Authority Layer** (AAP-001/002) of ATB.

What it does:
- Exposes a JWKS endpoint for PoA signature verification:
  - `GET /.well-known/jwks.json`
- Implements a simplified AAP-002-like flow:
  - `POST /v1/challenge` (agent requests authority)
  - `GET /v1/challenge/{id}` (check challenge status)
  - `POST /v1/approve` (user/MFA approval — supports dual control)
  - `POST /v1/mandate` (mint a short-lived PoA JWT mandate)
- **Dual control (four-eyes)** for high-risk actions:
  - Certain actions require two distinct approvers before mandate issuance
  - Configurable via `DUAL_CONTROL_ACTIONS` env var or `leg.dual_control.required` in request

What it **does not** do (by design, for now):
- Real MFA / user identity integration (Entra ID, Okta, etc.)
- Durable storage of approvals/challenges
- Key management/HSM integration

## Run

```bash
cd atb-gateway-go
GO111MODULE=on go run ./cmd/agentauth
```

## Configuration

- `LISTEN_ADDR` (default `:9090`)
- `POA_ISSUER` (default `atb-agentauth`)
- `POA_TTL_SECONDS` (default `300`, hard cap `900`)
- `CHALLENGE_TTL_SECONDS` (default `300`, hard cap `900`)
- `APPROVAL_SHARED_SECRET` (optional): if set, `POST /v1/approve` requires header `X-Approval-Token: <secret>`
- `POA_SIGNING_ED25519_PRIVKEY_PEM` (optional): PKCS8 Ed25519 private key PEM. If unset, an ephemeral key is generated (not for production).
- `DUAL_CONTROL_ACTIONS` (optional): comma-separated list of actions requiring dual control. Default: `sap.vendor.change,iam.privilege.escalate,payments.transfer.execute,ot.system.manual_override`

## Dual Control Flow

For high-risk actions, two distinct approvers must approve the challenge before a mandate can be issued:

1. **Challenge**: Agent requests authorization
   ```bash
   curl -X POST http://localhost:9090/v1/challenge \
     -H 'Content-Type: application/json' \
     -d '{"agent_spiffe_id":"spiffe://example/agent","act":"sap.vendor.change","con":{},"leg":{"jurisdiction":"DE","accountable_party":{"type":"employee","id":"emp-123"}}}'
   ```
   Response includes `requires_dual_control: true` and `approvers_needed: 2`.

2. **First Approval**: First approver approves
   ```bash
   curl -X POST http://localhost:9090/v1/approve \
     -H 'Content-Type: application/json' \
     -d '{"challenge_id":"chal_xxx","approver":"approver-1@example.com"}'
   ```
   Response: `fully_approved: false`, `approvers_count: 1`.

3. **Second Approval**: Second (different) approver approves
   ```bash
   curl -X POST http://localhost:9090/v1/approve \
     -H 'Content-Type: application/json' \
     -d '{"challenge_id":"chal_xxx","approver":"approver-2@example.com"}'
   ```
   Response: `fully_approved: true`, `approvers_count: 2`.

4. **Mandate**: Issue the PoA token
   ```bash
   curl -X POST http://localhost:9090/v1/mandate \
     -H 'Content-Type: application/json' \
     -d '{"challenge_id":"chal_xxx"}'
   ```
   The issued token includes `leg.dual_control.approvers` with both approver identities.

## Notes

The issued PoA JWT includes:
- `sub`: agent SPIFFE ID
- `act`: action scope
- `con`: constraints
- `leg`: legal grounding
- `iat`, `exp`, `jti`

Use the JWKS endpoint to configure the broker’s PoA verification (future step: broker fetches JWKS instead of static PEM).

The broker already supports JWKS-based verification via `POA_JWKS_URL` (recommended) and can fall back to a static PEM via `POA_VERIFY_PUBKEY_PEM`.
