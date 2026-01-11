# ATB AgentAuth (Go) — PoA Issuance Skeleton

This is a minimal Proof-of-Authorization (PoA) issuance service skeleton intended to represent the **Authority Layer** (AAP-001/002) of ATB.

What it does:
- Exposes a JWKS endpoint for PoA signature verification:
  - `GET /.well-known/jwks.json`
- Implements a simplified AAP-002-like flow:
  - `POST /v1/challenge` (agent requests authority)
  - `POST /v1/approve` (simulated user/MFA approval)
  - `POST /v1/mandate` (mint a short-lived PoA JWT mandate)

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

## Notes

The issued PoA JWT includes:
- `sub`: agent SPIFFE ID
- `act`: action scope
- `con`: constraints
- `leg`: legal grounding
- `iat`, `exp`, `jti`

Use the JWKS endpoint to configure the broker’s PoA verification (future step: broker fetches JWKS instead of static PEM).
