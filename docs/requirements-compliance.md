# ATB vs. "AI Safe Enterprise Autonomy Architecture" (requirements map)

Source document: `docs/AI_Safe_Enterprise_Autonomy_Architecture.pdf`

- OCR text used for this analysis: `docs/AI_Safe_Enterprise_Autonomy_Architecture.ocr.txt`
- This mapping is intentionally practical: what we already have in ATB, what is partial, and what is still missing.

## Key requirements extracted from the doc

1. **Single enforcement boundary (“Agent Tool Broker”)**

- No agent platform should access enterprise systems directly.
- Every action is authenticated, authorised, constrained, and audited through the broker.

2. **Universal, secret-less internal identity (SPIFFE/SPIRE)**

- Prefer short-lived, cryptographic workload identities and mTLS.
- Remove static internal secrets (API keys/certs) from the message path.

3. **Separate identity from actionable authority (PoA mandates)**

- Platform identity (“who is the agent platform/tenant”) is distinct from authority (“what may be done now”).
- High-risk actions require a short-lived, signed Proof-of-Authorization (PoA) mandate (AAP-001/002 style).
- Mandates must be explicit, bounded (scope + constraints), and auditable.

4. **Risk-tiering**

- High-risk tier: PoA required (examples include SAP vendor bank changes, payments, IAM privilege escalation, OT setpoint changes, etc.).
- Low-risk tier: allowed with logging (examples include read-only reporting, FAQ queries, status lookups).

5. **Centralised policy enforcement + audit trail**

- Central place to enforce policies consistently across multiple agent platforms.
- Central, immutable audit trail attributable to intent/delegation.

6. **Operating model**

- Clear RACI split across: Security Platform, Legal/Compliance, Business Owners, AI/Automation teams.

## Compliance matrix (current repo)

Legend: **Implemented** | **Partial** | **Gap**

| Requirement                                     |                     Status | Evidence in repo                                                                                     | Notes / follow-ups                                                                                                               |
| ----------------------------------------------- | -------------------------: | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Broker as single enforcement boundary           |                Implemented | `atb-gateway-go/cmd/broker/main.go`, Helm chart `charts/atb`                                         | Still needs real “connectors” to SAP/Salesforce/etc with egress allowlists and per-connector shaping.                            |
| SPIFFE/SPIRE workload identity (secret-less)    |                Implemented | `atb-gateway-go/cmd/broker/main.go` (Workload API), `spire/`, `docs/k8s-quickstart.md`, `charts/atb` | SPIFFE is currently focused on _internal_ mTLS identity.                                                                         |
| Separate platform identity vs authority         |                Implemented | PoA + AgentAuth + broker `X-Platform-Token` OIDC verification                                        | Broker validates Entra ID (or other IdP) tokens via JWKS; claims passed to OPA as `input.platform` and logged.                   |
| PoA mandates (short-lived, bounded, auditable)  |                Implemented | `atb-gateway-go/cmd/agentauth/main.go`, `opa/policy/poa.rego`, broker PoA verification (JWKS or PEM) | PoA contains `act/con/leg/jti/iat/exp`. Replay protection via `POA_SINGLE_USE`. `leg` schema: `schemas/poa-leg.schema.json`, validated by OPA. |
| Risk-tiering (high risk PoA, low risk log-only) | Implemented (configurable) | `opa/policy/poa.rego`, broker env `ALLOW_UNMANDATED_LOW_RISK`                                        | Default remains “PoA required for everything” unless the env var is enabled.                                                     |
| Central policy enforcement (OPA)                |                Implemented | `opa/policy/poa.rego`, broker `OPA_DECISION_URL`                                                     | Policy content is currently a pilot/sample; expand to real enterprise actions.                                                   |
| Semantic/prompt-injection firewall              |                    Partial | broker `semanticGuardrails(...)` placeholder                                                         | Replace placeholder with a real semantic firewall or guardrails service.                                                         |
| Centralised audit trail schema                  |                Implemented | `schemas/audit-event.schema.json`, `docs/audit.md`                                                   | Still missing: write-once storage backend + retention + tamper-evidence.                                                         |
| “Non-transferable” credentials                  |                    Partial | PoA `sub` bound to SPIFFE ID                                                                         | Still missing: replay protection keyed by `jti` + strict token binding story for externally visible PoA.                         |
| Operating model / RACI                          |              Gap (process) | N/A                                                                                                  | Needs non-code work: define approval flows (dual control), mandate templates, and risk thresholds.                               |

## Concrete backlog (recommended next steps)

Security/controls:

- ~~Add **PoA replay protection** (e.g., bounded `jti` cache with TTL, optionally backed by Redis).~~ ✅ Done (`POA_SINGLE_USE`)
- ~~Add **OIDC verification for agent-platform identity** (e.g., Entra ID JWT validation).~~ ✅ Done (`PLATFORM_JWKS_URL` et al.)
- Tighten **low-risk policy** from “GET allowed” to an explicit allowlist of actions/paths and connector-level scoping.

Governance/legal:

- ~~Define a **`leg` schema** (jurisdiction, accountable party, approval references) and enforce it in policy.~~ ✅ Done (`schemas/poa-leg.schema.json`, OPA rules in `poa.rego`)
- Implement **dual control** flow in AgentAuth for actions marked high risk.

Ops/observability:

- Persist audit events to a central sink (e.g., Log Analytics / SIEM) with correlation IDs.
- Add SLOs and alerting around broker/OPA/AgentAuth availability.
