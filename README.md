# Agent Trust Broker (ATB)

[![CI](https://github.com/mauriciomferz/ATB/actions/workflows/ci.yaml/badge.svg)](https://github.com/mauriciomferz/ATB/actions/workflows/ci.yaml)
[![Security](https://github.com/mauriciomferz/ATB/actions/workflows/security.yaml/badge.svg)](https://github.com/mauriciomferz/ATB/actions/workflows/security.yaml)
[![Deploy](https://github.com/mauriciomferz/ATB/actions/workflows/deploy-atb.yaml/badge.svg)](https://github.com/mauriciomferz/ATB/actions/workflows/deploy-atb.yaml)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev/)
[![OPA](https://img.shields.io/badge/OPA-Policy-7D9AAA?logo=openpolicyagent)](https://www.openpolicyagent.org/)
[![License](https://img.shields.io/badge/License-Proprietary-red)]()

A security enforcement layer for enterprise AI agent deployments, implementing the **AI Safe Enterprise Autonomy Architecture**.

## Overview

ATB provides a **single enforcement boundary** between AI agent platforms and enterprise systems. Every agent action is:

- **Authenticated** via SPIFFE/SPIRE workload identity
- **Authorized** via signed Proof-of-Authorization (PoA) mandates
- **Constrained** by OPA policy with risk-tiered controls
- **Audited** with immutable, tamper-evident logs

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│  Agent Platform │──────▶│   ATB Broker    │──────▶│ Enterprise APIs │
│  (Claude, GPT)  │ mTLS  │  (Enforcement)  │ mTLS  │ (SAP, SF, etc.) │
└─────────────────┘       └────────┬────────┘       └─────────────────┘
                                   │
                          ┌────────┴────────┐
                          │    OPA Policy   │
                          │  (Risk Tiers)   │
                          └─────────────────┘
```

## Key Features

| Feature                   | Description                                                                            |
| ------------------------- | -------------------------------------------------------------------------------------- |
| **SPIFFE/SPIRE Identity** | X509-SVID for mTLS, JWT-SVID for external APIs, Federation for cross-domain trust      |
| **PoA Mandates**          | Short-lived, signed authorization tokens with `act/con/leg` claims (AAP-001/002 style) |
| **Risk-Tiered Policy**    | 145+ enterprise actions across low/medium/high risk tiers                              |
| **Dual Control**          | High-risk actions require two distinct approvers                                       |
| **Semantic Guardrails**   | Prompt injection detection with external service support                               |
| **Immutable Audit**       | Azure Blob/S3 Object Lock with hash-chain tamper evidence                              |
| **Platform Binding**      | OIDC platform tokens bound to SPIFFE identities                                        |
| **Platform SDKs**         | Pre-built connectors for Microsoft Copilot, Salesforce, SAP                            |
| **Approval Workflows**    | Dashboard UI for human approval of high-risk actions                                   |
| **IdP Federation**        | OIDC federation with Entra ID, Okta, Salesforce, SAP IAS                               |
| **OT/Industrial Edge**    | TPM attestation for industrial devices, nested SPIRE for sites                         |

## Quick Start

### Prerequisites

- Kubernetes 1.28+
- Helm 3.x
- SPIRE server deployed

### Deploy with Helm

```bash
# Add staging values
helm install atb charts/atb \
  -n atb \
  -f charts/atb/values-staging.yaml \
  -f charts/atb/values-observability.yaml
```

### Verify Deployment

```bash
kubectl get pods -n atb
kubectl logs -n atb -l app=atb-broker
```

## Architecture

### Components

| Component       | Description                                    |
| --------------- | ---------------------------------------------- |
| `atb-broker`    | Main enforcement gateway (Go)                  |
| `atb-agentauth` | PoA issuance service with dual-control support |
| `opa`           | Policy decision engine (sidecar)               |
| `spire-agent`   | SPIFFE workload identity                       |

### Documentation

- [Getting Started](docs/getting-started.md) - Quick start guide for developers
- [Architecture Guide](docs/architecture.md) - System design and components
- [Authentication Guide](docs/authentication.md) - SPIFFE identity and PoA tokens
- [API Reference](docs/api-reference.md) - Practical API examples and SDK usage
- [API Spec - Broker](docs/openapi.yaml) - OpenAPI spec for ATB Broker
- [API Spec - AgentAuth](docs/openapi-agentauth.yaml) - OpenAPI spec for AgentAuth
- [Client Examples](examples/) - Python and Go client implementations
- [Production Deployment](docs/production-deployment.md) - HA, security, and operations
- [Kubernetes Quickstart](docs/k8s-quickstart.md) - Basic deployment guide
- [Security Best Practices](docs/security-best-practices.md) - Hardening guide
- [Observability Guide](docs/observability.md) - Metrics, logging, alerting
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions
- [FAQ](docs/faq.md) - Frequently asked questions
- [Operating Model](docs/operating-model.md) - RACI, approval flows, risk thresholds
- [Enterprise Actions](docs/enterprise-actions.md) - 145+ actions with constraint rules
- [Audit Events](docs/audit.md) - Event format, SIEM integration, querying
- [Requirements Compliance](docs/requirements-compliance.md) - Architecture alignment

## Risk Tiers

| Tier       | Actions | Approval                   | Examples                                 |
| ---------- | ------- | -------------------------- | ---------------------------------------- |
| **High**   | 60+     | Dual control (2 approvers) | SAP payments, PII export, IAM escalation |
| **Medium** | 40+     | Single approver            | CRM updates, order management            |
| **Low**    | 45+     | PoA only                   | Read operations, status checks           |

See [`docs/enterprise-actions.md`](docs/enterprise-actions.md) for the complete catalog.

## Configuration

### Environment Variables (Broker)

| Variable                    | Description                  | Default                                          |
| --------------------------- | ---------------------------- | ------------------------------------------------ |
| `SPIFFE_ENDPOINT_SOCKET`    | SPIRE Workload API socket    | `/run/spire/sockets/agent.sock`                  |
| `OPA_DECISION_URL`          | OPA policy endpoint          | `http://localhost:8181/v1/data/atb/poa/decision` |
| `PLATFORM_JWKS_URL`         | Platform OIDC JWKS endpoint  | -                                                |
| `POA_SINGLE_USE`            | Enable PoA replay protection | `true`                                           |
| `ALLOW_UNMANDATED_LOW_RISK` | Allow low-risk without PoA   | `false`                                          |
| `GUARDRAILS_URL`            | External guardrails service  | -                                                |
| `AUDIT_SINK_URL`            | Audit event sink endpoint    | -                                                |

### Connectors

Configure backend system connectors in `config/connectors.example.json`:

```json
{
  "connectors": [
    {
      "id": "salesforce-prod",
      "egress_allowlist": ["*.salesforce.com"],
      "jwt_svid_audience": "https://login.salesforce.com",
      "jwt_svid_header": "Authorization"
    }
  ]
}
```

## OPA Policy

The policy engine enforces:

- PoA structure validation (`act`, `con`, `leg`, `jti`, `iat`, `exp`)
- Risk tier determination and approval requirements
- Action-specific constraints (amount limits, allowlists, safety bounds)
- Platform↔SPIFFE identity binding

### Run Policy Tests

```bash
opa test opa/policy/ -v --v0-compatible
```

### Policy Templates

Pre-built policy templates for common enterprise platforms:

| Template | Location | Use Case |
|----------|----------|----------|
| SAP | `opa/policy/templates/sap.rego` | Payments, vendor changes, journal entries |
| Salesforce | `opa/policy/templates/salesforce.rego` | Opportunities, credits, contracts |
| OT/Industrial | `opa/policy/templates/ot.rego` | PLC control, setpoints, safety overrides |

## Platform SDKs

Pre-built connectors for enterprise AI platforms:

```python
from atb.platforms import CopilotConnector, SalesforceConnector, SAPConnector

# Microsoft Copilot / Entra ID
copilot = CopilotConnector(
    tenant_id="your-tenant",
    client_id="your-client-id",
    client_secret="your-secret"
)
identity = await copilot.authenticate()
result = await copilot.execute_action("calendar:create", {...})

# Salesforce Agentforce
salesforce = SalesforceConnector(
    instance_url="https://yourorg.salesforce.com",
    client_id="your-client-id"
)

# SAP Joule / S/4HANA
sap = SAPConnector(
    instance_url="https://your-sap.s4hana.cloud.sap",
    client_id="your-client-id"
)
```

See [sdk/python/README.md](sdk/python/README.md) for complete documentation.

## Approval Workflows

The ATB Dashboard provides human-in-the-loop approval for high-risk actions:

- **Real-time queue** - Pending approvals with 10s polling
- **Risk tier indicators** - Visual warnings for high-risk requests
- **Audit context** - Full action details, justification, constraints
- **Approve/Reject** - Immediate enforcement via ATB broker

Access the approvals page at: `http://localhost:3003/approvals`

## IdP Federation

ATB supports OIDC federation to bind platform identities to SPIFFE:

| Provider | Token Endpoint | JWKS Endpoint |
|----------|---------------|---------------|
| Entra ID | `login.microsoftonline.com` | `login.microsoftonline.com/{tenant}/discovery/v2.0/keys` |
| Okta | `{domain}/oauth2/default/v1/token` | `{domain}/oauth2/default/v1/keys` |
| Salesforce | `login.salesforce.com/services/oauth2/token` | `login.salesforce.com/id/keys` |
| SAP IAS | `{tenant}.accounts.ondemand.com/oauth2/token` | `{tenant}.accounts.ondemand.com/oauth2/certs` |

Configure federation in `config/oidc-federation.example.json`.

## OT/Industrial Edge

ATB supports industrial environments with TPM attestation:

- **TPM DevID** - Hardware-rooted identity for PLCs/HMIs
- **Nested SPIRE** - Site-level SPIRE servers with upstream federation
- **Safety bounds** - Constraint policies for setpoint limits

See [spire/ot/README.md](spire/ot/README.md) for industrial deployment.

## Development

### Quick Start for Developers

```bash
# One-command setup
make quickstart

# Or use the developer CLI
./scripts/atb.sh start
./scripts/atb.sh status
./scripts/atb.sh test opa
```

### Developer CLI

The `atb` CLI provides commands for common development tasks:

```bash
./scripts/atb.sh start          # Start local stack
./scripts/atb.sh stop           # Stop services
./scripts/atb.sh status         # Check service health
./scripts/atb.sh logs [service] # View logs
./scripts/atb.sh test [type]    # Run tests (opa, go, e2e, all)
./scripts/atb.sh query read:logs # Query OPA policy
./scripts/atb.sh demo           # Interactive demo
./scripts/atb.sh validate       # Validate all configs
```

### Make Targets

```bash
make help              # Show all available commands
make setup             # Install dependencies
make test              # Run all tests
make docker-up         # Start full stack
make demo              # Interactive risk tier demo
make validate          # Validate all configurations
make load-test         # Run k6 load tests
make docs              # Generate API documentation
```

### Project Structure

```
├── atb-gateway-go/    # Go services (broker, agentauth)
├── atb-gateway-py/    # Python gateway (alternative)
├── charts/atb/        # Helm chart
├── config/            # Example configurations
├── deploy/            # Deployment manifests
│   ├── grafana/       # Grafana dashboards
│   ├── k8s/           # Kubernetes manifests
│   └── prometheus/    # Alerting rules
├── dev/               # Development tools
├── docs/              # Documentation
├── examples/          # Client examples
├── opa/policy/        # OPA policies
├── schemas/           # JSON schemas
├── scripts/           # Utility scripts
├── sdk/               # SDK documentation
├── spire/             # SPIRE configuration
└── tests/load/        # k6 load tests
```

## CI/CD

The GitHub Actions workflow includes:

- **Security audit** - govulncheck, pip-audit
- **OPA policy tests** - Syntax check, unit tests, coverage
- **Helm lint** - Chart validation
- **Multi-arch builds** - amd64/arm64 container images
- **Staged deployment** - Staging → Production with manual gate

## Contributing

1. Policy changes require Security team approval (CODEOWNER)
2. All OPA policy changes must include tests
3. Follow the [operating model](docs/operating-model.md) RACI

## License

Proprietary - Internal use only
