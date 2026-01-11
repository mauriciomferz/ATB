# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ATB, please report it responsibly:

1. **Do NOT** create a public GitHub issue
2. Email: security@example.com (replace with your security team email)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested remediation (if any)

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Security Model

ATB implements defense-in-depth with the following security controls:

### Identity Layer

| Control | Implementation |
|---------|----------------|
| **Workload Identity** | SPIFFE/SPIRE X509-SVID for internal mTLS |
| **JWT-SVID** | Short-lived tokens for external API authentication |
| **Platform Identity** | OIDC tokens (e.g., Entra ID) with JWKS validation |
| **Platform↔SPIFFE Binding** | Cryptographic binding of platform tokens to SPIFFE IDs |

### Authorization Layer

| Control | Implementation |
|---------|----------------|
| **Proof-of-Authorization (PoA)** | EdDSA-signed mandates with 5-minute TTL |
| **Replay Protection** | JTI-based single-use enforcement |
| **Risk Tiers** | Low/Medium/High with escalating approval requirements |
| **Dual Control** | High-risk actions require 2+ distinct approvers |
| **OPA Policy** | Centralized policy enforcement with 145+ action rules |

### Data Protection

| Control | Implementation |
|---------|----------------|
| **Egress Allowlists** | Per-connector URL pattern restrictions |
| **Semantic Guardrails** | Prompt injection detection (local + Azure AI Content Safety) |
| **Immutable Audit** | Azure Blob/S3 Object Lock with hash-chain tamper evidence |
| **7-Year Retention** | WORM storage for compliance requirements |

### Network Security

| Control | Implementation |
|---------|----------------|
| **mTLS Everywhere** | SPIFFE-based mutual TLS for all internal communication |
| **No Static Secrets** | Workload identity replaces API keys on message path |
| **Rate Limiting** | Per-connector request rate and burst limits |

## Secure Development

### Code Review

- All changes require Security team approval (CODEOWNER)
- OPA policy changes require additional review gate
- Automated security scanning in CI (govulncheck, pip-audit)

### Dependencies

- Go dependencies scanned with `govulncheck`
- Python dependencies scanned with `pip-audit`
- Container images built from minimal base images
- Multi-arch builds (amd64/arm64) for supply chain security

### Testing

- 27 OPA policy unit tests
- 9 Go broker test suites
- Race condition detection (`go test -race`)
- Coverage reporting in CI

## Deployment Security

### Kubernetes

- Pod security contexts with non-root users
- Read-only root filesystems where possible
- SPIFFE CSI driver for workload identity
- Network policies for pod-to-pod isolation (recommended)

### Secrets Management

- No hardcoded secrets in codebase
- Kubernetes Secrets for sensitive configuration
- External secret management recommended (e.g., HashiCorp Vault, Azure Key Vault)

## Compliance

ATB is designed to support compliance with:

- **SOC 2** - Access controls, audit logging, change management
- **GDPR** - Data minimization, purpose limitation, erasure support
- **SOX** - Dual control, separation of duties, audit trail
- **NIS2** - Security controls, incident response readiness
- **EU AI Act** - Human oversight, transparency, risk management

## Security Configuration

### Required Environment Variables

| Variable | Purpose | Security Impact |
|----------|---------|-----------------|
| `POA_SINGLE_USE=true` | Enable replay protection | **Critical** - prevents mandate reuse |
| `ALLOW_UNMANDATED_LOW_RISK=false` | Require PoA for all actions | Reduces attack surface |
| `PLATFORM_JWKS_URL` | Platform token validation | Prevents token forgery |
| `SPIFFE_ENDPOINT_SOCKET` | Workload identity | Enables mTLS authentication |

### Recommended Hardening

1. **Network Policies**: Restrict broker ingress to known agent platforms
2. **Pod Security Standards**: Enforce `restricted` policy
3. **Audit Log Forwarding**: Send to SIEM for real-time monitoring
4. **SLO Alerting**: Monitor broker/OPA availability (see PrometheusRule)
5. **Regular Key Rotation**: Rotate EdDSA signing keys for PoA issuance

## Incident Response

### Detection

- Monitor `atb_broker_requests_total{decision="deny"}` for anomalies
- Alert on `atb_guardrails_requests_total{result="blocked"}`
- Review audit logs for unauthorized action attempts

### Response

1. Revoke compromised agent SPIFFE ID via SPIRE
2. Update OPA policy to block specific actions/actors
3. Rotate AgentAuth signing keys if mandate forgery suspected
4. Preserve audit logs for forensic analysis

## Version Support

| Version | Security Updates |
|---------|------------------|
| main branch | Active development |
| release/* branches | Security patches for 12 months |

## Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities.
