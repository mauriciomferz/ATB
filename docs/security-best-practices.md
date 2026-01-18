# Security Best Practices

This guide covers security best practices for deploying and operating ATB in production environments.

## Defense in Depth

ATB implements multiple layers of security:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Network Layer: mTLS, Egress Allowlist, Network Policies                │
├─────────────────────────────────────────────────────────────────────────┤
│  Identity Layer: SPIFFE/SPIRE, X.509 SVIDs, Certificate Rotation        │
├─────────────────────────────────────────────────────────────────────────┤
│  Authorization Layer: PoA Tokens, OPA Policy, Risk Tiers                │
├─────────────────────────────────────────────────────────────────────────┤
│  Audit Layer: Immutable Logs, Hash Chain, Tamper Evidence               │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Identity Security

### SPIFFE/SPIRE Configuration

**Workload Attestation**

Configure SPIRE to verify workload identity:

```hcl
# SPIRE Agent configuration
agent {
  # Use Kubernetes attestation
  workload_attestors = ["k8s"]
  
  # Bind to node identity
  join_token = ""
  node_attestor = "k8s_sat"
}
```

**Certificate Rotation**

Configure short-lived certificates:

```yaml
# SPIRE Server configuration
ca_ttl: "24h"      # CA certificate TTL
svid_ttl: "1h"     # Workload SVID TTL
```

**Trust Domain Separation**

Use separate trust domains for environments:

```
spiffe://prod.example.org/...    # Production
spiffe://staging.example.org/... # Staging  
spiffe://dev.example.org/...     # Development
```

### Agent Identity Best Practices

1. **Unique identities per agent instance**
   ```
   spiffe://example.org/ns/prod/agent/crm-agent/instance-1
   ```

2. **Include environment in identity**
   ```
   spiffe://example.org/env/prod/agent/payment-processor
   ```

3. **Limit identity scope**
   - Each agent should have the minimum identity needed
   - Don't share identities between different agent types

---

## Token Security

### PoA Token Lifetimes

Configure appropriate TTLs:

| Token Type | Recommended TTL | Rationale |
|------------|-----------------|-----------|
| Low-risk actions | 5 minutes | Short window of opportunity |
| Medium-risk actions | 3 minutes | Reduced exposure |
| High-risk actions | 1 minute | Minimize risk window |
| Challenge tokens | 5 minutes | Time for approval flow |

```yaml
# AgentAuth configuration
poa:
  default_ttl: "5m"
  max_ttl: "10m"
  high_risk_ttl: "1m"
```

### Token Replay Prevention

ATB prevents token replay by:

1. **JTI tracking**: Every token has a unique ID
2. **Cache-based deduplication**: Seen JTIs are cached until expiry
3. **Clock sync requirements**: Servers must be NTP-synced

Configure Redis for distributed JTI cache:

```yaml
redis:
  enabled: true
  cluster:
    enabled: true
  auth:
    password: "${REDIS_PASSWORD}"
```

### Signing Key Management

**Use Hardware Security Modules (HSM)**

For production, store signing keys in HSM:

```yaml
# AWS CloudHSM
signing:
  provider: "cloudhsm"
  slot: 1
  pin: "${HSM_PIN}"

# Azure Key Vault
signing:
  provider: "azure-keyvault"
  vault_url: "https://atb-keys.vault.azure.net"
  key_name: "poa-signing-key"
```

**Key Rotation Schedule**

| Key Type | Rotation Period | Notes |
|----------|-----------------|-------|
| Signing keys | 90 days | Overlap period for validation |
| mTLS certificates | 24 hours | Automatic via SPIRE |
| HSM master keys | Annual | Requires maintenance window |

**Key Rotation Procedure**

```bash
# 1. Generate new key (keep old key active)
kubectl create secret generic atb-agentauth-signing-key-new \
  --from-file=ed25519_privkey_pem=new-signing.key \
  -n atb

# 2. Configure AgentAuth to use both keys
kubectl set env deployment/atb-agentauth \
  SIGNING_KEY_NEW=/keys/new-signing.key \
  -n atb

# 3. Wait for all old tokens to expire (10+ minutes)
sleep 600

# 4. Remove old key
kubectl delete secret atb-agentauth-signing-key-old -n atb
```

---

## Network Security

### mTLS Configuration

**Cipher Suites**

Only allow strong cipher suites:

```yaml
tls:
  minVersion: "TLS1.3"
  cipherSuites:
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
```

**Certificate Pinning**

For critical upstreams, enable certificate pinning:

```yaml
connectors:
  - id: "payment-gateway"
    upstream_url: "https://payments.internal"
    tls:
      pin_certs:
        - "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
```

### Egress Allowlisting

Restrict broker egress to known upstreams:

```yaml
egress:
  mode: "strict"  # Deny by default
  allowlist:
    - "sap.internal:443"
    - "salesforce.internal:443"
    - "payments.internal:443"
```

### Kubernetes Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: atb-broker-policy
  namespace: atb
spec:
  podSelector:
    matchLabels:
      app: atb-broker
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Only from agent namespace
    - from:
        - namespaceSelector:
            matchLabels:
              name: agents
      ports:
        - port: 8443
  egress:
    # Only to allowed upstreams
    - to:
        - namespaceSelector:
            matchLabels:
              name: enterprise-systems
      ports:
        - port: 443
    # OPA sidecar
    - to:
        - podSelector:
            matchLabels:
              app: opa
      ports:
        - port: 8181
```

---

## Policy Security

### OPA Policy Best Practices

**Default Deny**

Always default to deny:

```rego
package atb.poa

default allow = false
default decision = "deny"
```

**Explicit Risk Classification**

Every action must be explicitly classified:

```rego
# Unknown actions are denied
risk_tier = "unknown" {
  not low_risk_actions[input.poa.act]
  not medium_risk_actions[input.poa.act]
  not high_risk_actions[input.poa.act]
}

deny[reason] {
  risk_tier == "unknown"
  reason := "action_not_classified"
}
```

**Policy Testing**

Test all policy paths:

```bash
# Run OPA policy tests
make test-opa

# Coverage report
opa test opa/policy/ --coverage --format=json | jq '.coverage'
```

**Policy Versioning**

Version policies with your code:

```
opa/
├── policy/
│   ├── poa.rego           # Main policy
│   ├── poa_test.rego      # Tests
│   └── data/
│       └── actions.json   # Action definitions
└── CHANGELOG.md           # Policy changes
```

### Constraint Validation

Validate all constraints server-side:

```rego
# Validate amount constraints
deny[reason] {
  input.poa.con.amount > 1000000
  reason := "amount_exceeds_limit"
}

# Validate date constraints
deny[reason] {
  input.poa.con.valid_until
  time.parse_rfc3339_ns(input.poa.con.valid_until) < time.now_ns()
  reason := "constraint_expired"
}
```

---

## Approval Security

### Dual Control Requirements

For high-risk actions, enforce dual control:

```rego
dual_control_required {
  risk_tier == "high"
}

minimum_approvers = 2 {
  dual_control_required
}

minimum_approvers = 1 {
  not dual_control_required
}
```

### Approver Validation

1. **Prevent self-approval**
   ```rego
   deny[reason] {
     input.approvers[_] == input.requester
     reason := "self_approval_not_allowed"
   }
   ```

2. **Validate approver identity**
   - Integrate with your IdP
   - Require MFA for approvals
   - Log all approval actions

3. **Time-bound approvals**
   - Challenges expire after 5 minutes
   - Approvals must be recent

### Separation of Duties

Configure approver pools by risk tier:

```yaml
approval:
  pools:
    high_risk:
      required: 2
      from:
        - "security-team@example.com"
        - "finance-leads@example.com"
    medium_risk:
      required: 1
      from:
        - "team-leads@example.com"
```

---

## Audit Security

### Immutable Storage

Configure immutable audit storage:

**AWS S3 with Object Lock**

```yaml
audit:
  sink: "s3"
  s3:
    bucket: "atb-audit-logs"
    region: "us-east-1"
    object_lock:
      enabled: true
      mode: "GOVERNANCE"  # or COMPLIANCE
      retention_days: 2555  # 7 years
```

**Azure Blob with Immutable Storage**

```yaml
audit:
  sink: "azure"
  azure:
    container: "atb-audit"
    immutable_policy:
      enabled: true
      retention_days: 2555
```

### Hash Chain Integrity

Enable hash chain for tamper evidence:

```yaml
audit:
  hash_chain:
    enabled: true
    algorithm: "sha256"
    checkpoint_interval: 100  # Checkpoint every 100 events
```

### Audit Log Signing

Sign audit events with HSM:

```yaml
audit:
  signing:
    enabled: true
    key_vault: "https://atb-keys.vault.azure.net"
    key_name: "audit-signing-key"
```

---

## Operational Security

### Secrets Management

**Never commit secrets**

Use external secrets management:

```yaml
# ExternalSecrets operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: atb-secrets
spec:
  secretStoreRef:
    name: azure-keyvault
    kind: ClusterSecretStore
  target:
    name: atb-secrets
  data:
    - secretKey: signing-key
      remoteRef:
        key: atb-signing-key
```

**Rotate secrets regularly**

| Secret | Rotation Period |
|--------|-----------------|
| Signing keys | 90 days |
| Database passwords | 30 days |
| API keys | 60 days |
| HSM credentials | Annual |

### Access Control

**RBAC for ATB namespace**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: atb-operator
  namespace: atb
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch", "update"]
  # No access to secrets!
```

**Break-glass procedures**

Document emergency access:
1. Require 2 operators for emergency changes
2. Log all emergency access
3. Review within 24 hours
4. Auto-expire emergency credentials

### Incident Response

**Detection triggers**

- High denial rate (>10% over 5 minutes)
- Unknown agent identities
- Invalid signatures
- Clock skew errors

**Response playbook**

1. **Contain**: Block suspicious agent identity
2. **Investigate**: Review audit logs
3. **Eradicate**: Revoke compromised credentials
4. **Recover**: Issue new credentials
5. **Lessons**: Update policies

---

## Compliance Checklist

### Pre-Production

- [ ] SPIRE production-ready (HA, backed by persistent storage)
- [ ] Signing keys in HSM
- [ ] mTLS enforced on all connections
- [ ] Egress allowlist configured
- [ ] Network policies applied
- [ ] Audit logs to immutable storage
- [ ] Hash chain enabled
- [ ] All policies tested (>80% coverage)
- [ ] Secret management in place
- [ ] RBAC configured
- [ ] Incident response documented

### Ongoing

- [ ] Key rotation on schedule
- [ ] Certificate rotation working
- [ ] Audit logs reviewed weekly
- [ ] Policy changes require review
- [ ] Access reviews quarterly
- [ ] Penetration testing annual

---

## Related Documentation

- [Authentication Guide](authentication.md) - Identity and token details
- [Audit Events](audit.md) - Audit format and querying
- [Observability](observability.md) - Monitoring and alerting
- [Troubleshooting](troubleshooting.md) - Security-related issues
