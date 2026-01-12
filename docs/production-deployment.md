# Production Deployment Guide

This guide covers deploying ATB to production Kubernetes environments with high availability, security hardening, and operational best practices.

---

## Prerequisites

- Kubernetes 1.28+ cluster
- Helm 3.12+
- SPIRE infrastructure deployed
- Secrets management (Vault, Azure Key Vault, AWS Secrets Manager)
- Observability stack (Prometheus, Grafana, logging)

---

## Architecture Overview

Production deployment includes:

```
                            ┌─────────────────────────────────────────────────────┐
                            │                 Kubernetes Cluster                   │
                            │                                                      │
                            │  ┌─────────────────┐    ┌─────────────────┐         │
                            │  │  ATB Namespace  │    │ SPIRE Namespace │         │
┌─────────────┐            │  │                 │    │                 │         │
│   Agents    │────mTLS───▶│  │ ┌─────────────┐ │    │ ┌─────────────┐ │         │
└─────────────┘            │  │ │   Ingress   │ │    │ │SPIRE Server │ │         │
                            │  │ └──────┬──────┘ │    │ └─────────────┘ │         │
                            │  │        │        │    │                 │         │
                            │  │ ┌──────▼──────┐ │    │ ┌─────────────┐ │         │
                            │  │ │  Broker (3) │ │    │ │ SPIRE Agent │ │         │
                            │  │ └──────┬──────┘ │    │ └─────────────┘ │         │
                            │  │        │        │    └─────────────────┘         │
                            │  │ ┌──────▼──────┐ │                                │
                            │  │ │ AgentAuth(2)│ │    ┌─────────────────┐         │
                            │  │ └─────────────┘ │    │   Redis (HA)    │         │
                            │  │                 │    └─────────────────┘         │
                            │  │ ┌─────────────┐ │                                │
                            │  │ │  OPA (per   │ │    ┌─────────────────┐         │
                            │  │ │   pod)      │ │    │  Observability  │         │
                            │  │ └─────────────┘ │    │  (Prometheus)   │         │
                            │  └─────────────────┘    └─────────────────┘         │
                            └─────────────────────────────────────────────────────┘
```

---

## Deployment Steps

### 1. Create Namespace

```bash
kubectl create namespace atb
kubectl label namespace atb \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted
```

### 2. Configure Secrets

**Using External Secrets Operator:**

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: atb-signing-key
  namespace: atb
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: azure-keyvault
    kind: ClusterSecretStore
  target:
    name: atb-agentauth-signing-key
    creationPolicy: Owner
  data:
    - secretKey: ed25519_privkey_pem
      remoteRef:
        key: atb-signing-key
```

**Using kubectl (not recommended for production):**

```bash
kubectl create secret generic atb-agentauth-signing-key \
  --from-file=ed25519_privkey_pem=signing.key \
  -n atb
```

### 3. Create Production Values

Create `values-production.yaml`:

```yaml
# Replica counts for HA
broker:
  replicaCount: 3
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 2000m
      memory: 2Gi
  
  # Pod disruption budget
  podDisruptionBudget:
    enabled: true
    minAvailable: 2
  
  # Anti-affinity for zone distribution
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        - labelSelector:
            matchLabels:
              app: atb-broker
          topologyKey: topology.kubernetes.io/zone

agentauth:
  replicaCount: 2
  resources:
    requests:
      cpu: 250m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 1Gi

opa:
  # OPA runs as sidecar
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi

# Redis for JTI cache (HA)
redis:
  enabled: true
  architecture: replication
  auth:
    existingSecret: atb-redis-password
  replica:
    replicaCount: 3

# Ingress configuration
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/ssl-passthrough: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
  hosts:
    - host: atb.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - hosts:
        - atb.example.com
      secretName: atb-tls

# Security context
securityContext:
  runAsNonRoot: true
  runAsUser: 65534
  fsGroup: 65534
  seccompProfile:
    type: RuntimeDefault

# Network policies
networkPolicy:
  enabled: true
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: agents
      ports:
        - port: 8443

# Observability
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 15s

# Logging
logging:
  format: json
  level: info
```

### 4. Deploy with Helm

```bash
helm upgrade --install atb charts/atb \
  -n atb \
  -f charts/atb/values-prod.yaml \
  -f values-production.yaml \
  --wait \
  --timeout 10m
```

### 5. Verify Deployment

```bash
# Check pods
kubectl get pods -n atb -o wide

# Check all replicas are ready
kubectl rollout status deployment/atb-broker -n atb
kubectl rollout status deployment/atb-agentauth -n atb

# Verify health endpoints
kubectl port-forward svc/atb-broker 8443:8443 -n atb &
curl -k https://localhost:8443/health
```

---

## High Availability

### Broker HA

The broker is stateless—scale horizontally:

```yaml
broker:
  replicaCount: 3
  
  # Horizontal Pod Autoscaler
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
```

### AgentAuth HA

AgentAuth requires shared state for challenges:

```yaml
agentauth:
  replicaCount: 2
  
  # Redis for challenge state
  redis:
    enabled: true
    url: "redis://atb-redis:6379"
```

### Redis HA

Use Redis Sentinel or Cluster mode:

```yaml
redis:
  architecture: replication
  sentinel:
    enabled: true
    masterSet: atb-master
  replica:
    replicaCount: 3
```

---

## Security Hardening

### Pod Security

```yaml
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 65534
  seccompProfile:
    type: RuntimeDefault
```

### Network Policies

Restrict ingress and egress:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: atb-broker
  namespace: atb
spec:
  podSelector:
    matchLabels:
      app: atb-broker
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: agents
      ports:
        - port: 8443
  egress:
    # OPA sidecar
    - to:
        - podSelector: {}
      ports:
        - port: 8181
    # Upstreams (use specific selectors)
    - to:
        - namespaceSelector:
            matchLabels:
              name: enterprise
      ports:
        - port: 443
    # DNS
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
```

### SPIFFE/SPIRE Integration

```yaml
spire:
  enabled: true
  agentSocket: /run/spire/sockets/agent.sock
  trustDomain: example.org
  
  # Workload registration
  registration:
    - spiffeID: spiffe://example.org/atb/broker
      selectors:
        - k8s:ns:atb
        - k8s:sa:atb-broker
    - spiffeID: spiffe://example.org/atb/agentauth
      selectors:
        - k8s:ns:atb
        - k8s:sa:atb-agentauth
```

---

## Disaster Recovery

### Backup Strategy

| Component | Backup Method | Frequency | Retention |
|-----------|--------------|-----------|-----------|
| Signing keys | Key Vault backup | N/A (managed) | Permanent |
| OPA policies | Git | On commit | Permanent |
| Redis (challenges) | RDB snapshots | Hourly | 24 hours |
| Audit logs | Immutable storage | Real-time | 7 years |
| Helm values | Git | On change | Permanent |

### Recovery Procedures

**Signing Key Rotation (Emergency):**

```bash
# 1. Generate new key
openssl genpkey -algorithm ed25519 -out new-signing.key

# 2. Store in Key Vault
az keyvault secret set --vault-name atb-keys \
  --name atb-signing-key-new \
  --file new-signing.key

# 3. Update deployment
kubectl rollout restart deployment/atb-agentauth -n atb

# 4. Wait for old tokens to expire (10 min)
sleep 600

# 5. Remove old key from Key Vault
az keyvault secret delete --vault-name atb-keys \
  --name atb-signing-key-old
```

**Full Cluster Recovery:**

```bash
# 1. Deploy SPIRE first
helm upgrade --install spire spire/spire-server -n spire

# 2. Register ATB workloads
kubectl apply -f spire/registration/

# 3. Deploy ATB
helm upgrade --install atb charts/atb \
  -n atb \
  -f charts/atb/values-prod.yaml

# 4. Verify
kubectl get pods -n atb
curl -k https://atb.example.com/health
```

---

## Monitoring

### Key Metrics

| Metric | Alert Threshold | Action |
|--------|-----------------|--------|
| `atb_requests_total{status="error"}` | >1% | Check upstream health |
| `atb_poa_validations_total{result="invalid"}` | >5% | Check signing keys |
| `atb_request_duration_seconds` | p99 >500ms | Scale brokers |
| Pod restarts | >3 in 1h | Check logs |

### Dashboards

Import pre-built Grafana dashboards:

```bash
kubectl apply -f charts/atb/dashboards/
```

### Alerts

```yaml
# Prometheus rules
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: atb-alerts
  namespace: atb
spec:
  groups:
    - name: atb
      rules:
        - alert: ATBBrokerDown
          expr: up{job="atb-broker"} == 0
          for: 1m
          labels:
            severity: critical
          annotations:
            summary: "ATB Broker is down"
        
        - alert: ATBHighErrorRate
          expr: |
            sum(rate(atb_requests_total{status="error"}[5m]))
            / sum(rate(atb_requests_total[5m])) > 0.01
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "ATB error rate > 1%"
```

---

## Operational Procedures

### Rolling Updates

```bash
# Update with zero downtime
helm upgrade atb charts/atb \
  -n atb \
  -f charts/atb/values-prod.yaml \
  --set broker.image.tag=v1.2.0 \
  --wait

# Monitor rollout
kubectl rollout status deployment/atb-broker -n atb
```

### Scaling

```bash
# Manual scale
kubectl scale deployment/atb-broker --replicas=5 -n atb

# Or update HPA
kubectl patch hpa atb-broker -n atb \
  --patch '{"spec":{"maxReplicas":15}}'
```

### Maintenance Window

```bash
# 1. Enable maintenance mode (reject new requests)
kubectl set env deployment/atb-broker MAINTENANCE_MODE=true -n atb

# 2. Wait for in-flight requests (5 min)
sleep 300

# 3. Perform maintenance
# ...

# 4. Disable maintenance mode
kubectl set env deployment/atb-broker MAINTENANCE_MODE=false -n atb
```

---

## Troubleshooting

### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Pods not starting | Missing secrets | Check ExternalSecrets sync |
| mTLS failures | SPIRE not ready | Check SPIRE agent logs |
| High latency | OPA policy slow | Profile with OPA benchmark |
| Token validation errors | Clock skew | Enable NTP on nodes |

### Debug Commands

```bash
# Broker logs
kubectl logs -n atb -l app=atb-broker --tail=100

# AgentAuth logs
kubectl logs -n atb -l app=atb-agentauth --tail=100

# OPA policy decisions
kubectl exec -n atb deploy/atb-broker -c opa -- \
  curl -s localhost:8181/v1/data/atb/poa/decision

# Check SPIRE registration
kubectl exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server entry show
```

---

## Checklist

### Pre-Deployment

- [ ] Kubernetes cluster provisioned
- [ ] SPIRE server/agents deployed
- [ ] Signing keys in Key Vault
- [ ] Network policies defined
- [ ] Ingress configured with TLS
- [ ] Observability stack ready
- [ ] Audit log sink configured

### Post-Deployment

- [ ] All pods healthy
- [ ] Health endpoints responding
- [ ] Metrics flowing to Prometheus
- [ ] Alerts configured
- [ ] E2E test passing
- [ ] Runbook documented

---

## Related Documentation

- [Kubernetes Quickstart](k8s-quickstart.md) - Basic deployment
- [Security Best Practices](security-best-practices.md) - Hardening guide
- [Observability](observability.md) - Monitoring setup
- [Troubleshooting](troubleshooting.md) - Common issues
