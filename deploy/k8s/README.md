# Kubernetes Deployment Examples

This directory contains standalone Kubernetes manifests for deploying ATB components. These are provided as examples and for quick testing. For production deployments, use the Helm chart in `/charts/atb`.

## Quick Deploy

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Deploy all components
kubectl apply -f .

# Or deploy specific components
kubectl apply -f opa/
kubectl apply -f broker/
kubectl apply -f agentauth/
```

## Components

| Directory | Description |
|-----------|-------------|
| `namespace.yaml` | ATB namespace definition |
| `opa/` | Open Policy Agent deployment |
| `broker/` | ATB Broker service |
| `agentauth/` | AgentAuth token service |
| `secrets/` | Secret templates (DO NOT commit real secrets!) |

## Prerequisites

1. **Kubernetes cluster** (1.25+)
2. **kubectl** configured
3. **Secrets** created (see below)

## Creating Secrets

### TLS Certificates

```bash
# Create TLS secret from cert files
kubectl create secret tls atb-tls \
  --cert=server.crt \
  --key=server.key \
  -n atb

# Create CA certificate configmap
kubectl create configmap atb-ca \
  --from-file=ca.crt=ca.crt \
  -n atb
```

### PoA Signing Keys

```bash
# Create signing key secret
kubectl create secret generic poa-signing-key \
  --from-file=private.key=poa_rsa.key \
  --from-file=public.key=poa_rsa.pub \
  -n atb
```

## Verification

```bash
# Check all pods are running
kubectl get pods -n atb

# Check services
kubectl get svc -n atb

# View logs
kubectl logs -f deployment/atb-broker -n atb
kubectl logs -f deployment/atb-opa -n atb

# Test OPA health
kubectl port-forward svc/atb-opa 8181:8181 -n atb
curl http://localhost:8181/health
```

## Cleanup

```bash
kubectl delete namespace atb
```

## Notes

- These manifests use `imagePullPolicy: Always` for development
- Resource limits are set conservatively - adjust for production
- NetworkPolicies are not included - add based on your cluster's CNI
- For production, use the Helm chart which includes:
  - ServiceMonitor for Prometheus
  - PodDisruptionBudgets
  - HorizontalPodAutoscaler
  - Ingress configuration
