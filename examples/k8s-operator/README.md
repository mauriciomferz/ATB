# ATB Kubernetes Operator Example

This example demonstrates a Kubernetes operator that integrates with ATB (Agent Trust Broker)
to provide policy-controlled operations for AI agents managing Kubernetes workloads.

## Overview

The ATB Kubernetes Operator enables AI agents to perform Kubernetes operations
(scale, restart, deploy, etc.) while enforcing enterprise governance through ATB.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ATB Kubernetes Operator                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────┐    ┌────────────┐    ┌───────────┐    ┌───────────────┐   │
│   │   AI    │───▶│ AgentTask  │───▶│  Operator │───▶│  ATB Broker   │   │
│   │  Agent  │    │    CRD     │    │           │    │               │   │
│   └─────────┘    └────────────┘    └─────┬─────┘    └───────────────┘.  │
│                                          │                              │
│                                          │ if allowed                   │
│                                          ▼                              │
│                                    ┌───────────┐                        │
│                                    │   K8s     │                        │
│                                    │   API     │                        │
│                                    └───────────┘                        │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### Custom Resource Definition (CRD)

The `AgentTask` CRD represents actions submitted by AI agents:

```yaml
apiVersion: atb.siemens.com/v1alpha1
kind: AgentTask
metadata:
  name: scale-web-frontend
spec:
  agentId: "spiffe://atb.example.com/agent/planning-agent"
  poaToken: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
  action: scale
  target:
    kind: Deployment
    name: web-frontend
    namespace: production
  payload:
    replicas: 5
```

### Supported Actions

| Action | Description | Risk Tier |
|--------|-------------|-----------|
| `scale` | Scale deployment replicas | LOW/MEDIUM |
| `restart` | Rolling restart of workload | MEDIUM |
| `update-config` | Update ConfigMap/Secret | MEDIUM |
| `deploy` | Deploy new version | HIGH |
| `rollback` | Rollback to previous version | HIGH |
| `patch` | Apply JSON patch | HIGH |

### Status Phases

| Phase | Description |
|-------|-------------|
| `Pending` | Task created, not yet processed |
| `Processing` | Authorizing with ATB |
| `Executing` | ATB approved, executing action |
| `Completed` | Action executed successfully |
| `Denied` | ATB denied the action |
| `Failed` | Execution failed |

## Installation

### Prerequisites

- Kubernetes cluster (1.20+)
- ATB Broker deployed and accessible
- kubectl configured for your cluster

### Deploy the Operator

```bash
# Install the CRD
kubectl apply -f examples/k8s-operator/crds/

# Create TLS certificates (or use cert-manager)
kubectl create secret tls atb-operator-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n atb-operator

# Deploy the operator
kubectl apply -f examples/k8s-operator/deploy/
```

### Verify Installation

```bash
# Check operator is running
kubectl get pods -n atb-operator

# Verify CRD is installed
kubectl get crd agenttasks.atb.siemens.com

# Check operator logs
kubectl logs -n atb-operator -l app.kubernetes.io/name=atb-operator
```

## Usage

### Create an AgentTask

```yaml
apiVersion: atb.siemens.com/v1alpha1
kind: AgentTask
metadata:
  name: my-task
spec:
  agentId: "spiffe://atb.example.com/agent/my-agent"
  poaToken: "<your-poa-token>"
  action: scale
  target:
    kind: Deployment
    name: my-app
    namespace: default
  payload:
    replicas: 3
```

```bash
kubectl apply -f my-task.yaml
```

### Monitor Task Status

```bash
# List all tasks
kubectl get agenttasks -A

# Watch task status
kubectl get agenttask my-task -w

# Get detailed status
kubectl describe agenttask my-task
```

### Example Output

```
NAME              ACTION   TARGET        PHASE       RISK      AGE
scale-frontend    scale    web-frontend  Completed   LOW       2m
restart-api       restart  api-server    Denied      MEDIUM    1m
deploy-v2         deploy   payment-svc   Executing   HIGH      30s
```

## ATB Policy Configuration

The operator maps Kubernetes actions to ATB actions using the format:

```
k8s.<kind>.<action>
```

Example ATB policy rules:

```rego
# Allow scaling for LOW risk actions
allow if {
    input.action == "k8s.Deployment.scale"
    input.poa.risk_tier == "LOW"
}

# Require approval for deploys
allow if {
    input.action == "k8s.Deployment.deploy"
    valid_approval(input.poa.approvals)
}

# Deny during maintenance windows
deny if {
    input.action == "k8s.Deployment.deploy"
    in_maintenance_window
}
```

## Agent Integration

AI agents can submit tasks using the Kubernetes API:

### Python Example

```python
from kubernetes import client, config

config.load_incluster_config()  # or load_kube_config() for local

api = client.CustomObjectsApi()

task = {
    "apiVersion": "atb.siemens.com/v1alpha1",
    "kind": "AgentTask",
    "metadata": {"name": "scale-frontend"},
    "spec": {
        "agentId": agent_spiffe_id,
        "poaToken": poa_token,
        "action": "scale",
        "target": {
            "kind": "Deployment",
            "name": "web-frontend",
            "namespace": "production"
        },
        "payload": {"replicas": 5}
    }
}

api.create_namespaced_custom_object(
    group="atb.siemens.com",
    version="v1alpha1",
    namespace="production",
    plural="agenttasks",
    body=task
)
```

### Go Example

```go
task := &unstructured.Unstructured{
    Object: map[string]interface{}{
        "apiVersion": "atb.siemens.com/v1alpha1",
        "kind":       "AgentTask",
        "metadata": map[string]interface{}{
            "name": "scale-frontend",
        },
        "spec": map[string]interface{}{
            "agentId":  agentSPIFFEID,
            "poaToken": poaToken,
            "action":   "scale",
            "target": map[string]interface{}{
                "kind":      "Deployment",
                "name":      "web-frontend",
                "namespace": "production",
            },
            "payload": map[string]interface{}{
                "replicas": 5,
            },
        },
    },
}

_, err := dynamicClient.Resource(agentTaskGVR).
    Namespace("production").
    Create(ctx, task, metav1.CreateOptions{})
```

## Observability

### Prometheus Metrics

The operator exposes the following metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `atb_operator_tasks_total` | Counter | Total tasks processed |
| `atb_operator_tasks_allowed` | Counter | Tasks authorized by ATB |
| `atb_operator_tasks_denied` | Counter | Tasks denied by ATB |
| `atb_operator_tasks_failed` | Counter | Tasks that failed execution |
| `atb_operator_processing_seconds` | Histogram | Task processing duration |

### Grafana Dashboard

Import the ATB Policy Analytics dashboard which includes panels for Kubernetes operator metrics.

### Audit Trail

All task decisions are logged and can be correlated with ATB audit logs using the `requestId` field in the task status.

## Security Considerations

1. **mTLS**: The operator uses mTLS to communicate with the ATB Broker
2. **RBAC**: Operator has minimal RBAC permissions for required resources
3. **Pod Security**: Runs as non-root with read-only filesystem
4. **Token Validation**: PoA tokens are validated by ATB before any action

## Development

### Build Locally

```bash
cd examples/k8s-operator
go build -o bin/operator main.go
```

### Run Locally

```bash
export KUBECONFIG=~/.kube/config
export ATB_BROKER_URL=https://localhost:8443
export ATB_INSECURE=true  # For local testing only
./bin/operator
```

### Run Tests

```bash
go test -v ./...
```

## Troubleshooting

### Task Stuck in Pending

- Check operator logs for errors
- Verify ATB Broker is accessible
- Check TLS certificate validity

### Task Denied

- Check `status.atbResult.reason` for denial reason
- Verify PoA token is valid and not expired
- Check agent has required approvals for the action

### Task Failed

- Check `status.message` for error details
- Verify RBAC permissions for target resource
- Check target resource exists
