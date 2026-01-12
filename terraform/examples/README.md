# ATB Terraform Examples

This directory contains complete, production-ready examples for deploying ATB to different cloud platforms.

## Available Examples

| Example | Description |
|---------|-------------|
| [azure-production](./azure-production/) | Production deployment on Azure AKS with Key Vault |
| [aws-production](./aws-production/) | Production deployment on AWS EKS with Secrets Manager |

## Getting Started

Each example includes:

- `README.md` - Detailed deployment instructions
- `main.tf` - Main Terraform configuration
- `variables.tf` - Input variables
- `outputs.tf` - Output values
- `terraform.tfvars.example` - Example variable values

## Prerequisites

1. **Terraform** >= 1.0.0
2. **Cloud CLI** authenticated:
   - Azure: `az login`
   - AWS: `aws configure`
   - GCP: `gcloud auth application-default login`
3. **kubectl** installed

## Quick Start

```bash
# Choose your cloud provider
cd azure-production  # or aws-production

# Configure variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

# Deploy
terraform init
terraform plan
terraform apply

# Get cluster credentials (example for Azure)
$(terraform output -raw get_credentials_command)

# Verify deployment
kubectl get pods -n atb
```

## Architecture

All examples deploy:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Cloud Platform (Azure/AWS/GCP)               │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Kubernetes Cluster                       │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │                  ATB Namespace                       │  │  │
│  │  │                                                      │  │  │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │  │  │
│  │  │  │  Broker  │  │AgentAuth │  │   OPA    │          │  │  │
│  │  │  │ (x3 HA)  │  │  (x2 HA) │  │  (x2 HA) │          │  │  │
│  │  │  └────┬─────┘  └────┬─────┘  └────┬─────┘          │  │  │
│  │  │       │              │              │               │  │  │
│  │  │  ┌────┴──────────────┴──────────────┴────┐         │  │  │
│  │  │  │           SPIRE Agent (DaemonSet)     │         │  │  │
│  │  │  └───────────────────────────────────────┘         │  │  │
│  │  │                                                      │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │                                                           │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │  │
│  │  │  Ingress    │  │  Monitoring │  │  Network    │       │  │
│  │  │  Controller │  │ (Prometheus)│  │  Policies   │       │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐     │
│  │  Key Vault /   │  │  Container    │  │  Logging      │      │
│  │  Secrets Mgr   │  │  Registry     │  │  (CloudWatch/ │      │
│  └────────────────┘  └────────────────┘  │   Log Analyt) │      │
│                                          └────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
```

## Security Best Practices

All examples implement:

1. **Private Clusters** - Control plane not exposed to internet
2. **Workload Identity** - No static credentials in pods
3. **Network Policies** - Zero-trust networking within cluster
4. **Encryption** - KMS/Key Vault for secrets at rest
5. **RBAC** - Least-privilege IAM roles

## Customization

### Adding Connectors

Edit `terraform.tfvars`:

```hcl
connectors = {
  sap = {
    type     = "sap"
    endpoint = "https://sap.example.com/api"
    auth     = "spiffe"
  }
  servicenow = {
    type     = "servicenow"
    endpoint = "https://instance.service-now.com/api"
    auth     = "oauth2"
  }
}
```

### Scaling

Modify replica counts in the `broker_config` and `agentauth_config`:

```hcl
broker_config = {
  replicas = 5  # Increase for higher throughput
  resources = {
    requests = { cpu = "500m", memory = "1Gi" }
    limits   = { cpu = "2000m", memory = "2Gi" }
  }
}
```

## Troubleshooting

### Pods not starting

Check events:
```bash
kubectl describe pods -n atb
```

### Network connectivity issues

Verify network policies:
```bash
kubectl get networkpolicies -n atb
```

### SPIRE issues

Check SPIRE agent logs:
```bash
kubectl logs -n atb daemonset/spire-agent
```

## Support

For issues or questions:
- Open a GitHub issue
- Check the main [ATB documentation](../../docs/)
