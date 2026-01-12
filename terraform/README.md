# ATB Terraform Modules

This directory contains Terraform modules for deploying the Agent Trust Broker (ATB) to cloud platforms.

## Available Modules

| Module | Description |
|--------|-------------|
| [azure](./azure/) | Azure AKS deployment with Workload Identity |
| [aws](./aws/) | AWS EKS deployment with IRSA |
| [gcp](./gcp/) | GCP GKE deployment with Workload Identity |
| [kubernetes](./kubernetes/) | Cloud-agnostic Kubernetes resources |

## Quick Start

### Azure

```hcl
module "atb" {
  source = "github.com/mauriciomferz/ATB//terraform/azure"

  resource_group_name = "atb-prod"
  location            = "westeurope"
  cluster_name        = "atb-cluster"
  trust_domain        = "atb.example.com"

  tags = {
    Environment = "production"
    Project     = "ATB"
  }
}
```

### AWS

```hcl
module "atb" {
  source = "github.com/mauriciomferz/ATB//terraform/aws"

  cluster_name   = "atb-cluster"
  vpc_id         = "vpc-xxxxxxxxx"
  subnet_ids     = ["subnet-xxx", "subnet-yyy"]
  trust_domain   = "atb.example.com"

  tags = {
    Environment = "production"
    Project     = "ATB"
  }
}
```

### GCP

```hcl
module "atb" {
  source = "github.com/mauriciomferz/ATB//terraform/gcp"

  project_id     = "my-project"
  region         = "europe-west1"
  cluster_name   = "atb-cluster"
  trust_domain   = "atb.example.com"
}
```

## Module Features

All modules include:

- ✅ Kubernetes cluster with security best practices
- ✅ SPIRE deployment for workload identity
- ✅ OPA deployment for policy enforcement
- ✅ ATB broker and agentauth services
- ✅ Prometheus/Grafana monitoring (optional)
- ✅ Ingress with TLS termination
- ✅ Secret management integration
- ✅ Network policies

## Prerequisites

- Terraform >= 1.5
- Cloud provider CLI authenticated
- kubectl configured

## Customization

Each module exposes common variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `trust_domain` | SPIFFE trust domain | `atb.example.com` |
| `namespace` | Kubernetes namespace | `atb-system` |
| `broker_replicas` | Broker pod replicas | `2` |
| `enable_monitoring` | Deploy Prometheus/Grafana | `true` |
| `enable_network_policies` | Apply network policies | `true` |

See individual module READMEs for complete variable documentation.

## License

MIT License
