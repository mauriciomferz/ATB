# ATB Kubernetes Terraform Module

This module deploys the ATB (Autonomy Trust Broker) components to an existing Kubernetes cluster.

## Features

- Deploys ATB Broker, Agent Auth, and OPA services
- Configures SPIRE for workload identity
- Sets up network policies for zero-trust security
- Configures Prometheus ServiceMonitors for observability
- Supports custom connector configurations

## Usage

```hcl
module "atb_kubernetes" {
  source = "github.com/mauriciomferz/ATB//terraform/kubernetes"

  namespace    = "atb"
  trust_domain = "atb.example.com"

  broker_config = {
    replicas = 3
    image    = "ghcr.io/mauriciomferz/atb-broker:v1.0.0"
    resources = {
      requests = {
        cpu    = "100m"
        memory = "256Mi"
      }
      limits = {
        cpu    = "500m"
        memory = "512Mi"
      }
    }
  }

  agentauth_config = {
    replicas = 2
    image    = "ghcr.io/mauriciomferz/atb-agentauth:v1.0.0"
  }

  connectors = {
    sap = {
      type     = "sap"
      endpoint = "https://sap.example.com"
      auth     = "spiffe"
    }
  }
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0.0 |
| kubernetes | >= 2.20.0 |
| helm | >= 2.10.0 |

## Providers

| Name | Version |
|------|---------|
| kubernetes | >= 2.20.0 |
| helm | >= 2.10.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| namespace | Kubernetes namespace for ATB | `string` | `"atb"` | no |
| trust_domain | SPIFFE trust domain | `string` | n/a | yes |
| broker_config | Broker deployment configuration | `object` | See below | no |
| agentauth_config | Agent Auth deployment configuration | `object` | See below | no |
| opa_config | OPA deployment configuration | `object` | See below | no |
| connectors | Connector configurations | `map(object)` | `{}` | no |
| enable_spire | Enable SPIRE deployment | `bool` | `true` | no |
| enable_monitoring | Enable Prometheus ServiceMonitors | `bool` | `true` | no |
| enable_network_policies | Enable network policies | `bool` | `true` | no |
| helm_values | Additional Helm values for ATB chart | `any` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| namespace | The namespace where ATB is deployed |
| broker_service | Broker service details |
| agentauth_service | Agent Auth service details |
| spire_agent_socket | Path to SPIRE agent socket |
