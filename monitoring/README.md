# ATB Monitoring

This directory contains monitoring configuration for the Autonomy Trust Broker (ATB) system.

## Overview

The monitoring stack consists of:
- **Prometheus** - Metrics collection and alerting
- **Grafana** - Visualization and dashboards

## Dashboards

### ATB Overview Dashboard
The main operational dashboard showing:
- Request rate and latency metrics
- Error rates and status codes
- Policy decisions (allow/deny)
- Risk tier distribution
- Agent authentication metrics

### ATB SLA Dashboard
Service Level Objective tracking:
- 7-day availability (target: 99.9%)
- P95 latency (target: <200ms)
- Error budget remaining
- Burn rate indicators

## Directory Structure

```
monitoring/
├── grafana/
│   ├── dashboards/
│   │   ├── atb-overview.json    # Main operational dashboard
│   │   └── atb-sla.json         # SLA/SLO tracking dashboard
│   └── provisioning/
│       ├── dashboards/
│       │   └── dashboards.yaml  # Dashboard provisioning config
│       └── datasources/
│           └── datasources.yaml # Prometheus datasource config
└── README.md
```

## Deployment

### With Helm

The dashboards are automatically provisioned when using the ATB Helm chart with observability values:

```bash
helm install atb ./charts/atb -f charts/atb/values-observability.yaml
```

### Manual Import

1. Access Grafana at your configured URL
2. Go to Dashboards → Import
3. Upload the JSON files from `grafana/dashboards/`
4. Select your Prometheus datasource

## Metrics Reference

### Broker Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `atb_broker_requests_total` | Counter | Total requests by action, status, risk_tier |
| `atb_broker_request_duration_seconds` | Histogram | Request latency distribution |
| `atb_broker_active_connections` | Gauge | Current active connections |

### Agent Auth Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `atb_agentauth_requests_total` | Counter | Authentication requests by status |
| `atb_agentauth_active_sessions` | Gauge | Active sessions by agent type |
| `atb_agentauth_token_validations_total` | Counter | Token validation attempts |

### OPA Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `atb_opa_decisions_total` | Counter | Policy decisions by decision, reason |
| `atb_opa_evaluation_duration_seconds` | Histogram | Policy evaluation latency |

## Alerting

Alert rules are defined in `charts/atb/templates/prometheus-rules.yaml` and include:

- **ATBHighErrorRate**: Error rate > 1% for 5 minutes
- **ATBHighLatency**: P95 latency > 500ms for 10 minutes
- **ATBPodDown**: ATB pods not running
- **ATBErrorBudgetBurn**: Error budget burning faster than expected

## Customization

### Adding Custom Dashboards

1. Create a new JSON dashboard file in `grafana/dashboards/`
2. Use the template variables `${datasource}` and `${namespace}` for consistency
3. Tag with `atb` for organization

### Modifying Alerts

Edit `charts/atb/templates/prometheus-rules.yaml` to add or modify alert rules.

## Troubleshooting

### No Data in Dashboards

1. Verify Prometheus is scraping ATB pods:
   ```bash
   kubectl port-forward svc/prometheus-server 9090:9090
   # Open http://localhost:9090/targets
   ```

2. Check ServiceMonitor is configured:
   ```bash
   kubectl get servicemonitor -n atb
   ```

### Missing Metrics

Ensure the broker and agentauth services are exposing metrics on the `/metrics` endpoint.
