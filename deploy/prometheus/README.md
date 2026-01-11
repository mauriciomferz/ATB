# Prometheus Configuration

Prometheus alerting rules and scrape configurations for ATB.

## Files

| File | Description |
|------|-------------|
| [alerts.yaml](alerts.yaml) | Alerting rules for ATB services |

## Alert Groups

### atb-availability
Critical alerts for service availability:
- `ATBBrokerDown` - Broker instance is down
- `ATBOPADown` - OPA instance is down
- `ATBAgentAuthDown` - AgentAuth instance is down

### atb-latency
Latency monitoring:
- `ATBHighLatency` - P95 latency > 500ms (warning)
- `ATBCriticalLatency` - P99 latency > 1s (critical)
- `OPAHighLatency` - OPA P95 > 100ms (warning)

### atb-errors
Error rate monitoring:
- `ATBHighErrorRate` - Error rate > 1% (warning)
- `ATBCriticalErrorRate` - Error rate > 5% (critical)
- `ATBAuthorizationDenialSpike` - Denial rate > 50% (warning)

### atb-approvals
Human-in-the-loop monitoring:
- `ATBPendingApprovalsHigh` - > 50 pending approvals
- `ATBApprovalWaitTimeHigh` - Avg wait > 10 minutes
- `ATBApprovalExpirationRate` - > 10% expiring

### atb-security
Security-focused alerts:
- `ATBHighRiskActionsSpike` - 2x increase in HIGH risk actions
- `ATBUnusualAgentActivity` - 50% more active agents than usual

### atb-resources
Resource monitoring:
- `OPAHighMemory` - OPA > 1GB memory
- `ATBBrokerHighMemory` - Broker > 512MB memory

## Installation

### Prometheus Operator (Kubernetes)

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: atb-alerts
  namespace: monitoring
spec:
  groups: # paste contents of alerts.yaml here
```

### Standalone Prometheus

Add to `prometheus.yml`:

```yaml
rule_files:
  - /etc/prometheus/rules/atb-alerts.yaml
```

## Scrape Configuration

Add these scrape configs for ATB services:

```yaml
scrape_configs:
  - job_name: 'atb-broker'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
        regex: broker
        action: keep
      - source_labels: [__meta_kubernetes_pod_container_port_name]
        regex: metrics
        action: keep

  - job_name: 'atb-opa'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
        regex: opa
        action: keep

  - job_name: 'atb-agentauth'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
        regex: agentauth
        action: keep
```

## Alertmanager Routes

Example Alertmanager routing:

```yaml
route:
  receiver: 'default'
  routes:
    - match:
        severity: critical
        service: atb
      receiver: 'pagerduty-atb'
      continue: true
    - match:
        security: 'true'
      receiver: 'security-team'
    - match:
        service: atb
      receiver: 'atb-slack'

receivers:
  - name: 'pagerduty-atb'
    pagerduty_configs:
      - service_key: '<your-pagerduty-key>'
  
  - name: 'security-team'
    email_configs:
      - to: 'security@example.com'
  
  - name: 'atb-slack'
    slack_configs:
      - api_url: '<your-slack-webhook>'
        channel: '#atb-alerts'
```
