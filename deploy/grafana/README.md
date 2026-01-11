# Grafana Dashboards

Pre-built Grafana dashboards for monitoring ATB services.

## Available Dashboards

| Dashboard | Description | UID |
|-----------|-------------|-----|
| [ATB Overview](dashboards/atb-overview.json) | Main operational dashboard | `atb-overview` |

## Installation

### Option 1: Import via Grafana UI

1. Open Grafana → Dashboards → Import
2. Upload the JSON file or paste its contents
3. Select your Prometheus data source
4. Click Import

### Option 2: Provisioning

Add to your Grafana provisioning config:

```yaml
# /etc/grafana/provisioning/dashboards/atb.yaml
apiVersion: 1
providers:
  - name: ATB
    orgId: 1
    folder: ATB
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards/atb
```

Then copy the dashboard JSON files to `/var/lib/grafana/dashboards/atb/`.

### Option 3: Kubernetes ConfigMap

```bash
kubectl create configmap grafana-dashboard-atb \
  --from-file=atb-overview.json=dashboards/atb-overview.json \
  -n monitoring
```

## Dashboard Panels

### ATB Overview Dashboard

**Overview Section:**
- Request Rate (req/s)
- Error Rate (%)
- P95 Latency (ms)
- Healthy Instances count

**Authorization Decisions:**
- Decisions over time (Allow/Deny/Pending)
- Decisions by Risk Tier pie chart (LOW/MEDIUM/HIGH)
- Top Actions bar chart

**OPA Policy Engine:**
- Query latency percentiles (p50/p95/p99)
- Memory usage per instance

**Human-in-the-Loop Approvals:**
- Pending approvals count
- Average approval wait time
- Approval outcomes (Approved/Rejected/Expired)

## Required Metrics

These dashboards expect the following Prometheus metrics:

### Broker Metrics
- `atb_broker_requests_total{status}` - Total HTTP requests
- `atb_broker_request_duration_seconds_bucket` - Request latency histogram
- `atb_broker_authorization_decisions_total{decision,risk_tier,action}` - Auth decisions
- `atb_broker_pending_approvals` - Current pending approvals gauge
- `atb_broker_approval_wait_time_seconds` - Approval wait time
- `atb_broker_approvals_total{status}` - Approval outcomes

### OPA Metrics
- `opa_request_duration_seconds_bucket` - OPA query latency
- `process_resident_memory_bytes{job="atb-opa"}` - OPA memory

### Standard Metrics
- `up{job=~"atb.*"}` - Service health

## Alerting

See [../prometheus/alerts.yaml](../prometheus/alerts.yaml) for alert rules that complement these dashboards.

## Customization

Feel free to modify these dashboards for your environment:
- Adjust thresholds based on your SLOs
- Add additional panels for your specific metrics
- Customize time ranges and refresh intervals
