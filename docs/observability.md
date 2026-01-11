# Observability Guide

This guide covers monitoring, logging, and alerting for the ATB system.

## Metrics

ATB exposes Prometheus metrics on the `/metrics` endpoint.

### Broker Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `atb_broker_requests_total` | Counter | `decision`, `action` | Total requests handled |
| `atb_broker_request_duration_seconds` | Histogram | `action`, `status` | Request latency |
| `atb_broker_opa_decision_duration_seconds` | Histogram | `action` | OPA query latency |
| `atb_broker_upstream_duration_seconds` | Histogram | `upstream`, `status` | Upstream call latency |
| `atb_broker_poa_validation_errors_total` | Counter | `error_type` | PoA validation failures |
| `atb_broker_active_connections` | Gauge | - | Current active connections |

### AgentAuth Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `atb_agentauth_tokens_issued_total` | Counter | `action`, `risk_tier` | Tokens issued |
| `atb_agentauth_token_denials_total` | Counter | `reason` | Token issuance denials |
| `atb_agentauth_token_duration_seconds` | Histogram | `action` | Token issuance latency |

### OPA Metrics

OPA provides built-in metrics at `/metrics`:

| Metric | Description |
|--------|-------------|
| `opa_http_request_duration_seconds` | HTTP request latency |
| `opa_decision_evaluation_seconds` | Policy evaluation time |
| `opa_loaded_policy_count` | Number of loaded policies |

## Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'atb-broker'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        regex: atb-broker
        action: keep
      - source_labels: [__meta_kubernetes_pod_container_port_number]
        regex: "9090"
        action: keep

  - job_name: 'atb-agentauth'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        regex: atb-agentauth
        action: keep

  - job_name: 'atb-opa'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        regex: opa
        action: keep
```

## Grafana Dashboards

### ATB Overview Dashboard

Create a dashboard with these panels:

**Request Rate**
```promql
sum(rate(atb_broker_requests_total[5m])) by (decision)
```

**Error Rate**
```promql
sum(rate(atb_broker_requests_total{decision="deny"}[5m])) /
sum(rate(atb_broker_requests_total[5m])) * 100
```

**P99 Latency**
```promql
histogram_quantile(0.99, 
  sum(rate(atb_broker_request_duration_seconds_bucket[5m])) by (le)
)
```

**OPA Decision Latency**
```promql
histogram_quantile(0.99,
  sum(rate(atb_broker_opa_decision_duration_seconds_bucket[5m])) by (le)
)
```

**Requests by Action**
```promql
topk(10, sum(rate(atb_broker_requests_total[5m])) by (action))
```

**Risk Tier Distribution**
```promql
sum(rate(atb_agentauth_tokens_issued_total[5m])) by (risk_tier)
```

## Alerting Rules

The Helm chart includes PrometheusRules. Key alerts:

### Critical Alerts

```yaml
# High error rate
- alert: ATBHighErrorRate
  expr: |
    sum(rate(atb_broker_requests_total{decision="deny"}[5m])) /
    sum(rate(atb_broker_requests_total[5m])) > 0.1
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "ATB error rate above 10%"

# Broker down
- alert: ATBBrokerDown
  expr: up{job="atb-broker"} == 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "ATB Broker is down"

# OPA down
- alert: ATBOPADown
  expr: up{job="atb-opa"} == 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "ATB OPA is down"
```

### Warning Alerts

```yaml
# High latency
- alert: ATBHighLatency
  expr: |
    histogram_quantile(0.99,
      sum(rate(atb_broker_request_duration_seconds_bucket[5m])) by (le)
    ) > 1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "ATB P99 latency above 1 second"

# PoA validation errors
- alert: ATBPoAValidationErrors
  expr: rate(atb_broker_poa_validation_errors_total[5m]) > 1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High rate of PoA validation errors"
```

## Logging

ATB uses structured JSON logging.

### Log Format

```json
{
  "ts": "2026-01-11T10:00:00.000Z",
  "level": "info",
  "msg": "request completed",
  "request_id": "abc-123",
  "agent_spiffe_id": "spiffe://example.org/agent",
  "action": "crm.contact.update",
  "decision": "allow",
  "risk_tier": "MEDIUM",
  "duration_ms": 45
}
```

### Log Levels

| Level | Description |
|-------|-------------|
| `debug` | Detailed debugging information |
| `info` | Normal operational events |
| `warn` | Warning conditions |
| `error` | Error conditions |

### Configure Log Level

```bash
# Environment variable
export LOG_LEVEL=debug

# Helm values
broker:
  env:
    LOG_LEVEL: info
```

### Log Aggregation

For Kubernetes deployments, use a log aggregator:

**Loki + Promtail**
```yaml
# promtail config
scrape_configs:
  - job_name: atb
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_namespace]
        regex: atb
        action: keep
```

**Example LogQL Queries**
```logql
# All denied requests
{namespace="atb"} |= "decision" |= "deny"

# High-risk actions
{namespace="atb"} | json | risk_tier="HIGH"

# Errors in last hour
{namespace="atb"} | json | level="error"
```

## Tracing

ATB supports distributed tracing via OpenTelemetry.

### Enable Tracing

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
export OTEL_SERVICE_NAME=atb-broker
```

### Trace Structure

```
ATB Broker Request
├── PoA Token Validation
│   ├── Signature Verification
│   └── Claims Validation
├── OPA Policy Decision
│   └── Policy Evaluation
├── Upstream Request
│   ├── TLS Handshake
│   └── Request/Response
└── Audit Event Emission
```

## Health Checks

### Broker Health

```bash
# Liveness
curl http://localhost:8080/healthz

# Readiness (includes OPA check)
curl http://localhost:8080/ready
```

### OPA Health

```bash
curl http://localhost:8181/health
```

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

## Runbook

### High Error Rate

1. Check broker logs for error patterns
2. Verify OPA is healthy and policies are loaded
3. Check upstream backend availability
4. Review recent policy or config changes

### High Latency

1. Check OPA policy evaluation time
2. Verify upstream backend performance
3. Check for resource constraints (CPU, memory)
4. Review connection pool settings

### PoA Validation Failures

1. Check if signing keys are correctly configured
2. Verify token expiration settings
3. Check SPIFFE ID mismatches
4. Review legal basis completeness

### OPA Down

1. Check OPA pod status and logs
2. Verify policy ConfigMap is mounted
3. Check for OOM or resource issues
4. Restart OPA if necessary
