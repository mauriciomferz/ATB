# ATB Audit Events

The gateways emit one JSON audit event per decision (allow/deny/error) to stdout. Every request—whether allowed, denied, or errored—generates an immutable audit record.

## Goals

- **Legal accountability**: Map each API call to a PoA mandate (`poa_jti`)
- **Traceability**: Correlate traces/logs via `request_id`
- **Observability**: Keep events structured for SIEM ingestion
- **Compliance**: Support GDPR, SOX, and regulatory requirements
- **Security monitoring**: Track authorization events, approvals, and security violations

---

## Audit Event Sources

ATB emits audit events from two services:

| Service       | Events               | Purpose                                      |
| ------------- | -------------------- | -------------------------------------------- |
| **Broker**    | Request decisions    | Tracks allow/deny for proxied requests       |
| **AgentAuth** | Authorization events | Tracks challenges, approvals, token issuance |

---

## Schema Reference

Canonical JSON Schema: [schemas/audit-event.schema.json](../schemas/audit-event.schema.json)

### Required Fields

| Field            | Type   | Description                       |
| ---------------- | ------ | --------------------------------- |
| `ts`             | string | RFC3339 UTC timestamp             |
| `agent_identity` | string | SPIFFE ID of the requesting agent |
| `decision`       | enum   | `allow`, `deny`, or `error`       |
| `reason`         | string | Machine-readable reason code      |
| `target_service` | string | Upstream service URL              |
| `method`         | string | HTTP method (GET, POST, etc.)     |
| `path`           | string | Request path                      |

### Optional Fields

| Field         | Type   | Description                                   |
| ------------- | ------ | --------------------------------------------- |
| `request_id`  | string | Unique request correlation ID                 |
| `poa_jti`     | string | PoA token ID (for allowed requests)           |
| `action`      | string | Authorized action (e.g., `sap.vendor.change`) |
| `constraints` | object | Action constraints (e.g., `{"amount": 1000}`) |
| `approvers`   | array  | List of approver IDs who authorized           |
| `legal_basis` | object | Legal basis for data processing               |
| `latency_ms`  | number | Request processing time                       |

---

## Event Examples

### Deny (Missing PoA)

```json
{
  "ts": "2026-01-11T10:20:30Z",
  "request_id": "req-123",
  "agent_identity": "spiffe://example.org/ns/default/sa/agent/connector",
  "decision": "deny",
  "reason": "missing_poa",
  "target_service": "http://upstream:9000",
  "method": "POST",
  "path": "/sap/vendor/change"
}
```

### Deny (Insufficient Approvals)

```json
{
  "ts": "2026-01-11T10:20:35Z",
  "request_id": "req-125",
  "agent_identity": "spiffe://example.org/ns/default/sa/agent/connector",
  "decision": "deny",
  "reason": "insufficient_approvals",
  "action": "payment.execute",
  "constraints": { "amount": 50000 },
  "target_service": "http://upstream:9000",
  "method": "POST",
  "path": "/payments/execute"
}
```

### Allow (Low Risk)

```json
{
  "ts": "2026-01-11T10:20:31Z",
  "request_id": "req-124",
  "poa_jti": "a0c7...",
  "agent_identity": "spiffe://example.org/ns/default/sa/agent/connector",
  "action": "crm.contact.read",
  "decision": "allow",
  "reason": "policy_allow",
  "target_service": "http://upstream:9000",
  "method": "GET",
  "path": "/crm/contacts/12345",
  "latency_ms": 12
}
```

### Allow (High Risk with Approvals)

```json
{
  "ts": "2026-01-11T10:21:00Z",
  "request_id": "req-200",
  "poa_jti": "b1d8...",
  "agent_identity": "spiffe://example.org/ns/default/sa/agent/connector",
  "action": "sap.vendor.change",
  "constraints": {
    "vendor_id": "V-12345",
    "changes": ["bank_account"]
  },
  "approvers": ["alice@example.com", "bob@example.com"],
  "legal_basis": {
    "type": "contract",
    "accountable_party": "finance-team@example.com"
  },
  "decision": "allow",
  "reason": "policy_allow",
  "target_service": "http://upstream:9000",
  "method": "POST",
  "path": "/sap/vendor/change"
}
```

### Error

```json
{
  "ts": "2026-01-11T10:22:00Z",
  "request_id": "req-300",
  "agent_identity": "spiffe://example.org/ns/default/sa/agent/connector",
  "decision": "error",
  "reason": "upstream_timeout",
  "target_service": "http://upstream:9000",
  "method": "POST",
  "path": "/sap/vendor/list"
}
```

---

## AgentAuth Audit Events

AgentAuth emits structured audit events for authorization operations. These events track the full lifecycle of PoA token issuance.

### AgentAuth Event Schema

| Field             | Type    | Description                             |
| ----------------- | ------- | --------------------------------------- |
| `timestamp`       | string  | RFC3339 UTC timestamp                   |
| `event_type`      | string  | Event category (see below)              |
| `request_id`      | string  | Unique request correlation ID           |
| `agent_spiffe_id` | string  | SPIFFE ID of the requesting agent       |
| `action`          | string  | Action being authorized                 |
| `risk_tier`       | string  | `low`, `medium`, or `high`              |
| `approver_id`     | string  | Approver identity (for approval events) |
| `challenge_id`    | string  | Challenge ID (for approval flow)        |
| `success`         | boolean | Whether the operation succeeded         |
| `error`           | string  | Error message (on failure)              |
| `source_ip`       | string  | Client IP address                       |
| `user_agent`      | string  | Client user agent                       |
| `duration_ms`     | number  | Processing time in milliseconds         |

### AgentAuth Event Types

| Event Type           | Description                    |
| -------------------- | ------------------------------ |
| `challenge_created`  | New approval challenge created |
| `approval_submitted` | Approver submitted approval    |
| `approval_rejected`  | Approver rejected request      |
| `poa_issued`         | PoA token successfully issued  |
| `auth_failed`        | Authentication failed          |
| `rate_limited`       | Request rate limited           |
| `validation_failed`  | Input validation failed        |

### Challenge Created

```json
{
  "timestamp": "2026-01-12T10:00:00Z",
  "event_type": "challenge_created",
  "request_id": "req-1001",
  "agent_spiffe_id": "spiffe://example.org/agent/finance-bot",
  "action": "sap.vendor.change",
  "risk_tier": "high",
  "challenge_id": "ch_abc123",
  "required_approvers": 2,
  "success": true,
  "source_ip": "10.0.0.50",
  "duration_ms": 15
}
```

### Approval Submitted

```json
{
  "timestamp": "2026-01-12T10:05:00Z",
  "event_type": "approval_submitted",
  "request_id": "req-1002",
  "challenge_id": "ch_abc123",
  "approver_id": "alice@example.com",
  "action": "sap.vendor.change",
  "success": true,
  "source_ip": "10.0.0.100"
}
```

### Self-Approval Blocked

```json
{
  "timestamp": "2026-01-12T10:05:30Z",
  "event_type": "approval_submitted",
  "request_id": "req-1003",
  "challenge_id": "ch_abc123",
  "approver_id": "finance-bot@example.com",
  "action": "sap.vendor.change",
  "success": false,
  "error": "self_approval_not_allowed",
  "source_ip": "10.0.0.50"
}
```

### PoA Issued (High Risk)

```json
{
  "timestamp": "2026-01-12T10:10:00Z",
  "event_type": "poa_issued",
  "request_id": "req-1004",
  "agent_spiffe_id": "spiffe://example.org/agent/finance-bot",
  "action": "sap.vendor.change",
  "risk_tier": "high",
  "challenge_id": "ch_abc123",
  "poa_jti": "poa_xyz789",
  "approvers": ["alice@example.com", "bob@example.com"],
  "success": true,
  "duration_ms": 8
}
```

### Authentication Failed

```json
{
  "timestamp": "2026-01-12T10:15:00Z",
  "event_type": "auth_failed",
  "request_id": "req-1005",
  "approver_id": "mallory@example.com",
  "success": false,
  "error": "invalid_jwt_signature",
  "source_ip": "192.168.1.100",
  "user_agent": "curl/7.81.0"
}
```

### Rate Limited

```json
{
  "timestamp": "2026-01-12T10:20:00Z",
  "event_type": "rate_limited",
  "request_id": "req-1006",
  "agent_spiffe_id": "spiffe://example.org/agent/rogue-bot",
  "source_ip": "10.0.0.200",
  "success": false,
  "error": "rate_limit_exceeded"
}
```

---

## Reason Codes

| Code                     | Decision | Description                         |
| ------------------------ | -------- | ----------------------------------- |
| `policy_allow`           | allow    | Request authorized by policy        |
| `missing_poa`            | deny     | No PoA token provided               |
| `invalid_poa_signature`  | deny     | PoA signature validation failed     |
| `token_expired`          | deny     | PoA token has expired               |
| `token_not_yet_valid`    | deny     | PoA `nbf` is in the future          |
| `token_already_used`     | deny     | Token JTI was already seen          |
| `action_not_allowed`     | deny     | Action not permitted for this agent |
| `constraint_violation`   | deny     | Constraint limits exceeded          |
| `insufficient_approvals` | deny     | Required approvals not met          |
| `legal_basis_missing`    | deny     | No legal basis provided             |
| `upstream_error`         | error    | Upstream returned an error          |
| `upstream_timeout`       | error    | Upstream request timed out          |
| `internal_error`         | error    | Broker internal error               |

---

## Collecting Audit Events

### Docker Compose (Development)

```bash
# Stream broker logs
docker compose logs -f broker | jq .

# Filter to denies only
docker compose logs broker | jq 'select(.decision == "deny")'
```

### Kubernetes

```bash
# Stream broker logs
kubectl logs -n atb -l app=atb-broker -f | jq .

# Filter by agent
kubectl logs -n atb -l app=atb-broker | \
  jq 'select(.agent_identity | contains("my-agent"))'
```

### Export to File

```bash
# Export last hour to JSONL
kubectl logs -n atb -l app=atb-broker --since=1h > audit-$(date +%Y%m%d).jsonl
```

---

## SIEM Integration

### Splunk

Use the Splunk HTTP Event Collector (HEC):

```yaml
# Kubernetes ConfigMap for Fluentd
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluentd-config
data:
  fluent.conf: |
    <source>
      @type tail
      path /var/log/containers/atb-broker*.log
      tag atb.audit
      <parse>
        @type json
      </parse>
    </source>

    <match atb.audit>
      @type splunk_hec
      host splunk.example.com
      port 8088
      token ${SPLUNK_HEC_TOKEN}
      index atb_audit
    </match>
```

### Elasticsearch/OpenSearch

```yaml
# Logstash pipeline
input {
file {
path => "/var/log/atb/*.jsonl"
codec => json
}
}

filter {
date {
match => ["ts", "ISO8601"]
target => "@timestamp"
}
mutate {
add_field => { "index_prefix" => "atb-audit" }
}
}

output {
elasticsearch {
hosts => ["https://es.example.com:9200"]
index => "%{index_prefix}-%{+YYYY.MM.dd}"
}
}
```

### Datadog

```yaml
# datadog-agent annotation
annotations:
  ad.datadoghq.com/broker.logs: |
    [{
      "source": "atb",
      "service": "atb-broker",
      "log_processing_rules": [{
        "type": "multi_line",
        "name": "json_logs",
        "pattern": "^\\{"
      }]
    }]
```

---

## Querying Audit Events

### Find All Denies for an Agent

```bash
kubectl logs -n atb -l app=atb-broker --since=24h | \
  jq 'select(.decision == "deny" and .agent_identity == "spiffe://example.org/ns/default/sa/my-agent")'
```

### Find High-Value Actions

```bash
kubectl logs -n atb -l app=atb-broker | \
  jq 'select(.constraints.amount > 10000)'
```

### Count by Decision Type

```bash
kubectl logs -n atb -l app=atb-broker --since=1h | \
  jq -r '.decision' | sort | uniq -c
```

### Find Slow Requests

```bash
kubectl logs -n atb -l app=atb-broker | \
  jq 'select(.latency_ms > 100)'
```

### Group by Action

```bash
kubectl logs -n atb -l app=atb-broker --since=1h | \
  jq -r '.action // "no-action"' | sort | uniq -c | sort -rn
```

---

## Retention and Compliance

### Retention Policy

| Environment | Retention | Rationale              |
| ----------- | --------- | ---------------------- |
| Development | 7 days    | Debugging only         |
| Staging     | 30 days   | Pre-production testing |
| Production  | 7 years   | SOX/GDPR compliance    |

### Immutability

Audit events should be stored in write-once storage:

- AWS S3 with Object Lock
- Azure Blob with Immutable Storage
- GCS with Retention Policies

### Chain of Custody

For legal proceedings, maintain:

1. **Hash chain**: Each event includes hash of previous
2. **Timestamps**: Cryptographic timestamps (RFC 3161)
3. **Signatures**: Events signed with HSM-backed keys

---

## Alerting

Configure alerts for suspicious patterns:

### High Deny Rate

```yaml
# Prometheus rule
- alert: ATBHighDenyRate
  expr: |
    sum(rate(atb_decisions_total{decision="deny"}[5m])) 
    / sum(rate(atb_decisions_total[5m])) > 0.5
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "More than 50% of ATB requests are denied"
```

### Multiple Failed Agents

```yaml
- alert: ATBAgentDenialSpike
  expr: |
    count(
      count by (agent_identity) (
        increase(atb_decisions_total{decision="deny"}[5m]) > 10
      )
    ) > 3
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Multiple agents experiencing high denial rates"
```

### Unusual High-Risk Actions

```yaml
- alert: ATBUnusualHighRiskActions
  expr: |
    sum(rate(atb_decisions_total{action=~".*delete.*|.*change.*"}[1h])) 
    > 2 * sum(rate(atb_decisions_total{action=~".*delete.*|.*change.*"}[1h] offset 1d))
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: "High-risk action rate is 2x normal"
```

---

## Related Documentation

- [Observability Guide](observability.md) - Metrics, dashboards, and tracing
- [Troubleshooting](troubleshooting.md) - Debugging common issues
- [Enterprise Actions](enterprise-actions.md) - Action definitions and policies
