# ATB SDK

This directory contains SDK implementations for various programming languages.

## Available SDKs

| SDK | Status | Installation |
|-----|--------|--------------|
| [Python](./python/) | 📋 Reference Design | `pip install atb-sdk` |
| [Go](./go/) | 📋 Reference Design | `go get github.com/your-org/atb/sdk/go` |

## SDK Design Principles

All ATB SDKs follow these design principles:

### 1. Security First

- **mTLS by default**: All communication uses mutual TLS with SPIFFE identities
- **No credential leakage**: Sensitive data never logged or exposed in errors
- **Secure defaults**: Conservative timeouts, retry limits, and validation

### 2. Idiomatic Design

Each SDK follows the conventions of its target language:
- Python: Type hints, dataclasses, async/await
- Go: Interfaces, contexts, options pattern

### 3. Observable

- **Structured logging**: JSON logs with correlation IDs
- **Metrics**: Prometheus-compatible metrics
- **Tracing**: OpenTelemetry support

### 4. Resilient

- **Automatic retries**: Exponential backoff for transient failures
- **Circuit breakers**: Prevent cascade failures
- **Timeouts**: Configurable per-operation timeouts

## Quick Comparison

### Python

```python
from atb import ATBClient, Action

client = ATBClient.from_env()
response = client.authorize(
    action=Action(verb="read", resource="data/users"),
    reason="Load user profiles",
)
```

### Go

```go
import "github.com/your-org/atb/sdk/go/atb"

client, _ := atb.NewClient(atb.FromEnv())
response, _ := client.Authorize(ctx, &atb.Action{
    Verb:     "read",
    Resource: "data/users",
}, "Load user profiles")
```

## Common Patterns

### Human-in-the-Loop Approval

All SDKs support the human-in-the-loop pattern for MEDIUM and HIGH risk actions:

1. **Request authorization** - SDK calls broker with action details
2. **Receive approval request** - Broker returns approval requirements
3. **Collect approval** - Your application collects human approval
4. **Retry with approval** - SDK calls broker again with approval proof

### Risk Tier Handling

| Risk Tier | Behavior | Approval Required |
|-----------|----------|-------------------|
| LOW | Auto-approve with audit | No |
| MEDIUM | Human approval required | Yes (1 approver) |
| HIGH | Multi-party approval | Yes (2+ approvers) |

### Audit Trail

All SDK operations automatically:
- Generate correlation IDs
- Log decision rationale
- Record approval chains
- Maintain immutable audit logs

## Integration Examples

See the [examples](../examples/) directory for complete integration examples.

## Contributing

We welcome SDK contributions for additional languages. Please:

1. Follow the design principles above
2. Implement the core authorization flow
3. Include comprehensive tests
4. Document all public APIs
5. Provide runnable examples

## License

Apache 2.0
