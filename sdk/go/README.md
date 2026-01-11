# ATB SDK - Go

Go SDK for interacting with the Agent Trust Broker.

## Installation

```bash
go get github.com/your-org/atb/sdk/go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/your-org/atb/sdk/go/atb"
)

func main() {
    // Initialize client
    client, err := atb.NewClient(
        atb.WithBrokerURL("https://broker.atb.example.com"),
        atb.WithAgentAuthURL("https://agentauth.atb.example.com"),
        atb.WithTLSFiles("client.crt", "client.key", "ca.crt"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Request authorization for an action
    ctx := context.Background()
    response, err := client.Authorize(ctx, &atb.Action{
        Verb:     "execute",
        Resource: "deployment/production",
        Parameters: map[string]any{
            "replicas": 3,
        },
    }, "Scale production deployment for traffic spike")

    if err != nil {
        log.Fatal(err)
    }

    if response.Allowed {
        fmt.Printf("Action authorized: %s\n", response.DecisionID)
        // Proceed with the action
    } else {
        fmt.Printf("Action denied: %s\n", response.Reason)
    }
}
```

## Features

- **mTLS Authentication**: Secure communication with SPIFFE/SPIRE identity
- **Risk-Tiered Authorization**: Automatic handling of LOW/MEDIUM/HIGH risk actions
- **Human-in-the-Loop**: Built-in support for approval workflows
- **Context Support**: Full context.Context integration
- **Connection Pooling**: Efficient HTTP/2 connection reuse
- **Metrics**: Prometheus-compatible metrics

## API Reference

### Client

```go
// NewClient creates a new ATB client with the given options.
func NewClient(opts ...Option) (*Client, error)

// Options
func WithBrokerURL(url string) Option
func WithAgentAuthURL(url string) Option
func WithTLSFiles(certFile, keyFile, caFile string) Option
func WithTLSConfig(config *tls.Config) Option
func WithTimeout(timeout time.Duration) Option
func WithRetryConfig(config RetryConfig) Option
func FromEnv() Option
```

### Authorization

```go
// Authorize requests authorization for an action.
func (c *Client) Authorize(
    ctx context.Context,
    action *Action,
    reason string,
    opts ...AuthorizeOption,
) (*AuthorizationResponse, error)

// Options
func WithApprovals(approvals ...*Approval) AuthorizeOption
func WithRequestID(id string) AuthorizeOption
```

### Types

```go
// Action represents an action to be authorized.
type Action struct {
    Verb       string         `json:"verb"`
    Resource   string         `json:"resource"`
    Parameters map[string]any `json:"parameters,omitempty"`
    Context    map[string]any `json:"context,omitempty"`
}

// RiskTier represents the risk level of an action.
type RiskTier string

const (
    RiskTierLow    RiskTier = "LOW"
    RiskTierMedium RiskTier = "MEDIUM"
    RiskTierHigh   RiskTier = "HIGH"
)

// AuthorizationResponse contains the result of an authorization request.
type AuthorizationResponse struct {
    Allowed          bool      `json:"allowed"`
    DecisionID       string    `json:"decision_id"`
    RiskTier         RiskTier  `json:"risk_tier"`
    Reason           string    `json:"reason"`
    ExpiresAt        time.Time `json:"expires_at"`
    AuditURL         string    `json:"audit_url"`
    RequiresApproval bool      `json:"requires_approval"`
    ApprovalRequest  *ApprovalRequest `json:"approval_request,omitempty"`
}
```

## Examples

### Basic Authorization

```go
ctx := context.Background()

// LOW risk action - auto-approved
response, err := client.Authorize(ctx, &atb.Action{
    Verb:     "read",
    Resource: "logs/application",
}, "Retrieve application logs for debugging")

if err != nil {
    log.Fatal(err)
}

if response.Allowed {
    // Proceed with reading logs
}
```

### Human-in-the-Loop for MEDIUM Risk

```go
ctx := context.Background()

// First attempt - will require approval
response, err := client.Authorize(ctx, &atb.Action{
    Verb:     "modify",
    Resource: "config/feature-flags",
}, "Enable new feature flag for A/B test")

if err != nil {
    log.Fatal(err)
}

if !response.Allowed && response.RequiresApproval {
    // Get human approval (via your approval system)
    approval := getHumanApproval(response.ApprovalRequest)
    
    // Retry with approval
    response, err = client.Authorize(ctx, &atb.Action{
        Verb:     "modify",
        Resource: "config/feature-flags",
    }, "Enable new feature flag for A/B test",
        atb.WithApprovals(approval),
    )
}
```

### With Context Timeout

```go
// Set per-request timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

response, err := client.Authorize(ctx, action, reason)
if errors.Is(err, context.DeadlineExceeded) {
    log.Println("Authorization timed out")
}
```

### Concurrent Requests

```go
var wg sync.WaitGroup
actions := []atb.Action{
    {Verb: "read", Resource: "metrics/cpu"},
    {Verb: "read", Resource: "metrics/memory"},
    {Verb: "read", Resource: "metrics/disk"},
}

results := make([]*atb.AuthorizationResponse, len(actions))
errors := make([]error, len(actions))

for i, action := range actions {
    wg.Add(1)
    go func(i int, action atb.Action) {
        defer wg.Done()
        results[i], errors[i] = client.Authorize(ctx, &action, "Collect metrics")
    }(i, action)
}

wg.Wait()
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ATB_BROKER_URL` | Broker service URL | - |
| `ATB_AGENTAUTH_URL` | AgentAuth service URL | - |
| `ATB_CERT_FILE` | Path to client certificate | - |
| `ATB_KEY_FILE` | Path to client private key | - |
| `ATB_CA_FILE` | Path to CA certificate | - |
| `ATB_TIMEOUT` | Request timeout | `30s` |
| `ATB_RETRY_MAX` | Maximum retries | `3` |

### Using Environment Variables

```go
client, err := atb.NewClient(atb.FromEnv())
```

## Error Handling

```go
import "github.com/your-org/atb/sdk/go/atb"

response, err := client.Authorize(ctx, action, reason)
if err != nil {
    var authErr *atb.AuthorizationDeniedError
    var tokenErr *atb.TokenExpiredError
    
    switch {
    case errors.As(err, &authErr):
        log.Printf("Access denied: %s (tier: %s)", authErr.Reason, authErr.RiskTier)
    case errors.As(err, &tokenErr):
        log.Printf("Token expired at %s", tokenErr.ExpiredAt)
        // Refresh token and retry
    default:
        log.Printf("ATB error: %v", err)
    }
}
```

## Metrics

The SDK exports Prometheus metrics:

```go
import "github.com/prometheus/client_golang/prometheus/promhttp"

// Register ATB metrics
atb.RegisterMetrics(prometheus.DefaultRegisterer)

// Expose metrics endpoint
http.Handle("/metrics", promhttp.Handler())
```

Available metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `atb_requests_total` | Counter | Total authorization requests |
| `atb_request_duration_seconds` | Histogram | Request latency |
| `atb_errors_total` | Counter | Total errors by type |

## License

Apache 2.0
