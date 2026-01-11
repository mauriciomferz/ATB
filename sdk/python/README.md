# ATB SDK - Python

Python SDK for interacting with the Agent Trust Broker.

## Installation

```bash
pip install atb-sdk
```

Or install from source:

```bash
pip install -e ./atb-sdk-python
```

## Quick Start

```python
from atb import ATBClient, Action, RiskTier

# Initialize client
client = ATBClient(
    broker_url="https://broker.atb.example.com",
    agentauth_url="https://agentauth.atb.example.com",
    cert_file="client.crt",
    key_file="client.key",
    ca_file="ca.crt",
)

# Request authorization for an action
response = client.authorize(
    action=Action(
        verb="execute",
        resource="deployment/production",
        parameters={"replicas": 3},
    ),
    reason="Scale production deployment for traffic spike",
)

if response.allowed:
    print(f"Action authorized: {response.decision_id}")
    # Proceed with the action
else:
    print(f"Action denied: {response.reason}")
```

## Features

- **mTLS Authentication**: Secure communication with SPIFFE/SPIRE identity
- **Risk-Tiered Authorization**: Automatic handling of LOW/MEDIUM/HIGH risk actions
- **Human-in-the-Loop**: Built-in support for approval workflows
- **Audit Logging**: All actions are logged for compliance
- **Async Support**: Full async/await support for concurrent operations

## API Reference

### ATBClient

The main client class for interacting with ATB services.

```python
class ATBClient:
    def __init__(
        self,
        broker_url: str,
        agentauth_url: str,
        cert_file: str,
        key_file: str,
        ca_file: str,
        timeout: float = 30.0,
    ):
        """Initialize ATB client with mTLS credentials."""
        
    def authorize(
        self,
        action: Action,
        reason: str,
        approvals: list[Approval] | None = None,
    ) -> AuthorizationResponse:
        """Request authorization for an action."""
        
    async def authorize_async(
        self,
        action: Action,
        reason: str,
        approvals: list[Approval] | None = None,
    ) -> AuthorizationResponse:
        """Async version of authorize."""
        
    def get_token(
        self,
        action: Action,
        reason: str,
    ) -> PoAToken:
        """Get a PoA token for the specified action."""
```

### Action

Represents an action to be authorized.

```python
@dataclass
class Action:
    verb: str           # e.g., "read", "write", "execute", "delete"
    resource: str       # e.g., "deployment/production"
    parameters: dict    # Optional action parameters
    context: dict       # Optional context (injected by ATB)
```

### RiskTier

Enumeration of risk levels.

```python
class RiskTier(Enum):
    LOW = "LOW"         # Auto-approve with audit
    MEDIUM = "MEDIUM"   # Requires human approval
    HIGH = "HIGH"       # Requires multi-party approval
```

### AuthorizationResponse

Response from authorization request.

```python
@dataclass
class AuthorizationResponse:
    allowed: bool
    decision_id: str
    risk_tier: RiskTier
    reason: str
    expires_at: datetime
    audit_url: str
```

## Examples

### Basic Authorization

```python
from atb import ATBClient, Action

client = ATBClient(...)

# LOW risk action - auto-approved
response = client.authorize(
    action=Action(verb="read", resource="logs/application"),
    reason="Retrieve application logs for debugging",
)
# response.allowed = True (if policy allows)
```

### Human-in-the-Loop for MEDIUM Risk

```python
from atb import ATBClient, Action, Approval

client = ATBClient(...)

# First attempt - will require approval
response = client.authorize(
    action=Action(verb="modify", resource="config/feature-flags"),
    reason="Enable new feature flag for A/B test",
)

if not response.allowed and response.requires_approval:
    # Get human approval (via your approval system)
    approval = get_human_approval(response.approval_request)
    
    # Retry with approval
    response = client.authorize(
        action=Action(verb="modify", resource="config/feature-flags"),
        reason="Enable new feature flag for A/B test",
        approvals=[approval],
    )
```

### Async Operations

```python
import asyncio
from atb import ATBClient, Action

async def main():
    client = ATBClient(...)
    
    # Authorize multiple actions concurrently
    actions = [
        Action(verb="read", resource="metrics/cpu"),
        Action(verb="read", resource="metrics/memory"),
        Action(verb="read", resource="metrics/disk"),
    ]
    
    responses = await asyncio.gather(*[
        client.authorize_async(action, reason="Collect system metrics")
        for action in actions
    ])
    
    for action, response in zip(actions, responses):
        print(f"{action.resource}: {'✓' if response.allowed else '✗'}")

asyncio.run(main())
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
| `ATB_TIMEOUT` | Request timeout in seconds | `30` |
| `ATB_RETRY_COUNT` | Number of retries | `3` |
| `ATB_LOG_LEVEL` | Logging level | `INFO` |

### Using Environment Variables

```python
from atb import ATBClient

# Client will use environment variables
client = ATBClient.from_env()
```

## Error Handling

```python
from atb import ATBClient, ATBError, AuthorizationDenied, TokenExpired

try:
    response = client.authorize(action, reason)
except AuthorizationDenied as e:
    print(f"Access denied: {e.reason}")
    print(f"Risk tier: {e.risk_tier}")
except TokenExpired as e:
    print(f"Token expired at {e.expired_at}")
    # Refresh token and retry
except ATBError as e:
    print(f"ATB error: {e}")
```

## License

Apache 2.0
