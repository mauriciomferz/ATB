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
- **Platform Connectors**: Pre-built integrations for Microsoft Copilot, Salesforce, SAP

## Platform Connectors

The SDK includes pre-built connectors for enterprise AI platforms. Each connector handles platform-specific authentication, action mapping, and identity binding.

### Microsoft Copilot (Entra ID)

```python
from atb.platforms import CopilotConnector

# Initialize with Entra ID credentials
copilot = CopilotConnector(
    tenant_id="your-tenant-id",
    client_id="your-client-id",
    client_secret="your-client-secret"
)

# Authenticate and get platform identity
identity = await copilot.authenticate()
print(f"Authenticated as: {identity.platform_user_id}")
print(f"SPIFFE ID: {identity.spiffe_id}")

# Execute a Copilot action with ATB authorization
result = await copilot.execute_action(
    action="calendar:create",
    parameters={
        "title": "Team standup",
        "attendees": ["alice@contoso.com"],
        "start": "2024-01-15T09:00:00Z"
    }
)

if result.success:
    print(f"Action completed: {result.action_id}")
else:
    print(f"Action failed: {result.error}")
```

#### Supported Copilot Actions

| Action                 | Risk Tier | Description            |
| ---------------------- | --------- | ---------------------- |
| `calendar:read`        | LOW       | Read calendar events   |
| `calendar:create`      | MEDIUM    | Create calendar events |
| `mail:read`            | LOW       | Read emails            |
| `mail:send`            | MEDIUM    | Send emails            |
| `mail:delete`          | HIGH      | Delete emails          |
| `files:read`           | LOW       | Read files             |
| `files:write`          | MEDIUM    | Write files            |
| `files:delete`         | HIGH      | Delete files           |
| `teams:send_message`   | LOW       | Send Teams messages    |
| `teams:create_channel` | MEDIUM    | Create Teams channels  |

### Salesforce Agentforce

```python
from atb.platforms import SalesforceConnector

# Initialize with Salesforce OAuth credentials
salesforce = SalesforceConnector(
    instance_url="https://yourorg.salesforce.com",
    client_id="your-connected-app-client-id",
    client_secret="your-client-secret",
    username="integration@yourorg.com",
    password="password",
    security_token="security-token"
)

# Authenticate
identity = await salesforce.authenticate()

# Execute Salesforce action
result = await salesforce.execute_action(
    action="opportunity:update",
    parameters={
        "opportunity_id": "006xxx",
        "stage": "Closed Won",
        "amount": 50000
    }
)
```

#### Supported Salesforce Actions

| Action               | Risk Tier | Description          |
| -------------------- | --------- | -------------------- |
| `account:read`       | LOW       | Read account data    |
| `account:create`     | MEDIUM    | Create accounts      |
| `opportunity:read`   | LOW       | Read opportunities   |
| `opportunity:create` | MEDIUM    | Create opportunities |
| `opportunity:update` | MEDIUM    | Update opportunities |
| `lead:create`        | MEDIUM    | Create leads         |
| `case:create`        | LOW       | Create support cases |
| `report:export`      | HIGH      | Export reports (PII) |
| `user:create`        | HIGH      | Create users         |

### SAP Joule (S/4HANA)

```python
from atb.platforms import SAPConnector

# Initialize with SAP OAuth credentials
sap = SAPConnector(
    instance_url="https://your-sap.s4hana.cloud.sap",
    client_id="your-client-id",
    client_secret="your-client-secret",
    token_url="https://your-tenant.authentication.sap.hana.ondemand.com/oauth/token"
)

# Authenticate
identity = await sap.authenticate()

# Execute SAP action
result = await sap.execute_action(
    action="payment:execute",
    parameters={
        "vendor_id": "VENDOR001",
        "amount": 25000.00,
        "currency": "EUR",
        "payment_date": "2024-01-15"
    }
)
```

#### Supported SAP Actions

| Action                   | Risk Tier | Description                |
| ------------------------ | --------- | -------------------------- |
| `material:read`          | LOW       | Read material master       |
| `material:create`        | MEDIUM    | Create materials           |
| `purchase_order:read`    | LOW       | Read purchase orders       |
| `purchase_order:create`  | MEDIUM    | Create purchase orders     |
| `purchase_order:approve` | MEDIUM    | Approve purchase orders    |
| `vendor:read`            | LOW       | Read vendor data           |
| `vendor:create`          | MEDIUM    | Create vendors             |
| `vendor:bank_change`     | HIGH      | Change vendor bank details |
| `payment:execute`        | HIGH      | Execute payments           |
| `journal:post`           | HIGH      | Post journal entries       |

### Custom Platform Connector

You can create custom connectors by extending the base class:

```python
from atb.platforms.base import PlatformConnector, PlatformIdentity, ActionResult
from dataclasses import dataclass

class MyPlatformConnector(PlatformConnector):
    def __init__(self, api_url: str, api_key: str):
        self.api_url = api_url
        self.api_key = api_key

    async def authenticate(self) -> PlatformIdentity:
        # Implement platform authentication
        return PlatformIdentity(
            platform_id="my-platform",
            platform_user_id="user@example.com",
            spiffe_id="spiffe://example.com/agent/my-platform",
            roles=["user"],
            attributes={}
        )

    async def execute_action(
        self,
        action: str,
        parameters: dict
    ) -> ActionResult:
        # Implement action execution with ATB authorization
        return ActionResult(
            success=True,
            action_id="action-123",
            action=action,
            result={"status": "completed"}
        )

    def get_spiffe_id(self, identity: PlatformIdentity) -> str:
        return f"spiffe://example.com/agent/my-platform/{identity.platform_user_id}"
```

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

| Variable            | Description                | Default |
| ------------------- | -------------------------- | ------- |
| `ATB_BROKER_URL`    | Broker service URL         | -       |
| `ATB_AGENTAUTH_URL` | AgentAuth service URL      | -       |
| `ATB_CERT_FILE`     | Path to client certificate | -       |
| `ATB_KEY_FILE`      | Path to client private key | -       |
| `ATB_CA_FILE`       | Path to CA certificate     | -       |
| `ATB_TIMEOUT`       | Request timeout in seconds | `30`    |
| `ATB_RETRY_COUNT`   | Number of retries          | `3`     |
| `ATB_LOG_LEVEL`     | Logging level              | `INFO`  |

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
