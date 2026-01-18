# ATB Lambda Authorizer

This example provides an AWS Lambda authorizer that integrates with ATB (Agent Trust Broker)
to authorize API Gateway requests from AI agents.

## Overview

The Lambda authorizer acts as a bridge between AWS API Gateway and ATB, enabling
enterprise governance for AI agents accessing AWS-hosted APIs.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    AWS API Gateway with ATB Authorizer                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────┐    ┌───────────┐    ┌─────────────┐    ┌──────────────┐   │
│   │   AI    │───▶│    API    │───▶│   Lambda    │───▶│     ATB      │   │
│   │  Agent  │    │  Gateway  │    │ Authorizer  │    │   Broker     │   │
│   └─────────┘    └─────┬─────┘    └─────────────┘    └──────────────┘   │
│                        │                                                │
│                        │ if allowed                                     │
│                        ▼                                                │
│                  ┌───────────┐                                          │
│                  │  Backend  │                                          │
│                  │  Lambda   │                                          │
│                  └───────────┘                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Features

- **PoA Token Validation**: Validates Proof of Authorization tokens via ATB
- **Action Mapping**: Maps API Gateway routes to ATB actions
- **Decision Caching**: Caches authorization decisions for performance
- **Audit Logging**: Logs all authorization decisions for compliance
- **Error Handling**: Graceful handling of ATB unavailability

## Prerequisites

- AWS Account with appropriate permissions
- AWS SAM CLI installed
- ATB Broker deployed and accessible from AWS

## Deployment

### Using SAM CLI

```bash
# Build the Lambda function
sam build

# Deploy (first time - creates necessary resources)
sam deploy --guided

# Deploy (subsequent - uses saved configuration)
sam deploy
```

### Using CloudFormation

```bash
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name atb-lambda-authorizer \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    ATBBrokerURL=https://your-atb-broker.example.com \
    CacheTTLSeconds=60 \
    LogLevel=INFO
```

## Configuration

### Environment Variables

| Variable            | Description               | Default                          |
| ------------------- | ------------------------- | -------------------------------- |
| `ATB_BROKER_URL`    | URL of the ATB Broker     | `https://atb-broker.example.com` |
| `CACHE_TTL_SECONDS` | TTL for caching decisions | `60`                             |
| `LOG_LEVEL`         | Logging level             | `INFO`                           |

### Stack Parameters

| Parameter         | Description                    |
| ----------------- | ------------------------------ |
| `ATBBrokerURL`    | URL of the ATB Broker          |
| `CacheTTLSeconds` | Cache TTL (0-3600 seconds)     |
| `LogLevel`        | DEBUG, INFO, WARNING, or ERROR |

## Usage

### Making Authorized Requests

Include the PoA token in the Authorization header:

```bash
curl -X GET https://your-api.execute-api.region.amazonaws.com/prod/protected \
  -H "Authorization: Bearer <your-poa-token>"
```

### Python Client Example

```python
import requests

poa_token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."

response = requests.get(
    "https://your-api.execute-api.region.amazonaws.com/prod/protected",
    headers={"Authorization": f"Bearer {poa_token}"}
)

if response.status_code == 200:
    print("Authorized:", response.json())
elif response.status_code == 403:
    print("Denied by ATB")
```

## Action Mapping

The authorizer maps API Gateway requests to ATB actions:

| HTTP Method | Path                | ATB Action    |
| ----------- | ------------------- | ------------- |
| GET         | /api/v1/agents      | agents.read   |
| POST        | /api/v1/agents      | agents.create |
| DELETE      | /api/v1/agents/{id} | agents.delete |
| PUT         | /api/v1/config      | config.update |
| GET         | /api/v1/status      | status.read   |

### Custom Action Mapping

To customize action mapping, modify the `extract_action` function:

```python
def extract_action(event: dict) -> str:
    # Custom mapping logic
    method = event.get("httpMethod", "GET")
    path = event.get("path", "/")

    # Your custom mapping
    if path.startswith("/admin"):
        return "admin.access"

    # Default mapping
    return f"api.{method.lower()}"
```

## Authorization Response

The authorizer returns context data accessible in the backend:

```python
# In your backend Lambda
def handler(event, context):
    authorizer = event["requestContext"]["authorizer"]

    agent_id = authorizer.get("agent_id")
    risk_tier = authorizer.get("atb_risk_tier")
    request_id = authorizer.get("atb_request_id")

    # Use for audit logging, rate limiting, etc.
```

## Caching

The authorizer caches decisions to reduce ATB calls:

- **Cache Key**: Hash of token + action
- **Default TTL**: 60 seconds
- **Max Entries**: 1000 (with automatic cleanup)

To disable caching, set `CACHE_TTL_SECONDS=0`.

## Monitoring

### CloudWatch Metrics

The Lambda function emits standard CloudWatch metrics:

- Invocations
- Duration
- Errors
- Throttles

### X-Ray Tracing

X-Ray tracing is enabled by default for request tracing.

### Log Analysis

Search CloudWatch Logs for audit events:

```
fields @timestamp, @message
| filter @message like /AUDIT/
| parse @message '"allowed": *,' as allowed
| stats count() by allowed
```

## Security Considerations

1. **Token Security**: Tokens are hashed before caching
2. **VPC Deployment**: Consider deploying in VPC for ATB access
3. **Secrets**: Use Secrets Manager for sensitive configuration
4. **IAM**: Function has minimal permissions

### VPC Configuration

For ATB Broker in private network:

```yaml
ATBAuthorizerFunction:
  Type: AWS::Serverless::Function
  Properties:
    VpcConfig:
      SecurityGroupIds:
        - !Ref LambdaSecurityGroup
      SubnetIds:
        - !Ref PrivateSubnet1
        - !Ref PrivateSubnet2
```

## Testing

### Local Testing

```bash
# Run the handler locally
python handler.py
```

### SAM Local Testing

```bash
# Invoke with test event
sam local invoke ATBAuthorizerFunction \
  --event events/test-event.json
```

### Test Event Example

```json
{
  "type": "TOKEN",
  "authorizationToken": "Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "methodArn": "arn:aws:execute-api:us-east-1:123456789:api/prod/GET/protected"
}
```

## Troubleshooting

### "Unauthorized" Response

- Verify PoA token is valid and not expired
- Check token is in correct format (Bearer <token>)
- Verify ATB Broker is accessible

### "ATB unavailable" Error

- Check network connectivity to ATB Broker
- Verify ATB_BROKER_URL is correct
- Check VPC configuration if applicable

### Cache Issues

- Check CACHE_TTL_SECONDS is set correctly
- For testing, set TTL to 0 to disable caching
- Monitor Lambda memory for cache size

## Architecture Decisions

### Why Lambda Authorizer?

- **Centralized**: Single authorization point for all API routes
- **Cached**: API Gateway caches results, reducing latency
- **Decoupled**: Backend services don't need ATB integration
- **Standard**: Works with any API Gateway-compatible backend

### Why Not Built-in JWT Authorizer?

ATB PoA tokens require:

- Policy evaluation (not just signature validation)
- Risk tier calculation
- Approval chain verification
- Revocation checking

These require the full ATB Broker, not just JWKS validation.
