# ATB API Documentation

This directory contains API documentation for the Autonomy Trust Broker (ATB).

## OpenAPI Specification

The main API specification is available in OpenAPI 3.0 format:
- [openapi.yaml](./openapi.yaml)

## Viewing the Documentation

### Swagger UI

You can view the API documentation interactively using Swagger UI:

```bash
# Using Docker
docker run -p 8081:8080 \
  -e SWAGGER_JSON=/spec/openapi.yaml \
  -v $(pwd)/docs/api:/spec \
  swaggerapi/swagger-ui

# Then open http://localhost:8081
```

### Redoc

Alternatively, use Redoc for a cleaner documentation view:

```bash
# Using Docker
docker run -p 8082:80 \
  -e SPEC_URL=/spec/openapi.yaml \
  -v $(pwd)/docs/api:/usr/share/nginx/html/spec \
  redocly/redoc

# Then open http://localhost:8082
```

### VS Code

Install the OpenAPI (Swagger) Editor extension to view and edit the specification with preview.

## Quick Reference

### Base URLs

| Environment | URL |
|-------------|-----|
| Production | `https://atb.example.com/api/v1` |
| Staging | `https://atb-staging.example.com/api/v1` |
| Development | `http://localhost:8080/api/v1` |

### Authentication

All API requests require a Power of Attorney (PoA) token in the Authorization header:

```
Authorization: Bearer <poa_token>
```

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/execute` | Execute an action |
| POST | `/policy/check` | Check if action is allowed |
| POST | `/policy/batch-check` | Check multiple actions |
| GET | `/audit` | Get audit logs |
| GET | `/audit/{id}` | Get specific audit entry |
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |

## SDK Integration

The SDKs provide typed wrappers around these APIs:

### Python

```python
from atb import Client

async with Client.from_config() as client:
    result = await client.execute(poa, private_key)
```

### Go

```go
client, _ := atb.NewClient(atb.DefaultConfig())
result, _ := client.Execute(ctx, poa, privateKey)
```

### TypeScript

```typescript
const client = new ATBClient(config);
const result = await client.execute(poa, privateKey);
```

## Error Codes

| Code | Description |
|------|-------------|
| `INVALID_POA` | PoA token is invalid or expired |
| `POLICY_DENIED` | Action denied by OPA policy |
| `CONNECTOR_ERROR` | Backend connector failed |
| `RATE_LIMITED` | Too many requests |
| `INTERNAL_ERROR` | Internal server error |

## Rate Limiting

The API implements rate limiting per agent:
- 100 requests per minute for LOW risk actions
- 20 requests per minute for MEDIUM risk actions
- 5 requests per minute for HIGH risk actions

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704067200
```

## Changelog

### v1.0.0 (2024-01-01)
- Initial release
- Execute, policy check, and audit endpoints
- OpenAPI 3.0 specification
