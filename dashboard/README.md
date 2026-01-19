# ATB Dashboard

Real-time monitoring dashboard for the Agent Trust Broker.

![Dashboard Preview](./preview.png)

## Features

- **Real-time Metrics**: Live updates of request counts, latency, and error rates
- **Audit Log**: Searchable and filterable authorization event history
- **Policy Stats**: OPA policy evaluation metrics and success rates
- **Agent Monitoring**: Track registered agents and their activity
- **System Health**: Broker, OPA, and SPIRE component status
- **Approval Workflows**: Human-in-the-loop approval queue for high-risk actions

## Quick Start

```bash
# Install dependencies
cd dashboard
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## Development

The dashboard runs on http://localhost:3003 and proxies API requests to the ATB broker.

### Environment Variables

| Variable       | Description    | Default                 |
| -------------- | -------------- | ----------------------- |
| `VITE_API_URL` | ATB Broker URL | `http://localhost:8080` |

### Mock Mode

By default, the dashboard runs in mock mode with simulated data. To connect to a real ATB instance:

1. Edit `src/api.ts`
2. Set `MOCK_MODE = false`
3. Ensure ATB services are running

## Project Structure

```
dashboard/
├── src/
│   ├── main.tsx          # Entry point
│   ├── App.tsx           # Router and layout
│   ├── api.ts            # API client
│   ├── types.ts          # TypeScript types
│   ├── index.css         # Tailwind styles
│   └── pages/
│       ├── Dashboard.tsx # Overview with charts
│       ├── AuditLog.tsx  # Event history
│       ├── Policies.tsx  # Policy stats
│       ├── Agents.tsx    # Agent registry
│       └── Approvals.tsx # Approval workflow queue
├── package.json
├── vite.config.ts
├── tailwind.config.js
└── tsconfig.json
```

## Approval Workflows

The Approvals page (`/approvals`) provides a human-in-the-loop interface for reviewing high-risk actions:

### Features

- **Pending Queue**: Real-time list of actions awaiting approval (10s polling)
- **Risk Tier Indicators**: Visual warnings for HIGH risk requests
- **Request Details**: Full context including action, parameters, justification
- **Approve/Reject**: Immediate enforcement via ATB broker API

### Approval Flow

1. Agent requests a HIGH or MEDIUM risk action
2. ATB creates approval request and returns `pending` status
3. Request appears in the Approvals dashboard
4. Approver reviews and clicks Approve or Reject
5. ATB broker processes the decision
6. Agent receives final authorization result

### API Endpoints

| Endpoint                     | Method | Description                    |
| ---------------------------- | ------ | ------------------------------ |
| `/v1/approvals/pending`      | GET    | List pending approval requests |
| `/v1/approvals/{id}/approve` | POST   | Approve a request              |
| `/v1/approvals/{id}/reject`  | POST   | Reject a request               |

## Tech Stack

- **React 18** - UI framework
- **Vite** - Build tool
- **TanStack Query** - Data fetching and caching
- **Recharts** - Charts and visualizations
- **Tailwind CSS** - Styling
- **TypeScript** - Type safety

## API Endpoints

The dashboard expects these endpoints from the ATB broker:

| Endpoint                   | Description          |
| -------------------------- | -------------------- |
| `GET /v1/audit`            | Audit log entries    |
| `GET /v1/metrics/summary`  | Metrics summary      |
| `GET /v1/metrics/requests` | Time series data     |
| `GET /v1/health`           | System health status |
| `GET /v1/agents`           | Registered agents    |
| `GET /v1/policies/stats`   | Policy statistics    |

## Deployment

### Docker

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: atb-dashboard
spec:
  replicas: 2
  selector:
    matchLabels:
      app: atb-dashboard
  template:
    metadata:
      labels:
        app: atb-dashboard
    spec:
      containers:
        - name: dashboard
          image: atb-dashboard:latest
          ports:
            - containerPort: 80
```

## License

MIT License
