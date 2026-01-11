# Load Testing

This directory contains load testing scripts for the ATB services.

## Tools

We use [k6](https://k6.io/) for load testing - it's modern, scriptable, and produces excellent metrics.

### Installation

```bash
# macOS
brew install k6

# Docker
docker run --rm -i grafana/k6 run - <script.js
```

## Test Scenarios

### 1. Broker Authorization Load Test

Tests the main authorization endpoint under load.

```bash
# Run basic load test
k6 run broker_load.js

# Run with custom settings
k6 run --vus 50 --duration 5m broker_load.js

# Run with environment variables
k6 run -e BROKER_URL=http://localhost:8080 broker_load.js
```

### 2. Stress Test

Tests system behavior under extreme load.

```bash
k6 run --config stress.json broker_load.js
```

### 3. Soak Test

Tests system stability over extended periods.

```bash
k6 run --config soak.json broker_load.js
```

## Metrics

Key metrics to monitor:

| Metric | Target | Description |
|--------|--------|-------------|
| `http_req_duration` | p95 < 100ms | Request latency |
| `http_req_failed` | < 1% | Error rate |
| `http_reqs` | > 1000/s | Throughput |
| `iterations` | - | Completed test iterations |

## Output

### Console Output

```bash
k6 run broker_load.js
```

### JSON Output

```bash
k6 run --out json=results.json broker_load.js
```

### InfluxDB + Grafana

```bash
k6 run --out influxdb=http://localhost:8086/k6 broker_load.js
```

## Configuration Files

- `broker_load.js` - Main load test script
- `stress.json` - Stress test configuration
- `soak.json` - Soak test configuration

## CI Integration

Load tests run automatically on:
- Release candidates
- Manual trigger via workflow dispatch

See `.github/workflows/load-test.yaml` for CI configuration.
