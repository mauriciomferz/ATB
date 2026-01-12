# ATB Load Tests

k6-based load tests for the Agent Trust Broker services.

## Prerequisites

Install k6:
```bash
# macOS
brew install k6

# Ubuntu/Debian
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

## Running Tests

### Basic smoke test
```bash
k6 run --duration 30s --vus 5 stress.js
```

### With custom broker URL
```bash
BROKER_URL=http://your-broker:8080 k6 run stress.js
```

### Generate HTML report
```bash
k6 run --out json=results.json stress.js
```

## Test Scenarios

- **healthCheck**: Tests `/health` endpoint
- **readyCheck**: Tests `/ready` endpoint
- **policyCheck**: Tests `/v1/policy/check` endpoint

## Thresholds

- 95th percentile response time < 500ms
- Error rate < 10%
