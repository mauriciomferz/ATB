# Troubleshooting Guide

This guide helps resolve common issues when developing with ATB.

## Development Environment

### Python Virtual Environment Issues

**Problem**: `ModuleNotFoundError: No module named 'jwt'`

```bash
# Activate the virtual environment
source .venv/bin/activate

# Reinstall dependencies
pip install -r atb-gateway-py/requirements.txt
pip install pyjwt cryptography
```

**Problem**: Wrong Python version

```bash
# Check Python version (need 3.9+)
python3 --version

# Create new venv with specific Python
python3.11 -m venv .venv
```

### Go Build Issues

**Problem**: `go: cannot find main module`

```bash
# Make sure you're in the right directory
cd atb-gateway-go
go build ./cmd/broker
```

**Problem**: Missing dependencies

```bash
cd atb-gateway-go
go mod download
go mod tidy
```

### Certificate Issues

**Problem**: `x509: certificate signed by unknown authority`

```bash
# Regenerate certificates
rm -rf dev/certs/*.crt dev/certs/*.key
make certs
```

**Problem**: SPIFFE SAN not in certificate

```bash
# Check certificate
openssl x509 -in dev/certs/client.crt -text -noout | grep -A1 "Subject Alternative Name"

# Should show: URI:spiffe://example.org/ns/default/sa/agent/connector
```

## OPA Policy

### Policy Test Failures

**Problem**: `undefined decision`

```bash
# Check policy syntax
opa check opa/policy/

# Run tests with verbose output
opa test opa/policy/ -v --v0-compatible
```

**Problem**: `rego_parse_error`

```bash
# Format the policy files
opa fmt -w opa/policy/*.rego

# Check for syntax errors
opa check opa/policy/
```

### Policy Not Loading

**Problem**: OPA returns empty decision

```bash
# Verify policy is loaded
curl http://localhost:8181/v1/policies

# Reload policy
curl -X PUT http://localhost:8181/v1/policies/poa \
  --data-binary @opa/policy/poa.rego
```

## Docker Compose

### Container Won't Start

**Problem**: Port already in use

```bash
# Find what's using the port
lsof -i :8181  # OPA
lsof -i :8443  # Broker
lsof -i :9000  # Upstream

# Kill the process or use different ports
docker compose down
OPA_PORT=8182 docker compose up -d
```

**Problem**: Docker daemon not running

```bash
# macOS
open -a Docker

# Linux
sudo systemctl start docker
```

### Volume Mount Issues

**Problem**: Permission denied on mounted files

```bash
# Check file permissions
ls -la dev/certs/

# Fix permissions
chmod 644 dev/certs/*.crt
chmod 600 dev/certs/*.key
```

## Broker Issues

### mTLS Handshake Failures

**Problem**: `tls: bad certificate`

```bash
# Verify client cert matches CA
openssl verify -CAfile dev/certs/ca.crt dev/certs/client.crt

# Check cert expiration
openssl x509 -in dev/certs/client.crt -noout -dates
```

**Problem**: `tls: unknown certificate authority`

```bash
# Make sure you're using the right CA
curl -k --cacert dev/certs/ca.crt \
     --cert dev/certs/client.crt \
     --key dev/certs/client.key \
     https://localhost:8443/health
```

### PoA Token Validation Failures

**Problem**: `invalid signature`

```bash
# Verify token was signed with correct key
# The public key must match POA_VERIFY_PUBKEY_PEM env var

# Re-mint token with correct key
.venv/bin/python dev/mint_poa.py \
    --priv dev/poa_rsa.key \
    --sub spiffe://example.org/ns/default/sa/agent/connector \
    --act system.status.read
```

**Problem**: `token expired`

```bash
# Tokens are short-lived (5 minutes by default)
# Mint a fresh token before each request
```

### OPA Decision Errors

**Problem**: `failed to query OPA`

```bash
# Check OPA is running
curl http://localhost:8181/health

# Check decision endpoint
curl -X POST http://localhost:8181/v1/data/atb/poa/decision \
  -H "Content-Type: application/json" \
  -d '{"input": {"method": "GET", "path": "/health"}}'
```

## CI/CD Issues

### GitHub Actions Failures

**Problem**: OPA tests fail in CI but pass locally

```bash
# Check OPA version matches
opa version

# Run tests with same flags as CI
opa test opa/policy/ -v --v0-compatible
```

**Problem**: Go tests fail with race conditions

```bash
# Run with race detector locally
cd atb-gateway-go
go test -race -v ./...
```

### Pre-commit Hook Failures

**Problem**: Hooks not running

```bash
# Reinstall hooks
pre-commit install --install-hooks

# Run manually
pre-commit run --all-files
```

**Problem**: gitleaks blocking commit

```bash
# Check for false positive
gitleaks detect --source . -v

# If it's a false positive, add to .gitleaksignore
echo "path/to/file:line" >> .gitleaksignore
```

## Performance Issues

### Slow OPA Decisions

**Problem**: Policy evaluation taking too long

```bash
# Profile the policy
opa eval -d opa/policy/ \
  --profile \
  --format=pretty \
  'data.atb.poa.decision' \
  --input input.json
```

### High Memory Usage

**Problem**: Broker using too much memory

```bash
# Check for goroutine leaks
curl http://localhost:6060/debug/pprof/goroutine?debug=1

# Profile memory
go tool pprof http://localhost:6060/debug/pprof/heap
```

## Getting Help

If you're still stuck:

1. **Check logs**: `docker compose logs -f` or broker stdout
2. **Enable debug logging**: Set `LOG_LEVEL=debug`
3. **Search issues**: Check GitHub Issues for similar problems
4. **Ask for help**: Create a new issue with:
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Go version, etc.)
   - Relevant logs
## Kubernetes Issues

### Pod Stuck in ImagePullBackOff

**Problem**: Images not available in cluster

```bash
# For kind clusters, load local images
docker build -f Dockerfile.broker -t atb-broker:local ./atb-gateway-go
kind load docker-image atb-broker:local --name <cluster-name>

# Then update Helm values
helm upgrade ... --set broker.image.repository=atb-broker --set broker.image.tag=local
```

### OPA ConfigMap Empty

**Problem**: `rego_parse_error: empty module`

This happens when Helm's `.Files.Get` can't find the policy file (path must be inside chart directory).

```bash
# Check if policy was rendered
kubectl get configmap -n <namespace> <release>-opa-policy -o yaml

# The policy file must be in charts/atb/files/poa.rego
# NOT in opa/policy/poa.rego (outside chart directory)
```

### SPIFFE CSI Driver Not Found

**Problem**: `driver name csi.spiffe.io not found in the list of registered CSI drivers`

If you don't have SPIRE CSI driver installed:

```bash
# Switch to TLS secret mode
helm upgrade ... \
  --set csi.enabled=false \
  --set broker.tls.mode=secret \
  --set broker.tls.secretName=atb-broker-tls

# Create TLS secret first
kubectl create secret tls atb-broker-tls \
  --cert=tls.crt --key=tls.key -n <namespace>
```

### OPA Unknown Flag Error

**Problem**: `unknown flag: --v0-compatible`

OPA version is too old (pre-1.0). The `--v0-compatible` flag was added in OPA 1.0.

```bash
# Update OPA image to latest
helm upgrade ... --set opa.image.tag=latest

# Or disable v0Compatible if using newer Rego syntax
helm upgrade ... --set opa.v0Compatible=false
```

### AgentAuth CrashLoopBackOff

**Problem**: Missing signing key secret

```bash
# Check pod logs
kubectl logs -n <namespace> -l app.kubernetes.io/component=agentauth

# Create signing key secret
./scripts/create-signing-key-secret.sh <namespace>

# Restart deployment
kubectl rollout restart deployment/<release>-agentauth -n <namespace>
```