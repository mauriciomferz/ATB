# ATB Development Quick Start

## 🚀 Services Currently Running

```
✅ OPA Policy Server    → http://localhost:8181
✅ Upstream Echo Server → http://localhost:9001
✅ ATB Broker (Health)  → http://localhost:8080
✅ ATB Broker (API)     → https://localhost:8443
✅ Frontend Dashboard   → http://localhost:3003
```

## 📝 Quick Commands

### Check Service Status

```bash
# All services
curl -s http://localhost:8181/health && echo "✅ OPA" || echo "❌ OPA"
curl -s http://localhost:9001 >/dev/null && echo "✅ Upstream" || echo "❌ Upstream"
curl -s http://localhost:8080/health && echo "✅ Broker" || echo "❌ Broker"
curl -s http://localhost:3003 >/dev/null && echo "✅ Frontend" || echo "❌ Frontend"
```

### Test OPA Policy

```bash
# Test without PoA (should deny)
curl -X POST http://localhost:8181/v1/data/atb/poa/decision \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"spiffe_id":"spiffe://example.org/agent"},"request":{"action":"test"}}}' \
  | python3 -m json.tool

# Test with valid PoA (should allow)
curl -X POST http://localhost:8181/v1/data/atb/poa/decision \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"spiffe_id":"spiffe://example.org/agent"},"poa":{"sub":"spiffe://example.org/agent","act":"sap.vendor.read","con":{},"leg":{"jurisdiction":"US-CA","accountable_party":{"type":"human","id":"user@example.com"}},"iat":1700000000,"exp":1700000200,"jti":"test-123"},"request":{"action":"sap.vendor.read"}}}' \
  | python3 -m json.tool
```

### Test Broker

```bash
# Health check
curl http://localhost:8080/health

# Ready check
curl http://localhost:8080/ready

# Metrics (if enabled)
curl http://localhost:8080/metrics
```

### View Logs

```bash
# Broker logs
tail -f /tmp/broker.log

# OPA logs (if redirected)
# Check the terminal where OPA is running
```

## 🔧 Development Workflow

### 1. Modify OPA Policies

```bash
# Edit policy file
code opa/policy/poa.rego

# OPA will auto-reload (no restart needed)
```

### 2. Test Policy Changes

```bash
# Run OPA tests
make test-opa

# Or directly
opa test opa/policy/ -v
```

### 3. Modify Broker Code

```bash
# Edit Go code
code atb-gateway-go/

# Rebuild
cd atb-gateway-go && go build -o bin/broker ./cmd/broker

# Restart broker
pkill broker
nohup sh -c 'cd atb-gateway-go && UPSTREAM_URL=http://localhost:9001 POA_VERIFY_PUBKEY_PEM="$(cat ../dev/poa_rsa.pub)" TLS_CERT_FILE=../dev/certs/server.crt TLS_KEY_FILE=../dev/certs/server.key HTTP_LISTEN_ADDR=:8080 OPA_DECISION_URL=http://localhost:8181/v1/data/atb/poa/decision ./bin/broker' > /tmp/broker.log 2>&1 &
```

### 4. Modify Frontend

```bash
# Frontend auto-reloads via Vite HMR
code dashboard/src/

# Check frontend terminal for any errors
```

## 🐛 Troubleshooting

### Service Won't Start

```bash
# Check if port is in use
lsof -ti:8181  # OPA
lsof -ti:9001  # Upstream
lsof -ti:8080  # Broker health
lsof -ti:8443  # Broker API
lsof -ti:3003  # Frontend

# Kill process on port
lsof -ti:PORT | xargs kill -9
```

### OPA Policy Errors

```bash
# Validate policy syntax
opa fmt -w opa/policy/

# Check for errors
opa check opa/policy/
```

### Broker Not Responding

```bash
# Check broker logs
tail -20 /tmp/broker.log

# Check process
ps aux | grep broker

# Restart broker
bash /tmp/restart-broker.sh  # If you create this script
```

## 📚 Key Files

- **OPA Policy**: `opa/policy/poa.rego`
- **Broker Code**: `atb-gateway-go/cmd/broker/`
- **Frontend**: `dashboard/src/`
- **API Spec**: `docs/openapi.yaml`
- **Examples**: `examples/`

## 🔗 Useful Endpoints

### OPA

- Health: `http://localhost:8181/health`
- Policy Query: `POST http://localhost:8181/v1/data/atb/poa/decision`
- Metrics: `http://localhost:8181/metrics`

### ATB Broker

- Health: `http://localhost:8080/health`
- Ready: `http://localhost:8080/ready`
- Metrics: `http://localhost:8080/metrics`
- API: `https://localhost:8443/v1/*`

### Frontend

- Dashboard: `http://localhost:3003`

## 🎯 Next Steps

1. **Explore the API**: Check `docs/api-reference.md`
2. **Review Examples**: See `examples/client_python.py` and `examples/client_go.go`
3. **Add New Actions**: Edit enterprise actions in `opa/policy/poa.rego`
4. **Create Tests**: Add integration tests in `tests/`
5. **Deploy**: See `docs/production-deployment.md`

## ⚡ Pro Tips

- Use `make test` to run all tests
- Use `make lint` to check code quality
- Frontend HMR is enabled - changes reflect immediately
- OPA auto-reloads policies - no restart needed
- Check `Makefile` for all available commands

---

**Happy Hacking! 🚀**
