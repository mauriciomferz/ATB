# Contributing to ATB

Thank you for your interest in contributing to the Agent Trust Broker!

## Code of Conduct

Please be respectful and professional in all interactions.

## Getting Started

### Prerequisites

- Go 1.21+
- Python 3.11+
- OPA CLI (`brew install opa` or from [openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/#running-opa))
- Docker (for container builds)
- kubectl + Helm 3 (for deployment)

### Development Setup

#### Quick Setup (Recommended)

```bash
# Clone the repository
git clone https://github.com/mauriciomferz/ATB.git
cd ATB

# Run the setup target (installs all dependencies)
make setup

# Generate local development certificates
make certs

# Run all tests
make test
```

#### Manual Setup

```bash
# Clone the repository
git clone https://github.com/mauriciomferz/ATB.git
cd ATB

# Install Go dependencies
cd atb-gateway-go && go mod download && cd ..

# Install Python dependencies
python3 -m venv .venv
.venv/bin/pip install -r atb-gateway-py/requirements.txt

# Run OPA tests
opa test opa/policy/ -v --v0-compatible

# Run Go tests
cd atb-gateway-go && go test -v -race ./... && cd ..
```

### Available Make Targets

| Command | Description |
|---------|-------------|
| `make setup` | Install all dependencies |
| `make test` | Run all tests (OPA + Go) |
| `make test-opa` | Run OPA policy tests only |
| `make test-go` | Run Go tests with race detection |
| `make lint` | Run linters (OPA + Go) |
| `make certs` | Generate local dev certificates |
| `make run-opa` | Start OPA server (localhost:8181) |
| `make run-broker` | Build and run the broker |
| `make build` | Build Go binaries |
| `make docker-build` | Build Docker images |
| `make clean` | Remove build artifacts |

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes

Follow the code style and conventions in existing files.

### 3. Write Tests

- **OPA Policy Changes**: Add tests to `opa/policy/*_test.rego`
- **Go Changes**: Add tests to `*_test.go` files
- **Python Changes**: Add tests to `test_*.py` files

### 4. Run All Tests Locally

```bash
# Using Makefile (recommended)
make test

# Or manually:
# OPA tests
opa test opa/policy/ -v --v0-compatible

# Go tests
cd atb-gateway-go && go test -v -race ./... && cd ..
```

### 5. Submit a Pull Request

- Use a clear, descriptive title
- Reference any related issues
- Ensure CI passes

## Areas for Contribution

### High Priority

| Area | Description |
|------|-------------|
| **Enterprise Actions** | Add new action definitions to OPA policy |
| **Connector Adapters** | New backend system integrations |
| **Audit Sink Drivers** | Additional immutable storage backends |
| **Platform Bindings** | Support for additional agent platforms |

### Good First Issues

- Documentation improvements
- Test coverage expansion
- Code cleanup and refactoring
- Example configurations

## OPA Policy Contribution Guide

### Adding New Enterprise Actions

1. Determine risk tier (low/medium/high)
2. Add to appropriate set in `opa/policy/poa.rego`:

```rego
# Low risk (read-only, no PII)
low_risk_allowlist contains "system.action.read"

# Medium risk (data mutations, limited scope)
medium_risk_actions contains "system.action.update"

# High risk (bulk data, PII, privileged, OT/SCADA)
high_risk_actions contains "system.action.bulkDelete"
```

3. If action needs specific constraints, add a validation rule:

```rego
validate_action_constraints["your.action.name"] := violations if {
    input.claim.act == "your.action.name"
    violations := array.concat(
        check_required_field("field_name", input.claim.con),
        []
    )
}
```

4. Add tests to appropriate `*_test.rego` file
5. Update `docs/enterprise-actions.md`

### Action Naming Convention

```
<system>.<domain>.<operation>
```

Examples:
- `salesforce.opportunity.update`
- `sap.vendor.create`
- `hr.pii.export`

### Risk Tier Guidelines

| Tier | Criteria |
|------|----------|
| **Low** | Read-only, no PII, no financial data, no privileged access |
| **Medium** | Data mutations, limited scope, non-bulk operations |
| **High** | Bulk data, PII, financial > $10k, privileged access, OT/SCADA |

## Go Code Contribution Guide

### Code Style

- Follow standard Go conventions (`gofmt`)
- Use meaningful variable names
- Add godoc comments for exported functions/types

### Error Handling

```go
// Prefer structured errors
if err != nil {
    return fmt.Errorf("failed to validate PoA: %w", err)
}
```

### Metrics

Use Prometheus counters/histograms for observability:

```go
requestsTotal.WithLabelValues("success").Inc()
latencyHistogram.WithLabelValues("action").Observe(duration.Seconds())
```

### Testing

- Use table-driven tests
- Test error cases
- Use `t.Parallel()` where appropriate
- Aim for >80% coverage

## Documentation Contribution

### File Locations

| Document | Purpose |
|----------|---------|
| `README.md` | Project overview and quickstart |
| `docs/k8s-quickstart.md` | Kubernetes deployment guide |
| `docs/operating-model.md` | Deployment and operations |
| `docs/enterprise-actions.md` | Action catalog reference |
| `docs/audit.md` | Audit event format and sinks |
| `docs/requirements-compliance.md` | Compliance matrix |
| `SECURITY.md` | Security policy and controls |
| `CONTRIBUTING.md` | Contribution guidelines |

### Style Guide

- Use clear, concise language
- Include code examples where helpful
- Use tables for structured information
- Link to related documents

## Pull Request Checklist

- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] No secrets or credentials committed
- [ ] Commit messages are descriptive
- [ ] Code follows existing style

## Review Process

1. **Automated Checks**: CI runs OPA tests, Go tests, security scans
2. **Code Review**: At least 1 maintainer approval required
3. **Security Review**: Required for:
   - OPA policy changes
   - Authentication/authorization logic
   - Cryptographic operations
   - External API integrations

## Release Process

Releases follow semantic versioning:

- **Major**: Breaking changes to APIs or policy format
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes, security patches

## Questions?

- Open a GitHub issue for bugs/features
- Check existing documentation
- Review closed issues for previous discussions

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
