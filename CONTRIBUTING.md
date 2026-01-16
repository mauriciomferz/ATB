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

# One-command setup (checks prerequisites, installs deps, runs tests)
make quickstart

# Or step-by-step:
make setup    # Install dependencies
make certs    # Generate dev certificates
make test     # Run all tests
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

| Command             | Description                                 |
| ------------------- | ------------------------------------------- |
| `make setup`        | Install all dependencies + pre-commit hooks |
| `make test`         | Run all tests (OPA + Go)                    |
| `make test-opa`     | Run OPA policy tests only                   |
| `make test-go`      | Run Go tests with race detection            |
| `make lint`         | Run linters (OPA + Go)                      |
| `make certs`        | Generate local dev certificates             |
| `make run-opa`      | Start OPA server (localhost:8181)           |
| `make run-broker`   | Build and run the broker                    |
| `make build`        | Build Go binaries                           |
| `make docker-build` | Build Docker images                         |
| `make clean`        | Remove build artifacts                      |

### Pre-commit Hooks

This project uses [pre-commit](https://pre-commit.com/) to run checks before each commit:

```bash
# Install pre-commit (if not already installed)
brew install pre-commit

# Install the hooks (done automatically by make setup)
pre-commit install

# Run hooks manually on all files
pre-commit run --all-files
```

The hooks check:

- Go formatting and tests
- OPA policy formatting and tests
- Secrets detection (gitleaks)
- Markdown linting
- Shell script linting
- Helm chart validation

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

| Area                   | Description                              |
| ---------------------- | ---------------------------------------- |
| **Enterprise Actions** | Add new action definitions to OPA policy |
| **Connector Adapters** | New backend system integrations          |
| **Audit Sink Drivers** | Additional immutable storage backends    |
| **Platform SDKs**      | Python connectors for AI platforms (see `sdk/python/atb/platforms/`) |
| **Policy Templates**   | Pre-built OPA policies for enterprise systems (see `opa/policy/templates/`) |
| **Dashboard Features** | React UI enhancements for approvals and monitoring |

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

| Tier       | Criteria                                                      |
| ---------- | ------------------------------------------------------------- |
| **Low**    | Read-only, no PII, no financial data, no privileged access    |
| **Medium** | Data mutations, limited scope, non-bulk operations            |
| **High**   | Bulk data, PII, financial > $10k, privileged access, OT/SCADA |

## Platform SDK Contribution Guide

### Adding a New Platform Connector

Platform connectors live in `sdk/python/atb/platforms/`. To add a new platform:

1. Create a new file `sdk/python/atb/platforms/your_platform.py`
2. Extend the `PlatformConnector` base class:

```python
from atb.platforms.base import PlatformConnector, PlatformIdentity, ActionResult

class YourPlatformConnector(PlatformConnector):
    async def authenticate(self) -> PlatformIdentity:
        # Implement platform authentication
        pass
    
    async def execute_action(self, action: str, parameters: dict) -> ActionResult:
        # Implement action execution with ATB authorization
        pass
    
    def get_spiffe_id(self, identity: PlatformIdentity) -> str:
        # Map platform identity to SPIFFE ID
        pass
```

3. Add to `sdk/python/atb/platforms/__init__.py`
4. Document in `sdk/python/README.md`

### Existing Platform Connectors

| Platform | File | Use Case |
|----------|------|----------|
| Microsoft Copilot | `copilot.py` | Entra ID, Graph API |
| Salesforce | `salesforce.py` | Agentforce, CRM |
| SAP | `sap.py` | Joule, S/4HANA |

## Policy Template Contribution Guide

### Adding New Policy Templates

Policy templates live in `opa/policy/templates/`. To add a new template:

1. Create `opa/policy/templates/your_platform.rego`:

```rego
package atb.templates.your_platform

import rego.v1

# Define risk classifications
your_high_risk_actions := {"your.action.critical"}
your_medium_risk_actions := {"your.action.update"}
your_low_risk_actions := {"your.action.read"}

# Export risk_tier
default risk_tier := "UNKNOWN"
risk_tier := "HIGH" if { input.act in your_high_risk_actions }
risk_tier := "MEDIUM" if { input.act in your_medium_risk_actions }
risk_tier := "LOW" if { input.act in your_low_risk_actions }

# Export deny rules
deny contains msg if {
    input.act in your_high_risk_actions
    not has_dual_control
    msg := "High risk action requires dual control"
}
```

2. Create test file `opa/policy/templates/your_platform_test.rego`
3. Run tests: `opa test opa/policy/templates/ -v --v0-compatible`
4. Document in `opa/policy/templates/README.md`

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

| Document                          | Purpose                         |
| --------------------------------- | ------------------------------- |
| `README.md`                       | Project overview and quickstart |
| `docs/architecture.md`            | System design and components    |
| `docs/getting-started.md`         | Quick start guide               |
| `docs/k8s-quickstart.md`          | Kubernetes deployment guide     |
| `docs/operating-model.md`         | Deployment and operations       |
| `docs/enterprise-actions.md`      | Action catalog reference        |
| `docs/audit.md`                   | Audit event format and sinks    |
| `docs/requirements-compliance.md` | Compliance matrix               |
| `sdk/python/README.md`            | Python SDK and platform connectors |
| `dashboard/README.md`             | Dashboard UI and approval workflows |
| `opa/policy/templates/README.md`  | Policy templates for SAP, Salesforce, OT |
| `spire/ot/README.md`              | OT/Industrial Edge deployment   |
| `SECURITY.md`                     | Security policy and controls    |
| `CONTRIBUTING.md`                 | Contribution guidelines         |

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
