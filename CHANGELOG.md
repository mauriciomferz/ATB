# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **CRITICAL Risk Tier**: New highest risk tier requiring 2+ executive approvers for actions like `system.config.delete`, `iam.admin.modify`
- **Time-based Policy Controls**: Business hours enforcement, rate limiting, and approval expiration validation in OPA policies
- **Real-time Activity Monitor**: `ActivityFeed` component and `LiveActivity` page with simulated WebSocket streaming
- **POA Verification UI**: Enhanced `TokenInspector` with signature verification and detailed validation results
- **Enhanced Prometheus Metrics**: 8 new metrics for OPA policy evaluation tracking (duration, risk tier, denial reasons)
- **Grafana Dashboard**: Comprehensive policy analytics dashboard (`monitoring/grafana/dashboards/atb-policy-analytics.json`)
- **POA Revocation List**: `internal/revocation` package with in-memory store support
- **Key Rotation Support**: `internal/keys` package with JWKS endpoint for signing key management
- **Kubernetes Operator Example**: Complete K8s operator with AgentTask CRD, RBAC, and deployment manifests (`examples/k8s-operator/`)
- **AWS Lambda Authorizer Example**: Lambda authorizer with SAM template for API Gateway integration (`examples/lambda-authorizer/`)
- **Architecture Comparison Document**: ATB vs SC2 SPIFFE Industrial Edge comparison (`docs/architecture/atb-vs-spiffe-industrial-edge.md`)
- **Development Quickstart Guide**: `DEV-QUICKSTART.md` with commands, workflows, and troubleshooting
- Development environment setup (Makefile, VS Code configs)
- CI/CD workflows (ci.yaml, security.yaml, release.yaml)
- Docker Compose for local development
- E2E test script and interactive demo
- Architecture documentation
- OpenAPI specifications for Broker and AgentAuth APIs
- Dependabot configuration for automated dependency updates
- GitHub issue and PR templates
- Pre-commit hooks for code quality
- Security scanning (govulncheck, pip-audit, Trivy, CodeQL)

### Changed

- **OPA Rego v1 Migration**: Updated all 134+ policy rules to Rego v1 syntax with `if` keywords
- **Removed `--v0-compatible` flag**: All OPA commands now use native Rego v1 syntax
- **Risk Tier Table**: Now includes Low, Medium, High, and Critical tiers
- **Dashboard Port**: Changed default development port to 3003
- **Upstream Echo Server**: Fixed port configuration (9001 → 9000 internal)
- Updated CI/CD workflows for OPA v1.12.2 compatibility
- Updated Helm charts to deprecate `v0Compatible` value
- Updated README with badges and documentation links

### Fixed

- OPA policy parse errors with Rego v1 syntax
- Test assertions using `not X with Y` pattern
- Helper functions with `else := value` syntax
- Missing `if` keywords in 134+ policy rules
- Unsafe variable errors in test files
- Rate limit bypass constraint access using `object.get`
- Approval timestamp extraction for dual control validation

### Security

- Added POA token revocation capability with `internal/revocation` package
- Added signing key rotation support with JWKS via `internal/keys` package
- Enhanced audit trail for policy decisions
- Added gitleaks for secret detection
- Added Trivy for container image scanning
- Added CodeQL for static analysis

## [0.1.0] - 2026-01-11

### Added

- Initial ATB Broker implementation (Go)
- AgentAuth service for PoA token issuance
- OPA policy engine with risk-tiered authorization
- SPIFFE/SPIRE integration for workload identity
- Helm chart for Kubernetes deployment
- Comprehensive OPA policy tests
- Go unit tests for broker and agentauth
- PoA token minting utility (Python)
- Development certificates generation
- Audit event schema
- Security documentation (SECURITY.md)
- Contributing guidelines (CONTRIBUTING.md)

### Security

- mTLS enforcement with SPIFFE identity
- RS256 signed PoA tokens
- Risk-tiered authorization (LOW/MEDIUM/HIGH)
- Dual control for high-risk actions
- Legal basis validation
