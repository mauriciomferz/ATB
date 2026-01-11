# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

- Updated README with badges and documentation links

### Security

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
