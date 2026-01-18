# ATB Security Policy

## Vulnerability Reporting

If you discover a security vulnerability, please report it privately:

- **Email**: security@example.com (replace with your actual security contact)
- **Do not** open public GitHub issues for security vulnerabilities
- We aim to respond within 48 hours

## Security Measures

### Container Security

ATB containers use **distroless static** base images to eliminate OS-level vulnerabilities:

| Image | Base | Why |
|-------|------|-----|
| `atb-broker` | `gcr.io/distroless/static-debian12:nonroot` | No shell, no glibc, minimal attack surface |
| `atb-agentauth` | `gcr.io/distroless/static-debian12:nonroot` | Statically compiled Go binary |

**Benefits of distroless/static:**
- No glibc (eliminates CVE-2024-33602, CVE-2024-33601, etc.)
- No shell (prevents shell injection attacks)
- No package manager (no attack vector for supply chain attacks)
- ~2MB image size (vs ~100MB+ for standard base images)

### Build Security

```dockerfile
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-s -w" \
  -trimpath \
  -o /binary
```

- **CGO_ENABLED=0**: Pure Go builds, no C dependencies
- **Static linking**: Self-contained binaries with no runtime dependencies
- **-trimpath**: Removes build path information from binary
- **-s -w**: Strips symbol table and debug info

### Runtime Security

- **Non-root user**: Containers run as `nonroot` (UID 65532)
- **Read-only filesystem**: Recommended in Kubernetes deployments
- **No capabilities**: Drop all Linux capabilities
- **Seccomp**: Use runtime/default seccomp profile

Example Kubernetes SecurityContext:
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

### Token Security

- **Never log tokens**: PoA tokens should never appear in logs or error messages
- **Short expiry**: Default 5-minute lifetime (configurable)
- **Unique JTI**: Every token has a unique identifier for revocation tracking
- **Ed25519 signatures**: Strong cryptographic signatures (256-bit security)
- **Key rotation**: Support for key rotation via `kid` header

### Network Security

- **mTLS required**: All broker communication requires client certificates
- **SPIFFE identity**: Workload identity via SPIRE, no static secrets
- **TLS 1.3 minimum**: Configurable via `--tls-min-version`
- **Certificate rotation**: Automatic via SPIRE (default 1-hour TTL)

## Dependency Management

### Automated Scanning

- **Trivy**: Runs on every PR and weekly on main branch
- **Dependabot**: Enabled for Go modules and Python packages
- **gosec**: Static analysis for Go security issues

### Update Policy

1. **Critical/High CVEs**: Patch within 24-48 hours
2. **Medium CVEs**: Patch within 7 days
3. **Low CVEs**: Patch in next release cycle
4. **Base images**: Monthly review and update

## Known Vulnerabilities

Track security advisories at:
https://github.com/mauriciomferz/ATB/security/advisories

## Compliance Alignment

ATB is designed to support:

| Regulation | Relevant Feature |
|------------|------------------|
| **GDPR Article 22** | Human oversight via approval workflows |
| **SOC 2 Type II** | Immutable audit logs, access controls |
| **ISO 27001** | Policy-based authorization, least privilege |
| **Zero Trust** | Identity-based access, no implicit trust |

## Incident Response

In case of a security incident:

1. **Contain**: Revoke affected tokens, rotate keys
2. **Investigate**: Audit logs provide full provenance
3. **Notify**: Follow your organization's breach notification procedures
4. **Remediate**: Patch, update policies, document lessons learned

## Security Contacts

- **Security Team**: security@example.com
- **Bug Bounty**: (if applicable)
- **PGP Key**: (if applicable)
