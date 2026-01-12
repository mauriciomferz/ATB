# SPIFFE/SPIRE Integration Guide for ATB

This guide explains how ATB uses SPIFFE (Secure Production Identity Framework for Everyone) for zero-trust workload identity.

## Table of Contents

1. [Overview](#overview)
2. [Core Concepts](#core-concepts)
3. [X.509 SVIDs](#x509-svids)
4. [JWT-SVIDs](#jwt-svids)
5. [Federation](#federation)
6. [Local Demo](#local-demo)
7. [Production Deployment](#production-deployment)

---

## Overview

ATB uses SPIFFE/SPIRE to provide cryptographic workload identity without long-lived secrets:

```
┌─────────────────┐              ┌─────────────────┐              ┌─────────────────┐
│   AI Agent      │    mTLS      │   ATB Broker    │    mTLS      │ Enterprise API  │
│                 │◄────────────►│                 │◄────────────►│ (SAP, SF, etc.) │
│ SPIFFE ID:      │              │ SPIFFE ID:      │              │                 │
│ spiffe://td/    │              │ spiffe://td/    │              │                 │
│ agents/crm      │              │ atb/broker      │              │                 │
└────────┬────────┘              └────────┬────────┘              └─────────────────┘
         │                                │
         │ Workload API                   │ Workload API
         ▼                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                            SPIRE Agent (per node)                                    │
│                                                                                      │
│  • Issues X.509 SVIDs (short-lived certificates) - for mTLS                         │
│  • Issues JWT-SVIDs (short-lived JWTs) - for external APIs                          │
│  • Attests workloads via selectors (k8s:ns, k8s:sa, docker:label)                  │
│  • Automatic certificate rotation (default: 10 minutes)                             │
└────────────────────────────────────────────┬────────────────────────────────────────┘
                                             │
                                             ▼
                              ┌─────────────────────────────┐
                              │       SPIRE Server          │
                              │                             │
                              │  • Trust domain authority   │
                              │  • Issues agent identities  │
                              │  • Manages workload entries │
                              │  • Federation endpoints     │
                              └─────────────────────────────┘
```

### Why SPIFFE?

| Traditional Approach | SPIFFE Approach |
|---------------------|-----------------|
| Long-lived API keys/secrets | Short-lived certificates (10 min) |
| Secrets in env vars/files | Identity from Workload API |
| Manual secret rotation | Automatic rotation |
| Identity = "has the secret" | Identity = cryptographically attested |
| Trust = shared secret | Trust = PKI chain of trust |

---

## Core Concepts

### Trust Domain

A trust domain is a SPIFFE identity namespace, similar to a DNS domain:

```
spiffe://example.org/...
        └─────┬─────┘
         Trust Domain
```

ATB components should share a trust domain:
```
spiffe://atb.example.org/broker
spiffe://atb.example.org/agentauth
spiffe://atb.example.org/agents/crm-agent
spiffe://atb.example.org/connectors/sap
```

### SPIFFE ID

A SPIFFE ID is a URI that uniquely identifies a workload:

```
spiffe://atb.example.org/ns/production/sa/crm-agent
        └──────┬───────┘ └──────────┬──────────────┘
         Trust Domain           Path (flexible)
```

Path conventions for ATB:
- `/atb/broker` - ATB Broker service
- `/atb/agentauth` - ATB AgentAuth service
- `/agents/<name>` - AI agent workloads
- `/connectors/<name>` - Enterprise connectors

### Workload Attestation

SPIRE verifies workload identity using selectors:

**Kubernetes Selectors:**
```bash
-selector k8s:ns:atb              # Namespace
-selector k8s:sa:atb-broker       # ServiceAccount
-selector k8s:pod-label:app:atb   # Pod label
```

**Docker Selectors:**
```bash
-selector docker:label:com.example.workload:broker
-selector docker:image_id:sha256:abc123...
```

**Unix Selectors:**
```bash
-selector unix:uid:1000
-selector unix:gid:1000
-selector unix:path:/usr/bin/agent
```

---

## X.509 SVIDs

X.509 SVIDs are short-lived certificates used for mTLS authentication.

### Structure

```
Certificate:
    Subject: O=SPIRE
    Subject Alternative Name:
        URI: spiffe://atb.example.org/agents/crm-agent
    Validity:
        Not Before: 2026-01-12 10:00:00 UTC
        Not After:  2026-01-12 10:10:00 UTC  (10 min TTL)
```

### Fetching X.509 SVID (Go)

```go
import (
    "github.com/spiffe/go-spiffe/v2/workloadapi"
    "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// Create X509 source from Workload API
ctx := context.Background()
source, err := workloadapi.NewX509Source(ctx,
    workloadapi.WithClientOptions(
        workloadapi.WithAddr("unix:///run/spire/sockets/agent.sock"),
    ),
)
if err != nil {
    log.Fatal(err)
}
defer source.Close()

// Use for mTLS server
tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())
server := &http.Server{
    TLSConfig: tlsConfig,
}

// Use for mTLS client
clientTLSConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
client := &http.Client{
    Transport: &http.Transport{TLSClientConfig: clientTLSConfig},
}
```

### Fetching X.509 SVID (Python)

```python
from spiffe import WorkloadApiClient

# Connect to Workload API
client = WorkloadApiClient("unix:///run/spire/sockets/agent.sock")

# Fetch X.509 SVID
svid = client.fetch_x509_svid()

print(f"SPIFFE ID: {svid.spiffe_id}")
print(f"Expires: {svid.expiry}")

# Get certificate and key for requests
cert_chain = svid.cert_chain  # List of certificates
private_key = svid.private_key

# Use with requests
import tempfile
with tempfile.NamedTemporaryFile(mode='w', suffix='.pem') as cert_file:
    for cert in cert_chain:
        cert_file.write(cert.public_bytes(Encoding.PEM).decode())
    cert_file.flush()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem') as key_file:
        key_file.write(private_key.private_bytes(...))
        key_file.flush()
        
        response = requests.get(
            "https://atb-broker:8443/api",
            cert=(cert_file.name, key_file.name),
            verify=trust_bundle_path
        )
```

### How ATB Uses X.509 SVIDs

1. **Broker mTLS Server** - Accepts connections only from valid SPIFFE workloads
2. **AgentAuth mTLS Server** - Validates agent identity before issuing PoA
3. **Broker to Upstream** - Uses SVID for mTLS to enterprise APIs
4. **Identity in PoA** - Certificate SPIFFE ID becomes PoA `sub` claim

---

## JWT-SVIDs

JWT-SVIDs are short-lived JWTs used for authentication to external APIs that don't support mTLS.

### Structure

```json
{
  "aud": ["https://api.salesforce.com"],
  "exp": 1736590200,
  "iat": 1736589900,
  "sub": "spiffe://atb.example.org/connectors/salesforce"
}
```

### Use Case: External API Authentication

```
┌─────────────┐       ┌─────────────┐       ┌─────────────────┐
│ ATB Broker  │──────▶│ SPIRE Agent │──────▶│ External API    │
│             │       │             │       │ (Salesforce)    │
│ Need token  │       │ Issue JWT   │       │                 │
│ for SF API  │       │ for audience│       │ Validate JWT    │
└─────────────┘       └─────────────┘       └─────────────────┘
       │                     │                      │
       │ FetchJWTSVID        │                      │
       │ (audience:          │                      │
       │  api.salesforce.com)│                      │
       │◄────────────────────│                      │
       │                     │                      │
       │ Bearer Token ───────┼──────────────────────▶
       │                     │                      │
```

### Fetching JWT-SVID (Go)

```go
import (
    "github.com/spiffe/go-spiffe/v2/workloadapi"
    "github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// Create workload API client
client, err := workloadapi.New(ctx,
    workloadapi.WithAddr("unix:///run/spire/sockets/agent.sock"),
)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Fetch JWT-SVID for specific audience
audience := "https://api.salesforce.com"
svids, err := client.FetchJWTSVIDs(ctx, jwtsvid.Params{Audience: audience})
if err != nil {
    log.Fatal(err)
}

token := svids[0].Marshal()

// Use as Bearer token
req, _ := http.NewRequest("GET", "https://api.salesforce.com/data", nil)
req.Header.Set("Authorization", "Bearer "+token)
```

### ATB JWT-SVID Caching

ATB caches JWT-SVIDs to reduce Workload API calls:

```go
type JWTSVIDSource struct {
    client   *workloadapi.Client
    cache    sync.Map  // audience -> cachedJWTSVID
    cacheTTL time.Duration
}

func (s *JWTSVIDSource) FetchJWTSVID(ctx context.Context, audience string) (string, error) {
    // Check cache first
    if cached, ok := s.cache.Load(audience); ok {
        c := cached.(*cachedJWTSVID)
        if time.Now().Before(c.expires) {
            return c.token, nil
        }
    }
    
    // Fetch from Workload API
    svids, err := s.client.FetchJWTSVIDs(ctx, jwtsvid.Params{Audience: audience})
    // ... cache and return
}
```

---

## Federation

SPIFFE Federation allows workloads in different trust domains to authenticate each other.

### Use Case: Multi-Cloud / Multi-Cluster

```
┌─────────────────────────┐       ┌─────────────────────────┐
│   Trust Domain A        │       │   Trust Domain B        │
│   atb.example.org       │       │   partner.example.com   │
│                         │       │                         │
│  ┌──────────────────┐   │       │   ┌──────────────────┐  │
│  │  ATB Broker      │   │       │   │  Partner Agent   │  │
│  │  (accepts B)     │◄──┼───────┼──▶│  (calls ATB)     │  │
│  └──────────────────┘   │       │   └──────────────────┘  │
│                         │       │                         │
│  ┌──────────────────┐   │  Fed  │   ┌──────────────────┐  │
│  │  SPIRE Server A  │◄──┼───────┼──▶│  SPIRE Server B  │  │
│  │  (has B's bundle)│   │       │   │  (has A's bundle)│  │
│  └──────────────────┘   │       │   └──────────────────┘  │
└─────────────────────────┘       └─────────────────────────┘
```

### Configuring Federation (SPIRE Server)

```hcl
# spire-server.conf
server {
    trust_domain = "atb.example.org"
    
    federation {
        bundle_endpoint {
            address = "0.0.0.0"
            port = 8443
        }
        
        federates_with "partner.example.com" {
            bundle_endpoint_url = "https://spire.partner.example.com:8443"
            bundle_endpoint_profile "https_spiffe" {
                endpoint_spiffe_id = "spiffe://partner.example.com/spire/server"
            }
        }
    }
}
```

### ATB Federation Configuration

```json
{
  "federation": {
    "trust_domains": [
      {
        "name": "partner.example.com",
        "bundle_endpoint": "https://spire.partner.example.com:8443",
        "allowed_identities": [
          "spiffe://partner.example.com/agents/*"
        ]
      }
    ]
  }
}
```

### Federation in Code

```go
import (
    "github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
    "github.com/spiffe/go-spiffe/v2/federation"
)

// Fetch bundle from federated trust domain
bundle, err := federation.FetchBundle(ctx, 
    spiffeid.RequireTrustDomainFromString("partner.example.com"),
    "https://spire.partner.example.com:8443",
)

// Use bundle to validate JWT-SVIDs from partner
validator := jwtsvid.NewValidator(jwtbundle.NewSet(bundle))
svid, err := validator.Validate(ctx, tokenString, audience)
```

---

## Local Demo

Run a complete SPIFFE demo locally:

### Prerequisites

```bash
# Docker and Docker Compose
docker --version
docker compose version
```

### Start the Demo

```bash
cd dev/spire-demo

# Generate keys for PoA signing
./scripts/gen-keys.sh

# Start all services
docker compose up -d

# Wait for SPIRE to be ready
docker compose logs -f spire-registration

# Run the demo script
python3 scripts/demo_spiffe_flow.py
```

### What's Running

| Service | Port | Description |
|---------|------|-------------|
| spire-server | 8081 | SPIRE Server (identity authority) |
| spire-agent | - | SPIRE Agent (issues SVIDs) |
| broker | 8443 | ATB Broker with SPIFFE mTLS |
| agentauth | 8444 | ATB AgentAuth with SPIFFE mTLS |
| opa | 8181 | OPA policy engine |
| upstream | 9000 | Echo server (simulated API) |

### Demo Flow

```bash
# 1. Check SPIRE health
docker compose exec spire-server /opt/spire/bin/spire-server healthcheck

# 2. List registered workloads
docker compose exec spire-server /opt/spire/bin/spire-server entry show

# 3. View agent SVIDs
docker compose exec spire-agent /opt/spire/bin/spire-agent api fetch x509

# 4. Run the identity flow demo
docker compose exec demo-agent python3 /scripts/demo_spiffe_flow.py
```

### Clean Up

```bash
docker compose down -v
```

---

## Production Deployment

### Kubernetes with SPIRE

1. **Deploy SPIRE**
   ```bash
   helm repo add spiffe https://spiffe.github.io/helm-charts/
   helm install spire spiffe/spire -n spire-system
   ```

2. **Register ATB Workloads**
   ```bash
   kubectl exec -n spire-system deploy/spire-server -- \
     /opt/spire/bin/spire-server entry create \
     -spiffeID spiffe://example.org/ns/atb/sa/atb-broker \
     -parentID spiffe://example.org/spire/agent/k8s_sat/cluster \
     -selector k8s:ns:atb \
     -selector k8s:sa:atb-broker \
     -ttl 600
   ```

3. **Deploy ATB with SPIFFE**
   ```bash
   helm install atb charts/atb \
     -n atb \
     --set csi.enabled=true \
     --set broker.tls.mode=spiffe \
     --set spiffe.trustDomain=example.org
   ```

### Configuration Reference

| Env Variable | Description | Default |
|-------------|-------------|---------|
| `SPIFFE_ENDPOINT_SOCKET` | Workload API socket | `unix:///run/spire/sockets/agent.sock` |
| `SPIFFE_TRUST_DOMAIN` | Expected trust domain | - |
| `TLS_MODE` | `spiffe` or `file` | `file` |

### Verification

```bash
# Check broker is using SPIFFE
kubectl logs -n atb deploy/atb-broker | grep -i spiffe

# Verify mTLS is working
kubectl exec -n atb deploy/atb-broker -- \
  openssl s_client -connect localhost:8443 -showcerts

# Check SVID rotation
kubectl exec -n atb deploy/atb-broker -- \
  cat /proc/1/fd/3 | openssl x509 -noout -dates
```

---

## Troubleshooting

### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| "no X509 SVID" | Workload not registered | Create SPIRE entry |
| "connection refused" | Socket not mounted | Check CSI driver |
| "trust domain mismatch" | Wrong trust domain | Verify SPIFFE_TRUST_DOMAIN |
| "certificate expired" | Rotation failed | Check SPIRE agent health |

### Debug Commands

```bash
# SPIRE Server health
spire-server healthcheck

# List all entries
spire-server entry show

# Check agent connection
spire-agent healthcheck

# Fetch current SVID
spire-agent api fetch x509 -write /tmp/

# View SVID details
openssl x509 -in /tmp/svid.0.pem -text -noout
```

---

## Related Documentation

- [Authentication Guide](authentication.md) - PoA tokens and identity
- [Security Best Practices](security-best-practices.md) - Key rotation, HSM
- [Production Deployment](production-deployment.md) - HA and operations
- [SPIFFE Specification](https://spiffe.io/docs/latest/spiffe-about/overview/)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/)
