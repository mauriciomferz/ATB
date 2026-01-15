# Security Hardening Checklist for ATB

This document outlines security hardening measures for production deployment of the Agent Trust Broker.

> **Last Updated:** January 2026
>
> **Implementation Status Legend:**
>
> - ✅ Implemented in code
> - ⚠️ Requires configuration
> - ❌ Not yet implemented

## 🔴 Critical - Required for Production

### 1. Signing Key Management ⚠️

**Issue:** Ephemeral keys are generated at startup if not configured.

**Status:** Requires configuration for production.

**Fix:**

```bash
# Generate a production key
openssl genpkey -algorithm Ed25519 -out poa-signing-key.pem

# Store in Kubernetes secret
kubectl create secret generic atb-signing-key \
  --from-file=key.pem=poa-signing-key.pem \
  -n atb

# Set environment variable
export POA_SIGNING_ED25519_PRIVKEY_PEM=$(cat poa-signing-key.pem)
```

**Verification:**

```bash
# Should NOT see this warning in logs:
# "WARN: POA_SIGNING_ED25519_PRIVKEY_PEM not set; generating ephemeral key"
```

---

### 2. mTLS on All Endpoints

**Issue:** Without mTLS, any client can claim any SPIFFE ID.

**Fix:** Configure AgentAuth to require client certificates:

```yaml
# helm values
agentauth:
  tls:
    enabled: true
    clientAuth: require
    certSecretName: atb-agentauth-tls
```

**Verification:**

```bash
# Without client cert - should fail
curl https://agentauth:8443/v1/challenge
# Expected: SSL handshake error

# With valid SVID - should succeed
curl --cert agent.crt --key agent.key https://agentauth:8443/v1/challenge
```

---

### 3. Approver Authentication ✅

**Issue:** `/v1/approve` endpoint previously accepted any approver claim without verification.

**Status:** Implemented with JWT authentication support.

**Configuration Options:**

```bash
# Option 1: HMAC/HS256 JWT verification
export APPROVER_JWT_SECRET="your-256-bit-secret-key"

# Option 2: RSA/RS256 JWT verification
export APPROVER_RSA_PUBLIC_KEY_PEM="-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"

# Option 3: EdDSA JWT verification
export APPROVER_ED25519_PUBLIC_KEY_PEM="-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"

# Restrict trusted JWT issuers (comma-separated)
export APPROVER_JWT_ISSUERS="https://idp.corp.com,https://auth.example.org"

# Require JWT (disable shared secret fallback)
export REQUIRE_JWT_AUTH=true
```

**JWT Claims Required:**

```json
{
  "approver_id": "alice@example.com",
  "sub": "alice@example.com",
  "email": "alice@example.com",
  "name": "Alice Smith",
  "roles": ["approver", "admin"],
  "org": "engineering",
  "iss": "https://idp.corp.com",
  "exp": 1704456789,
  "iat": 1704453189
}
```

**Usage:**

```bash
# Approve with JWT (preferred)
curl -X POST https://agentauth:8443/v1/approve \
  -H "Authorization: Bearer eyJhbG..." \
  -H "Content-Type: application/json" \
  -d '{"challenge_id": "chal_xxx"}'

# Legacy: Approve with shared secret
curl -X POST https://agentauth:8443/v1/approve \
  -H "X-Approval-Token: secret" \
  -H "Content-Type: application/json" \
  -d '{"challenge_id": "chal_xxx", "approver": "alice@example.com"}'
```

**Verification:**

```bash
# Without valid auth - should fail
curl -X POST https://agentauth:8443/v1/approve \
  -d '{"challenge_id": "chal_xxx", "approver": "evil@attacker.com"}'
# Expected: 401 Unauthorized

# With invalid JWT - should fail
curl -X POST https://agentauth:8443/v1/approve \
  -H "Authorization: Bearer invalid-token" \
  -d '{"challenge_id": "chal_xxx"}'
# Expected: 401 authentication failed: token validation failed
```

---

### 4. Rate Limiting ✅

**Issue:** No rate limiting allows DoS via challenge flooding.

**Status:** ✅ Implemented in AgentAuth service.

**Configuration:**

```bash
# Environment variables (defaults shown)
RATE_LIMIT_PER_IP=100      # requests per minute per IP
RATE_LIMIT_PER_AGENT=20    # requests per minute per agent SPIFFE ID
```

**Features:**

- Per-IP rate limiting (default: 100/min)
- Per-agent SPIFFE ID rate limiting (default: 20/min)
- Returns HTTP 429 Too Many Requests with Retry-After header
- Automatic cleanup of expired rate limit entries

**Verification:**

```bash
# Flood test - should see 429 responses after limit exceeded
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://localhost:8444/v1/challenge \
    -H "Content-Type: application/json" \
    -d '{"agent_spiffe_id":"spiffe://test/agent/flood","act":"test","con":{},"leg":{"basis":"test","jurisdiction":"US","accountable_party":{"type":"human","id":"x"}}}'
done
```

---

## 🟠 High Priority

### 5. Dual Control Enforcement ✅

**Status:** ✅ Implemented with the following protections:

- [x] Same approver cannot approve twice
- [x] Approver IDs are normalized (case-insensitive)
- [x] Self-approval prevention (approver != accountable party)

**Configuration:**

```bash
# Disable self-approval prevention (NOT recommended)
ALLOW_SELF_APPROVAL=true
```

**Verification:**

### 6. SPIFFE ID Validation ✅

**Status:** ✅ Implemented with strict validation.

**Checks Performed:**

- [x] Validate SPIFFE URI format strictly (regex)
- [x] Reject path traversal attempts (`..`)
- [x] Reject command injection characters (`$`, backticks, etc.)
- [x] Reject null bytes and control characters
- [x] Enforce maximum length (2048 chars)

**Validation Regex:**

```go
var validSPIFFE = regexp.MustCompile(`^spiffe://[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(/[a-zA-Z0-9._-]+)+$`)
```

**Verification:**

```bash
# Path traversal - should return 400
curl -X POST http://localhost:8444/v1/challenge \
  -H "Content-Type: application/json" \
  -d '{"agent_spiffe_id":"spiffe://test/../../../etc/passwd","act":"test","con":{},"leg":{"basis":"test","jurisdiction":"US","accountable_party":{"type":"human","id":"x"}}}'
# Expected: "invalid agent_spiffe_id: SPIFFE ID contains path traversal"

# Command injection - should return 400
curl -X POST http://localhost:8444/v1/challenge \
  -H "Content-Type: application/json" \
  -d '{"agent_spiffe_id":"spiffe://test/$(whoami)","act":"test","con":{},"leg":{"basis":"test","jurisdiction":"US","accountable_party":{"type":"human","id":"x"}}}'
# Expected: "invalid agent_spiffe_id: invalid SPIFFE ID format"
```

---

### 7. Constraint Enforcement at Broker ✅

**Issue:** Token constraints may not be validated against actual request.

**Status:** ✅ Implemented in Broker service.

**Validated Constraints:**

- [x] `contact_id` - validated against request path/query/body
- [x] `resource_id` - validated against request path/query/body
- [x] `max_amount` - validated against request body amount field
- [x] `read_only` - validates HTTP method is GET/HEAD/OPTIONS
- [x] `allowed_methods` - validates HTTP method in whitelist
- [x] `path_prefix` - validates request path starts with prefix

**Configuration:**

```go
constraintConfig := ConstraintEnforcementConfig{
    Enabled:           true,
    StrictMode:        false,
    EnforceContactID:  true,
    EnforceAmount:     true,
    EnforceResourceID: true,
}
```

---

## 🟡 Medium Priority

### 8. Audit Logging ✅

**Status:** ✅ Implemented in both AgentAuth and Broker services.

**Audit Events:**

- [x] `challenge.created` - Challenge creation with risk tier
- [x] `challenge.approved` - Approval recorded with approver ID
- [x] `mandate.issued` - Token issuance with JTI and expiry
- [x] Token usage at Broker (allow/deny with reason)
- [x] Policy decision details from OPA

**Example Event:**

```json
{
  "timestamp": "2026-01-15T12:00:00Z",
  "event": "challenge.created",
  "challenge_id": "chal_abc123",
  "agent_spiffe_id": "spiffe://example.org/agent/sales-bot",
  "action": "crm.contact.read",
  "risk_tier": "low",
  "requires_dual_control": false,
  "source_ip": "10.0.1.50",
  "success": true,
  "expires_at": "2026-01-15T12:05:00Z"
}
```

---

### 9. Challenge Expiry

**Configuration:**

```yaml
agentauth:
  challenge:
    defaultTTL: 300 # 5 minutes
    maxTTL: 900 # 15 minutes max
    cleanupInterval: 60 # Cleanup expired every minute
```

---

### 10. Input Validation ✅

**Status:** ✅ Implemented in AgentAuth service.

**Validation Rules:**

- [x] Maximum request body size: 1MB
- [x] JSON depth limit: 10 levels
- [x] String length limits: 4096 general, 512 for SPIFFE ID, 256 for action
- [x] Null byte rejection in all string fields and keys

---

## 🔵 Recommended

### 11. Security Headers ✅

**Status:** ✅ Implemented in AgentAuth service.

All responses include security headers:

```text
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-Xss-Protection: 1; mode=block
Cache-Control: no-store, no-cache, must-revalidate
```

**Verification:**

```bash
curl -sI http://localhost:8444/health | grep -E '^X-'
# Expected:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# X-Xss-Protection: 1; mode=block
```

---

### 12. Key Rotation ✅

**Status:** ✅ Implemented with multi-key JWKS support.

**Process:**

1. Generate new signing key
2. Set as `POA_SIGNING_ED25519_PRIVKEY_PEM_NEXT`
3. Promote to primary: move to `POA_SIGNING_ED25519_PRIVKEY_PEM`
4. Move old key to `POA_SIGNING_ED25519_PRIVKEY_PEM_PREV`
5. Remove previous key after TTL period

**Environment Variables:**

```bash
# Primary key (used for signing)
export POA_SIGNING_ED25519_PRIVKEY_PEM=$(cat current.key)

# Previous key (verification only, rotation overlap)
export POA_SIGNING_ED25519_PRIVKEY_PEM_PREV=$(cat previous.key)

# Next key (pre-staged for rotation)
export POA_SIGNING_ED25519_PRIVKEY_PEM_NEXT=$(cat next.key)
```

**JWKS:** All configured keys appear in `/.well-known/jwks.json` for verification.

---

## Verification Checklist

Run before production deployment:

```bash
# 1. No ephemeral key warning
docker logs atb-agentauth 2>&1 | grep -i ephemeral
# Should return nothing

# 2. mTLS required
curl -k https://agentauth:8443/health
# Should fail without client cert

# 3. Rate limiting active
for i in {1..100}; do curl -s -o /dev/null -w "%{http_code}\n" ...; done | grep 429
# Should see 429 responses

# 4. Dual control enforced
# (run dual control bypass test)

# 5. Audit logs present
kubectl logs -l app=atb-agentauth | grep "challenge.created"
# Should see structured logs
```

---

## Security Contacts

- Security issues: `security@your-domain.com`
- Emergency: +1-xxx-xxx-xxxx
- Bug bounty: `https://your-domain.com/security`
