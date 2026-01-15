# Security Hardening Checklist for ATB

This document outlines security hardening measures for production deployment of the Agent Trust Broker.

> **Last Updated:** January 2026
> 
> **Implementation Status Legend:**
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

### 3. Approver Authentication

**Issue:** `/v1/approve` endpoint accepts any approver claim without verification.

**Required Implementation:**
- Require signed approval requests (JWT signed by approver's key)
- Verify approver exists in identity provider
- Validate approver has approval privileges for the action

```go
// Example middleware (to be implemented)
func RequireSignedApproval(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        approvalJWT := r.Header.Get("X-Approval-Token")
        claims, err := verifyApprovalToken(approvalJWT)
        if err != nil {
            http.Error(w, "Invalid approval signature", 401)
            return
        }
        // Verify approver identity
        if !isValidApprover(claims.Subject) {
            http.Error(w, "Not an authorized approver", 403)
            return
        }
        next.ServeHTTP(w, r)
    })
}
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

### 7. Constraint Enforcement at Broker

**Issue:** Token constraints may not be validated against actual request.

**Required:**
- [ ] Broker validates `con.contact_id` matches request path
- [ ] Broker validates `con.amount` matches request body
- [ ] Reject requests that exceed token constraints

---

## 🟡 Medium Priority

### 8. Audit Logging

**Required Events:**
- [ ] Challenge creation (who, what action, when)
- [ ] Approval (who approved, when)
- [ ] Mandate issuance (token JTI, expiry)
- [ ] Token usage at Broker (success/failure)
- [ ] Policy decision details

```json
{
  "timestamp": "2026-01-15T12:00:00Z",
  "event": "challenge.created",
  "challenge_id": "chal_abc123",
  "agent_spiffe_id": "spiffe://example.org/agent/sales-bot",
  "action": "crm.contact.read",
  "risk_tier": "low",
  "requires_approval": true,
  "source_ip": "10.0.1.50"
}
```

---

### 9. Challenge Expiry

**Configuration:**
```yaml
agentauth:
  challenge:
    defaultTTL: 300      # 5 minutes
    maxTTL: 900          # 15 minutes max
    cleanupInterval: 60  # Cleanup expired every minute
```

---

### 10. Input Validation

**All Endpoints:**
- [ ] Maximum request body size: 1MB
- [ ] JSON depth limit: 10 levels
- [ ] String length limits per field
- [ ] Reject null bytes in strings

---

## 🔵 Recommended

### 11. Security Headers ✅

**Status:** ✅ Implemented in AgentAuth service.

All responses include security headers:

```
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

### 12. Key Rotation

**Process:**
1. Generate new signing key
2. Add to JWKS with new `kid`
3. Start signing new tokens with new key
4. Keep old key in JWKS for validation (TTL period)
5. Remove old key after all tokens expired

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

- Security issues: security@your-domain.com
- Emergency: +1-xxx-xxx-xxxx
- Bug bounty: https://your-domain.com/security
