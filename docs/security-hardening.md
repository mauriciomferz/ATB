# Security Hardening Checklist for ATB

This document outlines security hardening measures for production deployment of the Agent Trust Broker.

## 🔴 Critical - Required for Production

### 1. Signing Key Management

**Issue:** Ephemeral keys are generated at startup if not configured.

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

### 4. Rate Limiting

**Issue:** No rate limiting allows DoS via challenge flooding.

**Fix:** Add rate limiting middleware:

```yaml
# helm values
agentauth:
  rateLimit:
    enabled: true
    challengesPerMinutePerAgent: 10
    challengesPerMinutePerIP: 100
    approvalsPerMinutePerApprover: 50
```

---

## 🟠 High Priority

### 5. Dual Control Enforcement

**Verify:**
- [ ] Same approver cannot approve twice
- [ ] Approver IDs are normalized (case-insensitive)
- [ ] Approver != Requestor/Agent owner

```bash
# Test: Same approver twice should fail
curl -X POST /v1/approve -d '{"challenge_id":"X","approver":"admin@co.com"}'
curl -X POST /v1/approve -d '{"challenge_id":"X","approver":"admin@co.com"}'
# Second call should return 409 Conflict
```

---

### 6. SPIFFE ID Validation

**Required Checks:**
- [ ] Validate SPIFFE URI format strictly
- [ ] Reject path traversal attempts (`..`)
- [ ] Reject special characters
- [ ] Enforce maximum length (2048 chars)

```go
var validSPIFFE = regexp.MustCompile(`^spiffe://[a-z0-9.-]+/[a-z0-9/_-]+$`)

func validateSPIFFEID(id string) error {
    if len(id) > 2048 {
        return errors.New("SPIFFE ID too long")
    }
    if strings.Contains(id, "..") {
        return errors.New("path traversal not allowed")
    }
    if !validSPIFFE.MatchString(id) {
        return errors.New("invalid SPIFFE ID format")
    }
    return nil
}
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

### 11. Security Headers

```go
func SecurityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("Cache-Control", "no-store")
        w.Header().Set("Content-Security-Policy", "default-src 'none'")
        next.ServeHTTP(w, r)
    })
}
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
