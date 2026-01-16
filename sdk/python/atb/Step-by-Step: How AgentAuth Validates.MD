Step-by-Step: How AgentAuth Validates Agent Identity and Issues PoA Tokens
Overview Flow

┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐│   Agent     │────▶│  AgentAuth  │────▶│    OPA      │────▶│  PoA Token  ││  (AI/LLM)   │     │   Service   │     │   Policy    │     │   Issued    │└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
Step 1: Agent Sends Challenge Request
The agent (AI/LLM workload) sends a request to create a challenge:


curl -X POST http://localhost:8444/v1/challenge \  -H "Content-Type: application/json" \  -d '{    "agent_spiffe_id": "spiffe://example.org/agent/sales-bot",    "act": "crm.contact.read",    "con": {"contact_id": "12345"},    "leg": {      "basis": "contract",      "jurisdiction": "US",      "accountable_party": {"type": "human", "id": "user@example.com"}    }  }'
What's in the request:

Field	Purpose
agent_spiffe_id	The agent's claimed identity
act	The action the agent wants to perform
con	Constraints/parameters for the action
leg	Legal basis (GDPR compliance)
Step 2: AgentAuth Validates the SPIFFE ID
AgentAuth performs strict validation on the claimed SPIFFE ID:


// From atb-gateway-go/cmd/agentauth/main.go// Step 2a: Check format with regexvar validSPIFFE = regexp.MustCompile(    `^spiffe://[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(/[a-zA-Z0-9._-]+)+$`)if !validSPIFFE.MatchString(spiffeID) {    return error("invalid SPIFFE ID format")}// Step 2b: Check for path traversalif strings.Contains(spiffeID, "..") {    return error("SPIFFE ID contains path traversal")}// Step 2c: Check for injection attemptsdangerousChars := []string{"$", "`", "(", ")", "{", "}", "|", ";", "&", "<", ">"}for _, char := range dangerousChars {    if strings.Contains(spiffeID, char) {        return error("SPIFFE ID contains dangerous characters")    }}// Step 2d: Check lengthif len(spiffeID) > 2048 {    return error("SPIFFE ID too long")}
Validation checks:

✅ Valid spiffe:// URI format
✅ No path traversal (..)
✅ No injection characters ($, backticks, etc.)
✅ Length under 2048 characters
Step 3: Platform Attestation (mTLS)
In production, the agent's identity is cryptographically verified via mTLS:


┌─────────────────────────────────────────────────────────────────┐│                         SPIRE Agent                             ││  (Running on same node as the AI agent)                         ││                                                                 ││  Provides X.509 SVID to the agent workload:                     ││  - Certificate: CN=spiffe://example.org/agent/sales-bot         ││  - Private Key: (kept secure by SPIRE)                          │└─────────────────────────────────────────────────────────────────┘                              │                    Agent uses SVID for mTLS                              ▼┌─────────────────────────────────────────────────────────────────┐│                      AgentAuth Service                          ││                                                                 ││  TLS Handshake:                                                 ││  1. Agent presents X.509 certificate                            ││  2. AgentAuth verifies certificate chain                        ││  3. AgentAuth extracts SPIFFE ID from SAN (Subject Alt Name)    ││  4. Compares extracted ID with claimed agent_spiffe_id          │└─────────────────────────────────────────────────────────────────┘
How it works:


// AgentAuth extracts SPIFFE ID from client certificatefunc extractSPIFFEFromCert(r *http.Request) (string, error) {    // Get client certificate from TLS connection    if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {        return "", errors.New("no client certificate")    }        cert := r.TLS.PeerCertificates[0]        // SPIFFE ID is in the URI SAN (Subject Alternative Name)    for _, uri := range cert.URIs {        if strings.HasPrefix(uri.String(), "spiffe://") {            return uri.String(), nil        }    }        return "", errors.New("no SPIFFE ID in certificate")}// Verify claimed ID matches certificatefunc validateAgentIdentity(claimed string, fromCert string) error {    if claimed != fromCert {        return fmt.Errorf(            "SPIFFE ID mismatch: claimed %s, certificate has %s",            claimed, fromCert,        )    }    return nil}
Key point: The agent cannot lie about its identity because:

SPIRE only issues certificates to properly attested workloads
The certificate is signed by SPIRE's CA
AgentAuth verifies the certificate chain
The SPIFFE ID in the certificate must match the claimed ID
Step 4: AgentAuth Queries OPA for Policy Decision
AgentAuth sends the request to OPA to determine:

Risk tier (low/medium/high)
Whether dual control is required
Whether the action is allowed

// Query OPAopaRequest := map[string]interface{}{    "input": map[string]interface{}{        "poa": map[string]interface{}{            "sub": req.AgentSPIFFEID,            "act": req.Act,            "con": req.Con,            "leg": req.Leg,        },    },}resp, _ := http.Post("http://opa:8181/v1/data/atb/authz",     "application/json",     opaRequest)
OPA evaluates the policy:


# From opa/policy/poa.rego# Determine risk tier based on actionrisk_tier := "high" if {    high_risk_actions[input.poa.act]}risk_tier := "medium" if {    medium_risk_actions[input.poa.act]}risk_tier := "low" if {    not high_risk_actions[input.poa.act]    not medium_risk_actions[input.poa.act]}# Require dual control for high-risk actionsrequires_dual_control if {    risk_tier == "high"}
OPA response:


{  "result": {    "allow": true,    "risk_tier": "low",    "requires_dual_control": false,    "approvers_needed": 1  }}
Step 5: Challenge Created and Stored
AgentAuth creates a challenge record:


challenge := &Challenge{    ID:                  "chal_" + generateID(),    AgentSPIFFEID:       req.AgentSPIFFEID,    Action:              req.Act,    Constraints:         req.Con,    LegalBasis:          req.Leg,    RiskTier:            opaResult.RiskTier,    RequiresDualControl: opaResult.RequiresDualControl,    ApproversNeeded:     opaResult.ApproversNeeded,    Approvers:           []Approver{},    CreatedAt:           time.Now(),    ExpiresAt:           time.Now().Add(5 * time.Minute),    Status:              "pending",}// Store in memory (or database in production)challenges[challenge.ID] = challenge// Audit logauditLog(AuditEvent{    Event:         "challenge.created",    ChallengeID:   challenge.ID,    AgentSPIFFEID: challenge.AgentSPIFFEID,    Action:        challenge.Action,    RiskTier:      challenge.RiskTier,})
Response to agent:


{  "challenge_id": "chal_abc123",  "requires_dual_control": false,  "approvers_needed": 1,  "expires_at": "2026-01-15T12:05:00Z"}
Step 6: Human Approves the Challenge
A human (manager, supervisor) approves the challenge:


curl -X POST http://localhost:8444/v1/approve \  -H "Content-Type: application/json" \  -H "Authorization: Bearer <approver-jwt>" \  -d '{"challenge_id": "chal_abc123", "approver": "manager@example.com"}'
AgentAuth validates the approval:


func handleApprove(challenge *Challenge, approverID string) error {    // Step 6a: Verify JWT token (approver authentication)    claims, err := verifyApproverJWT(r.Header.Get("Authorization"))    if err != nil {        return errors.New("invalid approver token")    }        // Step 6b: Extract approver ID from JWT    approverID = strings.ToLower(claims.Subject)        // Step 6c: Check self-approval prevention    accountableParty := strings.ToLower(challenge.LegalBasis.AccountableParty.ID)    if approverID == accountableParty {        return errors.New("self-approval not allowed")    }        // Step 6d: Check duplicate approver    for _, existing := range challenge.Approvers {        if strings.EqualFold(existing.ID, approverID) {            return errors.New("approver already approved")        }    }        // Step 6e: Add approver    challenge.Approvers = append(challenge.Approvers, Approver{        ID:         approverID,        ApprovedAt: time.Now(),    })        // Step 6f: Check if fully approved    if len(challenge.Approvers) >= challenge.ApproversNeeded {        challenge.Status = "approved"    }        return nil}
Step 7: Agent Requests PoA Token (Mandate)
Once approved, the agent requests the actual token:


curl -X POST http://localhost:8444/v1/mandate \  -H "Content-Type: application/json" \  -d '{"challenge_id": "chal_abc123"}'
Step 8: AgentAuth Issues the PoA Token
AgentAuth creates and signs the JWT:


func issueMandate(challenge *Challenge) (string, error) {    // Step 8a: Verify challenge is fully approved    if challenge.Status != "approved" {        return "", errors.New("challenge not approved")    }        // Step 8b: Verify challenge not expired    if time.Now().After(challenge.ExpiresAt) {        return "", errors.New("challenge expired")    }        // Step 8c: Generate unique token ID (JTI)    jti := "poa_" + generateID()        // Step 8d: Create PoA claims    claims := PoAClaims{        // Standard JWT claims        Issuer:    "atb-agentauth",        Subject:   challenge.AgentSPIFFEID,  // ← Agent's SPIFFE ID        IssuedAt:  time.Now().Unix(),        ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),        JTI:       jti,                // PoA-specific claims        Act: challenge.Action,        Con: challenge.Constraints,        Leg: challenge.LegalBasis,    }        // Step 8e: Sign with Ed25519 private key    token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)    token.Header["kid"] = currentKeyID  // Key ID for rotation        signedToken, err := token.SignedString(signingKey)    if err != nil {        return "", err    }        // Step 8f: Audit log    auditLog(AuditEvent{        Event:       "mandate.issued",        ChallengeID: challenge.ID,        JTI:         jti,        ExpiresAt:   claims.ExpiresAt,    })        // Step 8g: Mark challenge as used (prevent reuse)    challenge.Status = "issued"        return signedToken, nil}
Step 9: PoA Token Structure
The issued token looks like this:


eyJhbGciOiJFZERTQSIsImtpZCI6IjJ0ZW56YksyOW5ySy1aNk9Id2xHeUtWbXNFcW04RUs5T042bVRVa3dfcTAiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy9hZ2VudC9zYWxlcy1ib3QiLCJhY3QiOiJjcm0uY29udGFjdC5yZWFkIiwiY29uIjp7ImNvbnRhY3RfaWQiOiIxMjM0NSJ9LCJsZWciOnsiYmFzaXMiOiJjb250cmFjdCIsImp1cmlzZGljdGlvbiI6IlVTIiwiYWNjb3VudGFibGVfcGFydHkiOnsidHlwZSI6Imh1bWFuIiwiaWQiOiJ1c2VyQGV4YW1wbGUuY29tIn19LCJpc3MiOiJhdGItYWdlbnRhdXRoIiwiZXhwIjoxNzM2OTQ2NzAwLCJpYXQiOjE3MzY5NDY0MDAsImp0aSI6InBvYV94eXo3ODkifQ.<Ed25519 signature>
Decoded payload:


{  "sub": "spiffe://example.org/agent/sales-bot",  "act": "crm.contact.read",  "con": {    "contact_id": "12345"  },  "leg": {    "basis": "contract",    "jurisdiction": "US",    "accountable_party": {      "type": "human",      "id": "user@example.com"    }  },  "iss": "atb-agentauth",  "exp": 1736946700,  "iat": 1736946400,  "jti": "poa_xyz789"}
Step 10: Agent Uses Token with Broker
The agent includes the token when calling the Broker:


curl -X GET http://broker:8080/api/contacts/12345 \  -H "Authorization: Bearer eyJhbGciOiJFZERTQSIs..."
Broker validates:


func validatePoAToken(tokenString string, request *http.Request) error {    // Step 10a: Parse and verify signature    token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {        kid := t.Header["kid"].(string)        return getPublicKey(kid)  // From JWKS    })        // Step 10b: Verify not expired    if claims.ExpiresAt < time.Now().Unix() {        return errors.New("token expired")    }        // Step 10c: Verify SPIFFE ID matches caller (mTLS)    callerSPIFFE := extractSPIFFEFromCert(request)    if claims.Subject != callerSPIFFE {        return errors.New("SPIFFE ID mismatch - token theft detected")    }        // Step 10d: Verify action matches request    if claims.Act != deriveActionFromRequest(request) {        return errors.New("action mismatch")    }        // Step 10e: Verify constraints match request    if claims.Con["contact_id"] != request.PathParam("contact_id") {        return errors.New("constraint violation")    }        // Step 10f: Check JTI for replay    if isJTIUsed(claims.JTI) {        return errors.New("token replay detected")    }    markJTIUsed(claims.JTI)        return nil}
Complete Flow Diagram

┌──────────────────────────────────────────────────────────────────────────┐│                              SPIRE Server                                 ││                    (Issues SVIDs to attested workloads)                   │└──────────────────────────────────────────────────────────────────────────┘                                    │                         Issues X.509 SVID                                    ▼┌──────────────────────────────────────────────────────────────────────────┐│                              SPIRE Agent                                  ││                         (Runs on K8s node)                                │└──────────────────────────────────────────────────────────────────────────┘                                    │                    Provides SVID to workload                                    ▼┌──────────────────────────────────────────────────────────────────────────┐│                           AI Agent (sales-bot)                            ││                                                                          ││  1. Has SVID: spiffe://example.org/agent/sales-bot                       ││  2. Wants to: crm.contact.read                                           │└──────────────────────────────────────────────────────────────────────────┘                                    │                    POST /v1/challenge (with mTLS)                                    ▼┌──────────────────────────────────────────────────────────────────────────┐│                           AgentAuth Service                               ││                                                                          ││  1. Extract SPIFFE ID from client cert                                   ││  2. Validate claimed ID matches cert                                      ││  3. Validate SPIFFE ID format (no injection)                             ││  4. Query OPA for policy decision                                        ││  5. Create challenge                                                     │└──────────────────────────────────────────────────────────────────────────┘                                    │                              Challenge created                                    ▼┌──────────────────────────────────────────────────────────────────────────┐│                           Human Approver                                  ││                                                                          ││  POST /v1/approve with signed JWT                                        │└──────────────────────────────────────────────────────────────────────────┘                                    │                              Approval recorded                                    ▼┌──────────────────────────────────────────────────────────────────────────┐│                           AgentAuth Service                               ││                                                                          ││  POST /v1/mandate → Issue PoA token                                      ││  - Sign with Ed25519                                                     ││  - Set sub = agent's SPIFFE ID                                           ││  - Include act, con, leg claims                                          │└──────────────────────────────────────────────────────────────────────────┘                                    │                              PoA Token returned                                    ▼┌──────────────────────────────────────────────────────────────────────────┐│                           AI Agent (sales-bot)                            ││                                                                          ││  Uses token: Authorization: Bearer <poa_token>                           │└──────────────────────────────────────────────────────────────────────────┘                                    │                    GET /api/contacts/12345 (with mTLS + token)                                    ▼┌──────────────────────────────────────────────────────────────────────────┐│                              Broker                                       ││                                                                          ││  1. Verify token signature (EdDSA)                                       ││  2. Verify token.sub == caller's SPIFFE ID (from cert)                   ││  3. Verify action matches request                                        ││  4. Verify constraints match request params                              ││  5. Check JTI not replayed                                               ││  6. Forward to connector                                                 │└──────────────────────────────────────────────────────────────────────────┘                                    │                              Request forwarded                                    ▼┌──────────────────────────────────────────────────────────────────────────┐│                           CRM Connector                                   ││                                                                          ││  Executes: GET contact 12345                                             ││  Returns: Contact data                                                   │└──────────────────────────────────────────────────────────────────────────┘
Key Security Properties
Property	How It's Achieved
Agent can't lie about identity	mTLS + SPIFFE certificate verification
Token can't be stolen	sub claim must match caller's cert
Token can't be replayed	JTI tracking
Token can't be used forever	Short expiry (5 min)
Action can't be exceeded	Constraints validated at Broker
Humans stay accountable	Legal basis with accountable party
High-risk actions need oversight	Dual control enforcement
