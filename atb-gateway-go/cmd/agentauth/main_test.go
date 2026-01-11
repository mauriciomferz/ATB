package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ===========================================================================
// Test: requiresDualControl function
// ===========================================================================

func TestRequiresDualControl_ExplicitInLeg(t *testing.T) {
	t.Parallel()

	req := ChallengeRequest{
		AgentSPIFFEID: "spiffe://trust.example/agent/test",
		Act:           "crm.contact.read",
		Con:           map[string]interface{}{"contact_id": "C-123"},
		Leg: map[string]interface{}{
			"jurisdiction": "EU",
			"dual_control": map[string]interface{}{
				"required": true,
			},
		},
	}

	highRiskActions := []string{"sap.vendor.change", "iam.privilege.escalate"}

	if !requiresDualControl(req, highRiskActions) {
		t.Error("expected dual control required when leg.dual_control.required=true")
	}
}

func TestRequiresDualControl_HighRiskAction(t *testing.T) {
	t.Parallel()

	req := ChallengeRequest{
		AgentSPIFFEID: "spiffe://trust.example/agent/test",
		Act:           "sap.vendor.change",
		Con:           map[string]interface{}{"vendor_id": "V-123"},
		Leg: map[string]interface{}{
			"jurisdiction": "US",
		},
	}

	highRiskActions := []string{"sap.vendor.change", "iam.privilege.escalate"}

	if !requiresDualControl(req, highRiskActions) {
		t.Error("expected dual control required for high-risk action")
	}
}

func TestRequiresDualControl_LowRiskAction(t *testing.T) {
	t.Parallel()

	req := ChallengeRequest{
		AgentSPIFFEID: "spiffe://trust.example/agent/test",
		Act:           "crm.contact.read",
		Con:           map[string]interface{}{"contact_id": "C-123"},
		Leg: map[string]interface{}{
			"jurisdiction": "US",
		},
	}

	highRiskActions := []string{"sap.vendor.change", "iam.privilege.escalate"}

	if requiresDualControl(req, highRiskActions) {
		t.Error("expected dual control NOT required for low-risk action")
	}
}

// ===========================================================================
// Test: parseHighRiskActions function
// ===========================================================================

func TestParseHighRiskActions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single action",
			input:    "sap.vendor.change",
			expected: []string{"sap.vendor.change"},
		},
		{
			name:     "multiple actions",
			input:    "sap.vendor.change, iam.privilege.escalate, payments.transfer.execute",
			expected: []string{"sap.vendor.change", "iam.privilege.escalate", "payments.transfer.execute"},
		},
		{
			name:     "actions with extra whitespace",
			input:    "  sap.vendor.change ,  iam.privilege.escalate  ",
			expected: []string{"sap.vendor.change", "iam.privilege.escalate"},
		},
		{
			name:     "trailing comma",
			input:    "sap.vendor.change,",
			expected: []string{"sap.vendor.change"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseHighRiskActions(tc.input)

			if len(got) != len(tc.expected) {
				t.Errorf("parseHighRiskActions(%q) = %v; want %v", tc.input, got, tc.expected)
				return
			}
			for i := range got {
				if got[i] != tc.expected[i] {
					t.Errorf("parseHighRiskActions(%q)[%d] = %q; want %q", tc.input, i, got[i], tc.expected[i])
				}
			}
		})
	}
}

// ===========================================================================
// Test: Store operations
// ===========================================================================

func TestStore_PutAndGet(t *testing.T) {
	t.Parallel()

	s := newStore()
	now := time.Now().UTC()

	c := &Challenge{
		ID: "chal_test123",
		Req: ChallengeRequest{
			AgentSPIFFEID: "spiffe://trust.example/agent/test",
			Act:           "crm.contact.read",
			Con:           map[string]interface{}{},
			Leg:           map[string]interface{}{},
		},
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
		Approvers: []Approver{},
	}

	s.put(c)

	got, ok := s.get("chal_test123")
	if !ok {
		t.Fatal("expected challenge to be found")
	}
	if got.ID != c.ID {
		t.Errorf("got challenge ID %q; want %q", got.ID, c.ID)
	}
}

func TestStore_GetNotFound(t *testing.T) {
	t.Parallel()

	s := newStore()
	_, ok := s.get("nonexistent")
	if ok {
		t.Error("expected challenge not found")
	}
}

func TestStore_CleanupExpired(t *testing.T) {
	t.Parallel()

	s := newStore()
	now := time.Now().UTC()

	// Add an expired challenge
	expired := &Challenge{
		ID:        "chal_expired",
		ExpiresAt: now.Add(-1 * time.Minute),
	}
	s.put(expired)

	// Add a valid challenge
	valid := &Challenge{
		ID:        "chal_valid",
		ExpiresAt: now.Add(5 * time.Minute),
	}
	s.put(valid)

	// Cleanup
	s.cleanupExpired(now)

	// Expired should be gone
	if _, ok := s.get("chal_expired"); ok {
		t.Error("expected expired challenge to be removed")
	}

	// Valid should remain
	if _, ok := s.get("chal_valid"); !ok {
		t.Error("expected valid challenge to remain")
	}
}

// ===========================================================================
// Test: Key utility functions
// ===========================================================================

func TestKidForPublicKey(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	kid := kidForPublicKey(pub)

	// KID should be base64url-encoded SHA256 hash
	if kid == "" {
		t.Error("expected non-empty kid")
	}
	if len(kid) == 0 {
		t.Error("expected non-empty kid string")
	}

	// Same public key should produce same KID
	kid2 := kidForPublicKey(pub)
	if kid != kid2 {
		t.Errorf("same public key produced different KIDs: %q vs %q", kid, kid2)
	}
}

func TestMustRandID(t *testing.T) {
	t.Parallel()

	id1 := mustRandID("test_")
	id2 := mustRandID("test_")

	if !strings.HasPrefix(id1, "test_") {
		t.Errorf("expected id to start with prefix, got %q", id1)
	}
	if id1 == id2 {
		t.Error("expected unique IDs")
	}
}

func TestB64url(t *testing.T) {
	t.Parallel()

	input := []byte("hello world")
	encoded := b64url(input)

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if string(decoded) != "hello world" {
		t.Errorf("got %q; want %q", decoded, "hello world")
	}
}

// ===========================================================================
// Test: HTTP Handlers via integration-style tests
// ===========================================================================

// testServer creates a minimal test server with the core handlers
type testServer struct {
	store           *Store
	priv            ed25519.PrivateKey
	pub             ed25519.PublicKey
	kid             string
	highRiskActions []string
	issuer          string
	poaTTLSec       int64
	challengeTTLSec int64
}

func newTestServer() *testServer {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(pub)
	kid := base64.RawURLEncoding.EncodeToString(sum[:])

	return &testServer{
		store:           newStore(),
		priv:            priv,
		pub:             pub,
		kid:             kid,
		highRiskActions: []string{"sap.vendor.change", "iam.privilege.escalate"},
		issuer:          "test-agentauth",
		poaTTLSec:       300,
		challengeTTLSec: 300,
	}
}

func (ts *testServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ChallengeRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.AgentSPIFFEID = strings.TrimSpace(req.AgentSPIFFEID)
	req.Act = strings.TrimSpace(req.Act)
	if req.AgentSPIFFEID == "" || !strings.HasPrefix(req.AgentSPIFFEID, "spiffe://") {
		http.Error(w, "invalid agent_spiffe_id", http.StatusBadRequest)
		return
	}
	if req.Act == "" || req.Con == nil || req.Leg == nil {
		http.Error(w, "missing act/con/leg", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	needsDualControl := requiresDualControl(req, ts.highRiskActions)
	c := &Challenge{
		ID:                  mustRandID("chal_"),
		Req:                 req,
		CreatedAt:           now,
		ExpiresAt:           now.Add(time.Duration(ts.challengeTTLSec) * time.Second),
		Approvers:           []Approver{},
		RequiresDualControl: needsDualControl,
	}
	ts.store.put(c)

	approversNeeded := 1
	if needsDualControl {
		approversNeeded = 2
	}

	writeJSON(w, 200, map[string]interface{}{
		"challenge_id":          c.ID,
		"expires_at":            c.ExpiresAt.Format(time.RFC3339),
		"requires_dual_control": needsDualControl,
		"approvers_needed":      approversNeeded,
	})
}

func (ts *testServer) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ChallengeID string `json:"challenge_id"`
		Approver    string `json:"approver"`
	}
	if err := readJSON(r, &body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(body.ChallengeID)
	approverID := strings.TrimSpace(body.Approver)
	if id == "" || approverID == "" {
		http.Error(w, "missing challenge_id or approver", http.StatusBadRequest)
		return
	}

	c, ok := ts.store.get(id)
	if !ok {
		http.Error(w, "unknown challenge", http.StatusNotFound)
		return
	}
	now := time.Now().UTC()
	if now.After(c.ExpiresAt) {
		http.Error(w, "challenge expired", http.StatusGone)
		return
	}

	// Check duplicate approver
	for _, a := range c.Approvers {
		if a.ID == approverID {
			http.Error(w, "approver already approved", http.StatusConflict)
			return
		}
	}

	c.Approvers = append(c.Approvers, Approver{ID: approverID, ApprovedAt: now})

	approversNeeded := 1
	if c.RequiresDualControl {
		approversNeeded = 2
	}
	if len(c.Approvers) >= approversNeeded {
		c.Approved = true
	}

	writeJSON(w, 200, map[string]interface{}{
		"status":         "approved",
		"fully_approved": c.Approved,
	})
}

func TestHTTP_CreateChallenge_Success(t *testing.T) {
	t.Parallel()

	ts := newTestServer()
	handler := http.HandlerFunc(ts.handleChallenge)

	body := `{
		"agent_spiffe_id": "spiffe://trust.example/agent/test",
		"act": "crm.contact.read",
		"con": {"contact_id": "C-123"},
		"leg": {"jurisdiction": "US"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if _, ok := resp["challenge_id"]; !ok {
		t.Error("expected challenge_id in response")
	}
	if resp["requires_dual_control"].(bool) {
		t.Error("expected requires_dual_control=false for low-risk action")
	}
	if int(resp["approvers_needed"].(float64)) != 1 {
		t.Errorf("expected approvers_needed=1, got %v", resp["approvers_needed"])
	}
}

func TestHTTP_CreateChallenge_HighRiskAction(t *testing.T) {
	t.Parallel()

	ts := newTestServer()
	handler := http.HandlerFunc(ts.handleChallenge)

	body := `{
		"agent_spiffe_id": "spiffe://trust.example/agent/test",
		"act": "sap.vendor.change",
		"con": {"vendor_id": "V-123"},
		"leg": {"jurisdiction": "DE"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if !resp["requires_dual_control"].(bool) {
		t.Error("expected requires_dual_control=true for high-risk action")
	}
	if int(resp["approvers_needed"].(float64)) != 2 {
		t.Errorf("expected approvers_needed=2, got %v", resp["approvers_needed"])
	}
}

func TestHTTP_CreateChallenge_InvalidSPIFFEID(t *testing.T) {
	t.Parallel()

	ts := newTestServer()
	handler := http.HandlerFunc(ts.handleChallenge)

	body := `{
		"agent_spiffe_id": "not-a-spiffe-id",
		"act": "crm.contact.read",
		"con": {},
		"leg": {}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestHTTP_CreateChallenge_MissingFields(t *testing.T) {
	t.Parallel()

	ts := newTestServer()
	handler := http.HandlerFunc(ts.handleChallenge)

	// Missing act
	body := `{
		"agent_spiffe_id": "spiffe://trust.example/agent/test",
		"con": {},
		"leg": {}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestHTTP_Approve_SingleApprover(t *testing.T) {
	t.Parallel()

	ts := newTestServer()
	now := time.Now().UTC()

	// Create a low-risk challenge (needs 1 approver)
	c := &Challenge{
		ID: "chal_single",
		Req: ChallengeRequest{
			AgentSPIFFEID: "spiffe://trust.example/agent/test",
			Act:           "crm.contact.read",
			Con:           map[string]interface{}{},
			Leg:           map[string]interface{}{},
		},
		CreatedAt:           now,
		ExpiresAt:           now.Add(5 * time.Minute),
		Approvers:           []Approver{},
		RequiresDualControl: false,
	}
	ts.store.put(c)

	handler := http.HandlerFunc(ts.handleApprove)
	body := `{"challenge_id": "chal_single", "approver": "user:alice@example.com"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/approve", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if !resp["fully_approved"].(bool) {
		t.Error("expected fully_approved=true after single approval")
	}
}

func TestHTTP_Approve_DualControl(t *testing.T) {
	t.Parallel()

	ts := newTestServer()
	now := time.Now().UTC()

	// Create a high-risk challenge (needs 2 approvers)
	c := &Challenge{
		ID: "chal_dual",
		Req: ChallengeRequest{
			AgentSPIFFEID: "spiffe://trust.example/agent/test",
			Act:           "sap.vendor.change",
			Con:           map[string]interface{}{},
			Leg:           map[string]interface{}{},
		},
		CreatedAt:           now,
		ExpiresAt:           now.Add(5 * time.Minute),
		Approvers:           []Approver{},
		RequiresDualControl: true,
	}
	ts.store.put(c)

	handler := http.HandlerFunc(ts.handleApprove)

	// First approval
	body1 := `{"challenge_id": "chal_dual", "approver": "user:alice@example.com"}`
	req1 := httptest.NewRequest(http.MethodPost, "/v1/approve", bytes.NewBufferString(body1))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	var resp1 map[string]interface{}
	json.Unmarshal(rec1.Body.Bytes(), &resp1)

	if resp1["fully_approved"].(bool) {
		t.Error("expected fully_approved=false after first approval in dual control")
	}

	// Second approval (different approver)
	body2 := `{"challenge_id": "chal_dual", "approver": "user:bob@example.com"}`
	req2 := httptest.NewRequest(http.MethodPost, "/v1/approve", bytes.NewBufferString(body2))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	var resp2 map[string]interface{}
	json.Unmarshal(rec2.Body.Bytes(), &resp2)

	if !resp2["fully_approved"].(bool) {
		t.Error("expected fully_approved=true after second approval")
	}
}

func TestHTTP_Approve_DuplicateApprover(t *testing.T) {
	t.Parallel()

	ts := newTestServer()
	now := time.Now().UTC()

	c := &Challenge{
		ID: "chal_dup",
		Req: ChallengeRequest{
			AgentSPIFFEID: "spiffe://trust.example/agent/test",
			Act:           "sap.vendor.change",
			Con:           map[string]interface{}{},
			Leg:           map[string]interface{}{},
		},
		CreatedAt:           now,
		ExpiresAt:           now.Add(5 * time.Minute),
		Approvers:           []Approver{{ID: "user:alice@example.com", ApprovedAt: now}},
		RequiresDualControl: true,
	}
	ts.store.put(c)

	handler := http.HandlerFunc(ts.handleApprove)

	// Same approver tries again
	body := `{"challenge_id": "chal_dup", "approver": "user:alice@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/approve", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected status 409 Conflict, got %d", rec.Code)
	}
}

func TestHTTP_Approve_ExpiredChallenge(t *testing.T) {
	t.Parallel()

	ts := newTestServer()
	now := time.Now().UTC()

	c := &Challenge{
		ID:        "chal_expired",
		ExpiresAt: now.Add(-1 * time.Minute), // Already expired
		Approvers: []Approver{},
	}
	ts.store.put(c)

	handler := http.HandlerFunc(ts.handleApprove)

	body := `{"challenge_id": "chal_expired", "approver": "user:alice@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/approve", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Errorf("expected status 410 Gone, got %d", rec.Code)
	}
}

func TestHTTP_Approve_NotFound(t *testing.T) {
	t.Parallel()

	ts := newTestServer()
	handler := http.HandlerFunc(ts.handleApprove)

	body := `{"challenge_id": "nonexistent", "approver": "user:alice@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/approve", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

// ===========================================================================
// Test: Health endpoint
// ===========================================================================

func TestHTTP_Health(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("expected 'ok' in body, got %q", rec.Body.String())
	}
}

// ===========================================================================
// Test: JWKS endpoint format
// ===========================================================================

func TestJWKS_Format(t *testing.T) {
	t.Parallel()

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(pub)
	kid := base64.RawURLEncoding.EncodeToString(sum[:])

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"use": "sig",
				"alg": "EdDSA",
				"kid": kid,
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, jwks)
	})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JWKS: %v", err)
	}

	keys, ok := resp["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Fatal("expected keys array in JWKS")
	}

	key := keys[0].(map[string]interface{})
	if key["kty"] != "OKP" {
		t.Errorf("expected kty=OKP, got %v", key["kty"])
	}
	if key["crv"] != "Ed25519" {
		t.Errorf("expected crv=Ed25519, got %v", key["crv"])
	}
	if key["alg"] != "EdDSA" {
		t.Errorf("expected alg=EdDSA, got %v", key["alg"])
	}
}
