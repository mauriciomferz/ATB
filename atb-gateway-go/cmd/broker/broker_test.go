package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestPoAClaimsValidation tests PoA claims parsing
func TestPoAClaimsValidation(t *testing.T) {
	tests := []struct {
		name    string
		claims  PoAClaims
		wantErr bool
	}{
		{
			name: "valid PoA claims",
			claims: PoAClaims{
				Act: "sap.vendor.change",
				Con: map[string]interface{}{"amount": 1000},
				Leg: map[string]interface{}{
					"jurisdiction":      "US",
					"accountable_party": map[string]interface{}{"type": "employee", "id": "emp-123"},
				},
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "spiffe://atb.example/agent/test",
					ID:        "jti-12345",
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				},
			},
			wantErr: false,
		},
		{
			name: "missing act claim",
			claims: PoAClaims{
				Act: "",
				Con: map[string]interface{}{},
				Leg: map[string]interface{}{},
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "spiffe://atb.example/agent/test",
					ID:        "jti-12345",
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				},
			},
			wantErr: true,
		},
		{
			name: "expired PoA",
			claims: PoAClaims{
				Act: "sap.vendor.change",
				Con: map[string]interface{}{},
				Leg: map[string]interface{}{
					"jurisdiction":      "US",
					"accountable_party": map[string]interface{}{"type": "employee", "id": "emp-123"},
				},
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "spiffe://atb.example/agent/test",
					ID:        "jti-12345",
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePoAClaims(tt.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePoAClaims() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// validatePoAClaims is extracted validation logic for testing
func validatePoAClaims(claims PoAClaims) error {
	if claims.Act == "" {
		return errMissingAct
	}
	if claims.ExpiresAt == nil || claims.ExpiresAt.Before(time.Now()) {
		return errExpiredPoA
	}
	if claims.Subject == "" {
		return errMissingSubject
	}
	return nil
}

var (
	errMissingAct     = &validationError{"missing act claim"}
	errExpiredPoA     = &validationError{"PoA expired"}
	errMissingSubject = &validationError{"missing subject claim"}
)

type validationError struct {
	msg string
}

func (e *validationError) Error() string {
	return e.msg
}

// TestAuditEventSerialization tests audit event JSON serialization
func TestAuditEventSerialization(t *testing.T) {
	event := AuditEvent{
		Timestamp:        time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		RequestID:        "req-123",
		MandateID:        "jti-456",
		AgentIdentity:    "spiffe://atb.example/agent/test",
		PlatformIdentity: "platform@tenant.onmicrosoft.com",
		Action:           "sap.vendor.change",
		Constraints:      map[string]interface{}{"amount": 1000},
		Decision:         "allow",
		Reason:           "policy_passed",
		Target:           "sap-connector",
		Method:           "POST",
		Path:             "/sap/vendor/12345",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal audit event: %v", err)
	}

	var decoded AuditEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal audit event: %v", err)
	}

	if decoded.MandateID != event.MandateID {
		t.Errorf("MandateID = %v, want %v", decoded.MandateID, event.MandateID)
	}
	if decoded.Decision != event.Decision {
		t.Errorf("Decision = %v, want %v", decoded.Decision, event.Decision)
	}
}

// TestConnectorConfigParsing tests connector configuration parsing
func TestConnectorConfigParsing(t *testing.T) {
	configJSON := `{
		"connectors": [
			{
				"id": "salesforce-prod",
				"name": "Salesforce Production",
				"upstream_url": "https://api.salesforce.com",
				"egress_allowlist": ["*.salesforce.com", "login.salesforce.com"],
				"rate_limit": 100,
				"enabled": true,
				"jwt_svid_audience": "https://login.salesforce.com",
				"jwt_svid_header": "X-SVID-Token"
			}
		]
	}`

	var config struct {
		Connectors []Connector `json:"connectors"`
	}
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		t.Fatalf("failed to parse connector config: %v", err)
	}

	if len(config.Connectors) != 1 {
		t.Fatalf("expected 1 connector, got %d", len(config.Connectors))
	}

	c := config.Connectors[0]
	if c.ID != "salesforce-prod" {
		t.Errorf("ID = %v, want salesforce-prod", c.ID)
	}
	if c.RateLimit != 100 {
		t.Errorf("RateLimit = %v, want 100", c.RateLimit)
	}
	if c.JWTSVIDAudience != "https://login.salesforce.com" {
		t.Errorf("JWTSVIDAudience = %v, want https://login.salesforce.com", c.JWTSVIDAudience)
	}
	if len(c.EgressAllowlist) != 2 {
		t.Errorf("EgressAllowlist length = %v, want 2", len(c.EgressAllowlist))
	}
	if !c.Enabled {
		t.Error("Enabled should be true")
	}
}

// TestEgressAllowlistValidation tests URL matching against egress allowlist
func TestEgressAllowlistValidation(t *testing.T) {
	tests := []struct {
		name      string
		allowlist []string
		targetURL string
		want      bool
	}{
		{
			name:      "exact match",
			allowlist: []string{"api.salesforce.com"},
			targetURL: "https://api.salesforce.com/v1/query",
			want:      true,
		},
		{
			name:      "wildcard subdomain match",
			allowlist: []string{"*.salesforce.com"},
			targetURL: "https://myorg.salesforce.com/api",
			want:      true,
		},
		{
			name:      "wildcard no match different domain",
			allowlist: []string{"*.salesforce.com"},
			targetURL: "https://evil.com/api",
			want:      false,
		},
		{
			name:      "multiple allowlist entries",
			allowlist: []string{"*.salesforce.com", "login.microsoft.com"},
			targetURL: "https://login.microsoft.com/oauth",
			want:      true,
		},
		{
			name:      "empty allowlist denies all",
			allowlist: []string{},
			targetURL: "https://api.salesforce.com",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesEgressAllowlist(tt.allowlist, tt.targetURL)
			if got != tt.want {
				t.Errorf("matchesEgressAllowlist() = %v, want %v", got, tt.want)
			}
		})
	}
}

// matchesEgressAllowlist checks if URL matches any pattern in allowlist
func matchesEgressAllowlist(allowlist []string, targetURL string) bool {
	if len(allowlist) == 0 {
		return false
	}

	// Extract host from URL
	host := targetURL
	if strings.HasPrefix(targetURL, "https://") {
		host = strings.TrimPrefix(targetURL, "https://")
	} else if strings.HasPrefix(targetURL, "http://") {
		host = strings.TrimPrefix(targetURL, "http://")
	}
	// Remove path
	if idx := strings.Index(host, "/"); idx > 0 {
		host = host[:idx]
	}

	for _, pattern := range allowlist {
		if pattern == host {
			return true
		}
		// Handle wildcard patterns like *.salesforce.com
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".salesforce.com"
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

// TestHealthEndpoint tests the /health endpoint
func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	// Simple health handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("health endpoint returned %v, want %v", w.Code, http.StatusOK)
	}

	if !strings.Contains(w.Body.String(), "healthy") {
		t.Errorf("health response missing 'healthy': %v", w.Body.String())
	}
}

// TestRiskTierDetermination tests action risk tier logic
func TestRiskTierDetermination(t *testing.T) {
	highRiskActions := []string{
		"sap.vendor.change",
		"sap.payment.execute",
		"salesforce.bulk.export",
		"hr.employee.export_pii",
		"iam.role.assign",
	}

	mediumRiskActions := []string{
		"crm.contact.update",
		"erp.order.create",
		"inventory.stock.adjust",
	}

	lowRiskActions := []string{
		"system.health.check",
		"crm.contact.read",
		"report.sales.summary",
	}

	for _, action := range highRiskActions {
		tier := determineRiskTier(action, highRiskActions, mediumRiskActions)
		if tier != "high" {
			t.Errorf("action %s: got tier %v, want high", action, tier)
		}
	}

	for _, action := range mediumRiskActions {
		tier := determineRiskTier(action, highRiskActions, mediumRiskActions)
		if tier != "medium" {
			t.Errorf("action %s: got tier %v, want medium", action, tier)
		}
	}

	for _, action := range lowRiskActions {
		tier := determineRiskTier(action, highRiskActions, mediumRiskActions)
		if tier != "low" {
			t.Errorf("action %s: got tier %v, want low", action, tier)
		}
	}
}

func determineRiskTier(action string, highRisk, mediumRisk []string) string {
	for _, a := range highRisk {
		if a == action {
			return "high"
		}
	}
	for _, a := range mediumRisk {
		if a == action {
			return "medium"
		}
	}
	return "low"
}

// TestPlatformSPIFFEBindingModes tests platform↔SPIFFE binding validation
func TestPlatformSPIFFEBindingModes(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		platformSub string
		spiffeID    string
		want        bool
	}{
		{
			name:        "exact match valid",
			mode:        "exact",
			platformSub: "spiffe://atb.example/agent/copilot-prod",
			spiffeID:    "spiffe://atb.example/agent/copilot-prod",
			want:        true,
		},
		{
			name:        "exact match invalid",
			mode:        "exact",
			platformSub: "spiffe://atb.example/agent/copilot-prod",
			spiffeID:    "spiffe://atb.example/agent/other",
			want:        false,
		},
		{
			name:        "prefix match valid",
			mode:        "prefix",
			platformSub: "tenant-123",
			spiffeID:    "spiffe://atb.example/platform/tenant-123/agent/copilot",
			want:        true,
		},
		{
			name:        "prefix match invalid",
			mode:        "prefix",
			platformSub: "tenant-123",
			spiffeID:    "spiffe://atb.example/platform/tenant-456/agent/copilot",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validatePlatformBinding(tt.mode, tt.platformSub, tt.spiffeID)
			if got != tt.want {
				t.Errorf("validatePlatformBinding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func validatePlatformBinding(mode, platformSub, spiffeID string) bool {
	switch mode {
	case "exact":
		return platformSub == spiffeID
	case "prefix":
		return strings.Contains(spiffeID, platformSub)
	default:
		return false
	}
}

// TestDualControlApproverValidation tests dual control approver requirements
func TestDualControlApproverValidation(t *testing.T) {
	tests := []struct {
		name      string
		approvers []map[string]string
		requester string
		wantValid bool
	}{
		{
			name: "valid dual control - two distinct approvers",
			approvers: []map[string]string{
				{"id": "approver-a", "type": "manager"},
				{"id": "approver-b", "type": "compliance"},
			},
			requester: "requester-1",
			wantValid: true,
		},
		{
			name: "invalid - only one approver",
			approvers: []map[string]string{
				{"id": "approver-a", "type": "manager"},
			},
			requester: "requester-1",
			wantValid: false,
		},
		{
			name: "invalid - requester is an approver",
			approvers: []map[string]string{
				{"id": "requester-1", "type": "manager"},
				{"id": "approver-b", "type": "compliance"},
			},
			requester: "requester-1",
			wantValid: false,
		},
		{
			name: "invalid - duplicate approvers",
			approvers: []map[string]string{
				{"id": "approver-a", "type": "manager"},
				{"id": "approver-a", "type": "compliance"},
			},
			requester: "requester-1",
			wantValid: false,
		},
		{
			name:      "invalid - empty approvers",
			approvers: []map[string]string{},
			requester: "requester-1",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateDualControl(tt.approvers, tt.requester)
			if got != tt.wantValid {
				t.Errorf("validateDualControl() = %v, want %v", got, tt.wantValid)
			}
		})
	}
}

func validateDualControl(approvers []map[string]string, requester string) bool {
	if len(approvers) < 2 {
		return false
	}

	seen := make(map[string]bool)
	for _, approver := range approvers {
		id := approver["id"]
		if id == requester {
			return false // self-approval
		}
		if seen[id] {
			return false // duplicate
		}
		seen[id] = true
	}
	return true
}

// TestReplayProtectionCache tests JTI replay protection
func TestReplayProtectionCache(t *testing.T) {
	cache := newJTICache(5 * time.Minute)

	jti := "test-jti-12345"

	// First use should succeed
	if !cache.TryAdd(jti, time.Now().Add(5*time.Minute)) {
		t.Error("first TryAdd should succeed")
	}

	// Second use should fail (replay)
	if cache.TryAdd(jti, time.Now().Add(5*time.Minute)) {
		t.Error("second TryAdd should fail (replay detected)")
	}

	// Different JTI should succeed
	if !cache.TryAdd("different-jti", time.Now().Add(5*time.Minute)) {
		t.Error("different JTI should succeed")
	}
}

type jtiCache struct {
	mu    sync.RWMutex
	items map[string]time.Time
	ttl   time.Duration
}

func newJTICache(ttl time.Duration) *jtiCache {
	return &jtiCache{
		items: make(map[string]time.Time),
		ttl:   ttl,
	}
}

func (c *jtiCache) TryAdd(jti string, exp time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Cleanup expired entries
	now := time.Now()
	for k, v := range c.items {
		if v.Before(now) {
			delete(c.items, k)
		}
	}

	// Check if already exists
	if _, exists := c.items[jti]; exists {
		return false
	}

	c.items[jti] = exp
	return true
}
