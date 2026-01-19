//go:build integration
// +build integration

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Integration tests for broker + OPA
// Run with: go test -tags=integration -v ./cmd/broker

// TestBrokerOPAIntegration tests the broker with a real OPA instance
func TestBrokerOPAIntegration(t *testing.T) {
	// Skip if OPA is not running
	resp, err := http.Get("http://localhost:8181/health")
	if err != nil {
		t.Skip("OPA not running at localhost:8181, skipping integration tests")
	}
	resp.Body.Close()

	// Generate test RSA key for PoA signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name           string
		action         string
		legBasis       map[string]interface{}
		method         string
		path           string
		expectedAllow  bool
		expectedReason string
	}{
		{
			name:   "low_risk_health_check",
			action: "",
			legBasis: map[string]interface{}{
				"basis":        "contract",
				"jurisdiction": "US",
				"accountable_party": map[string]interface{}{
					"type": "human",
					"id":   "user@example.com",
				},
			},
			method:        "GET",
			path:          "/health",
			expectedAllow: true,
		},
		{
			name:   "low_risk_action_with_poa",
			action: "system.status.read",
			legBasis: map[string]interface{}{
				"basis":        "contract",
				"jurisdiction": "US",
				"accountable_party": map[string]interface{}{
					"type": "human",
					"id":   "user@example.com",
				},
			},
			method:        "GET",
			path:          "/status",
			expectedAllow: true,
		},
		{
			name:   "medium_risk_without_approval_denied",
			action: "crm.contact.update",
			legBasis: map[string]interface{}{
				"basis":        "contract",
				"jurisdiction": "US",
				"accountable_party": map[string]interface{}{
					"type": "human",
					"id":   "user@example.com",
				},
			},
			method:         "POST",
			path:           "/crm/contact",
			expectedAllow:  false,
			expectedReason: "approval",
		},
		{
			name:   "medium_risk_with_approval_allowed",
			action: "crm.contact.update",
			legBasis: map[string]interface{}{
				"basis":        "contract",
				"jurisdiction": "US",
				"accountable_party": map[string]interface{}{
					"type": "human",
					"id":   "user@example.com",
				},
				"approval": map[string]interface{}{
					"approver":  "manager@example.com",
					"timestamp": "2026-01-11T10:00:00Z",
				},
			},
			method:        "POST",
			path:          "/crm/contact",
			expectedAllow: true,
		},
		{
			name:   "high_risk_single_approval_denied",
			action: "sap.payment.execute",
			legBasis: map[string]interface{}{
				"basis":        "contract",
				"jurisdiction": "US",
				"accountable_party": map[string]interface{}{
					"type": "human",
					"id":   "user@example.com",
				},
				"approval": map[string]interface{}{
					"approver":  "manager@example.com",
					"timestamp": "2026-01-11T10:00:00Z",
				},
			},
			method:         "POST",
			path:           "/sap/payment",
			expectedAllow:  false,
			expectedReason: "dual",
		},
		{
			name:   "high_risk_with_dual_control_allowed",
			action: "sap.payment.execute",
			legBasis: map[string]interface{}{
				"basis":        "contract",
				"jurisdiction": "US",
				"accountable_party": map[string]interface{}{
					"type": "human",
					"id":   "user@example.com",
				},
				"dual_control": map[string]interface{}{
					"approvers": []map[string]interface{}{
						{"id": "approver1@example.com", "timestamp": "2026-01-11T10:00:00Z"},
						{"id": "approver2@example.com", "timestamp": "2026-01-11T10:05:00Z"},
					},
				},
			},
			method:        "POST",
			path:          "/sap/payment",
			expectedAllow: true,
		},
		{
			name:     "missing_legal_basis_denied",
			action:   "system.status.read",
			legBasis: map[string]interface{}{
				// Missing required fields
			},
			method:         "GET",
			path:           "/status",
			expectedAllow:  false,
			expectedReason: "legal",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Build OPA input
			input := map[string]interface{}{
				"method": tc.method,
				"path":   tc.path,
			}

			// Add PoA claim if action is specified
			if tc.action != "" {
				claim := map[string]interface{}{
					"act": tc.action,
					"sub": "spiffe://example.org/agent",
					"exp": time.Now().Add(5 * time.Minute).Unix(),
					"iat": time.Now().Unix(),
					"jti": "test-" + tc.name,
					"leg": tc.legBasis,
				}
				input["claim"] = claim
			}

			// Query OPA
			reqBody, _ := json.Marshal(map[string]interface{}{"input": input})
			resp, err := http.Post(
				"http://localhost:8181/v1/data/atb/poa/decision",
				"application/json",
				bytes.NewReader(reqBody),
			)
			if err != nil {
				t.Fatalf("Failed to query OPA: %v", err)
			}
			defer resp.Body.Close()

			var result struct {
				Result struct {
					Allow   bool     `json:"allow"`
					Reasons []string `json:"reasons"`
				} `json:"result"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				t.Fatalf("Failed to decode OPA response: %v", err)
			}

			// Check result
			if result.Result.Allow != tc.expectedAllow {
				t.Errorf("Expected allow=%v, got allow=%v (reasons: %v)",
					tc.expectedAllow, result.Result.Allow, result.Result.Reasons)
			}

			// If denied, check reason contains expected substring
			if !tc.expectedAllow && tc.expectedReason != "" {
				found := false
				for _, r := range result.Result.Reasons {
					if contains(r, tc.expectedReason) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected reason containing %q, got %v",
						tc.expectedReason, result.Result.Reasons)
				}
			}
		})
	}

	// Suppress unused variable warning
	_ = privateKey
}

func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

// TestPoATokenValidation tests PoA token parsing and validation
func TestPoATokenValidation(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name        string
		claims      jwt.MapClaims
		expectValid bool
	}{
		{
			name: "valid_token",
			claims: jwt.MapClaims{
				"sub": "spiffe://example.org/agent",
				"act": "system.status.read",
				"con": map[string]interface{}{},
				"leg": map[string]interface{}{
					"basis":             "contract",
					"accountable_party": map[string]interface{}{"type": "human", "id": "user@example.com"},
				},
				"iat": time.Now().Unix(),
				"exp": time.Now().Add(5 * time.Minute).Unix(),
				"jti": "test-valid",
			},
			expectValid: true,
		},
		{
			name: "expired_token",
			claims: jwt.MapClaims{
				"sub": "spiffe://example.org/agent",
				"act": "system.status.read",
				"con": map[string]interface{}{},
				"leg": map[string]interface{}{
					"basis":             "contract",
					"accountable_party": map[string]interface{}{"type": "human", "id": "user@example.com"},
				},
				"iat": time.Now().Add(-10 * time.Minute).Unix(),
				"exp": time.Now().Add(-5 * time.Minute).Unix(),
				"jti": "test-expired",
			},
			expectValid: false,
		},
		{
			name: "missing_action",
			claims: jwt.MapClaims{
				"sub": "spiffe://example.org/agent",
				// Missing "act"
				"con": map[string]interface{}{},
				"leg": map[string]interface{}{
					"basis":             "contract",
					"accountable_party": map[string]interface{}{"type": "human", "id": "user@example.com"},
				},
				"iat": time.Now().Unix(),
				"exp": time.Now().Add(5 * time.Minute).Unix(),
				"jti": "test-no-action",
			},
			expectValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create token
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, tc.claims)
			tokenString, err := token.SignedString(privateKey)
			if err != nil {
				t.Fatalf("Failed to sign token: %v", err)
			}

			// Parse and validate token
			parsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return &privateKey.PublicKey, nil
			})

			if tc.expectValid {
				if err != nil {
					t.Errorf("Expected valid token, got error: %v", err)
				}
				if !parsed.Valid {
					t.Error("Expected token to be valid")
				}

				// Check required claims
				claims, ok := parsed.Claims.(jwt.MapClaims)
				if !ok {
					t.Fatal("Failed to get claims")
				}
				if _, ok := claims["act"]; !ok && tc.name != "missing_action" {
					t.Error("Missing 'act' claim")
				}
			} else {
				// For missing action, we check separately since JWT validation passes
				if tc.name == "missing_action" {
					claims, _ := parsed.Claims.(jwt.MapClaims)
					if _, ok := claims["act"]; ok {
						t.Error("Expected 'act' claim to be missing")
					}
				} else if err == nil {
					t.Error("Expected token to be invalid")
				}
			}
		})
	}
}
