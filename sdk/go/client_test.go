package atb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "default config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "custom config",
			config: Config{
				BrokerURL: "https://custom.example.com",
				Timeout:   30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "empty broker URL uses default",
			config: Config{
				BrokerURL: "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client")
			}

			if client != nil {
				client.Close()
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.BrokerURL == "" {
		t.Error("DefaultConfig BrokerURL should not be empty")
	}

	if config.Timeout == 0 {
		t.Error("DefaultConfig Timeout should not be zero")
	}
}

func TestClientExecute(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		// Verify path
		if r.URL.Path != "/v1/action" {
			t.Errorf("expected /v1/action, got %s", r.URL.Path)
		}

		// Verify authorization header
		auth := r.Header.Get("Authorization")
		if auth == "" {
			t.Error("Authorization header missing")
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Audit-ID", "aud_123")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"success": true,
			"data": {"vendor_id": "V-001", "name": "Test Vendor"}
		}`))
	}))
	defer server.Close()

	// Create client with test server URL
	client, err := NewClient(Config{
		BrokerURL: server.URL,
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	// Build a PoA
	poa, err := NewPoABuilder().
		ForAgent("spiffe://example.com/agent/test").
		Action("sap.vendor.read").
		WithParams(map[string]any{"vendor_id": "V-001"}).
		Legal(LegalGrounding{
			Jurisdiction: "DE",
			AccountableParty: AccountableParty{
				Type: "user",
				ID:   "test@example.com",
			},
		}).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Generate a test private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Execute with the test private key
	ctx := context.Background()
	result, err := client.Execute(ctx, poa, privateKey)

	// Check the result
	if err != nil {
		t.Errorf("Execute() error = %v", err)
		return
	}
	if result != nil {
		if !result.Success {
			t.Error("expected success")
		}
		if result.AuditID != "aud_123" {
			t.Errorf("expected audit_id 'aud_123', got '%s'", result.AuditID)
		}
	}
}

func TestClientCheckPolicy(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policy/check" {
			t.Errorf("expected /v1/policy/check, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"allow": true,
			"risk_tier": "LOW",
			"reasons": []
		}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		BrokerURL: server.URL,
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	result, err := client.CheckPolicy(ctx, "sap.vendor.read", nil, "spiffe://example.com/agent/test")

	if err != nil {
		t.Fatalf("CheckPolicy() error = %v", err)
	}

	allow, ok := result["allow"].(bool)
	if !ok || !allow {
		t.Error("expected allow to be true")
	}
}

func TestClientGetAuditLog(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audit" {
			t.Errorf("expected /v1/audit, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{
				"id": "aud_123",
				"timestamp": "2024-01-01T00:00:00Z",
				"action": "sap.vendor.read",
				"agent": "spiffe://example.com/agent/test",
				"decision": "allow",
				"risk_tier": "LOW"
			}
		]`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		BrokerURL: server.URL,
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	logs, err := client.GetAuditLog(ctx, AuditLogOptions{Limit: 100})

	if err != nil {
		t.Fatalf("GetAuditLog() error = %v", err)
	}

	if len(logs) != 1 {
		t.Errorf("expected 1 log entry, got %d", len(logs))
	}
}

func TestClientClose(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Close should not panic
	err = client.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Closing again should be safe
	err = client.Close()
	if err != nil {
		t.Errorf("Close() error on second call = %v", err)
	}
}
