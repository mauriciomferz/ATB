package atb

import (
	"testing"
)

func TestActionResult(t *testing.T) {
	result := ActionResult{
		Success:  true,
		Data:     map[string]any{"vendor_id": "V-001"},
		AuditID:  "aud_123",
		Decision: "allow",
	}

	if !result.Success {
		t.Error("expected Success to be true")
	}

	if result.AuditID != "aud_123" {
		t.Errorf("expected AuditID 'aud_123', got '%s'", result.AuditID)
	}

	if result.Decision != "allow" {
		t.Errorf("expected Decision 'allow', got '%s'", result.Decision)
	}
}

func TestActionResultWithError(t *testing.T) {
	result := ActionResult{
		Success: false,
		Error:   "Policy denied: insufficient permissions",
	}

	if result.Success {
		t.Error("expected Success to be false")
	}

	if result.Error == "" {
		t.Error("expected Error to be set")
	}
}

func TestAuditLogOptions(t *testing.T) {
	opts := AuditLogOptions{
		Limit:   100,
		Action:  "sap.vendor.read",
		Agent:   "spiffe://example.com/agent/test",
		AuditID: "aud_123",
	}

	if opts.Limit != 100 {
		t.Errorf("expected Limit 100, got %d", opts.Limit)
	}

	if opts.Action != "sap.vendor.read" {
		t.Errorf("expected Action 'sap.vendor.read', got '%s'", opts.Action)
	}

	if opts.AuditID != "aud_123" {
		t.Errorf("expected AuditID 'aud_123', got '%s'", opts.AuditID)
	}
}

func TestConfigDefaults(t *testing.T) {
	config := Config{}

	// Empty config should still work
	if config.BrokerURL != "" {
		t.Error("expected empty BrokerURL for zero config")
	}

	// DefaultConfig should set values
	defaultConfig := DefaultConfig()
	if defaultConfig.BrokerURL == "" {
		t.Error("DefaultConfig should set BrokerURL")
	}
	if defaultConfig.Timeout == 0 {
		t.Error("DefaultConfig should set Timeout")
	}
}
