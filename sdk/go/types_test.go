package atb
package atb

import (
	"testing"
)

func TestRiskTierConstants(t *testing.T) {
	tests := []struct {
		tier     string
		expected string
	}{
		{RiskTierLow, "LOW"},
		{RiskTierMedium, "MEDIUM"},
		{RiskTierHigh, "HIGH"},
	}

	for _, tt := range tests {
		if tt.tier != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.tier)
		}
	}
}

func TestActionResult(t *testing.T) {
	result := ActionResult{
		Success:  true,
		Result:   map[string]any{"vendor_id": "V-001"},
		AuditID:  "aud_123",
		RiskTier: RiskTierLow,
	}

	if !result.Success {
		t.Error("expected Success to be true")
	}

	if result.AuditID != "aud_123" {
		t.Errorf("expected AuditID 'aud_123', got '%s'", result.AuditID)
	}

	if result.RiskTier != RiskTierLow {
		t.Errorf("expected RiskTier 'LOW', got '%s'", result.RiskTier)
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
		Limit:    100,
		Offset:   0,
		Action:   "sap.vendor.read",
		Agent:    "spiffe://example.com/agent/test",
		Decision: "allow",
		RiskTier: RiskTierLow,
	}

	if opts.Limit != 100 {
		t.Errorf("expected Limit 100, got %d", opts.Limit)
	}

	if opts.Action != "sap.vendor.read" {
		t.Errorf("expected Action 'sap.vendor.read', got '%s'", opts.Action)
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
