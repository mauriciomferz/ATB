package atb

import (
	"testing"
	"time"
)

func TestAccountableParty(t *testing.T) {
	party := AccountableParty{
		Type:        "user",
		ID:          "alice@example.com",
		DisplayName: "Alice Smith",
	}

	if party.Type != "user" {
		t.Errorf("expected type 'user', got %q", party.Type)
	}
	if party.ID != "alice@example.com" {
		t.Errorf("expected id 'alice@example.com', got %q", party.ID)
	}
}

func TestPoAValidate(t *testing.T) {
	tests := []struct {
		name    string
		poa     PoA
		wantErr bool
	}{
		{
			name: "valid PoA",
			poa: PoA{
				Sub: "spiffe://atb.example/agent/copilot",
				Act: "sap.vendor.change",
				Con: Constraints{},
				Leg: LegalGrounding{
					Jurisdiction:     "DE",
					AccountableParty: AccountableParty{Type: "user", ID: "alice@example.com"},
				},
				Iat: time.Now().Unix(),
				Exp: time.Now().Add(5 * time.Minute).Unix(),
				Jti: "poa_abc123def456",
			},
			wantErr: false,
		},
		{
			name: "invalid SPIFFE ID",
			poa: PoA{
				Sub: "invalid-id",
				Act: "sap.vendor.change",
				Con: Constraints{},
				Leg: LegalGrounding{
					Jurisdiction:     "DE",
					AccountableParty: AccountableParty{Type: "user", ID: "alice@example.com"},
				},
				Iat: time.Now().Unix(),
				Exp: time.Now().Add(5 * time.Minute).Unix(),
				Jti: "poa_abc123def456",
			},
			wantErr: true,
		},
		{
			name: "invalid action format",
			poa: PoA{
				Sub: "spiffe://atb.example/agent/copilot",
				Act: "invalidaction", // No dot
				Con: Constraints{},
				Leg: LegalGrounding{
					Jurisdiction:     "DE",
					AccountableParty: AccountableParty{Type: "user", ID: "alice@example.com"},
				},
				Iat: time.Now().Unix(),
				Exp: time.Now().Add(5 * time.Minute).Unix(),
				Jti: "poa_abc123def456",
			},
			wantErr: true,
		},
		{
			name: "exp before iat",
			poa: PoA{
				Sub: "spiffe://atb.example/agent/copilot",
				Act: "sap.vendor.change",
				Con: Constraints{},
				Leg: LegalGrounding{
					Jurisdiction:     "DE",
					AccountableParty: AccountableParty{Type: "user", ID: "alice@example.com"},
				},
				Iat: time.Now().Unix(),
				Exp: time.Now().Add(-5 * time.Minute).Unix(), // Before iat
				Jti: "poa_abc123def456",
			},
			wantErr: true,
		},
		{
			name: "short JTI",
			poa: PoA{
				Sub: "spiffe://atb.example/agent/copilot",
				Act: "sap.vendor.change",
				Con: Constraints{},
				Leg: LegalGrounding{
					Jurisdiction:     "DE",
					AccountableParty: AccountableParty{Type: "user", ID: "alice@example.com"},
				},
				Iat: time.Now().Unix(),
				Exp: time.Now().Add(5 * time.Minute).Unix(),
				Jti: "short", // Less than 8 chars
			},
			wantErr: true,
		},
		{
			name: "missing jurisdiction",
			poa: PoA{
				Sub: "spiffe://atb.example/agent/copilot",
				Act: "sap.vendor.change",
				Con: Constraints{},
				Leg: LegalGrounding{
					Jurisdiction:     "",
					AccountableParty: AccountableParty{Type: "user", ID: "alice@example.com"},
				},
				Iat: time.Now().Unix(),
				Exp: time.Now().Add(5 * time.Minute).Unix(),
				Jti: "poa_abc123def456",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.poa.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("PoA.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPoAIsExpired(t *testing.T) {
	t.Run("expired token", func(t *testing.T) {
		poa := PoA{
			Exp: time.Now().Add(-1 * time.Hour).Unix(),
		}
		if !poa.IsExpired() {
			t.Error("expected token to be expired")
		}
	})

	t.Run("valid token", func(t *testing.T) {
		poa := PoA{
			Exp: time.Now().Add(1 * time.Hour).Unix(),
		}
		if poa.IsExpired() {
			t.Error("expected token to be valid")
		}
	})
}

func TestPoABuilder(t *testing.T) {
	t.Run("build minimal PoA", func(t *testing.T) {
		poa, err := NewPoABuilder().
			ForAgent("spiffe://atb.example/agent/copilot").
			Action("sap.vendor.change").
			Legal(LegalGrounding{
				Jurisdiction:     "DE",
				AccountableParty: AccountableParty{Type: "user", ID: "alice@example.com"},
			}).
			Build()

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if poa.Sub != "spiffe://atb.example/agent/copilot" {
			t.Errorf("expected sub 'spiffe://atb.example/agent/copilot', got %q", poa.Sub)
		}
		if poa.Act != "sap.vendor.change" {
			t.Errorf("expected act 'sap.vendor.change', got %q", poa.Act)
		}
		if poa.Leg.Jurisdiction != "DE" {
			t.Errorf("expected jurisdiction 'DE', got %q", poa.Leg.Jurisdiction)
		}
	})

	t.Run("build with params and constraints", func(t *testing.T) {
		poa, err := NewPoABuilder().
			ForAgent("spiffe://atb.example/agent/copilot").
			Action("sap.vendor.change").
			WithParam("vendor_id", "V-12345").
			WithParams(map[string]any{"amount": 5000}).
			WithConstraint("liability_cap", 10000).
			WithConstraints(map[string]any{"dual_control": true}).
			Legal(LegalGrounding{
				Jurisdiction:     "DE",
				AccountableParty: AccountableParty{Type: "user", ID: "alice@example.com"},
			}).
			Build()

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if poa.Con.Params["vendor_id"] != "V-12345" {
			t.Errorf("expected vendor_id 'V-12345', got %v", poa.Con.Params["vendor_id"])
		}
		if poa.Con.Params["amount"] != 5000 {
			t.Errorf("expected amount 5000, got %v", poa.Con.Params["amount"])
		}
		if poa.Con.Constraints["liability_cap"] != 10000 {
			t.Errorf("expected liability_cap 10000, got %v", poa.Con.Constraints["liability_cap"])
		}
	})

	t.Run("build with custom TTL", func(t *testing.T) {
		poa, err := NewPoABuilder().
			ForAgent("spiffe://atb.example/agent/copilot").
			Action("sap.vendor.change").
			TTL(1 * time.Minute).
			Legal(LegalGrounding{
				Jurisdiction:     "DE",
				AccountableParty: AccountableParty{Type: "user", ID: "alice@example.com"},
			}).
			Build()

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		ttl := poa.Exp - poa.Iat
		if ttl != 60 {
			t.Errorf("expected TTL 60, got %d", ttl)
		}
	})

	t.Run("build fails without agent", func(t *testing.T) {
		_, err := NewPoABuilder().
			Action("sap.vendor.change").
			Legal(LegalGrounding{
				Jurisdiction:     "DE",
				AccountableParty: AccountableParty{Type: "user", ID: "alice@example.com"},
			}).
			Build()

		if err == nil {
			t.Error("expected error for missing agent")
		}
	})

	t.Run("build fails without action", func(t *testing.T) {
		_, err := NewPoABuilder().
			ForAgent("spiffe://atb.example/agent/copilot").
			Legal(LegalGrounding{
				Jurisdiction:     "DE",
				AccountableParty: AccountableParty{Type: "user", ID: "alice@example.com"},
			}).
			Build()

		if err == nil {
			t.Error("expected error for missing action")
		}
	})

	t.Run("build fails without legal", func(t *testing.T) {
		_, err := NewPoABuilder().
			ForAgent("spiffe://atb.example/agent/copilot").
			Action("sap.vendor.change").
			Build()

		if err == nil {
			t.Error("expected error for missing legal grounding")
		}
	})
}
