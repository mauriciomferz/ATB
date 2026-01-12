package atb

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccountableParty represents the human or organization legally accountable.
type AccountableParty struct {
	Type        string `json:"type"`         // "user", "service_account", "org_unit", "role"
	ID          string `json:"id"`           // Unique identifier
	DisplayName string `json:"display_name,omitempty"` // Human-readable name
}

// DualControl represents dual-control / four-eyes approval metadata.
type DualControl struct {
	Required   bool              `json:"required"`
	Approver   *AccountableParty `json:"approver,omitempty"`
	ApprovedAt string            `json:"approved_at,omitempty"` // ISO 8601 timestamp
}

// LegalGrounding represents the legal basis for a PoA mandate.
type LegalGrounding struct {
	Jurisdiction     string            `json:"jurisdiction"`      // ISO 3166-1 alpha-2 or "GLOBAL"
	AccountableParty AccountableParty  `json:"accountable_party"` // Who is legally responsible
	ApprovalRef      string            `json:"approval_ref,omitempty"` // External approval reference
	DualControl      *DualControl      `json:"dual_control,omitempty"` // Dual-control metadata
	RegulationRefs   []string          `json:"regulation_refs,omitempty"` // e.g., ["NIS2", "SOX"]
	RetentionDays    int               `json:"retention_days,omitempty"` // Audit retention period
}

// Constraints represents action parameters and policy constraints.
type Constraints struct {
	Params      map[string]any `json:"params,omitempty"`      // Action parameters
	Constraints map[string]any `json:"constraints,omitempty"` // Policy constraints
}

// PoA represents a Proof-of-Authorization mandate.
type PoA struct {
	Sub string         `json:"sub"` // Agent SPIFFE ID
	Act string         `json:"act"` // Action identifier
	Con Constraints    `json:"con"` // Constraints
	Leg LegalGrounding `json:"leg"` // Legal grounding
	Iat int64          `json:"iat"` // Issued at (Unix timestamp)
	Exp int64          `json:"exp"` // Expiration (Unix timestamp)
	Jti string         `json:"jti"` // JWT ID for replay protection
	Iss string         `json:"iss,omitempty"` // Issuer SPIFFE ID
	Aud []string       `json:"aud,omitempty"` // Audience SPIFFE ID(s)
}

// IsExpired checks if the PoA has expired.
func (p *PoA) IsExpired() bool {
	return time.Now().Unix() > p.Exp
}

// Validate checks the PoA structure for validity.
func (p *PoA) Validate() error {
	// Check SPIFFE ID format
	if len(p.Sub) < 10 || p.Sub[:9] != "spiffe://" {
		return fmt.Errorf("%w: subject must be a valid SPIFFE ID", ErrValidation)
	}

	// Check action format
	hasNamespace := false
	for _, c := range p.Act {
		if c == '.' {
			hasNamespace = true
			break
		}
	}
	if !hasNamespace {
		return fmt.Errorf("%w: action must be dot-separated (e.g., 'sap.vendor.change')", ErrValidation)
	}

	// Check timestamps
	if p.Exp <= p.Iat {
		return fmt.Errorf("%w: expiration must be after issued time", ErrValidation)
	}

	// Check JTI
	if len(p.Jti) < 8 {
		return fmt.Errorf("%w: jti must be at least 8 characters", ErrValidation)
	}

	// Check legal grounding
	if p.Leg.Jurisdiction == "" {
		return fmt.Errorf("%w: jurisdiction is required", ErrValidation)
	}
	if p.Leg.AccountableParty.ID == "" {
		return fmt.Errorf("%w: accountable party ID is required", ErrValidation)
	}

	return nil
}

// ToJWT signs and encodes the PoA as a JWT.
func (p *PoA) ToJWT(privateKey *ecdsa.PrivateKey) (string, error) {
	claims := jwt.MapClaims{
		"sub": p.Sub,
		"act": p.Act,
		"con": map[string]any{
			"params":      p.Con.Params,
			"constraints": p.Con.Constraints,
		},
		"leg": map[string]any{
			"jurisdiction": p.Leg.Jurisdiction,
			"accountable_party": map[string]any{
				"type":         p.Leg.AccountableParty.Type,
				"id":           p.Leg.AccountableParty.ID,
				"display_name": p.Leg.AccountableParty.DisplayName,
			},
		},
		"iat": p.Iat,
		"exp": p.Exp,
		"jti": p.Jti,
	}

	if p.Iss != "" {
		claims["iss"] = p.Iss
	}
	if len(p.Aud) > 0 {
		claims["aud"] = p.Aud
	}
	if p.Leg.ApprovalRef != "" {
		claims["leg"].(map[string]any)["approval_ref"] = p.Leg.ApprovalRef
	}
	if p.Leg.DualControl != nil {
		claims["leg"].(map[string]any)["dual_control"] = p.Leg.DualControl
	}
	if len(p.Leg.RegulationRefs) > 0 {
		claims["leg"].(map[string]any)["regulation_refs"] = p.Leg.RegulationRefs
	}
	if p.Leg.RetentionDays > 0 {
		claims["leg"].(map[string]any)["retention_days"] = p.Leg.RetentionDays
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(privateKey)
}

// PoABuilder provides a fluent interface for building PoA mandates.
type PoABuilder struct {
	sub         string
	act         string
	params      map[string]any
	constraints map[string]any
	leg         *LegalGrounding
	ttl         time.Duration
	iss         string
	aud         []string
}

// NewPoABuilder creates a new PoA builder with default values.
func NewPoABuilder() *PoABuilder {
	return &PoABuilder{
		params:      make(map[string]any),
		constraints: make(map[string]any),
		ttl:         5 * time.Minute,
	}
}

// ForAgent sets the subject (agent SPIFFE ID).
func (b *PoABuilder) ForAgent(spiffeID string) *PoABuilder {
	b.sub = spiffeID
	return b
}

// Action sets the action to authorize.
func (b *PoABuilder) Action(action string) *PoABuilder {
	b.act = action
	return b
}

// WithParams adds action parameters.
func (b *PoABuilder) WithParams(params map[string]any) *PoABuilder {
	for k, v := range params {
		b.params[k] = v
	}
	return b
}

// WithParam adds a single action parameter.
func (b *PoABuilder) WithParam(key string, value any) *PoABuilder {
	b.params[key] = value
	return b
}

// WithConstraint adds a constraint.
func (b *PoABuilder) WithConstraint(key string, value any) *PoABuilder {
	b.constraints[key] = value
	return b
}

// WithConstraints adds multiple constraints.
func (b *PoABuilder) WithConstraints(constraints map[string]any) *PoABuilder {
	for k, v := range constraints {
		b.constraints[k] = v
	}
	return b
}

// Legal sets the legal grounding.
func (b *PoABuilder) Legal(leg LegalGrounding) *PoABuilder {
	b.leg = &leg
	return b
}

// TTL sets the time-to-live (default: 5 minutes).
func (b *PoABuilder) TTL(d time.Duration) *PoABuilder {
	b.ttl = d
	return b
}

// Issuer sets the issuer SPIFFE ID.
func (b *PoABuilder) Issuer(spiffeID string) *PoABuilder {
	b.iss = spiffeID
	return b
}

// Audience sets the audience SPIFFE ID(s).
func (b *PoABuilder) Audience(spiffeIDs ...string) *PoABuilder {
	b.aud = spiffeIDs
	return b
}

// Build creates the PoA mandate.
func (b *PoABuilder) Build() (*PoA, error) {
	if b.sub == "" {
		return nil, errors.New("subject (agent SPIFFE ID) is required")
	}
	if b.act == "" {
		return nil, errors.New("action is required")
	}
	if b.leg == nil {
		return nil, errors.New("legal grounding is required")
	}

	now := time.Now().Unix()
	poa := &PoA{
		Sub: b.sub,
		Act: b.act,
		Con: Constraints{
			Params:      b.params,
			Constraints: b.constraints,
		},
		Leg: *b.leg,
		Iat: now,
		Exp: now + int64(b.ttl.Seconds()),
		Jti: "poa_" + uuid.New().String()[:12],
		Iss: b.iss,
		Aud: b.aud,
	}

	if err := poa.Validate(); err != nil {
		return nil, err
	}

	return poa, nil
}

// MustBuild is like Build but panics on error.
func (b *PoABuilder) MustBuild() *PoA {
	poa, err := b.Build()
	if err != nil {
		panic(err)
	}
	return poa
}
