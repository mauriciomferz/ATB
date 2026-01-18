// Package keys provides JWKS (JSON Web Key Set) management for POA signing key rotation.
package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`           // Key type (RSA, EC)
	Kid string `json:"kid"`           // Key ID
	Use string `json:"use,omitempty"` // Key use (sig, enc)
	Alg string `json:"alg,omitempty"` // Algorithm

	// RSA specific
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Exponent

	// EC specific
	Crv string `json:"crv,omitempty"` // Curve
	X   string `json:"x,omitempty"`   // X coordinate
	Y   string `json:"y,omitempty"`   // Y coordinate
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// KeyState represents the lifecycle state of a signing key.
type KeyState string

const (
	KeyStateActive     KeyState = "active"     // Currently used for signing
	KeyStateRotating   KeyState = "rotating"   // New key being phased in
	KeyStateDeprecated KeyState = "deprecated" // Still valid for verification, not signing
	KeyStateRevoked    KeyState = "revoked"    // No longer valid
)

// ManagedKey represents a key with lifecycle metadata.
type ManagedKey struct {
	Kid       string        `json:"kid"`
	State     KeyState      `json:"state"`
	CreatedAt time.Time     `json:"created_at"`
	ExpiresAt time.Time     `json:"expires_at,omitempty"`
	RevokedAt time.Time     `json:"revoked_at,omitempty"`
	PublicKey interface{}   `json:"-"` // *rsa.PublicKey or *ecdsa.PublicKey
	PrivateKey interface{}  `json:"-"` // *rsa.PrivateKey or *ecdsa.PrivateKey (only for active/rotating)
}

// KeyManager manages signing keys with rotation support.
type KeyManager struct {
	mu      sync.RWMutex
	keys    map[string]*ManagedKey
	current string // Kid of current active key
}

// NewKeyManager creates a new key manager.
func NewKeyManager() *KeyManager {
	return &KeyManager{
		keys: make(map[string]*ManagedKey),
	}
}

// AddKey adds a key to the manager.
func (km *KeyManager) AddKey(key *ManagedKey) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if _, exists := km.keys[key.Kid]; exists {
		return fmt.Errorf("key with kid %s already exists", key.Kid)
	}

	km.keys[key.Kid] = key

	// If this is active and there's no current, set it
	if key.State == KeyStateActive && km.current == "" {
		km.current = key.Kid
	}

	return nil
}

// SetActive sets a key as the active signing key.
func (km *KeyManager) SetActive(kid string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	key, exists := km.keys[kid]
	if !exists {
		return fmt.Errorf("key %s not found", kid)
	}

	if key.State == KeyStateRevoked {
		return fmt.Errorf("cannot activate revoked key")
	}

	// Deprecate the current active key
	if km.current != "" && km.current != kid {
		if current, ok := km.keys[km.current]; ok {
			current.State = KeyStateDeprecated
		}
	}

	key.State = KeyStateActive
	km.current = kid
	return nil
}

// RevokeKey marks a key as revoked.
func (km *KeyManager) RevokeKey(kid string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	key, exists := km.keys[kid]
	if !exists {
		return fmt.Errorf("key %s not found", kid)
	}

	key.State = KeyStateRevoked
	key.RevokedAt = time.Now()
	key.PrivateKey = nil // Clear private key

	if km.current == kid {
		km.current = ""
	}

	return nil
}

// GetActiveKey returns the current active signing key.
func (km *KeyManager) GetActiveKey() (*ManagedKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.current == "" {
		return nil, fmt.Errorf("no active key")
	}

	key, exists := km.keys[km.current]
	if !exists || key.State != KeyStateActive {
		return nil, fmt.Errorf("active key not found")
	}

	return key, nil
}

// GetKey returns a key by kid (for verification).
func (km *KeyManager) GetKey(kid string) (*ManagedKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	key, exists := km.keys[kid]
	if !exists {
		return nil, fmt.Errorf("key %s not found", kid)
	}

	if key.State == KeyStateRevoked {
		return nil, fmt.Errorf("key %s is revoked", kid)
	}

	return key, nil
}

// JWKS returns the public keys as a JWKS for the /.well-known/jwks.json endpoint.
func (km *KeyManager) JWKS() (*JWKS, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	jwks := &JWKS{Keys: make([]JWK, 0)}

	for _, key := range km.keys {
		// Only include active and deprecated keys (not revoked)
		if key.State == KeyStateRevoked {
			continue
		}

		jwk, err := publicKeyToJWK(key.Kid, key.PublicKey)
		if err != nil {
			continue
		}
		jwks.Keys = append(jwks.Keys, *jwk)
	}

	return jwks, nil
}

// ListKeys returns all keys with their states.
func (km *KeyManager) ListKeys() []*ManagedKey {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keys := make([]*ManagedKey, 0, len(km.keys))
	for _, key := range km.keys {
		keys = append(keys, key)
	}
	return keys
}

// GenerateECKey generates a new ECDSA key pair.
func GenerateECKey(kid string, curve elliptic.Curve) (*ManagedKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC key: %w", err)
	}

	return &ManagedKey{
		Kid:        kid,
		State:      KeyStateActive,
		CreatedAt:  time.Now(),
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	}, nil
}

// GenerateRSAKey generates a new RSA key pair.
func GenerateRSAKey(kid string, bits int) (*ManagedKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &ManagedKey{
		Kid:        kid,
		State:      KeyStateActive,
		CreatedAt:  time.Now(),
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	}, nil
}

// publicKeyToJWK converts a public key to JWK format.
func publicKeyToJWK(kid string, pubKey interface{}) (*JWK, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return &JWK{
			Kty: "RSA",
			Kid: kid,
			Use: "sig",
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}, nil

	case *ecdsa.PublicKey:
		var alg, crv string
		switch key.Curve {
		case elliptic.P256():
			alg, crv = "ES256", "P-256"
		case elliptic.P384():
			alg, crv = "ES384", "P-384"
		case elliptic.P521():
			alg, crv = "ES512", "P-521"
		default:
			return nil, fmt.Errorf("unsupported EC curve")
		}

		return &JWK{
			Kty: "EC",
			Kid: kid,
			Use: "sig",
			Alg: alg,
			Crv: crv,
			X:   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %T", pubKey)
	}
}

// ToJSON serializes JWKS to JSON.
func (j *JWKS) ToJSON() ([]byte, error) {
	return json.Marshal(j)
}
