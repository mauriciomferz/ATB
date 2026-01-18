package keys

import (
	"crypto/elliptic"
	"encoding/json"
	"testing"
)

func TestGenerateECKey(t *testing.T) {
	key, err := GenerateECKey("ec-key-1", elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECKey failed: %v", err)
	}
	if key.Kid != "ec-key-1" {
		t.Errorf("Expected kid 'ec-key-1', got '%s'", key.Kid)
	}
	if key.PublicKey == nil {
		t.Error("PublicKey should not be nil")
	}
	if key.PrivateKey == nil {
		t.Error("PrivateKey should not be nil")
	}
}

func TestGenerateRSAKey(t *testing.T) {
	key, err := GenerateRSAKey("rsa-key-1", 2048)
	if err != nil {
		t.Fatalf("GenerateRSAKey failed: %v", err)
	}
	if key.Kid != "rsa-key-1" {
		t.Errorf("Expected kid 'rsa-key-1', got '%s'", key.Kid)
	}
	if key.PublicKey == nil {
		t.Error("PublicKey should not be nil")
	}
	if key.PrivateKey == nil {
		t.Error("PrivateKey should not be nil")
	}
}

func TestKeyManager_AddAndGet(t *testing.T) {
	km := NewKeyManager()
	key, _ := GenerateECKey("key-1", elliptic.P256())

	if err := km.AddKey(key); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}

	// Should be set as current since first active key
	active, err := km.GetActiveKey()
	if err != nil {
		t.Fatalf("GetActiveKey failed: %v", err)
	}
	if active.Kid != "key-1" {
		t.Errorf("Expected active key 'key-1', got '%s'", active.Kid)
	}

	// Try adding duplicate
	if err := km.AddKey(key); err == nil {
		t.Error("Expected error for duplicate key")
	}
}

func TestKeyManager_SetActive(t *testing.T) {
	km := NewKeyManager()
	key1, _ := GenerateECKey("key-1", elliptic.P256())
	key2, _ := GenerateECKey("key-2", elliptic.P256())
	key2.State = KeyStateRotating

	km.AddKey(key1)
	km.AddKey(key2)

	// key1 should be active
	active, _ := km.GetActiveKey()
	if active.Kid != "key-1" {
		t.Errorf("Expected 'key-1' active, got '%s'", active.Kid)
	}

	// Switch to key2
	if err := km.SetActive("key-2"); err != nil {
		t.Fatalf("SetActive failed: %v", err)
	}

	// key2 should now be active
	active, _ = km.GetActiveKey()
	if active.Kid != "key-2" {
		t.Errorf("Expected 'key-2' active, got '%s'", active.Kid)
	}

	// key1 should be deprecated
	key1, _ = km.GetKey("key-1")
	if key1.State != KeyStateDeprecated {
		t.Errorf("Expected key-1 deprecated, got '%s'", key1.State)
	}
}

func TestKeyManager_RevokeKey(t *testing.T) {
	km := NewKeyManager()
	key, _ := GenerateECKey("key-1", elliptic.P256())
	km.AddKey(key)

	if err := km.RevokeKey("key-1"); err != nil {
		t.Fatalf("RevokeKey failed: %v", err)
	}

	// Should not be able to get revoked key
	_, err := km.GetKey("key-1")
	if err == nil {
		t.Error("Expected error when getting revoked key")
	}

	// Should not be able to set revoked key as active
	if err := km.SetActive("key-1"); err == nil {
		t.Error("Expected error when activating revoked key")
	}
}

func TestKeyManager_JWKS(t *testing.T) {
	km := NewKeyManager()
	ecKey, _ := GenerateECKey("ec-key-1", elliptic.P256())
	rsaKey, _ := GenerateRSAKey("rsa-key-1", 2048)
	revokedKey, _ := GenerateECKey("revoked-key", elliptic.P256())

	km.AddKey(ecKey)
	km.AddKey(rsaKey)
	km.AddKey(revokedKey)
	km.RevokeKey("revoked-key")

	jwks, err := km.JWKS()
	if err != nil {
		t.Fatalf("JWKS failed: %v", err)
	}

	// Should have 2 keys (revoked excluded)
	if len(jwks.Keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(jwks.Keys))
	}

	// Verify JSON serialization
	jsonBytes, err := jwks.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	var parsed JWKS
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("Failed to parse JWKS JSON: %v", err)
	}

	if len(parsed.Keys) != 2 {
		t.Errorf("Parsed JWKS has %d keys, expected 2", len(parsed.Keys))
	}

	// Check key types
	foundEC, foundRSA := false, false
	for _, key := range parsed.Keys {
		if key.Kty == "EC" && key.Kid == "ec-key-1" {
			foundEC = true
			if key.Crv != "P-256" {
				t.Errorf("Expected curve P-256, got %s", key.Crv)
			}
			if key.Alg != "ES256" {
				t.Errorf("Expected alg ES256, got %s", key.Alg)
			}
		}
		if key.Kty == "RSA" && key.Kid == "rsa-key-1" {
			foundRSA = true
			if key.Alg != "RS256" {
				t.Errorf("Expected alg RS256, got %s", key.Alg)
			}
		}
	}

	if !foundEC {
		t.Error("EC key not found in JWKS")
	}
	if !foundRSA {
		t.Error("RSA key not found in JWKS")
	}
}

func TestKeyManager_ListKeys(t *testing.T) {
	km := NewKeyManager()
	key1, _ := GenerateECKey("key-1", elliptic.P256())
	key2, _ := GenerateECKey("key-2", elliptic.P256())

	km.AddKey(key1)
	km.AddKey(key2)

	keys := km.ListKeys()
	if len(keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(keys))
	}
}
