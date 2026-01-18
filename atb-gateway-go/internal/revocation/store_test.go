package revocation

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestMemoryStore_AddAndIsRevoked(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	jti := "test-token-123"
	token := RevokedToken{
		JTI:       jti,
		RevokedAt: time.Now(),
		RevokedBy: "admin@example.com",
		Reason:    "compromised",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	revoked, err := store.IsRevoked(ctx, jti)
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if revoked {
		t.Error("Token should not be revoked initially")
	}

	if err := store.Add(ctx, token); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	revoked, err = store.IsRevoked(ctx, jti)
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if !revoked {
		t.Error("Token should be revoked after Add")
	}
}

func TestMemoryStore_Remove(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	jti := "test-token-456"
	token := RevokedToken{
		JTI:       jti,
		RevokedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	if err := store.Add(ctx, token); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	if err := store.Remove(ctx, jti); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	revoked, _ := store.IsRevoked(ctx, jti)
	if revoked {
		t.Error("Token should not be revoked after Remove")
	}
}

func TestMemoryStore_List(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	tokens := []RevokedToken{
		{JTI: "token-1", ExpiresAt: time.Now().Add(time.Hour)},
		{JTI: "token-2", ExpiresAt: time.Now().Add(time.Hour)},
		{JTI: "token-3", ExpiresAt: time.Now().Add(time.Hour)},
	}

	for _, tok := range tokens {
		store.Add(ctx, tok)
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(list) != 3 {
		t.Errorf("Expected 3 tokens, got %d", len(list))
	}
}

func TestMemoryStore_Count(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	count, _ := store.Count(ctx)
	if count != 0 {
		t.Errorf("Expected 0 tokens, got %d", count)
	}

	store.Add(ctx, RevokedToken{JTI: "token-1", ExpiresAt: time.Now().Add(time.Hour)})
	store.Add(ctx, RevokedToken{JTI: "token-2", ExpiresAt: time.Now().Add(time.Hour)})

	count, _ = store.Count(ctx)
	if count != 2 {
		t.Errorf("Expected 2 tokens, got %d", count)
	}
}

func TestMemoryStore_Cleanup(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	store.Add(ctx, RevokedToken{JTI: "expired-1", ExpiresAt: time.Now().Add(-time.Hour)})
	store.Add(ctx, RevokedToken{JTI: "expired-2", ExpiresAt: time.Now().Add(-30 * time.Minute)})
	store.Add(ctx, RevokedToken{JTI: "valid-1", ExpiresAt: time.Now().Add(time.Hour)})

	removed, err := store.Cleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if removed != 2 {
		t.Errorf("Expected 2 tokens removed, got %d", removed)
	}

	count, _ := store.Count(ctx)
	if count != 1 {
		t.Errorf("Expected 1 token after cleanup, got %d", count)
	}
}

func TestManager_RevokeAndCheck(t *testing.T) {
	store := NewMemoryStore()
	manager := NewManager(store)
	ctx := context.Background()

	jti := "managed-token-123"
	expiresAt := time.Now().Add(time.Hour)

	revoked, _ := manager.IsRevoked(ctx, jti)
	if revoked {
		t.Error("Token should not be revoked initially")
	}

	err := manager.RevokeToken(ctx, jti, expiresAt, "security@example.com", "security incident")
	if err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	revoked, _ = manager.IsRevoked(ctx, jti)
	if !revoked {
		t.Error("Token should be revoked after RevokeToken")
	}

	tokens, _ := manager.List(ctx)
	if len(tokens) != 1 {
		t.Fatalf("Expected 1 token, got %d", len(tokens))
	}
	if tokens[0].RevokedBy != "security@example.com" {
		t.Errorf("Expected revokedBy 'security@example.com', got '%s'", tokens[0].RevokedBy)
	}
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(id int) {
			jti := fmt.Sprintf("token-%d", id)
			store.Add(ctx, RevokedToken{JTI: jti, ExpiresAt: time.Now().Add(time.Hour)})
			store.IsRevoked(ctx, jti)
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	count, _ := store.Count(ctx)
	if count != 100 {
		t.Errorf("Expected 100 tokens, got %d", count)
	}
}
