// Package revocation provides POA token revocation list management.
package revocation

import (
	"context"
	"sync"
	"time"
)

// RevokedToken represents a revoked POA token.
type RevokedToken struct {
	JTI       string    `json:"jti"`
	RevokedAt time.Time `json:"revoked_at"`
	RevokedBy string    `json:"revoked_by,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store defines the interface for revocation list storage backends.
type Store interface {
	Add(ctx context.Context, token RevokedToken) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
	Remove(ctx context.Context, jti string) error
	List(ctx context.Context) ([]RevokedToken, error)
	Cleanup(ctx context.Context) (int, error)
	Count(ctx context.Context) (int, error)
}

// MemoryStore implements an in-memory revocation list.
type MemoryStore struct {
	mu     sync.RWMutex
	tokens map[string]RevokedToken
}

// NewMemoryStore creates a new in-memory revocation store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tokens: make(map[string]RevokedToken),
	}
}

// Add adds a token to the revocation list.
func (s *MemoryStore) Add(_ context.Context, token RevokedToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.JTI] = token
	return nil
}

// IsRevoked checks if a token with the given JTI is revoked.
func (s *MemoryStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.tokens[jti]
	return exists, nil
}

// Remove removes a token from the revocation list.
func (s *MemoryStore) Remove(_ context.Context, jti string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, jti)
	return nil
}

// List returns all currently revoked tokens.
func (s *MemoryStore) List(_ context.Context) ([]RevokedToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tokens := make([]RevokedToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		tokens = append(tokens, t)
	}
	return tokens, nil
}

// Cleanup removes expired entries from the revocation list.
func (s *MemoryStore) Cleanup(_ context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	removed := 0
	for jti, token := range s.tokens {
		if token.ExpiresAt.Before(now) {
			delete(s.tokens, jti)
			removed++
		}
	}
	return removed, nil
}

// Count returns the number of entries in the revocation list.
func (s *MemoryStore) Count(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens), nil
}

// Manager handles revocation list operations with automatic cleanup.
type Manager struct {
	store   Store
	cleanup chan struct{}
}

// NewManager creates a new revocation manager with the given store.
func NewManager(store Store) *Manager {
	return &Manager{
		store:   store,
		cleanup: make(chan struct{}),
	}
}

// Start begins the background cleanup routine.
func (m *Manager) Start(ctx context.Context, cleanupInterval time.Duration) {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.cleanup:
				return
			case <-ticker.C:
				m.store.Cleanup(ctx)
			}
		}
	}()
}

// Stop stops the background cleanup routine.
func (m *Manager) Stop() {
	close(m.cleanup)
}

// RevokeToken adds a token to the revocation list.
func (m *Manager) RevokeToken(ctx context.Context, jti string, expiresAt time.Time, revokedBy, reason string) error {
	return m.store.Add(ctx, RevokedToken{
		JTI:       jti,
		RevokedAt: time.Now(),
		RevokedBy: revokedBy,
		Reason:    reason,
		ExpiresAt: expiresAt,
	})
}

// IsRevoked checks if a token is revoked.
func (m *Manager) IsRevoked(ctx context.Context, jti string) (bool, error) {
	return m.store.IsRevoked(ctx, jti)
}

// List returns all revoked tokens.
func (m *Manager) List(ctx context.Context) ([]RevokedToken, error) {
	return m.store.List(ctx)
}

// Count returns the number of revoked tokens.
func (m *Manager) Count(ctx context.Context) (int, error) {
	return m.store.Count(ctx)
}
