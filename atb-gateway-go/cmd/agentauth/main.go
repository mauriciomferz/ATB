package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ChallengeRequest struct {
	AgentSPIFFEID string                 `json:"agent_spiffe_id"`
	Act           string                 `json:"act"`
	Con           map[string]interface{} `json:"con"`
	Leg           map[string]interface{} `json:"leg"`
}

type Challenge struct {
	ID         string
	Req        ChallengeRequest
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Approved   bool
	Approver   string
	ApprovedAt *time.Time
}

type Store struct {
	mu         sync.Mutex
	challenges map[string]*Challenge
}

func newStore() *Store {
	return &Store{challenges: map[string]*Challenge{}}
}

func (s *Store) put(c *Challenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[c.ID] = c
}

func (s *Store) get(id string) (*Challenge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	return c, ok
}

func (s *Store) cleanupExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.challenges {
		if now.After(c.ExpiresAt) {
			delete(s.challenges, id)
		}
	}
}

type PoAClaims struct {
	Act string                 `json:"act"`
	Con map[string]interface{} `json:"con"`
	Leg map[string]interface{} `json:"leg"`
	jwt.RegisteredClaims
}

func mustRandID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s%s", prefix, base64.RawURLEncoding.EncodeToString(b))
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func kidForPublicKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return b64url(sum[:])
}

func decodeEd25519PrivateKeyFromPEM(pemText string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ed25519 private key: %T", key)
	}
	return priv, nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, out interface{}) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func main() {
	listenAddr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	if listenAddr == "" {
		listenAddr = ":9090"
	}

	issuer := strings.TrimSpace(os.Getenv("POA_ISSUER"))
	if issuer == "" {
		issuer = "atb-agentauth"
	}

	poaTTLSec := int64(300)
	if v := strings.TrimSpace(os.Getenv("POA_TTL_SECONDS")); v != "" {
		fmt.Sscanf(v, "%d", &poaTTLSec)
	}
	if poaTTLSec <= 0 {
		poaTTLSec = 300
	}
	if poaTTLSec > 900 {
		log.Printf("WARN: POA_TTL_SECONDS capped to 900s")
		poaTTLSec = 900
	}

	challengeTTLSec := int64(300)
	if v := strings.TrimSpace(os.Getenv("CHALLENGE_TTL_SECONDS")); v != "" {
		fmt.Sscanf(v, "%d", &challengeTTLSec)
	}
	if challengeTTLSec <= 0 {
		challengeTTLSec = 300
	}
	if challengeTTLSec > 900 {
		challengeTTLSec = 900
	}

	approvalToken := strings.TrimSpace(os.Getenv("APPROVAL_SHARED_SECRET"))

	var priv ed25519.PrivateKey
	var pub ed25519.PublicKey
	pemKey := strings.TrimSpace(os.Getenv("POA_SIGNING_ED25519_PRIVKEY_PEM"))
	if pemKey != "" {
		k, err := decodeEd25519PrivateKeyFromPEM(pemKey)
		if err != nil {
			log.Fatalf("invalid POA_SIGNING_ED25519_PRIVKEY_PEM: %v", err)
		}
		priv = k
		pub = k.Public().(ed25519.PublicKey)
	} else {
		log.Printf("WARN: POA_SIGNING_ED25519_PRIVKEY_PEM not set; generating ephemeral key (NOT for production)")
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("keygen failed: %v", err)
		}
		priv = k
		pub = k.Public().(ed25519.PublicKey)
	}

	kid := kidForPublicKey(pub)
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"use": "sig",
				"alg": "EdDSA",
				"kid": kid,
				"x":   b64url(pub),
			},
		},
	}

	store := newStore()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for now := range t.C {
			store.cleanupExpired(now)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ready\n"))
	})

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, jwks)
	})

	mux.HandleFunc("/v1/challenge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req ChallengeRequest
		if err := readJSON(r, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		req.AgentSPIFFEID = strings.TrimSpace(req.AgentSPIFFEID)
		req.Act = strings.TrimSpace(req.Act)
		if req.AgentSPIFFEID == "" || !strings.HasPrefix(req.AgentSPIFFEID, "spiffe://") {
			http.Error(w, "invalid agent_spiffe_id", http.StatusBadRequest)
			return
		}
		if req.Act == "" || req.Con == nil || req.Leg == nil {
			http.Error(w, "missing act/con/leg", http.StatusBadRequest)
			return
		}

		now := time.Now().UTC()
		c := &Challenge{
			ID:        mustRandID("chal_"),
			Req:       req,
			CreatedAt: now,
			ExpiresAt: now.Add(time.Duration(challengeTTLSec) * time.Second),
		}
		store.put(c)

		writeJSON(w, 200, map[string]interface{}{
			"challenge_id":  c.ID,
			"expires_at":    c.ExpiresAt.Format(time.RFC3339),
			"approval_hint": "POST /v1/approve with challenge_id (this skeleton simulates MFA/approval)",
		})
	})

	mux.HandleFunc("/v1/approve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if approvalToken != "" {
			got := strings.TrimSpace(r.Header.Get("X-Approval-Token"))
			if got == "" || got != approvalToken {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		var body struct {
			ChallengeID string `json:"challenge_id"`
			Approver    string `json:"approver"`
		}
		if err := readJSON(r, &body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		id := strings.TrimSpace(body.ChallengeID)
		if id == "" {
			http.Error(w, "missing challenge_id", http.StatusBadRequest)
			return
		}
		c, ok := store.get(id)
		if !ok {
			http.Error(w, "unknown challenge", http.StatusNotFound)
			return
		}
		now := time.Now().UTC()
		if now.After(c.ExpiresAt) {
			http.Error(w, "challenge expired", http.StatusGone)
			return
		}
		c.Approved = true
		c.Approver = strings.TrimSpace(body.Approver)
		c.ApprovedAt = &now
		writeJSON(w, 200, map[string]interface{}{"status": "approved"})
	})

	mux.HandleFunc("/v1/mandate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			ChallengeID string `json:"challenge_id"`
		}
		if err := readJSON(r, &body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		id := strings.TrimSpace(body.ChallengeID)
		if id == "" {
			http.Error(w, "missing challenge_id", http.StatusBadRequest)
			return
		}
		c, ok := store.get(id)
		if !ok {
			http.Error(w, "unknown challenge", http.StatusNotFound)
			return
		}
		now := time.Now().UTC()
		if now.After(c.ExpiresAt) {
			http.Error(w, "challenge expired", http.StatusGone)
			return
		}
		if !c.Approved {
			http.Error(w, "challenge not approved", http.StatusForbidden)
			return
		}

		iat := jwt.NewNumericDate(now)
		exp := jwt.NewNumericDate(now.Add(time.Duration(poaTTLSec) * time.Second))
		claims := &PoAClaims{
			Act: c.Req.Act,
			Con: c.Req.Con,
			Leg: c.Req.Leg,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   c.Req.AgentSPIFFEID,
				IssuedAt:  iat,
				ExpiresAt: exp,
				ID:        mustRandID("poa_"),
			},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		tok.Header["kid"] = kid
		jwtStr, err := tok.SignedString(priv)
		if err != nil {
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"token":      jwtStr,
			"expires_at": exp.Time.Format(time.RFC3339),
			"jti":        claims.ID,
		})
	})

	log.Printf("ATB AgentAuth listening on %s (issuer=%s, kid=%s)", listenAddr, issuer, kid)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
