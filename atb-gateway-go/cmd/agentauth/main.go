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

type Approver struct {
	ID         string    `json:"id"`
	ApprovedAt time.Time `json:"approved_at"`
}

type Challenge struct {
	ID                 string
	Req                ChallengeRequest
	CreatedAt          time.Time
	ExpiresAt          time.Time
	Approved           bool
	Approvers          []Approver // For dual control: need 2 distinct approvers
	RequiresDualControl bool
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

// requiresDualControl checks if the request requires two approvers.
// This is determined by:
//   1. leg.dual_control.required == true (explicit in request)
//   2. Action is in the high-risk action list (configurable via env)
func requiresDualControl(req ChallengeRequest, highRiskActions []string) bool {
	// Check leg.dual_control.required
	if dc, ok := req.Leg["dual_control"].(map[string]interface{}); ok {
		if required, ok := dc["required"].(bool); ok && required {
			return true
		}
	}
	// Check against high-risk action list
	for _, a := range highRiskActions {
		if req.Act == a {
			return true
		}
	}
	return false
}

// parseHighRiskActions reads a comma-separated list of actions from env
func parseHighRiskActions(envVal string) []string {
	if envVal == "" {
		return nil
	}
	parts := strings.Split(envVal, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			result = append(result, s)
		}
	}
	return result
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

	// High-risk actions that always require dual control (comma-separated)
	highRiskActions := parseHighRiskActions(os.Getenv("DUAL_CONTROL_ACTIONS"))
	if len(highRiskActions) == 0 {
		// Default high-risk actions requiring dual control
		highRiskActions = []string{
			"sap.vendor.change",
			"iam.privilege.escalate",
			"payments.transfer.execute",
			"ot.system.manual_override",
		}
	}
	log.Printf("Dual control required for actions: %v", highRiskActions)

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

	// GET /v1/challenge/{id} - check challenge status
	mux.HandleFunc("/v1/challenge/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/challenge/")
		if id == "" {
			http.Error(w, "missing challenge_id in path", http.StatusBadRequest)
			return
		}
		c, ok := store.get(id)
		if !ok {
			http.Error(w, "unknown challenge", http.StatusNotFound)
			return
		}
		now := time.Now().UTC()
		expired := now.After(c.ExpiresAt)
		approversNeeded := 1
		if c.RequiresDualControl {
			approversNeeded = 2
		}
		writeJSON(w, 200, map[string]interface{}{
			"challenge_id":          c.ID,
			"action":                c.Req.Act,
			"agent_spiffe_id":       c.Req.AgentSPIFFEID,
			"created_at":            c.CreatedAt.Format(time.RFC3339),
			"expires_at":            c.ExpiresAt.Format(time.RFC3339),
			"expired":               expired,
			"requires_dual_control": c.RequiresDualControl,
			"approvers_needed":      approversNeeded,
			"approvers_count":       len(c.Approvers),
			"approvers":             c.Approvers,
			"fully_approved":        c.Approved,
		})
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
		needsDualControl := requiresDualControl(req, highRiskActions)
		c := &Challenge{
			ID:                  mustRandID("chal_"),
			Req:                 req,
			CreatedAt:           now,
			ExpiresAt:           now.Add(time.Duration(challengeTTLSec) * time.Second),
			Approvers:           []Approver{},
			RequiresDualControl: needsDualControl,
		}
		store.put(c)

		approversNeeded := 1
		if needsDualControl {
			approversNeeded = 2
		}

		writeJSON(w, 200, map[string]interface{}{
			"challenge_id":      c.ID,
			"expires_at":        c.ExpiresAt.Format(time.RFC3339),
			"requires_dual_control": needsDualControl,
			"approvers_needed":  approversNeeded,
			"approval_hint":     "POST /v1/approve with challenge_id and approver identity",
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
		approverID := strings.TrimSpace(body.Approver)
		if id == "" {
			http.Error(w, "missing challenge_id", http.StatusBadRequest)
			return
		}
		if approverID == "" {
			http.Error(w, "missing approver", http.StatusBadRequest)
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

		// Check if this approver already approved
		for _, a := range c.Approvers {
			if a.ID == approverID {
				http.Error(w, "approver already approved this challenge", http.StatusConflict)
				return
			}
		}

		// Add this approver
		c.Approvers = append(c.Approvers, Approver{
			ID:         approverID,
			ApprovedAt: now,
		})

		// Determine how many approvers are needed
		approversNeeded := 1
		if c.RequiresDualControl {
			approversNeeded = 2
		}

		// Mark as approved if sufficient approvers
		if len(c.Approvers) >= approversNeeded {
			c.Approved = true
		}

		writeJSON(w, 200, map[string]interface{}{
			"status":            "approved",
			"approvers_count":   len(c.Approvers),
			"approvers_needed":  approversNeeded,
			"fully_approved":    c.Approved,
			"approvers":         c.Approvers,
		})
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
			approversNeeded := 1
			if c.RequiresDualControl {
				approversNeeded = 2
			}
			writeJSON(w, http.StatusForbidden, map[string]interface{}{
				"error":             "challenge not fully approved",
				"approvers_count":   len(c.Approvers),
				"approvers_needed":  approversNeeded,
				"requires_dual_control": c.RequiresDualControl,
			})
			return
		}

		// Enrich leg with approval metadata
		legCopy := make(map[string]interface{})
		for k, v := range c.Req.Leg {
			legCopy[k] = v
		}
		// Add dual_control info if applicable
		if c.RequiresDualControl {
			approversList := make([]map[string]interface{}, len(c.Approvers))
			for i, a := range c.Approvers {
				approversList[i] = map[string]interface{}{
					"id":          a.ID,
					"approved_at": a.ApprovedAt.Format(time.RFC3339),
				}
			}
			legCopy["dual_control"] = map[string]interface{}{
				"required":  true,
				"approvers": approversList,
			}
		}

		iat := jwt.NewNumericDate(now)
		exp := jwt.NewNumericDate(now.Add(time.Duration(poaTTLSec) * time.Second))
		claims := &PoAClaims{
			Act: c.Req.Act,
			Con: c.Req.Con,
			Leg: legCopy,
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
			"token":             jwtStr,
			"expires_at":        exp.Time.Format(time.RFC3339),
			"jti":               claims.ID,
			"dual_control_used": c.RequiresDualControl,
			"approvers_count":   len(c.Approvers),
		})
	})

	log.Printf("ATB AgentAuth listening on %s (issuer=%s, kid=%s)", listenAddr, issuer, kid)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
