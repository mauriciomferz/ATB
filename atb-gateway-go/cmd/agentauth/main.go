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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ─────────────────────────────────────────────────────────────────────────────
// Rate Limiter
// ─────────────────────────────────────────────────────────────────────────────

type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int           // max requests
	window   time.Duration // time window
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	// Cleanup goroutine
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for now := range ticker.C {
			rl.cleanup(now)
		}
	}()
	return rl
}

func (rl *RateLimiter) cleanup(now time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := now.Add(-rl.window)
	for key, times := range rl.requests {
		var valid []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, key)
		} else {
			rl.requests[key] = valid
		}
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Filter old requests
	var valid []time.Time
	for _, t := range rl.requests[key] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[key] = valid
		return false
	}

	rl.requests[key] = append(valid, now)
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// Security Helpers
// ─────────────────────────────────────────────────────────────────────────────

// SPIFFE ID validation regex - strict format
var validSPIFFEIDRegex = regexp.MustCompile(`^spiffe://[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(/[a-zA-Z0-9._-]+)+$`)

// validateSPIFFEID performs strict validation of SPIFFE IDs
func validateSPIFFEID(id string) error {
	if len(id) == 0 {
		return errors.New("SPIFFE ID is empty")
	}
	if len(id) > 2048 {
		return errors.New("SPIFFE ID too long (max 2048)")
	}
	if strings.Contains(id, "..") {
		return errors.New("SPIFFE ID contains path traversal")
	}
	if strings.ContainsAny(id, "<>\"'`${}()[];|&\\") {
		return errors.New("SPIFFE ID contains invalid characters")
	}
	if strings.Contains(id, "\x00") {
		return errors.New("SPIFFE ID contains null byte")
	}
	if !validSPIFFEIDRegex.MatchString(id) {
		return errors.New("SPIFFE ID format invalid")
	}
	return nil
}

// normalizeApproverID normalizes approver IDs for comparison
func normalizeApproverID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// Fall back to RemoteAddr
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// securityHeaders adds security headers to responses
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Approver JWT Authentication
// ─────────────────────────────────────────────────────────────────────────────

// ApproverClaims represents JWT claims for approvers
type ApproverClaims struct {
	jwt.RegisteredClaims
	ApproverID   string   `json:"approver_id"`
	Email        string   `json:"email,omitempty"`
	Name         string   `json:"name,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Organization string   `json:"org,omitempty"`
}

// ApproverAuthConfig holds configuration for approver authentication
type ApproverAuthConfig struct {
	// SharedSecret for HMAC verification (legacy)
	SharedSecret string
	// JWTSecret for HS256 JWT verification
	JWTSecret []byte
	// RSAPublicKeyPEM for RS256 JWT verification
	RSAPublicKeyPEM string
	// Ed25519PublicKeyPEM for EdDSA JWT verification
	Ed25519PublicKeyPEM string
	// AllowedIssuers restricts which issuers are trusted
	AllowedIssuers []string
	// RequireJWT forces JWT authentication (disables shared secret)
	RequireJWT bool
}

// verifyApproverJWT validates a JWT token and extracts approver claims
func verifyApproverJWT(tokenString string, config ApproverAuthConfig) (*ApproverClaims, error) {
	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	// Remove "Bearer " prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	claims := &ApproverClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Validate signing algorithm
		switch token.Method.Alg() {
		case "HS256", "HS384", "HS512":
			if len(config.JWTSecret) == 0 {
				return nil, errors.New("HMAC signing not configured")
			}
			return config.JWTSecret, nil
		case "RS256", "RS384", "RS512":
			if config.RSAPublicKeyPEM == "" {
				return nil, errors.New("RSA signing not configured")
			}
			block, _ := pem.Decode([]byte(config.RSAPublicKeyPEM))
			if block == nil {
				return nil, errors.New("failed to parse RSA public key PEM")
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse RSA public key: %v", err)
			}
			return pub, nil
		case "EdDSA":
			if config.Ed25519PublicKeyPEM == "" {
				return nil, errors.New("EdDSA signing not configured")
			}
			block, _ := pem.Decode([]byte(config.Ed25519PublicKeyPEM))
			if block == nil {
				return nil, errors.New("failed to parse Ed25519 public key PEM")
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse Ed25519 public key: %v", err)
			}
			return pub, nil
		default:
			return nil, fmt.Errorf("unsupported signing algorithm: %s", token.Method.Alg())
		}
	})

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %v", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Validate issuer if configured
	if len(config.AllowedIssuers) > 0 {
		issuer, err := claims.GetIssuer()
		if err != nil {
			return nil, errors.New("missing issuer claim")
		}
		allowed := false
		for _, iss := range config.AllowedIssuers {
			if iss == issuer {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("issuer not allowed: %s", issuer)
		}
	}

	// Validate approver_id is present
	if claims.ApproverID == "" && claims.Subject == "" && claims.Email == "" {
		return nil, errors.New("token must contain approver_id, sub, or email claim")
	}

	// Use subject or email as fallback for approver_id
	if claims.ApproverID == "" {
		if claims.Subject != "" {
			claims.ApproverID = claims.Subject
		} else {
			claims.ApproverID = claims.Email
		}
	}

	return claims, nil
}

// authenticateApprover verifies the approver using JWT or shared secret
func authenticateApprover(r *http.Request, config ApproverAuthConfig) (string, error) {
	// Try Authorization header first (JWT)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		claims, err := verifyApproverJWT(authHeader, config)
		if err != nil {
			return "", fmt.Errorf("JWT verification failed: %v", err)
		}
		log.Printf("Approver authenticated via JWT: %s", claims.ApproverID)
		return claims.ApproverID, nil
	}

	// Fall back to shared secret (legacy, unless RequireJWT is set)
	if config.RequireJWT {
		return "", errors.New("JWT authentication required")
	}

	if config.SharedSecret != "" {
		got := strings.TrimSpace(r.Header.Get("X-Approval-Token"))
		if got == "" || got != config.SharedSecret {
			return "", errors.New("invalid approval token")
		}
		// With shared secret, approver must be in request body
		return "", nil // Caller should get approver from request body
	}

	// No authentication configured - allow (for development)
	return "", nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Structured Audit Logging
// ─────────────────────────────────────────────────────────────────────────────

// AuditEvent represents a structured audit log entry
type AuditEvent struct {
	Timestamp           string                 `json:"timestamp"`
	Event               string                 `json:"event"`
	ChallengeID         string                 `json:"challenge_id,omitempty"`
	MandateID           string                 `json:"mandate_id,omitempty"`
	AgentSPIFFEID       string                 `json:"agent_spiffe_id,omitempty"`
	Action              string                 `json:"action,omitempty"`
	Constraints         map[string]interface{} `json:"constraints,omitempty"`
	RiskTier            string                 `json:"risk_tier,omitempty"`
	RequiresDualControl bool                   `json:"requires_dual_control,omitempty"`
	ApproverID          string                 `json:"approver_id,omitempty"`
	ApproversCount      int                    `json:"approvers_count,omitempty"`
	SourceIP            string                 `json:"source_ip,omitempty"`
	Success             bool                   `json:"success"`
	Reason              string                 `json:"reason,omitempty"`
	ExpiresAt           string                 `json:"expires_at,omitempty"`
}

// auditLog outputs a structured JSON audit event to stdout
func auditLog(event AuditEvent) {
	event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, _ := json.Marshal(event)
	fmt.Println(string(data))
}

// ─────────────────────────────────────────────────────────────────────────────
// Data Types
// ─────────────────────────────────────────────────────────────────────────────

type ChallengeRequest struct {
	AgentSPIFFEID string                 `json:"agent_spiffe_id"`
	Act           string                 `json:"act"`
	Con           map[string]interface{} `json:"con"`
	Leg           map[string]interface{} `json:"leg"`
}

// getAccountablePartyID extracts the accountable party ID from the legal basis
func (req *ChallengeRequest) getAccountablePartyID() string {
	if ap, ok := req.Leg["accountable_party"].(map[string]interface{}); ok {
		if id, ok := ap["id"].(string); ok {
			return id
		}
	}
	return ""
}

type Approver struct {
	ID         string    `json:"id"`
	ApprovedAt time.Time `json:"approved_at"`
}

type Challenge struct {
	ID                  string
	Req                 ChallengeRequest
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Approved            bool
	Approvers           []Approver // For dual control: need 2 distinct approvers
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

// ─────────────────────────────────────────────────────────────────────────────
// Input Validation
// ─────────────────────────────────────────────────────────────────────────────

const (
	maxBodySize     = 1 << 20 // 1MB
	maxJSONDepth    = 10
	maxStringLength = 4096
	maxSPIFFELength = 512
	maxActionLength = 256
)

// readJSON reads and validates JSON input with size and depth limits
func readJSON(r *http.Request, out interface{}) error {
	// Limit request body size
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodySize)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(out); err != nil {
		return err
	}

	return nil
}

// validateRequestInput performs security validation on request fields
func validateRequestInput(req *ChallengeRequest) error {
	// Check for null bytes in strings (injection prevention)
	if strings.ContainsRune(req.AgentSPIFFEID, 0) {
		return errors.New("null bytes not allowed in agent_spiffe_id")
	}
	if strings.ContainsRune(req.Act, 0) {
		return errors.New("null bytes not allowed in action")
	}

	// String length limits
	if len(req.AgentSPIFFEID) > maxSPIFFELength {
		return fmt.Errorf("agent_spiffe_id exceeds max length of %d", maxSPIFFELength)
	}
	if len(req.Act) > maxActionLength {
		return fmt.Errorf("action exceeds max length of %d", maxActionLength)
	}

	// Validate JSON depth for constraints
	if err := validateJSONDepth(req.Con, 0); err != nil {
		return fmt.Errorf("constraints: %w", err)
	}
	if err := validateJSONDepth(req.Leg, 0); err != nil {
		return fmt.Errorf("legal_basis: %w", err)
	}

	return nil
}

// validateJSONDepth recursively checks JSON depth
func validateJSONDepth(v interface{}, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("exceeds max depth of %d", maxJSONDepth)
	}

	switch val := v.(type) {
	case map[string]interface{}:
		for k, child := range val {
			// Check key length
			if len(k) > maxStringLength {
				return fmt.Errorf("key too long: %d", len(k))
			}
			// Check for null bytes in keys
			if strings.ContainsRune(k, 0) {
				return errors.New("null bytes not allowed in keys")
			}
			if err := validateJSONDepth(child, depth+1); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, child := range val {
			if err := validateJSONDepth(child, depth+1); err != nil {
				return err
			}
		}
	case string:
		if len(val) > maxStringLength {
			return fmt.Errorf("string value too long: %d", len(val))
		}
		if strings.ContainsRune(val, 0) {
			return errors.New("null bytes not allowed in values")
		}
	}

	return nil
}

// requiresDualControl checks if the request requires two approvers.
// This is determined by:
//  1. leg.dual_control.required == true (explicit in request)
//  2. Action is in the high-risk action list (configurable via env)
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

	// Rate limiting configuration
	rateLimitPerIP := 100   // requests per minute per IP
	rateLimitPerAgent := 20 // requests per minute per agent
	if v := strings.TrimSpace(os.Getenv("RATE_LIMIT_PER_IP")); v != "" {
		fmt.Sscanf(v, "%d", &rateLimitPerIP)
	}
	if v := strings.TrimSpace(os.Getenv("RATE_LIMIT_PER_AGENT")); v != "" {
		fmt.Sscanf(v, "%d", &rateLimitPerAgent)
	}
	ipRateLimiter := NewRateLimiter(rateLimitPerIP, time.Minute)
	agentRateLimiter := NewRateLimiter(rateLimitPerAgent, time.Minute)
	log.Printf("Rate limiting: %d/min per IP, %d/min per agent", rateLimitPerIP, rateLimitPerAgent)

	// Approver authentication configuration
	approverAuthConfig := ApproverAuthConfig{
		SharedSecret: approvalToken,
	}

	// JWT-based approver authentication (HMAC/HS256)
	if secret := strings.TrimSpace(os.Getenv("APPROVER_JWT_SECRET")); secret != "" {
		approverAuthConfig.JWTSecret = []byte(secret)
		log.Printf("Approver JWT authentication enabled (HMAC)")
	}

	// JWT-based approver authentication (RSA/RS256)
	if pubKey := strings.TrimSpace(os.Getenv("APPROVER_RSA_PUBLIC_KEY_PEM")); pubKey != "" {
		approverAuthConfig.RSAPublicKeyPEM = pubKey
		log.Printf("Approver JWT authentication enabled (RSA)")
	}

	// JWT-based approver authentication (EdDSA)
	if pubKey := strings.TrimSpace(os.Getenv("APPROVER_ED25519_PUBLIC_KEY_PEM")); pubKey != "" {
		approverAuthConfig.Ed25519PublicKeyPEM = pubKey
		log.Printf("Approver JWT authentication enabled (EdDSA)")
	}

	// Allowed JWT issuers (comma-separated)
	if issuers := strings.TrimSpace(os.Getenv("APPROVER_JWT_ISSUERS")); issuers != "" {
		for _, iss := range strings.Split(issuers, ",") {
			iss = strings.TrimSpace(iss)
			if iss != "" {
				approverAuthConfig.AllowedIssuers = append(approverAuthConfig.AllowedIssuers, iss)
			}
		}
		log.Printf("Allowed JWT issuers: %v", approverAuthConfig.AllowedIssuers)
	}

	// Require JWT authentication (disable shared secret fallback)
	if v := strings.TrimSpace(os.Getenv("REQUIRE_JWT_AUTH")); strings.ToLower(v) == "true" {
		approverAuthConfig.RequireJWT = true
		log.Printf("JWT authentication required for approvers")
	}

	// Self-approval prevention (default: enabled)
	preventSelfApproval := true
	if v := strings.TrimSpace(os.Getenv("ALLOW_SELF_APPROVAL")); strings.ToLower(v) == "true" {
		preventSelfApproval = false
		log.Printf("WARN: Self-approval is ALLOWED (not recommended)")
	}

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

	// ─────────────────────────────────────────────────────────────────────────
	// Key Rotation Support
	// Supports multiple signing keys for graceful key rotation
	// Primary key is used for signing, all keys are available for verification
	// ─────────────────────────────────────────────────────────────────────────

	type SigningKey struct {
		Kid     string
		Private ed25519.PrivateKey
		Public  ed25519.PublicKey
		Primary bool
	}

	var signingKeys []SigningKey
	var primaryKey *SigningKey

	// Load primary signing key
	pemKey := strings.TrimSpace(os.Getenv("POA_SIGNING_ED25519_PRIVKEY_PEM"))
	if pemKey != "" {
		k, err := decodeEd25519PrivateKeyFromPEM(pemKey)
		if err != nil {
			log.Fatalf("invalid POA_SIGNING_ED25519_PRIVKEY_PEM: %v", err)
		}
		pub := k.Public().(ed25519.PublicKey)
		kid := kidForPublicKey(pub)
		signingKeys = append(signingKeys, SigningKey{
			Kid:     kid,
			Private: k,
			Public:  pub,
			Primary: true,
		})
		log.Printf("Loaded primary signing key (kid=%s)", kid)
	}

	// Load previous key for rotation overlap (verification only)
	pemKeyPrev := strings.TrimSpace(os.Getenv("POA_SIGNING_ED25519_PRIVKEY_PEM_PREV"))
	if pemKeyPrev != "" {
		k, err := decodeEd25519PrivateKeyFromPEM(pemKeyPrev)
		if err != nil {
			log.Printf("WARN: invalid POA_SIGNING_ED25519_PRIVKEY_PEM_PREV: %v (skipping)", err)
		} else {
			pub := k.Public().(ed25519.PublicKey)
			kid := kidForPublicKey(pub)
			signingKeys = append(signingKeys, SigningKey{
				Kid:     kid,
				Private: k,
				Public:  pub,
				Primary: false,
			})
			log.Printf("Loaded previous signing key for rotation (kid=%s)", kid)
		}
	}

	// Load next key for rotation (signing will switch when promoted)
	pemKeyNext := strings.TrimSpace(os.Getenv("POA_SIGNING_ED25519_PRIVKEY_PEM_NEXT"))
	if pemKeyNext != "" {
		k, err := decodeEd25519PrivateKeyFromPEM(pemKeyNext)
		if err != nil {
			log.Printf("WARN: invalid POA_SIGNING_ED25519_PRIVKEY_PEM_NEXT: %v (skipping)", err)
		} else {
			pub := k.Public().(ed25519.PublicKey)
			kid := kidForPublicKey(pub)
			signingKeys = append(signingKeys, SigningKey{
				Kid:     kid,
				Private: k,
				Public:  pub,
				Primary: false,
			})
			log.Printf("Loaded next signing key for rotation (kid=%s)", kid)
		}
	}

	// If no keys configured, generate ephemeral key
	if len(signingKeys) == 0 {
		log.Printf("WARN: POA_SIGNING_ED25519_PRIVKEY_PEM not set; generating ephemeral key (NOT for production)")
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("keygen failed: %v", err)
		}
		pub := k.Public().(ed25519.PublicKey)
		kid := kidForPublicKey(pub)
		signingKeys = append(signingKeys, SigningKey{
			Kid:     kid,
			Private: k,
			Public:  pub,
			Primary: true,
		})
	}

	// Find primary key
	for i := range signingKeys {
		if signingKeys[i].Primary {
			primaryKey = &signingKeys[i]
			break
		}
	}
	if primaryKey == nil {
		primaryKey = &signingKeys[0]
		primaryKey.Primary = true
	}

	// Convenience variables for backward compatibility
	priv := primaryKey.Private
	_ = primaryKey.Public // Used in JWKS
	kid := primaryKey.Kid

	// Build JWKS with all keys for verification
	jwksKeys := make([]map[string]interface{}, len(signingKeys))
	for i, sk := range signingKeys {
		jwksKeys[i] = map[string]interface{}{
			"kty": "OKP",
			"crv": "Ed25519",
			"use": "sig",
			"alg": "EdDSA",
			"kid": sk.Kid,
			"x":   b64url(sk.Public),
		}
	}
	jwks := map[string]interface{}{
		"keys": jwksKeys,
	}
	log.Printf("JWKS contains %d key(s) for verification", len(signingKeys))

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

		// Rate limiting by IP
		clientIP := getClientIP(r)
		if !ipRateLimiter.Allow(clientIP) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		var req ChallengeRequest
		if err := readJSON(r, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		req.AgentSPIFFEID = strings.TrimSpace(req.AgentSPIFFEID)
		req.Act = strings.TrimSpace(req.Act)

		// Input validation (size, depth, null bytes)
		if err := validateRequestInput(&req); err != nil {
			http.Error(w, fmt.Sprintf("input validation failed: %s", err.Error()), http.StatusBadRequest)
			return
		}

		// Strict SPIFFE ID validation
		if err := validateSPIFFEID(req.AgentSPIFFEID); err != nil {
			http.Error(w, fmt.Sprintf("invalid agent_spiffe_id: %s", err.Error()), http.StatusBadRequest)
			return
		}

		// Rate limiting by agent
		if !agentRateLimiter.Allow(req.AgentSPIFFEID) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "rate limit exceeded for agent", http.StatusTooManyRequests)
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

		// Audit: challenge created
		riskTier := "low"
		if needsDualControl {
			riskTier = "high"
		}
		auditLog(AuditEvent{
			Event:               "challenge.created",
			ChallengeID:         c.ID,
			AgentSPIFFEID:       req.AgentSPIFFEID,
			Action:              req.Act,
			Constraints:         req.Con,
			RiskTier:            riskTier,
			RequiresDualControl: needsDualControl,
			SourceIP:            getClientIP(r),
			Success:             true,
			ExpiresAt:           c.ExpiresAt.Format(time.RFC3339),
		})

		writeJSON(w, 200, map[string]interface{}{
			"challenge_id":          c.ID,
			"expires_at":            c.ExpiresAt.Format(time.RFC3339),
			"requires_dual_control": needsDualControl,
			"approvers_needed":      approversNeeded,
			"approval_hint":         "POST /v1/approve with challenge_id and approver identity",
		})
	})

	mux.HandleFunc("/v1/approve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Try JWT authentication first
		jwtApproverID, authErr := authenticateApprover(r, approverAuthConfig)
		if authErr != nil {
			// Check if this is a hard failure (JWT required or JWT provided but invalid)
			if approverAuthConfig.RequireJWT {
				http.Error(w, fmt.Sprintf("authentication failed: %s", authErr.Error()), http.StatusUnauthorized)
				return
			}
			// Check if JWT was provided but failed validation
			if r.Header.Get("Authorization") != "" {
				http.Error(w, fmt.Sprintf("authentication failed: %s", authErr.Error()), http.StatusUnauthorized)
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

		// Use JWT-extracted approver ID if available, otherwise use body
		approverID := jwtApproverID
		if approverID == "" {
			approverID = strings.TrimSpace(body.Approver)
		}
		normalizedApproverID := normalizeApproverID(approverID)

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

		// Self-approval prevention: approver cannot be the accountable party
		if preventSelfApproval {
			accountablePartyID := normalizeApproverID(c.Req.getAccountablePartyID())
			if accountablePartyID != "" && normalizedApproverID == accountablePartyID {
				http.Error(w, "self-approval not allowed: approver cannot be the accountable party", http.StatusForbidden)
				return
			}
		}

		// Check if this approver already approved (case-insensitive)
		for _, a := range c.Approvers {
			if normalizeApproverID(a.ID) == normalizedApproverID {
				http.Error(w, "approver already approved this challenge", http.StatusConflict)
				return
			}
		}

		// Add this approver (store original ID for display, but check normalized)
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

		// Audit: approval recorded
		auditLog(AuditEvent{
			Event:               "challenge.approved",
			ChallengeID:         c.ID,
			AgentSPIFFEID:       c.Req.AgentSPIFFEID,
			Action:              c.Req.Act,
			ApproverID:          approverID,
			ApproversCount:      len(c.Approvers),
			RequiresDualControl: c.RequiresDualControl,
			SourceIP:            getClientIP(r),
			Success:             true,
			Reason:              fmt.Sprintf("approver %d of %d", len(c.Approvers), approversNeeded),
		})

		writeJSON(w, 200, map[string]interface{}{
			"status":           "approved",
			"approvers_count":  len(c.Approvers),
			"approvers_needed": approversNeeded,
			"fully_approved":   c.Approved,
			"approvers":        c.Approvers,
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
				"error":                 "challenge not fully approved",
				"approvers_count":       len(c.Approvers),
				"approvers_needed":      approversNeeded,
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

		// Audit: mandate issued
		auditLog(AuditEvent{
			Event:               "mandate.issued",
			ChallengeID:         c.ID,
			MandateID:           claims.ID,
			AgentSPIFFEID:       c.Req.AgentSPIFFEID,
			Action:              c.Req.Act,
			Constraints:         c.Req.Con,
			RequiresDualControl: c.RequiresDualControl,
			ApproversCount:      len(c.Approvers),
			SourceIP:            getClientIP(r),
			Success:             true,
			ExpiresAt:           exp.Time.Format(time.RFC3339),
		})

		writeJSON(w, 200, map[string]interface{}{
			"token":             jwtStr,
			"expires_at":        exp.Time.Format(time.RFC3339),
			"jti":               claims.ID,
			"dual_control_used": c.RequiresDualControl,
			"approvers_count":   len(c.Approvers),
		})
	})

	// Wrap with security headers middleware
	handler := securityHeaders(mux)

	log.Printf("ATB AgentAuth listening on %s (issuer=%s, kid=%s)", listenAddr, issuer, kid)
	log.Printf("Security: rate limiting enabled, self-approval prevention=%v", preventSelfApproval)
	log.Fatal(http.ListenAndServe(listenAddr, handler))
}
