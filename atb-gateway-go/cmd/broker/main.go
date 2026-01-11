package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var (
	brokerRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "atb_broker_requests_total",
			Help: "Total number of brokered requests handled by the gateway.",
		},
		[]string{"decision", "action"},
	)
)

func init() {
	prometheus.MustRegister(brokerRequestsTotal)
}

type PoAClaims struct {
	Act string                 `json:"act"`
	Con map[string]interface{} `json:"con"`
	Leg map[string]interface{} `json:"leg"`
	jwt.RegisteredClaims
}

type AuditEvent struct {
	Timestamp        time.Time              `json:"ts"`
	RequestID        string                 `json:"request_id,omitempty"`
	MandateID        string                 `json:"poa_jti,omitempty"`
	AgentIdentity    string                 `json:"agent_identity"`
	PlatformIdentity string                 `json:"platform_identity,omitempty"`
	Action           string                 `json:"action,omitempty"`
	Constraints      map[string]interface{} `json:"constraints,omitempty"`
	Decision         string                 `json:"decision"` // allow|deny|error
	Reason           string                 `json:"reason"`
	Target           string                 `json:"target_service"`
	Method           string                 `json:"method"`
	Path             string                 `json:"path"`
}

type OPAClient struct {
	URL  string
	HTTP *http.Client
}

type OPAInput struct {
	Agent    map[string]interface{} `json:"agent"`
	Platform map[string]interface{} `json:"platform,omitempty"`
	PoA      map[string]interface{} `json:"poa"`
	Request  map[string]interface{} `json:"request"`
	Policy   map[string]interface{} `json:"policy,omitempty"`
}

func (c *OPAClient) Decide(ctx context.Context, input OPAInput) (bool, string, error) {
	body, err := json.Marshal(map[string]interface{}{"input": input})
	if err != nil {
		return false, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return false, "", fmt.Errorf("OPA status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var decoded struct {
		Result interface{} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return false, "", err
	}

	// Support either boolean result or object {allow, reason}.
	switch v := decoded.Result.(type) {
	case bool:
		return v, "", nil
	case map[string]interface{}:
		allow, _ := v["allow"].(bool)
		reason, _ := v["reason"].(string)
		return allow, reason, nil
	default:
		return false, "", fmt.Errorf("unexpected OPA result type: %T", decoded.Result)
	}
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		log.Fatalf("invalid URL %q: %v", raw, err)
	}
	return u
}

func deriveOPAHealthURL(opaDecisionURL string) string {
	u, err := url.Parse(strings.TrimSpace(opaDecisionURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "http://localhost:8181/health"
	}
	u.Path = "/health"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func checkHTTPHealth(ctx context.Context, client *http.Client, healthURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health check status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func envInt64(name string, def int64) int64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	var out int64
	_, err := fmt.Sscanf(v, "%d", &out)
	if err != nil {
		return def
	}
	return out
}

func envBool(name string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "t", "yes", "y", "on":
		return true
	case "0", "false", "f", "no", "n", "off":
		return false
	default:
		return def
	}
}

func peerSPIFFEIDFromVerifiedCert(r *http.Request) (string, error) {
	if r.TLS == nil {
		return "", errors.New("missing TLS state")
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("missing client certificate")
	}
	cert := r.TLS.PeerCertificates[0]
	if cert != nil {
		if id, err := x509svid.IDFromCert(cert); err == nil {
			return id.String(), nil
		}
	}
	for _, uri := range cert.URIs {
		if uri != nil && strings.EqualFold(uri.Scheme, "spiffe") {
			return uri.String(), nil
		}
	}
	return "", errors.New("no SPIFFE URI SAN in client certificate")
}

func loadVerifyKey() (interface{}, []string, error) {
	pemText := strings.TrimSpace(os.Getenv("POA_VERIFY_PUBKEY_PEM"))
	if pemText == "" {
		return nil, nil, errors.New("POA_VERIFY_PUBKEY_PEM not set")
	}
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, nil, errors.New("failed to decode PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Some keys may be in certificate form.
		if cert, certErr := x509.ParseCertificate(block.Bytes); certErr == nil {
			pub = cert.PublicKey
			err = nil
		} else {
			return nil, nil, err
		}
	}
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return k, []string{"EdDSA"}, nil
	case *rsa.PublicKey:
		return k, []string{"RS256"}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

type jwksCache struct {
	url      string
	http     *http.Client
	cacheTTL time.Duration

	mu        sync.RWMutex
	keysByKID map[string]interface{}
	lastFetch time.Time
}

type replayCache struct {
	mu         sync.Mutex
	seenUntil  map[string]time.Time
	maxEntries int
}

func newReplayCache(maxEntries int) *replayCache {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	return &replayCache{seenUntil: map[string]time.Time{}, maxEntries: maxEntries}
}

func (c *replayCache) markIfFresh(jti string, until time.Time, now time.Time) bool {
	if strings.TrimSpace(jti) == "" {
		return true
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Opportunistic cleanup.
	for k, exp := range c.seenUntil {
		if !exp.After(now) {
			delete(c.seenUntil, k)
		}
	}

	if exp, ok := c.seenUntil[jti]; ok && exp.After(now) {
		return false
	}

	c.seenUntil[jti] = until

	// Cap memory growth.
	if len(c.seenUntil) > c.maxEntries {
		for k := range c.seenUntil {
			delete(c.seenUntil, k)
			if len(c.seenUntil) <= c.maxEntries {
				break
			}
		}
	}

	return true
}

// platformVerifier validates OIDC tokens from agent platforms (e.g., Entra ID).
type platformVerifier struct {
	jwks          *jwksCache
	issuer        string
	audience      string
	allowedAlgs   []string
	requirePlatID bool
}

func newPlatformVerifier(jwksURL, issuer, audience string, httpClient *http.Client, cacheTTL time.Duration, required bool) *platformVerifier {
	if strings.TrimSpace(jwksURL) == "" {
		return &platformVerifier{requirePlatID: required}
	}
	return &platformVerifier{
		jwks:          newJWKSCache(jwksURL, httpClient, cacheTTL),
		issuer:        strings.TrimSpace(issuer),
		audience:      strings.TrimSpace(audience),
		allowedAlgs:   []string{"RS256", "ES256"},
		requirePlatID: required,
	}
}

type platformClaims struct {
	Sub   string `json:"sub"`
	Oid   string `json:"oid,omitempty"`
	AppID string `json:"appid,omitempty"`
	Azp   string `json:"azp,omitempty"`
	jwt.RegisteredClaims
}

func (p *platformVerifier) verify(ctx context.Context, tokenRaw string) (*platformClaims, error) {
	if p.jwks == nil {
		if p.requirePlatID {
			return nil, errors.New("platform identity verification not configured")
		}
		return nil, nil
	}
	if strings.TrimSpace(tokenRaw) == "" {
		if p.requirePlatID {
			return nil, errors.New("missing platform identity token")
		}
		return nil, nil
	}

	token, err := jwt.ParseWithClaims(tokenRaw, &platformClaims{}, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid in token header")
		}
		key, err := p.jwks.get(context.Background(), kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}, jwt.WithValidMethods(p.allowedAlgs), jwt.WithIssuer(p.issuer), jwt.WithAudience(p.audience), jwt.WithLeeway(30*time.Second))
	if err != nil {
		return nil, fmt.Errorf("platform token invalid: %w", err)
	}
	claims, ok := token.Claims.(*platformClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid platform token claims")
	}
	return claims, nil
}

func newJWKSCache(url string, httpClient *http.Client, cacheTTL time.Duration) *jwksCache {
	return &jwksCache{
		url:       url,
		http:      httpClient,
		cacheTTL:  cacheTTL,
		keysByKID: map[string]interface{}{},
	}
}

func (c *jwksCache) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("jwks status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return err
	}
	keys := map[string]interface{}{}
	for _, k := range set.Keys {
		if k.Key == nil {
			continue
		}
		kid := strings.TrimSpace(k.KeyID)
		if kid == "" {
			continue
		}
		keys[kid] = k.Key
	}
	if len(keys) == 0 {
		return errors.New("jwks contained no usable keys")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keysByKID = keys
	c.lastFetch = time.Now().UTC()
	return nil
}

func (c *jwksCache) get(ctx context.Context, kid string) (interface{}, error) {
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return nil, errors.New("missing kid")
	}
	c.mu.RLock()
	key, ok := c.keysByKID[kid]
	last := c.lastFetch
	ttl := c.cacheTTL
	c.mu.RUnlock()

	if ok && ttl > 0 && time.Since(last) < ttl {
		return key, nil
	}
	// Refresh on miss or staleness.
	ctx2, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	if err := c.refresh(ctx2); err != nil {
		if ok {
			// Serve stale key if we had it.
			return key, nil
		}
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok = c.keysByKID[kid]
	if !ok {
		return nil, fmt.Errorf("kid not found: %s", kid)
	}
	return key, nil
}

func loadPoAKeyFunc(httpClient *http.Client) (jwt.Keyfunc, []string, error) {
	jwksURL := strings.TrimSpace(os.Getenv("POA_JWKS_URL"))
	if jwksURL != "" {
		cacheSec := envInt64("POA_JWKS_CACHE_SECONDS", 300)
		if cacheSec < 0 {
			cacheSec = 0
		}
		cache := newJWKSCache(jwksURL, httpClient, time.Duration(cacheSec)*time.Second)
		// Eager fetch so we fail fast at startup.
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		if err := cache.refresh(ctx); err != nil {
			return nil, nil, fmt.Errorf("jwks refresh failed: %w", err)
		}
		keyFunc := func(t *jwt.Token) (interface{}, error) {
			kid, _ := t.Header["kid"].(string)
			return cache.get(context.Background(), kid)
		}
		return keyFunc, []string{"EdDSA", "RS256"}, nil
	}

	verifyKey, allowedAlgs, err := loadVerifyKey()
	if err != nil {
		return nil, nil, err
	}
	keyFunc := func(t *jwt.Token) (interface{}, error) { return verifyKey, nil }
	return keyFunc, allowedAlgs, nil
}

func verifyPoAJWT(tokenStr string, maxTTLSec int64, keyFunc jwt.Keyfunc, allowedAlgs []string) (*PoAClaims, error) {
	claims := &PoAClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithLeeway(10*time.Second),
	)

	tok, err := parser.ParseWithClaims(tokenStr, claims, keyFunc)
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("token invalid")
	}
	if claims.IssuedAt == nil || claims.ExpiresAt == nil {
		return nil, errors.New("missing iat/exp")
	}
	if claims.ID == "" {
		return nil, errors.New("missing jti")
	}
	if claims.Subject == "" {
		return nil, errors.New("missing sub")
	}
	if strings.TrimSpace(claims.Act) == "" {
		return nil, errors.New("missing act")
	}
	if claims.Con == nil {
		return nil, errors.New("missing con")
	}
	if claims.Leg == nil {
		return nil, errors.New("missing leg")
	}

	issued := claims.IssuedAt.Time.Unix()
	exp := claims.ExpiresAt.Time.Unix()
	ttl := exp - issued
	if ttl <= 0 {
		return nil, errors.New("invalid ttl")
	}
	if ttl > 900 {
		return nil, errors.New("ttl exceeds 15 minute hard cap")
	}
	if ttl > maxTTLSec {
		return nil, fmt.Errorf("ttl exceeds configured max (%ds)", maxTTLSec)
	}
	if time.Now().Unix() > exp {
		return nil, errors.New("expired")
	}
	return claims, nil
}

func semanticGuardrails(params map[string]interface{}) (bool, string) {
	// Placeholder for NeMo Guardrails.
	bad := []string{"ignore previous", "disable safety", "exfiltrate", "curl http", "drop table"}
	for _, v := range params {
		s, ok := v.(string)
		if !ok {
			continue
		}
		low := strings.ToLower(s)
		for _, b := range bad {
			if strings.Contains(low, b) {
				return false, "semantic_firewall_block"
			}
		}
	}
	return true, ""
}

func audit(ev AuditEvent) {
	_ = json.NewEncoder(os.Stdout).Encode(ev)
}

func main() {
	upstream := strings.TrimSpace(os.Getenv("UPSTREAM_URL"))
	if upstream == "" {
		log.Fatal("UPSTREAM_URL is required")
	}
	opaURL := strings.TrimSpace(os.Getenv("OPA_DECISION_URL"))
	if opaURL == "" {
		opaURL = "http://localhost:8181/v1/data/atb/poa/decision"
	}
	listenAddr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	if listenAddr == "" {
		listenAddr = ":8443"
	}
	httpListenAddr := strings.TrimSpace(os.Getenv("HTTP_LISTEN_ADDR"))
	if httpListenAddr == "" {
		httpListenAddr = ":8080"
	}
	spiffeEndpointSocket := strings.TrimSpace(os.Getenv("SPIFFE_ENDPOINT_SOCKET"))
	certFile := strings.TrimSpace(os.Getenv("TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("TLS_KEY_FILE"))
	clientCAFile := strings.TrimSpace(os.Getenv("TLS_CLIENT_CA_FILE"))
	if spiffeEndpointSocket == "" && (certFile == "" || keyFile == "") {
		log.Fatal("either SPIFFE_ENDPOINT_SOCKET must be set (Workload API) or TLS_CERT_FILE/TLS_KEY_FILE must be provided")
	}

	maxTTLSec := envInt64("POA_MAX_TTL_SECONDS", 300)
	allowUnmandatedLowRisk := envBool("ALLOW_UNMANDATED_LOW_RISK", false)
	poaSingleUse := envBool("POA_SINGLE_USE", false)
	poaReplayCacheMax := int(envInt64("POA_REPLAY_CACHE_MAX", 10000))
	replay := newReplayCache(poaReplayCacheMax)

	// Platform identity (OIDC) verification – e.g., Entra ID access tokens.
	platJWKSURL := strings.TrimSpace(os.Getenv("PLATFORM_JWKS_URL"))
	platIssuer := strings.TrimSpace(os.Getenv("PLATFORM_ISSUER"))
	platAudience := strings.TrimSpace(os.Getenv("PLATFORM_AUDIENCE"))
	platRequired := envBool("PLATFORM_IDENTITY_REQUIRED", false)
	platCacheSec := envInt64("PLATFORM_JWKS_CACHE_SECONDS", 300)

	targetURL := mustParseURL(upstream)
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	httpClient := &http.Client{Timeout: 1500 * time.Millisecond}

	platVerifier := newPlatformVerifier(platJWKSURL, platIssuer, platAudience, httpClient, time.Duration(platCacheSec)*time.Second, platRequired)

	opa := &OPAClient{URL: opaURL, HTTP: httpClient}
	keyFunc, allowedAlgs, err := loadPoAKeyFunc(httpClient)
	authConfigured := true
	if err != nil {
		authConfigured = false
		log.Printf("WARN: PoA verification not configured; gateway will deny protected requests (%v)", err)
	}
	opaHealthURL := strings.TrimSpace(os.Getenv("OPA_HEALTH_URL"))
	if opaHealthURL == "" {
		opaHealthURL = deriveOPAHealthURL(opaURL)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now().UTC()
		reqID := r.Header.Get("X-Request-ID")

		actionHeader := strings.TrimSpace(r.Header.Get("X-ATB-Action"))
		if actionHeader == "" {
			actionHeader = strings.TrimSpace(r.Header.Get("X-Action"))
		}
		actionForLogs := actionHeader
		if actionForLogs == "" {
			actionForLogs = strings.TrimSpace(r.Method + " " + r.URL.Path)
		}

		agentSPIFFE, err := peerSPIFFEIDFromVerifiedCert(r)
		if err != nil {
			brokerRequestsTotal.WithLabelValues("deny", "").Inc()
			http.Error(w, "mTLS client cert with SPIFFE ID required", http.StatusUnauthorized)
			return
		}

		// Validate platform identity token (e.g., Entra ID) if configured.
		platToken := strings.TrimSpace(r.Header.Get("X-Platform-Token"))
		platClaims, platErr := platVerifier.verify(r.Context(), platToken)
		if platErr != nil {
			audit(AuditEvent{Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE, Decision: "deny", Reason: "platform_identity_invalid:" + platErr.Error(), Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", "").Inc()
			http.Error(w, "invalid platform identity", http.StatusUnauthorized)
			return
		}
		platformID := ""
		var platformData map[string]interface{}
		if platClaims != nil {
			platformID = platClaims.Sub
			if platformID == "" {
				platformID = platClaims.Oid
			}
			platformData = map[string]interface{}{
				"sub":   platClaims.Sub,
				"oid":   platClaims.Oid,
				"appid": platClaims.AppID,
				"azp":   platClaims.Azp,
				"iss":   platClaims.Issuer,
				"aud":   platClaims.Audience,
			}
		}

		if !authConfigured {
			audit(AuditEvent{Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE, PlatformIdentity: platformID, Decision: "deny", Reason: "poa_verification_not_configured", Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", "").Inc()
			http.Error(w, "authorization not configured", http.StatusServiceUnavailable)
			return
		}

		bodyBytes, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		params := map[string]interface{}{}
		if len(bodyBytes) > 0 {
			_ = json.Unmarshal(bodyBytes, &params)
		}

		if ok, why := semanticGuardrails(params); !ok {
			audit(AuditEvent{Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE, Action: actionForLogs, Decision: "deny", Reason: why, Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", actionForLogs).Inc()
			http.Error(w, "blocked by semantic firewall", http.StatusForbidden)
			return
		}

		poaToken := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if poaToken == "" {
			poaToken = strings.TrimSpace(r.Header.Get("X-PoA-Token"))
		}
		if poaToken == "" {
			if !allowUnmandatedLowRisk {
				audit(AuditEvent{Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE, PlatformIdentity: platformID, Action: actionForLogs, Decision: "deny", Reason: "missing_poa", Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
				brokerRequestsTotal.WithLabelValues("deny", actionForLogs).Inc()
				http.Error(w, "missing PoA token", http.StatusUnauthorized)
				return
			}

			input := OPAInput{
				Agent:    map[string]interface{}{"spiffe_id": agentSPIFFE},
				Platform: platformData,
				PoA:      map[string]interface{}{},
				Request: map[string]interface{}{
					"action": actionHeader,
					"method": r.Method,
					"path":   r.URL.Path,
					"params": params,
				},
				Policy: map[string]interface{}{"max_ttl_seconds": maxTTLSec},
			}

			allow, reason, err := opa.Decide(r.Context(), input)
			if err != nil {
				audit(AuditEvent{Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE, PlatformIdentity: platformID, Action: actionForLogs, Decision: "error", Reason: "opa_error:" + err.Error(), Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
				brokerRequestsTotal.WithLabelValues("error", actionForLogs).Inc()
				http.Error(w, "policy evaluation error", http.StatusInternalServerError)
				return
			}
			if !allow {
				audit(AuditEvent{Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE, PlatformIdentity: platformID, Action: actionForLogs, Decision: "deny", Reason: reason, Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
				brokerRequestsTotal.WithLabelValues("deny", actionForLogs).Inc()
				http.Error(w, "PoA required", http.StatusUnauthorized)
				return
			}

			audit(AuditEvent{Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE, PlatformIdentity: platformID, Action: actionForLogs, Decision: "allow", Reason: reason, Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("allow", actionForLogs).Inc()
			proxy.ServeHTTP(w, r)
			return
		}

		claims, err := verifyPoAJWT(poaToken, maxTTLSec, keyFunc, allowedAlgs)
		if err != nil {
			audit(AuditEvent{Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE, PlatformIdentity: platformID, Action: actionForLogs, Decision: "deny", Reason: "poa_invalid:" + err.Error(), Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", actionForLogs).Inc()
			http.Error(w, "invalid PoA", http.StatusForbidden)
			return
		}

		if claims.Subject != agentSPIFFE {
			audit(AuditEvent{Timestamp: start, RequestID: reqID, MandateID: claims.ID, AgentIdentity: agentSPIFFE, PlatformIdentity: platformID, Action: claims.Act, Constraints: claims.Con, Decision: "deny", Reason: "sub_mismatch", Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", claims.Act).Inc()
			http.Error(w, "PoA subject mismatch", http.StatusForbidden)
			return
		}

		if actionHeader != "" && actionHeader != claims.Act {
			audit(AuditEvent{Timestamp: start, RequestID: reqID, MandateID: claims.ID, AgentIdentity: agentSPIFFE, PlatformIdentity: platformID, Action: claims.Act, Constraints: claims.Con, Decision: "deny", Reason: "action_mismatch", Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", claims.Act).Inc()
			http.Error(w, "PoA action mismatch", http.StatusForbidden)
			return
		}

		input := OPAInput{
			Agent:    map[string]interface{}{"spiffe_id": agentSPIFFE},
			Platform: platformData,
			PoA: map[string]interface{}{
				"sub": claims.Subject,
				"act": claims.Act,
				"con": claims.Con,
				"leg": claims.Leg,
				"iat": claims.IssuedAt.Time.Unix(),
				"exp": claims.ExpiresAt.Time.Unix(),
				"jti": claims.ID,
			},
			Request: map[string]interface{}{
				"action": actionHeader,
				"method": r.Method,
				"path":   r.URL.Path,
				"params": params,
			},
			Policy: map[string]interface{}{"max_ttl_seconds": maxTTLSec},
		}

		allow, reason, err := opa.Decide(r.Context(), input)
		if err != nil {
			audit(AuditEvent{Timestamp: start, RequestID: reqID, MandateID: claims.ID, AgentIdentity: agentSPIFFE, PlatformIdentity: platformID, Action: claims.Act, Constraints: claims.Con, Decision: "error", Reason: "opa_error:" + err.Error(), Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("error", claims.Act).Inc()
			http.Error(w, "policy evaluation error", http.StatusInternalServerError)
			return
		}
		if !allow {
			if reason == "" {
				reason = "policy_denied"
			}
			audit(AuditEvent{Timestamp: start, RequestID: reqID, MandateID: claims.ID, AgentIdentity: agentSPIFFE, PlatformIdentity: platformID, Action: claims.Act, Constraints: claims.Con, Decision: "deny", Reason: reason, Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", claims.Act).Inc()
			http.Error(w, "policy denied", http.StatusForbidden)
			return
		}

		if poaSingleUse {
			now := time.Now().UTC()
			until := claims.ExpiresAt.Time.Add(30 * time.Second)
			if !replay.markIfFresh(claims.ID, until, now) {
				audit(AuditEvent{Timestamp: start, RequestID: reqID, MandateID: claims.ID, AgentIdentity: agentSPIFFE, PlatformIdentity: platformID, Action: claims.Act, Constraints: claims.Con, Decision: "deny", Reason: "poa_replay_detected", Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
				brokerRequestsTotal.WithLabelValues("deny", claims.Act).Inc()
				http.Error(w, "PoA replay detected", http.StatusForbidden)
				return
			}
		}

		audit(AuditEvent{Timestamp: start, RequestID: reqID, MandateID: claims.ID, AgentIdentity: agentSPIFFE, PlatformIdentity: platformID, Action: claims.Act, Constraints: claims.Con, Decision: "allow", Reason: "policy_allow", Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
		brokerRequestsTotal.WithLabelValues("allow", claims.Act).Inc()
		proxy.ServeHTTP(w, r)
	})

	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	healthMux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 1200*time.Millisecond)
		defer cancel()
		if err := checkHTTPHealth(ctx, httpClient, opaHealthURL); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ready\n"))
	})
	healthMux.Handle("/metrics", promhttp.Handler())

	mtlsServer := &http.Server{
		Addr:              listenAddr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         nil,
	}

	if spiffeEndpointSocket != "" {
		// Secret-less mode: server and client identities come from the SPIFFE Workload API.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(spiffeEndpointSocket)))
		if err != nil {
			log.Fatalf("failed to create X509Source: %v", err)
		}
		defer source.Close()

		mtlsServer.TLSConfig = tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())
		mtlsServer.TLSConfig.MinVersion = tls.VersionTLS12
		// When using Workload API, certFile/keyFile are not needed.
		certFile = ""
		keyFile = ""
	} else {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if clientCAFile != "" {
			b, err := os.ReadFile(clientCAFile)
			if err != nil {
				log.Fatalf("failed to read TLS_CLIENT_CA_FILE: %v", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(b) {
				log.Fatalf("failed to parse TLS_CLIENT_CA_FILE PEM")
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			log.Printf("WARN: TLS_CLIENT_CA_FILE not set; client certs will not be verified (dev-only)")
			tlsCfg.ClientAuth = tls.RequireAnyClientCert
		}
		mtlsServer.TLSConfig = tlsCfg
	}

	httpServer := &http.Server{
		Addr:              httpListenAddr,
		Handler:           healthMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)

	go func() {
		log.Printf("ATB Broker health listening on %s", httpListenAddr)
		errCh <- httpServer.ListenAndServe()
	}()
	go func() {
		log.Printf("ATB Broker Gateway listening on %s -> %s", listenAddr, targetURL.String())
		errCh <- mtlsServer.ListenAndServeTLS(certFile, keyFile)
	}()

	log.Fatal(<-errCh)
}
