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
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	Timestamp     time.Time              `json:"ts"`
	RequestID     string                 `json:"request_id,omitempty"`
	MandateID     string                 `json:"poa_jti,omitempty"`
	AgentIdentity string                 `json:"agent_identity"`
	Action        string                 `json:"action,omitempty"`
	Constraints   map[string]interface{} `json:"constraints,omitempty"`
	Decision      string                 `json:"decision"` // allow|deny|error
	Reason        string                 `json:"reason"`
	Target        string                 `json:"target_service"`
	Method        string                 `json:"method"`
	Path          string                 `json:"path"`
}

type OPAClient struct {
	URL  string
	HTTP *http.Client
}

type OPAInput struct {
	Agent   map[string]interface{} `json:"agent"`
	PoA     map[string]interface{} `json:"poa"`
	Request map[string]interface{} `json:"request"`
	Policy  map[string]interface{} `json:"policy,omitempty"`
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

func peerSPIFFEIDFromVerifiedCert(r *http.Request) (string, error) {
	if r.TLS == nil {
		return "", errors.New("missing TLS state")
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("missing client certificate")
	}
	cert := r.TLS.PeerCertificates[0]
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

func verifyPoAJWT(tokenStr string, maxTTLSec int64, verifyKey interface{}, allowedAlgs []string) (*PoAClaims, error) {
	claims := &PoAClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithLeeway(10*time.Second),
	)

	tok, err := parser.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
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
	certFile := strings.TrimSpace(os.Getenv("TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("TLS_KEY_FILE"))
	if certFile == "" || keyFile == "" {
		log.Fatal("TLS_CERT_FILE and TLS_KEY_FILE are required")
	}

	maxTTLSec := envInt64("POA_MAX_TTL_SECONDS", 300)
	verifyKey, allowedAlgs, err := loadVerifyKey()
	authConfigured := true
	if err != nil {
		authConfigured = false
		log.Printf("WARN: PoA verification not configured; gateway will deny protected requests (%v)", err)
	}

	targetURL := mustParseURL(upstream)
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	httpClient := &http.Client{Timeout: 1500 * time.Millisecond}
	opa := &OPAClient{URL: opaURL, HTTP: httpClient}
	opaHealthURL := strings.TrimSpace(os.Getenv("OPA_HEALTH_URL"))
	if opaHealthURL == "" {
		opaHealthURL = deriveOPAHealthURL(opaURL)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now().UTC()
		reqID := r.Header.Get("X-Request-ID")

		agentSPIFFE, err := peerSPIFFEIDFromVerifiedCert(r)
		if err != nil {
			brokerRequestsTotal.WithLabelValues("deny", "").Inc()
			http.Error(w, "mTLS client cert with SPIFFE ID required", http.StatusUnauthorized)
			return
		}

		if !authConfigured {
			audit(AuditEvent{Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE, Decision: "deny", Reason: "poa_verification_not_configured", Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", "").Inc()
			http.Error(w, "authorization not configured", http.StatusServiceUnavailable)
			return
		}

		poaToken := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if poaToken == "" {
			poaToken = strings.TrimSpace(r.Header.Get("X-PoA-Token"))
		}
		if poaToken == "" {
			audit(AuditEvent{Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE, Decision: "deny", Reason: "missing_poa", Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", "").Inc()
			http.Error(w, "missing PoA token", http.StatusUnauthorized)
			return
		}

		claims, err := verifyPoAJWT(poaToken, maxTTLSec, verifyKey, allowedAlgs)
		if err != nil {
			audit(AuditEvent{Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE, Decision: "deny", Reason: "poa_invalid:" + err.Error(), Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", "").Inc()
			http.Error(w, "invalid PoA", http.StatusForbidden)
			return
		}

		if claims.Subject != agentSPIFFE {
			audit(AuditEvent{Timestamp: start, RequestID: reqID, MandateID: claims.ID, AgentIdentity: agentSPIFFE, Action: claims.Act, Constraints: claims.Con, Decision: "deny", Reason: "sub_mismatch", Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", claims.Act).Inc()
			http.Error(w, "PoA subject mismatch", http.StatusForbidden)
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
			audit(AuditEvent{Timestamp: start, RequestID: reqID, MandateID: claims.ID, AgentIdentity: agentSPIFFE, Action: claims.Act, Constraints: claims.Con, Decision: "deny", Reason: why, Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", claims.Act).Inc()
			http.Error(w, "blocked by semantic firewall", http.StatusForbidden)
			return
		}

		input := OPAInput{
			Agent: map[string]interface{}{"spiffe_id": agentSPIFFE},
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
				"method": r.Method,
				"path":   r.URL.Path,
				"params": params,
			},
			Policy: map[string]interface{}{"max_ttl_seconds": maxTTLSec},
		}

		allow, reason, err := opa.Decide(r.Context(), input)
		if err != nil {
			audit(AuditEvent{Timestamp: start, RequestID: reqID, MandateID: claims.ID, AgentIdentity: agentSPIFFE, Action: claims.Act, Constraints: claims.Con, Decision: "error", Reason: "opa_error:" + err.Error(), Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("error", claims.Act).Inc()
			http.Error(w, "policy evaluation error", http.StatusInternalServerError)
			return
		}
		if !allow {
			if reason == "" {
				reason = "policy_denied"
			}
			audit(AuditEvent{Timestamp: start, RequestID: reqID, MandateID: claims.ID, AgentIdentity: agentSPIFFE, Action: claims.Act, Constraints: claims.Con, Decision: "deny", Reason: reason, Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
			brokerRequestsTotal.WithLabelValues("deny", claims.Act).Inc()
			http.Error(w, "policy denied", http.StatusForbidden)
			return
		}

		audit(AuditEvent{Timestamp: start, RequestID: reqID, MandateID: claims.ID, AgentIdentity: agentSPIFFE, Action: claims.Act, Constraints: claims.Con, Decision: "allow", Reason: "policy_allow", Target: targetURL.String(), Method: r.Method, Path: r.URL.Path})
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
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequireAnyClientCert,
		},
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
