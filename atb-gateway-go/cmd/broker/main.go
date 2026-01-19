package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
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

	// Enhanced OPA metrics
	opaEvaluationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "atb_opa_evaluation_duration_seconds",
			Help:    "Time spent evaluating OPA policy decisions.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 15), // 100µs to 1.6s
		},
		[]string{"action"},
	)

	opaDecisionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "atb_opa_decisions_total",
			Help: "Total OPA policy decisions by outcome, tier, and reason.",
		},
		[]string{"decision", "risk_tier", "reason"},
	)

	opaRiskTierUsage = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "atb_risk_tier_requests_total",
			Help: "Total requests by risk tier.",
		},
		[]string{"tier"},
	)

	opaDenialReasons = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "atb_denial_reasons_total",
			Help: "Total denials by denial reason category.",
		},
		[]string{"reason"},
	)

	opaTimePolicyViolations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "atb_time_policy_violations_total",
			Help: "Total time-based policy violations by type.",
		},
		[]string{"violation_type"},
	)

	opaActivePoAs = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "atb_active_poas",
			Help: "Number of currently active PoAs (estimated from recent requests).",
		},
	)

	opaApprovalExpiry = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "atb_approval_time_since_seconds",
			Help:    "Time since approval was granted (for tracking expiration trends).",
			Buckets: []float64{60, 120, 180, 240, 300, 360, 420, 480, 540, 600}, // 1-10 minutes
		},
		[]string{"tier"},
	)
)

func init() {
	prometheus.MustRegister(brokerRequestsTotal)
	prometheus.MustRegister(opaEvaluationDuration, opaDecisionsTotal, opaRiskTierUsage)
	prometheus.MustRegister(opaDenialReasons, opaTimePolicyViolations)
	prometheus.MustRegister(opaActivePoAs, opaApprovalExpiry)
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

// AuditSink defines an interface for sending audit events
type AuditSink interface {
	Send(ctx context.Context, ev AuditEvent) error
	Close() error
}

// StdoutSink writes audit events to stdout (default)
type StdoutSink struct{}

func (s *StdoutSink) Send(_ context.Context, ev AuditEvent) error {
	return json.NewEncoder(os.Stdout).Encode(ev)
}

func (s *StdoutSink) Close() error { return nil }

// HTTPSink sends audit events to an HTTP endpoint (e.g., SIEM, Log Analytics)
type HTTPSink struct {
	url        string
	authHeader string // e.g., "Bearer <token>" or "SharedKey <workspace-id>:<sig>"
	httpClient *http.Client
	queue      chan AuditEvent
	wg         sync.WaitGroup
	stopCh     chan struct{}
}

func newHTTPSink(sinkURL, authHeader string, batchSize int, flushInterval time.Duration) *HTTPSink {
	if batchSize <= 0 {
		batchSize = 100
	}
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second
	}
	s := &HTTPSink{
		url:        sinkURL,
		authHeader: authHeader,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		queue:      make(chan AuditEvent, 10000),
		stopCh:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.worker(batchSize, flushInterval)
	return s
}

func (s *HTTPSink) Send(_ context.Context, ev AuditEvent) error {
	select {
	case s.queue <- ev:
		return nil
	default:
		// Queue full, drop event but log warning
		log.Printf("WARN: audit queue full, dropping event request_id=%s", ev.RequestID)
		return errors.New("audit queue full")
	}
}

func (s *HTTPSink) worker(batchSize int, flushInterval time.Duration) {
	defer s.wg.Done()
	batch := make([]AuditEvent, 0, batchSize)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.sendBatch(batch); err != nil {
			log.Printf("ERROR: failed to send audit batch: %v", err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case ev := <-s.queue:
			batch = append(batch, ev)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.stopCh:
			// Drain remaining events
			for {
				select {
				case ev := <-s.queue:
					batch = append(batch, ev)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *HTTPSink) sendBatch(events []AuditEvent) error {
	body, err := json.Marshal(events)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.authHeader != "" {
		req.Header.Set("Authorization", s.authHeader)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("audit sink returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (s *HTTPSink) Close() error {
	close(s.stopCh)
	s.wg.Wait()
	return nil
}

// MultiSink sends to multiple sinks (e.g., stdout + HTTP)
type MultiSink struct {
	sinks []AuditSink
}

func (m *MultiSink) Send(ctx context.Context, ev AuditEvent) error {
	var lastErr error
	for _, sink := range m.sinks {
		if err := sink.Send(ctx, ev); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (m *MultiSink) Close() error {
	var lastErr error
	for _, sink := range m.sinks {
		if err := sink.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// ──────────────────────────────────────────────────────────────────────────────
// Immutable Storage Sink for write-once audit logs with tamper-evidence
// Supports Azure Blob (immutable policy), AWS S3 (Object Lock), or generic HTTP
// ──────────────────────────────────────────────────────────────────────────────

var (
	auditStorageWritesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "atb_audit_storage_writes_total",
			Help: "Total audit writes to immutable storage.",
		},
		[]string{"backend", "status"},
	)
	auditStorageLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "atb_audit_storage_latency_seconds",
			Help:    "Latency for audit writes to immutable storage.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"backend"},
	)
)

func init() {
	prometheus.MustRegister(auditStorageWritesTotal, auditStorageLatency)
}

// ImmutableStorageSink writes audit events to immutable (WORM) storage.
// Supports:
// - Azure Blob Storage (with immutability policy / legal hold)
// - AWS S3 (with Object Lock in GOVERNANCE or COMPLIANCE mode)
// - Generic HTTP endpoint with HMAC signature for integrity
type ImmutableStorageSink struct {
	backend       string // "azure", "s3", "http"
	containerURL  string // Base URL: https://<account>.blob.core.windows.net/<container> or S3 bucket URL
	authHeader    string // SAS token, AWS signature header, or Bearer token
	httpClient    *http.Client
	queue         chan AuditEvent
	wg            sync.WaitGroup
	stopCh        chan struct{}
	retentionDays int // Legal retention period (passed to storage layer)
	hashChain     string
	hashChainMu   sync.Mutex
}

// AuditBatch represents a batch of events with integrity metadata
type AuditBatch struct {
	BatchID      string       `json:"batch_id"`
	Timestamp    time.Time    `json:"timestamp"`
	PrevHash     string       `json:"prev_hash"` // Hash chain for tamper detection
	ContentHash  string       `json:"content_hash"`
	Events       []AuditEvent `json:"events"`
	EventCount   int          `json:"event_count"`
	RetentionExp time.Time    `json:"retention_expires"`
}

func newImmutableStorageSink(backend, containerURL, authHeader string, retentionDays int) *ImmutableStorageSink {
	if backend == "" {
		backend = "azure"
	}
	if retentionDays <= 0 {
		retentionDays = 2555 // ~7 years for compliance
	}
	s := &ImmutableStorageSink{
		backend:       backend,
		containerURL:  strings.TrimSuffix(containerURL, "/"),
		authHeader:    authHeader,
		httpClient:    &http.Client{Timeout: 30 * time.Second},
		queue:         make(chan AuditEvent, 10000),
		stopCh:        make(chan struct{}),
		retentionDays: retentionDays,
		hashChain:     "genesis",
	}
	s.wg.Add(1)
	go s.worker(100, 5*time.Second)
	return s
}

func (s *ImmutableStorageSink) Send(_ context.Context, ev AuditEvent) error {
	select {
	case s.queue <- ev:
		return nil
	default:
		log.Printf("WARN: immutable storage queue full, dropping event request_id=%s", ev.RequestID)
		return errors.New("immutable storage queue full")
	}
}

func (s *ImmutableStorageSink) worker(batchSize int, flushInterval time.Duration) {
	defer s.wg.Done()
	batch := make([]AuditEvent, 0, batchSize)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.writeBatch(batch); err != nil {
			log.Printf("ERROR: immutable storage write failed: %v", err)
			auditStorageWritesTotal.WithLabelValues(s.backend, "error").Inc()
		} else {
			auditStorageWritesTotal.WithLabelValues(s.backend, "success").Inc()
		}
		batch = batch[:0]
	}

	for {
		select {
		case ev := <-s.queue:
			batch = append(batch, ev)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.stopCh:
			for {
				select {
				case ev := <-s.queue:
					batch = append(batch, ev)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *ImmutableStorageSink) writeBatch(events []AuditEvent) error {
	start := time.Now()
	defer func() {
		auditStorageLatency.WithLabelValues(s.backend).Observe(time.Since(start).Seconds())
	}()

	// Build batch with hash chain for tamper evidence
	content, _ := json.Marshal(events)
	contentHash := computeSHA256(content)

	s.hashChainMu.Lock()
	prevHash := s.hashChain
	s.hashChain = computeSHA256([]byte(prevHash + contentHash))
	s.hashChainMu.Unlock()

	batch := AuditBatch{
		BatchID:      fmt.Sprintf("audit-%s-%d", time.Now().Format("20060102T150405"), time.Now().UnixNano()%10000),
		Timestamp:    time.Now().UTC(),
		PrevHash:     prevHash,
		ContentHash:  contentHash,
		Events:       events,
		EventCount:   len(events),
		RetentionExp: time.Now().AddDate(0, 0, s.retentionDays),
	}

	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	switch s.backend {
	case "azure":
		return s.writeAzureBlob(batch.BatchID, body)
	case "s3":
		return s.writeS3Object(batch.BatchID, body)
	default:
		return s.writeGenericHTTP(batch.BatchID, body)
	}
}

// writeAzureBlob uploads to Azure Blob Storage with immutability headers
func (s *ImmutableStorageSink) writeAzureBlob(blobName string, content []byte) error {
	// PUT https://<account>.blob.core.windows.net/<container>/<blob>?<sas>
	blobURL := fmt.Sprintf("%s/%s.json", s.containerURL, blobName)
	if s.authHeader != "" && strings.Contains(s.authHeader, "?") {
		// SAS token passed as auth header in format "?sv=...&sig=..."
		blobURL = fmt.Sprintf("%s/%s.json%s", s.containerURL, blobName, s.authHeader)
	}

	req, err := http.NewRequest(http.MethodPut, blobURL, bytes.NewReader(content))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-ms-blob-type", "BlockBlob")

	// Set immutability policy (requires container-level immutable storage enabled)
	// x-ms-immutability-policy-until-date sets the retention end date
	retentionEnd := time.Now().AddDate(0, 0, s.retentionDays).UTC().Format(time.RFC1123)
	req.Header.Set("x-ms-immutability-policy-until-date", retentionEnd)
	req.Header.Set("x-ms-immutability-policy-mode", "unlocked") // or "locked" for stricter

	// For Bearer token auth (AAD)
	if s.authHeader != "" && !strings.HasPrefix(s.authHeader, "?") {
		req.Header.Set("Authorization", s.authHeader)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("azure blob write failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}
	log.Printf("INFO: audit batch written to Azure Blob: %s", blobName)
	return nil
}

// writeS3Object uploads to S3 with Object Lock headers
func (s *ImmutableStorageSink) writeS3Object(objectKey string, content []byte) error {
	// PUT https://<bucket>.s3.<region>.amazonaws.com/<key>
	objectURL := fmt.Sprintf("%s/%s.json", s.containerURL, objectKey)

	req, err := http.NewRequest(http.MethodPut, objectURL, bytes.NewReader(content))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// S3 Object Lock headers (requires bucket with Object Lock enabled)
	retentionEnd := time.Now().AddDate(0, 0, s.retentionDays).UTC().Format(time.RFC3339)
	req.Header.Set("x-amz-object-lock-mode", "GOVERNANCE") // or "COMPLIANCE" for stricter
	req.Header.Set("x-amz-object-lock-retain-until-date", retentionEnd)

	// AWS Signature V4 should be passed as auth header
	if s.authHeader != "" {
		req.Header.Set("Authorization", s.authHeader)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("s3 object write failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}
	log.Printf("INFO: audit batch written to S3: %s", objectKey)
	return nil
}

// writeGenericHTTP posts to a generic HTTP endpoint with HMAC signature
func (s *ImmutableStorageSink) writeGenericHTTP(batchID string, content []byte) error {
	req, err := http.NewRequest(http.MethodPost, s.containerURL, bytes.NewReader(content))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Batch-ID", batchID)
	if s.authHeader != "" {
		req.Header.Set("Authorization", s.authHeader)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("http audit write failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}
	log.Printf("INFO: audit batch written via HTTP: %s", batchID)
	return nil
}

func (s *ImmutableStorageSink) Close() error {
	close(s.stopCh)
	s.wg.Wait()
	return nil
}

// computeSHA256 returns a hex-encoded SHA-256 hash
func computeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ──────────────────────────────────────────────────────────────────────────────
// SPIFFE JWT-SVID source for external API authentication
// Fetches short-lived JWT-SVIDs from Workload API for bearer token auth
// ──────────────────────────────────────────────────────────────────────────────

var (
	jwtSVIDFetchTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "atb_jwt_svid_fetch_total",
			Help: "JWT-SVID fetch attempts from Workload API.",
		},
		[]string{"status", "audience"},
	)
	jwtSVIDFetchLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "atb_jwt_svid_fetch_latency_seconds",
			Help:    "Latency for JWT-SVID fetch operations.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"audience"},
	)
)

func init() {
	prometheus.MustRegister(jwtSVIDFetchTotal, jwtSVIDFetchLatency)
}

// JWTSVIDSource manages JWT-SVID fetching from SPIFFE Workload API
type JWTSVIDSource struct {
	client   *workloadapi.Client
	cache    sync.Map // audience -> cachedJWTSVID
	cacheTTL time.Duration
}

type cachedJWTSVID struct {
	token   string
	expires time.Time
}

var jwtSVIDSource *JWTSVIDSource

func newJWTSVIDSource(ctx context.Context, socketPath string, cacheTTL time.Duration) (*JWTSVIDSource, error) {
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		return nil, fmt.Errorf("creating JWT-SVID workload client: %w", err)
	}
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Second // cache tokens for 30s by default
	}
	return &JWTSVIDSource{client: client, cacheTTL: cacheTTL}, nil
}

// FetchJWTSVID gets a JWT-SVID for the given audience (e.g., "https://api.salesforce.com")
func (s *JWTSVIDSource) FetchJWTSVID(ctx context.Context, audience string) (string, error) {
	// Check cache first
	if cached, ok := s.cache.Load(audience); ok {
		c := cached.(*cachedJWTSVID)
		if time.Now().Before(c.expires) {
			return c.token, nil
		}
	}

	start := time.Now()
	svids, err := s.client.FetchJWTSVIDs(ctx, jwtsvid.Params{Audience: audience})
	elapsed := time.Since(start).Seconds()
	jwtSVIDFetchLatency.WithLabelValues(audience).Observe(elapsed)

	if err != nil {
		jwtSVIDFetchTotal.WithLabelValues("error", audience).Inc()
		return "", fmt.Errorf("fetching JWT-SVID for %s: %w", audience, err)
	}
	if len(svids) == 0 {
		jwtSVIDFetchTotal.WithLabelValues("empty", audience).Inc()
		return "", fmt.Errorf("no JWT-SVID returned for audience %s", audience)
	}

	jwtSVIDFetchTotal.WithLabelValues("success", audience).Inc()
	token := svids[0].Marshal()

	// Cache with buffer before actual expiry
	expiry := svids[0].Expiry.Add(-10 * time.Second)
	if expiry.After(time.Now()) {
		s.cache.Store(audience, &cachedJWTSVID{token: token, expires: expiry})
	}

	return token, nil
}

func (s *JWTSVIDSource) Close() error {
	return s.client.Close()
}

// ──────────────────────────────────────────────────────────────────────────────
// SPIFFE Federation - trust bundles from federated trust domains
// ──────────────────────────────────────────────────────────────────────────────

// FederationConfig holds federated trust domain configurations
type FederationConfig struct {
	TrustDomains []FederatedDomain `json:"trust_domains"`
}

type FederatedDomain struct {
	TrustDomain string `json:"trust_domain"` // e.g., "partner.example.com"
	BundleURL   string `json:"bundle_url"`   // SPIFFE bundle endpoint URL
	Enabled     bool   `json:"enabled"`
}

// FederationManager manages trust bundles from federated SPIFFE domains
type FederationManager struct {
	mu       sync.RWMutex
	bundles  map[string]*jwtbundle.Bundle // trust_domain -> bundle
	config   FederationConfig
	stopCh   chan struct{}
	interval time.Duration
}

var federationMgr *FederationManager

func newFederationManager(config FederationConfig, refreshInterval time.Duration) *FederationManager {
	if refreshInterval <= 0 {
		refreshInterval = 5 * time.Minute
	}
	return &FederationManager{
		bundles:  make(map[string]*jwtbundle.Bundle),
		config:   config,
		stopCh:   make(chan struct{}),
		interval: refreshInterval,
	}
}

func (f *FederationManager) Start(ctx context.Context) {
	// Initial fetch
	f.refreshBundles(ctx)
	// Periodic refresh
	go func() {
		ticker := time.NewTicker(f.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				f.refreshBundles(ctx)
			case <-f.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (f *FederationManager) refreshBundles(ctx context.Context) {
	for _, domain := range f.config.TrustDomains {
		if !domain.Enabled {
			continue
		}
		td, err := spiffeid.TrustDomainFromString(domain.TrustDomain)
		if err != nil {
			log.Printf("WARN: invalid trust domain %q: %v", domain.TrustDomain, err)
			continue
		}
		bundle, err := federation.FetchBundle(ctx, td, domain.BundleURL)
		if err != nil {
			log.Printf("WARN: failed to fetch bundle for %s from %s: %v", domain.TrustDomain, domain.BundleURL, err)
			continue
		}
		f.mu.Lock()
		f.bundles[domain.TrustDomain] = bundle.JWTBundle()
		f.mu.Unlock()
		log.Printf("INFO: refreshed federation bundle for %s", domain.TrustDomain)
	}
}

func (f *FederationManager) GetBundle(trustDomain string) *jwtbundle.Bundle {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.bundles[trustDomain]
}

func (f *FederationManager) Stop() {
	close(f.stopCh)
}

// ──────────────────────────────────────────────────────────────────────────────
// Constraint Enforcement
// Validates that request parameters match PoA token constraints
// ──────────────────────────────────────────────────────────────────────────────

// ConstraintViolation represents a constraint check failure
type ConstraintViolation struct {
	Field    string      `json:"field"`
	Expected interface{} `json:"expected"`
	Actual   interface{} `json:"actual"`
	Message  string      `json:"message"`
}

// ConstraintEnforcementConfig defines which constraints to enforce
type ConstraintEnforcementConfig struct {
	Enabled           bool     `json:"enabled"`
	StrictMode        bool     `json:"strict_mode"` // Fail if constraint exists but can't be validated
	EnforceContactID  bool     `json:"enforce_contact_id"`
	EnforceAmount     bool     `json:"enforce_amount"`
	EnforceResourceID bool     `json:"enforce_resource_id"`
	CustomConstraints []string `json:"custom_constraints"` // Additional constraint keys to enforce
}

var constraintConfig = ConstraintEnforcementConfig{
	Enabled:           true,
	StrictMode:        false,
	EnforceContactID:  true,
	EnforceAmount:     true,
	EnforceResourceID: true,
}

// ValidateConstraints checks if request parameters match PoA token constraints
// Returns nil if valid, or a list of violations if constraints are violated
func ValidateConstraints(constraints map[string]interface{}, r *http.Request, body []byte) []ConstraintViolation {
	if !constraintConfig.Enabled || constraints == nil {
		return nil
	}

	var violations []ConstraintViolation

	// Extract path parameters (e.g., /contacts/{id} -> id)
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var pathID string
	if len(pathParts) >= 2 {
		pathID = pathParts[len(pathParts)-1]
	}

	// Parse JSON body if present
	var bodyData map[string]interface{}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &bodyData) // Ignore parse errors, constraint just won't match
	}

	// Query parameters
	queryParams := r.URL.Query()

	// Check contact_id constraint
	if constraintConfig.EnforceContactID {
		if contactID, ok := constraints["contact_id"]; ok {
			actualID := getRequestValue("contact_id", pathID, queryParams, bodyData)
			if !matchConstraint(contactID, actualID) {
				violations = append(violations, ConstraintViolation{
					Field:    "contact_id",
					Expected: contactID,
					Actual:   actualID,
					Message:  "contact_id in request does not match PoA constraint",
				})
			}
		}
	}

	// Check resource_id constraint (generic ID)
	if constraintConfig.EnforceResourceID {
		if resourceID, ok := constraints["resource_id"]; ok {
			actualID := getRequestValue("resource_id", pathID, queryParams, bodyData)
			if !matchConstraint(resourceID, actualID) {
				violations = append(violations, ConstraintViolation{
					Field:    "resource_id",
					Expected: resourceID,
					Actual:   actualID,
					Message:  "resource_id in request does not match PoA constraint",
				})
			}
		}
	}

	// Check amount constraint
	if constraintConfig.EnforceAmount {
		if maxAmount, ok := constraints["max_amount"]; ok {
			actualAmount := getNumericValue("amount", queryParams, bodyData)
			if actualAmount > 0 {
				maxVal := toFloat64(maxAmount)
				if actualAmount > maxVal {
					violations = append(violations, ConstraintViolation{
						Field:    "max_amount",
						Expected: maxAmount,
						Actual:   actualAmount,
						Message:  fmt.Sprintf("amount %.2f exceeds max_amount %.2f", actualAmount, maxVal),
					})
				}
			}
		}
	}

	// Check read_only constraint
	if readOnly, ok := constraints["read_only"].(bool); ok && readOnly {
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			violations = append(violations, ConstraintViolation{
				Field:    "read_only",
				Expected: true,
				Actual:   r.Method,
				Message:  fmt.Sprintf("read_only constraint violated by %s method", r.Method),
			})
		}
	}

	// Check allowed_methods constraint
	if allowedMethods, ok := constraints["allowed_methods"].([]interface{}); ok {
		methodAllowed := false
		for _, m := range allowedMethods {
			if mStr, ok := m.(string); ok && strings.EqualFold(mStr, r.Method) {
				methodAllowed = true
				break
			}
		}
		if !methodAllowed {
			violations = append(violations, ConstraintViolation{
				Field:    "allowed_methods",
				Expected: allowedMethods,
				Actual:   r.Method,
				Message:  fmt.Sprintf("method %s not in allowed_methods", r.Method),
			})
		}
	}

	// Check path_prefix constraint
	if pathPrefix, ok := constraints["path_prefix"].(string); ok {
		if !strings.HasPrefix(r.URL.Path, pathPrefix) {
			violations = append(violations, ConstraintViolation{
				Field:    "path_prefix",
				Expected: pathPrefix,
				Actual:   r.URL.Path,
				Message:  fmt.Sprintf("request path does not match prefix %s", pathPrefix),
			})
		}
	}

	// Custom constraints
	for _, key := range constraintConfig.CustomConstraints {
		if expected, ok := constraints[key]; ok {
			actual := getRequestValue(key, "", queryParams, bodyData)
			if !matchConstraint(expected, actual) {
				violations = append(violations, ConstraintViolation{
					Field:    key,
					Expected: expected,
					Actual:   actual,
					Message:  fmt.Sprintf("custom constraint %s not satisfied", key),
				})
			}
		}
	}

	return violations
}

// getRequestValue tries to extract a value from path, query, or body
func getRequestValue(key, pathID string, query url.Values, body map[string]interface{}) interface{} {
	// Check query parameters first
	if v := query.Get(key); v != "" {
		return v
	}
	// Check common ID variations
	if key == "contact_id" || key == "resource_id" {
		if v := query.Get("id"); v != "" {
			return v
		}
		if pathID != "" {
			return pathID
		}
	}
	// Check body
	if body != nil {
		if v, ok := body[key]; ok {
			return v
		}
		// Nested check for common patterns
		if key == "contact_id" {
			if v, ok := body["contactId"]; ok {
				return v
			}
			if v, ok := body["id"]; ok {
				return v
			}
		}
	}
	return nil
}

// getNumericValue extracts a numeric value from query or body
func getNumericValue(key string, query url.Values, body map[string]interface{}) float64 {
	// Check query
	if v := query.Get(key); v != "" {
		var f float64
		fmt.Sscanf(v, "%f", &f)
		return f
	}
	// Check body
	if body != nil {
		if v, ok := body[key]; ok {
			return toFloat64(v)
		}
	}
	return 0
}

// toFloat64 converts an interface to float64
func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		var f float64
		fmt.Sscanf(n, "%f", &f)
		return f
	default:
		return 0
	}
}

// matchConstraint compares expected and actual values
func matchConstraint(expected, actual interface{}) bool {
	if actual == nil {
		return false
	}
	// String comparison (case-insensitive for IDs)
	expectedStr := fmt.Sprintf("%v", expected)
	actualStr := fmt.Sprintf("%v", actual)
	return strings.EqualFold(expectedStr, actualStr)
}

// ──────────────────────────────────────────────────────────────────────────────
// Platform ↔ SPIFFE identity binding
// Validates that platform OIDC sub claim maps to caller's SPIFFE ID
// ──────────────────────────────────────────────────────────────────────────────

// SPIFFEPlatformBinding defines the mapping between platform identity and SPIFFE ID
type SPIFFEPlatformBinding struct {
	// Mode: "exact" (sub must match SPIFFE ID), "prefix" (sub is prefix of SPIFFE path), "mapping" (lookup table)
	Mode string `json:"mode"`
	// Mappings for "mapping" mode: platform sub -> allowed SPIFFE ID pattern
	Mappings map[string]string `json:"mappings,omitempty"`
}

var platformBindingConfig SPIFFEPlatformBinding

// ValidatePlatformSPIFFEBinding checks if the platform sub claim matches the caller's SPIFFE ID
func ValidatePlatformSPIFFEBinding(platformSub, spiffeID string) (bool, string) {
	if platformBindingConfig.Mode == "" || platformBindingConfig.Mode == "none" {
		return true, "" // binding not enforced
	}

	switch platformBindingConfig.Mode {
	case "exact":
		// Platform sub must exactly match SPIFFE ID
		if platformSub == spiffeID {
			return true, ""
		}
		return false, fmt.Sprintf("platform sub %q does not match SPIFFE ID %q", platformSub, spiffeID)

	case "prefix":
		// Platform sub should be a prefix of the SPIFFE ID path
		// e.g., sub="agent-platform-1" matches spiffe://trust.domain/agent-platform-1/worker-123
		if strings.Contains(spiffeID, "/"+platformSub+"/") || strings.HasSuffix(spiffeID, "/"+platformSub) {
			return true, ""
		}
		return false, fmt.Sprintf("platform sub %q is not in SPIFFE ID path %q", platformSub, spiffeID)

	case "mapping":
		// Lookup: platform sub -> allowed SPIFFE pattern (regex)
		pattern, ok := platformBindingConfig.Mappings[platformSub]
		if !ok {
			return false, fmt.Sprintf("no mapping found for platform sub %q", platformSub)
		}
		matched, err := regexp.MatchString(pattern, spiffeID)
		if err != nil {
			return false, fmt.Sprintf("invalid mapping pattern for %q: %v", platformSub, err)
		}
		if matched {
			return true, ""
		}
		return false, fmt.Sprintf("SPIFFE ID %q does not match pattern %q for platform %q", spiffeID, pattern, platformSub)

	default:
		return true, "" // unknown mode, don't block
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Connector types for multi-backend routing with egress allowlists and shaping
// ──────────────────────────────────────────────────────────────────────────────

// Connector represents a backend system (SAP, Salesforce, etc.) with routing config
type Connector struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	UpstreamURL     string            `json:"upstream_url"`
	EgressAllowlist []string          `json:"egress_allowlist,omitempty"`
	RateLimit       float64           `json:"rate_limit,omitempty"`
	BurstLimit      int               `json:"burst_limit,omitempty"`
	TimeoutSec      int               `json:"timeout_seconds,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Enabled         bool              `json:"enabled"`
	// JWT-SVID identity injection for external APIs (SPIFFE-based auth)
	JWTSVIDAudience string `json:"jwt_svid_audience,omitempty"` // if set, fetch JWT-SVID for this audience
	JWTSVIDHeader   string `json:"jwt_svid_header,omitempty"`   // header name for JWT-SVID (default: Authorization)
	egressPatterns  []*regexp.Regexp
	proxy           *httputil.ReverseProxy
	limiter         *connectorLimiter
}

type connectorLimiter struct {
	mu       sync.Mutex
	tokens   float64
	rate     float64
	burst    int
	lastTick time.Time
}

func newConnectorLimiter(rate float64, burst int) *connectorLimiter {
	if burst <= 0 {
		burst = int(rate)
	}
	if burst <= 0 {
		burst = 1
	}
	return &connectorLimiter{tokens: float64(burst), rate: rate, burst: burst, lastTick: time.Now()}
}

func (l *connectorLimiter) Allow() bool {
	if l == nil || l.rate <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(l.lastTick).Seconds()
	l.lastTick = now
	l.tokens += elapsed * l.rate
	if l.tokens > float64(l.burst) {
		l.tokens = float64(l.burst)
	}
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// ConnectorRegistry manages connectors with thread-safe access
type ConnectorRegistry struct {
	mu         sync.RWMutex
	connectors map[string]*Connector
	defaultID  string
}

func newConnectorRegistry() *ConnectorRegistry {
	return &ConnectorRegistry{connectors: make(map[string]*Connector)}
}

func (r *ConnectorRegistry) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading connector config: %w", err)
	}
	return r.LoadFromJSON(data)
}

func (r *ConnectorRegistry) LoadFromJSON(data []byte) error {
	var config struct {
		DefaultConnector string       `json:"default_connector"`
		Connectors       []*Connector `json:"connectors"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parsing connector config: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultID = config.DefaultConnector
	r.connectors = make(map[string]*Connector)
	for _, c := range config.Connectors {
		if err := c.compile(); err != nil {
			return fmt.Errorf("connector %s: %w", c.ID, err)
		}
		r.connectors[c.ID] = c
	}
	return nil
}

func (c *Connector) compile() error {
	c.egressPatterns = make([]*regexp.Regexp, 0, len(c.EgressAllowlist))
	for _, pattern := range c.EgressAllowlist {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid egress pattern %q: %w", pattern, err)
		}
		c.egressPatterns = append(c.egressPatterns, re)
	}
	target, err := url.Parse(c.UpstreamURL)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}
	c.proxy = httputil.NewSingleHostReverseProxy(target)
	if c.TimeoutSec > 0 {
		c.proxy.Transport = &http.Transport{ResponseHeaderTimeout: time.Duration(c.TimeoutSec) * time.Second}
	}
	if c.RateLimit > 0 {
		c.limiter = newConnectorLimiter(c.RateLimit, c.BurstLimit)
	}
	return nil
}

func (r *ConnectorRegistry) Get(id string) *Connector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.connectors[id]
}

func (r *ConnectorRegistry) GetDefault() *Connector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.defaultID == "" {
		return nil
	}
	return r.connectors[r.defaultID]
}

type ConnectorError struct {
	Code    string
	Message string
}

func (e *ConnectorError) Error() string { return e.Message }

// Resolve finds connector by: PoA con.connector > header > default
func (r *ConnectorRegistry) Resolve(connectorID, header string) (*Connector, *ConnectorError) {
	id := connectorID
	if id == "" {
		id = header
	}
	if id == "" {
		r.mu.RLock()
		id = r.defaultID
		r.mu.RUnlock()
	}
	if id == "" {
		return nil, &ConnectorError{Code: "no_connector", Message: "no connector specified and no default configured"}
	}
	c := r.Get(id)
	if c == nil {
		return nil, &ConnectorError{Code: "connector_not_found", Message: fmt.Sprintf("connector %q not found", id)}
	}
	if !c.Enabled {
		return nil, &ConnectorError{Code: "connector_disabled", Message: fmt.Sprintf("connector %q is disabled", id)}
	}
	return c, nil
}

func (c *Connector) EgressAllowed(path string) bool {
	if len(c.egressPatterns) == 0 {
		return true
	}
	for _, re := range c.egressPatterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func (c *Connector) RateLimitAllowed() bool {
	return c.limiter.Allow()
}

func (c *Connector) ValidateRequest(path string) *ConnectorError {
	if !c.EgressAllowed(path) {
		msg := fmt.Sprintf("path %q not in egress allowlist for connector %q", path, c.ID)
		return &ConnectorError{Code: "egress_denied", Message: msg}
	}
	if !c.RateLimitAllowed() {
		return &ConnectorError{Code: "rate_limited", Message: fmt.Sprintf("rate limit exceeded for connector %q", c.ID)}
	}
	return nil
}

func (c *Connector) AddHeaders(r *http.Request) {
	for k, v := range c.Headers {
		r.Header.Set(k, v)
	}
}

// AddHeadersWithJWTSVID adds static headers plus JWT-SVID for external API auth
func (c *Connector) AddHeadersWithJWTSVID(ctx context.Context, r *http.Request) error {
	// Add static headers first
	c.AddHeaders(r)

	// Inject JWT-SVID if configured
	if c.JWTSVIDAudience != "" && jwtSVIDSource != nil {
		token, err := jwtSVIDSource.FetchJWTSVID(ctx, c.JWTSVIDAudience)
		if err != nil {
			return fmt.Errorf("fetching JWT-SVID for connector %s: %w", c.ID, err)
		}
		header := c.JWTSVIDHeader
		if header == "" {
			header = "Authorization"
		}
		if header == "Authorization" {
			r.Header.Set(header, "Bearer "+token)
		} else {
			r.Header.Set(header, token)
		}
		log.Printf("DEBUG: injected JWT-SVID for connector %s audience %s", c.ID, c.JWTSVIDAudience)
	}
	return nil
}

// Prometheus metrics for connectors
var (
	connectorRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "atb_connector_requests_total", Help: "Requests per connector"},
		[]string{"connector", "decision", "reason"},
	)
	connectorEgressDenied = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "atb_connector_egress_denied_total", Help: "Egress denials per connector"},
		[]string{"connector"},
	)
	connectorRateLimited = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "atb_connector_rate_limited_total", Help: "Rate limit denials per connector"},
		[]string{"connector"},
	)
)

func init() {
	prometheus.MustRegister(connectorRequestsTotal, connectorEgressDenied, connectorRateLimited)
}

// Global audit sink (configured at startup)
var auditSink AuditSink = &StdoutSink{}

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

// OPADecision represents the full result from an OPA policy evaluation
type OPADecision struct {
	Allow    bool                   `json:"allow"`
	Reason   string                 `json:"reason"`
	Details  map[string]interface{} `json:"details,omitempty"`
	RiskTier string                 `json:"risk_tier,omitempty"`
}

// DecideWithMetrics evaluates OPA policy and records detailed metrics
func (c *OPAClient) DecideWithMetrics(ctx context.Context, input OPAInput) (OPADecision, error) {
	startTime := time.Now()
	action := ""
	if act, ok := input.PoA["act"].(string); ok {
		action = act
	}

	defer func() {
		duration := time.Since(startTime).Seconds()
		opaEvaluationDuration.WithLabelValues(action).Observe(duration)
	}()

	body, err := json.Marshal(map[string]interface{}{"input": input})
	if err != nil {
		return OPADecision{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return OPADecision{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		opaDecisionsTotal.WithLabelValues("error", "unknown", "opa_unreachable").Inc()
		return OPADecision{}, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		opaDecisionsTotal.WithLabelValues("error", "unknown", "opa_error").Inc()
		return OPADecision{}, fmt.Errorf("OPA status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var decoded struct {
		Result interface{} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return OPADecision{}, err
	}

	var decision OPADecision

	switch v := decoded.Result.(type) {
	case bool:
		decision.Allow = v
		if v {
			decision.Reason = "allow"
		} else {
			decision.Reason = "deny"
		}
	case map[string]interface{}:
		decision.Allow, _ = v["allow"].(bool)
		decision.Reason, _ = v["reason"].(string)
		if details, ok := v["details"].(map[string]interface{}); ok {
			decision.Details = details
			if tier, ok := details["tier"].(string); ok {
				decision.RiskTier = tier
			}
		}
	default:
		return OPADecision{}, fmt.Errorf("unexpected OPA result type: %T", decoded.Result)
	}

	// Record metrics based on decision
	decisionStr := "allow"
	if !decision.Allow {
		decisionStr = "deny"
	}

	// Determine risk tier from details or infer from action
	riskTier := decision.RiskTier
	if riskTier == "" {
		riskTier = inferRiskTier(action)
	}

	opaDecisionsTotal.WithLabelValues(decisionStr, riskTier, decision.Reason).Inc()
	opaRiskTierUsage.WithLabelValues(riskTier).Inc()

	if !decision.Allow {
		opaDenialReasons.WithLabelValues(decision.Reason).Inc()

		// Track time policy violations specifically
		if decision.Reason == "time_policy_violation" {
			if violations, ok := decision.Details["violations"].([]interface{}); ok {
				for _, v := range violations {
					if vs, ok := v.(string); ok {
						// Extract violation type (e.g., "rate_limit_exceeded", "outside_business_hours")
						violationType := strings.Split(vs, ":")[0]
						opaTimePolicyViolations.WithLabelValues(violationType).Inc()
					}
				}
			}
		}
	}

	return decision, nil
}

// inferRiskTier attempts to determine risk tier from action name patterns
func inferRiskTier(action string) string {
	// Critical actions
	if strings.HasPrefix(action, "org.") ||
		strings.HasPrefix(action, "security.root") ||
		strings.HasPrefix(action, "security.master_key") ||
		strings.Contains(action, "full_export") ||
		strings.Contains(action, "over_10m") {
		return "critical"
	}
	// High risk patterns
	if strings.HasPrefix(action, "sap.payment") ||
		strings.HasPrefix(action, "ot.") ||
		strings.HasPrefix(action, "iam.") ||
		strings.Contains(action, "bulk_") ||
		strings.Contains(action, "execute") {
		return "high"
	}
	// Medium risk patterns
	if strings.Contains(action, "update") ||
		strings.Contains(action, "delete") ||
		strings.Contains(action, "create") {
		return "medium"
	}
	return "low"
}

func (c *OPAClient) Decide(ctx context.Context, input OPAInput) (bool, string, error) {
	decision, err := c.DecideWithMetrics(ctx, input)
	if err != nil {
		return false, "", err
	}
	return decision.Allow, decision.Reason, nil
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

func newPlatformVerifier(
	jwksURL, issuer, audience string,
	httpClient *http.Client,
	cacheTTL time.Duration,
	required bool,
) *platformVerifier {
	if strings.TrimSpace(jwksURL) == "" {
		return &platformVerifier{requirePlatID: required}
	}
	pv := &platformVerifier{
		jwks:          newJWKSCache(jwksURL, httpClient, cacheTTL),
		allowedAlgs:   []string{"RS256", "ES256"},
		requirePlatID: required,
	}
	if trimmed := strings.TrimSpace(issuer); trimmed != "" {
		pv.issuer = trimmed
	}
	if trimmed := strings.TrimSpace(audience); trimmed != "" {
		pv.audience = trimmed
	}
	return pv
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

	// Build parse options dynamically; only validate issuer/audience when configured
	parseOpts := []jwt.ParserOption{
		jwt.WithValidMethods(p.allowedAlgs),
		jwt.WithLeeway(30 * time.Second),
	}
	if p.issuer != "" {
		parseOpts = append(parseOpts, jwt.WithIssuer(p.issuer))
	}
	if p.audience != "" {
		parseOpts = append(parseOpts, jwt.WithAudience(p.audience))
	}

	token, err := jwt.ParseWithClaims(tokenRaw, &platformClaims{}, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid in token header")
		}
		key, err := p.jwks.get(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}, parseOpts...)
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

// ──────────────────────────────────────────────────────────────────────────────
// Semantic Guardrails - prompt injection / content safety filtering
// ──────────────────────────────────────────────────────────────────────────────

// GuardrailsClient handles content safety checks via external service
type GuardrailsClient struct {
	URL        string
	AuthHeader string
	HTTP       *http.Client
	Enabled    bool
}

// GuardrailsRequest is sent to the guardrails service
type GuardrailsRequest struct {
	Text       string                 `json:"text"`
	Action     string                 `json:"action,omitempty"`
	Agent      string                 `json:"agent,omitempty"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// GuardrailsResponse from the guardrails service
type GuardrailsResponse struct {
	Safe     bool    `json:"safe"`
	Reason   string  `json:"reason,omitempty"`
	Score    float64 `json:"score,omitempty"`
	Category string  `json:"category,omitempty"`
}

var guardrailsClient *GuardrailsClient

// Prometheus metrics for guardrails
var (
	guardrailsRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "atb_guardrails_requests_total", Help: "Guardrails check requests"},
		[]string{"result", "category"},
	)
	guardrailsLatencySeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "atb_guardrails_latency_seconds",
			Help:    "Guardrails check latency",
			Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
	)
)

func init() {
	prometheus.MustRegister(guardrailsRequestsTotal, guardrailsLatencySeconds)
}

func (g *GuardrailsClient) Check(ctx context.Context, req GuardrailsRequest) (bool, string) {
	if g == nil || !g.Enabled || g.URL == "" {
		// Fall back to local pattern matching if no external service
		return localGuardrailsCheck(req.Text, req.Parameters)
	}

	start := time.Now()
	defer func() {
		guardrailsLatencySeconds.Observe(time.Since(start).Seconds())
	}()

	body, err := json.Marshal(req)
	if err != nil {
		log.Printf("WARN: guardrails marshal error: %v", err)
		guardrailsRequestsTotal.WithLabelValues("error", "marshal").Inc()
		return true, "" // fail-open on error (configurable)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, g.URL, bytes.NewReader(body))
	if err != nil {
		guardrailsRequestsTotal.WithLabelValues("error", "request").Inc()
		return true, ""
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if g.AuthHeader != "" {
		httpReq.Header.Set("Authorization", g.AuthHeader)
	}

	resp, err := g.HTTP.Do(httpReq)
	if err != nil {
		log.Printf("WARN: guardrails request error: %v", err)
		guardrailsRequestsTotal.WithLabelValues("error", "network").Inc()
		return true, "" // fail-open
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		guardrailsRequestsTotal.WithLabelValues("error", "http_error").Inc()
		return true, ""
	}

	var result GuardrailsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		guardrailsRequestsTotal.WithLabelValues("error", "decode").Inc()
		return true, ""
	}

	if result.Safe {
		guardrailsRequestsTotal.WithLabelValues("allow", result.Category).Inc()
		return true, ""
	}

	guardrailsRequestsTotal.WithLabelValues("block", result.Category).Inc()
	return false, result.Reason
}

// localGuardrailsCheck performs basic pattern matching when no external service is configured
func localGuardrailsCheck(text string, params map[string]interface{}) (bool, string) {
	// Patterns indicating potential prompt injection or malicious content
	dangerousPatterns := []string{
		"ignore previous",
		"ignore all previous",
		"disregard previous",
		"forget previous",
		"disable safety",
		"bypass security",
		"you are now",
		"pretend you are",
		"act as if",
		"jailbreak",
		"dan mode",
		"developer mode",
		"exfiltrate",
		"curl http",
		"wget http",
		"drop table",
		"delete from",
		"; exec",
		"$(", // command substitution
		"`",  // backtick command substitution
	}

	checkText := func(s string) (bool, string) {
		low := strings.ToLower(s)
		for _, pattern := range dangerousPatterns {
			if strings.Contains(low, pattern) {
				return false, "prompt_injection_detected"
			}
		}
		return true, ""
	}

	// Check main text
	if text != "" {
		if safe, reason := checkText(text); !safe {
			return safe, reason
		}
	}

	// Check all string parameters
	for _, v := range params {
		if s, ok := v.(string); ok {
			if safe, reason := checkText(s); !safe {
				return safe, reason
			}
		}
	}

	return true, ""
}

// semanticGuardrails is the main entry point for guardrails checks
func semanticGuardrails(ctx context.Context, action, agent string, params map[string]interface{}) (bool, string) {
	// Build combined text from all params for checking
	var textParts []string
	for k, v := range params {
		if s, ok := v.(string); ok {
			textParts = append(textParts, fmt.Sprintf("%s: %s", k, s))
		}
	}
	combinedText := strings.Join(textParts, "\n")

	req := GuardrailsRequest{
		Text:       combinedText,
		Action:     action,
		Agent:      agent,
		Parameters: params,
	}

	if guardrailsClient != nil {
		return guardrailsClient.Check(ctx, req)
	}
	return localGuardrailsCheck(combinedText, params)
}

func audit(ev AuditEvent) {
	// Always log to stdout for container environments
	_ = json.NewEncoder(os.Stdout).Encode(ev)
	// Also send to configured sink if different from stdout
	if _, isStdout := auditSink.(*StdoutSink); !isStdout {
		_ = auditSink.Send(context.Background(), ev)
	}
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

	// Configure audit sink (SIEM/Log Analytics)
	auditSinkURL := strings.TrimSpace(os.Getenv("AUDIT_SINK_URL"))
	auditSinkAuth := strings.TrimSpace(os.Getenv("AUDIT_SINK_AUTH")) // e.g., "Bearer <token>"
	if auditSinkURL != "" {
		batchSize := 100
		if v := strings.TrimSpace(os.Getenv("AUDIT_SINK_BATCH_SIZE")); v != "" {
			fmt.Sscanf(v, "%d", &batchSize)
		}
		flushSec := 5
		if v := strings.TrimSpace(os.Getenv("AUDIT_SINK_FLUSH_SECONDS")); v != "" {
			fmt.Sscanf(v, "%d", &flushSec)
		}
		auditSink = newHTTPSink(auditSinkURL, auditSinkAuth, batchSize, time.Duration(flushSec)*time.Second)
		log.Printf("Audit sink configured: %s (batch=%d, flush=%ds)", auditSinkURL, batchSize, flushSec)
		// Ensure graceful shutdown
		defer auditSink.Close()
	}

	// Configure immutable (WORM) audit storage for compliance / tamper-evidence
	// Supports Azure Blob immutability, AWS S3 Object Lock, or generic HTTP
	immutableStorageURL := strings.TrimSpace(os.Getenv("AUDIT_IMMUTABLE_URL"))
	immutableStorageAuth := strings.TrimSpace(os.Getenv("AUDIT_IMMUTABLE_AUTH"))
	immutableStorageBackend := strings.TrimSpace(os.Getenv("AUDIT_IMMUTABLE_BACKEND")) // "azure", "s3", or "http"
	if immutableStorageURL != "" {
		retentionDays := int(envInt64("AUDIT_RETENTION_DAYS", 2555)) // ~7 years default
		immutableSink := newImmutableStorageSink(
			immutableStorageBackend, immutableStorageURL, immutableStorageAuth, retentionDays)
		log.Printf("Immutable audit storage configured: backend=%s url=%s retention=%d days",
			immutableStorageBackend, immutableStorageURL, retentionDays)
		defer immutableSink.Close()

		// If we already have an audit sink (HTTP), wrap both in MultiSink
		if auditSink != nil {
			auditSink = &MultiSink{sinks: []AuditSink{auditSink, immutableSink}}
		} else {
			auditSink = immutableSink
		}
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

	// Connector registry for multi-backend routing
	var connRegistry *ConnectorRegistry
	connectorConfigFile := strings.TrimSpace(os.Getenv("CONNECTOR_CONFIG_FILE"))
	if connectorConfigFile != "" {
		connRegistry = newConnectorRegistry()
		if err := connRegistry.LoadFromFile(connectorConfigFile); err != nil {
			log.Fatalf("Failed to load connector config: %v", err)
		}
		log.Printf("Loaded connector config from %s", connectorConfigFile)
	}

	// Semantic guardrails / content safety service
	guardrailsURL := strings.TrimSpace(os.Getenv("GUARDRAILS_URL"))
	guardrailsAuth := strings.TrimSpace(os.Getenv("GUARDRAILS_AUTH")) // e.g., "Bearer <token>" or API key
	if guardrailsURL != "" {
		guardrailsClient = &GuardrailsClient{
			URL:        guardrailsURL,
			AuthHeader: guardrailsAuth,
			HTTP:       &http.Client{Timeout: 2 * time.Second},
			Enabled:    true,
		}
		log.Printf("Guardrails service configured: %s", guardrailsURL)
	} else {
		log.Printf("Guardrails: using local pattern matching (no external service configured)")
	}

	// JWT-SVID source for external API authentication (SPIFFE-based)
	if spiffeEndpointSocket != "" {
		jwtCacheTTL := time.Duration(envInt64("JWT_SVID_CACHE_TTL_SECONDS", 30)) * time.Second
		ctx := context.Background()
		src, err := newJWTSVIDSource(ctx, spiffeEndpointSocket, jwtCacheTTL)
		if err != nil {
			log.Printf("WARN: JWT-SVID source not available (connectors won't have SPIFFE auth): %v", err)
		} else {
			jwtSVIDSource = src
			defer jwtSVIDSource.Close()
			log.Printf("JWT-SVID source initialized (cache TTL %s)", jwtCacheTTL)
		}
	}

	// SPIFFE Federation - load trust bundles from federated domains
	federationConfigFile := strings.TrimSpace(os.Getenv("SPIFFE_FEDERATION_CONFIG"))
	if federationConfigFile != "" {
		data, err := os.ReadFile(federationConfigFile)
		if err != nil {
			log.Printf("WARN: failed to read federation config %s: %v", federationConfigFile, err)
		} else {
			var fedConfig FederationConfig
			if err := json.Unmarshal(data, &fedConfig); err != nil {
				log.Printf("WARN: invalid federation config: %v", err)
			} else {
				refreshInterval := time.Duration(envInt64("SPIFFE_FEDERATION_REFRESH_SECONDS", 300)) * time.Second
				federationMgr = newFederationManager(fedConfig, refreshInterval)
				ctx := context.Background()
				federationMgr.Start(ctx)
				defer federationMgr.Stop()
				log.Printf("SPIFFE Federation manager started with %d trust domains", len(fedConfig.TrustDomains))
			}
		}
	}

	// Platform ↔ SPIFFE binding mode (none, exact, prefix, mapping)
	platBindingMode := strings.TrimSpace(os.Getenv("PLATFORM_SPIFFE_BINDING_MODE"))
	if platBindingMode != "" && platBindingMode != "none" {
		platformBindingConfig.Mode = platBindingMode
		platMappingFile := strings.TrimSpace(os.Getenv("PLATFORM_SPIFFE_MAPPING_FILE"))
		if platBindingMode == "mapping" && platMappingFile != "" {
			data, err := os.ReadFile(platMappingFile)
			if err != nil {
				log.Fatalf("Failed to read platform-SPIFFE mapping file: %v", err)
			}
			if err := json.Unmarshal(data, &platformBindingConfig.Mappings); err != nil {
				log.Fatalf("Invalid platform-SPIFFE mapping JSON: %v", err)
			}
		}
		log.Printf("Platform↔SPIFFE binding enabled: mode=%s", platBindingMode)
	}

	targetURL := mustParseURL(upstream)
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	httpClient := &http.Client{Timeout: 1500 * time.Millisecond}

	platVerifier := newPlatformVerifier(
		platJWKSURL, platIssuer, platAudience, httpClient,
		time.Duration(platCacheSec)*time.Second, platRequired)

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
			audit(AuditEvent{
				Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE,
				Decision: "deny", Reason: "platform_identity_invalid:" + platErr.Error(),
				Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
			})
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

			// Validate Platform ↔ SPIFFE binding if configured
			if valid, reason := ValidatePlatformSPIFFEBinding(platformID, agentSPIFFE); !valid {
				audit(AuditEvent{
					Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE,
					PlatformIdentity: platformID, Decision: "deny",
					Reason: "spiffe_binding_mismatch:" + reason,
					Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
				})
				brokerRequestsTotal.WithLabelValues("deny", "").Inc()
				http.Error(w, "platform identity does not match SPIFFE identity", http.StatusForbidden)
				return
			}
		}

		if !authConfigured {
			audit(AuditEvent{
				Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE,
				PlatformIdentity: platformID, Decision: "deny",
				Reason: "poa_verification_not_configured",
				Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
			})
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

		if ok, why := semanticGuardrails(r.Context(), actionForLogs, agentSPIFFE, params); !ok {
			audit(AuditEvent{
				Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE,
				Action: actionForLogs, Decision: "deny", Reason: why,
				Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
			})
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
				audit(AuditEvent{
					Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE,
					PlatformIdentity: platformID, Action: actionForLogs,
					Decision: "deny", Reason: "missing_poa",
					Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
				})
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
				audit(AuditEvent{
					Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE,
					PlatformIdentity: platformID, Action: actionForLogs,
					Decision: "error", Reason: "opa_error:" + err.Error(),
					Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
				})
				brokerRequestsTotal.WithLabelValues("error", actionForLogs).Inc()
				http.Error(w, "policy evaluation error", http.StatusInternalServerError)
				return
			}
			if !allow {
				audit(AuditEvent{
					Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE,
					PlatformIdentity: platformID, Action: actionForLogs,
					Decision: "deny", Reason: reason,
					Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
				})
				brokerRequestsTotal.WithLabelValues("deny", actionForLogs).Inc()
				http.Error(w, "PoA required", http.StatusUnauthorized)
				return
			}

			audit(AuditEvent{
				Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE,
				PlatformIdentity: platformID, Action: actionForLogs,
				Decision: "allow", Reason: reason,
				Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
			})
			brokerRequestsTotal.WithLabelValues("allow", actionForLogs).Inc()

			// Use connector if configured, otherwise default proxy
			if connRegistry != nil {
				connectorHeader := strings.TrimSpace(r.Header.Get("X-ATB-Connector"))
				conn, connErr := connRegistry.Resolve("", connectorHeader)
				if connErr != nil {
					connectorRequestsTotal.WithLabelValues("", "deny", connErr.Code).Inc()
					http.Error(w, connErr.Message, http.StatusBadRequest)
					return
				}
				if valErr := conn.ValidateRequest(r.URL.Path); valErr != nil {
					if valErr.Code == "egress_denied" {
						connectorEgressDenied.WithLabelValues(conn.ID).Inc()
					} else if valErr.Code == "rate_limited" {
						connectorRateLimited.WithLabelValues(conn.ID).Inc()
					}
					connectorRequestsTotal.WithLabelValues(conn.ID, "deny", valErr.Code).Inc()
					http.Error(w, valErr.Message, http.StatusForbidden)
					return
				}
				conn.AddHeaders(r)
				connectorRequestsTotal.WithLabelValues(conn.ID, "allow", "").Inc()
				conn.proxy.ServeHTTP(w, r)
				return
			}

			proxy.ServeHTTP(w, r)
			return
		}

		claims, err := verifyPoAJWT(poaToken, maxTTLSec, keyFunc, allowedAlgs)
		if err != nil {
			audit(AuditEvent{
				Timestamp: start, RequestID: reqID, AgentIdentity: agentSPIFFE,
				PlatformIdentity: platformID, Action: actionForLogs,
				Decision: "deny", Reason: "poa_invalid:" + err.Error(),
				Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
			})
			brokerRequestsTotal.WithLabelValues("deny", actionForLogs).Inc()
			http.Error(w, "invalid PoA", http.StatusForbidden)
			return
		}

		if claims.Subject != agentSPIFFE {
			audit(AuditEvent{
				Timestamp: start, RequestID: reqID, MandateID: claims.ID,
				AgentIdentity: agentSPIFFE, PlatformIdentity: platformID,
				Action: claims.Act, Constraints: claims.Con,
				Decision: "deny", Reason: "sub_mismatch",
				Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
			})
			brokerRequestsTotal.WithLabelValues("deny", claims.Act).Inc()
			http.Error(w, "PoA subject mismatch", http.StatusForbidden)
			return
		}

		if actionHeader != "" && actionHeader != claims.Act {
			audit(AuditEvent{
				Timestamp: start, RequestID: reqID, MandateID: claims.ID,
				AgentIdentity: agentSPIFFE, PlatformIdentity: platformID,
				Action: claims.Act, Constraints: claims.Con,
				Decision: "deny", Reason: "action_mismatch",
				Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
			})
			brokerRequestsTotal.WithLabelValues("deny", claims.Act).Inc()
			http.Error(w, "PoA action mismatch", http.StatusForbidden)
			return
		}

		// Constraint enforcement: validate request matches PoA constraints
		if violations := ValidateConstraints(claims.Con, r, bodyBytes); len(violations) > 0 {
			violationDetails := make([]string, len(violations))
			for i, v := range violations {
				violationDetails[i] = v.Message
			}
			reason := "constraint_violation:" + strings.Join(violationDetails, "; ")
			audit(AuditEvent{
				Timestamp: start, RequestID: reqID, MandateID: claims.ID,
				AgentIdentity: agentSPIFFE, PlatformIdentity: platformID,
				Action: claims.Act, Constraints: claims.Con,
				Decision: "deny", Reason: reason,
				Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
			})
			brokerRequestsTotal.WithLabelValues("deny", claims.Act).Inc()
			http.Error(w, "PoA constraint violation: "+violationDetails[0], http.StatusForbidden)
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
			audit(AuditEvent{
				Timestamp: start, RequestID: reqID, MandateID: claims.ID,
				AgentIdentity: agentSPIFFE, PlatformIdentity: platformID,
				Action: claims.Act, Constraints: claims.Con,
				Decision: "error", Reason: "opa_error:" + err.Error(),
				Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
			})
			brokerRequestsTotal.WithLabelValues("error", claims.Act).Inc()
			http.Error(w, "policy evaluation error", http.StatusInternalServerError)
			return
		}
		if !allow {
			if reason == "" {
				reason = "policy_denied"
			}
			audit(AuditEvent{
				Timestamp: start, RequestID: reqID, MandateID: claims.ID,
				AgentIdentity: agentSPIFFE, PlatformIdentity: platformID,
				Action: claims.Act, Constraints: claims.Con,
				Decision: "deny", Reason: reason,
				Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
			})
			brokerRequestsTotal.WithLabelValues("deny", claims.Act).Inc()
			http.Error(w, "policy denied", http.StatusForbidden)
			return
		}

		if poaSingleUse {
			now := time.Now().UTC()
			until := claims.ExpiresAt.Time.Add(30 * time.Second)
			if !replay.markIfFresh(claims.ID, until, now) {
				audit(AuditEvent{
					Timestamp: start, RequestID: reqID, MandateID: claims.ID,
					AgentIdentity: agentSPIFFE, PlatformIdentity: platformID,
					Action: claims.Act, Constraints: claims.Con,
					Decision: "deny", Reason: "poa_replay_detected",
					Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
				})
				brokerRequestsTotal.WithLabelValues("deny", claims.Act).Inc()
				http.Error(w, "PoA replay detected", http.StatusForbidden)
				return
			}
		}

		audit(AuditEvent{
			Timestamp: start, RequestID: reqID, MandateID: claims.ID,
			AgentIdentity: agentSPIFFE, PlatformIdentity: platformID,
			Action: claims.Act, Constraints: claims.Con,
			Decision: "allow", Reason: "policy_allow",
			Target: targetURL.String(), Method: r.Method, Path: r.URL.Path,
		})
		brokerRequestsTotal.WithLabelValues("allow", claims.Act).Inc()

		// Resolve and validate connector if registry is configured
		if connRegistry != nil {
			connectorIDFromPoA := ""
			if claims.Con != nil {
				if cid, ok := claims.Con["connector"].(string); ok {
					connectorIDFromPoA = cid
				}
			}
			connectorHeader := strings.TrimSpace(r.Header.Get("X-ATB-Connector"))
			conn, connErr := connRegistry.Resolve(connectorIDFromPoA, connectorHeader)
			if connErr != nil {
				connectorRequestsTotal.WithLabelValues(connectorIDFromPoA, "deny", connErr.Code).Inc()
				http.Error(w, connErr.Message, http.StatusBadRequest)
				return
			}
			if valErr := conn.ValidateRequest(r.URL.Path); valErr != nil {
				if valErr.Code == "egress_denied" {
					connectorEgressDenied.WithLabelValues(conn.ID).Inc()
				} else if valErr.Code == "rate_limited" {
					connectorRateLimited.WithLabelValues(conn.ID).Inc()
				}
				connectorRequestsTotal.WithLabelValues(conn.ID, "deny", valErr.Code).Inc()
				http.Error(w, valErr.Message, http.StatusForbidden)
				return
			}
			conn.AddHeaders(r)
			connectorRequestsTotal.WithLabelValues(conn.ID, "allow", "").Inc()
			conn.proxy.ServeHTTP(w, r)
			return
		}

		proxy.ServeHTTP(w, r)
	})

	// Health and metrics mux
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

	// Combined mux for HTTP server (health + proxy for dev mode)
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	httpMux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 1200*time.Millisecond)
		defer cancel()
		if err := checkHTTPHealth(ctx, httpClient, opaHealthURL); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ready\n"))
	})
	httpMux.Handle("/metrics", promhttp.Handler())
	// Proxy all other requests through the main handler (for dev mode without mTLS)
	httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	})

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
		Handler:           httpMux,
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
