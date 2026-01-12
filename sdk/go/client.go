package atb

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Config holds the ATB client configuration.
type Config struct {
	BrokerURL     string        // Broker endpoint (default: http://localhost:8080)
	AgentAuthURL  string        // AgentAuth endpoint (default: http://localhost:8081)
	Timeout       time.Duration // Request timeout (default: 30s)
	HTTPClient    *http.Client  // Custom HTTP client (optional)
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() Config {
	return Config{
		BrokerURL:    "http://localhost:8080",
		AgentAuthURL: "http://localhost:8081",
		Timeout:      30 * time.Second,
	}
}

// ActionResult represents the result of an action execution.
type ActionResult struct {
	Success  bool           `json:"success"`
	Data     map[string]any `json:"data,omitempty"`
	Error    string         `json:"error,omitempty"`
	AuditID  string         `json:"audit_id,omitempty"`
	Decision string         `json:"decision,omitempty"` // "allow" or "deny"
}

// Client is the ATB client for executing actions.
type Client struct {
	config     Config
	httpClient *http.Client
}

// NewClient creates a new ATB client.
func NewClient(config Config) (*Client, error) {
	if config.BrokerURL == "" {
		config.BrokerURL = "http://localhost:8080"
	}
	if config.AgentAuthURL == "" {
		config.AgentAuthURL = "http://localhost:8081"
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: config.Timeout,
		}
	}

	return &Client{
		config:     config,
		httpClient: httpClient,
	}, nil
}

// Execute submits a PoA mandate to the broker.
func (c *Client) Execute(ctx context.Context, poa *PoA, privateKey *ecdsa.PrivateKey) (*ActionResult, error) {
	// Sign the PoA
	token, err := poa.ToJWT(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign PoA: %w", err)
	}

	// Prepare request body
	body := map[string]any{
		"action": poa.Act,
		"params": poa.Con.Params,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", c.config.BrokerURL+"/v1/action", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnection, err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var data map[string]any
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &data); err != nil {
			data = map[string]any{"raw": string(respBody)}
		}
	}

	// Handle response
	switch resp.StatusCode {
	case http.StatusOK:
		return &ActionResult{
			Success:  true,
			Data:     data,
			AuditID:  resp.Header.Get("X-Audit-ID"),
			Decision: "allow",
		}, nil

	case http.StatusForbidden:
		errMsg := "action denied by policy"
		if msg, ok := data["error"].(string); ok {
			errMsg = msg
		}
		return nil, fmt.Errorf("%w: %s", ErrAuthorizationDenied, errMsg)

	default:
		errMsg := fmt.Sprintf("request failed with status %d", resp.StatusCode)
		if msg, ok := data["error"].(string); ok {
			errMsg = msg
		}
		return &ActionResult{
			Success: false,
			Error:   errMsg,
			Data:    data,
		}, nil
	}
}

// CheckPolicy checks if an action would be allowed without executing it.
func (c *Client) CheckPolicy(ctx context.Context, action string, params map[string]any, agentSPIFFEID string) (map[string]any, error) {
	body := map[string]any{
		"action": action,
		"params": params,
		"agent":  agentSPIFFEID,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.config.BrokerURL+"/v1/policy/check", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnection, err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

// GetAuditLog retrieves audit log entries.
func (c *Client) GetAuditLog(ctx context.Context, opts AuditLogOptions) ([]map[string]any, error) {
	url := fmt.Sprintf("%s/v1/audit?limit=%d", c.config.BrokerURL, opts.Limit)
	if opts.AuditID != "" {
		url += "&audit_id=" + opts.AuditID
	}
	if opts.Action != "" {
		url += "&action=" + opts.Action
	}
	if opts.Agent != "" {
		url += "&agent=" + opts.Agent
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnection, err)
	}
	defer resp.Body.Close()

	var entries []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return entries, nil
}

// AuditLogOptions configures audit log queries.
type AuditLogOptions struct {
	AuditID string
	Action  string
	Agent   string
	Limit   int
}

// Close cleans up client resources.
func (c *Client) Close() error {
	// Currently no cleanup needed
	return nil
}
