// Package main demonstrates batch action execution with the ATB Go SDK.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	atb "github.com/mauriciomferz/ATB/sdk/go"
)

// VendorOperation represents a vendor operation to execute.
type VendorOperation struct {
	Action   string
	VendorID string
	Params   map[string]any
}

// BatchResult holds the result of a batch operation.
type BatchResult struct {
	Operation VendorOperation
	Result    *atb.ActionResult
	Error     error
}

// ExecuteBatch executes multiple actions concurrently.
func ExecuteBatch(
	ctx context.Context,
	client *atb.Client,
	privateKey *ecdsa.PrivateKey,
	operations []VendorOperation,
	userEmail string,
) []BatchResult {
	results := make([]BatchResult, len(operations))
	var wg sync.WaitGroup

	for i, op := range operations {
		wg.Add(1)
		go func(idx int, operation VendorOperation) {
			defer wg.Done()

			// Build PoA for this operation
			poa, err := atb.NewPoABuilder().
				ForAgent("spiffe://atb.example/agent/batch-processor").
				Action(operation.Action).
				WithParams(map[string]any{
					"vendor_id": operation.VendorID,
				}).
				Legal(atb.LegalGrounding{
					Jurisdiction: "DE",
					AccountableParty: atb.AccountableParty{
						Type:        "user",
						ID:          userEmail,
						DisplayName: "Batch User",
					},
				}).
				Build()
			if err != nil {
				results[idx] = BatchResult{
					Operation: operation,
					Error:     err,
				}
				return
			}

			// Execute
			result, err := client.Execute(ctx, poa, privateKey)
			results[idx] = BatchResult{
				Operation: operation,
				Result:    result,
				Error:     err,
			}
		}(i, op)
	}

	wg.Wait()
	return results
}

func main() {
	// Create client
	client, err := atb.NewClient(atb.DefaultConfig())
	if err != nil {
		panic(err)
	}
	defer client.Close()

	// Load private key (in production, use secure key management)
	privateKey, err := loadPrivateKey("./private.pem")
	if err != nil {
		fmt.Println("Warning: Could not load private key, using demo mode")
		privateKey = nil
	}

	// Define batch operations
	operations := []VendorOperation{
		{Action: "sap.vendor.read", VendorID: "V-001"},
		{Action: "sap.vendor.read", VendorID: "V-002"},
		{Action: "sap.vendor.read", VendorID: "V-003"},
		{Action: "sap.payment.list", VendorID: "V-001"},
	}

	// Execute batch
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results := ExecuteBatch(ctx, client, privateKey, operations, "batch-user@example.com")

	// Print results
	fmt.Println("\n=== Batch Execution Results ===")
	successful := 0
	failed := 0

	for _, r := range results {
		if r.Error != nil {
			fmt.Printf("✗ %s (%s): %v\n", r.Operation.Action, r.Operation.VendorID, r.Error)
			failed++
		} else if r.Result.Success {
			fmt.Printf("✓ %s (%s): Success\n", r.Operation.Action, r.Operation.VendorID)
			successful++
		} else {
			fmt.Printf("✗ %s (%s): %s\n", r.Operation.Action, r.Operation.VendorID, r.Result.Error)
			failed++
		}
	}

	fmt.Printf("\nSummary: %d succeeded, %d failed\n", successful, failed)
}

// loadPrivateKey loads an ECDSA private key from a PEM file.
func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an ECDSA private key")
		}
		return ecKey, nil
	}

	return key, nil
}
