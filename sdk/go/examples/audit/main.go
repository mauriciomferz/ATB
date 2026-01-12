// Package main demonstrates audit log analysis with the ATB Go SDK.
package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"time"

	atb "github.com/mauriciomferz/ATB/sdk/go"
)

// Counter is a simple counter for string values.
type Counter map[string]int

// Increment adds one to the count for a key.
func (c Counter) Increment(key string) {
	c[key]++
}

// TopN returns the top N entries by count.
func (c Counter) TopN(n int) []struct {
	Key   string
	Count int
} {
	type kv struct {
		Key   string
		Count int
	}

	var entries []kv
	for k, v := range c {
		entries = append(entries, kv{k, v})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	if len(entries) > n {
		entries = entries[:n]
	}

	result := make([]struct {
		Key   string
		Count int
	}, len(entries))
	for i, e := range entries {
		result[i] = struct {
			Key   string
			Count int
		}{e.Key, e.Count}
	}
	return result
}

// AnalyzeAuditLogs analyzes recent audit logs.
func AnalyzeAuditLogs(ctx context.Context, client *atb.Client, hours int) error {
	logs, err := client.GetAuditLog(ctx, atb.AuditLogOptions{
		Limit: 1000,
	})
	if err != nil {
		return fmt.Errorf("failed to get audit logs: %w", err)
	}

	if len(logs) == 0 {
		fmt.Println("No audit logs found")
		return nil
	}

	fmt.Printf("\n=== Audit Log Analysis (last %d hours) ===\n\n", hours)
	fmt.Printf("Total events: %d\n", len(logs))

	// Analyze by decision
	decisions := make(Counter)
	riskTiers := make(Counter)
	actions := make(Counter)
	agents := make(Counter)

	for _, log := range logs {
		if decision, ok := log["decision"].(string); ok {
			decisions.Increment(decision)
		}
		if riskTier, ok := log["risk_tier"].(string); ok {
			riskTiers.Increment(riskTier)
		}
		if action, ok := log["action"].(string); ok {
			actions.Increment(action)
		}
		if agent, ok := log["agent"].(string); ok {
			// Extract last part of SPIFFE ID
			for i := len(agent) - 1; i >= 0; i-- {
				if agent[i] == '/' {
					agent = agent[i+1:]
					break
				}
			}
			agents.Increment(agent)
		}
	}

	fmt.Println("\nBy Decision:")
	fmt.Printf("  Allowed: %d\n", decisions["allow"])
	fmt.Printf("  Denied: %d\n", decisions["deny"])

	fmt.Println("\nBy Risk Tier:")
	for _, tier := range []string{"LOW", "MEDIUM", "HIGH"} {
		fmt.Printf("  %s: %d\n", tier, riskTiers[tier])
	}

	fmt.Println("\nTop 5 Actions:")
	for _, entry := range actions.TopN(5) {
		fmt.Printf("  %s: %d\n", entry.Key, entry.Count)
	}

	fmt.Println("\nTop 5 Agents:")
	for _, entry := range agents.TopN(5) {
		fmt.Printf("  %s: %d\n", entry.Key, entry.Count)
	}

	return nil
}

// ExportLogsCSV exports audit logs to CSV.
func ExportLogsCSV(ctx context.Context, client *atb.Client, filename string) error {
	logs, err := client.GetAuditLog(ctx, atb.AuditLogOptions{
		Limit: 10000,
	})
	if err != nil {
		return fmt.Errorf("failed to get audit logs: %w", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"timestamp", "action", "agent", "decision", "risk_tier", "duration_ms", "audit_id"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write rows
	for _, log := range logs {
		row := []string{
			fmt.Sprintf("%v", log["timestamp"]),
			fmt.Sprintf("%v", log["action"]),
			fmt.Sprintf("%v", log["agent"]),
			fmt.Sprintf("%v", log["decision"]),
			fmt.Sprintf("%v", log["risk_tier"]),
			fmt.Sprintf("%v", log["duration_ms"]),
			fmt.Sprintf("%v", log["id"]),
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write row: %w", err)
		}
	}

	fmt.Printf("Exported %d logs to %s\n", len(logs), filename)
	return nil
}

func main() {
	// Create client
	client, err := atb.NewClient(atb.DefaultConfig())
	if err != nil {
		panic(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Analyze logs
	if err := AnalyzeAuditLogs(ctx, client, 24); err != nil {
		fmt.Printf("Error analyzing logs: %v\n", err)
	}

	// Export to CSV
	if err := ExportLogsCSV(ctx, client, "audit_logs.csv"); err != nil {
		fmt.Printf("Error exporting logs: %v\n", err)
	}
}
