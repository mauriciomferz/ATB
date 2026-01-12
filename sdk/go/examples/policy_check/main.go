package policycheck
// Package main demonstrates policy pre-check with the ATB Go SDK.
package main

import (
	"context"
	"fmt"
	"time"

	atb "github.com/mauriciomferz/ATB/sdk/go"
)

// CheckPermissions checks which actions a user is authorized to perform.
func CheckPermissions(ctx context.Context, client *atb.Client, userID string, actions []string) map[string]bool {
	results := make(map[string]bool)
	agentSPIFFEID := fmt.Sprintf("spiffe://atb.example/user/%s", userID)

	for _, action := range actions {
		result, err := client.CheckPolicy(ctx, action, nil, agentSPIFFEID)
		if err != nil {
			fmt.Printf("Error checking %s: %v\n", action, err)
			results[action] = false
			continue
		}

		allowed, ok := result["allow"].(bool)
		results[action] = ok && allowed
	}

	return results
}

func main() {
	// Create client
	client, err := atb.NewClient(atb.DefaultConfig())
	if err != nil {
		panic(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Define actions to check
	actionsToCheck := []string{
		"sap.vendor.read",
		"sap.vendor.create",
		"sap.vendor.update",























}	}		}			fmt.Printf("  %s %s\n", status, action)			}				status = "✓"			if permissions[action] {			status := "✗"		for _, action := range actionsToCheck {		permissions := CheckPermissions(ctx, client, user, actionsToCheck)		fmt.Println("----------------------------------------")		fmt.Printf("\nPermissions for %s:\n", user)	for _, user := range users {	users := []string{"alice", "bob", "readonly-service"}	// Check permissions for different users	}		"sap.payment.execute",		"sap.payment.approve",		"sap.vendor.delete",