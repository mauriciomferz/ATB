// Package atb provides a Go client for the Agent Trust Broker (ATB).
//
// The ATB SDK enables applications to create, sign, and submit
// Proof-of-Authorization (PoA) mandates for AI agent actions.
//
// # Quick Start
//
//	client, err := atb.NewClient(atb.Config{
//	    BrokerURL: "http://localhost:8080",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	poa := atb.NewPoABuilder().
//	    ForAgent("spiffe://atb.example/agent/copilot").
//	    Action("sap.vendor.change").
//	    WithParams(map[string]any{"vendor_id": "V-12345", "amount": 5000}).
//	    WithConstraint("liability_cap", 10000).
//	    Legal(atb.LegalGrounding{
//	        Jurisdiction: "DE",
//	        AccountableParty: atb.AccountableParty{
//	            Type: "user",
//	            ID:   "alice@example.com",
//	        },
//	    }).
//	    Build()
//
//	result, err := client.Execute(ctx, poa, privateKey)
package atb

import "errors"

// Version is the SDK version.
const Version = "0.1.0"

// Common errors returned by the SDK.
var (
	ErrAuthorizationDenied = errors.New("authorization denied by policy")
	ErrTokenExpired        = errors.New("PoA token has expired")
	ErrValidation          = errors.New("PoA validation failed")
	ErrConnection          = errors.New("connection to ATB services failed")
)
