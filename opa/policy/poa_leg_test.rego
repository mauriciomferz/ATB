package atb.poa

# Tests for legal grounding (leg) claim validation

# Helper: minimal valid input
base_input := {
	"agent": {"spiffe_id": "spiffe://atb.example/agent/task-agent"},
	"poa": {
		"sub": "spiffe://atb.example/agent/task-agent",
		"act": "sap.vendor.change",
		"con": {"liability_cap": 1000},
		"leg": {
			"jurisdiction": "DE",
			"accountable_party": {
				"type": "employee",
				"id": "emp-123",
				"display_name": "Alice Smith"
			}
		},
		"iat": 1700000000,
		"exp": 1700000300,
		"jti": "test-jti-001"
	},
	"request": {"method": "POST", "path": "/test", "action": "sap.vendor.change", "params": {"amount": 500}},
	"policy": {"max_ttl_seconds": 300}
}

# Test: valid leg allows request
test_leg_valid_allows {
	decision.allow with input as base_input
}

# Test: missing leg field entirely
test_leg_missing_denies {
	inp := json.patch(base_input, [{"op": "remove", "path": "/poa/leg"}])
	d := decision with input as inp
	d.allow == false
	d.reason == "missing_required_fields"
}

# Test: leg missing jurisdiction
test_leg_missing_jurisdiction {
	inp := json.patch(base_input, [{"op": "remove", "path": "/poa/leg/jurisdiction"}])
	d := decision with input as inp
	d.allow == false
	d.reason == "leg_invalid"
}

# Test: leg empty jurisdiction
test_leg_empty_jurisdiction {
	inp := json.patch(base_input, [{"op": "replace", "path": "/poa/leg/jurisdiction", "value": ""}])
	d := decision with input as inp
	d.allow == false
	d.reason == "leg_invalid"
}

# Test: leg missing accountable_party
test_leg_missing_accountable_party {
	inp := json.patch(base_input, [{"op": "remove", "path": "/poa/leg/accountable_party"}])
	d := decision with input as inp
	d.allow == false
	d.reason == "leg_invalid"
}

# Test: leg accountable_party missing type
test_leg_accountable_party_missing_type {
	inp := json.patch(base_input, [{"op": "remove", "path": "/poa/leg/accountable_party/type"}])
	d := decision with input as inp
	d.allow == false
	d.reason == "leg_invalid"
}

# Test: leg accountable_party missing id
test_leg_accountable_party_missing_id {
	inp := json.patch(base_input, [{"op": "remove", "path": "/poa/leg/accountable_party/id"}])
	d := decision with input as inp
	d.allow == false
	d.reason == "leg_invalid"
}

# Test: leg accountable_party empty id
test_leg_accountable_party_empty_id {
	inp := json.patch(base_input, [{"op": "replace", "path": "/poa/leg/accountable_party/id", "value": ""}])
	d := decision with input as inp
	d.allow == false
	d.reason == "leg_invalid"
}

# Test: valid leg with optional fields (dual_control, approval_ref)
test_leg_valid_with_optional_fields {
	inp := json.patch(base_input, [
		{"op": "add", "path": "/poa/leg/approval_ref", "value": "SNOW-INC-001"},
		{"op": "add", "path": "/poa/leg/dual_control", "value": {
			"required": true,
			"approver": {"type": "manager", "id": "mgr-456"},
			"approved_at": "2024-01-15T10:00:00Z"
		}},
		{"op": "add", "path": "/poa/leg/regulation_refs", "value": ["NIS2", "EU-AI-Act"]}
	])
	decision.allow with input as inp
}

# Test: GLOBAL jurisdiction is valid
test_leg_global_jurisdiction {
	inp := json.patch(base_input, [{"op": "replace", "path": "/poa/leg/jurisdiction", "value": "GLOBAL"}])
	decision.allow with input as inp
}
