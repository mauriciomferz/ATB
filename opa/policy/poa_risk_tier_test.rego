package atb.poa

# Tests for medium-risk and high-risk tier enforcement

# Base input for a medium-risk action (crm.contact.update)
medium_risk_base := {
	"agent": {"spiffe_id": "spiffe://atb.example/agent/crm-agent"},
	"poa": {
		"sub": "spiffe://atb.example/agent/crm-agent",
		"act": "crm.contact.update",
		"con": {},
		"leg": {
			"jurisdiction": "US",
			"accountable_party": {"type": "employee", "id": "emp-100"},
			"approval": {
				"approver_id": "manager-001",
				"approved_at": "2024-01-15T10:00:00Z",
			},
		},
		"iat": 1700000000,
		"exp": 1700000300,
		"jti": "medium-risk-001",
	},
	"request": {"method": "POST", "path": "/crm/contacts", "action": "crm.contact.update", "params": {}},
	"policy": {"max_ttl_seconds": 300},
}

# Base input for a high-risk action (sap.vendor.create - no constraint-specific rules)
high_risk_base := {
	"agent": {"spiffe_id": "spiffe://atb.example/agent/export-agent"},
	"poa": {
		"sub": "spiffe://atb.example/agent/export-agent",
		"act": "sap.vendor.create",
		"con": {},
		"leg": {
			"jurisdiction": "EU",
			"accountable_party": {"type": "employee", "id": "emp-200"},
			"dual_control": {
				"required": true,
				"approvers": [
					{"id": "approver-a", "type": "manager"},
					{"id": "approver-b", "type": "compliance"},
				],
			},
		},
		"iat": 1700000000,
		"exp": 1700000300,
		"jti": "high-risk-001",
	},
	"request": {"method": "POST", "path": "/sap/vendor", "action": "sap.vendor.create", "params": {}},
	"policy": {"max_ttl_seconds": 300},
}

# Test: medium-risk with proper approval is allowed
test_medium_risk_with_approval_allowed if {
	decision.allow with input as medium_risk_base
}

# Test: medium-risk without approval is denied
test_medium_risk_without_approval_denied if {
	inp := json.patch(medium_risk_base, [{"op": "remove", "path": "/poa/leg/approval"}])
	d := decision with input as inp
	d.allow == false
	d.reason == "medium_risk_approval_required"
}

# Test: medium-risk with self-approval is denied
test_medium_risk_self_approval_denied if {
	inp := json.patch(medium_risk_base, [{"op": "replace", "path": "/poa/leg/approval/approver_id", "value": "spiffe://atb.example/agent/crm-agent"}])
	d := decision with input as inp
	d.allow == false
	d.reason == "medium_risk_approval_required"
}

# Test: high-risk with dual control is allowed
test_high_risk_with_dual_control_allowed if {
	decision.allow with input as high_risk_base
}

# Test: high-risk without dual control is denied
test_high_risk_without_dual_control_denied if {
	inp := json.patch(high_risk_base, [{"op": "remove", "path": "/poa/leg/dual_control"}])
	d := decision with input as inp
	d.allow == false
	d.reason == "high_risk_dual_control_required"
}

# Test: high-risk with only one approver is denied
test_high_risk_single_approver_denied if {
	inp := json.patch(high_risk_base, [{"op": "replace", "path": "/poa/leg/dual_control/approvers", "value": [{"id": "approver-a", "type": "manager"}]}])
	d := decision with input as inp
	d.allow == false
	d.reason == "high_risk_dual_control_required"
}

# Test: high-risk with requester as approver is denied
test_high_risk_self_approval_denied if {
	inp := json.patch(high_risk_base, [{"op": "replace", "path": "/poa/leg/dual_control/approvers", "value": [
		{"id": "spiffe://atb.example/agent/export-agent", "type": "requester"},
		{"id": "approver-b", "type": "manager"},
	]}])
	d := decision with input as inp
	d.allow == false
	d.reason == "high_risk_dual_control_required"
}

# Test: low-risk action (not in medium or high list) is allowed without special approval
test_low_risk_action_allowed if {
	inp := json.patch(medium_risk_base, [
		{"op": "replace", "path": "/poa/act", "value": "custom.low_risk.action"},
		{"op": "replace", "path": "/request/action", "value": "custom.low_risk.action"},
		{"op": "remove", "path": "/poa/leg/approval"},
	])
	decision.allow with input as inp
}
