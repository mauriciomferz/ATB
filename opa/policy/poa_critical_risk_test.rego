package atb.poa_test

import rego.v1

import data.atb.poa

# ==============================================================================
# CRITICAL Risk Tier Tests
# Tests for executive-level approval requirements on critical actions
# ==============================================================================

# Helper: Base PoA for critical actions
critical_base_poa := {
	"sub": "spiffe://example.com/agent/treasury",
	"act": "finance.wire.over_10m",
	"con": {},
	"leg": {
		"basis": "contract",
		"jurisdiction": "US",
		"accountable_party": {"type": "human", "id": "cfo@example.com"},
	},
	"iat": 1700000000,
	"exp": 1700000300,
	"jti": "critical-test-123",
}

critical_base_input := {
	"agent": {"spiffe_id": "spiffe://example.com/agent/treasury"},
	"poa": critical_base_poa,
	"request": {"method": "POST", "path": "/treasury/wire", "action": "finance.wire.over_10m"},
	"policy": {"max_ttl_seconds": 300},
}

# ==============================================================================
# Critical Tier Detection Tests
# ==============================================================================

# Test: Finance wire over 10M is detected as critical
test_critical_tier_detected if {
	tier := poa.action_risk_tier with input as critical_base_input
	tier == "critical"
}

# Test: Security root access is critical
test_security_root_access_critical if {
	poa_security := object.union(critical_base_poa, {
		"act": "security.root.access",
	})
	
	input_security := object.union(critical_base_input, {
		"poa": poa_security,
		"request": {"method": "POST", "path": "/security/root", "action": "security.root.access"},
	})
	
	tier := poa.action_risk_tier with input as input_security
	tier == "critical"
}

# Test: OT emergency stop is critical
test_ot_emergency_critical if {
	poa_ot := object.union(critical_base_poa, {
		"act": "ot.emergency.stop_all",
	})
	
	input_ot := object.union(critical_base_input, {
		"poa": poa_ot,
		"request": {"method": "POST", "path": "/ot/emergency", "action": "ot.emergency.stop_all"},
	})
	
	tier := poa.action_risk_tier with input as input_ot
	tier == "critical"
}

# ==============================================================================
# Executive Approval Tests
# ==============================================================================

# Test: Critical action without executive approval is denied
test_critical_without_executive_approval_denied if {
	d := poa.decision with input as critical_base_input
	
	d.allow == false
	d.reason == "critical_risk_executive_approval_required"
	d.details.tier == "critical"
}

# Test: Critical action with valid executive approval is allowed
test_critical_with_executive_approval_allowed if {
	poa_approved := object.union(critical_base_poa, {
		"leg": {
			"basis": "board_resolution",
			"jurisdiction": "US",
			"accountable_party": {"type": "human", "id": "cfo@example.com"},
			"executive_control": {
				"required": true,
				"approvers": [
					{"id": "ceo@example.com", "type": "human", "role": "CEO", "timestamp": 1700000100},
					{"id": "cfo@example.com", "type": "human", "role": "CFO", "timestamp": 1700000150},
				],
			},
		},
	})
	
	input_approved := object.union(critical_base_input, {
		"poa": poa_approved,
	})
	
	d := poa.decision with input as input_approved
	d.allow == true
}

# Test: Critical action with only one executive approver is denied
test_critical_single_executive_denied if {
	poa_single := object.union(critical_base_poa, {
		"leg": {
			"basis": "board_resolution",
			"jurisdiction": "US",
			"accountable_party": {"type": "human", "id": "cfo@example.com"},
			"executive_control": {
				"required": true,
				"approvers": [
					{"id": "ceo@example.com", "type": "human", "role": "CEO", "timestamp": 1700000100},
				],
			},
		},
	})
	
	input_single := object.union(critical_base_input, {
		"poa": poa_single,
	})
	
	d := poa.decision with input as input_single
	d.allow == false
	d.reason == "critical_risk_executive_approval_required"
}

# Test: Critical action with non-executive roles is denied
test_critical_non_executive_roles_denied if {
	poa_wrong_roles := object.union(critical_base_poa, {
		"leg": {
			"basis": "board_resolution",
			"jurisdiction": "US",
			"accountable_party": {"type": "human", "id": "manager@example.com"},
			"executive_control": {
				"required": true,
				"approvers": [
					{"id": "manager@example.com", "type": "human", "role": "Manager", "timestamp": 1700000100},
					{"id": "director@example.com", "type": "human", "role": "Director", "timestamp": 1700000150},
				],
			},
		},
	})
	
	input_wrong := object.union(critical_base_input, {
		"poa": poa_wrong_roles,
	})
	
	d := poa.decision with input as input_wrong
	d.allow == false
	d.reason == "critical_risk_executive_approval_required"
}

# Test: Board member and CEO can approve critical actions
test_critical_board_ceo_approval_allowed if {
	poa_board := object.union(critical_base_poa, {
		"act": "org.company.merge",
		"leg": {
			"basis": "board_resolution",
			"jurisdiction": "US",
			"accountable_party": {"type": "human", "id": "board_chair@example.com"},
			"executive_control": {
				"required": true,
				"approvers": [
					{"id": "board_chair@example.com", "type": "human", "role": "board_member", "timestamp": 1700000100},
					{"id": "ceo@example.com", "type": "human", "role": "CEO", "timestamp": 1700000150},
				],
			},
		},
	})
	
	input_board := object.union(critical_base_input, {
		"poa": poa_board,
		"request": {"method": "POST", "path": "/org/merge", "action": "org.company.merge"},
	})
	
	d := poa.decision with input as input_board
	d.allow == true
}

# Test: High-risk action is NOT critical
test_high_risk_not_critical if {
	poa_high := object.union(critical_base_poa, {
		"act": "sap.payment.execute",
	})
	
	input_high := object.union(critical_base_input, {
		"poa": poa_high,
		"request": {"method": "POST", "path": "/sap/payments", "action": "sap.payment.execute"},
	})
	
	tier := poa.action_risk_tier with input as input_high
	tier == "high"
}

# Test: Data full export is critical
test_data_full_export_critical if {
	poa_data := object.union(critical_base_poa, {
		"act": "data.customer.full_export",
	})
	
	input_data := object.union(critical_base_input, {
		"poa": poa_data,
		"request": {"method": "POST", "path": "/data/export", "action": "data.customer.full_export"},
	})
	
	tier := poa.action_risk_tier with input as input_data
	tier == "critical"
}
