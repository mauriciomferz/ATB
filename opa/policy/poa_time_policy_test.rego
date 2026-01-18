package atb.poa_test

import rego.v1

import data.atb.poa

# ==============================================================================
# Time-based Policy Tests
# Tests for business hours, rate limiting, and approval expiration
# ==============================================================================

# Helper: Generate a valid base PoA (using low-risk action for simplicity)
valid_base_poa := {
	"sub": "spiffe://example.com/agent/test",
	"act": "crm.contact.read",
	"con": {},
	"leg": {
		"basis": "contract",
		"jurisdiction": "US",
		"accountable_party": {"type": "human", "id": "alice@example.com"},
	},
	"iat": 1700000000,
	"exp": 1700000300,
	"jti": "test-jti-123",
}

valid_base_input := {
	"agent": {"spiffe_id": "spiffe://example.com/agent/test"},
	"poa": valid_base_poa,
	"request": {"method": "GET", "path": "/crm/contacts", "action": "crm.contact.read"},
	"policy": {"max_ttl_seconds": 300},
}

# ==============================================================================
# Business Hours Tests
# ==============================================================================

# Test: Request during business hours (Tuesday 10 AM) should be allowed
test_business_hours_allowed if {
	# Tuesday Jan 2, 2024 10:00:00 UTC = 1704189600
	input_with_time := object.union(valid_base_input, {
		"current_time_ns": 1704189600000000000,  # 10 AM Tuesday
	})
	
	d := poa.decision with input as input_with_time
		with data.time_policy.business_hours.required_for_high_risk as true
	
	d.allow == true
}

# Test: High-risk action outside business hours is denied when required
test_business_hours_denied_high_risk_weekend if {
	high_risk_poa := object.union(valid_base_poa, {
		"act": "sap.payment.execute",
		"con": {"payment_limit": 10000},
		"leg": {
			"basis": "contract",
			"jurisdiction": "US",
			"jurisdiction": "US",
			"accountable_party": {"type": "human", "id": "alice@example.com"},
			"dual_control": {
				"required": true,
				"approvers": [
					{"id": "bob@example.com", "type": "human", "timestamp": 1704034800},
					{"id": "carol@example.com", "type": "human", "timestamp": 1704034800},
				],
			},
		},
	})
	
	input_weekend := {
		"agent": {"spiffe_id": "spiffe://example.com/agent/test"},
		"poa": high_risk_poa,
		"request": {"method": "POST", "path": "/sap/payments", "action": "sap.payment.execute", "params": {"amount": 5000, "payment_type": "standard"}},
		"policy": {"max_ttl_seconds": 300},
		"current_time_ns": 1704034800000000000,  # Saturday Jan 1, 2024 01:00:00 UTC
	}
	
	d := poa.decision with input as input_weekend
		with data.time_policy.business_hours.required_for_high_risk as true
	
	d.allow == false
	d.reason == "time_policy_violation"
}

# Test: Low-risk action outside business hours is allowed (no restriction)
test_business_hours_low_risk_always_allowed if {
	low_risk_input := object.union(valid_base_input, {
		"poa": object.union(valid_base_poa, {"act": "crm.contact.read"}),
		"request": {"method": "GET", "path": "/crm/contacts", "action": "crm.contact.read"},
		"current_time_ns": 1704034800000000000,  # Saturday
	})
	
	d := poa.decision with input as low_risk_input
		with data.time_policy.business_hours.required_for_high_risk as true
	
	d.allow == true
}

# Test: Business hours bypass via constraint
test_business_hours_bypass_with_constraint if {
	high_risk_poa := object.union(valid_base_poa, {
		"act": "sap.payment.execute",
		"con": {"payment_limit": 10000, "allow_outside_business_hours": true},
		"leg": {
			"basis": "contract",
			"jurisdiction": "US",
			"jurisdiction": "US",
			"accountable_party": {"type": "human", "id": "alice@example.com"},
			"dual_control": {
				"required": true,
				"approvers": [
					{"id": "bob@example.com", "type": "human", "timestamp": 1704034800},
					{"id": "carol@example.com", "type": "human", "timestamp": 1704034800},
				],
			},
		},
	})
	
	input_bypass := {
		"agent": {"spiffe_id": "spiffe://example.com/agent/test"},
		"poa": high_risk_poa,
		"request": {"method": "POST", "path": "/sap/payments", "action": "sap.payment.execute", "params": {"amount": 5000, "payment_type": "standard"}},
		"policy": {"max_ttl_seconds": 300},
		"current_time_ns": 1704034800000000000,  # Saturday
	}
	
	d := poa.decision with input as input_bypass
		with data.time_policy.business_hours.required_for_high_risk as true
	
	d.allow == true
}

# ==============================================================================
# Rate Limiting Tests
# Note: Uses medium-risk action (crm.contact.update) because low-risk actions
# are allowed without PoA and bypass time policy checks
# ==============================================================================

# Helper for rate limit tests - medium risk action that requires PoA with leg.approval
rate_limit_poa := {
	"sub": "spiffe://example.com/agent/test",
	"act": "crm.contact.update",
	"con": {},
	"leg": {
		"basis": "contract",
		"jurisdiction": "US",
		"accountable_party": {"type": "human", "id": "alice@example.com"},
		"approval": {
			"approver_id": "bob@example.com",
			"timestamp": 1700000100,
		},
	},
	"iat": 1700000000,
	"exp": 1700000300,
	"jti": "test-rate-limit-123",
}

rate_limit_base_input := {
	"agent": {"spiffe_id": "spiffe://example.com/agent/test"},
	"poa": rate_limit_poa,
	"request": {"method": "PUT", "path": "/crm/contacts/123", "action": "crm.contact.update"},
	"policy": {"max_ttl_seconds": 300},
}

# Test: Request within rate limit is allowed
test_rate_limit_within_limit if {
	input_with_rate := object.union(rate_limit_base_input, {
		"rate_limit_state": {"crm.contact.update": 50},
		"current_time_ns": 1704189600000000000,
	})
	
	d := poa.decision with input as input_with_rate
		with data.rate_limits as {"default_per_hour": 100}
	
	d.allow == true
}

# Test: Request exceeding rate limit is denied
test_rate_limit_exceeded if {
	input_exceeded := object.union(rate_limit_base_input, {
		"rate_limit_state": {"crm.contact.update": 100},
		"current_time_ns": 1704189600000000000,
	})
	
	d := poa.decision with input as input_exceeded
		with data.rate_limits as {"default_per_hour": 100}
	
	d.allow == false
	d.reason == "time_policy_violation"
}

# Test: Action-specific rate limit
test_rate_limit_per_action if {
	# This action has a specific limit of 10
	input_action_limit := object.union(rate_limit_base_input, {
		"rate_limit_state": {"crm.contact.update": 15},
		"current_time_ns": 1704189600000000000,
	})
	
	d := poa.decision with input as input_action_limit
		with data.rate_limits as {"default_per_hour": 100, "per_action": {"crm.contact.update": 10}}
	
	d.allow == false
	d.reason == "time_policy_violation"
}

# Test: Rate limit bypass via constraint
test_rate_limit_bypass if {
	poa_bypass := object.union(rate_limit_poa, {
		"con": {"bypass_rate_limit": true},
	})
	
	input_bypass := object.union(rate_limit_base_input, {
		"poa": poa_bypass,
		"rate_limit_state": {"crm.contact.update": 500},
		"current_time_ns": 1704189600000000000,
	})
	
	d := poa.decision with input as input_bypass
		with data.rate_limits as {"default_per_hour": 100}
	
	d.allow == true
}

# ==============================================================================
# Approval Expiration Tests
# ==============================================================================

# Test: Recent approval is valid
test_approval_recent_valid if {
	# Approval was 2 minutes ago
	poa_recent := object.union(valid_base_poa, {
		"leg": {
			"basis": "contract",
			"jurisdiction": "US",
			"accountable_party": {"type": "human", "id": "alice@example.com"},
			"approval": {
				"approver_id": "bob@example.com",
				"timestamp": 1704189480,  # 2 minutes before current time
			},
		},
	})
	
	input_recent := object.union(valid_base_input, {
		"poa": poa_recent,
		"current_time_ns": 1704189600000000000,  # Current time
	})
	
	d := poa.decision with input as input_recent
		with data.time_policy.approval_window_seconds as 300
	
	d.allow == true
}

# Test: Expired approval is denied
test_approval_expired if {
	# Approval was 10 minutes ago (600 seconds)
	poa_expired := object.union(valid_base_poa, {
		"leg": {
			"basis": "contract",
			"jurisdiction": "US",
			"accountable_party": {"type": "human", "id": "alice@example.com"},
			"approval": {
				"approver_id": "bob@example.com",
				"timestamp": 1704189000,  # 10 minutes before current time
			},
		},
	})
	
	input_expired := object.union(valid_base_input, {
		"poa": poa_expired,
		"current_time_ns": 1704189600000000000,
	})
	
	d := poa.decision with input as input_expired
		with data.time_policy.approval_window_seconds as 300
	
	d.allow == false
	d.reason == "time_policy_violation"
}

# Test: Dual control approval expiration uses oldest timestamp
test_dual_control_oldest_approval if {
	# First approver: 2 minutes ago, Second approver: 8 minutes ago (expired)
	poa_dual := object.union(valid_base_poa, {
		"act": "sap.payment.execute",
		"con": {"payment_limit": 10000},
		"leg": {
			"basis": "contract",
			"jurisdiction": "US",
			"accountable_party": {"type": "human", "id": "alice@example.com"},
			"dual_control": {
				"required": true,
				"approvers": [
					{"id": "bob@example.com", "type": "human", "timestamp": 1704189480},   # 2 min ago
					{"id": "carol@example.com", "type": "human", "timestamp": 1704189120}, # 8 min ago
				],
			},
		},
	})
	
	input_dual := {
		"agent": {"spiffe_id": "spiffe://example.com/agent/test"},
		"poa": poa_dual,
		"request": {"method": "POST", "path": "/sap/payments", "action": "sap.payment.execute", "params": {"amount": 5000, "payment_type": "standard"}},
		"policy": {"max_ttl_seconds": 300},
		"current_time_ns": 1704189600000000000,
	}
	
	d := poa.decision with input as input_dual
		with data.time_policy.approval_window_seconds as 300
	
	d.allow == false
	d.reason == "time_policy_violation"
}

# Test: No approval timestamp means no time check (for low-risk)
test_no_approval_no_check if {
	poa_no_approval := object.union(valid_base_poa, {
		"act": "crm.contact.read",
		"leg": {
			"basis": "legitimate_interest",
			"jurisdiction": "US",
			"accountable_party": {"type": "human", "id": "alice@example.com"},
		},
	})
	
	input_no_approval := object.union(valid_base_input, {
		"poa": poa_no_approval,
		"request": {"method": "GET", "path": "/crm/contacts", "action": "crm.contact.read"},
		"current_time_ns": 1704189600000000000,
	})
	
	d := poa.decision with input as input_no_approval
		with data.time_policy.approval_window_seconds as 300
	
	d.allow == true
}

# ==============================================================================
# Combined Time Policy Tests
# ==============================================================================

# Test: All time policies pass
test_all_time_policies_pass if {
	input_all_pass := object.union(valid_base_input, {
		"current_time_ns": 1704189600000000000,  # Tuesday 10 AM
		"rate_limit_state": {"crm.contact.read": 5},
		"poa": object.union(valid_base_poa, {
			"leg": {
				"basis": "contract",
			"jurisdiction": "US",
				"accountable_party": {"type": "human", "id": "alice@example.com"},
				"approval": {
					"approver_id": "bob@example.com",
					"timestamp": 1704189540,  # 1 minute ago
				},
			},
		}),
	})
	
	d := poa.decision with input as input_all_pass
		with data.time_policy.business_hours.required_for_high_risk as true
		with data.time_policy.approval_window_seconds as 300
		with data.rate_limits as {"default_per_hour": 100}
	
	d.allow == true
}

# Test: Multiple time policy violations reported
test_multiple_violations if {
	input_multi := object.union(valid_base_input, {
		"current_time_ns": 1704034800000000000,  # Saturday (outside business hours)
		"rate_limit_state": {"crm.contact.read": 200},  # Over limit
		"poa": object.union(valid_base_poa, {
			"act": "sap.payment.execute",
			"con": {"payment_limit": 10000},
			"leg": {
				"basis": "contract",
			"jurisdiction": "US",
				"accountable_party": {"type": "human", "id": "alice@example.com"},
				"dual_control": {
					"required": true,
					"approvers": [
						{"id": "bob@example.com", "type": "human", "timestamp": 1704024000},  # 3 hours ago
						{"id": "carol@example.com", "type": "human", "timestamp": 1704024000},
					],
				},
			},
		}),
	})
	
	# Just verify it's denied - violations may vary based on evaluation order
	d := poa.decision with input as input_multi
		with input.request.action as "sap.payment.execute"
		with input.request.params as {"amount": 5000, "payment_type": "standard"}
		with data.time_policy.business_hours.required_for_high_risk as true
		with data.time_policy.approval_window_seconds as 300
		with data.rate_limits as {"default_per_hour": 100}
	
	d.allow == false
}
