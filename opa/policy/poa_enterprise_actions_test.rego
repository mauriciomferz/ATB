package atb.poa

# Additional tests for enterprise action coverage
# Tests for various action categories: IAM, Payments, SAP, OT, Compliance

# ─────────────────────────────────────────────────────────────────────────────
# IAM Actions Tests
# ─────────────────────────────────────────────────────────────────────────────

iam_role_assign_base := {
	"agent": {"spiffe_id": "spiffe://atb.example/agent/iam-agent"},
	"poa": {
		"sub": "spiffe://atb.example/agent/iam-agent",
		"act": "iam.role.assign",
		"con": {"user_id": "user-123", "target_role": "admin", "assignable_roles": ["admin", "viewer"]},
		"leg": {
			"jurisdiction": "US",
			"accountable_party": {"type": "employee", "id": "security-admin"},
			"dual_control": {
				"required": true,
				"approvers": [
					{"id": "approver-security", "type": "security"},
					{"id": "approver-manager", "type": "manager"},
				],
			},
		},
		"iat": 1700000000,
		"exp": 1700000300,
		"jti": "iam-assign-001",
	},
	"request": {"method": "POST", "path": "/iam/roles", "action": "iam.role.assign", "params": {"role_name": "admin", "target_user_id": "other-user-456"}},
	"policy": {"max_ttl_seconds": 300},
}

test_iam_role_assign_without_dual_control_denied if {
	inp := json.patch(iam_role_assign_base, [{"op": "remove", "path": "/poa/leg/dual_control"}])
	d := decision with input as inp
	d.allow == false
}

test_iam_role_assign_with_dual_control_allowed if {
	decision.allow with input as iam_role_assign_base
}

# ─────────────────────────────────────────────────────────────────────────────
# Payment Actions Tests
# ─────────────────────────────────────────────────────────────────────────────

payment_transfer_base := {
	"agent": {"spiffe_id": "spiffe://atb.example/agent/payment-agent"},
	"poa": {
		"sub": "spiffe://atb.example/agent/payment-agent",
		"act": "finance.wire_transfer.execute",
		"con": {"amount": 50000, "currency": "USD", "destination": "IBAN123"},
		"leg": {
			"jurisdiction": "US",
			"accountable_party": {"type": "employee", "id": "finance-001"},
			"dual_control": {
				"required": true,
				"approvers": [
					{"id": "cfo@example.com", "type": "executive"},
					{"id": "compliance@example.com", "type": "compliance"},
				],
			},
		},
		"iat": 1700000000,
		"exp": 1700000300,
		"jti": "payment-001",
	},
	"request": {"method": "POST", "path": "/payments/transfer", "action": "finance.wire_transfer.execute", "params": {}},
	"policy": {"max_ttl_seconds": 300},
}

test_payment_transfer_without_dual_control_denied if {
	inp := json.patch(payment_transfer_base, [{"op": "remove", "path": "/poa/leg/dual_control"}])
	d := decision with input as inp
	d.allow == false
}

test_payment_transfer_with_dual_control_allowed if {
	decision.allow with input as payment_transfer_base
}

# ─────────────────────────────────────────────────────────────────────────────
# OT (Operational Technology) Actions Tests
# ─────────────────────────────────────────────────────────────────────────────

ot_manual_override_base := {
	"agent": {"spiffe_id": "spiffe://atb.example/agent/ot-agent"},
	"poa": {
		"sub": "spiffe://atb.example/agent/ot-agent",
		"act": "ot.system.manual_override",
		"con": {"system_id": "SCADA-001", "override_type": "safety_bypass", "override_window_seconds": 600},
		"leg": {
			"jurisdiction": "US",
			"accountable_party": {"type": "engineer", "id": "ops-engineer-001"},
			"dual_control": {
				"required": true,
				"approvers": [
					{"id": "safety-officer", "type": "safety"},
					{"id": "plant-manager", "type": "manager"},
				],
			},
		},
		"iat": 1700000000,
		"exp": 1700000300,
		"jti": "ot-override-001",
	},
	"request": {"method": "POST", "path": "/ot/override", "action": "ot.system.manual_override", "params": {"human_in_loop_approved": true}},
	"policy": {"max_ttl_seconds": 300},
}

test_ot_manual_override_without_dual_control_denied if {
	inp := json.patch(ot_manual_override_base, [{"op": "remove", "path": "/poa/leg/dual_control"}])
	d := decision with input as inp
	d.allow == false
}

test_ot_manual_override_with_dual_control_allowed if {
	decision.allow with input as ot_manual_override_base
}

# ─────────────────────────────────────────────────────────────────────────────
# CRM Actions Tests (Medium Risk)
# ─────────────────────────────────────────────────────────────────────────────

crm_contact_read_base := {
	"agent": {"spiffe_id": "spiffe://atb.example/agent/crm-reader"},
	"poa": {
		"sub": "spiffe://atb.example/agent/crm-reader",
		"act": "crm.contact.read",
		"con": {"contact_id": "C-12345"},
		"leg": {
			"basis": "contract",
			"jurisdiction": "US",
			"accountable_party": {"type": "human", "id": "sales@example.com"},
			"approval": {
				"approver_id": "manager@example.com",
				"approved_at": "2024-01-15T10:00:00Z",
			},
		},
		"iat": 1700000000,
		"exp": 1700000300,
		"jti": "crm-read-001",
	},
	"request": {"method": "GET", "path": "/crm/contacts/C-12345", "action": "crm.contact.read", "params": {}},
	"policy": {"max_ttl_seconds": 300},
}

test_crm_contact_read_with_approval_allowed if {
	decision.allow with input as crm_contact_read_base
}

crm_contact_delete_base := {
	"agent": {"spiffe_id": "spiffe://atb.example/agent/crm-admin"},
	"poa": {
		"sub": "spiffe://atb.example/agent/crm-admin",
		"act": "crm.contact.delete",
		"con": {"contact_id": "C-12345"},
		"leg": {
			"basis": "legitimate_interest",
			"jurisdiction": "US",
			"accountable_party": {"type": "employee", "id": "admin@example.com"},
			"approval": {
				"approver_id": "supervisor@example.com",
				"approved_at": "2024-01-15T10:00:00Z",
			},
		},
		"iat": 1700000000,
		"exp": 1700000300,
		"jti": "crm-delete-001",
	},
	"request": {"method": "DELETE", "path": "/crm/contacts/C-12345", "action": "crm.contact.delete", "params": {}},
	"policy": {"max_ttl_seconds": 300},
}

test_crm_contact_delete_with_approval_allowed if {
	decision.allow with input as crm_contact_delete_base
}

# ─────────────────────────────────────────────────────────────────────────────
# SAP Vendor Actions Tests
# ─────────────────────────────────────────────────────────────────────────────

sap_vendor_change_base := {
	"agent": {"spiffe_id": "spiffe://atb.example/agent/sap-agent"},
	"poa": {
		"sub": "spiffe://atb.example/agent/sap-agent",
		"act": "sap.vendor.change",
		"con": {"vendor_id": "V-98765", "field": "bank_account"},
		"leg": {
			"jurisdiction": "EU",
			"accountable_party": {"type": "employee", "id": "procurement@example.com"},
			"dual_control": {
				"required": true,
				"approvers": [
					{"id": "finance@example.com", "type": "finance"},
					{"id": "compliance@example.com", "type": "compliance"},
				],
			},
		},
		"iat": 1700000000,
		"exp": 1700000300,
		"jti": "sap-change-001",
	},
	"request": {"method": "PATCH", "path": "/sap/vendors/V-98765", "action": "sap.vendor.change", "params": {}},
	"policy": {"max_ttl_seconds": 300},
}

test_sap_vendor_change_without_dual_control_denied if {
	inp := json.patch(sap_vendor_change_base, [{"op": "remove", "path": "/poa/leg/dual_control"}])
	d := decision with input as inp
	d.allow == false
}

test_sap_vendor_change_with_dual_control_allowed if {
	decision.allow with input as sap_vendor_change_base
}

# ─────────────────────────────────────────────────────────────────────────────
# SPIFFE ID Mismatch Tests
# ─────────────────────────────────────────────────────────────────────────────

test_spiffe_mismatch_denied if {
	inp := json.patch(crm_contact_read_base, [{"op": "replace", "path": "/agent/spiffe_id", "value": "spiffe://atb.example/agent/different-agent"}])
	d := decision with input as inp
	d.allow == false
}

# ─────────────────────────────────────────────────────────────────────────────
# Missing Required Fields Tests
# ─────────────────────────────────────────────────────────────────────────────

test_missing_act_denied if {
	inp := json.patch(crm_contact_read_base, [{"op": "remove", "path": "/poa/act"}])
	d := decision with input as inp
	d.allow == false
}

test_missing_jti_denied if {
	inp := json.patch(crm_contact_read_base, [{"op": "remove", "path": "/poa/jti"}])
	d := decision with input as inp
	d.allow == false
}

test_missing_leg_denied if {
	inp := json.patch(crm_contact_read_base, [{"op": "remove", "path": "/poa/leg"}])
	d := decision with input as inp
	d.allow == false
}

test_missing_sub_denied if {
	inp := json.patch(crm_contact_read_base, [{"op": "remove", "path": "/poa/sub"}])
	d := decision with input as inp
	d.allow == false
}
