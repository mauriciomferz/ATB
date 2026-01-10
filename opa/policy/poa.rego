package atb.poa

# Decision endpoint used by the Go/Python skeletons:
#   POST /v1/data/atb/poa/decision
#
# Input shape (expected):
# {
#   "agent": {"spiffe_id": "spiffe://..."},
#   "poa": {
#     "sub": "spiffe://...",
#     "act": "sap.vendor.change",
#     "con": {...},
#     "leg": {...},
#     "iat": 1700000000,
#     "exp": 1700000300,
#     "jti": "..."
#   },
#   "request": {"method": "POST", "path": "/...", "params": {...}},
#   "policy": {"max_ttl_seconds": 300}
# }

default decision := {"allow": false, "reason": "deny_by_default"}

max_ttl_seconds := v {
	v := input.policy.max_ttl_seconds
	is_number(v)
} else := 300

hard_cap_ttl_seconds := 900

required_poa_fields := {"sub", "act", "con", "leg", "iat", "exp", "jti"}

missing_required_fields[f] {
	f := required_poa_fields[_]
	not has_field(input.poa, f)
}

has_field(obj, f) {
	obj[f]
}

# Normalized helpers
agent_spiffe := input.agent.spiffe_id
poa := input.poa
act := poa.act
constraints := poa.con
params := input.request.params

poa_ttl := poa.exp - poa.iat

# Main decision

decision := {"allow": true, "reason": "allow"} {
	count(missing_required_fields) == 0
	poa_ttl > 0
	poa_ttl <= hard_cap_ttl_seconds
	poa_ttl <= max_ttl_seconds
	poa.sub == agent_spiffe
	action_allowed
}

# More specific deny reasons (first-match style via else)

decision := {"allow": false, "reason": "missing_required_fields"} {
	count(missing_required_fields) > 0
} else := {"allow": false, "reason": "ttl_invalid"} {
	count(missing_required_fields) == 0
	(poa_ttl <= 0 or poa_ttl > hard_cap_ttl_seconds or poa_ttl > max_ttl_seconds)
} else := {"allow": false, "reason": "sub_mismatch"} {
	count(missing_required_fields) == 0
	poa_ttl > 0
	poa_ttl <= hard_cap_ttl_seconds
	poa_ttl <= max_ttl_seconds
	poa.sub != agent_spiffe
} else := {"allow": false, "reason": "action_denied"} {
	count(missing_required_fields) == 0
	poa_ttl > 0
	poa_ttl <= hard_cap_ttl_seconds
	poa_ttl <= max_ttl_seconds
	poa.sub == agent_spiffe
	not action_allowed
}

# Pilot actions

action_allowed {
	act == "sap.vendor.change"
	sap_vendor_change_allowed
}

action_allowed {
	act == "salesforce.bulk.export"
	salesforce_bulk_export_allowed
}

action_allowed {
	act == "ot.system.manual_override"
	ot_manual_override_allowed
}

# === Action policies ===

# SAP Vendor Change:
# Example control: high-impact financial changes require dual control when amount exceeds 5000.
# Example constraint: liability_cap must exist and be >= amount.

sap_vendor_change_allowed {
	amount := number_or_default(params.amount, 0)
	dual := bool_or_default(constraints.dual_control, false)
	liability := number_or_default(constraints.liability_cap, 0)

	amount <= 5000
	liability >= amount
} else {
	amount := number_or_default(params.amount, 0)
	dual := bool_or_default(constraints.dual_control, false)
	liability := number_or_default(constraints.liability_cap, 0)

	amount > 5000
	dual == true
	liability >= amount
}

# Salesforce Bulk Export:
# Example control: require dataset allowlist and enforce row-limit.

salesforce_bulk_export_allowed {
	dataset := string_or_default(params.dataset, "")
	rows := number_or_default(params.row_count, 0)
	allowed := constraints.dataset_allowlist
	is_array(allowed)
	some i
	allowed[i] == dataset
	rows > 0
	rows <= number_or_default(constraints.max_rows, 10000)
}

# OT System Manual Override:
# Example control: require explicit human approval + time-bound window.

ot_manual_override_allowed {
	hil := bool_or_default(params.human_in_loop_approved, false)
	hil == true

	window := number_or_default(constraints.override_window_seconds, 0)
	window > 0
	window <= 900
}

# === Helpers ===

number_or_default(x, d) := n {
	is_number(x)
	n := x
} else := d

bool_or_default(x, d) := b {
	is_boolean(x)
	b := x
} else := d

string_or_default(x, d) := s {
	is_string(x)
	s := x
} else := d
