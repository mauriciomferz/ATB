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

# If a request is low-risk (e.g., read-only) we may allow it without a PoA.
# This supports the architecture doc's "Low-Risk Tier - Allowed with Logging".
#
# IMPORTANT: Treat this as a *policy choice*. The broker can still be configured
# to require PoA for everything.

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

poa_provided {
	is_object(input.poa)
	count(input.poa) > 0
}

req_action := v {
	v := input.request.action
	is_string(v)
	v != ""
} else := ""

# Normalized helpers
agent_spiffe := input.agent.spiffe_id
poa := input.poa
act := poa.act
constraints := poa.con
leg := poa.leg
params := input.request.params

poa_ttl := poa.exp - poa.iat

# TTL validity helpers
ttl_valid {
	poa_ttl > 0
	poa_ttl <= hard_cap_ttl_seconds
	poa_ttl <= max_ttl_seconds
}

ttl_invalid {
	poa_ttl <= 0
}

ttl_invalid {
	poa_ttl > hard_cap_ttl_seconds
}

ttl_invalid {
	poa_ttl > max_ttl_seconds
}

# Legal grounding (leg) validation
# The leg claim must contain at minimum: jurisdiction (string) and accountable_party (object with type + id).

leg_valid {
	is_object(leg)
	is_string(leg.jurisdiction)
	count(leg.jurisdiction) > 0
	is_object(leg.accountable_party)
	is_string(leg.accountable_party.type)
	is_string(leg.accountable_party.id)
	count(leg.accountable_party.id) > 0
}

leg_missing_fields[f] {
	not is_object(leg)
	f := "leg"
}

leg_missing_fields[f] {
	is_object(leg)
	not is_string(leg.jurisdiction)
	f := "leg.jurisdiction"
}

leg_missing_fields[f] {
	is_object(leg)
	is_string(leg.jurisdiction)
	count(leg.jurisdiction) == 0
	f := "leg.jurisdiction"
}

leg_missing_fields[f] {
	is_object(leg)
	not is_object(leg.accountable_party)
	f := "leg.accountable_party"
}

leg_missing_fields[f] {
	is_object(leg)
	is_object(leg.accountable_party)
	not is_string(leg.accountable_party.type)
	f := "leg.accountable_party.type"
}

leg_missing_fields[f] {
	is_object(leg)
	is_object(leg.accountable_party)
	not is_string(leg.accountable_party.id)
	f := "leg.accountable_party.id"
}

leg_missing_fields[f] {
	is_object(leg)
	is_object(leg.accountable_party)
	is_string(leg.accountable_party.id)
	count(leg.accountable_party.id) == 0
	f := "leg.accountable_party.id"
}

# Main decision

# No-PoA path: allow only low-risk activity.
decision := {"allow": true, "reason": "allow_low_risk_without_poa"} {
	not poa_provided
	low_risk_without_poa
}

decision := {"allow": false, "reason": "poa_required_for_action"} {
	not poa_provided
	not low_risk_without_poa
}

decision := {"allow": true, "reason": "allow"} {
	poa_provided
	count(missing_required_fields) == 0
	leg_valid
	ttl_valid
	poa.sub == agent_spiffe
	action_matches_request
	action_allowed
}

# Action matches request check (either no action requested or matches PoA)
action_matches_request {
	req_action == ""
}

action_matches_request {
	req_action != ""
	act == req_action
}

# More specific deny reasons (first-match style via else)

decision := {"allow": false, "reason": "missing_required_fields"} {
	poa_provided
	count(missing_required_fields) > 0
} else := {"allow": false, "reason": "leg_invalid", "details": leg_missing_fields} {
	poa_provided
	count(missing_required_fields) == 0
	not leg_valid
} else := {"allow": false, "reason": "ttl_invalid"} {
	poa_provided
	count(missing_required_fields) == 0
	leg_valid
	ttl_invalid
} else := {"allow": false, "reason": "sub_mismatch"} {
	poa_provided
	count(missing_required_fields) == 0
	leg_valid
	ttl_valid
	poa.sub != agent_spiffe
} else := {"allow": false, "reason": "action_mismatch"} {
	poa_provided
	count(missing_required_fields) == 0
	leg_valid
	ttl_valid
	poa.sub == agent_spiffe
	req_action != ""
	act != req_action
} else := {"allow": false, "reason": "action_denied"} {
	poa_provided
	count(missing_required_fields) == 0
	leg_valid
	ttl_valid
	poa.sub == agent_spiffe
	not action_allowed
}

# Low-risk action allowlist (no PoA required when ALLOW_UNMANDATED_LOW_RISK=true)
# Each entry specifies action name and optional path pattern.
# Extend this list per enterprise policy; prefer explicit actions over blanket method checks.

low_risk_allowlist := [
	# Read-only status/health checks
	{"action": "system.health.check", "methods": ["GET"]},
	{"action": "system.status.get", "methods": ["GET"]},

	# FAQ and documentation queries
	{"action": "kb.faq.query", "methods": ["GET", "POST"]},
	{"action": "kb.docs.search", "methods": ["GET", "POST"]},

	# Read-only reporting (non-PII, aggregated)
	{"action": "reporting.dashboard.view", "methods": ["GET"]},
	{"action": "reporting.metrics.get", "methods": ["GET"]},

	# Agent introspection (own identity/capabilities)
	{"action": "agent.self.capabilities", "methods": ["GET"]},
	{"action": "agent.self.identity", "methods": ["GET"]},
]

low_risk_without_poa {
	# Match against explicit allowlist
	some i
	entry := low_risk_allowlist[i]
	input.request.action == entry.action
	input.request.method == entry.methods[_]
}

# Fallback: allow GET on paths explicitly marked safe (e.g., /health, /ready, /metrics)
low_risk_without_poa {
	input.request.method == "GET"
	low_risk_path_patterns[_] == input.request.path
}

low_risk_path_patterns := [
	"/health",
	"/ready",
	"/metrics",
	"/ping",
]

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
	amount := object.get(params, "amount", 0)
	dual := object.get(constraints, "dual_control", false)
	liability := object.get(constraints, "liability_cap", 0)

	amount <= 5000
	liability >= amount
}

sap_vendor_change_allowed {
	amount := object.get(params, "amount", 0)
	dual := object.get(constraints, "dual_control", false)
	liability := object.get(constraints, "liability_cap", 0)

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
