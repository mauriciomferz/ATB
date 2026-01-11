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

# Platform identity (from OIDC token like Entra ID)
platform := input.platform
platform_sub := platform.sub

poa_ttl := poa.exp - poa.iat

# ─────────────────────────────────────────────────────────────────────────────
# Platform ↔ SPIFFE identity binding validation
# When enabled, the platform identity (OIDC sub) must map to the SPIFFE ID
# of the calling agent. This prevents token-forwarding attacks.
# ─────────────────────────────────────────────────────────────────────────────

# Policy data: set via /v1/policies or data document
# data.platform_binding.mode: "none" | "exact" | "prefix" | "mapping"
# data.platform_binding.mappings: {"platform_sub": "spiffe_pattern"}

platform_binding_mode := data.platform_binding.mode

# No binding enforcement if mode is not set or is "none"
platform_spiffe_binding_valid {
	not platform_binding_mode
}

platform_spiffe_binding_valid {
	platform_binding_mode == "none"
}

# Exact mode: platform sub must exactly match SPIFFE ID
platform_spiffe_binding_valid {
	platform_binding_mode == "exact"
	platform_sub == agent_spiffe
}

# Prefix mode: platform sub should appear in SPIFFE ID path
platform_spiffe_binding_valid {
	platform_binding_mode == "prefix"
	contains(agent_spiffe, concat("/", ["", platform_sub, ""]))
}

platform_spiffe_binding_valid {
	platform_binding_mode == "prefix"
	endswith(agent_spiffe, concat("/", ["", platform_sub]))
}

# Mapping mode: lookup platform_sub -> SPIFFE pattern in data
platform_spiffe_binding_valid {
	platform_binding_mode == "mapping"
	pattern := data.platform_binding.mappings[platform_sub]
	regex.match(pattern, agent_spiffe)
}

platform_binding_reason := reason {
	not platform_spiffe_binding_valid
	reason := sprintf("platform_sub '%s' does not match SPIFFE ID '%s'", [platform_sub, agent_spiffe])
}

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
	platform_spiffe_binding_valid
	action_matches_request
	action_allowed
	risk_tier_approved
}

# Risk tier approval check
risk_tier_approved {
	action_risk_tier == "low"
}

risk_tier_approved {
	action_risk_tier == "medium"
	medium_risk_approved
}

risk_tier_approved {
	action_risk_tier == "high"
	high_risk_approved
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
} else := {"allow": false, "reason": "platform_spiffe_binding_mismatch", "details": platform_binding_reason} {
	poa_provided
	count(missing_required_fields) == 0
	leg_valid
	ttl_valid
	poa.sub == agent_spiffe
	not platform_spiffe_binding_valid
} else := {"allow": false, "reason": "action_mismatch"} {
	poa_provided
	count(missing_required_fields) == 0
	leg_valid
	ttl_valid
	poa.sub == agent_spiffe
	platform_spiffe_binding_valid
	req_action != ""
	act != req_action
} else := {"allow": false, "reason": "action_denied"} {
	poa_provided
	count(missing_required_fields) == 0
	leg_valid
	ttl_valid
	poa.sub == agent_spiffe
	platform_spiffe_binding_valid
	not action_allowed
} else := {"allow": false, "reason": "medium_risk_approval_required", "details": {"tier": "medium", "action": act}} {
	poa_provided
	count(missing_required_fields) == 0
	leg_valid
	ttl_valid
	poa.sub == agent_spiffe
	platform_spiffe_binding_valid
	action_allowed
	is_medium_risk
	not medium_risk_approved
} else := {"allow": false, "reason": "high_risk_dual_control_required", "details": {"tier": "high", "action": act}} {
	poa_provided
	count(missing_required_fields) == 0
	leg_valid
	ttl_valid
	poa.sub == agent_spiffe
	platform_spiffe_binding_valid
	action_allowed
	is_high_risk
	not high_risk_approved
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

# ─────────────────────────────────────────────────────────────────────────────
# Medium-risk tier: requires PoA with single approver (lighter than dual control)
# Actions in this tier need explicit approval but not full dual-control ceremony.
# ─────────────────────────────────────────────────────────────────────────────

medium_risk_actions := [
	# Write operations on non-critical data
	"crm.contact.update",
	"crm.lead.create",
	"erp.order.create",
	"erp.order.update",
	# Limited PII access
	"hr.employee.view_limited",
	"support.ticket.create",
	"support.ticket.update",
	# Non-financial updates
	"inventory.stock.adjust",
	"catalog.product.update",
]

# High-risk tier: requires PoA with dual control (two distinct approvers)
high_risk_actions := [
	# Financial transactions
	"sap.vendor.change",
	"sap.payment.execute",
	"erp.payment.process",
	# Bulk operations
	"salesforce.bulk.export",
	"salesforce.bulk.delete",
	"crm.contacts.bulk_delete",
	# PII exports
	"hr.employee.export_pii",
	"customer.data.export",
	# Privileged access
	"iam.role.assign",
	"iam.permission.grant",
	# OT/safety critical
	"ot.system.manual_override",
	"scada.setpoint.change",
]

# Check if action is medium-risk
is_medium_risk {
	medium_risk_actions[_] == act
}

# Check if action is high-risk
is_high_risk {
	high_risk_actions[_] == act
}

# Medium-risk validation: requires approval in leg claim
medium_risk_approved {
	is_medium_risk
	is_object(leg.approval)
	is_string(leg.approval.approver_id)
	count(leg.approval.approver_id) > 0
	# Approver must be different from requester
	leg.approval.approver_id != poa.sub
}

# High-risk validation: requires dual control (two distinct approvers)
high_risk_approved {
	is_high_risk
	is_object(leg.dual_control)
	leg.dual_control.required == true
	is_array(leg.dual_control.approvers)
	count(leg.dual_control.approvers) >= 2
	# All approvers must be distinct from requester
	all_approvers_distinct
}

all_approvers_distinct {
	approvers := leg.dual_control.approvers
	# No approver is the same as the PoA subject
	no_self_approval
	# All approvers are unique (check via count of unique IDs)
	unique_ids := {id | some i; id := approvers[i].id}
	count(unique_ids) >= 2
}

no_self_approval {
	approvers := leg.dual_control.approvers
	# Ensure no approver has the same ID as PoA subject
	count([a | some i; a := approvers[i]; a.id == poa.sub]) == 0
}

# Action risk tier determination
action_risk_tier := "high" {
	is_high_risk
}

action_risk_tier := "medium" {
	not is_high_risk
	is_medium_risk
}

action_risk_tier := "low" {
	not is_high_risk
	not is_medium_risk
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

# Default: allow actions not explicitly denied (relies on risk tier checks for approval)
# This covers medium-risk, high-risk, and custom actions not in the pilot list.
action_allowed {
	# Action is in medium-risk or high-risk list (risk tier will validate approval)
	is_medium_risk
}

action_allowed {
	is_high_risk
}

# Default allow for actions not in any explicit list (low-risk custom actions)
action_allowed {
	not is_medium_risk
	not is_high_risk
	# Not a pilot action (those have their own rules above)
	act != "sap.vendor.change"
	act != "salesforce.bulk.export"
	act != "ot.system.manual_override"
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
