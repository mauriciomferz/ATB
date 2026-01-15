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
	# ── System/Infrastructure ──
	{"action": "system.health.check", "methods": ["GET"]},
	{"action": "system.status.get", "methods": ["GET"]},
	{"action": "system.version.get", "methods": ["GET"]},
	{"action": "system.config.read", "methods": ["GET"]},
	# ── Knowledge Base / Documentation ──
	{"action": "kb.faq.query", "methods": ["GET", "POST"]},
	{"action": "kb.docs.search", "methods": ["GET", "POST"]},
	{"action": "kb.article.read", "methods": ["GET"]},
	# ── Reporting (non-PII, aggregated) ──
	{"action": "reporting.dashboard.view", "methods": ["GET"]},
	{"action": "reporting.metrics.get", "methods": ["GET"]},
	{"action": "report.sales.summary", "methods": ["GET"]},
	{"action": "report.inventory.status", "methods": ["GET"]},
	{"action": "report.support.metrics", "methods": ["GET"]},
	{"action": "analytics.dashboard.view", "methods": ["GET"]},
	# ── Agent Introspection ──
	{"action": "agent.self.capabilities", "methods": ["GET"]},
	{"action": "agent.self.identity", "methods": ["GET"]},
	# ── CRM Read Operations ──
	{"action": "crm.contact.read", "methods": ["GET"]},
	{"action": "crm.contact.list", "methods": ["GET"]},
	{"action": "crm.lead.read", "methods": ["GET"]},
	{"action": "crm.lead.list", "methods": ["GET"]},
	{"action": "crm.opportunity.read", "methods": ["GET"]},
	{"action": "crm.opportunity.list", "methods": ["GET"]},
	{"action": "crm.account.read", "methods": ["GET"]},
	{"action": "crm.account.list", "methods": ["GET"]},
	# ── ERP Read Operations ──
	{"action": "erp.order.read", "methods": ["GET"]},
	{"action": "erp.order.list", "methods": ["GET"]},
	{"action": "erp.invoice.read", "methods": ["GET"]},
	{"action": "erp.purchase_order.read", "methods": ["GET"]},
	{"action": "erp.product.read", "methods": ["GET"]},
	{"action": "erp.vendor.read", "methods": ["GET"]},
	{"action": "erp.customer.read", "methods": ["GET"]},
	# ── HR Read Operations (non-PII) ──
	{"action": "hr.org_chart.read", "methods": ["GET"]},
	{"action": "hr.department.list", "methods": ["GET"]},
	{"action": "hr.job_posting.read", "methods": ["GET"]},
	{"action": "hr.holiday.list", "methods": ["GET"]},
	# ── Support/Ticketing Read Operations ──
	{"action": "support.ticket.read", "methods": ["GET"]},
	{"action": "support.ticket.list", "methods": ["GET"]},
	{"action": "support.kb.search", "methods": ["GET", "POST"]},
	{"action": "support.kb.read", "methods": ["GET"]},
	# ── Inventory Read Operations ──
	{"action": "inventory.stock.read", "methods": ["GET"]},
	{"action": "inventory.location.list", "methods": ["GET"]},
	{"action": "warehouse.status.read", "methods": ["GET"]},
	# ── Catalog Read Operations ──
	{"action": "catalog.product.read", "methods": ["GET"]},
	{"action": "catalog.product.list", "methods": ["GET"]},
	{"action": "catalog.category.list", "methods": ["GET"]},
	{"action": "catalog.price.read", "methods": ["GET"]},
	# ── Collaboration Read Operations ──
	{"action": "sharepoint.document.read", "methods": ["GET"]},
	{"action": "sharepoint.list.read", "methods": ["GET"]},
	{"action": "teams.channel.list", "methods": ["GET"]},
	{"action": "teams.message.read", "methods": ["GET"]},
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
	# ── CRM Operations ──
	"crm.contact.update",
	"crm.contact.delete",
	"crm.lead.create",
	"crm.lead.convert",
	"crm.opportunity.update",
	"crm.account.update",
	# ── ERP/Order Management ──
	"erp.order.create",
	"erp.order.update",
	"erp.order.cancel",
	"erp.invoice.create",
	"erp.invoice.void",
	"erp.purchase_order.create",
	"erp.purchase_order.approve",
	# ── HR (limited PII access) ──
	"hr.employee.view_limited",
	"hr.employee.update_contact",
	"hr.timesheet.approve",
	"hr.leave.approve",
	"hr.org_chart.update",
	# ── Support/Ticketing ──
	"support.ticket.create",
	"support.ticket.update",
	"support.ticket.escalate",
	"support.ticket.reassign",
	"support.case.merge",
	# ── Inventory/Warehouse ──
	"inventory.stock.adjust",
	"inventory.transfer.create",
	"inventory.count.submit",
	"warehouse.location.update",
	# ── Product/Catalog ──
	"catalog.product.update",
	"catalog.product.publish",
	"catalog.price.update",
	"catalog.category.update",
	# ── Marketing ──
	"marketing.campaign.launch",
	"marketing.email.send_batch",
	"marketing.segment.update",
	# ── Collaboration ──
	"sharepoint.document.share_external",
	"teams.channel.create",
	"confluence.space.permission_update",
]

# ─────────────────────────────────────────────────────────────────────────────
# High-risk tier: requires PoA with dual control (two distinct approvers)
# ─────────────────────────────────────────────────────────────────────────────

high_risk_actions := [
	# ── SAP ERP ──
	"sap.vendor.create",
	"sap.vendor.change",
	"sap.vendor.bank_change",
	"sap.payment.execute",
	"sap.payment.batch_release",
	"sap.goods_receipt.post",
	"sap.invoice.post",
	"sap.journal_entry.post",
	"sap.cost_center.create",
	"sap.gl_account.create",
	# ── Financial Transactions ──
	"erp.payment.process",
	"erp.payment.batch",
	"erp.refund.process",
	"erp.credit_note.issue",
	"finance.wire_transfer.execute",
	"finance.ach.batch_submit",
	"finance.fx.trade_execute",
	# ── Salesforce ──
	"salesforce.bulk.export",
	"salesforce.bulk.delete",
	"salesforce.bulk.update",
	"salesforce.apex.execute",
	"salesforce.permission_set.assign",
	"salesforce.profile.modify",
	"salesforce.report.export_all",
	# ── CRM Bulk Operations ──
	"crm.contacts.bulk_delete",
	"crm.contacts.bulk_export",
	"crm.accounts.bulk_merge",
	"crm.data.mass_update",
	# ── HR/PII Sensitive ──
	"hr.employee.export_pii",
	"hr.employee.terminate",
	"hr.payroll.run",
	"hr.payroll.adjust",
	"hr.compensation.change",
	"hr.ssn.view",
	"hr.bank_details.update",
	# ── Customer Data ──
	"customer.data.export",
	"customer.data.bulk_delete",
	"customer.pii.access",
	"customer.gdpr.erasure",
	"customer.ccpa.export",
	# ── IAM/Identity ──
	"iam.role.assign",
	"iam.role.create",
	"iam.permission.grant",
	"iam.user.create_admin",
	"iam.mfa.disable",
	"iam.api_key.create",
	"iam.service_account.create",
	"azure.ad.group_add",
	"azure.ad.role_assign",
	"okta.user.unlock",
	"okta.factor.reset",
	# ── Infrastructure ──
	"aws.iam.policy_attach",
	"aws.s3.bucket_policy",
	"aws.ec2.security_group_modify",
	"azure.rbac.assign",
	"azure.keyvault.secret_set",
	"gcp.iam.binding_add",
	"k8s.rbac.clusterrole_bind",
	"k8s.secret.create",
	# ── OT/Safety Critical ──
	"ot.system.manual_override",
	"ot.safety.interlock_bypass",
	"scada.setpoint.change",
	"scada.alarm.acknowledge_critical",
	"plc.program.upload",
	"hmi.mode.change_to_manual",
	# ── ServiceNow ──
	"servicenow.change.emergency_approve",
	"servicenow.incident.priority1_create",
	"servicenow.cmdb.bulk_update",
	# ── Workday ──
	"workday.worker.terminate",
	"workday.compensation.change",
	"workday.org.restructure",
	# ── Dynamics 365 ──
	"dynamics.entity.bulk_delete",
	"dynamics.workflow.deactivate",
	"dynamics.security_role.assign",
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

# Action risk tier determination - using else chain to avoid multiple outputs
default action_risk_tier := "low"

action_risk_tier := "high" {
	is_high_risk
}

action_risk_tier := "medium" {
	not is_high_risk
	is_medium_risk
}

# ─────────────────────────────────────────────────────────────────────────────
# Action-specific policies with enterprise constraints
# ─────────────────────────────────────────────────────────────────────────────

# Low-risk allowlisted actions: always allowed with valid PoA
action_allowed {
	low_risk_without_poa
}

# === SAP Actions ===

# SAP Vendor Change:
# Constraint: high-impact financial changes require dual control when amount > $5000
# Constraint: liability_cap must exist and cover the amount

action_allowed {
	act == "sap.vendor.change"
	sap_vendor_change_allowed
}

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

# SAP Vendor Bank Change:
# Constraint: requires second-channel verification flag

action_allowed {
	act == "sap.vendor.bank_change"
	sap_vendor_bank_change_allowed
}

sap_vendor_bank_change_allowed {
	# Must have second-channel verification (e.g., callback to vendor)
	verified := bool_or_default(params.second_channel_verified, false)
	verified == true

	# Change reason must be provided
	reason := string_or_default(params.change_reason, "")
	count(reason) > 10
}

# SAP Payment Execute:
# Constraint: amount limits based on payment type

action_allowed {
	act == "sap.payment.execute"
	sap_payment_execute_allowed
}

sap_payment_execute_allowed {
	amount := number_or_default(params.amount, 0)
	payment_type := string_or_default(params.payment_type, "standard")
	limit := object.get(constraints, "payment_limit", 100000)
	amount <= limit
	amount > 0
}

# SAP Batch Payment Release:
# Constraint: batch size and total amount limits

action_allowed {
	act == "sap.payment.batch_release"
	sap_batch_payment_allowed
}

sap_batch_payment_allowed {
	batch_count := number_or_default(params.batch_count, 0)
	total_amount := number_or_default(params.total_amount, 0)
	max_batch := number_or_default(constraints.max_batch_count, 100)
	max_amount := number_or_default(constraints.max_batch_amount, 1000000)
	batch_count <= max_batch
	batch_count > 0
	total_amount <= max_amount
}

# SAP Journal Entry Post:
# Constraint: must have valid GL account and cost center

action_allowed {
	act == "sap.journal_entry.post"
	sap_journal_entry_allowed
}

sap_journal_entry_allowed {
	gl_account := string_or_default(params.gl_account, "")
	cost_center := string_or_default(params.cost_center, "")
	count(gl_account) > 0
	count(cost_center) > 0

	# Amount must be non-zero
	amount := number_or_default(params.amount, 0)
	amount != 0
}

# === Salesforce Actions ===

# Salesforce Bulk Export:
# Constraint: dataset must be in allowlist, row limit enforced

action_allowed {
	act == "salesforce.bulk.export"
	salesforce_bulk_export_allowed
}

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

# Salesforce Bulk Delete:
# Constraint: object type must be in deletable list, count limit

action_allowed {
	act == "salesforce.bulk.delete"
	salesforce_bulk_delete_allowed
}

salesforce_bulk_delete_allowed {
	object_type := string_or_default(params.object_type, "")
	record_count := number_or_default(params.record_count, 0)
	deletable := object.get(constraints, "deletable_objects", [])
	is_array(deletable)
	some i
	deletable[i] == object_type
	record_count > 0
	record_count <= number_or_default(constraints.max_delete_count, 1000)
}

# Salesforce Apex Execute:
# Constraint: script must be in approved list

action_allowed {
	act == "salesforce.apex.execute"
	salesforce_apex_allowed
}

salesforce_apex_allowed {
	script_name := string_or_default(params.script_name, "")
	approved_scripts := object.get(constraints, "approved_apex_scripts", [])
	is_array(approved_scripts)
	some i
	approved_scripts[i] == script_name
}

# Salesforce Report Export:
# Constraint: report must be in exportable list

action_allowed {
	act == "salesforce.report.export_all"
	salesforce_report_export_allowed
}

salesforce_report_export_allowed {
	report_id := string_or_default(params.report_id, "")
	exportable := object.get(constraints, "exportable_reports", [])
	is_array(exportable)
	some i
	exportable[i] == report_id
}

# === HR/PII Actions ===

# HR Employee PII Export:
# Constraint: purpose must be specified, record limit enforced

action_allowed {
	act == "hr.employee.export_pii"
	hr_export_pii_allowed
}

hr_export_pii_allowed {
	purpose := string_or_default(params.purpose, "")
	count(purpose) > 5

	# Valid purposes
	valid_purposes := ["audit", "legal_hold", "regulatory_compliance", "internal_investigation"]
	some i
	valid_purposes[i] == purpose

	# Record limit
	record_count := number_or_default(params.record_count, 0)
	record_count > 0
	record_count <= number_or_default(constraints.max_pii_export, 500)
}

# HR Employee Terminate:
# Constraint: must have offboarding checklist completed

action_allowed {
	act == "hr.employee.terminate"
	hr_terminate_allowed
}

hr_terminate_allowed {
	checklist_complete := bool_or_default(params.offboarding_checklist_complete, false)
	checklist_complete == true

	# Reason required
	reason := string_or_default(params.termination_reason, "")
	count(reason) > 10
}

# HR Payroll Run:
# Constraint: must be within scheduled window

action_allowed {
	act == "hr.payroll.run"
	hr_payroll_run_allowed
}

hr_payroll_run_allowed {
	# Payroll period must be specified
	period := string_or_default(params.payroll_period, "")
	count(period) > 0

	# Employee count must be within limit
	employee_count := number_or_default(params.employee_count, 0)
	max_employees := number_or_default(constraints.max_payroll_employees, 10000)
	employee_count <= max_employees
}

# HR Compensation Change:
# Constraint: percentage change limit, requires justification

action_allowed {
	act == "hr.compensation.change"
	hr_compensation_allowed
}

hr_compensation_allowed {
	pct_change := number_or_default(params.percentage_change, 0)
	max_pct := number_or_default(constraints.max_compensation_pct_change, 25)
	pct_change <= max_pct
	pct_change >= -50 # Cannot reduce more than 50%

	# Justification required
	justification := string_or_default(params.justification, "")
	count(justification) > 20
}

# Customer Data Export (GDPR/CCPA):
# Constraint: must have valid request reference

action_allowed {
	act == "customer.gdpr.erasure"
	customer_gdpr_erasure_allowed
}

customer_gdpr_erasure_allowed {
	request_id := string_or_default(params.request_id, "")
	count(request_id) > 0

	# Must be within retention window (days since request)
	days_since_request := number_or_default(params.days_since_request, 999)
	days_since_request <= 30 # GDPR requires response within 30 days
}

action_allowed {
	act == "customer.ccpa.export"
	customer_ccpa_export_allowed
}

customer_ccpa_export_allowed {
	request_id := string_or_default(params.request_id, "")
	count(request_id) > 0

	# Format must be specified
	format := string_or_default(params.export_format, "")
	valid_formats := ["json", "csv", "pdf"]
	some i
	valid_formats[i] == format
}

# Customer PII Access:
# Constraint: purpose limitation

action_allowed {
	act == "customer.pii.access"
	customer_pii_access_allowed
}

customer_pii_access_allowed {
	purpose := string_or_default(params.purpose, "")
	valid_purposes := ["support_case", "billing_inquiry", "identity_verification", "fraud_investigation"]
	some i
	valid_purposes[i] == purpose

	# Must reference a specific support case or request
	reference_id := string_or_default(params.reference_id, "")
	count(reference_id) > 0
}

# === IAM/Identity Actions ===

# IAM Role Assign:
# Constraint: role must be in assignable list, target user must be specified

action_allowed {
	act == "iam.role.assign"
	iam_role_assign_allowed
}

iam_role_assign_allowed {
	role := string_or_default(params.role_name, "")
	target_user := string_or_default(params.target_user_id, "")
	count(role) > 0
	count(target_user) > 0

	# Cannot self-assign
	target_user != poa.sub

	# Role must be in assignable list (if constrained)
	assignable := object.get(constraints, "assignable_roles", [])
	role_allowed_or_unconstrained(role, assignable)
}

role_allowed_or_unconstrained(role, assignable) {
	count(assignable) == 0 # No constraint = allow all
}

role_allowed_or_unconstrained(role, assignable) {
	count(assignable) > 0
	some i
	assignable[i] == role
}

# IAM MFA Disable:
# Constraint: requires security incident reference

action_allowed {
	act == "iam.mfa.disable"
	iam_mfa_disable_allowed
}

iam_mfa_disable_allowed {
	# Must have incident reference
	incident_ref := string_or_default(params.incident_reference, "")
	count(incident_ref) > 0

	# Must be for a specific user (not bulk)
	target_user := string_or_default(params.target_user_id, "")
	count(target_user) > 0

	# Must have identity verification
	verified := bool_or_default(params.identity_verified, false)
	verified == true
}

# === OT/SCADA Actions ===

# OT System Manual Override:
# Constraint: requires human-in-loop approval, time-bounded

action_allowed {
	act == "ot.system.manual_override"
	ot_manual_override_allowed
}

ot_manual_override_allowed {
	hil := bool_or_default(params.human_in_loop_approved, false)
	hil == true
	window := number_or_default(constraints.override_window_seconds, 0)
	window > 0
	window <= 900 # Max 15 minutes
}

# SCADA Setpoint Change:
# Constraint: change must be within safety bounds

action_allowed {
	act == "scada.setpoint.change"
	scada_setpoint_allowed
}

scada_setpoint_allowed {
	new_value := number_or_default(params.new_value, 0)
	min_safe := number_or_default(constraints.setpoint_min, 0)
	max_safe := number_or_default(constraints.setpoint_max, 100)
	new_value >= min_safe
	new_value <= max_safe

	# Safety review must be acknowledged
	safety_ack := bool_or_default(params.safety_review_acknowledged, false)
	safety_ack == true
}

# Safety Interlock Bypass:
# Constraint: must have emergency justification and max duration

action_allowed {
	act == "ot.safety.interlock_bypass"
	safety_interlock_bypass_allowed
}

safety_interlock_bypass_allowed {
	# Emergency justification required
	justification := string_or_default(params.emergency_justification, "")
	count(justification) > 20

	# Max bypass duration (seconds)
	duration := number_or_default(params.bypass_duration_seconds, 0)
	max_duration := number_or_default(constraints.max_bypass_duration, 3600)
	duration > 0
	duration <= max_duration

	# Safety officer approval
	safety_approved := bool_or_default(params.safety_officer_approved, false)
	safety_approved == true
}

# === ServiceNow Actions ===

# ServiceNow Emergency Change Approve:
# Constraint: must have CAB member approval or emergency flag

action_allowed {
	act == "servicenow.change.emergency_approve"
	servicenow_emergency_change_allowed
}

servicenow_emergency_change_allowed {
	change_number := string_or_default(params.change_number, "")
	count(change_number) > 0

	# Must have either CAB approval or emergency flag with justification
	cab_approved := bool_or_default(params.cab_approved, false)
	emergency_flag := bool_or_default(params.emergency_flag, false)
	cab_or_emergency_justified(cab_approved, emergency_flag, params)
}

cab_or_emergency_justified(cab_approved, _, _) {
	cab_approved == true
}

cab_or_emergency_justified(_, emergency_flag, params) {
	emergency_flag == true
	justification := string_or_default(params.emergency_justification, "")
	count(justification) > 20
}

# ServiceNow Priority 1 Incident:
# Constraint: must have business impact assessment

action_allowed {
	act == "servicenow.incident.priority1_create"
	servicenow_p1_incident_allowed
}

servicenow_p1_incident_allowed {
	# Impact assessment required
	impact := string_or_default(params.business_impact, "")
	count(impact) > 10

	# Affected users/systems count
	affected := number_or_default(params.affected_users, 0)
	affected > 0
}

# === Workday Actions ===

# Workday Compensation Change:
action_allowed {
	act == "workday.compensation.change"
	workday_compensation_allowed
}

workday_compensation_allowed {
	# Same constraints as HR compensation
	pct_change := number_or_default(params.percentage_change, 0)
	max_pct := number_or_default(constraints.max_compensation_pct_change, 25)
	pct_change <= max_pct
	effective_date := string_or_default(params.effective_date, "")
	count(effective_date) > 0
}

# === Dynamics 365 Actions ===

# Dynamics Bulk Delete:
action_allowed {
	act == "dynamics.entity.bulk_delete"
	dynamics_bulk_delete_allowed
}

dynamics_bulk_delete_allowed {
	entity_type := string_or_default(params.entity_type, "")
	record_count := number_or_default(params.record_count, 0)

	# Entity must be in deletable list
	deletable := object.get(constraints, "deletable_entities", [])
	entity_allowed_or_unconstrained(entity_type, deletable)

	# Count limit
	record_count > 0
	record_count <= number_or_default(constraints.max_delete_count, 1000)
}

entity_allowed_or_unconstrained(entity, deletable) {
	count(deletable) == 0
}

entity_allowed_or_unconstrained(entity, deletable) {
	count(deletable) > 0
	some i
	deletable[i] == entity
}

# === Cloud Infrastructure Actions ===

# AWS IAM Policy Attach:
action_allowed {
	act == "aws.iam.policy_attach"
	aws_iam_policy_attach_allowed
}

aws_iam_policy_attach_allowed {
	policy_arn := string_or_default(params.policy_arn, "")
	count(policy_arn) > 0

	# Cannot attach admin policies without constraint approval
	not startswith(policy_arn, "arn:aws:iam::aws:policy/Administrator")
}

aws_iam_policy_attach_allowed {
	policy_arn := string_or_default(params.policy_arn, "")
	startswith(policy_arn, "arn:aws:iam::aws:policy/Administrator")

	# Admin policy requires explicit constraint
	admin_allowed := bool_or_default(constraints.allow_admin_policy, false)
	admin_allowed == true
}

# Azure RBAC Assign:
action_allowed {
	act == "azure.rbac.assign"
	azure_rbac_assign_allowed
}

azure_rbac_assign_allowed {
	role_name := string_or_default(params.role_name, "")
	principal_id := string_or_default(params.principal_id, "")
	scope := string_or_default(params.scope, "")
	count(role_name) > 0
	count(principal_id) > 0
	count(scope) > 0

	# Block subscription-level Owner assignments without explicit constraint
	not dangerous_azure_assignment(role_name, scope, constraints)
}

dangerous_azure_assignment(role, scope, constraints) {
	role == "Owner"
	contains(scope, "/subscriptions/")
	not contains(scope, "/resourceGroups/")
	allow_sub_owner := bool_or_default(constraints.allow_subscription_owner, false)
	allow_sub_owner == false
}

# Azure Key Vault Secret Set:
action_allowed {
	act == "azure.keyvault.secret_set"
	azure_keyvault_secret_allowed
}

azure_keyvault_secret_allowed {
	vault_name := string_or_default(params.vault_name, "")
	secret_name := string_or_default(params.secret_name, "")
	count(vault_name) > 0
	count(secret_name) > 0

	# Cannot set secrets in production vaults without constraint
	not production_vault_blocked(vault_name, constraints)
}

production_vault_blocked(vault_name, constraints) {
	prod_vaults := object.get(constraints, "protected_vaults", [])
	some i
	prod_vaults[i] == vault_name
	allow_prod := bool_or_default(constraints.allow_protected_vault_write, false)
	allow_prod == false
}

# === Catch-all for risk-tiered actions ===

# Medium-risk actions not explicitly defined above: allowed if tier check passes
action_allowed {
	is_medium_risk
	not explicit_medium_risk_rule
}

explicit_medium_risk_rule {
	# List of medium-risk actions that have explicit rules above
	explicit_actions := []
	some i
	explicit_actions[i] == act
}

# High-risk actions not explicitly defined above: allowed if tier check passes
action_allowed {
	is_high_risk
	not explicit_high_risk_rule
}

explicit_high_risk_rule {
	# High-risk actions with explicit constraint rules
	explicit_actions := [
		"sap.vendor.change",
		"sap.vendor.bank_change",
		"sap.payment.execute",
		"sap.payment.batch_release",
		"sap.journal_entry.post",
		"salesforce.bulk.export",
		"salesforce.bulk.delete",
		"salesforce.apex.execute",
		"salesforce.report.export_all",
		"hr.employee.export_pii",
		"hr.employee.terminate",
		"hr.payroll.run",
		"hr.compensation.change",
		"customer.gdpr.erasure",
		"customer.ccpa.export",
		"customer.pii.access",
		"iam.role.assign",
		"iam.mfa.disable",
		"ot.system.manual_override",
		"scada.setpoint.change",
		"ot.safety.interlock_bypass",
		"servicenow.change.emergency_approve",
		"servicenow.incident.priority1_create",
		"workday.compensation.change",
		"dynamics.entity.bulk_delete",
		"aws.iam.policy_attach",
		"azure.rbac.assign",
		"azure.keyvault.secret_set",
	]
	some i
	explicit_actions[i] == act
}

# Low-risk actions not in allowlist: allowed if not blocked
action_allowed {
	not is_medium_risk
	not is_high_risk
	not low_risk_without_poa
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
