# Salesforce Policy Templates for ATB
# Pre-built OPA policies for Salesforce Agentforce and Einstein actions

package atb.templates.salesforce

import rego.v1

# ==============================================================================
# Salesforce Action Risk Classification
# ==============================================================================

# HIGH risk actions - financial impact, legal commitments
sf_high_risk_actions := {
	"crm.opportunity.close",
	"legal.contract.activate",
	"legal.contract.terminate",
	"legal.contract.amend",
	"commerce.quote.approve",
	"billing.credit.issue",
	"billing.refund.process",
	"support.case.escalate",
}

# MEDIUM risk actions - data modification
sf_medium_risk_actions := {
	"crm.opportunity.create",
	"crm.opportunity.update",
	"crm.account.create",
	"crm.account.update",
	"crm.contact.create",
	"crm.contact.update",
	"crm.contact.delete",
	"support.case.create",
	"support.case.update",
	"commerce.order.create",
	"commerce.order.activate",
	"knowledge.article.publish",
}

# LOW risk actions - read operations
sf_low_risk_actions := {
	"crm.opportunity.read",
	"crm.account.read",
	"crm.contact.read",
	"support.case.read",
	"knowledge.article.read",
	"commerce.order.read",
	"legal.contract.read",
}

# Determine risk tier for Salesforce actions
sf_risk_tier := "HIGH" if input.poa.act in sf_high_risk_actions

sf_risk_tier := "MEDIUM" if {
	not input.poa.act in sf_high_risk_actions
	input.poa.act in sf_medium_risk_actions
}

sf_risk_tier := "LOW" if {
	not input.poa.act in sf_high_risk_actions
	not input.poa.act in sf_medium_risk_actions
	input.poa.act in sf_low_risk_actions
}

sf_risk_tier := "MEDIUM" if {
	startswith(input.poa.act, "crm.")
	not input.poa.act in sf_high_risk_actions
	not input.poa.act in sf_medium_risk_actions
	not input.poa.act in sf_low_risk_actions
}

# ==============================================================================
# Opportunity Close Policy
# ==============================================================================

opportunity_close_allowed if {
	input.poa.act == "crm.opportunity.close"

	# Check amount thresholds
	amount := input.poa.con.max_amount
	amount < 100000

	# Standard close - single approval sufficient
	count(input.poa.leg.approvals) >= 1
}

opportunity_close_allowed if {
	input.poa.act == "crm.opportunity.close"

	# Large deal requires manager approval
	amount := input.poa.con.max_amount
	amount >= 100000
	amount < 500000

	# Need manager approval
	has_manager_approval
}

opportunity_close_allowed if {
	input.poa.act == "crm.opportunity.close"

	# Enterprise deal requires VP approval
	amount := input.poa.con.max_amount
	amount >= 500000

	# Need VP or director approval
	has_executive_approval
}

opportunity_close_denial_reason := "Deals >= $100k require manager approval" if {
	input.poa.act == "crm.opportunity.close"
	amount := input.poa.con.max_amount
	amount >= 100000
	not has_manager_approval
}

# ==============================================================================
# Credit and Refund Policy
# ==============================================================================

credit_issue_allowed if {
	input.poa.act == "billing.credit.issue"

	# Small credits auto-approved
	amount := input.poa.con.max_amount
	amount < 1000

	# Must have reason
	input.poa.con.reason != ""
}

credit_issue_allowed if {
	input.poa.act == "billing.credit.issue"

	# Medium credits need approval
	amount := input.poa.con.max_amount
	amount >= 1000
	amount < 10000

	count(input.poa.leg.approvals) >= 1
	input.poa.con.reason != ""
}

credit_issue_allowed if {
	input.poa.act == "billing.credit.issue"

	# Large credits need manager + dual control
	amount := input.poa.con.max_amount
	amount >= 10000

	input.poa.con.dual_control == true
	has_manager_approval
}

refund_process_allowed if {
	input.poa.act == "billing.refund.process"

	# All refunds require approval
	count(input.poa.leg.approvals) >= 1

	# Refund reason must be valid
	valid_refund_reasons := {"product_defect", "service_failure", "billing_error", "customer_satisfaction", "contract_termination"}
	input.poa.con.reason in valid_refund_reasons
}

refund_process_allowed if {
	input.poa.act == "billing.refund.process"

	# Large refunds need dual control
	amount := input.poa.con.max_amount
	amount >= 5000

	input.poa.con.dual_control == true
}

# ==============================================================================
# Contract Policy
# ==============================================================================

contract_activate_allowed if {
	input.poa.act == "legal.contract.activate"

	# Contract value check
	value := input.poa.con.contract_value
	value < 100000

	# Legal review not required for small contracts
	count(input.poa.leg.approvals) >= 1
}

contract_activate_allowed if {
	input.poa.act == "legal.contract.activate"

	# Large contracts need legal review
	value := input.poa.con.contract_value
	value >= 100000

	# Must have legal approval
	has_legal_approval
}

contract_terminate_allowed if {
	input.poa.act == "legal.contract.terminate"

	# All terminations need manager + legal
	has_manager_approval
	has_legal_approval

	# Must have termination reason
	input.poa.con.termination_reason != ""
}

# ==============================================================================
# Data Export/Bulk Operations Policy
# ==============================================================================

bulk_export_allowed if {
	input.poa.act == "salesforce.bulk.export"

	# Check record count
	record_count := input.poa.con.record_count
	record_count < 10000

	# Must have data access reason
	input.poa.con.data_purpose != ""

	# Must comply with GDPR if EU data
	gdpr_compliant
}

bulk_export_allowed if {
	input.poa.act == "salesforce.bulk.export"

	# Large exports need DPO approval
	record_count := input.poa.con.record_count
	record_count >= 10000

	has_dpo_approval
	gdpr_compliant
}

gdpr_compliant if {
	# Non-EU jurisdiction - no special requirements
	not input.poa.leg.jurisdiction in {"DE", "FR", "GB", "EU", "GDPR"}
}

gdpr_compliant if {
	# EU jurisdiction - need legal basis
	input.poa.leg.jurisdiction in {"DE", "FR", "GB", "EU", "GDPR"}
	valid_gdpr_bases := {"consent", "contract", "legal_obligation", "vital_interest", "public_interest", "legitimate_interest"}
	input.poa.leg.basis in valid_gdpr_bases
}

# ==============================================================================
# Record Ownership Policy
# ==============================================================================

# Users can only modify records they own or have explicit permission
record_access_allowed if {
	# User owns the record
	input.poa.con.record_owner == input.poa.leg.accountable_party.id
}

record_access_allowed if {
	# User has admin role
	"salesforce.admin" in input.poa.leg.accountable_party.roles
}

record_access_allowed if {
	# User is in the same team as record owner
	owner_team := data.salesforce.user_teams[input.poa.con.record_owner]
	user_team := data.salesforce.user_teams[input.poa.leg.accountable_party.id]
	owner_team == user_team
}

record_access_allowed if {
	# Manager can access team members' records
	user_id := input.poa.leg.accountable_party.id
	record_owner := input.poa.con.record_owner
	user_id in data.salesforce.managers[record_owner]
}

# ==============================================================================
# Helper Functions
# ==============================================================================

has_manager_approval if {
	some approval in input.poa.leg.approvals
	approval.role == "manager"
}

has_manager_approval if {
	some approval in input.poa.leg.approvals
	"manager" in data.salesforce.user_roles[approval.approver]
}

has_executive_approval if {
	some approval in input.poa.leg.approvals
	approval.role in {"vp", "director", "executive"}
}

has_legal_approval if {
	some approval in input.poa.leg.approvals
	approval.role == "legal"
}

has_legal_approval if {
	some approval in input.poa.leg.approvals
	startswith(approval.approver, "legal@")
}

has_dpo_approval if {
	some approval in input.poa.leg.approvals
	approval.role == "dpo"
}

has_dpo_approval if {
	some approval in input.poa.leg.approvals
	approval.approver == data.organization.dpo_email
}
