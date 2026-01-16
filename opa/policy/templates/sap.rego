# SAP Policy Templates for ATB
# Pre-built OPA policies for common SAP S/4HANA and Joule actions

package atb.templates.sap

import rego.v1

# ==============================================================================
# SAP Action Risk Classification
# ==============================================================================

# HIGH risk actions - require dual control and manager approval
sap_high_risk_actions := {
	"sap.vendor.bank_change",
	"sap.vendor.create",
	"sap.payment.approve",
	"sap.payment.release",
	"sap.journal.post",
	"sap.journal.reverse",
	"sap.hcm.payroll.run",
	"sap.hcm.compensation.change",
	"sap.ariba.contract.approve",
	"sap.ariba.sourcing.award",
	"sap.po.release",
	"sap.user.privilege.grant",
}

# MEDIUM risk actions - require single approval
sap_medium_risk_actions := {
	"sap.vendor.update",
	"sap.vendor.block",
	"sap.po.create",
	"sap.po.approve",
	"sap.pr.approve",
	"sap.gr.post",
	"sap.ir.post",
	"sap.material.create",
	"sap.stock.transfer",
	"sap.sd.order.create",
	"sap.hcm.employee.update",
}

# LOW risk actions - auto-approved with logging
sap_low_risk_actions := {
	"sap.vendor.read",
	"sap.material.read",
	"sap.stock.read",
	"sap.order.read",
	"sap.report.run",
	"sap.hcm.employee.read",
}

# Determine risk tier for SAP actions
sap_risk_tier := "HIGH" if input.poa.act in sap_high_risk_actions

sap_risk_tier := "MEDIUM" if {
	not input.poa.act in sap_high_risk_actions
	input.poa.act in sap_medium_risk_actions
}

sap_risk_tier := "LOW" if {
	not input.poa.act in sap_high_risk_actions
	not input.poa.act in sap_medium_risk_actions
	input.poa.act in sap_low_risk_actions
}

sap_risk_tier := "MEDIUM" if {
	startswith(input.poa.act, "sap.")
	not input.poa.act in sap_high_risk_actions
	not input.poa.act in sap_medium_risk_actions
	not input.poa.act in sap_low_risk_actions
}

# ==============================================================================
# SAP Vendor Bank Change Policy (Critical BEC Prevention)
# ==============================================================================

# Vendor bank changes are the #1 target for business email compromise
vendor_bank_change_allowed if {
	input.poa.act == "sap.vendor.bank_change"

	# Must have dual control (2 approvers)
	input.poa.con.dual_control == true
	count(input.poa.leg.approvals) >= 2

	# Approvers must be different people
	approvers := {a.approver | some a in input.poa.leg.approvals}
	count(approvers) >= 2

	# Requestor cannot be an approver
	requestor := input.poa.leg.accountable_party.id
	not requestor in approvers

	# Must have manager approval
	has_manager_approval

	# Time window check (request within business hours)
	within_business_hours
}

vendor_bank_change_denial_reason := "Vendor bank change requires dual control with 2 different approvers" if {
	input.poa.act == "sap.vendor.bank_change"
	not input.poa.con.dual_control == true
}

vendor_bank_change_denial_reason := "Vendor bank change requires manager approval" if {
	input.poa.act == "sap.vendor.bank_change"
	not has_manager_approval
}

# ==============================================================================
# SAP Payment Approval Policy
# ==============================================================================

payment_approval_allowed if {
	input.poa.act == "sap.payment.approve"

	# Amount within authorized limit
	amount := input.poa.con.max_amount
	amount <= payment_limit_for_user

	# Dual control for amounts over threshold
	amount < 10000
}

payment_approval_allowed if {
	input.poa.act == "sap.payment.approve"

	amount := input.poa.con.max_amount
	amount >= 10000

	# Amounts >= 10000 require dual control
	input.poa.con.dual_control == true
	count(input.poa.leg.approvals) >= 2
}

payment_limit_for_user := 50000 if {
	"sap.payment.manager" in input.poa.leg.accountable_party.roles
}

payment_limit_for_user := 10000 if {
	"sap.payment.standard" in input.poa.leg.accountable_party.roles
	not "sap.payment.manager" in input.poa.leg.accountable_party.roles
}

payment_limit_for_user := 1000 if {
	not "sap.payment.manager" in input.poa.leg.accountable_party.roles
	not "sap.payment.standard" in input.poa.leg.accountable_party.roles
}

# ==============================================================================
# SAP Journal Posting Policy
# ==============================================================================

journal_post_allowed if {
	input.poa.act == "sap.journal.post"

	# Document type must be valid
	valid_doc_types := {"SA", "AB", "SK", "KR", "KZ", "DZ", "DA"}
	input.poa.con.document_type in valid_doc_types

	# Amount within limit
	amount := input.poa.con.max_amount
	amount <= 100000
}

journal_post_allowed if {
	input.poa.act == "sap.journal.post"

	# Large postings require dual control
	amount := input.poa.con.max_amount
	amount > 100000
	input.poa.con.dual_control == true
}

# ==============================================================================
# SAP Company Code Restrictions
# ==============================================================================

# Restrict actions to specific company codes based on user's authorization
company_code_authorized if {
	user_company_codes := data.sap.user_authorizations[input.poa.leg.accountable_party.id].company_codes
	input.poa.con.company_code in user_company_codes
}

company_code_authorized if {
	# If no company code in constraints, allow (will be checked by SAP)
	not input.poa.con.company_code
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
	endswith(approval.approver, "@management.example.com")
}

within_business_hours if {
	# Extract hour from timestamp (simplified)
	now_ns := time.now_ns()
	[hour, _, _] := time.clock([now_ns, "Europe/Berlin"])
	hour >= 8
	hour < 18
}

within_business_hours if {
	# Allow override for emergency
	input.poa.con.emergency_override == true
}
