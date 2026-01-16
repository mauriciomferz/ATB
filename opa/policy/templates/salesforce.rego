# Salesforce Policy Templates for ATB
# Pre-built OPA policies for Salesforce and Agentforce actions
# SPDX-License-Identifier: Apache-2.0

package atb.templates.salesforce

import rego.v1

# ==============================================================================
# Salesforce Action Risk Classification
# ==============================================================================

# HIGH risk actions - require dual control
salesforce_high_risk_actions := {
    "salesforce.report.export",
    "salesforce.bulk.export",
    "salesforce.user.create",
    "salesforce.user.deactivate",
    "salesforce.permission_set.assign",
    "salesforce.data.delete_bulk",
}

# MEDIUM risk actions - require single approval
salesforce_medium_risk_actions := {
    "salesforce.opportunity.create",
    "salesforce.opportunity.update",
    "salesforce.opportunity.close_won",
    "salesforce.credit.issue",
    "salesforce.refund.process",
    "salesforce.contract.create",
    "salesforce.contract.terminate",
    "salesforce.lead.convert",
    "salesforce.case.escalate",
}

# LOW risk actions - auto-approved with logging
salesforce_low_risk_actions := {
    "salesforce.account.read",
    "salesforce.contact.read",
    "salesforce.opportunity.read",
    "salesforce.lead.read",
    "salesforce.case.read",
    "salesforce.report.view",
    "salesforce.dashboard.view",
}

# ==============================================================================
# Risk Tier Calculation
# ==============================================================================

default risk_tier := "UNKNOWN"

risk_tier := "HIGH" if {
    input.act in salesforce_high_risk_actions
}

risk_tier := "MEDIUM" if {
    not input.act in salesforce_high_risk_actions
    input.act in salesforce_medium_risk_actions
}

risk_tier := "LOW" if {
    not input.act in salesforce_high_risk_actions
    not input.act in salesforce_medium_risk_actions
    input.act in salesforce_low_risk_actions
}

# ==============================================================================
# Deny Rules
# ==============================================================================

# Credit issuance has amount limit
deny contains msg if {
    input.act == "salesforce.credit.issue"
    amount := object.get(input.con, "amount", 0)
    amount > 10000
    msg := sprintf("Credit amount %v exceeds $10,000 limit", [amount])
}

# Refund processing has amount limit
deny contains msg if {
    input.act == "salesforce.refund.process"
    amount := object.get(input.con, "amount", 0)
    amount > 5000
    msg := sprintf("Refund amount %v exceeds $5,000 limit", [amount])
}

# Large opportunities require dual control
deny contains msg if {
    input.act == "salesforce.opportunity.close_won"
    amount := object.get(input.con, "amount", 0)
    amount > 100000
    not has_dual_control
    msg := sprintf("Opportunity close over $100,000 requires dual control", [])
}

# Contract termination requires legal basis and justification
deny contains msg if {
    input.act == "salesforce.contract.terminate"
    not has_legal_basis
    msg := "Contract termination requires legal basis"
}

deny contains msg if {
    input.act == "salesforce.contract.terminate"
    not has_justification
    msg := "Contract termination requires justification"
}

# Report export requires dual control (PII protection)
deny contains msg if {
    input.act == "salesforce.report.export"
    not has_dual_control
    msg := "Report export requires dual control (PII protection)"
}

# Bulk export requires dual control
deny contains msg if {
    input.act == "salesforce.bulk.export"
    not has_dual_control
    msg := "Bulk data export requires dual control"
}

# User creation requires dual control
deny contains msg if {
    input.act == "salesforce.user.create"
    not has_dual_control
    msg := "User creation requires dual control"
}

# ==============================================================================
# Helper Functions
# ==============================================================================

has_dual_control if {
    input.con.dual_control == true
    input.leg.dual_control.approvers
    count(input.leg.dual_control.approvers) >= 2
}

has_legal_basis if {
    input.leg.basis
    input.leg.basis != ""
}

has_justification if {
    input.leg.justification
    input.leg.justification != ""
}
