# SAP Policy Templates for ATB
# Pre-built OPA policies for common SAP S/4HANA and Joule actions
# SPDX-License-Identifier: Apache-2.0

package atb.templates.sap

import rego.v1

# ==============================================================================
# SAP Action Risk Classification
# ==============================================================================

# HIGH risk actions - require dual control and manager approval
sap_high_risk_actions := {
    "sap.vendor.bank_change",
    "sap.vendor.create",
    "sap.payment.execute",
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

# ==============================================================================
# Risk Tier Calculation
# ==============================================================================

default risk_tier := "UNKNOWN"

risk_tier := "HIGH" if {
    input.act in sap_high_risk_actions
}

risk_tier := "MEDIUM" if {
    not input.act in sap_high_risk_actions
    input.act in sap_medium_risk_actions
}

risk_tier := "LOW" if {
    not input.act in sap_high_risk_actions
    not input.act in sap_medium_risk_actions
    input.act in sap_low_risk_actions
}

# ==============================================================================
# Deny Rules
# ==============================================================================

# Vendor bank change requires dual control (BEC prevention)
deny contains msg if {
    input.act == "sap.vendor.bank_change"
    not has_dual_control
    msg := "Vendor bank change requires dual control with 2 different approvers"
}

# Payment execution has amount limit
deny contains msg if {
    input.act == "sap.payment.execute"
    amount := object.get(input.con, "amount", 0)
    amount > 1000000
    msg := sprintf("Payment amount %v exceeds $1,000,000 limit", [amount])
}

# Payment execution requires dual control
deny contains msg if {
    input.act == "sap.payment.execute"
    not has_dual_control
    msg := "Payment execution requires dual control"
}

# Journal posting has amount limit
deny contains msg if {
    input.act == "sap.journal.post"
    amount := object.get(input.con, "amount", 0)
    amount > 1000000
    msg := sprintf("Journal amount %v exceeds $1,000,000 limit", [amount])
}

# Journal posting requires dual control
deny contains msg if {
    input.act == "sap.journal.post"
    not has_dual_control
    msg := "Journal posting requires dual control"
}

# All HIGH risk actions require dual control (generic rule)
deny contains msg if {
    input.act in sap_high_risk_actions
    not has_dual_control
    not input.act == "sap.vendor.bank_change"
    not input.act == "sap.payment.execute"
    not input.act == "sap.journal.post"
    msg := sprintf("Action %s requires dual control", [input.act])
}

# ==============================================================================
# Helper Functions
# ==============================================================================

has_dual_control if {
    input.con.dual_control == true
    input.leg.dual_control.approvers
    count(input.leg.dual_control.approvers) >= 2
}

has_manager_approval if {
    some approver in input.leg.dual_control.approvers
    approver.role == "manager"
}
