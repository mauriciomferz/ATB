# OT/Industrial Policy Templates for ATB
# Pre-built OPA policies for industrial control systems and OT environments

package atb.templates.ot

import rego.v1

# ==============================================================================
# OT Action Risk Classification
# ==============================================================================

# CRITICAL risk - can cause physical harm or production stoppage
ot_critical_actions := {
	"s7.plc.stop",
	"s7.plc.start",
	"s7.program.upload",
	"s7.program.download",
	"opcua.method.call",
	"modbus.coil.write",
	"scada.setpoint.change",
	"scada.alarm.acknowledge",
	"ot.actuator.command",
	"ot.emergency.stop",
	"ot.safety.override",
}

# HIGH risk - affects production parameters
ot_high_risk_actions := {
	"s7.db.write",
	"opcua.node.write",
	"modbus.register.write",
	"scada.parameter.change",
	"historian.data.delete",
	"ot.recipe.change",
	"ot.batch.start",
}

# MEDIUM risk - monitoring configuration
ot_medium_risk_actions := {
	"s7.db.read",
	"opcua.node.read",
	"modbus.register.read",
	"scada.trend.configure",
	"historian.tag.create",
	"ot.alarm.configure",
}

# LOW risk - passive monitoring
ot_low_risk_actions := {
	"scada.screen.view",
	"historian.data.read",
	"ot.status.read",
	"ot.alarm.view",
	"ot.report.generate",
}

# Determine risk tier
ot_risk_tier := "CRITICAL" if input.poa.act in ot_critical_actions

ot_risk_tier := "HIGH" if {
	not input.poa.act in ot_critical_actions
	input.poa.act in ot_high_risk_actions
}

ot_risk_tier := "MEDIUM" if {
	not input.poa.act in ot_critical_actions
	not input.poa.act in ot_high_risk_actions
	input.poa.act in ot_medium_risk_actions
}

ot_risk_tier := "LOW" if {
	not input.poa.act in ot_critical_actions
	not input.poa.act in ot_high_risk_actions
	not input.poa.act in ot_medium_risk_actions
}

# ==============================================================================
# PLC Control Policy
# ==============================================================================

plc_stop_allowed if {
	input.poa.act == "s7.plc.stop"

	# Must have operator certification
	has_operator_certification

	# Must be during maintenance window OR emergency
	in_maintenance_window
}

plc_stop_allowed if {
	input.poa.act == "s7.plc.stop"

	# Emergency stop always allowed for certified operators
	input.poa.con.emergency == true
	has_operator_certification

	# But must have reason
	input.poa.con.emergency_reason != ""
}

plc_start_allowed if {
	input.poa.act == "s7.plc.start"

	# Must have operator certification
	has_operator_certification

	# Safety checks must be complete
	input.poa.con.safety_checks_complete == true

	# Dual control for production PLCs
	is_production_plc
	input.poa.con.dual_control == true
}

plc_start_allowed if {
	input.poa.act == "s7.plc.start"

	# Test/dev PLCs don't need dual control
	not is_production_plc
	has_operator_certification
}

plc_program_upload_allowed if {
	input.poa.act in {"s7.program.upload", "s7.program.download"}

	# Only during maintenance window
	in_maintenance_window

	# Requires engineering role
	has_engineering_role

	# Dual control required
	input.poa.con.dual_control == true

	# Change ticket required
	input.poa.con.change_ticket != ""
}

# ==============================================================================
# Setpoint Change Policy
# ==============================================================================

setpoint_change_allowed if {
	input.poa.act == "scada.setpoint.change"

	# Check setpoint is within safe limits
	setpoint_value := input.poa.con.setpoint_value
	min_value := input.poa.con.safe_min
	max_value := input.poa.con.safe_max

	setpoint_value >= min_value
	setpoint_value <= max_value

	# Operator certification required
	has_operator_certification
}

setpoint_change_allowed if {
	input.poa.act == "scada.setpoint.change"

	# Setpoint outside normal range requires engineering approval
	setpoint_value := input.poa.con.setpoint_value
	min_value := input.poa.con.safe_min
	max_value := input.poa.con.safe_max

	setpoint_value < min_value
	has_engineering_approval
	input.poa.con.override_reason != ""
}

setpoint_change_allowed if {
	input.poa.act == "scada.setpoint.change"

	setpoint_value := input.poa.con.setpoint_value
	max_value := input.poa.con.safe_max

	setpoint_value > max_value
	has_engineering_approval
	input.poa.con.override_reason != ""
}

setpoint_denial_reason := "Setpoint outside safe operating range - requires engineering approval" if {
	input.poa.act == "scada.setpoint.change"
	setpoint_value := input.poa.con.setpoint_value

	out_of_range := setpoint_value < input.poa.con.safe_min
	out_of_range2 := setpoint_value > input.poa.con.safe_max
	out_of_range
	not has_engineering_approval
}

# ==============================================================================
# Safety Override Policy
# ==============================================================================

# Safety overrides are extremely sensitive and require multiple controls
safety_override_allowed if {
	input.poa.act == "ot.safety.override"

	# Must have safety officer approval
	has_safety_officer_approval

	# Must have engineering approval
	has_engineering_approval

	# Must have documented reason
	input.poa.con.override_reason != ""

	# Must have time limit
	input.poa.con.override_duration_minutes > 0
	input.poa.con.override_duration_minutes <= 60

	# Must not be in production
	not in_production_mode
}

safety_override_denied_reason := "Safety overrides not allowed during production" if {
	input.poa.act == "ot.safety.override"
	in_production_mode
}

safety_override_denied_reason := "Safety overrides require safety officer and engineering approval" if {
	input.poa.act == "ot.safety.override"
	not has_safety_officer_approval
}

# ==============================================================================
# Zone-Based Access Control
# ==============================================================================

# IEC 62443 Zone-based security
zone_access_allowed if {
	# User's zone clearance includes target zone
	target_zone := input.poa.con.target_zone
	user_zones := data.ot.user_zone_access[input.poa.leg.accountable_party.id]
	target_zone in user_zones
}

zone_access_allowed if {
	# Admin has access to all zones
	"ot.admin" in input.poa.leg.accountable_party.roles
}

zone_access_denied_reason := sprintf("User not authorized for zone %s", [input.poa.con.target_zone]) if {
	not zone_access_allowed
	input.poa.con.target_zone
}

# ==============================================================================
# Time-Based Restrictions
# ==============================================================================

in_maintenance_window if {
	# Check if current time is within scheduled maintenance
	now_ns := time.now_ns()
	[hour, _, _] := time.clock([now_ns, "UTC"])

	# Maintenance window: 02:00-06:00 UTC
	hour >= 2
	hour < 6
}

in_maintenance_window if {
	# Or if maintenance mode is explicitly enabled
	input.poa.con.maintenance_mode == true
}

in_production_mode if {
	# Production hours: 06:00-22:00 local time
	now_ns := time.now_ns()
	[hour, _, _] := time.clock([now_ns, "Europe/Berlin"])
	hour >= 6
	hour < 22

	# And not in maintenance mode
	not input.poa.con.maintenance_mode == true
}

# ==============================================================================
# Helper Functions
# ==============================================================================

has_operator_certification if {
	"ot.operator.certified" in input.poa.leg.accountable_party.roles
}

has_operator_certification if {
	user_id := input.poa.leg.accountable_party.id
	user_id in data.ot.certified_operators
}

has_engineering_role if {
	"ot.engineer" in input.poa.leg.accountable_party.roles
}

has_engineering_approval if {
	some approval in input.poa.leg.approvals
	approval.role == "engineer"
}

has_engineering_approval if {
	some approval in input.poa.leg.approvals
	approval.approver in data.ot.engineers
}

has_safety_officer_approval if {
	some approval in input.poa.leg.approvals
	approval.role == "safety_officer"
}

has_safety_officer_approval if {
	some approval in input.poa.leg.approvals
	approval.approver in data.ot.safety_officers
}

is_production_plc if {
	plc_id := input.poa.con.plc_id
	plc_id in data.ot.production_plcs
}

is_production_plc if {
	startswith(input.poa.con.plc_id, "PROD-")
}
