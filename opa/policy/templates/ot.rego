# OT/Industrial Policy Templates for ATB
# Pre-built OPA policies for PLCs, HMIs, and SCADA systems
# SPDX-License-Identifier: Apache-2.0

package atb.templates.ot

import rego.v1

# ==============================================================================
# OT Action Risk Classification
# ==============================================================================

# HIGH risk actions - require dual control and maintenance window
ot_high_risk_actions := {
    "ot.plc.firmware_update",
    "ot.plc.logic_change",
    "ot.plc.factory_reset",
    "ot.safety.override",
    "ot.scada.config_change",
    "ot.network.firewall_change",
}

# MEDIUM risk actions - require single approval
ot_medium_risk_actions := {
    "ot.hmi.setpoint_change",
    "ot.plc.parameter_change",
    "ot.scada.control_action",
    "ot.alarm.acknowledge",
    "ot.recipe.change",
}

# LOW risk actions - auto-approved with logging
ot_low_risk_actions := {
    "ot.plc.status_read",
    "ot.hmi.display_read",
    "ot.scada.data_read",
    "ot.alarm.view",
    "ot.historian.query",
    "ot.asset.inventory_read",
}

# ==============================================================================
# Safety Bounds
# ==============================================================================

safety_bounds := {
    "temperature": {"min": -40, "max": 120, "unit": "celsius"},
    "pressure": {"min": 0, "max": 150, "unit": "bar"},
    "flow_rate": {"min": 0, "max": 1000, "unit": "l_per_min"},
    "speed": {"min": 0, "max": 3000, "unit": "rpm"},
    "level": {"min": 0, "max": 100, "unit": "percent"},
    "voltage": {"min": 0, "max": 480, "unit": "volts"},
}

# ==============================================================================
# Risk Tier Calculation
# ==============================================================================

default risk_tier := "UNKNOWN"

risk_tier := "HIGH" if {
    input.act in ot_high_risk_actions
}

risk_tier := "MEDIUM" if {
    not input.act in ot_high_risk_actions
    input.act in ot_medium_risk_actions
}

risk_tier := "LOW" if {
    not input.act in ot_high_risk_actions
    not input.act in ot_medium_risk_actions
    input.act in ot_low_risk_actions
}

# ==============================================================================
# Deny Rules
# ==============================================================================

# Setpoint change must be within safety bounds (below minimum)
deny contains msg if {
    input.act == "ot.hmi.setpoint_change"
    param := input.con.parameter
    bound := safety_bounds[param]
    value := input.con.value
    value < bound.min
    msg := sprintf("%s value %v below minimum %v %s", [param, value, bound.min, bound.unit])
}

# Setpoint change must be within safety bounds (above maximum)
deny contains msg if {
    input.act == "ot.hmi.setpoint_change"
    param := input.con.parameter
    bound := safety_bounds[param]
    value := input.con.value
    value > bound.max
    msg := sprintf("%s value %v exceeds maximum %v %s", [param, value, bound.max, bound.unit])
}

# Firmware update requires maintenance window
deny contains msg if {
    input.act == "ot.plc.firmware_update"
    not input.con.maintenance_window == true
    msg := "Firmware update requires maintenance window"
}

# Firmware update requires dual control
deny contains msg if {
    input.act == "ot.plc.firmware_update"
    not has_dual_control
    msg := "Firmware update requires dual control"
}

# Logic change requires dual control
deny contains msg if {
    input.act == "ot.plc.logic_change"
    not has_dual_control
    msg := "PLC logic change requires dual control"
}

# Safety override is always denied (requires physical key)
deny contains msg if {
    input.act == "ot.safety.override"
    msg := "Safety override cannot be performed remotely - requires physical key"
}

# Factory reset requires dual control
deny contains msg if {
    input.act == "ot.plc.factory_reset"
    not has_dual_control
    msg := "Factory reset requires dual control"
}

# SCADA config change requires dual control
deny contains msg if {
    input.act == "ot.scada.config_change"
    not has_dual_control
    msg := "SCADA configuration change requires dual control"
}

# ==============================================================================
# Helper Functions
# ==============================================================================

has_dual_control if {
    input.con.dual_control == true
    input.leg.dual_control.approvers
    count(input.leg.dual_control.approvers) >= 2
}

in_maintenance_window if {
    input.con.maintenance_window == true
}
