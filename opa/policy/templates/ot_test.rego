# OT/Industrial Policy Template Tests
# SPDX-License-Identifier: Apache-2.0

package atb.templates.ot_test

import data.atb.templates.ot
import rego.v1

# Test: Temperature below minimum is denied
test_temperature_below_min if {
    result := ot.deny with input as {
        "act": "ot.hmi.setpoint_change",
        "con": {
            "parameter": "temperature",
            "value": -50,
            "unit": "celsius"
        },
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "operator@example.com"}
        }
    }
    count(result) > 0
}

# Test: Temperature above maximum is denied
test_temperature_above_max if {
    result := ot.deny with input as {
        "act": "ot.hmi.setpoint_change",
        "con": {
            "parameter": "temperature",
            "value": 150,
            "unit": "celsius"
        },
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "operator@example.com"}
        }
    }
    count(result) > 0
}

# Test: Temperature within bounds is allowed
test_temperature_within_bounds if {
    result := ot.deny with input as {
        "act": "ot.hmi.setpoint_change",
        "con": {
            "parameter": "temperature",
            "value": 75,
            "unit": "celsius"
        },
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "operator@example.com"}
        }
    }
    count(result) == 0
}

# Test: Pressure exceeding maximum is denied
test_pressure_above_max if {
    result := ot.deny with input as {
        "act": "ot.hmi.setpoint_change",
        "con": {
            "parameter": "pressure",
            "value": 200,
            "unit": "bar"
        },
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "operator@example.com"}
        }
    }
    count(result) > 0
}

# Test: Speed within bounds is allowed
test_speed_within_bounds if {
    result := ot.deny with input as {
        "act": "ot.hmi.setpoint_change",
        "con": {
            "parameter": "speed",
            "value": 1500,
            "unit": "rpm"
        },
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "operator@example.com"}
        }
    }
    count(result) == 0
}

# Test: Firmware update requires maintenance window
test_firmware_update_requires_maintenance_window if {
    result := ot.deny with input as {
        "act": "ot.plc.firmware_update",
        "con": {},
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "engineer@example.com"}
        }
    }
    count(result) > 0
}

# Test: Firmware update allowed during maintenance window
test_firmware_update_with_maintenance_window if {
    result := ot.deny with input as {
        "act": "ot.plc.firmware_update",
        "con": {
            "maintenance_window": true,
            "dual_control": true
        },
        "leg": {
            "basis": "contract",
            "dual_control": {
                "approvers": [
                    {"id": "engineer@example.com", "timestamp": "2026-01-15T02:00:00Z"},
                    {"id": "safety@example.com", "timestamp": "2026-01-15T02:05:00Z"}
                ]
            },
            "accountable_party": {"type": "human", "id": "engineer@example.com"}
        }
    }
    count(result) == 0
}

# Test: Logic change requires dual control
test_logic_change_requires_dual_control if {
    result := ot.deny with input as {
        "act": "ot.plc.logic_change",
        "con": {},
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "engineer@example.com"}
        }
    }
    count(result) > 0
}

# Test: Safety override always denied
test_safety_override_denied if {
    result := ot.deny with input as {
        "act": "ot.safety.override",
        "con": {},
        "leg": {
            "basis": "legal_obligation",
            "accountable_party": {"type": "human", "id": "safety@example.com"}
        }
    }
    count(result) > 0
}

# Test: PLC status read is allowed (low risk)
test_plc_status_read_allowed if {
    result := ot.deny with input as {
        "act": "ot.plc.status_read",
        "con": {},
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "operator@example.com"}
        }
    }
    count(result) == 0
}

# Test: Risk tier classification - high risk
test_risk_tier_high if {
    tier := ot.risk_tier with input as {"act": "ot.plc.firmware_update"}
    tier == "HIGH"
}

# Test: Risk tier classification - medium risk
test_risk_tier_medium if {
    tier := ot.risk_tier with input as {"act": "ot.hmi.setpoint_change"}
    tier == "MEDIUM"
}

# Test: Risk tier classification - low risk
test_risk_tier_low if {
    tier := ot.risk_tier with input as {"act": "ot.plc.status_read"}
    tier == "LOW"
}
