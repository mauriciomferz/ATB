# SAP Policy Template Tests
# SPDX-License-Identifier: Apache-2.0

package atb.templates.sap_test

import data.atb.templates.sap
import rego.v1

# Test: Vendor bank change requires dual control
test_vendor_bank_change_requires_dual_control if {
    result := sap.deny with input as {
        "act": "sap.vendor.bank_change",
        "con": {},
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) > 0
}

# Test: Vendor bank change allowed with dual control
test_vendor_bank_change_allowed_with_dual_control if {
    result := sap.deny with input as {
        "act": "sap.vendor.bank_change",
        "con": {
            "dual_control": true
        },
        "leg": {
            "basis": "contract",
            "dual_control": {
                "approvers": [
                    {"id": "bob@example.com", "timestamp": "2026-01-15T10:00:00Z"},
                    {"id": "carol@example.com", "timestamp": "2026-01-15T10:05:00Z"}
                ]
            },
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) == 0
}

# Test: Payment exceeding limit is denied
test_payment_exceeds_limit if {
    result := sap.deny with input as {
        "act": "sap.payment.execute",
        "con": {
            "amount": 1500000,
            "currency": "USD"
        },
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) > 0
}

# Test: Payment within limit is allowed
test_payment_within_limit if {
    result := sap.deny with input as {
        "act": "sap.payment.execute",
        "con": {
            "amount": 500000,
            "currency": "USD",
            "dual_control": true
        },
        "leg": {
            "basis": "contract",
            "dual_control": {
                "approvers": [
                    {"id": "bob@example.com", "timestamp": "2026-01-15T10:00:00Z"},
                    {"id": "carol@example.com", "timestamp": "2026-01-15T10:05:00Z"}
                ]
            },
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) == 0
}

# Test: Journal entry exceeding limit is denied
test_journal_exceeds_limit if {
    result := sap.deny with input as {
        "act": "sap.journal.post",
        "con": {
            "amount": 2000000,
            "currency": "EUR"
        },
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) > 0
}

# Test: Low risk material read is allowed
test_material_read_allowed if {
    result := sap.deny with input as {
        "act": "sap.material.read",
        "con": {},
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) == 0
}

# Test: Risk tier classification - high risk
test_risk_tier_high if {
    tier := sap.risk_tier with input as {"act": "sap.vendor.bank_change"}
    tier == "HIGH"
}

# Test: Risk tier classification - medium risk
test_risk_tier_medium if {
    tier := sap.risk_tier with input as {"act": "sap.material.create"}
    tier == "MEDIUM"
}

# Test: Risk tier classification - low risk
test_risk_tier_low if {
    tier := sap.risk_tier with input as {"act": "sap.material.read"}
    tier == "LOW"
}
