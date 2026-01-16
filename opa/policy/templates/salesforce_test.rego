# Salesforce Policy Template Tests
# SPDX-License-Identifier: Apache-2.0

package atb.templates.salesforce_test

import data.atb.templates.salesforce
import rego.v1

# Test: Credit exceeding limit is denied
test_credit_exceeds_limit if {
    result := salesforce.deny with input as {
        "act": "salesforce.credit.issue",
        "con": {
            "amount": 15000,
            "currency": "USD"
        },
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) > 0
}

# Test: Credit within limit is allowed
test_credit_within_limit if {
    result := salesforce.deny with input as {
        "act": "salesforce.credit.issue",
        "con": {
            "amount": 5000,
            "currency": "USD"
        },
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) == 0
}

# Test: Refund exceeding limit is denied
test_refund_exceeds_limit if {
    result := salesforce.deny with input as {
        "act": "salesforce.refund.process",
        "con": {
            "amount": 7500,
            "currency": "USD"
        },
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) > 0
}

# Test: Large opportunity close requires dual control
test_large_opportunity_requires_dual_control if {
    result := salesforce.deny with input as {
        "act": "salesforce.opportunity.close_won",
        "con": {
            "amount": 150000,
            "currency": "USD"
        },
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) > 0
}

# Test: Small opportunity close allowed without dual control
test_small_opportunity_allowed if {
    result := salesforce.deny with input as {
        "act": "salesforce.opportunity.close_won",
        "con": {
            "amount": 50000,
            "currency": "USD"
        },
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) == 0
}

# Test: Contract termination requires legal basis
test_contract_termination_requires_legal_basis if {
    result := salesforce.deny with input as {
        "act": "salesforce.contract.terminate",
        "con": {},
        "leg": {}
    }
    count(result) > 0
}

# Test: Contract termination allowed with legal basis
test_contract_termination_with_legal_basis if {
    result := salesforce.deny with input as {
        "act": "salesforce.contract.terminate",
        "con": {},
        "leg": {
            "basis": "contract",
            "justification": "Customer requested termination per clause 12.3",
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) == 0
}

# Test: Report export requires dual control (PII)
test_report_export_requires_dual_control if {
    result := salesforce.deny with input as {
        "act": "salesforce.report.export",
        "con": {},
        "leg": {
            "basis": "contract",
            "accountable_party": {"type": "human", "id": "alice@example.com"}
        }
    }
    count(result) > 0
}

# Test: Account read is allowed (low risk)
test_account_read_allowed if {
    result := salesforce.deny with input as {
        "act": "salesforce.account.read",
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
    tier := salesforce.risk_tier with input as {"act": "salesforce.report.export"}
    tier == "HIGH"
}

# Test: Risk tier classification - medium risk
test_risk_tier_medium if {
    tier := salesforce.risk_tier with input as {"act": "salesforce.credit.issue"}
    tier == "MEDIUM"
}

# Test: Risk tier classification - low risk
test_risk_tier_low if {
    tier := salesforce.risk_tier with input as {"act": "salesforce.account.read"}
    tier == "LOW"
}
