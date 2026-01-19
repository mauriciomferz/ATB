# OPA Policy Templates

Pre-built policy templates for enterprise platforms. These templates provide risk-tiered authorization rules for common enterprise actions.

## Available Templates

| Template      | File                               | Platform               | Actions                                   |
| ------------- | ---------------------------------- | ---------------------- | ----------------------------------------- |
| SAP           | [sap.rego](sap.rego)               | SAP S/4HANA, Joule     | Payments, vendor changes, journal entries |
| Salesforce    | [salesforce.rego](salesforce.rego) | Salesforce, Agentforce | Opportunities, credits, contracts         |
| OT/Industrial | [ot.rego](ot.rego)                 | PLCs, HMIs, SCADA      | Setpoints, controls, safety overrides     |

## SAP Template

High-risk financial operations requiring dual control:

### Actions

| Action                   | Risk Tier | Constraints                            |
| ------------------------ | --------- | -------------------------------------- |
| `sap.vendor.bank_change` | HIGH      | Requires dual approvers, audit logging |
| `sap.payment.execute`    | HIGH      | Max amount: $1,000,000                 |
| `sap.journal.post`       | HIGH      | Max amount: $1,000,000                 |
| `sap.material.create`    | MEDIUM    | Standard approval                      |
| `sap.material.read`      | LOW       | Auto-approved                          |

### Example Policy

```rego
# From sap.rego
sap_high_risk_actions := {
    "sap.vendor.bank_change",
    "sap.payment.execute",
    "sap.journal.post"
}

deny[msg] {
    input.act == "sap.payment.execute"
    input.con.amount > 1000000
    msg := sprintf("Payment amount %v exceeds $1M limit", [input.con.amount])
}
```

## Salesforce Template

CRM operations with PII protection:

### Actions

| Action                             | Risk Tier | Constraints                    |
| ---------------------------------- | --------- | ------------------------------ |
| `salesforce.report.export`         | HIGH      | PII protection, dual control   |
| `salesforce.opportunity.close_won` | HIGH      | > $100k requires dual approval |
| `salesforce.credit.issue`          | MEDIUM    | Max: $10,000                   |
| `salesforce.refund.process`        | MEDIUM    | Max: $5,000                    |
| `salesforce.contract.terminate`    | HIGH      | Requires legal basis           |
| `salesforce.account.read`          | LOW       | Auto-approved                  |

### Example Policy

```rego
# From salesforce.rego
deny[msg] {
    input.act == "salesforce.credit.issue"
    input.con.amount > 10000
    msg := sprintf("Credit amount %v exceeds $10,000 limit", [input.con.amount])
}
```

## OT/Industrial Template

Safety-critical operations for industrial environments:

### Actions

| Action                    | Risk Tier | Constraints                 |
| ------------------------- | --------- | --------------------------- |
| `ot.plc.firmware_update`  | HIGH      | Requires maintenance window |
| `ot.plc.logic_change`     | HIGH      | Dual control required       |
| `ot.hmi.setpoint_change`  | MEDIUM    | Within safety bounds        |
| `ot.scada.control_action` | MEDIUM    | Standard approval           |
| `ot.plc.status_read`      | LOW       | Auto-approved               |

### Safety Bounds

```rego
# From ot.rego
safety_bounds := {
    "temperature": {"min": -40, "max": 120, "unit": "celsius"},
    "pressure": {"min": 0, "max": 150, "unit": "bar"},
    "flow_rate": {"min": 0, "max": 1000, "unit": "l_per_min"},
    "speed": {"min": 0, "max": 3000, "unit": "rpm"}
}

deny[msg] {
    input.act == "ot.hmi.setpoint_change"
    bound := safety_bounds[input.con.parameter]
    input.con.value < bound.min
    msg := sprintf("%s value %v below minimum %v %s",
        [input.con.parameter, input.con.value, bound.min, bound.unit])
}
```

## Usage

### Import Templates

```rego
package atb.poa

import data.atb.templates.sap
import data.atb.templates.salesforce
import data.atb.templates.ot

# Combine with base policy
deny[msg] {
    sap.deny[msg]
}

deny[msg] {
    salesforce.deny[msg]
}

deny[msg] {
    ot.deny[msg]
}
```

### Run Template Tests

```bash
# Test all templates
opa test opa/policy/templates/ -v

# Test specific template
opa test opa/policy/templates/sap.rego -v
```

## Customization

Templates are designed to be customized for your environment:

### 1. Adjust Thresholds

```rego
# Override default amounts
payment_limit := 500000  # Lower limit for your org
```

### 2. Add Custom Actions

```rego
# Add org-specific actions
sap_high_risk_actions := sap.sap_high_risk_actions | {
    "sap.custom.sensitive_report"
}
```

### 3. Integrate with SPIFFE

```rego
# Restrict by agent identity
deny[msg] {
    input.act == "sap.payment.execute"
    not startswith(input.spiffe_id, "spiffe://corp.example.com/ns/finance/")
    msg := "Only finance agents can execute payments"
}
```

## Related Documentation

- [OPA Policy](../poa.rego) - Main policy entry point
- [Enterprise Actions](../../docs/enterprise-actions.md) - Complete action catalog
- [Operating Model](../../docs/operating-model.md) - Risk tier definitions
