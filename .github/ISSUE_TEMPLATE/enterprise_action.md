---
name: New Enterprise Action
about: Request a new enterprise action to be added to OPA policy
title: '[ACTION] '
labels: ['enterprise-action', 'policy']
assignees: ''
---

## Action Details

**Action Name**: `<system>.<domain>.<operation>`
<!-- Example: salesforce.opportunity.update -->

**System**: 
<!-- The enterprise system (e.g., SAP, Salesforce, ServiceNow) -->

**Description**:
<!-- What this action does -->

## Risk Classification

**Proposed Risk Tier**:
- [ ] **Low** - Read-only, no PII, no financial data
- [ ] **Medium** - Data mutations, limited scope, non-bulk
- [ ] **High** - Bulk data, PII, financial > $10k, privileged access, OT/SCADA

**Justification**:
<!-- Why this risk tier is appropriate -->

## Constraints

**Required Constraints** (`con` claim):
<!-- List any constraints that should be enforced -->
| Constraint | Type | Description |
|------------|------|-------------|
| | | |

**Example Constraint**:
```json
{
  "dual_control": true,
  "liability_cap": 10000,
  "dataset_allowlist": ["accounts"]
}
```

## Legal Basis

**Typical Legal Basis** (`leg` claim):
<!-- What legal/regulatory basis would authorize this action -->
- Jurisdiction: 
- Basis: (contract, legitimate_interest, legal_obligation, consent)

## Approval Requirements

- [ ] Single approver sufficient
- [ ] Dual control required (two distinct approvers)
- [ ] Additional approval workflow needed

## Security Considerations
<!-- Any security implications of this action -->

## Testing

**Test Scenarios**:
1. 
2. 
3. 

## Checklist
- [ ] Action follows naming convention (`<system>.<domain>.<operation>`)
- [ ] Risk tier is appropriate and justified
- [ ] Constraints are well-defined
- [ ] Test cases provided
