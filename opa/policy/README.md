# OPA Policy (AAP-001 PoA validation)

- Policy file: `poa.rego`
- Data path used by skeletons: `data.atb.poa.decision`

## Run locally
- `opa run --server poa.rego`

## Notes
- This policy assumes the gateway already verified JWT signature and passed structured claims.
- The policy enforces:
  - required AAP-001 fields
  - max TTL (default 300s, hard cap 900s)
  - `sub` matches authenticated SPIFFE ID
  - action-specific constraints for the three pilot actions
