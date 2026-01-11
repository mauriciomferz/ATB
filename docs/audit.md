# ATB Audit Events

The gateways emit one JSON audit event per decision (allow/deny/error) to stdout.

Goals:
- Map each tool/API call to a PoA mandate (`poa_jti`) for legal/accountability.
- Correlate traces/logs via `request_id`.
- Keep events structured for ingestion into Splunk/ELK.

## Schema

Canonical JSON Schema: [schemas/audit-event.schema.json](../schemas/audit-event.schema.json)

Required fields:
- `ts` (RFC3339 UTC)
- `agent_identity` (typically a SPIFFE ID)
- `decision` (`allow|deny|error`)
- `reason` (short code)
- `target_service` (upstream target)
- `method`, `path`

Optional fields:
- `request_id`
- `poa_jti`
- `action`
- `constraints`

## Examples

Deny (missing PoA):

```json
{"ts":"2026-01-11T10:20:30Z","request_id":"req-123","agent_identity":"spiffe://example.org/ns/default/sa/agent/connector","decision":"deny","reason":"missing_poa","target_service":"http://upstream:9000","method":"POST","path":"/sap/vendor/change"}
```

Allow:

```json
{"ts":"2026-01-11T10:20:31Z","request_id":"req-124","poa_jti":"a0c7...","agent_identity":"spiffe://example.org/ns/default/sa/agent/connector","action":"sap.vendor.change","constraints":{"amount":1000},"decision":"allow","reason":"policy_allow","target_service":"http://upstream:9000","method":"POST","path":"/sap/vendor/change"}
```
