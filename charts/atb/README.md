# ATB Helm Chart (skeleton)

This chart deploys:
- Broker (service ports: mTLS + HTTP health/metrics)
- OPA (with the repo policy loaded from `opa/policy/poa.rego`)
- Optional ServiceMonitor (Prometheus Operator)

## Install (staging)
- `helm upgrade --install atb-staging ./charts/atb -n atb-staging --create-namespace -f charts/atb/values-staging.yaml -f charts/atb/values-observability.yaml`

## Install (prod)
- `helm upgrade --install atb ./charts/atb -n atb --create-namespace -f charts/atb/values-prod.yaml -f charts/atb/values-observability.yaml`

## Notes
- TLS secret `{{release}}-broker-tls` is required (contains `tls.crt` and `tls.key`).
- CSI integration is enabled via `csi.enabled=true` (requires SPIFFE CSI Driver installed).
- This chart is intentionally minimal; tailor NetworkPolicies, PodSecurity, and key management for production.
