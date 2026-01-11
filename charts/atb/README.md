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
- TLS:
	- Default (`broker.tls.mode=secret`): a TLS secret is required (defaults to `{{release}}-broker-tls`, containing `tls.crt` and `tls.key`).
	- Secret-less (`broker.tls.mode=spiffe`): no TLS secret is mounted; broker must receive `SPIFFE_ENDPOINT_SOCKET` (typically via CSI driver).
- CSI integration is enabled via `csi.enabled=true` (requires SPIFFE CSI Driver installed).
- This chart is intentionally minimal; tailor NetworkPolicies, PodSecurity, and key management for production.

## Kubernetes quickstart

See [docs/k8s-quickstart.md](../../docs/k8s-quickstart.md) for an end-to-end walkthrough (SPIRE + CSI + Helm + registration).
