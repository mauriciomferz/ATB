# SPIRE configuration (examples)

This folder contains **example** SPIRE Server/Agent configuration for a Kubernetes deployment supporting the ATB trust domain.

These files are meant as a starting point:
- You still need to supply cluster-specific settings (service accounts, namespaces, bundle distribution, etc.).
- Registration entries must be created for workloads (Broker, Connectors, AgentAuth) so they receive X.509 SVIDs.

## Files

- [spire/server/server.conf](server/server.conf): SPIRE Server config (trust domain, datastore, k8s node/workload attestation).
- [spire/agent/agent.conf](agent/agent.conf): SPIRE Agent config (k8s node attestation, Workload API socket).
- [spire/registration/README.md](registration/README.md): Example `spire-server entry create` commands for ATB services.

## Intended identity model

- Trust domain: `example.org` (replace with your enterprise trust domain).
- SPIFFE IDs (recommended pattern):
  - Broker: `spiffe://<td>/ns/<namespace>/sa/atb-broker`
  - AgentAuth: `spiffe://<td>/ns/<namespace>/sa/atb-agentauth`
  - OPA (optional): `spiffe://<td>/ns/<namespace>/sa/atb-opa`
  - Connector(s): `spiffe://<td>/ns/<namespace>/sa/<connector-sa>`

Where `<namespace>` should match the Helm chart value `namespace` (e.g., `atb` or `atb-staging`).

## Helm + SPIFFE CSI driver integration

The ATB Helm chart supports secret-less mTLS for the broker via the SPIFFE Workload API socket.

1) Install a SPIFFE CSI driver (example: `csi.spiffe.io`) and run SPIRE Agent with Workload API enabled.

2) Enable the socket mount and SPIFFE TLS mode in your values:

- In staging/prod, we default to:
  - `csi.enabled: true`
  - `broker.tls.mode: spiffe`

3) The chart mounts the Workload API socket and sets:

- `SPIFFE_ENDPOINT_SOCKET=unix://<mountPath>/<socketFile>`

Defaults:
- `mountPath=/spire-agent-socket`
- `socketFile=workload-api.sock`

## ServiceAccounts (for k8s selectors)

The chart creates stable ServiceAccounts by default (in `.Values.namespace`):
- `atb-broker`
- `atb-agentauth`
- `atb-opa`

These are intended to be used as SPIRE workload selectors (`k8s:ns`, `k8s:sa`).

## Operational notes

- Prefer short-lived X.509 SVIDs (e.g., 10 minutes) and rely on automatic rotation.
- Use k8s selectors (`k8s:ns`, `k8s:sa`) for workload attestation.
- Avoid embedding long-lived private keys in app containers; use the Workload API socket.
