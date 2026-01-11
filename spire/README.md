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
- SPIFFE IDs:
  - Broker: `spiffe://<td>/ns/atb/sa/atb-broker`
  - AgentAuth: `spiffe://<td>/ns/atb/sa/atb-agentauth`
  - Connector(s): `spiffe://<td>/ns/atb/sa/<connector-sa>`

## Operational notes

- Prefer short-lived X.509 SVIDs (e.g., 10 minutes) and rely on automatic rotation.
- Use k8s selectors (`k8s:ns`, `k8s:sa`) for workload attestation.
- Avoid embedding long-lived private keys in app containers; use the Workload API socket.
