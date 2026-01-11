# SPIRE registration entries (examples)

These are **example** `spire-server entry create` commands showing how to register ATB workloads based on Kubernetes selectors.

Assumptions:
- Trust domain: `example.org` (replace)
- Node SPIFFE ID(s) are issued to SPIRE agents via the k8s node attestor.

Tip: to find your agent parent IDs, run `spire-server agent list` on the SPIRE server and copy the SPIFFE ID for the agent(s) serving the node(s) where your workloads run.

These examples assume the ATB Helm chart defaults:
- Namespace: `atb` (prod) or `atb-staging` (staging)
- ServiceAccounts: `atb-broker`, `atb-agentauth`, `atb-opa`

## Broker

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/ns/<namespace>/sa/atb-broker \
  -parentID spiffe://example.org/spire/agent/k8s_sat/k8s/<node-or-agent-id> \
  -selector k8s:ns:<namespace> \
  -selector k8s:sa:atb-broker \
  -ttl 600
```

## AgentAuth

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/ns/<namespace>/sa/atb-agentauth \
  -parentID spiffe://example.org/spire/agent/k8s_sat/k8s/<node-or-agent-id> \
  -selector k8s:ns:<namespace> \
  -selector k8s:sa:atb-agentauth \
  -ttl 600
```

## Connector (example)

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/ns/<namespace>/sa/atb-connector-sap \
  -parentID spiffe://example.org/spire/agent/k8s_sat/k8s/<node-or-agent-id> \
  -selector k8s:ns:<namespace> \
  -selector k8s:sa:atb-connector-sap \
  -ttl 600

## OPA (optional)

OPA does not need an SVID for the current ATB skeleton, but you can register it for future mTLS/identity-based authorization.

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/ns/<namespace>/sa/atb-opa \
  -parentID spiffe://example.org/spire/agent/k8s_sat/k8s/<node-or-agent-id> \
  -selector k8s:ns:<namespace> \
  -selector k8s:sa:atb-opa \
  -ttl 600
```
```

## Notes

- `-ttl 600` corresponds to a 10-minute X.509 SVID TTL.
- You can also add selectors like `k8s:pod-label:<key>:<value>` depending on your workload attestor configuration.
- For supply-chain hardening (binary hash / image digest constraints), you can encode additional selectors or use OPA admission controls alongside SPIRE registration.
