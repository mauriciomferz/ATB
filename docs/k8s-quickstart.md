# ATB Kubernetes Quickstart (SPIRE + SPIFFE CSI + Helm)

This guide gets the ATB stack running in Kubernetes with **secret-less broker mTLS** via the SPIFFE Workload API socket.

## Prereqs

- A Kubernetes cluster and `kubectl` access
- `helm`
- SPIRE Server + SPIRE Agent installed in the cluster (trust domain chosen by you)
- A SPIFFE CSI driver installed (so pods can mount the Workload API socket)

Notes:
- The repo includes example SPIRE configs in [spire/README.md](../spire/README.md).
- SPIRE workload registrations are documented in [spire/registration/README.md](../spire/registration/README.md).

## 1) Deploy ATB via Helm

Staging:

- `helm upgrade --install atb-staging ./charts/atb -n atb-staging --create-namespace -f charts/atb/values-staging.yaml -f charts/atb/values-observability.yaml`

Prod:

- `helm upgrade --install atb ./charts/atb -n atb --create-namespace -f charts/atb/values-prod.yaml -f charts/atb/values-observability.yaml`

By default (staging/prod values):
- `broker.tls.mode: spiffe`
- `csi.enabled: true`
- The broker expects `SPIFFE_ENDPOINT_SOCKET=unix:///spire-agent-socket/workload-api.sock`.

If you cannot install SPIRE/CSI yet, you can switch to secret-based TLS:
- Set `broker.tls.mode=secret` and `csi.enabled=false`
- Create a TLS secret in the namespace (defaults to `<release>-broker-tls`):
  - `kubectl -n <namespace> create secret tls <release>-broker-tls --cert tls.crt --key tls.key`

## 2) Create SPIRE registration entries

The Helm chart creates stable ServiceAccounts (in `.Values.namespace`):
- `atb-broker`
- `atb-agentauth`
- `atb-opa`

Create SPIRE entries matching the namespace you deployed into (e.g., `atb` or `atb-staging`).

The exact `parentID` depends on your SPIRE agent identity. A common workflow is:

1) List agents on the SPIRE server and pick the agent(s) responsible for your worker nodes:
- `spire-server agent list`

2) Create entries (examples):

- Broker and AgentAuth: see [spire/registration/README.md](../spire/registration/README.md)

3) Restart the workloads (or wait for rotation) so they pick up their SVIDs:
- `kubectl -n <namespace> rollout restart deploy/<release>-broker`
- `kubectl -n <namespace> rollout restart deploy/<release>-agentauth`

## 3) Optional: provide AgentAuth secrets (recommended for production)

By default, AgentAuth generates an ephemeral Ed25519 signing key at startup (not suitable for production).

Recommended:
- Create a Kubernetes Secret containing the signing key PEM (PKCS8 Ed25519):
  - key name: `ed25519_privkey_pem`

Example:
- `kubectl -n <namespace> create secret generic atb-agentauth-signing-key --from-file=ed25519_privkey_pem=agentauth_ed25519_pkcs8.pem`

Then configure Helm values:

- `agentauth.secrets.signingKey.name: atb-agentauth-signing-key`
- `agentauth.secrets.signingKey.key: ed25519_privkey_pem`

If you want `/v1/approve` to require an approval token:
- Create a secret:
  - `kubectl -n <namespace> create secret generic atb-agentauth-approval --from-literal=approval_shared_secret='<token>'`
- Set:
  - `agentauth.secrets.approvalSharedSecret.name: atb-agentauth-approval`
  - `agentauth.secrets.approvalSharedSecret.key: approval_shared_secret`

## 4) Validate

- `helm test <release> -n <namespace> --timeout 5m`
- Broker readiness endpoint:
  - `kubectl -n <namespace> port-forward svc/<release>-broker 8080:8080`
  - `curl -sSf http://127.0.0.1:8080/ready`

