# ATB Broker Gateway (Python) — Skeleton

This is a FastAPI-based Policy Enforcement Point (PEP) skeleton.

## Run (dev)

- `python -m venv .venv && source .venv/bin/activate`
- `pip install -r requirements.txt`
- `uvicorn app.main:app --host 0.0.0.0 --port 8080`

## Required env vars

- `POA_VERIFY_PUBKEY_PEM`: PEM public key for RS256 or EdDSA
- Optional: `OPA_DECISION_URL` (default `http://localhost:8181/v1/data/atb/poa/decision`)
- Optional: `UPSTREAM_URL` (default `http://localhost:9000`, used as the proxy upstream)
- Optional: `POA_MAX_TTL_SECONDS` (default `300`, hard cap `900`)
- Optional: `ALLOW_UNMANDATED_LOW_RISK` (default `false`) — if `true`, the gateway may allow low-risk requests without a PoA when OPA permits.

## Request headers (dev)

- `X-SPIFFE-ID: spiffe://...`
- `Authorization: Bearer <poa-jwt>`
- Optional: `X-ATB-Action: <action-name>` (or `X-Action`) — lets policy validate the intended action and cross-check it against PoA `act`.

Notes:

- This skeleton does not implement full mTLS termination in Python; production setups should rely on SPIRE/service-mesh mTLS and propagate authenticated identities over a trusted channel.
