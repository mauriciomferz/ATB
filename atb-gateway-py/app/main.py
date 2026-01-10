import json
import os
import time
from typing import Any, Dict, Optional, Tuple

import jwt
import requests
from fastapi import FastAPI, Header, HTTPException, Request

app = FastAPI(title="ATB Broker Gateway (Python) - Skeleton")

UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://localhost:9000")
OPA_DECISION_URL = os.environ.get("OPA_DECISION_URL", "http://localhost:8181/v1/data/atb/poa/decision")
POA_VERIFY_PUBKEY_PEM = os.environ.get("POA_VERIFY_PUBKEY_PEM", "")
POA_MAX_TTL_SECONDS = int(os.environ.get("POA_MAX_TTL_SECONDS", "300"))


def audit(event: Dict[str, Any]) -> None:
    print(json.dumps(event, separators=(",", ":")))


def extract_agent_spiffe_id(
    x_spiffe_id: Optional[str],
) -> str:
    # In a full SPIFFE/SPIRE deployment, you typically terminate mTLS at a sidecar/mesh and
    # pass the authenticated SPIFFE ID via a trusted channel. For this skeleton, accept a header.
    if not x_spiffe_id:
        raise HTTPException(status_code=401, detail="Missing SPIFFE identity")
    if not x_spiffe_id.startswith("spiffe://"):
        raise HTTPException(status_code=401, detail="Invalid SPIFFE identity")
    return x_spiffe_id


def verify_poa_jwt(token: str) -> Dict[str, Any]:
    if not POA_VERIFY_PUBKEY_PEM.strip():
        raise HTTPException(status_code=500, detail="POA_VERIFY_PUBKEY_PEM not configured")

    # Accept RS256/EdDSA (supply the matching public key in PEM).
    try:
        claims = jwt.decode(
            token,
            POA_VERIFY_PUBKEY_PEM,
            algorithms=["RS256", "EdDSA"],
            options={"require": ["sub", "exp", "iat", "jti", "act", "con", "leg"]},
            leeway=10,
        )
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"Invalid PoA: {e}")

    ttl = int(claims["exp"]) - int(claims["iat"])
    if ttl <= 0 or ttl > 900:
        raise HTTPException(status_code=403, detail="PoA TTL exceeds 15-minute hard cap")
    if ttl > POA_MAX_TTL_SECONDS:
        raise HTTPException(status_code=403, detail=f"PoA TTL exceeds configured max ({POA_MAX_TTL_SECONDS}s)")
    if int(time.time()) > int(claims["exp"]):
        raise HTTPException(status_code=403, detail="PoA expired")

    return claims


def semantic_guardrails(params: Dict[str, Any]) -> Tuple[bool, str]:
    # Placeholder for NeMo Guardrails integration.
    markers = ["ignore previous", "disable safety", "exfiltrate", "curl http", "drop table"]
    for v in params.values():
        if isinstance(v, str):
            low = v.lower()
            if any(m in low for m in markers):
                return False, "semantic_firewall_block"
    return True, ""


def opa_decide(payload: Dict[str, Any]) -> Tuple[bool, str]:
    r = requests.post(OPA_DECISION_URL, json={"input": payload}, timeout=1.5)
    if r.status_code // 100 != 2:
        raise HTTPException(status_code=500, detail=f"OPA error: {r.status_code} {r.text}")
    data = r.json().get("result")
    if isinstance(data, bool):
        return data, ""
    if isinstance(data, dict):
        return bool(data.get("allow", False)), str(data.get("reason", ""))
    raise HTTPException(status_code=500, detail="OPA returned unexpected result")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def broker(
    request: Request,
    path: str,
    authorization: Optional[str] = Header(default=None),
    x_poa_token: Optional[str] = Header(default=None),
    x_request_id: Optional[str] = Header(default=None),
    x_spiffe_id: Optional[str] = Header(default=None),
):
    start = int(time.time())
    agent_spiffe = extract_agent_spiffe_id(x_spiffe_id)

    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    if not token and x_poa_token:
        token = x_poa_token.strip()
    if not token:
        audit({"ts": start, "request_id": x_request_id, "agent_identity": agent_spiffe, "decision": "deny", "reason": "missing_poa"})
        raise HTTPException(status_code=401, detail="Missing PoA")

    claims = verify_poa_jwt(token)
    if claims.get("sub") != agent_spiffe:
        audit({"ts": start, "request_id": x_request_id, "poa_jti": claims.get("jti"), "agent_identity": agent_spiffe, "decision": "deny", "reason": "sub_mismatch"})
        raise HTTPException(status_code=403, detail="PoA subject mismatch")

    body = await request.body()
    params: Dict[str, Any] = {}
    if body:
        try:
            params = json.loads(body.decode("utf-8"))
        except Exception:
            params = {}

    ok, why = semantic_guardrails(params)
    if not ok:
        audit({"ts": start, "request_id": x_request_id, "poa_jti": claims.get("jti"), "agent_identity": agent_spiffe, "action": claims.get("act"), "decision": "deny", "reason": why})
        raise HTTPException(status_code=403, detail="Blocked by semantic firewall")

    opa_input = {
        "agent": {"spiffe_id": agent_spiffe},
        "poa": {
            "sub": claims.get("sub"),
            "act": claims.get("act"),
            "con": claims.get("con"),
            "leg": claims.get("leg"),
            "iat": claims.get("iat"),
            "exp": claims.get("exp"),
            "jti": claims.get("jti"),
        },
        "request": {"method": request.method, "path": "/" + path, "params": params},
        "policy": {"max_ttl_seconds": POA_MAX_TTL_SECONDS},
    }

    allow, reason = opa_decide(opa_input)
    if not allow:
        audit({"ts": start, "request_id": x_request_id, "poa_jti": claims.get("jti"), "agent_identity": agent_spiffe, "action": claims.get("act"), "decision": "deny", "reason": reason or "policy_denied"})
        raise HTTPException(status_code=403, detail="Policy denied")

    audit({"ts": start, "request_id": x_request_id, "poa_jti": claims.get("jti"), "agent_identity": agent_spiffe, "action": claims.get("act"), "decision": "allow", "reason": "policy_allow"})

    # Minimal proxy: forward request to upstream. Production should enforce strict egress allowlists,
    # timeouts, and per-connector request shaping.
    upstream_url = UPSTREAM_URL.rstrip("/") + "/" + path
    headers = dict(request.headers)
    # Strip authn/authz headers that must not be forwarded.
    headers.pop("authorization", None)
    headers.pop("x-poa-token", None)
    headers.pop("x-spiffe-id", None)
    if x_request_id:
        headers["x-request-id"] = x_request_id

    try:
        r = requests.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            data=body,
            timeout=5.0,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Upstream error: {e}")

    # Pass-through status and body. (Headers can be selectively forwarded as needed.)
    return {"upstream_status": r.status_code, "upstream_body": r.text}
