import argparse
import json
import time
import uuid

import jwt


def main() -> int:
    p = argparse.ArgumentParser(description="Mint a short-lived AAP-001 PoA JWT (dev harness)")
    p.add_argument("--priv", required=True, help="Path to RS256 private key (PEM)")
    p.add_argument("--sub", required=True, help="Subject (agent identity), e.g. spiffe://...")
    p.add_argument("--act", required=True, help="Action scope, e.g. sap.vendor.change")
    p.add_argument("--con", required=True, help="Constraints JSON object")
    p.add_argument("--leg", required=True, help="Legal grounding JSON object")
    p.add_argument("--ttl", type=int, default=300, help="TTL seconds (default 300)")

    args = p.parse_args()

    with open(args.priv, "rb") as f:
        priv = f.read()

    now = int(time.time())
    exp = now + int(args.ttl)

    try:
        con = json.loads(args.con)
        leg = json.loads(args.leg)
    except Exception as e:
        raise SystemExit(f"Invalid JSON for --con/--leg: {e}")

    payload = {
        "sub": args.sub,
        "act": args.act,
        "con": con,
        "leg": leg,
        "iat": now,
        "exp": exp,
        "jti": str(uuid.uuid4()),
    }

    token = jwt.encode(payload, priv, algorithm="RS256")
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
