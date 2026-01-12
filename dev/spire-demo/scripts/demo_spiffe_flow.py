#!/usr/bin/env python3
"""
SPIFFE Identity Flow Demo for ATB

This script demonstrates the complete SPIFFE-based identity flow:
1. Fetch X.509 SVID from SPIRE Workload API
2. Use SVID for mTLS to AgentAuth
3. Get PoA token with SPIFFE identity
4. Call ATB Broker with mTLS + PoA

Requirements:
  pip install py-spiffe requests cryptography pyjwt

Run:
  SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/public/api.sock python3 demo_spiffe_flow.py
"""

import os
import sys
import json
import time
import tempfile
from datetime import datetime, timezone

try:
    from spiffe import SpiffeId, WorkloadApiClient
    from spiffe.svid.x509_svid import X509Svid
    SPIFFE_AVAILABLE = True
except ImportError:
    SPIFFE_AVAILABLE = False
    print("WARNING: py-spiffe not installed. Using simulated mode.")

import requests
import jwt
from cryptography.hazmat.primitives import serialization


def get_spiffe_socket():
    """Get SPIFFE Workload API socket path"""
    socket = os.environ.get("SPIFFE_ENDPOINT_SOCKET", "")
    if not socket:
        socket = "unix:///tmp/spire-agent/public/api.sock"
    return socket


class SpiffeIdentityDemo:
    """Demonstrates SPIFFE identity flow with ATB"""
    
    def __init__(self, broker_url: str, agentauth_url: str):
        self.broker_url = broker_url
        self.agentauth_url = agentauth_url
        self.spiffe_id = None
        self.x509_svid = None
        self.cert_file = None
        self.key_file = None
        
    def fetch_x509_svid(self) -> dict:
        """
        Step 1: Fetch X.509 SVID from SPIRE Workload API
        
        The SVID contains:
        - Certificate chain (with SPIFFE ID in SAN)
        - Private key
        - Trust bundle (CAs)
        """
        print("\n" + "="*60)
        print("STEP 1: Fetching X.509 SVID from SPIRE Workload API")
        print("="*60)
        
        socket_path = get_spiffe_socket()
        print(f"  Workload API socket: {socket_path}")
        
        if SPIFFE_AVAILABLE:
            # Real SPIFFE flow
            client = WorkloadApiClient(socket_path)
            svid = client.fetch_x509_svid()
            
            self.spiffe_id = str(svid.spiffe_id)
            self.x509_svid = svid
            
            # Write cert and key to temp files for requests library
            self.cert_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
            self.key_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
            
            # Write certificate chain
            for cert in svid.cert_chain:
                self.cert_file.write(cert.public_bytes(serialization.Encoding.PEM).decode())
            self.cert_file.close()
            
            # Write private key
            self.key_file.write(svid.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode())
            self.key_file.close()
            
            result = {
                "spiffe_id": self.spiffe_id,
                "cert_file": self.cert_file.name,
                "key_file": self.key_file.name,
                "expires": svid.expiry.isoformat() if hasattr(svid, 'expiry') else "N/A"
            }
        else:
            # Simulated mode using local dev certs
            print("  [SIMULATED] Using local development certificates")
            self.spiffe_id = "spiffe://atb.example.org/agents/demo-agent"
            self.cert_file = type('obj', (object,), {'name': 'dev/certs/client.crt'})()
            self.key_file = type('obj', (object,), {'name': 'dev/certs/client.key'})()
            
            result = {
                "spiffe_id": self.spiffe_id,
                "cert_file": self.cert_file.name,
                "key_file": self.key_file.name,
                "expires": "N/A (simulated)"
            }
        
        print(f"\n  ✓ SPIFFE ID: {result['spiffe_id']}")
        print(f"  ✓ Certificate: {result['cert_file']}")
        print(f"  ✓ Private Key: {result['key_file']}")
        print(f"  ✓ Expires: {result['expires']}")
        
        return result
    
    def request_poa_token(self, action: str, constraints: dict = None) -> dict:
        """
        Step 2: Request PoA token from AgentAuth using mTLS
        
        The SPIFFE ID from the client certificate becomes the 'sub' claim
        in the PoA token.
        """
        print("\n" + "="*60)
        print("STEP 2: Requesting PoA Token from AgentAuth")
        print("="*60)
        
        print(f"  Action: {action}")
        print(f"  Constraints: {json.dumps(constraints or {})}")
        print(f"  Using mTLS with SPIFFE certificate")
        
        payload = {
            "action": action,
            "constraints": constraints or {},
            "legal_basis": {
                "type": "legitimate_interest",
                "accountable_party": "demo@example.com"
            }
        }
        
        try:
            resp = requests.post(
                f"{self.agentauth_url}/authorize",
                json=payload,
                cert=(self.cert_file.name, self.key_file.name),
                verify=False,  # In production, verify against trust bundle
                timeout=10
            )
            
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("token", "")
                
                # Decode token to show claims (without verification for display)
                claims = jwt.decode(token, options={"verify_signature": False})
                
                print(f"\n  ✓ PoA Token received!")
                print(f"  ✓ Token subject (from SPIFFE): {claims.get('sub')}")
                print(f"  ✓ Action: {claims.get('act')}")
                print(f"  ✓ Expires: {datetime.fromtimestamp(claims.get('exp', 0), tz=timezone.utc).isoformat()}")
                print(f"  ✓ Token ID (jti): {claims.get('jti', 'N/A')[:16]}...")
                
                return {"token": token, "claims": claims}
            else:
                print(f"\n  ✗ Error: {resp.status_code}")
                print(f"    {resp.text}")
                return {"error": resp.text}
                
        except requests.exceptions.ConnectionError as e:
            print(f"\n  ✗ Connection error: {e}")
            print("    Make sure the SPIRE demo is running: make spire-demo-up")
            return {"error": str(e)}
    
    def call_broker(self, poa_token: str, method: str, path: str) -> dict:
        """
        Step 3: Call ATB Broker with mTLS + PoA token
        
        The broker validates:
        1. mTLS client certificate (SPIFFE identity)
        2. PoA token signature
        3. PoA token subject matches certificate SPIFFE ID
        4. OPA policy allows the action
        """
        print("\n" + "="*60)
        print("STEP 3: Calling ATB Broker with mTLS + PoA")
        print("="*60)
        
        print(f"  Method: {method}")
        print(f"  Path: {path}")
        print(f"  mTLS: Using SPIFFE certificate")
        print(f"  PoA: {poa_token[:50]}...")
        
        try:
            headers = {"X-Poa-Token": poa_token}
            
            resp = requests.request(
                method,
                f"{self.broker_url}{path}",
                headers=headers,
                cert=(self.cert_file.name, self.key_file.name),
                verify=False,  # In production, verify against trust bundle
                timeout=10
            )
            
            print(f"\n  Response Status: {resp.status_code}")
            
            if resp.status_code == 200:
                print(f"  ✓ Request ALLOWED by ATB")
                try:
                    data = resp.json()
                    print(f"  ✓ Response: {json.dumps(data, indent=4)[:200]}...")
                except:
                    print(f"  ✓ Response: {resp.text[:200]}...")
                return {"status": "allowed", "response": resp.text}
            else:
                print(f"  ✗ Request DENIED by ATB")
                print(f"  ✗ Reason: {resp.text}")
                return {"status": "denied", "reason": resp.text}
                
        except requests.exceptions.ConnectionError as e:
            print(f"\n  ✗ Connection error: {e}")
            return {"error": str(e)}
    
    def cleanup(self):
        """Clean up temporary files"""
        if SPIFFE_AVAILABLE:
            if self.cert_file and hasattr(self.cert_file, 'name'):
                try:
                    os.unlink(self.cert_file.name)
                except:
                    pass
            if self.key_file and hasattr(self.key_file, 'name'):
                try:
                    os.unlink(self.key_file.name)
                except:
                    pass


def demo_low_risk_action(demo: SpiffeIdentityDemo):
    """Demo: Low-risk action (no approval needed)"""
    print("\n" + "#"*60)
    print("# DEMO: Low-Risk Action (system.status.read)")
    print("#"*60)
    
    result = demo.request_poa_token("system.status.read", {})
    if "token" in result:
        demo.call_broker(result["token"], "GET", "/system/status")


def demo_medium_risk_action(demo: SpiffeIdentityDemo):
    """Demo: Medium-risk action (single approver needed in production)"""
    print("\n" + "#"*60)
    print("# DEMO: Medium-Risk Action (crm.contact.update)")
    print("#"*60)
    
    result = demo.request_poa_token(
        "crm.contact.update",
        {"contact_id": "C-12345", "fields": ["email", "phone"]}
    )
    if "token" in result:
        demo.call_broker(result["token"], "POST", "/crm/contacts/C-12345")


def demo_high_risk_action(demo: SpiffeIdentityDemo):
    """Demo: High-risk action (dual control needed in production)"""
    print("\n" + "#"*60)
    print("# DEMO: High-Risk Action (sap.payment.execute)")
    print("#"*60)
    
    result = demo.request_poa_token(
        "sap.payment.execute",
        {"amount": 50000, "currency": "USD", "vendor_id": "V-999"}
    )
    if "token" in result:
        demo.call_broker(result["token"], "POST", "/sap/payments/execute")


def main():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║            ATB + SPIFFE Identity Flow Demonstration              ║
║                                                                  ║
║  This demo shows how AI agents use SPIFFE workload identity      ║
║  for zero-trust authentication and authorization with ATB.       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    broker_url = os.environ.get("ATB_BROKER_URL", "https://localhost:8443")
    agentauth_url = os.environ.get("ATB_AGENTAUTH_URL", "https://localhost:8444")
    
    print(f"Configuration:")
    print(f"  ATB Broker: {broker_url}")
    print(f"  ATB AgentAuth: {agentauth_url}")
    print(f"  SPIFFE Socket: {get_spiffe_socket()}")
    print(f"  py-spiffe available: {SPIFFE_AVAILABLE}")
    
    demo = SpiffeIdentityDemo(broker_url, agentauth_url)
    
    try:
        # Step 1: Fetch SPIFFE identity
        demo.fetch_x509_svid()
        
        # Step 2 & 3: Request PoA and call broker for different risk tiers
        demo_low_risk_action(demo)
        demo_medium_risk_action(demo)
        demo_high_risk_action(demo)
        
        print("\n" + "="*60)
        print("DEMO COMPLETE")
        print("="*60)
        print("""
Summary:
  1. X.509 SVID fetched from SPIRE Workload API
  2. SVID used for mTLS authentication to AgentAuth
  3. PoA tokens include SPIFFE ID as subject claim
  4. Broker validates mTLS + PoA for every request
  
Key Points:
  - No long-lived secrets in containers
  - Certificates auto-rotate every 10 minutes
  - Identity is cryptographically proven
  - Every action is authorized and audited
        """)
        
    finally:
        demo.cleanup()


if __name__ == "__main__":
    main()
