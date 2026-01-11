#!/usr/bin/env python3
"""
ATB Client Example - Python

This example demonstrates how to:
1. Load SPIFFE client certificates
2. Mint a PoA token
3. Call the ATB broker with mTLS + PoA

Prerequisites:
    pip install requests pyjwt cryptography

Usage:
    python examples/client_python.py
"""

import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import jwt
import requests

# Configuration
BROKER_URL = os.getenv("ATB_BROKER_URL", "https://localhost:8443")
POA_KEY_PATH = os.getenv("POA_KEY_PATH", "dev/poa_rsa.key")
CLIENT_CERT_PATH = os.getenv("CLIENT_CERT_PATH", "dev/certs/client.crt")
CLIENT_KEY_PATH = os.getenv("CLIENT_KEY_PATH", "dev/certs/client.key")
CA_CERT_PATH = os.getenv("CA_CERT_PATH", "dev/certs/ca.crt")

# SPIFFE ID for this agent
AGENT_SPIFFE_ID = "spiffe://example.org/ns/default/sa/agent/connector"


def load_private_key(key_path: str):
    """Load RSA private key for PoA signing."""
    from cryptography.hazmat.primitives import serialization
    
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def mint_poa_token(
    private_key,
    action: str,
    constraints: dict = None,
    legal_basis: dict = None,
    ttl_seconds: int = 300,
) -> str:
    """
    Mint a Proof-of-Authorization (PoA) token.
    
    Args:
        private_key: RSA private key for signing
        action: The action being authorized (e.g., "crm.contact.update")
        constraints: Action-specific constraints
        legal_basis: Legal basis with accountability chain
        ttl_seconds: Token lifetime in seconds (max 300)
    
    Returns:
        Signed JWT token string
    """
    now = datetime.utcnow()
    
    # Default legal basis if not provided
    if legal_basis is None:
        legal_basis = {
            "basis": "contract",
            "jurisdiction": "US",
            "accountable_party": {
                "type": "human",
                "id": "developer@example.com"
            }
        }
    
    claims = {
        "sub": AGENT_SPIFFE_ID,
        "act": action,
        "con": constraints or {},
        "leg": legal_basis,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    
    return jwt.encode(claims, private_key, algorithm="RS256")


def call_broker(
    method: str,
    path: str,
    poa_token: str,
    payload: dict = None,
) -> requests.Response:
    """
    Call the ATB broker with mTLS and PoA token.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        path: Request path
        poa_token: PoA JWT token
        payload: JSON payload for POST/PUT requests
    
    Returns:
        Response object
    """
    url = f"{BROKER_URL}{path}"
    
    headers = {
        "Authorization": f"Bearer {poa_token}",
        "Content-Type": "application/json",
        "X-Request-ID": str(uuid.uuid4()),
    }
    
    # mTLS client certificate
    cert = (CLIENT_CERT_PATH, CLIENT_KEY_PATH)
    
    response = requests.request(
        method=method,
        url=url,
        headers=headers,
        json=payload,
        cert=cert,
        verify=CA_CERT_PATH,
        timeout=30,
    )
    
    return response


def example_low_risk_action():
    """Example: Low-risk action (status check)."""
    print("\n" + "=" * 60)
    print("Example 1: Low-Risk Action (Status Check)")
    print("=" * 60)
    
    private_key = load_private_key(POA_KEY_PATH)
    
    # Mint PoA for status read
    token = mint_poa_token(
        private_key=private_key,
        action="system.status.read",
    )
    
    print(f"Action: system.status.read")
    print(f"Risk Tier: LOW")
    print(f"PoA Token: {token[:50]}...")
    
    try:
        response = call_broker("GET", "/status", token)
        print(f"Response: {response.status_code}")
        print(f"Body: {response.text[:200]}")
    except Exception as e:
        print(f"Error: {e}")


def example_medium_risk_action():
    """Example: Medium-risk action (CRM update with approval)."""
    print("\n" + "=" * 60)
    print("Example 2: Medium-Risk Action (CRM Update)")
    print("=" * 60)
    
    private_key = load_private_key(POA_KEY_PATH)
    
    # Medium-risk actions require approval
    legal_basis = {
        "basis": "contract",
        "jurisdiction": "US",
        "accountable_party": {
            "type": "human",
            "id": "alice@example.com"
        },
        "approval": {
            "approver": "manager@example.com",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    }
    
    token = mint_poa_token(
        private_key=private_key,
        action="crm.contact.update",
        constraints={"contact_id": "C12345"},
        legal_basis=legal_basis,
    )
    
    print(f"Action: crm.contact.update")
    print(f"Risk Tier: MEDIUM")
    print(f"Approval: manager@example.com")
    
    payload = {
        "contact_id": "C12345",
        "email": "newemail@example.com"
    }
    
    try:
        response = call_broker("POST", "/crm/contact", token, payload)
        print(f"Response: {response.status_code}")
        print(f"Body: {response.text[:200]}")
    except Exception as e:
        print(f"Error: {e}")


def example_high_risk_action():
    """Example: High-risk action (payment with dual control)."""
    print("\n" + "=" * 60)
    print("Example 3: High-Risk Action (SAP Payment)")
    print("=" * 60)
    
    private_key = load_private_key(POA_KEY_PATH)
    
    # High-risk actions require dual control
    legal_basis = {
        "basis": "contract",
        "jurisdiction": "US",
        "accountable_party": {
            "type": "human",
            "id": "alice@example.com"
        },
        "dual_control": {
            "approvers": [
                {
                    "id": "approver1@example.com",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                },
                {
                    "id": "approver2@example.com",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            ]
        }
    }
    
    token = mint_poa_token(
        private_key=private_key,
        action="sap.payment.execute",
        constraints={"max_amount": 10000},
        legal_basis=legal_basis,
    )
    
    print(f"Action: sap.payment.execute")
    print(f"Risk Tier: HIGH")
    print(f"Dual Control: approver1@example.com, approver2@example.com")
    
    payload = {
        "vendor_id": "V12345",
        "amount": 5000,
        "currency": "USD"
    }
    
    try:
        response = call_broker("POST", "/sap/payment", token, payload)
        print(f"Response: {response.status_code}")
        print(f"Body: {response.text[:200]}")
    except Exception as e:
        print(f"Error: {e}")


def main():
    print("ATB Client Example - Python")
    print("===========================")
    print(f"Broker URL: {BROKER_URL}")
    print(f"Agent SPIFFE ID: {AGENT_SPIFFE_ID}")
    
    # Check if certificates exist
    for path in [POA_KEY_PATH, CLIENT_CERT_PATH, CLIENT_KEY_PATH, CA_CERT_PATH]:
        if not Path(path).exists():
            print(f"\nError: {path} not found")
            print("Run 'make certs && make certs-poa' to generate certificates")
            sys.exit(1)
    
    example_low_risk_action()
    example_medium_risk_action()
    example_high_risk_action()
    
    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
