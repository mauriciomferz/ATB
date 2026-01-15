"""
Security Tests for ATB

Tests for security edge cases and attack vectors:
- Token replay attacks
- SPIFFE ID spoofing
- Expired tokens
- Invalid signatures
- Privilege escalation attempts

Prerequisites:
- ATB services running
"""

import os
import pytest
import httpx
import jwt
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any


AGENTAUTH_URL = os.environ.get("ATB_AGENTAUTH_URL", "http://localhost:8444")
OPA_URL = os.environ.get("ATB_OPA_URL", "http://localhost:8181")


class TestTokenSecurity:
    """Test token security properties."""

    async def _get_valid_token(self, client: httpx.AsyncClient) -> str:
        """Helper to get a valid PoA token."""
        # Create challenge
        create_resp = await client.post(
            f"{AGENTAUTH_URL}/v1/challenge",
            json={
                "agent_spiffe_id": "spiffe://example.org/agent/test",
                "act": "crm.contact.read",
                "con": {},
                "leg": {
                    "basis": "contract",
                    "jurisdiction": "US",
                    "accountable_party": {"type": "human", "id": "user@example.com"}
                }
            },
            timeout=5.0
        )
        challenge_id = create_resp.json()["challenge_id"]
        
        # Approve
        await client.post(
            f"{AGENTAUTH_URL}/v1/approve",
            json={"challenge_id": challenge_id, "approver": "approver@example.com"},
            timeout=5.0
        )
        
        # Get token
        mandate_resp = await client.post(
            f"{AGENTAUTH_URL}/v1/mandate",
            json={"challenge_id": challenge_id},
            timeout=5.0
        )
        return mandate_resp.json()["token"]

    @pytest.mark.asyncio
    async def test_token_has_unique_jti(self):
        """Each token should have a unique JTI."""
        async with httpx.AsyncClient() as client:
            try:
                token1 = await self._get_valid_token(client)
                token2 = await self._get_valid_token(client)
                
                claims1 = jwt.decode(token1, options={"verify_signature": False})
                claims2 = jwt.decode(token2, options={"verify_signature": False})
                
                assert claims1["jti"] != claims2["jti"]
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_token_has_reasonable_expiry(self):
        """Token expiry should be within reasonable bounds."""
        async with httpx.AsyncClient() as client:
            try:
                token = await self._get_valid_token(client)
                claims = jwt.decode(token, options={"verify_signature": False})
                
                now = int(time.time())
                ttl = claims["exp"] - claims["iat"]
                
                # TTL should be positive and less than 15 minutes (900 seconds)
                assert ttl > 0
                assert ttl <= 900
                
                # Token should not be expired
                assert claims["exp"] > now
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_token_contains_required_claims(self):
        """Token should contain all required claims."""
        async with httpx.AsyncClient() as client:
            try:
                token = await self._get_valid_token(client)
                claims = jwt.decode(token, options={"verify_signature": False})
                
                required_claims = ["act", "con", "leg", "iss", "sub", "exp", "iat", "jti"]
                for claim in required_claims:
                    assert claim in claims, f"Missing required claim: {claim}"
                    
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_token_uses_ed25519_signature(self):
        """Token should use EdDSA (Ed25519) signature."""
        async with httpx.AsyncClient() as client:
            try:
                token = await self._get_valid_token(client)
                
                # Decode header
                header = jwt.get_unverified_header(token)
                
                assert header["alg"] == "EdDSA"
                assert header["typ"] == "JWT"
                assert "kid" in header
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


class TestInputValidation:
    """Test input validation and sanitization."""

    @pytest.mark.asyncio
    async def test_empty_request_body_rejected(self):
        """Empty request body should be rejected."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    content="",
                    headers={"Content-Type": "application/json"},
                    timeout=5.0
                )
                assert response.status_code == 400
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_malformed_json_rejected(self):
        """Malformed JSON should be rejected."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    content="{invalid json",
                    headers={"Content-Type": "application/json"},
                    timeout=5.0
                )
                assert response.status_code == 400
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_spiffe_id_injection_prevented(self):
        """SPIFFE ID injection attempts should be prevented."""
        async with httpx.AsyncClient() as client:
            try:
                # Attempt injection in SPIFFE ID
                malicious_ids = [
                    "spiffe://example.org/../admin",
                    "spiffe://example.org/agent/test; DROP TABLE users",
                    "spiffe://example.org/agent/<script>alert(1)</script>",
                    "spiffe://",
                    "",
                    "not-a-spiffe-id",
                ]
                
                for malicious_id in malicious_ids:
                    response = await client.post(
                        f"{AGENTAUTH_URL}/v1/challenge",
                        json={
                            "agent_spiffe_id": malicious_id,
                            "act": "crm.contact.read",
                            "con": {},
                            "leg": {"basis": "contract"}
                        },
                        timeout=5.0
                    )
                    # Should either reject or sanitize
                    assert response.status_code in [400, 422], f"Failed for: {malicious_id}"
                    
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_oversized_request_handled(self):
        """Oversized requests should be handled gracefully."""
        async with httpx.AsyncClient() as client:
            try:
                # Create a large constraints object
                large_con = {"data": "x" * 100000}  # 100KB of data
                
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json={
                        "agent_spiffe_id": "spiffe://example.org/agent/test",
                        "act": "crm.contact.read",
                        "con": large_con,
                        "leg": {"basis": "contract"}
                    },
                    timeout=10.0
                )
                # Should either accept or reject with appropriate status
                assert response.status_code in [200, 400, 413, 422]
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


class TestRateLimiting:
    """Test rate limiting and abuse prevention."""

    @pytest.mark.asyncio
    async def test_rapid_challenge_creation(self):
        """Rapid challenge creation should not cause issues."""
        async with httpx.AsyncClient() as client:
            try:
                # Create many challenges rapidly
                responses = []
                for i in range(10):
                    response = await client.post(
                        f"{AGENTAUTH_URL}/v1/challenge",
                        json={
                            "agent_spiffe_id": f"spiffe://example.org/agent/test-{i}",
                            "act": "crm.contact.read",
                            "con": {"request_num": i},
                            "leg": {
                                "basis": "contract",
                                "jurisdiction": "US",
                                "accountable_party": {"type": "human", "id": "user@example.com"}
                            }
                        },
                        timeout=5.0
                    )
                    responses.append(response)
                
                # Most should succeed (rate limiting may kick in)
                success_count = sum(1 for r in responses if r.status_code == 200)
                assert success_count >= 5, "Too many requests failed"
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


class TestOPAPolicySecurity:
    """Test OPA policy security decisions."""

    @pytest.mark.asyncio
    async def test_policy_denies_expired_token(self):
        """Policy should deny requests with expired tokens."""
        async with httpx.AsyncClient() as client:
            try:
                past_time = int(datetime.now(timezone.utc).timestamp()) - 3600
                input_data = {
                    "input": {
                        "agent": {"spiffe_id": "spiffe://example.org/agent/test"},
                        "poa": {
                            "sub": "spiffe://example.org/agent/test",
                            "act": "crm.contact.read",
                            "con": {},
                            "leg": {"basis": "contract"},
                            "iat": past_time - 300,
                            "exp": past_time,  # Expired
                            "jti": "expired-token-001"
                        },
                        "request": {"method": "GET", "path": "/test"},
                        "policy": {"max_ttl_seconds": 300}
                    }
                }
                
                response = await client.post(
                    f"{OPA_URL}/v1/data/atb/poa/decision",
                    json=input_data,
                    timeout=5.0
                )
                
                assert response.status_code == 200
                result = response.json()
                
                # Should be denied
                if "result" in result and "allow" in result["result"]:
                    assert result["result"]["allow"] == False
                    
            except httpx.ConnectError:
                pytest.skip("OPA not running")

    @pytest.mark.asyncio
    async def test_policy_denies_spiffe_mismatch(self):
        """Policy should deny when agent SPIFFE doesn't match token subject."""
        async with httpx.AsyncClient() as client:
            try:
                now = int(datetime.now(timezone.utc).timestamp())
                input_data = {
                    "input": {
                        "agent": {"spiffe_id": "spiffe://example.org/agent/attacker"},
                        "poa": {
                            "sub": "spiffe://example.org/agent/victim",  # Different!
                            "act": "crm.contact.read",
                            "con": {},
                            "leg": {
                                "basis": "contract",
                                "accountable_party": {"type": "human", "id": "user@example.com"},
                                "approval": {"approver_id": "mgr", "approved_at": "2024-01-01T00:00:00Z"}
                            },
                            "iat": now,
                            "exp": now + 300,
                            "jti": "mismatch-token-001"
                        },
                        "request": {"method": "GET", "path": "/test"},
                        "policy": {"max_ttl_seconds": 300}
                    }
                }
                
                response = await client.post(
                    f"{OPA_URL}/v1/data/atb/poa/decision",
                    json=input_data,
                    timeout=5.0
                )
                
                assert response.status_code == 200
                result = response.json()
                
                # Should be denied
                if "result" in result and "allow" in result["result"]:
                    assert result["result"]["allow"] == False
                    
            except httpx.ConnectError:
                pytest.skip("OPA not running")


class TestChallengeExpiry:
    """Test challenge expiration handling."""

    @pytest.mark.asyncio
    async def test_challenge_has_expiry(self):
        """Challenges should have an expiry time."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json={
                        "agent_spiffe_id": "spiffe://example.org/agent/test",
                        "act": "crm.contact.read",
                        "con": {},
                        "leg": {
                            "basis": "contract",
                            "jurisdiction": "US",
                            "accountable_party": {"type": "human", "id": "user@example.com"}
                        }
                    },
                    timeout=5.0
                )
                
                assert response.status_code == 200
                data = response.json()
                
                assert "expires_at" in data
                
                # Parse expiry time
                from datetime import datetime
                expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                
                # Should expire within reasonable time (5 minutes)
                time_until_expiry = (expires_at - now).total_seconds()
                assert 0 < time_until_expiry <= 300
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
