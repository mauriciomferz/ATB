"""
End-to-End Tests for AgentAuth Challenge/Approve/Mandate Flow

Tests the complete PoA token issuance workflow:
1. Create challenge
2. Approve challenge
3. Get mandate (PoA token)
4. Verify token structure

Prerequisites:
- AgentAuth container running on port 8444
"""

import os
import pytest
import httpx
import jwt
from datetime import datetime, timezone
from typing import Dict, Any


# Test configuration
AGENTAUTH_URL = os.environ.get("ATB_AGENTAUTH_URL", "http://localhost:8444")


class TestAgentAuthHealth:
    """Test AgentAuth health and discovery endpoints."""

    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        """Health endpoint should return 'ok'."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{AGENTAUTH_URL}/health", timeout=5.0)
                assert response.status_code == 200
                assert response.text.strip() == "ok"
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_ready_endpoint(self):
        """Ready endpoint should return 'ok'."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{AGENTAUTH_URL}/ready", timeout=5.0)
                assert response.status_code == 200
                assert response.text.strip() == "ok"
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_jwks_endpoint(self):
        """JWKS endpoint should return valid key set."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{AGENTAUTH_URL}/.well-known/jwks.json",
                    timeout=5.0
                )
                assert response.status_code == 200
                data = response.json()
                
                assert "keys" in data
                assert len(data["keys"]) > 0
                
                key = data["keys"][0]
                assert key["kty"] == "OKP"
                assert key["crv"] == "Ed25519"
                assert key["alg"] == "EdDSA"
                assert "kid" in key
                assert "x" in key
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


class TestChallengeCreation:
    """Test challenge creation endpoint."""

    @pytest.mark.asyncio
    async def test_create_challenge_success(self):
        """Should create challenge with valid request."""
        async with httpx.AsyncClient() as client:
            try:
                request_data = {
                    "agent_spiffe_id": "spiffe://example.org/agent/test",
                    "act": "crm.contact.read",
                    "con": {"contact_id": "C-12345"},
                    "leg": {
                        "basis": "contract",
                        "jurisdiction": "US",
                        "accountable_party": {
                            "type": "human",
                            "id": "test@example.com"
                        }
                    }
                }
                
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json=request_data,
                    timeout=5.0
                )
                
                assert response.status_code == 200
                data = response.json()
                
                assert "challenge_id" in data
                assert data["challenge_id"].startswith("chal_")
                assert "expires_at" in data
                assert "requires_dual_control" in data
                assert "approvers_needed" in data
                assert data["approvers_needed"] >= 1
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_create_challenge_missing_spiffe_id(self):
        """Should reject challenge without SPIFFE ID."""
        async with httpx.AsyncClient() as client:
            try:
                request_data = {
                    "act": "crm.contact.read",
                    "con": {},
                    "leg": {"basis": "contract"}
                }
                
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json=request_data,
                    timeout=5.0
                )
                
                assert response.status_code == 400
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_create_challenge_invalid_spiffe_id(self):
        """Should reject challenge with invalid SPIFFE ID format."""
        async with httpx.AsyncClient() as client:
            try:
                request_data = {
                    "agent_spiffe_id": "not-a-valid-spiffe-id",
                    "act": "crm.contact.read",
                    "con": {},
                    "leg": {"basis": "contract"}
                }
                
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json=request_data,
                    timeout=5.0
                )
                
                assert response.status_code == 400
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_create_challenge_missing_action(self):
        """Should reject challenge without action."""
        async with httpx.AsyncClient() as client:
            try:
                request_data = {
                    "agent_spiffe_id": "spiffe://example.org/agent/test",
                    "con": {},
                    "leg": {"basis": "contract"}
                }
                
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json=request_data,
                    timeout=5.0
                )
                
                assert response.status_code == 400
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_create_challenge_high_risk_action(self):
        """High-risk actions should require dual control."""
        async with httpx.AsyncClient() as client:
            try:
                request_data = {
                    "agent_spiffe_id": "spiffe://example.org/agent/test",
                    "act": "sap.vendor.change",  # High-risk action
                    "con": {"vendor_id": "V-12345"},
                    "leg": {
                        "basis": "contract",
                        "jurisdiction": "US",
                        "accountable_party": {"type": "human", "id": "admin@example.com"}
                    }
                }
                
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json=request_data,
                    timeout=5.0
                )
                
                assert response.status_code == 200
                data = response.json()
                
                assert data["requires_dual_control"] == True
                assert data["approvers_needed"] == 2
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


class TestChallengeApproval:
    """Test challenge approval endpoint."""

    async def _create_challenge(self, client: httpx.AsyncClient, action: str = "crm.contact.read") -> str:
        """Helper to create a challenge and return its ID."""
        request_data = {
            "agent_spiffe_id": "spiffe://example.org/agent/test",
            "act": action,
            "con": {},
            "leg": {
                "basis": "contract",
                "jurisdiction": "US",
                "accountable_party": {"type": "human", "id": "user@example.com"}
            }
        }
        response = await client.post(
            f"{AGENTAUTH_URL}/v1/challenge",
            json=request_data,
            timeout=5.0
        )
        return response.json()["challenge_id"]

    @pytest.mark.asyncio
    async def test_approve_challenge_success(self):
        """Should approve challenge with valid request."""
        async with httpx.AsyncClient() as client:
            try:
                # Create challenge first
                challenge_id = await self._create_challenge(client)
                
                # Approve it
                approve_data = {
                    "challenge_id": challenge_id,
                    "approver": "approver@example.com"
                }
                
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json=approve_data,
                    timeout=5.0
                )
                
                assert response.status_code == 200
                data = response.json()
                
                assert data["status"] == "approved"
                assert data["fully_approved"] == True
                assert data["approvers_count"] == 1
                assert len(data["approvers"]) == 1
                assert data["approvers"][0]["id"] == "approver@example.com"
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_approve_nonexistent_challenge(self):
        """Should return 404 for nonexistent challenge."""
        async with httpx.AsyncClient() as client:
            try:
                approve_data = {
                    "challenge_id": "chal_nonexistent_12345",
                    "approver": "approver@example.com"
                }
                
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json=approve_data,
                    timeout=5.0
                )
                
                assert response.status_code == 404
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_approve_missing_challenge_id(self):
        """Should reject approval without challenge ID."""
        async with httpx.AsyncClient() as client:
            try:
                approve_data = {
                    "approver": "approver@example.com"
                }
                
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json=approve_data,
                    timeout=5.0
                )
                
                assert response.status_code == 400
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


class TestMandateIssuance:
    """Test mandate (PoA token) issuance endpoint."""

    async def _create_and_approve_challenge(self, client: httpx.AsyncClient) -> str:
        """Helper to create and approve a challenge."""
        # Create
        request_data = {
            "agent_spiffe_id": "spiffe://example.org/agent/test",
            "act": "crm.contact.read",
            "con": {"contact_id": "C-12345"},
            "leg": {
                "basis": "contract",
                "jurisdiction": "US",
                "accountable_party": {"type": "human", "id": "user@example.com"}
            }
        }
        create_resp = await client.post(
            f"{AGENTAUTH_URL}/v1/challenge",
            json=request_data,
            timeout=5.0
        )
        challenge_id = create_resp.json()["challenge_id"]
        
        # Approve
        await client.post(
            f"{AGENTAUTH_URL}/v1/approve",
            json={"challenge_id": challenge_id, "approver": "approver@example.com"},
            timeout=5.0
        )
        
        return challenge_id

    @pytest.mark.asyncio
    async def test_mandate_success(self):
        """Should issue PoA token for approved challenge."""
        async with httpx.AsyncClient() as client:
            try:
                challenge_id = await self._create_and_approve_challenge(client)
                
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/mandate",
                    json={"challenge_id": challenge_id},
                    timeout=5.0
                )
                
                assert response.status_code == 200
                data = response.json()
                
                assert "token" in data
                assert "expires_at" in data
                assert "jti" in data
                assert data["jti"].startswith("poa_")
                assert "approvers_count" in data
                assert data["approvers_count"] >= 1
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_mandate_token_structure(self):
        """PoA token should have valid JWT structure."""
        async with httpx.AsyncClient() as client:
            try:
                challenge_id = await self._create_and_approve_challenge(client)
                
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/mandate",
                    json={"challenge_id": challenge_id},
                    timeout=5.0
                )
                
                token = response.json()["token"]
                
                # Decode without verification to check structure
                unverified = jwt.decode(token, options={"verify_signature": False})
                
                assert "act" in unverified
                assert unverified["act"] == "crm.contact.read"
                assert "con" in unverified
                assert "leg" in unverified
                assert "iss" in unverified
                assert "sub" in unverified
                assert unverified["sub"] == "spiffe://example.org/agent/test"
                assert "exp" in unverified
                assert "iat" in unverified
                assert "jti" in unverified
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_mandate_unapproved_challenge(self):
        """Should reject mandate for unapproved challenge."""
        async with httpx.AsyncClient() as client:
            try:
                # Create but don't approve
                request_data = {
                    "agent_spiffe_id": "spiffe://example.org/agent/test",
                    "act": "crm.contact.read",
                    "con": {},
                    "leg": {"basis": "contract", "jurisdiction": "US", 
                            "accountable_party": {"type": "human", "id": "user@example.com"}}
                }
                create_resp = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json=request_data,
                    timeout=5.0
                )
                challenge_id = create_resp.json()["challenge_id"]
                
                # Try to get mandate without approval
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/mandate",
                    json={"challenge_id": challenge_id},
                    timeout=5.0
                )
                
                assert response.status_code == 403
                data = response.json()
                assert "error" in data
                assert "not fully approved" in data["error"]
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_mandate_nonexistent_challenge(self):
        """Should return 404 for nonexistent challenge."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{AGENTAUTH_URL}/v1/mandate",
                    json={"challenge_id": "chal_nonexistent"},
                    timeout=5.0
                )
                
                assert response.status_code == 404
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


class TestDualControlFlow:
    """Test dual control (two-approver) workflow."""

    @pytest.mark.asyncio
    async def test_dual_control_requires_two_approvers(self):
        """High-risk actions should require two different approvers."""
        async with httpx.AsyncClient() as client:
            try:
                # Create high-risk challenge
                request_data = {
                    "agent_spiffe_id": "spiffe://example.org/agent/test",
                    "act": "iam.privilege.escalate",  # High-risk
                    "con": {"user_id": "U-12345", "role": "admin"},
                    "leg": {
                        "basis": "contract",
                        "jurisdiction": "US",
                        "accountable_party": {"type": "human", "id": "admin@example.com"}
                    }
                }
                
                create_resp = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json=request_data,
                    timeout=5.0
                )
                
                assert create_resp.status_code == 200
                data = create_resp.json()
                challenge_id = data["challenge_id"]
                
                assert data["requires_dual_control"] == True
                assert data["approvers_needed"] == 2
                
                # First approval
                approve1_resp = await client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json={"challenge_id": challenge_id, "approver": "approver1@example.com"},
                    timeout=5.0
                )
                
                assert approve1_resp.status_code == 200
                approve1_data = approve1_resp.json()
                assert approve1_data["fully_approved"] == False
                assert approve1_data["approvers_count"] == 1
                
                # Second approval (different approver)
                approve2_resp = await client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json={"challenge_id": challenge_id, "approver": "approver2@example.com"},
                    timeout=5.0
                )
                
                assert approve2_resp.status_code == 200
                approve2_data = approve2_resp.json()
                assert approve2_data["fully_approved"] == True
                assert approve2_data["approvers_count"] == 2
                
                # Now mandate should succeed
                mandate_resp = await client.post(
                    f"{AGENTAUTH_URL}/v1/mandate",
                    json={"challenge_id": challenge_id},
                    timeout=5.0
                )
                
                assert mandate_resp.status_code == 200
                mandate_data = mandate_resp.json()
                assert mandate_data["dual_control_used"] == True
                assert mandate_data["approvers_count"] == 2
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_dual_control_same_approver_rejected(self):
        """Same approver should not be able to approve twice."""
        async with httpx.AsyncClient() as client:
            try:
                # Create high-risk challenge
                request_data = {
                    "agent_spiffe_id": "spiffe://example.org/agent/test",
                    "act": "payments.transfer.execute",  # High-risk
                    "con": {"amount": 10000, "currency": "USD"},
                    "leg": {
                        "basis": "contract",
                        "jurisdiction": "US",
                        "accountable_party": {"type": "human", "id": "finance@example.com"}
                    }
                }
                
                create_resp = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json=request_data,
                    timeout=5.0
                )
                challenge_id = create_resp.json()["challenge_id"]
                
                # First approval
                await client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json={"challenge_id": challenge_id, "approver": "same@example.com"},
                    timeout=5.0
                )
                
                # Same approver tries again
                approve2_resp = await client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json={"challenge_id": challenge_id, "approver": "same@example.com"},
                    timeout=5.0
                )
                
                assert approve2_resp.status_code == 409  # Conflict
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


class TestChallengeRetrieval:
    """Test challenge status retrieval."""

    @pytest.mark.asyncio
    async def test_get_challenge_status(self):
        """Should retrieve challenge status by ID."""
        async with httpx.AsyncClient() as client:
            try:
                # Create challenge
                request_data = {
                    "agent_spiffe_id": "spiffe://example.org/agent/test",
                    "act": "crm.contact.read",
                    "con": {},
                    "leg": {"basis": "contract", "jurisdiction": "US",
                            "accountable_party": {"type": "human", "id": "user@example.com"}}
                }
                create_resp = await client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json=request_data,
                    timeout=5.0
                )
                challenge_id = create_resp.json()["challenge_id"]
                
                # Get status
                response = await client.get(
                    f"{AGENTAUTH_URL}/v1/challenge/{challenge_id}",
                    timeout=5.0
                )
                
                assert response.status_code == 200
                data = response.json()
                
                assert data["challenge_id"] == challenge_id
                assert "action" in data
                assert "agent_spiffe_id" in data
                assert "created_at" in data
                assert "expires_at" in data
                assert "expired" in data
                assert data["expired"] == False
                assert "fully_approved" in data
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_get_nonexistent_challenge(self):
        """Should return 404 for nonexistent challenge."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{AGENTAUTH_URL}/v1/challenge/chal_nonexistent",
                    timeout=5.0
                )
                
                assert response.status_code == 404
                
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")
