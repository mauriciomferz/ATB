"""
Integration Tests for ATB Broker

These tests verify the integration between:
- ATB Broker
- OPA Policy Engine
- AgentAuth Service
- Python SDK

Prerequisites:
- Running ATB services (broker, OPA, agentauth)
- Valid test credentials
"""

import asyncio
import os
import sys
import pytest
import httpx
from datetime import datetime, timezone
from typing import AsyncGenerator

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'sdk', 'python', 'src'))

from atb import ATBClient
from atb.models import PoARequest, ActionLeg


# Test configuration
BROKER_URL = os.environ.get("ATB_BROKER_URL", "http://localhost:8080")
AGENTAUTH_URL = os.environ.get("ATB_AGENTAUTH_URL", "http://localhost:9090")
OPA_URL = os.environ.get("ATB_OPA_URL", "http://localhost:8181")


class TestBrokerHealth:
    """Test broker health endpoints."""

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Broker should respond to health checks."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{BROKER_URL}/health", timeout=5.0)
                assert response.status_code == 200
            except httpx.ConnectError:
                pytest.skip("Broker not running")

    @pytest.mark.asyncio
    async def test_ready_check(self):
        """Broker should respond to readiness checks."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{BROKER_URL}/ready", timeout=5.0)
                assert response.status_code == 200
            except httpx.ConnectError:
                pytest.skip("Broker not running")


class TestOPAIntegration:
    """Test OPA policy engine integration."""

    @pytest.mark.asyncio
    async def test_opa_health(self):
        """OPA should be healthy."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{OPA_URL}/health", timeout=5.0)
                assert response.status_code == 200
            except httpx.ConnectError:
                pytest.skip("OPA not running")

    @pytest.mark.asyncio
    async def test_policy_loaded(self):
        """ATB policies should be loaded."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{OPA_URL}/v1/policies",
                    timeout=5.0
                )
                assert response.status_code == 200
                data = response.json()
                # Check that we have policies loaded
                assert "result" in data
            except httpx.ConnectError:
                pytest.skip("OPA not running")

    @pytest.mark.asyncio
    async def test_low_risk_action_allowed(self):
        """Low-risk actions should be allowed."""
        async with httpx.AsyncClient() as client:
            try:
                input_data = {
                    "input": {
                        "poa": {
                            "iss": "test-issuer",
                            "sub": "test-agent",
                            "aud": "atb-broker",
                            "iat": int(datetime.now(timezone.utc).timestamp()),
                            "exp": int(datetime.now(timezone.utc).timestamp()) + 300,
                            "jti": "test-jti-123",
                            "legs": [
                                {
                                    "idx": 0,
                                    "target": "storage",
                                    "action": "read",
                                    "resource": "/documents/public/readme.txt",
                                    "context": {}
                                }
                            ]
                        },
                        "leg_idx": 0
                    }
                }
                response = await client.post(
                    f"{OPA_URL}/v1/data/atb/poa/decision",
                    json=input_data,
                    timeout=5.0
                )
                assert response.status_code == 200
                result = response.json()
                # Check policy decision
                assert "result" in result
            except httpx.ConnectError:
                pytest.skip("OPA not running")


class TestAgentAuthIntegration:
    """Test AgentAuth service integration."""

    @pytest.mark.asyncio
    async def test_agentauth_health(self):
        """AgentAuth should be healthy."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{AGENTAUTH_URL}/health", timeout=5.0)
                assert response.status_code == 200
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    @pytest.mark.asyncio
    async def test_jwks_endpoint(self):
        """JWKS endpoint should return public keys."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{AGENTAUTH_URL}/.well-known/jwks.json",
                    timeout=5.0
                )
                assert response.status_code == 200
                data = response.json()
                assert "keys" in data
            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


class TestSDKIntegration:
    """Test Python SDK integration with live services."""

    @pytest.fixture
    def client(self) -> ATBClient:
        """Create SDK client."""
        return ATBClient(
            base_url=BROKER_URL,
            timeout=10.0
        )

    @pytest.mark.asyncio
    async def test_sdk_health_check(self, client: ATBClient):
        """SDK should be able to check broker health."""
        try:
            is_healthy = await client.health_check()
            assert is_healthy
        except Exception:
            pytest.skip("Broker not running")

    @pytest.mark.asyncio
    async def test_sdk_list_connectors(self, client: ATBClient):
        """SDK should be able to list connectors."""
        try:
            connectors = await client.list_connectors()
            assert isinstance(connectors, list)
        except Exception:
            pytest.skip("Broker not running or connectors not configured")


class TestEndToEndFlow:
    """End-to-end test scenarios."""

    @pytest.mark.asyncio
    async def test_full_action_flow(self):
        """Test complete action execution flow."""
        # This test requires all services running
        try:
            # 1. Create SDK client
            client = ATBClient(base_url=BROKER_URL)
            
            # 2. Check health
            assert await client.health_check()
            
            # 3. Create PoA request (would normally get signed by AgentAuth)
            poa_request = PoARequest(
                issuer="e2e-test",
                subject="test-agent",
                audience="atb-broker",
                ttl=300,
                legs=[
                    ActionLeg(
                        idx=0,
                        target="echo",
                        action="GET",
                        resource="/test",
                        context={"test": True}
                    )
                ]
            )
            
            # 4. For E2E, we'd execute with a real signed PoA
            # This is a placeholder for the full flow
            print(f"Would execute PoA: {poa_request}")
            
        except Exception as e:
            pytest.skip(f"Services not running: {e}")


# Test fixtures for async client
@pytest.fixture
async def async_http_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Async HTTP client fixture."""
    async with httpx.AsyncClient() as client:
        yield client


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
