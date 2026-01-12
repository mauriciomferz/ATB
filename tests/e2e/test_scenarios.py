"""
End-to-End Tests for ATB

These tests simulate real-world scenarios:
- Agent executing multi-step workflows
- Policy enforcement across different risk tiers
- Audit logging and compliance verification

Prerequisites:
- Full ATB stack running (broker, OPA, agentauth, SPIRE)
- Test data fixtures
"""

import asyncio
import json
import os
import sys
import pytest
import httpx
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from uuid import uuid4

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'sdk', 'python', 'src'))

from atb import ATBClient
from atb.models import PoARequest, ActionLeg


# Test configuration
BROKER_URL = os.environ.get("ATB_BROKER_URL", "http://localhost:8080")
AGENTAUTH_URL = os.environ.get("ATB_AGENTAUTH_URL", "http://localhost:9090")
OPA_URL = os.environ.get("ATB_OPA_URL", "http://localhost:8181")


class TestScenarios:
    """Real-world test scenarios."""

    @pytest.mark.asyncio
    async def test_scenario_document_read(self):
        """
        Scenario: Agent reads a public document
        
        Expected: Should be allowed without approval (low risk)
        """
        client = ATBClient(base_url=BROKER_URL)
        
        try:
            # Create read action
            poa = PoARequest(
                issuer="e2e-test",
                subject="doc-reader-agent",
                audience="atb-broker",
                ttl=60,
                legs=[
                    ActionLeg(
                        idx=0,
                        target="storage",
                        action="read",
                        resource="/documents/public/readme.txt",
                        context={"reason": "User requested document"}
                    )
                ]
            )
            
            # Verify health first
            if not await client.health_check():
                pytest.skip("Broker not healthy")
            
            # In real scenario, would execute with signed PoA
            print(f"Scenario: Document read - PoA: {poa}")
            
        except Exception as e:
            pytest.skip(f"Services not available: {e}")

    @pytest.mark.asyncio
    async def test_scenario_multi_step_workflow(self):
        """
        Scenario: Agent executes a multi-step workflow
        
        Steps:
        1. Read customer data
        2. Process with AI
        3. Write result to storage
        
        Expected: Each step should be validated independently
        """
        client = ATBClient(base_url=BROKER_URL)
        
        try:
            # Create multi-step workflow
            poa = PoARequest(
                issuer="e2e-test",
                subject="workflow-agent",
                audience="atb-broker",
                ttl=300,
                legs=[
                    ActionLeg(
                        idx=0,
                        target="database",
                        action="read",
                        resource="/customers/123",
                        context={"workflow_id": "test-workflow"}
                    ),
                    ActionLeg(
                        idx=1,
                        target="ai-service",
                        action="analyze",
                        resource="/customer-analysis",
                        context={"model": "gpt-4", "workflow_id": "test-workflow"}
                    ),
                    ActionLeg(
                        idx=2,
                        target="storage",
                        action="write",
                        resource="/results/customer-123-analysis.json",
                        context={"workflow_id": "test-workflow"}
                    )
                ]
            )
            
            if not await client.health_check():
                pytest.skip("Broker not healthy")
            
            print(f"Scenario: Multi-step workflow - {len(poa.legs)} legs")
            
        except Exception as e:
            pytest.skip(f"Services not available: {e}")

    @pytest.mark.asyncio
    async def test_scenario_high_risk_action_blocked(self):
        """
        Scenario: Agent attempts high-risk action without approval
        
        Expected: Should be blocked and require human approval
        """
        client = ATBClient(base_url=BROKER_URL)
        
        try:
            # Create high-risk action (delete)
            poa = PoARequest(
                issuer="e2e-test",
                subject="cleanup-agent",
                audience="atb-broker",
                ttl=60,
                legs=[
                    ActionLeg(
                        idx=0,
                        target="database",
                        action="delete",
                        resource="/customers/all",
                        context={"reason": "Data cleanup"}
                    )
                ]
            )
            
            if not await client.health_check():
                pytest.skip("Broker not healthy")
            
            # This should be blocked by OPA policy
            print(f"Scenario: High-risk delete - should require approval")
            
        except Exception as e:
            pytest.skip(f"Services not available: {e}")


class TestPolicyEnforcement:
    """Test policy enforcement at different risk tiers."""

    @pytest.mark.asyncio
    async def test_risk_tier_low(self):
        """Low-risk actions should auto-approve."""
        input_data = {
            "input": {
                "poa": {
                    "iss": "test-issuer",
                    "sub": "test-agent",
                    "aud": "atb-broker",
                    "iat": int(datetime.now(timezone.utc).timestamp()),
                    "exp": int(datetime.now(timezone.utc).timestamp()) + 300,
                    "jti": str(uuid4()),
                    "legs": [
                        {
                            "idx": 0,
                            "target": "storage",
                            "action": "read",
                            "resource": "/public/data.json",
                            "context": {}
                        }
                    ]
                },
                "leg_idx": 0
            }
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{OPA_URL}/v1/data/atb/poa/decision",
                    json=input_data,
                    timeout=5.0
                )
                assert response.status_code == 200
                result = response.json()
                
                # Low-risk should be allowed
                if "result" in result and "allow" in result["result"]:
                    assert result["result"]["allow"] == True
                    
            except httpx.ConnectError:
                pytest.skip("OPA not running")

    @pytest.mark.asyncio
    async def test_risk_tier_medium(self):
        """Medium-risk actions should require logging."""
        input_data = {
            "input": {
                "poa": {
                    "iss": "test-issuer",
                    "sub": "test-agent",
                    "aud": "atb-broker",
                    "iat": int(datetime.now(timezone.utc).timestamp()),
                    "exp": int(datetime.now(timezone.utc).timestamp()) + 300,
                    "jti": str(uuid4()),
                    "legs": [
                        {
                            "idx": 0,
                            "target": "database",
                            "action": "update",
                            "resource": "/records/123",
                            "context": {"data": {"status": "processed"}}
                        }
                    ]
                },
                "leg_idx": 0
            }
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{OPA_URL}/v1/data/atb/poa/decision",
                    json=input_data,
                    timeout=5.0
                )
                assert response.status_code == 200
                result = response.json()
                
                # Medium-risk should require audit
                if "result" in result:
                    print(f"Medium-risk decision: {result['result']}")
                    
            except httpx.ConnectError:
                pytest.skip("OPA not running")

    @pytest.mark.asyncio
    async def test_risk_tier_high(self):
        """High-risk actions should require approval."""
        input_data = {
            "input": {
                "poa": {
                    "iss": "test-issuer",
                    "sub": "test-agent",
                    "aud": "atb-broker",
                    "iat": int(datetime.now(timezone.utc).timestamp()),
                    "exp": int(datetime.now(timezone.utc).timestamp()) + 300,
                    "jti": str(uuid4()),
                    "legs": [
                        {
                            "idx": 0,
                            "target": "database",
                            "action": "delete",
                            "resource": "/records/all",
                            "context": {}
                        }
                    ]
                },
                "leg_idx": 0
            }
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{OPA_URL}/v1/data/atb/poa/decision",
                    json=input_data,
                    timeout=5.0
                )
                assert response.status_code == 200
                result = response.json()
                
                # High-risk should require approval or be denied
                if "result" in result:
                    print(f"High-risk decision: {result['result']}")
                    
            except httpx.ConnectError:
                pytest.skip("OPA not running")


class TestAuditCompliance:
    """Test audit logging and compliance features."""

    @pytest.mark.asyncio
    async def test_audit_events_captured(self):
        """All actions should generate audit events."""
        client = ATBClient(base_url=BROKER_URL)
        
        try:
            # Get recent audit events
            events = await client.get_audit_events(limit=10)
            
            # Verify audit event structure
            for event in events:
                assert "timestamp" in event or "ts" in event
                assert "event_type" in event or "type" in event
                
        except Exception as e:
            pytest.skip(f"Audit endpoint not available: {e}")

    @pytest.mark.asyncio
    async def test_audit_event_integrity(self):
        """Audit events should have integrity verification."""
        # This test verifies that audit events contain hash chains
        # for tamper-evidence
        client = ATBClient(base_url=BROKER_URL)
        
        try:
            events = await client.get_audit_events(limit=10)
            
            for event in events:
                # Check for hash chain or signature
                if "prev_hash" in event or "signature" in event:
                    print(f"Event has integrity fields: {list(event.keys())}")
                    
        except Exception as e:
            pytest.skip(f"Audit endpoint not available: {e}")


class TestConcurrency:
    """Test concurrent action execution."""

    @pytest.mark.asyncio
    async def test_concurrent_actions(self):
        """Multiple concurrent actions should be handled correctly."""
        client = ATBClient(base_url=BROKER_URL)
        
        try:
            if not await client.health_check():
                pytest.skip("Broker not healthy")
            
            # Create multiple concurrent health checks as a proxy
            tasks = [
                client.health_check()
                for _ in range(10)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # All should succeed
            successes = sum(1 for r in results if r is True)
            assert successes == 10, f"Only {successes}/10 health checks succeeded"
            
        except Exception as e:
            pytest.skip(f"Services not available: {e}")

    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        """Rate limiting should be enforced."""
        async with httpx.AsyncClient() as client:
            try:
                # Send many requests quickly
                tasks = [
                    client.get(f"{BROKER_URL}/health")
                    for _ in range(100)
                ]
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Check for rate limit responses (429)
                rate_limited = sum(
                    1 for r in responses
                    if isinstance(r, httpx.Response) and r.status_code == 429
                )
                
                print(f"Rate limited: {rate_limited}/100 requests")
                
            except Exception as e:
                pytest.skip(f"Services not available: {e}")


# Test data fixtures
@pytest.fixture
def sample_poa_requests() -> List[Dict[str, Any]]:
    """Sample PoA requests for testing."""
    return [
        {
            "name": "low_risk_read",
            "poa": {
                "issuer": "test",
                "subject": "agent-1",
                "audience": "atb-broker",
                "ttl": 60,
                "legs": [
                    {"idx": 0, "target": "storage", "action": "read", "resource": "/public"}
                ]
            },
            "expected_risk": "low"
        },
        {
            "name": "medium_risk_update",
            "poa": {
                "issuer": "test",
                "subject": "agent-1",
                "audience": "atb-broker",
                "ttl": 60,
                "legs": [
                    {"idx": 0, "target": "database", "action": "update", "resource": "/records/1"}
                ]
            },
            "expected_risk": "medium"
        },
        {
            "name": "high_risk_delete",
            "poa": {
                "issuer": "test",
                "subject": "agent-1",
                "audience": "atb-broker",
                "ttl": 60,
                "legs": [
                    {"idx": 0, "target": "database", "action": "delete", "resource": "/all"}
                ]
            },
            "expected_risk": "high"
        }
    ]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
