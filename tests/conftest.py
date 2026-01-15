"""
Fixtures for ATB Integration and E2E Tests
"""

import os
import pytest
import asyncio
from typing import AsyncGenerator

import httpx

# Service URLs from environment or defaults
BROKER_URL = os.environ.get("ATB_BROKER_URL", "http://localhost:8080")
AGENTAUTH_URL = os.environ.get("ATB_AGENTAUTH_URL", "http://localhost:8444")
OPA_URL = os.environ.get("ATB_OPA_URL", "http://localhost:8181")


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def http_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Async HTTP client fixture."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        yield client


@pytest.fixture
def broker_url() -> str:
    """Broker URL fixture."""
    return BROKER_URL


@pytest.fixture
def agentauth_url() -> str:
    """AgentAuth URL fixture."""
    return AGENTAUTH_URL


@pytest.fixture
def opa_url() -> str:
    """OPA URL fixture."""
    return OPA_URL


@pytest.fixture
async def services_available(http_client: httpx.AsyncClient) -> bool:
    """Check if all services are available."""
    try:
        broker_health = await http_client.get(f"{BROKER_URL}/health")
        opa_health = await http_client.get(f"{OPA_URL}/health")
        agentauth_health = await http_client.get(f"{AGENTAUTH_URL}/health")
        
        return all([
            broker_health.status_code == 200,
            opa_health.status_code == 200,
            agentauth_health.status_code == 200
        ])
    except httpx.ConnectError:
        return False


@pytest.fixture
def sample_poa_low_risk():
    """Sample low-risk PoA."""
    return {
        "iss": "test-issuer",
        "sub": "test-agent",
        "aud": "atb-broker",
        "legs": [
            {
                "idx": 0,
                "target": "storage",
                "action": "read",
                "resource": "/public/data.json",
                "context": {}
            }
        ]
    }


@pytest.fixture
def sample_poa_high_risk():
    """Sample high-risk PoA."""
    return {
        "iss": "test-issuer",
        "sub": "test-agent",
        "aud": "atb-broker",
        "legs": [
            {
                "idx": 0,
                "target": "database",
                "action": "delete",
                "resource": "/records/all",
                "context": {}
            }
        ]
    }
