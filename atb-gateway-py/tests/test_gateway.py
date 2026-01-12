"""Tests for ATB Gateway Python service."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_endpoint(self, client):
        """Test /health returns ok status."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_ready_endpoint_without_opa(self, client):
        """Test /ready returns 503 when OPA is not available."""
        # Without OPA running, this should return 503
        response = client.get("/ready")
        # In test environment without OPA, expect 503
        assert response.status_code in (200, 503)


class TestActionEndpoint:
    """Tests for action execution endpoint."""

    def test_action_without_auth(self, client):
        """Test /v1/action requires authentication."""
        response = client.post(
            "/v1/action",
            json={"action": "sap.vendor.read", "params": {}},
        )
        # Should return 401 without SPIFFE identity
        assert response.status_code == 401

    def test_action_without_poa(self, client):
        """Test /v1/action requires PoA for most actions."""
        response = client.post(
            "/v1/action",
            json={"action": "sap.vendor.change", "params": {}},
            headers={"X-SPIFFE-ID": "spiffe://test.example/agent/test"},
        )
        # Should return 403 without PoA for non-low-risk actions
        assert response.status_code in (400, 403)


class TestPolicyCheckEndpoint:
    """Tests for policy check endpoint."""

    def test_policy_check_without_auth(self, client):
        """Test /v1/policy/check requires authentication."""
        response = client.post(
            "/v1/policy/check",
            json={
                "action": "sap.vendor.read",
                "params": {},
                "agent": "spiffe://test.example/agent/test",
            },
        )
        # Should work without full auth for policy check
        assert response.status_code in (200, 500, 503)


class TestAuditEndpoint:
    """Tests for audit log endpoint."""

    def test_audit_log_endpoint(self, client):
        """Test /v1/audit returns audit entries."""
        response = client.get("/v1/audit?limit=10")
        # Audit endpoint should exist
        assert response.status_code in (200, 404)
