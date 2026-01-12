"""Tests for ATB client."""

import httpx
import pytest
import respx

from atb.client import ActionResult, ATBClient, ATBConfig
from atb.exceptions import AuthorizationDeniedError
from atb.poa import AccountableParty, PoABuilder


class TestActionResult:
    """Tests for ActionResult."""

    def test_success_is_truthy(self):
        """Test that successful result is truthy."""
        result = ActionResult(success=True, data={"key": "value"})
        assert result
        assert bool(result) is True

    def test_failure_is_falsy(self):
        """Test that failed result is falsy."""
        result = ActionResult(success=False, error="Something went wrong")
        assert not result
        assert bool(result) is False


class TestATBClient:
    """Tests for ATBClient."""

    def test_init_with_defaults(self):
        """Test client initialization with defaults."""
        client = ATBClient()
        assert client.config.broker_url == "http://localhost:8080"
        assert client.config.agentauth_url == "http://localhost:8081"
        assert client.config.timeout == 30.0
        assert client.config.verify_ssl is True

    def test_init_with_custom_config(self):
        """Test client initialization with custom config."""
        config = ATBConfig(
            broker_url="http://broker:9000",
            agentauth_url="http://auth:9001",
            timeout=60.0,
            verify_ssl=False,
        )
        client = ATBClient(config)
        assert client.config.broker_url == "http://broker:9000"
        assert client.config.timeout == 60.0

    def test_context_manager(self):
        """Test client as context manager."""
        with ATBClient() as client:
            assert client._http_client is None  # Lazy init
        # After exit, client should be cleaned up

    @respx.mock
    def test_execute_success(self, tmp_path):
        """Test successful action execution."""
        # Create a test private key
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        key_path = tmp_path / "private.key"
        key_path.write_bytes(pem)

        # Mock the broker response
        respx.post("http://localhost:8080/v1/action").mock(
            return_value=httpx.Response(
                200,
                json={"result": "success", "data": {"updated": True}},
                headers={"X-Audit-ID": "audit_123"},
            )
        )

        config = ATBConfig(private_key_path=str(key_path))
        client = ATBClient(config)

        poa = (
            PoABuilder()
            .for_agent("spiffe://atb.example/agent/copilot")
            .action("sap.vendor.change")
            .with_params(vendor_id="V-12345")
            .legal(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            )
            .build()
        )

        result = client.execute(poa)

        assert result.success
        assert result.data["result"] == "success"
        assert result.audit_id == "audit_123"
        assert result.decision == "allow"

    @respx.mock
    def test_execute_denied(self, tmp_path):
        """Test action denied by policy."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        key_path = tmp_path / "private.key"
        key_path.write_bytes(pem)

        # Mock 403 response
        respx.post("http://localhost:8080/v1/action").mock(
            return_value=httpx.Response(
                403,
                json={"error": "Policy denied", "reason": "liability_cap exceeded"},
            )
        )

        config = ATBConfig(private_key_path=str(key_path))
        client = ATBClient(config)

        poa = (
            PoABuilder()
            .for_agent("spiffe://atb.example/agent/copilot")
            .action("sap.vendor.change")
            .with_params(vendor_id="V-12345")
            .legal(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            )
            .build()
        )

        with pytest.raises(AuthorizationDeniedError) as exc:
            client.execute(poa)

        assert exc.value.reason == "liability_cap exceeded"

    @respx.mock
    def test_check_policy(self):
        """Test policy check."""
        respx.post("http://localhost:8080/v1/policy/check").mock(
            return_value=httpx.Response(
                200,
                json={"allowed": True, "reason": "Action permitted"},
            )
        )

        client = ATBClient()
        result = client.check_policy(
            action="sap.vendor.change",
            params={"amount": 5000},
            agent_spiffe_id="spiffe://atb.example/agent/copilot",
        )

        assert result["allowed"] is True

    @respx.mock
    def test_get_audit_log(self):
        """Test audit log retrieval."""
        respx.get("http://localhost:8080/v1/audit").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "audit_id": "audit_123",
                        "action": "sap.vendor.change",
                        "decision": "allow",
                        "timestamp": "2024-01-15T10:30:00Z",
                    }
                ],
            )
        )

        client = ATBClient()
        entries = client.get_audit_log(action="sap.vendor.change", limit=10)

        assert len(entries) == 1
        assert entries[0]["audit_id"] == "audit_123"
