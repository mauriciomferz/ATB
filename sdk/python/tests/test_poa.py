"""Tests for PoA data structures and builder."""

import time
import pytest
from atb.poa import (
    PoA,
    PoABuilder,
    AccountableParty,
    LegalGrounding,
    DualControl,
)
from atb.exceptions import ValidationError


class TestAccountableParty:
    """Tests for AccountableParty dataclass."""

    def test_to_dict_minimal(self):
        """Test conversion with required fields only."""
        party = AccountableParty(type="user", id="alice@example.com")
        result = party.to_dict()
        assert result == {"type": "user", "id": "alice@example.com"}

    def test_to_dict_with_display_name(self):
        """Test conversion with display name."""
        party = AccountableParty(
            type="user",
            id="alice@example.com",
            display_name="Alice Smith",
        )
        result = party.to_dict()
        assert result == {
            "type": "user",
            "id": "alice@example.com",
            "display_name": "Alice Smith",
        }


class TestLegalGrounding:
    """Tests for LegalGrounding dataclass."""

    def test_to_dict_minimal(self):
        """Test conversion with required fields only."""
        leg = LegalGrounding(
            jurisdiction="DE",
            accountable_party=AccountableParty(type="user", id="alice@example.com"),
        )
        result = leg.to_dict()
        assert result["jurisdiction"] == "DE"
        assert result["accountable_party"]["id"] == "alice@example.com"

    def test_to_dict_with_all_fields(self):
        """Test conversion with all optional fields."""
        leg = LegalGrounding(
            jurisdiction="DE",
            accountable_party=AccountableParty(type="user", id="alice@example.com"),
            approval_ref="SNOW-CHG0012345",
            dual_control=DualControl(
                required=True,
                approver=AccountableParty(type="role", id="approver"),
                approved_at="2024-01-15T10:30:00Z",
            ),
            regulation_refs=["NIS2", "SOX"],
            retention_days=2555,
        )
        result = leg.to_dict()
        assert result["approval_ref"] == "SNOW-CHG0012345"
        assert result["dual_control"]["required"] is True
        assert result["regulation_refs"] == ["NIS2", "SOX"]
        assert result["retention_days"] == 2555


class TestPoA:
    """Tests for PoA dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        poa = PoA(
            sub="spiffe://atb.example/agent/copilot",
            act="sap.vendor.change",
            con={"params": {"vendor_id": "V-12345"}, "constraints": {}},
            leg=LegalGrounding(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            ),
            iat=1700000000,
            exp=1700000300,
            jti="poa_abc123def456",
        )
        result = poa.to_dict()

        assert result["sub"] == "spiffe://atb.example/agent/copilot"
        assert result["act"] == "sap.vendor.change"
        assert result["con"]["params"]["vendor_id"] == "V-12345"
        assert result["iat"] == 1700000000
        assert result["exp"] == 1700000300
        assert result["jti"] == "poa_abc123def456"

    def test_is_expired_true(self):
        """Test expiration check for expired token."""
        poa = PoA(
            sub="spiffe://atb.example/agent/copilot",
            act="sap.vendor.change",
            con={},
            leg=LegalGrounding(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            ),
            iat=1000000000,
            exp=1000000300,  # Way in the past
            jti="poa_abc123def456",
        )
        assert poa.is_expired() is True

    def test_is_expired_false(self):
        """Test expiration check for valid token."""
        now = int(time.time())
        poa = PoA(
            sub="spiffe://atb.example/agent/copilot",
            act="sap.vendor.change",
            con={},
            leg=LegalGrounding(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            ),
            iat=now,
            exp=now + 300,
            jti="poa_abc123def456",
        )
        assert poa.is_expired() is False

    def test_validate_success(self):
        """Test validation passes for valid PoA."""
        now = int(time.time())
        poa = PoA(
            sub="spiffe://atb.example/agent/copilot",
            act="sap.vendor.change",
            con={},
            leg=LegalGrounding(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            ),
            iat=now,
            exp=now + 300,
            jti="poa_abc123def456",
        )
        poa.validate()  # Should not raise

    def test_validate_invalid_subject(self):
        """Test validation fails for invalid SPIFFE ID."""
        now = int(time.time())
        poa = PoA(
            sub="invalid-spiffe-id",
            act="sap.vendor.change",
            con={},
            leg=LegalGrounding(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            ),
            iat=now,
            exp=now + 300,
            jti="poa_abc123def456",
        )
        with pytest.raises(ValidationError) as exc:
            poa.validate()
        assert exc.value.field == "sub"

    def test_validate_invalid_action(self):
        """Test validation fails for action without namespace."""
        now = int(time.time())
        poa = PoA(
            sub="spiffe://atb.example/agent/copilot",
            act="invalidaction",  # No dot separator
            con={},
            leg=LegalGrounding(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            ),
            iat=now,
            exp=now + 300,
            jti="poa_abc123def456",
        )
        with pytest.raises(ValidationError) as exc:
            poa.validate()
        assert exc.value.field == "act"

    def test_validate_exp_before_iat(self):
        """Test validation fails when exp <= iat."""
        now = int(time.time())
        poa = PoA(
            sub="spiffe://atb.example/agent/copilot",
            act="sap.vendor.change",
            con={},
            leg=LegalGrounding(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            ),
            iat=now,
            exp=now - 100,  # Before iat
            jti="poa_abc123def456",
        )
        with pytest.raises(ValidationError) as exc:
            poa.validate()
        assert exc.value.field == "exp"


class TestPoABuilder:
    """Tests for PoABuilder."""

    def test_build_minimal(self):
        """Test building PoA with minimal required fields."""
        poa = (
            PoABuilder()
            .for_agent("spiffe://atb.example/agent/copilot")
            .action("sap.vendor.change")
            .legal(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            )
            .build()
        )

        assert poa.sub == "spiffe://atb.example/agent/copilot"
        assert poa.act == "sap.vendor.change"
        assert poa.leg.jurisdiction == "DE"
        assert poa.jti.startswith("poa_")
        assert poa.exp > poa.iat

    def test_build_with_params(self):
        """Test building PoA with action parameters."""
        poa = (
            PoABuilder()
            .for_agent("spiffe://atb.example/agent/copilot")
            .action("sap.vendor.change")
            .with_params(vendor_id="V-12345", amount=5000)
            .legal(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            )
            .build()
        )

        assert poa.con["params"]["vendor_id"] == "V-12345"
        assert poa.con["params"]["amount"] == 5000

    def test_build_with_constraints(self):
        """Test building PoA with constraints."""
        poa = (
            PoABuilder()
            .for_agent("spiffe://atb.example/agent/copilot")
            .action("sap.vendor.change")
            .with_constraint("liability_cap", 10000)
            .with_constraints(dual_control=True, max_retries=3)
            .legal(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            )
            .build()
        )

        assert poa.con["constraints"]["liability_cap"] == 10000
        assert poa.con["constraints"]["dual_control"] is True
        assert poa.con["constraints"]["max_retries"] == 3

    def test_build_with_custom_ttl(self):
        """Test building PoA with custom TTL."""
        poa = (
            PoABuilder()
            .for_agent("spiffe://atb.example/agent/copilot")
            .action("sap.vendor.change")
            .ttl(60)  # 1 minute
            .legal(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            )
            .build()
        )

        assert poa.exp - poa.iat == 60

    def test_build_with_issuer_and_audience(self):
        """Test building PoA with issuer and audience."""
        poa = (
            PoABuilder()
            .for_agent("spiffe://atb.example/agent/copilot")
            .action("sap.vendor.change")
            .issuer("spiffe://atb.example/service/agentauth")
            .audience("spiffe://atb.example/service/broker")
            .legal(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            )
            .build()
        )

        assert poa.iss == "spiffe://atb.example/service/agentauth"
        assert poa.aud == "spiffe://atb.example/service/broker"

    def test_build_fails_without_agent(self):
        """Test building fails without agent."""
        builder = (
            PoABuilder()
            .action("sap.vendor.change")
            .legal(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            )
        )
        with pytest.raises(ValidationError):
            builder.build()

    def test_build_fails_without_action(self):
        """Test building fails without action."""
        builder = (
            PoABuilder()
            .for_agent("spiffe://atb.example/agent/copilot")
            .legal(
                jurisdiction="DE",
                accountable_party=AccountableParty(type="user", id="alice@example.com"),
            )
        )
        with pytest.raises(ValidationError):
            builder.build()

    def test_build_fails_without_legal(self):
        """Test building fails without legal grounding."""
        builder = (
            PoABuilder()
            .for_agent("spiffe://atb.example/agent/copilot")
            .action("sap.vendor.change")
        )
        with pytest.raises(ValidationError):
            builder.build()
