"""Proof-of-Authorization (PoA) data structures and builder."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

import jwt

from atb.exceptions import ValidationError


@dataclass
class AccountableParty:
    """The human or organizational entity legally accountable for the action."""

    type: Literal["user", "service_account", "org_unit", "role"]
    id: str
    display_name: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary, excluding None values."""
        result = {"type": self.type, "id": self.id}
        if self.display_name:
            result["display_name"] = self.display_name
        return result


@dataclass
class DualControl:
    """Dual-control / four-eyes approval metadata."""

    required: bool
    approver: AccountableParty | None = None
    approved_at: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = {"required": self.required}
        if self.approver:
            result["approver"] = self.approver.to_dict()
        if self.approved_at:
            result["approved_at"] = self.approved_at
        return result


@dataclass
class LegalGrounding:
    """Legal grounding for a PoA mandate."""

    jurisdiction: str
    accountable_party: AccountableParty
    approval_ref: str | None = None
    dual_control: DualControl | None = None
    regulation_refs: list[str] = field(default_factory=list)
    retention_days: int | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = {
            "jurisdiction": self.jurisdiction,
            "accountable_party": self.accountable_party.to_dict(),
        }
        if self.approval_ref:
            result["approval_ref"] = self.approval_ref
        if self.dual_control:
            result["dual_control"] = self.dual_control.to_dict()
        if self.regulation_refs:
            result["regulation_refs"] = self.regulation_refs
        if self.retention_days:
            result["retention_days"] = self.retention_days
        return result


@dataclass
class PoA:
    """Proof-of-Authorization mandate token."""

    # Required fields
    sub: str  # SPIFFE ID of the agent
    act: str  # Action identifier (e.g., "sap.vendor.change")
    con: dict[str, Any]  # Constraints - params and constraints
    leg: LegalGrounding  # Legal grounding
    iat: int  # Issued at (Unix timestamp)
    exp: int  # Expiration (Unix timestamp)
    jti: str  # JWT ID for replay protection

    # Optional fields
    iss: str | None = None  # Issuer SPIFFE ID
    aud: str | list[str] | None = None  # Audience SPIFFE ID(s)

    def to_dict(self) -> dict:
        """Convert to dictionary for JWT encoding."""
        result = {
            "sub": self.sub,
            "act": self.act,
            "con": self.con,
            "leg": self.leg.to_dict(),
            "iat": self.iat,
            "exp": self.exp,
            "jti": self.jti,
        }
        if self.iss:
            result["iss"] = self.iss
        if self.aud:
            result["aud"] = self.aud
        return result

    def to_jwt(self, private_key: str, algorithm: str = "ES256") -> str:
        """Sign and encode the PoA as a JWT.

        Args:
            private_key: PEM-encoded private key for signing.
            algorithm: JWT signing algorithm (default: ES256).

        Returns:
            Signed JWT string.
        """
        return jwt.encode(self.to_dict(), private_key, algorithm=algorithm)

    def is_expired(self) -> bool:
        """Check if the PoA has expired."""
        return time.time() > self.exp

    def validate(self) -> None:
        """Validate the PoA structure.

        Raises:
            ValidationError: If validation fails.
        """
        # Check SPIFFE ID format
        if not self.sub.startswith("spiffe://"):
            raise ValidationError("Subject must be a valid SPIFFE ID", field="sub")

        # Check action format (dot-separated namespace)
        if "." not in self.act:
            raise ValidationError(
                "Action must be dot-separated (e.g., 'sap.vendor.change')",
                field="act",
            )

        # Check timestamps
        if self.exp <= self.iat:
            raise ValidationError("Expiration must be after issued time", field="exp")

        # Check JTI
        if len(self.jti) < 8:
            raise ValidationError("JTI must be at least 8 characters", field="jti")

        # Check legal grounding
        if not self.leg.jurisdiction:
            raise ValidationError("Jurisdiction is required", field="leg.jurisdiction")

    @classmethod
    def from_jwt(cls, token: str, public_key: str, algorithms: list[str] | None = None) -> PoA:
        """Decode and verify a JWT to create a PoA.

        Args:
            token: JWT string to decode.
            public_key: PEM-encoded public key for verification.
            algorithms: Allowed algorithms (default: ["ES256"]).

        Returns:
            PoA instance.

        Raises:
            ValidationError: If token is invalid or expired.
        """
        algorithms = algorithms or ["ES256"]
        try:
            payload = jwt.decode(token, public_key, algorithms=algorithms)
        except jwt.ExpiredSignatureError:
            raise ValidationError("Token has expired") from None
        except jwt.InvalidTokenError as e:
            raise ValidationError(f"Invalid token: {e}") from e

        leg_data = payload["leg"]
        accountable_party = AccountableParty(
            type=leg_data["accountable_party"]["type"],
            id=leg_data["accountable_party"]["id"],
            display_name=leg_data["accountable_party"].get("display_name"),
        )

        dual_control = None
        if "dual_control" in leg_data:
            dc = leg_data["dual_control"]
            approver = None
            if "approver" in dc:
                approver = AccountableParty(
                    type=dc["approver"]["type"],
                    id=dc["approver"]["id"],
                    display_name=dc["approver"].get("display_name"),
                )
            dual_control = DualControl(
                required=dc["required"],
                approver=approver,
                approved_at=dc.get("approved_at"),
            )

        leg = LegalGrounding(
            jurisdiction=leg_data["jurisdiction"],
            accountable_party=accountable_party,
            approval_ref=leg_data.get("approval_ref"),
            dual_control=dual_control,
            regulation_refs=leg_data.get("regulation_refs", []),
            retention_days=leg_data.get("retention_days"),
        )

        return cls(
            sub=payload["sub"],
            act=payload["act"],
            con=payload["con"],
            leg=leg,
            iat=payload["iat"],
            exp=payload["exp"],
            jti=payload["jti"],
            iss=payload.get("iss"),
            aud=payload.get("aud"),
        )


class PoABuilder:
    """Builder for creating PoA mandates with a fluent interface."""

    def __init__(self) -> None:
        self._sub: str | None = None
        self._act: str | None = None
        self._params: dict[str, Any] = {}
        self._constraints: dict[str, Any] = {}
        self._leg: LegalGrounding | None = None
        self._ttl: int = 300  # Default 5 minutes
        self._iss: str | None = None
        self._aud: str | list[str] | None = None

    def for_agent(self, spiffe_id: str) -> PoABuilder:
        """Set the subject (agent SPIFFE ID).

        Args:
            spiffe_id: SPIFFE ID of the agent (e.g., "spiffe://atb.example/agent/copilot").
        """
        self._sub = spiffe_id
        return self

    def action(self, action: str) -> PoABuilder:
        """Set the action to authorize.

        Args:
            action: Action identifier (e.g., "sap.vendor.change").
        """
        self._act = action
        return self

    def with_params(self, **params: Any) -> PoABuilder:
        """Add action parameters.

        Args:
            **params: Key-value pairs for action parameters.
        """
        self._params.update(params)
        return self

    def with_constraint(self, name: str, value: Any) -> PoABuilder:
        """Add a constraint.

        Args:
            name: Constraint name (e.g., "liability_cap").
            value: Constraint value.
        """
        self._constraints[name] = value
        return self

    def with_constraints(self, **constraints: Any) -> PoABuilder:
        """Add multiple constraints.

        Args:
            **constraints: Key-value pairs for constraints.
        """
        self._constraints.update(constraints)
        return self

    def legal(
        self,
        jurisdiction: str,
        accountable_party: AccountableParty,
        approval_ref: str | None = None,
        dual_control: DualControl | None = None,
        regulation_refs: list[str] | None = None,
        retention_days: int | None = None,
    ) -> PoABuilder:
        """Set legal grounding.

        Args:
            jurisdiction: ISO 3166-1 alpha-2 country code or "GLOBAL".
            accountable_party: The human/org legally accountable.
            approval_ref: External approval reference (e.g., "SNOW-CHG0012345").
            dual_control: Dual-control approval metadata.
            regulation_refs: Regulatory frameworks (e.g., ["NIS2", "SOX"]).
            retention_days: Audit retention period in days.
        """
        self._leg = LegalGrounding(
            jurisdiction=jurisdiction,
            accountable_party=accountable_party,
            approval_ref=approval_ref,
            dual_control=dual_control,
            regulation_refs=regulation_refs or [],
            retention_days=retention_days,
        )
        return self

    def ttl(self, seconds: int) -> PoABuilder:
        """Set time-to-live (default: 300 seconds / 5 minutes).

        Args:
            seconds: TTL in seconds (recommended max: 300).
        """
        self._ttl = seconds
        return self

    def issuer(self, spiffe_id: str) -> PoABuilder:
        """Set the issuer SPIFFE ID.

        Args:
            spiffe_id: SPIFFE ID of the issuing service.
        """
        self._iss = spiffe_id
        return self

    def audience(self, spiffe_id: str | list[str]) -> PoABuilder:
        """Set the audience SPIFFE ID(s).

        Args:
            spiffe_id: SPIFFE ID or list of IDs for the broker(s).
        """
        self._aud = spiffe_id
        return self

    def build(self) -> PoA:
        """Build the PoA mandate.

        Returns:
            PoA instance.

        Raises:
            ValidationError: If required fields are missing.
        """
        if not self._sub:
            raise ValidationError("Subject (agent SPIFFE ID) is required")
        if not self._act:
            raise ValidationError("Action is required")
        if not self._leg:
            raise ValidationError("Legal grounding is required")

        now = int(time.time())
        poa = PoA(
            sub=self._sub,
            act=self._act,
            con={"params": self._params, "constraints": self._constraints},
            leg=self._leg,
            iat=now,
            exp=now + self._ttl,
            jti=f"poa_{uuid.uuid4().hex}",
            iss=self._iss,
            aud=self._aud,
        )
        poa.validate()
        return poa
