"""ATB SDK Models - Data classes for ATB operations.

This module provides structured data types for:
- Proof-of-Authorization requests
- Action definitions with legal grounding
- Approval workflows
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class RiskTier(str, Enum):
    """Risk classification for actions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PartyType(str, Enum):
    """Type of accountable party."""

    HUMAN = "human"
    ORGANIZATION = "organization"
    SYSTEM = "system"


@dataclass
class AccountableParty:
    """The party legally responsible for an agent's actions."""

    type: PartyType
    id: str
    name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API requests."""
        result = {
            "type": self.type.value if isinstance(self.type, PartyType) else self.type,
            "id": self.id,
        }
        if self.name:
            result["name"] = self.name
        if self.metadata:
            result["metadata"] = self.metadata
        return result


@dataclass
class DualControl:
    """Dual control requirements for high-risk actions."""

    required: bool = False
    min_approvers: int = 2
    approver_roles: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API requests."""
        return {
            "required": self.required,
            "min_approvers": self.min_approvers,
            "approver_roles": self.approver_roles,
        }


@dataclass
class ActionLeg:
    """Legal grounding for an agent action.

    'Leg' stands for 'Legal Basis' - the lawful basis for processing.
    """

    basis: str  # e.g., "contract", "consent", "legitimate_interest"
    jurisdiction: str  # e.g., "US", "EU", "GDPR"
    accountable_party: AccountableParty
    dual_control: DualControl | None = None
    purpose: str | None = None
    retention_days: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API requests."""
        result = {
            "basis": self.basis,
            "jurisdiction": self.jurisdiction,
            "accountable_party": self.accountable_party.to_dict(),
        }
        if self.dual_control:
            result["dual_control"] = self.dual_control.to_dict()
        if self.purpose:
            result["purpose"] = self.purpose
        if self.retention_days is not None:
            result["retention_days"] = self.retention_days
        if self.metadata:
            result["metadata"] = self.metadata
        return result


@dataclass
class PoARequest:
    """Request for a Proof-of-Authorization mandate.

    This represents the initial request to the AgentAuth service
    to create a challenge for authorization.
    """

    agent_spiffe_id: str
    act: str  # Action identifier, e.g., "crm.contact.read"
    con: dict[str, Any]  # Constraints, e.g., {"contact_id": "123"}
    leg: ActionLeg  # Legal basis

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API requests."""
        return {
            "agent_spiffe_id": self.agent_spiffe_id,
            "act": self.act,
            "con": self.con,
            "leg": self.leg.to_dict(),
        }


@dataclass
class ChallengeResponse:
    """Response from creating a challenge."""

    challenge_id: str
    expires_at: datetime
    requires_dual_control: bool
    approvers_needed: int
    approval_hint: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChallengeResponse:
        """Create from API response dictionary."""
        expires_at = data.get("expires_at", "")
        if isinstance(expires_at, str):
            # Parse ISO format datetime
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))

        return cls(
            challenge_id=data["challenge_id"],
            expires_at=expires_at,
            requires_dual_control=data.get("requires_dual_control", False),
            approvers_needed=data.get("approvers_needed", 1),
            approval_hint=data.get("approval_hint", ""),
        )


@dataclass
class ApprovalRequest:
    """Request to approve a challenge."""

    challenge_id: str
    approver: str
    approval_token: str | None = None  # JWT for authenticated approvals

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API requests."""
        return {
            "challenge_id": self.challenge_id,
            "approver": self.approver,
        }


@dataclass
class Approver:
    """An approver who has approved a challenge."""

    id: str
    approved_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Approver:
        """Create from API response dictionary."""
        approved_at = data.get("approved_at", "")
        if isinstance(approved_at, str):
            approved_at = datetime.fromisoformat(approved_at.replace("Z", "+00:00"))

        return cls(
            id=data["id"],
            approved_at=approved_at,
        )


@dataclass
class ApprovalResponse:
    """Response from an approval request."""

    status: str
    approvers_count: int
    approvers_needed: int
    fully_approved: bool
    approvers: list[Approver] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApprovalResponse:
        """Create from API response dictionary."""
        approvers = [Approver.from_dict(a) for a in data.get("approvers", [])]
        return cls(
            status=data.get("status", ""),
            approvers_count=data.get("approvers_count", 0),
            approvers_needed=data.get("approvers_needed", 1),
            fully_approved=data.get("fully_approved", False),
            approvers=approvers,
        )


@dataclass
class MandateRequest:
    """Request to issue a mandate (PoA token)."""

    challenge_id: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API requests."""
        return {
            "challenge_id": self.challenge_id,
        }


@dataclass
class MandateResponse:
    """Response containing the issued PoA token."""

    poa_token: str
    expires_at: datetime
    token_id: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MandateResponse:
        """Create from API response dictionary."""
        expires_at = data.get("expires_at", "")
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))

        return cls(
            poa_token=data.get("poa_token", ""),
            expires_at=expires_at,
            token_id=data.get("token_id", data.get("jti", "")),
        )


@dataclass
class ChallengeStatus:
    """Status of a challenge."""

    challenge_id: str
    action: str
    agent_spiffe_id: str
    created_at: datetime
    expires_at: datetime
    expired: bool
    requires_dual_control: bool
    approvers_needed: int
    approvers_count: int
    approvers: list[Approver]
    fully_approved: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChallengeStatus:
        """Create from API response dictionary."""
        created_at = data.get("created_at", "")
        expires_at = data.get("expires_at", "")

        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))

        approvers = [Approver.from_dict(a) for a in data.get("approvers", [])]

        return cls(
            challenge_id=data["challenge_id"],
            action=data.get("action", ""),
            agent_spiffe_id=data.get("agent_spiffe_id", ""),
            created_at=created_at,
            expires_at=expires_at,
            expired=data.get("expired", False),
            requires_dual_control=data.get("requires_dual_control", False),
            approvers_needed=data.get("approvers_needed", 1),
            approvers_count=data.get("approvers_count", 0),
            approvers=approvers,
            fully_approved=data.get("fully_approved", False),
        )
