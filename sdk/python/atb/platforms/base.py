"""Base platform connector interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from atb.client import ATBClient


@dataclass
class PlatformIdentity:
    """Identity information from the platform."""

    platform: str
    subject: str
    tenant_id: str | None = None
    display_name: str | None = None
    email: str | None = None
    roles: list[str] | None = None
    raw_token: str | None = None


@dataclass
class ActionResult:
    """Result of an action execution."""

    success: bool
    data: dict[str, Any] | None = None
    error: str | None = None
    audit_id: str | None = None
    risk_tier: str | None = None


class PlatformConnector(ABC):
    """Base class for platform-specific ATB integrations.

    Platform connectors provide:
    - Identity extraction from platform tokens (Entra ID, Salesforce, etc.)
    - Action mapping to ATB action names
    - Constraint building from platform context
    - Pre-built action helpers for common operations
    """

    def __init__(
        self,
        atb_client: ATBClient,
        platform_name: str,
    ):
        """Initialize the platform connector.

        Args:
            atb_client: ATB client instance for broker communication
            platform_name: Name of the platform (e.g., "copilot", "salesforce")
        """
        self.atb = atb_client
        self.platform_name = platform_name

    @abstractmethod
    def extract_identity(self, platform_token: str) -> PlatformIdentity:
        """Extract identity information from platform token.

        Args:
            platform_token: JWT or opaque token from the platform

        Returns:
            PlatformIdentity with extracted claims
        """
        pass

    @abstractmethod
    def map_action(self, platform_action: str) -> str:
        """Map platform-specific action to ATB action name.

        Args:
            platform_action: Platform's action identifier

        Returns:
            ATB-compatible action string (e.g., "sap.vendor.change")
        """
        pass

    @abstractmethod
    def build_constraints(
        self,
        action: str,
        params: dict[str, Any],
        identity: PlatformIdentity,
    ) -> dict[str, Any]:
        """Build ATB constraints from platform context.

        Args:
            action: ATB action name
            params: Action parameters
            identity: Platform identity

        Returns:
            Constraints dict for PoA token
        """
        pass

    async def execute(
        self,
        platform_token: str,
        action: str,
        params: dict[str, Any],
        legal_basis: str = "legitimate_interest",
        jurisdiction: str = "US",
    ) -> ActionResult:
        """Execute an action through ATB with platform identity.

        This is the main entry point for platform integrations.

        Args:
            platform_token: Platform authentication token
            action: Platform-specific action name
            params: Action parameters
            legal_basis: Legal basis for processing
            jurisdiction: Applicable jurisdiction

        Returns:
            ActionResult with success status and data
        """
        # Extract identity from platform token
        identity = self.extract_identity(platform_token)

        # Map to ATB action
        atb_action = self.map_action(action)

        # Build constraints
        constraints = self.build_constraints(atb_action, params, identity)

        # Request PoA from AgentAuth
        poa = await self.atb.request_poa(
            action=atb_action,
            constraints=constraints,
            legal_basis={
                "basis": legal_basis,
                "jurisdiction": jurisdiction,
                "accountable_party": {
                    "type": "human",
                    "id": identity.email or identity.subject,
                },
            },
            platform_identity={
                "platform": self.platform_name,
                "sub": identity.subject,
                "tenant_id": identity.tenant_id,
            },
        )

        # Execute through broker
        result = await self.atb.execute(poa, params)

        return ActionResult(
            success=result.get("success", False),
            data=result.get("data"),
            error=result.get("error"),
            audit_id=result.get("audit_id"),
            risk_tier=result.get("risk_tier"),
        )
