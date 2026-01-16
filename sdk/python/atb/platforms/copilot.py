"""Microsoft Copilot / Azure AI integration for ATB.

This connector supports:
- Microsoft 365 Copilot
- Azure OpenAI agents
- Power Platform AI Builder
- Dynamics 365 Copilot

Authentication: Entra ID (Azure AD) JWT tokens
"""

import base64
import json
from typing import Any

from atb.platforms.base import ActionResult, PlatformConnector, PlatformIdentity


class CopilotConnector(PlatformConnector):
    """Microsoft Copilot integration for ATB.

    Example usage:
        ```python
        from atb import ATBClient
        from atb.platforms import CopilotConnector

        client = ATBClient(broker_url="https://atb.example.com")
        copilot = CopilotConnector(client)

        # Execute action with Entra ID token
        result = await copilot.execute(
            platform_token=entra_jwt,
            action="dynamics.contact.update",
            params={"contact_id": "123", "email": "new@example.com"},
        )
        ```
    """

    # Action mappings from Copilot plugins to ATB actions
    ACTION_MAP = {
        # Dynamics 365 CRM
        "dynamics.contact.read": "crm.contact.read",
        "dynamics.contact.update": "crm.contact.update",
        "dynamics.contact.create": "crm.contact.create",
        "dynamics.contact.delete": "crm.contact.delete",
        "dynamics.opportunity.read": "crm.opportunity.read",
        "dynamics.opportunity.update": "crm.opportunity.update",
        "dynamics.opportunity.close": "crm.opportunity.close",
        # Dynamics 365 Finance
        "dynamics.vendor.read": "erp.vendor.read",
        "dynamics.vendor.create": "erp.vendor.create",
        "dynamics.vendor.bank_change": "erp.vendor.bank_change",
        "dynamics.payment.approve": "erp.payment.approve",
        "dynamics.journal.post": "erp.journal.post",
        # SharePoint
        "sharepoint.file.read": "docs.file.read",
        "sharepoint.file.write": "docs.file.write",
        "sharepoint.file.share": "docs.file.share",
        # Teams
        "teams.message.send": "comms.message.send",
        "teams.meeting.schedule": "comms.meeting.schedule",
        # Power Platform
        "power.flow.trigger": "automation.flow.trigger",
        "power.app.invoke": "automation.app.invoke",
        # Graph API general
        "graph.user.read": "identity.user.read",
        "graph.group.read": "identity.group.read",
        "graph.mail.send": "comms.email.send",
    }

    # Risk tier overrides for specific actions
    HIGH_RISK_ACTIONS = {
        "erp.vendor.bank_change",
        "erp.payment.approve",
        "erp.journal.post",
        "crm.opportunity.close",
    }

    def __init__(self, atb_client, tenant_id: str | None = None):
        """Initialize Copilot connector.

        Args:
            atb_client: ATB client instance
            tenant_id: Azure tenant ID (optional, extracted from token if not provided)
        """
        super().__init__(atb_client, "microsoft_copilot")
        self.tenant_id = tenant_id

    def extract_identity(self, platform_token: str) -> PlatformIdentity:
        """Extract identity from Entra ID JWT token.

        Args:
            platform_token: Entra ID JWT token

        Returns:
            PlatformIdentity with Azure AD claims
        """
        # Decode JWT payload (without verification - ATB does full validation)
        parts = platform_token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        # Add padding if needed
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        return PlatformIdentity(
            platform="microsoft_copilot",
            subject=payload.get("oid") or payload.get("sub", ""),
            tenant_id=payload.get("tid") or self.tenant_id,
            display_name=payload.get("name"),
            email=payload.get("preferred_username") or payload.get("upn"),
            roles=payload.get("roles", []),
            raw_token=platform_token,
        )

    def map_action(self, platform_action: str) -> str:
        """Map Copilot plugin action to ATB action.

        Args:
            platform_action: Copilot action (e.g., "dynamics.vendor.bank_change")

        Returns:
            ATB action string
        """
        # Direct mapping if exists
        if platform_action in self.ACTION_MAP:
            return self.ACTION_MAP[platform_action]

        # Fallback: pass through with copilot prefix
        return f"copilot.{platform_action}"

    def build_constraints(
        self,
        action: str,
        params: dict[str, Any],
        identity: PlatformIdentity,
    ) -> dict[str, Any]:
        """Build constraints from Copilot context.

        Args:
            action: ATB action name
            params: Action parameters
            identity: Platform identity

        Returns:
            Constraints dict for PoA
        """
        constraints: dict[str, Any] = {
            "platform": "microsoft_copilot",
            "tenant_id": identity.tenant_id,
        }

        # High-risk actions require dual control
        if action in self.HIGH_RISK_ACTIONS:
            constraints["dual_control"] = True

        # Add amount limits for financial actions
        if action.startswith("erp.payment") or action.startswith("erp.journal"):
            amount = params.get("amount")
            if amount:
                constraints["max_amount"] = amount
                constraints["currency"] = params.get("currency", "USD")

        # Add user roles for authorization
        if identity.roles:
            constraints["required_roles"] = identity.roles

        return constraints

    # Pre-built action helpers

    async def read_contact(
        self,
        platform_token: str,
        contact_id: str,
    ) -> ActionResult:
        """Read a CRM contact.

        Args:
            platform_token: Entra ID token
            contact_id: Contact identifier

        Returns:
            ActionResult with contact data
        """
        return await self.execute(
            platform_token=platform_token,
            action="dynamics.contact.read",
            params={"contact_id": contact_id},
            legal_basis="legitimate_interest",
        )

    async def update_vendor_bank(
        self,
        platform_token: str,
        vendor_id: str,
        bank_account: str,
        routing_number: str,
        approver_email: str,
    ) -> ActionResult:
        """Change vendor bank details (HIGH RISK - requires dual control).

        Args:
            platform_token: Entra ID token
            vendor_id: Vendor identifier
            bank_account: New bank account number
            routing_number: Bank routing number
            approver_email: Email of second approver

        Returns:
            ActionResult with update status
        """
        return await self.execute(
            platform_token=platform_token,
            action="dynamics.vendor.bank_change",
            params={
                "vendor_id": vendor_id,
                "bank_account": bank_account,
                "routing_number": routing_number,
                "approver": approver_email,
            },
            legal_basis="contract",
        )

    async def approve_payment(
        self,
        platform_token: str,
        payment_id: str,
        amount: float,
        currency: str = "USD",
    ) -> ActionResult:
        """Approve a payment (HIGH RISK).

        Args:
            platform_token: Entra ID token
            payment_id: Payment identifier
            amount: Payment amount
            currency: Currency code

        Returns:
            ActionResult with approval status
        """
        return await self.execute(
            platform_token=platform_token,
            action="dynamics.payment.approve",
            params={
                "payment_id": payment_id,
                "amount": amount,
                "currency": currency,
            },
            legal_basis="contract",
        )
