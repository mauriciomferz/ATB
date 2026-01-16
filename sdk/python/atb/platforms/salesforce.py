"""Salesforce Agentforce integration for ATB.

This connector supports:
- Salesforce Agentforce AI agents
- Einstein GPT actions
- Flow-triggered agent actions
- Apex-based integrations

Authentication: Salesforce OAuth2 JWT tokens
"""

import base64
import json
from typing import Any

from atb.platforms.base import ActionResult, PlatformConnector, PlatformIdentity


class SalesforceConnector(PlatformConnector):
    """Salesforce Agentforce integration for ATB.

    Example usage:
        ```python
        from atb import ATBClient
        from atb.platforms import SalesforceConnector

        client = ATBClient(broker_url="https://atb.example.com")
        salesforce = SalesforceConnector(client, org_id="00D...")

        # Execute action with Salesforce token
        result = await salesforce.execute(
            platform_token=sf_access_token,
            action="opportunity.close",
            params={"opportunity_id": "006...", "amount": 50000},
        )
        ```
    """

    # Action mappings from Salesforce to ATB actions
    ACTION_MAP = {
        # Opportunities
        "opportunity.read": "crm.opportunity.read",
        "opportunity.create": "crm.opportunity.create",
        "opportunity.update": "crm.opportunity.update",
        "opportunity.close": "crm.opportunity.close",
        "opportunity.delete": "crm.opportunity.delete",
        # Accounts
        "account.read": "crm.account.read",
        "account.create": "crm.account.create",
        "account.update": "crm.account.update",
        # Contacts
        "contact.read": "crm.contact.read",
        "contact.create": "crm.contact.create",
        "contact.update": "crm.contact.update",
        "contact.delete": "crm.contact.delete",
        # Cases
        "case.read": "support.case.read",
        "case.create": "support.case.create",
        "case.update": "support.case.update",
        "case.close": "support.case.close",
        "case.escalate": "support.case.escalate",
        # Contracts
        "contract.read": "legal.contract.read",
        "contract.create": "legal.contract.create",
        "contract.activate": "legal.contract.activate",
        "contract.amend": "legal.contract.amend",
        "contract.terminate": "legal.contract.terminate",
        # Orders & Quotes
        "order.create": "commerce.order.create",
        "order.activate": "commerce.order.activate",
        "quote.create": "commerce.quote.create",
        "quote.approve": "commerce.quote.approve",
        # Billing
        "invoice.create": "billing.invoice.create",
        "credit.issue": "billing.credit.issue",
        "refund.process": "billing.refund.process",
        # Knowledge
        "article.read": "knowledge.article.read",
        "article.create": "knowledge.article.create",
        "article.publish": "knowledge.article.publish",
    }

    # High-risk actions requiring dual control
    HIGH_RISK_ACTIONS = {
        "crm.opportunity.close",
        "legal.contract.activate",
        "legal.contract.terminate",
        "commerce.quote.approve",
        "billing.credit.issue",
        "billing.refund.process",
    }

    # Amount thresholds for escalation
    AMOUNT_THRESHOLDS = {
        "crm.opportunity.close": 100000,  # $100k opportunities
        "commerce.quote.approve": 50000,  # $50k quotes
        "billing.credit.issue": 10000,  # $10k credits
        "billing.refund.process": 5000,  # $5k refunds
    }

    def __init__(
        self,
        atb_client,
        org_id: str | None = None,
        instance_url: str | None = None,
    ):
        """Initialize Salesforce connector.

        Args:
            atb_client: ATB client instance
            org_id: Salesforce Organization ID (optional)
            instance_url: Salesforce instance URL (optional)
        """
        super().__init__(atb_client, "salesforce_agentforce")
        self.org_id = org_id
        self.instance_url = instance_url

    def extract_identity(self, platform_token: str) -> PlatformIdentity:
        """Extract identity from Salesforce access token.

        Note: Salesforce access tokens are opaque, so we use
        the userinfo endpoint or decode if it's a JWT.

        Args:
            platform_token: Salesforce access token

        Returns:
            PlatformIdentity with Salesforce claims
        """
        # Try to decode as JWT (some Salesforce tokens are JWTs)
        try:
            parts = platform_token.split(".")
            if len(parts) == 3:
                payload_b64 = parts[1]
                padding = 4 - len(payload_b64) % 4
                if padding != 4:
                    payload_b64 += "=" * padding
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                return PlatformIdentity(
                    platform="salesforce_agentforce",
                    subject=payload.get("sub", ""),
                    tenant_id=self.org_id or payload.get("organization_id"),
                    display_name=payload.get("name"),
                    email=payload.get("email") or payload.get("username"),
                    roles=payload.get("custom_attributes", {}).get("roles", []),
                    raw_token=platform_token,
                )
        except Exception:
            pass

        # Fallback for opaque tokens
        return PlatformIdentity(
            platform="salesforce_agentforce",
            subject="opaque_token",
            tenant_id=self.org_id,
            raw_token=platform_token,
        )

    def map_action(self, platform_action: str) -> str:
        """Map Salesforce action to ATB action.

        Args:
            platform_action: Salesforce action (e.g., "opportunity.close")

        Returns:
            ATB action string
        """
        if platform_action in self.ACTION_MAP:
            return self.ACTION_MAP[platform_action]
        return f"salesforce.{platform_action}"

    def build_constraints(
        self,
        action: str,
        params: dict[str, Any],
        identity: PlatformIdentity,
    ) -> dict[str, Any]:
        """Build constraints from Salesforce context.

        Args:
            action: ATB action name
            params: Action parameters
            identity: Platform identity

        Returns:
            Constraints dict for PoA
        """
        constraints: dict[str, Any] = {
            "platform": "salesforce_agentforce",
            "org_id": identity.tenant_id,
        }

        # High-risk actions require dual control
        if action in self.HIGH_RISK_ACTIONS:
            constraints["dual_control"] = True

        # Check amount thresholds
        amount = params.get("amount") or params.get("value") or 0
        threshold = self.AMOUNT_THRESHOLDS.get(action)
        if threshold and amount >= threshold:
            constraints["dual_control"] = True
            constraints["requires_manager_approval"] = True

        # Add amount constraints
        if amount:
            constraints["max_amount"] = amount
            constraints["currency"] = params.get("currency", "USD")

        # Salesforce-specific: record ownership
        if "owner_id" in params:
            constraints["record_owner"] = params["owner_id"]

        return constraints

    # Pre-built action helpers

    async def close_opportunity(
        self,
        platform_token: str,
        opportunity_id: str,
        amount: float,
        stage: str = "Closed Won",
        close_date: str | None = None,
    ) -> ActionResult:
        """Close an opportunity (HIGH RISK for large deals).

        Args:
            platform_token: Salesforce access token
            opportunity_id: Opportunity record ID
            amount: Deal amount
            stage: Close stage (Closed Won/Closed Lost)
            close_date: Close date (ISO format)

        Returns:
            ActionResult with update status
        """
        return await self.execute(
            platform_token=platform_token,
            action="opportunity.close",
            params={
                "opportunity_id": opportunity_id,
                "amount": amount,
                "stage": stage,
                "close_date": close_date,
            },
            legal_basis="contract",
        )

    async def issue_credit(
        self,
        platform_token: str,
        account_id: str,
        amount: float,
        reason: str,
        currency: str = "USD",
    ) -> ActionResult:
        """Issue a credit to an account (HIGH RISK).

        Args:
            platform_token: Salesforce access token
            account_id: Account record ID
            amount: Credit amount
            reason: Credit reason
            currency: Currency code

        Returns:
            ActionResult with credit record
        """
        return await self.execute(
            platform_token=platform_token,
            action="credit.issue",
            params={
                "account_id": account_id,
                "amount": amount,
                "reason": reason,
                "currency": currency,
            },
            legal_basis="contract",
        )

    async def process_refund(
        self,
        platform_token: str,
        order_id: str,
        amount: float,
        reason: str,
    ) -> ActionResult:
        """Process a refund (HIGH RISK).

        Args:
            platform_token: Salesforce access token
            order_id: Order record ID
            amount: Refund amount
            reason: Refund reason

        Returns:
            ActionResult with refund status
        """
        return await self.execute(
            platform_token=platform_token,
            action="refund.process",
            params={
                "order_id": order_id,
                "amount": amount,
                "reason": reason,
            },
            legal_basis="contract",
        )

    async def create_case(
        self,
        platform_token: str,
        subject: str,
        description: str,
        contact_id: str | None = None,
        priority: str = "Medium",
    ) -> ActionResult:
        """Create a support case.

        Args:
            platform_token: Salesforce access token
            subject: Case subject
            description: Case description
            contact_id: Related contact ID
            priority: Case priority

        Returns:
            ActionResult with case record
        """
        return await self.execute(
            platform_token=platform_token,
            action="case.create",
            params={
                "subject": subject,
                "description": description,
                "contact_id": contact_id,
                "priority": priority,
            },
            legal_basis="legitimate_interest",
        )
