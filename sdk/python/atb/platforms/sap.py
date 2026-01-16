"""SAP integration for ATB.

This connector supports:
- SAP Joule AI assistant
- SAP S/4HANA Cloud
- SAP Business Technology Platform
- SAP Ariba

Authentication: SAP OAuth2 / SAML tokens
"""

import base64
import json
from typing import Any

from atb.platforms.base import ActionResult, PlatformConnector, PlatformIdentity


class SAPConnector(PlatformConnector):
    """SAP Joule / S/4HANA integration for ATB.

    Example usage:
        ```python
        from atb import ATBClient
        from atb.platforms import SAPConnector

        client = ATBClient(broker_url="https://atb.example.com")
        sap = SAPConnector(client, system_id="S4H")

        # Execute action with SAP token
        result = await sap.execute(
            platform_token=sap_jwt,
            action="vendor.bank_change",
            params={"vendor_id": "1000", "bank_account": "..."},
        )
        ```
    """

    # Action mappings from SAP to ATB actions
    ACTION_MAP = {
        # Vendor Management
        "vendor.read": "sap.vendor.read",
        "vendor.create": "sap.vendor.create",
        "vendor.update": "sap.vendor.update",
        "vendor.bank_change": "sap.vendor.bank_change",
        "vendor.block": "sap.vendor.block",
        # Payments & Finance
        "payment.create": "sap.payment.create",
        "payment.approve": "sap.payment.approve",
        "payment.release": "sap.payment.release",
        "journal.post": "sap.journal.post",
        "journal.reverse": "sap.journal.reverse",
        # Procurement
        "po.create": "sap.po.create",
        "po.approve": "sap.po.approve",
        "po.release": "sap.po.release",
        "pr.create": "sap.pr.create",
        "pr.approve": "sap.pr.approve",
        "gr.post": "sap.gr.post",
        "ir.post": "sap.ir.post",
        # Materials Management
        "material.read": "sap.material.read",
        "material.create": "sap.material.create",
        "material.update": "sap.material.update",
        "stock.transfer": "sap.stock.transfer",
        "stock.adjustment": "sap.stock.adjustment",
        # Human Capital
        "employee.read": "sap.hcm.employee.read",
        "employee.update": "sap.hcm.employee.update",
        "payroll.run": "sap.hcm.payroll.run",
        "compensation.change": "sap.hcm.compensation.change",
        # Sales & Distribution
        "sales_order.create": "sap.sd.order.create",
        "sales_order.change": "sap.sd.order.change",
        "delivery.create": "sap.sd.delivery.create",
        "billing.create": "sap.sd.billing.create",
        # Ariba
        "ariba.contract.create": "sap.ariba.contract.create",
        "ariba.contract.approve": "sap.ariba.contract.approve",
        "ariba.sourcing.award": "sap.ariba.sourcing.award",
    }

    # High-risk actions requiring dual control
    HIGH_RISK_ACTIONS = {
        "sap.vendor.bank_change",
        "sap.payment.approve",
        "sap.payment.release",
        "sap.journal.post",
        "sap.po.approve",
        "sap.hcm.payroll.run",
        "sap.hcm.compensation.change",
        "sap.ariba.contract.approve",
        "sap.ariba.sourcing.award",
    }

    # Amount thresholds for escalation (in EUR)
    AMOUNT_THRESHOLDS = {
        "sap.payment.approve": 10000,
        "sap.payment.release": 50000,
        "sap.journal.post": 100000,
        "sap.po.approve": 25000,
        "sap.ariba.contract.approve": 100000,
    }

    def __init__(
        self,
        atb_client,
        system_id: str | None = None,
        client_number: str = "100",
    ):
        """Initialize SAP connector.

        Args:
            atb_client: ATB client instance
            system_id: SAP System ID (SID)
            client_number: SAP client number
        """
        super().__init__(atb_client, "sap_joule")
        self.system_id = system_id
        self.client_number = client_number

    def extract_identity(self, platform_token: str) -> PlatformIdentity:
        """Extract identity from SAP token.

        SAP tokens can be:
        - JWT tokens from SAP IAS
        - SAML assertions
        - OAuth2 access tokens

        Args:
            platform_token: SAP authentication token

        Returns:
            PlatformIdentity with SAP claims
        """
        try:
            parts = platform_token.split(".")
            if len(parts) == 3:
                payload_b64 = parts[1]
                padding = 4 - len(payload_b64) % 4
                if padding != 4:
                    payload_b64 += "=" * padding
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                # SAP IAS specific claims
                return PlatformIdentity(
                    platform="sap_joule",
                    subject=payload.get("user_uuid") or payload.get("sub", ""),
                    tenant_id=payload.get("zone_uuid") or self.system_id,
                    display_name=payload.get("given_name", "")
                    + " "
                    + payload.get("family_name", ""),
                    email=payload.get("email"),
                    roles=payload.get("xs.system.attributes", {}).get("xs.rolecollections", []),
                    raw_token=platform_token,
                )
        except Exception:
            pass

        return PlatformIdentity(
            platform="sap_joule",
            subject="sap_user",
            tenant_id=self.system_id,
            raw_token=platform_token,
        )

    def map_action(self, platform_action: str) -> str:
        """Map SAP action to ATB action.

        Args:
            platform_action: SAP action (e.g., "vendor.bank_change")

        Returns:
            ATB action string
        """
        if platform_action in self.ACTION_MAP:
            return self.ACTION_MAP[platform_action]
        return f"sap.{platform_action}"

    def build_constraints(
        self,
        action: str,
        params: dict[str, Any],
        identity: PlatformIdentity,
    ) -> dict[str, Any]:
        """Build constraints from SAP context.

        Args:
            action: ATB action name
            params: Action parameters
            identity: Platform identity

        Returns:
            Constraints dict for PoA
        """
        constraints: dict[str, Any] = {
            "platform": "sap_joule",
            "system_id": identity.tenant_id or self.system_id,
            "client": self.client_number,
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
            constraints["currency"] = params.get("currency", "EUR")

        # SAP-specific: company code
        if "company_code" in params:
            constraints["company_code"] = params["company_code"]

        # SAP-specific: document type
        if "doc_type" in params:
            constraints["document_type"] = params["doc_type"]

        return constraints

    # Pre-built action helpers

    async def change_vendor_bank(
        self,
        platform_token: str,
        vendor_id: str,
        bank_country: str,
        bank_key: str,
        bank_account: str,
        iban: str | None = None,
        approver_email: str | None = None,
    ) -> ActionResult:
        """Change vendor bank details (HIGH RISK - requires dual control).

        This is one of the most sensitive SAP operations and is a
        common target for business email compromise attacks.

        Args:
            platform_token: SAP access token
            vendor_id: Vendor number
            bank_country: Bank country key
            bank_key: Bank routing number
            bank_account: Bank account number
            iban: IBAN (optional)
            approver_email: Second approver email

        Returns:
            ActionResult with update status
        """
        params = {
            "vendor_id": vendor_id,
            "bank_country": bank_country,
            "bank_key": bank_key,
            "bank_account": bank_account,
        }
        if iban:
            params["iban"] = iban
        if approver_email:
            params["approver"] = approver_email

        return await self.execute(
            platform_token=platform_token,
            action="vendor.bank_change",
            params=params,
            legal_basis="contract",
        )

    async def approve_payment(
        self,
        platform_token: str,
        payment_document: str,
        company_code: str,
        fiscal_year: str,
        amount: float,
        currency: str = "EUR",
    ) -> ActionResult:
        """Approve a payment run (HIGH RISK).

        Args:
            platform_token: SAP access token
            payment_document: Payment document number
            company_code: Company code
            fiscal_year: Fiscal year
            amount: Payment amount
            currency: Currency code

        Returns:
            ActionResult with approval status
        """
        return await self.execute(
            platform_token=platform_token,
            action="payment.approve",
            params={
                "payment_document": payment_document,
                "company_code": company_code,
                "fiscal_year": fiscal_year,
                "amount": amount,
                "currency": currency,
            },
            legal_basis="contract",
        )

    async def post_journal_entry(
        self,
        platform_token: str,
        company_code: str,
        doc_date: str,
        posting_date: str,
        doc_type: str,
        line_items: list[dict[str, Any]],
        reference: str | None = None,
    ) -> ActionResult:
        """Post a journal entry (HIGH RISK for large amounts).

        Args:
            platform_token: SAP access token
            company_code: Company code
            doc_date: Document date
            posting_date: Posting date
            doc_type: Document type (SA, AB, etc.)
            line_items: List of line items with accounts and amounts
            reference: Reference text

        Returns:
            ActionResult with document number
        """
        # Calculate total amount
        total_amount = sum(abs(item.get("amount", 0)) for item in line_items)

        return await self.execute(
            platform_token=platform_token,
            action="journal.post",
            params={
                "company_code": company_code,
                "doc_date": doc_date,
                "posting_date": posting_date,
                "doc_type": doc_type,
                "line_items": line_items,
                "reference": reference,
                "amount": total_amount,
            },
            legal_basis="contract",
        )

    async def create_purchase_order(
        self,
        platform_token: str,
        vendor_id: str,
        company_code: str,
        items: list[dict[str, Any]],
        currency: str = "EUR",
    ) -> ActionResult:
        """Create a purchase order.

        Args:
            platform_token: SAP access token
            vendor_id: Vendor number
            company_code: Company code
            items: List of PO items
            currency: Currency code

        Returns:
            ActionResult with PO number
        """
        total_amount = sum(
            item.get("quantity", 0) * item.get("price", 0) for item in items
        )

        return await self.execute(
            platform_token=platform_token,
            action="po.create",
            params={
                "vendor_id": vendor_id,
                "company_code": company_code,
                "items": items,
                "currency": currency,
                "amount": total_amount,
            },
            legal_basis="contract",
        )
