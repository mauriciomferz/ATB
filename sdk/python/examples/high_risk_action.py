"""Example of high-risk action with dual control."""

from atb import AccountableParty, ATBClient, ATBConfig, PoABuilder
from atb.exceptions import AuthorizationDeniedError
from atb.poa import DualControl


def main():
    config = ATBConfig(
        broker_url="http://localhost:8080",
        private_key_path="./private.key",
    )

    with ATBClient(config) as client:
        # Build a PoA for a high-risk financial action
        poa = (
            PoABuilder()
            .for_agent("spiffe://atb.example/agent/finance-bot")
            .action("sap.payment.approve")
            .with_params(
                payment_id="PAY-2024-001",
                amount=500000,
                currency="EUR",
                vendor_id="V-98765",
                bank_account="DE89370400440532013000",
            )
            .with_constraints(
                liability_cap=1000000,
                require_dual_control=True,
                geo_fence=["DE", "AT", "CH"],  # DACH region only
            )
            .legal(
                jurisdiction="DE",
                accountable_party=AccountableParty(
                    type="user",
                    id="cfo@example.com",
                    display_name="Jane Smith (CFO)",
                ),
                approval_ref="SNOW-CHG0098765",
                dual_control=DualControl(
                    required=True,
                    approver=AccountableParty(
                        type="role",
                        id="treasury-approver",
                        display_name="Treasury Department Approver",
                    ),
                    approved_at="2024-01-15T10:30:00Z",
                ),
                regulation_refs=["SOX", "NIS2", "EU-AI-Act"],
                retention_days=2555,  # 7 years for financial records
            )
            .issuer("spiffe://atb.example/service/agentauth")
            .audience("spiffe://atb.example/service/broker")
            .ttl(60)  # Short TTL for high-risk actions
            .build()
        )

        try:
            result = client.execute(poa)

            if result.success:
                print("✅ High-risk action approved!")
                print("   Payment ID: PAY-2024-001")
                print("   Amount: €500,000")
                print(f"   Audit ID: {result.audit_id}")
                print("   Keep this for compliance records.")
            else:
                print(f"⚠️ Action completed with warnings: {result.error}")

        except AuthorizationDeniedError as e:
            print("❌ Action DENIED by policy")
            print(f"   Reason: {e.reason}")
            print(f"   Details: {e.details}")
            print("\n   This denial has been logged for audit purposes.")


if __name__ == "__main__":
    main()
