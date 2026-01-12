"""Basic example of using the ATB SDK."""

from atb import ATBClient, ATBConfig, PoABuilder, AccountableParty


def main():
    # Configure the client
    config = ATBConfig(
        broker_url="http://localhost:8080",
        private_key_path="./private.key",
    )

    # Create a client
    with ATBClient(config) as client:
        # Build a PoA for a low-risk action
        poa = (
            PoABuilder()
            .for_agent("spiffe://atb.example/agent/copilot")
            .action("crm.contact.read")
            .with_params(
                contact_id="C-12345",
                fields=["name", "email", "phone"],
            )
            .legal(
                jurisdiction="US",
                accountable_party=AccountableParty(
                    type="user",
                    id="bob@example.com",
                    display_name="Bob Jones",
                ),
            )
            .ttl(300)  # 5 minutes
            .build()
        )

        # Execute the action
        result = client.execute(poa)

        if result.success:
            print(f"✅ Action completed successfully!")
            print(f"   Audit ID: {result.audit_id}")
            print(f"   Response: {result.data}")
        else:
            print(f"❌ Action failed: {result.error}")


if __name__ == "__main__":
    main()
