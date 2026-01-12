#!/usr/bin/env python3
"""
Example: Policy Pre-Check with ATB SDK

This example demonstrates how to check if an action would be allowed
before actually executing it. Useful for UX (disable buttons) or
validation flows.
"""

from atb import ATBClient, ATBConfig


def check_user_permissions(
    client: ATBClient,
    user_id: str,
    actions: list[str],
) -> dict[str, bool]:
    """Check which actions a user is authorized to perform."""

    results = {}
    agent_spiffe_id = f"spiffe://atb.example/user/{user_id}"

    for action in actions:
        try:
            policy_result = client.check_policy(
                action=action,
                agent_spiffe_id=agent_spiffe_id,
                params={},
            )
            results[action] = policy_result.get("allow", False)
        except Exception as e:
            print(f"Error checking {action}: {e}")
            results[action] = False

    return results


def main():
    """Main entry point."""
    config = ATBConfig(broker_url="http://localhost:8080")
    client = ATBClient(config)

    # Define actions to check
    actions_to_check = [
        "sap.vendor.read",
        "sap.vendor.create",
        "sap.vendor.update",
        "sap.vendor.delete",
        "sap.payment.approve",
        "sap.payment.execute",
    ]

    # Check permissions for different users
    users = ["alice", "bob", "readonly-service"]

    for user in users:
        print(f"\nPermissions for {user}:")
        print("-" * 40)

        permissions = check_user_permissions(client, user, actions_to_check)

        for action, allowed in permissions.items():
            status = "✓" if allowed else "✗"
            print(f"  {status} {action}")


if __name__ == "__main__":
    main()
