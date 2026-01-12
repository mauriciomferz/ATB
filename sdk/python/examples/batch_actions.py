#!/usr/bin/env python3
"""
Example: Batch Action Execution with ATB SDK

This example demonstrates how to execute multiple actions in batch,
with proper error handling and result aggregation.
"""

import asyncio

from atb import AccountableParty, ActionResult, AsyncATBClient, PoABuilder


async def execute_batch_actions(
    client: AsyncATBClient,
    private_key: str,
    user_email: str,
) -> list[ActionResult]:
    """Execute a batch of vendor operations."""

    # Define batch of actions
    vendor_operations = [
        {"action": "sap.vendor.read", "vendor_id": "V-001"},
        {"action": "sap.vendor.read", "vendor_id": "V-002"},
        {"action": "sap.vendor.read", "vendor_id": "V-003"},
        {"action": "sap.payment.list", "vendor_id": "V-001", "limit": 10},
    ]

    # Build PoA mandates for each action
    poas = []
    for op in vendor_operations:
        params = {k: v for k, v in op.items() if k != "action"}
        poa = (
            PoABuilder()
            .for_agent("spiffe://atb.example/agent/batch-processor")
            .action(op["action"])
            .with_params(**params)
            .legal(
                jurisdiction="DE",
                accountable_party=AccountableParty(
                    type="user",
                    id=user_email,
                    display_name="Batch User",
                ),
            )
            .build()
        )
        poas.append(poa)

    # Execute all actions concurrently
    tasks = [client.execute(poa, private_key=private_key) for poa in poas]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    successful = []
    failed = []

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"Action {vendor_operations[i]['action']} failed: {result}")
            failed.append((vendor_operations[i], result))
        elif result.success:
            print(f"Action {vendor_operations[i]['action']} succeeded")
            successful.append((vendor_operations[i], result))
        else:
            print(f"Action {vendor_operations[i]['action']} denied: {result.error}")
            failed.append((vendor_operations[i], result))

    print(f"\nSummary: {len(successful)} succeeded, {len(failed)} failed")
    return results


async def main():
    """Main entry point."""
    # Load private key (in production, use secure key management)
    private_key = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END EC PRIVATE KEY-----"""

    async with AsyncATBClient() as client:
        await execute_batch_actions(
            client,
            private_key=private_key,
            user_email="batch-user@example.com",
        )


if __name__ == "__main__":
    asyncio.run(main())
