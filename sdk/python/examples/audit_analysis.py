#!/usr/bin/env python3
"""
Example: Audit Log Query with ATB SDK

This example demonstrates how to query and analyze audit logs
from the ATB broker.
"""

from collections import Counter
from datetime import datetime, timedelta

from atb import ATBClient, ATBConfig


def analyze_audit_logs(client: ATBClient, hours: int = 24):
    """Analyze recent audit logs."""

    # Query audit logs
    since = datetime.utcnow() - timedelta(hours=hours)
    logs = client.get_audit_logs(
        limit=1000,
        since=since.isoformat() + "Z",
    )

    if not logs:
        print("No audit logs found")
        return

    print(f"\n=== Audit Log Analysis (last {hours} hours) ===\n")
    print(f"Total events: {len(logs)}")

    # Analyze by decision
    decisions = Counter(log.get("decision") for log in logs)
    print("\nBy Decision:")
    print(f"  Allowed: {decisions.get('allow', 0)}")
    print(f"  Denied: {decisions.get('deny', 0)}")

    # Analyze by risk tier
    risk_tiers = Counter(log.get("risk_tier") for log in logs)
    print("\nBy Risk Tier:")
    for tier in ["LOW", "MEDIUM", "HIGH"]:
        count = risk_tiers.get(tier, 0)
        print(f"  {tier}: {count}")

    # Analyze by action
    actions = Counter(log.get("action") for log in logs)
    print("\nTop 5 Actions:")
    for action, count in actions.most_common(5):
        print(f"  {action}: {count}")

    # Analyze by agent
    agents = Counter(log.get("agent", "").split("/")[-1] for log in logs)
    print("\nTop 5 Agents:")
    for agent, count in agents.most_common(5):
        print(f"  {agent}: {count}")

    # Find denied high-risk actions
    denied_high_risk = [
        log for log in logs
        if log.get("decision") == "deny" and log.get("risk_tier") == "HIGH"
    ]
    if denied_high_risk:
        print(f"\n⚠️  Denied High-Risk Actions: {len(denied_high_risk)}")
        for log in denied_high_risk[:5]:
            print(f"  - {log.get('action')} by {log.get('agent', '').split('/')[-1]}")
            print(f"    Reason: {log.get('deny_reason', 'Unknown')}")


def export_logs_csv(client: ATBClient, filename: str = "audit_logs.csv"):
    """Export audit logs to CSV."""
    import csv

    logs = client.get_audit_logs(limit=10000)

    with open(filename, "w", newline="") as f:
        fieldnames = [
            "timestamp", "action", "agent", "decision",
            "risk_tier", "duration_ms", "audit_id"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for log in logs:
            writer.writerow({
                "timestamp": log.get("timestamp"),
                "action": log.get("action"),
                "agent": log.get("agent"),
                "decision": log.get("decision"),
                "risk_tier": log.get("risk_tier"),
                "duration_ms": log.get("duration_ms"),
                "audit_id": log.get("id"),
            })

    print(f"Exported {len(logs)} logs to {filename}")


def main():
    """Main entry point."""
    config = ATBConfig(broker_url="http://localhost:8080")
    client = ATBClient(config)

    # Analyze logs
    analyze_audit_logs(client, hours=24)

    # Export to CSV
    export_logs_csv(client)


if __name__ == "__main__":
    main()
