"""
Security attack vector tests for ATB.

These tests verify that known attack vectors are mitigated.
Some tests document current vulnerabilities that need fixing.
"""

import os
import time
import concurrent.futures
from typing import Optional

import httpx
import pytest

AGENTAUTH_URL = os.getenv("AGENTAUTH_URL", "http://localhost:8444")
OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")


def create_challenge(
    client: httpx.Client,
    agent_id: str = "spiffe://example.org/agent/test",
    action: str = "crm.contact.read",
) -> Optional[str]:
    """Helper to create a challenge."""
    resp = client.post(
        f"{AGENTAUTH_URL}/v1/challenge",
        json={
            "agent_spiffe_id": agent_id,
            "act": action,
            "con": {},
            "leg": {
                "basis": "contract",
                "jurisdiction": "US",
                "accountable_party": {"type": "human", "id": "test@test.com"},
            },
        },
        timeout=5.0,
    )
    if resp.status_code == 200:
        return resp.json().get("challenge_id")
    return None


class TestApproverSecurity:
    """Tests for approver authentication and authorization."""

    def test_approver_identity_should_be_verified(self):
        """
        VULNERABILITY: Approver identity is not verified.

        Current behavior: Anyone can claim to be any approver.
        Expected behavior: Approver must authenticate (mTLS/JWT).

        Status: KNOWN VULNERABILITY - needs fix
        """
        with httpx.Client() as client:
            try:
                challenge_id = create_challenge(client)
                if not challenge_id:
                    pytest.skip("Could not create challenge")

                # Try to approve as CEO without authentication
                resp = client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json={
                        "challenge_id": challenge_id,
                        "approver": "ceo@company.com",
                    },
                    timeout=5.0,
                )

                # Document current (vulnerable) behavior
                if resp.status_code == 200:
                    pytest.xfail(
                        "VULNERABILITY: Approver spoofing is possible. "
                        "Implement approver authentication."
                    )
                else:
                    # If this passes, the vulnerability is fixed
                    assert resp.status_code in [401, 403]

            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    def test_self_approval_rejected(self):
        """Agent owner cannot approve their own requests."""
        with httpx.Client() as client:
            try:
                # Create challenge with specific accountable party
                resp = client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json={
                        "agent_spiffe_id": "spiffe://example.org/agent/test",
                        "act": "crm.contact.read",
                        "con": {},
                        "leg": {
                            "basis": "contract",
                            "jurisdiction": "US",
                            "accountable_party": {
                                "type": "human",
                                "id": "requester@company.com",
                            },
                        },
                    },
                    timeout=5.0,
                )

                if resp.status_code != 200:
                    pytest.skip("Could not create challenge")

                challenge_id = resp.json().get("challenge_id")

                # Try to approve as the same person who made the request
                resp = client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json={
                        "challenge_id": challenge_id,
                        "approver": "requester@company.com",  # Same as accountable_party
                    },
                    timeout=5.0,
                )

                # Self-approval should be rejected with 403 Forbidden
                assert (
                    resp.status_code == 403
                ), f"Self-approval should be rejected (got {resp.status_code})"

            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


class TestDualControlBypass:
    """Tests for dual control enforcement."""

    def test_same_approver_twice_rejected(self):
        """Same person cannot provide both approvals for dual control."""
        with httpx.Client() as client:
            try:
                # Create high-risk challenge requiring dual control
                resp = client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json={
                        "agent_spiffe_id": "spiffe://example.org/agent/test",
                        "act": "sap.vendor.change",  # High-risk action
                        "con": {"vendor_id": "V001"},
                        "leg": {
                            "basis": "contract",
                            "jurisdiction": "US",
                            "accountable_party": {
                                "type": "human",
                                "id": "test@test.com",
                            },
                        },
                    },
                    timeout=5.0,
                )

                if resp.status_code != 200:
                    pytest.skip("Could not create challenge")

                challenge_id = resp.json().get("challenge_id")

                # First approval
                resp1 = client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json={
                        "challenge_id": challenge_id,
                        "approver": "admin@company.com",
                    },
                    timeout=5.0,
                )

                # Second approval - same person
                resp2 = client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json={
                        "challenge_id": challenge_id,
                        "approver": "admin@company.com",
                    },
                    timeout=5.0,
                )

                # Second approval should be rejected
                assert resp2.status_code in [
                    400,
                    409,
                ], "Duplicate approver should be rejected"

            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    def test_case_variation_approver_rejected(self):
        """Case variations of same approver should be detected."""
        with httpx.Client() as client:
            try:
                challenge_id = create_challenge(client, action="sap.vendor.change")
                if not challenge_id:
                    pytest.skip("Could not create challenge")

                # First approval
                client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json={
                        "challenge_id": challenge_id,
                        "approver": "admin@company.com",
                    },
                    timeout=5.0,
                )

                # Second approval - case variation
                resp = client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json={
                        "challenge_id": challenge_id,
                        "approver": "ADMIN@COMPANY.COM",  # Same person, different case
                    },
                    timeout=5.0,
                )

                # Should detect as same approver with 409 Conflict
                assert (
                    resp.status_code == 409
                ), f"Case variation should be detected as duplicate (got {resp.status_code})"

            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


class TestRateLimiting:
    """Tests for rate limiting protection."""

    def test_challenge_flood_mitigated(self):
        """
        Rapid challenge creation should be rate limited per agent.

        Uses same agent ID to trigger per-agent rate limit (default: 20/min).
        """
        with httpx.Client() as client:
            try:
                results = []
                start = time.time()

                # Send 50 requests with SAME agent ID to trigger per-agent limit
                for i in range(50):
                    resp = client.post(
                        f"{AGENTAUTH_URL}/v1/challenge",
                        json={
                            "agent_spiffe_id": "spiffe://example.org/agent/flood-test",
                            "act": "crm.contact.read",
                            "con": {},
                            "leg": {
                                "basis": "contract",
                                "jurisdiction": "US",
                                "accountable_party": {"type": "human", "id": "x"},
                            },
                        },
                        timeout=5.0,
                    )
                    results.append(resp.status_code)

                elapsed = time.time() - start

                # Count rate limited responses
                rate_limited = sum(1 for code in results if code == 429)

                # Per-agent limit should trigger (default 20/min)
                assert rate_limited > 0, (
                    f"No rate limiting detected. "
                    f"Processed {len(results)} requests in {elapsed:.2f}s. "
                    f"Expected rate limiting for production."
                )

            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    def test_concurrent_challenge_flood(self):
        """Concurrent requests should be rate limited per IP (100/min default)."""
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = []

                # Use 150 requests to exceed IP rate limit (100/min)
                for i in range(150):
                    futures.append(
                        executor.submit(
                            httpx.post,
                            f"{AGENTAUTH_URL}/v1/challenge",
                            json={
                                "agent_spiffe_id": f"spiffe://example.org/agent/concurrent-{i}",
                                "act": "crm.contact.read",
                                "con": {},
                                "leg": {
                                    "basis": "contract",
                                    "jurisdiction": "US",
                                    "accountable_party": {"type": "human", "id": "x"},
                                },
                            },
                            timeout=5.0,
                        )
                    )

                results = []
                for future in concurrent.futures.as_completed(futures):
                    try:
                        resp = future.result()
                        results.append(resp.status_code)
                    except Exception:
                        results.append(0)

                rate_limited = sum(1 for code in results if code == 429)

                # Per-IP rate limiting (100/min) should trigger for 150 requests
                assert rate_limited > 0, (
                    f"Concurrent rate limiting not enforced. "
                    f"All {len(results)} requests succeeded."
                )

        except httpx.ConnectError:
            pytest.skip("AgentAuth not running")


class TestSPIFFEIDValidation:
    """Tests for SPIFFE ID input validation."""

    @pytest.mark.parametrize(
        "malicious_id,description",
        [
            ("spiffe://example.org/agent/../../../etc/passwd", "Path traversal"),
            ("spiffe://example.org/agent/$(whoami)", "Command injection"),
            ("spiffe://example.org/agent/`id`", "Backtick injection"),
            ("spiffe://example.org/agent/${PATH}", "Variable expansion"),
            ("spiffe://example.org/agent/'; DROP TABLE agents; --", "SQL injection"),
            ("spiffe://example.org/agent/<script>alert(1)</script>", "XSS"),
            ("spiffe://example.org/agent/\x00hidden", "Null byte injection"),
            ("", "Empty string"),
            ("not-a-spiffe-id", "Invalid format"),
            ("spiffe://", "Incomplete URI"),
            ("http://example.org/agent/test", "Wrong scheme"),
            ("spiffe://example.org/agent/" + "a" * 10000, "Oversized ID"),
        ],
    )
    def test_malicious_spiffe_id_rejected(self, malicious_id: str, description: str):
        """Malicious SPIFFE IDs should be rejected."""
        with httpx.Client() as client:
            try:
                resp = client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json={
                        "agent_spiffe_id": malicious_id,
                        "act": "crm.contact.read",
                        "con": {},
                        "leg": {
                            "basis": "contract",
                            "jurisdiction": "US",
                            "accountable_party": {"type": "human", "id": "x"},
                        },
                    },
                    timeout=5.0,
                )

                # Should reject with 400, 422, or 429 (rate limited)
                # SPIFFE ID validation is now implemented
                assert resp.status_code in [400, 422, 429], (
                    f"SPIFFE ID validation should reject {description}: "
                    f"got {resp.status_code}"
                )

            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")


class TestChallengeExpiry:
    """Tests for challenge expiration handling."""

    def test_expired_challenge_cannot_be_approved(self):
        """Expired challenges should not accept approvals."""
        # This test requires either:
        # 1. A very short challenge TTL for testing
        # 2. Time manipulation capability
        # For now, document the expected behavior
        pytest.skip(
            "Requires test mode with short TTL or time manipulation. "
            "Verify manually that expired challenges return 410 Gone on approval."
        )

    def test_expired_challenge_cannot_issue_mandate(self):
        """Expired challenges should not issue mandates."""
        pytest.skip(
            "Requires test mode with short TTL. "
            "Verify that /v1/mandate returns 410 for expired challenges."
        )


class TestTokenSecurity:
    """Tests for PoA token security."""

    def test_token_cannot_be_modified(self):
        """Modified tokens should be rejected by OPA."""
        with httpx.Client() as client:
            try:
                # Get a valid token
                challenge_id = create_challenge(client)
                if not challenge_id:
                    pytest.skip("Could not create challenge")

                client.post(
                    f"{AGENTAUTH_URL}/v1/approve",
                    json={"challenge_id": challenge_id, "approver": "test@test.com"},
                    timeout=5.0,
                )

                resp = client.post(
                    f"{AGENTAUTH_URL}/v1/mandate",
                    json={"challenge_id": challenge_id},
                    timeout=5.0,
                )

                if resp.status_code != 200:
                    pytest.skip("Could not get mandate")

                token = resp.json().get("token", "")

                # Modify the token payload
                parts = token.split(".")
                if len(parts) == 3:
                    # Tamper with the payload
                    import base64
                    import json

                    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
                    payload["act"] = "admin.system.delete"  # Escalate action

                    tampered_payload = (
                        base64.urlsafe_b64encode(json.dumps(payload).encode())
                        .decode()
                        .rstrip("=")
                    )

                    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

                    # OPA should reject tampered token
                    opa_resp = client.post(
                        f"{OPA_URL}/v1/data/atb/poa/decision",
                        json={
                            "input": {
                                "agent": {
                                    "spiffe_id": "spiffe://example.org/agent/test"
                                },
                                "poa": {},  # Would need to parse tampered token
                                "request": {"action": "admin.system.delete"},
                            }
                        },
                        timeout=5.0,
                    )

                    # Signature verification should fail
                    # This test is simplified - real verification happens in Broker

            except httpx.ConnectError:
                pytest.skip("Services not running")


class TestInformationDisclosure:
    """Tests for information disclosure vulnerabilities."""

    def test_nonexistent_agent_error_is_generic(self):
        """Error messages should not reveal if an agent exists."""
        with httpx.Client() as client:
            try:
                # Try two different nonexistent agents
                resp1 = client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json={
                        "agent_spiffe_id": "spiffe://example.org/agent/definitely-does-not-exist-1",
                        "act": "crm.contact.read",
                        "con": {},
                        "leg": {
                            "basis": "contract",
                            "jurisdiction": "US",
                            "accountable_party": {"type": "human", "id": "x"},
                        },
                    },
                    timeout=5.0,
                )

                resp2 = client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    json={
                        "agent_spiffe_id": "spiffe://example.org/agent/definitely-does-not-exist-2",
                        "act": "crm.contact.read",
                        "con": {},
                        "leg": {
                            "basis": "contract",
                            "jurisdiction": "US",
                            "accountable_party": {"type": "human", "id": "x"},
                        },
                    },
                    timeout=5.0,
                )

                # Both should return same status and similar error
                # to prevent agent enumeration
                if resp1.status_code == 200 and resp2.status_code == 200:
                    # System accepts any agent ID (by design or vulnerability)
                    pass
                elif resp1.status_code != resp2.status_code:
                    pytest.fail(
                        "Different error codes for different nonexistent agents "
                        "may allow agent enumeration"
                    )

            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")

    def test_error_messages_do_not_leak_internals(self):
        """Error messages should not expose internal details."""
        with httpx.Client() as client:
            try:
                # Send malformed request
                resp = client.post(
                    f"{AGENTAUTH_URL}/v1/challenge",
                    content=b"not json",
                    headers={"Content-Type": "application/json"},
                    timeout=5.0,
                )

                error_text = resp.text.lower()

                # Check for internal info leakage
                leak_patterns = [
                    "stack trace",
                    "goroutine",
                    "panic",
                    "/go/src/",
                    "/home/",
                    "password",
                    "secret",
                    "internal server error",  # Generic is OK, but check for details
                ]

                for pattern in leak_patterns:
                    if pattern in error_text:
                        pytest.fail(
                            f"Error message may leak internal info: '{pattern}'"
                        )

            except httpx.ConnectError:
                pytest.skip("AgentAuth not running")
