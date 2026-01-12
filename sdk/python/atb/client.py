"""ATB Client for interacting with the Agent Trust Broker."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from atb.exceptions import (
    ATBError,
    AuthorizationDeniedError,
    ConnectionError,
    ValidationError,
)
from atb.poa import PoA, PoABuilder

logger = logging.getLogger(__name__)


@dataclass
class ActionResult:
    """Result of an action execution."""

    success: bool
    data: dict[str, Any] | None = None
    error: str | None = None
    audit_id: str | None = None
    decision: str | None = None  # "allow" or "deny"

    def __bool__(self) -> bool:
        return self.success


@dataclass
class ATBConfig:
    """Configuration for ATB client."""

    broker_url: str = "http://localhost:8080"
    agentauth_url: str = "http://localhost:8081"
    timeout: float = 30.0
    verify_ssl: bool = True
    private_key_path: str | None = None
    cert_path: str | None = None
    spiffe_endpoint: str | None = None  # Unix socket path for workload API


class ATBClient:
    """Client for interacting with the Agent Trust Broker.

    Example:
        >>> client = ATBClient(config=ATBConfig(broker_url="http://localhost:8080"))
        >>> poa = (PoABuilder()
        ...     .for_agent("spiffe://atb.example/agent/copilot")
        ...     .action("sap.vendor.change")
        ...     .with_params(vendor_id="V-12345", amount=5000)
        ...     .with_constraint("liability_cap", 10000)
        ...     .legal(
        ...         jurisdiction="DE",
        ...         accountable_party=AccountableParty(
        ...             type="user",
        ...             id="alice@example.com",
        ...             display_name="Alice Smith"
        ...         ),
        ...         approval_ref="SNOW-CHG0012345"
        ...     )
        ...     .build())
        >>> result = client.execute(poa)
        >>> if result.success:
        ...     print(f"Action completed: {result.data}")
    """

    def __init__(self, config: ATBConfig | None = None) -> None:
        """Initialize the ATB client.

        Args:
            config: ATB configuration. Uses defaults if not provided.
        """
        self.config = config or ATBConfig()
        self._private_key: str | None = None
        self._http_client: httpx.Client | None = None

    def _get_http_client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.Client(
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
        return self._http_client

    def _load_private_key(self) -> str:
        """Load private key for JWT signing."""
        if self._private_key is None:
            if not self.config.private_key_path:
                raise ATBError("Private key path not configured")
            with open(self.config.private_key_path) as f:
                self._private_key = f.read()
        return self._private_key

    def execute(
        self,
        poa: PoA,
        private_key: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> ActionResult:
        """Execute an action with a PoA mandate.

        Args:
            poa: The Proof-of-Authorization mandate.
            private_key: Optional private key for signing (uses config if not provided).
            headers: Additional HTTP headers.

        Returns:
            ActionResult with success status and data.

        Raises:
            AuthorizationDeniedError: If the action is denied by policy.
            ConnectionError: If connection to broker fails.
        """
        # Get private key for signing
        key = private_key or self._load_private_key()

        # Sign the PoA
        token = poa.to_jwt(key)

        # Prepare request
        request_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        if headers:
            request_headers.update(headers)

        try:
            client = self._get_http_client()
            response = client.post(
                f"{self.config.broker_url}/v1/action",
                headers=request_headers,
                json={"action": poa.act, "params": poa.con.get("params", {})},
            )
        except httpx.ConnectError as e:
            raise ConnectionError(
                f"Failed to connect to broker: {e}",
                endpoint=self.config.broker_url,
            ) from e

        # Parse response
        try:
            data = response.json()
        except json.JSONDecodeError:
            data = {"raw": response.text}

        # Handle response based on status
        if response.status_code == 200:
            return ActionResult(
                success=True,
                data=data,
                audit_id=response.headers.get("X-Audit-ID"),
                decision="allow",
            )
        elif response.status_code == 403:
            raise AuthorizationDeniedError(
                message=data.get("error", "Action denied by policy"),
                reason=data.get("reason"),
                details=data,
            )
        else:
            return ActionResult(
                success=False,
                error=data.get("error", f"Request failed with status {response.status_code}"),
                data=data,
            )

    def validate_poa(self, token: str, public_key: str | None = None) -> PoA:
        """Validate a PoA JWT token.

        Args:
            token: JWT token to validate.
            public_key: Public key for verification.

        Returns:
            Validated PoA instance.

        Raises:
            ValidationError: If token is invalid.
        """
        if not public_key:
            # Fetch from AgentAuth service
            try:
                client = self._get_http_client()
                response = client.get(f"{self.config.agentauth_url}/.well-known/jwks.json")
                response.raise_for_status()
                # In production, would extract key from JWKS
                raise ValidationError("JWKS validation not yet implemented - provide public_key")
            except httpx.HTTPError as e:
                raise ConnectionError(
                    f"Failed to fetch JWKS: {e}",
                    endpoint=self.config.agentauth_url,
                ) from e

        return PoA.from_jwt(token, public_key)

    def check_policy(
        self,
        action: str,
        params: dict[str, Any],
        agent_spiffe_id: str,
    ) -> dict[str, Any]:
        """Check if an action would be allowed without executing it.

        Args:
            action: Action identifier.
            params: Action parameters.
            agent_spiffe_id: SPIFFE ID of the agent.

        Returns:
            Policy decision with allowed status and reason.
        """
        try:
            client = self._get_http_client()
            response = client.post(
                f"{self.config.broker_url}/v1/policy/check",
                json={
                    "action": action,
                    "params": params,
                    "agent": agent_spiffe_id,
                },
            )
            return response.json()
        except httpx.HTTPError as e:
            raise ConnectionError(
                f"Failed to check policy: {e}",
                endpoint=self.config.broker_url,
            ) from e

    def get_audit_log(
        self,
        audit_id: str | None = None,
        action: str | None = None,
        agent: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve audit log entries.

        Args:
            audit_id: Filter by specific audit ID.
            action: Filter by action.
            agent: Filter by agent SPIFFE ID.
            limit: Maximum entries to return.

        Returns:
            List of audit log entries.
        """
        params = {"limit": limit}
        if audit_id:
            params["audit_id"] = audit_id
        if action:
            params["action"] = action
        if agent:
            params["agent"] = agent

        try:
            client = self._get_http_client()
            response = client.get(
                f"{self.config.broker_url}/v1/audit",
                params=params,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise ConnectionError(
                f"Failed to fetch audit log: {e}",
                endpoint=self.config.broker_url,
            ) from e

    def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            self._http_client.close()
            self._http_client = None

    def __enter__(self) -> ATBClient:
        return self

    def __exit__(self, *args) -> None:
        self.close()


# Convenience function for one-off actions
def execute_action(
    action: str,
    params: dict[str, Any],
    agent_spiffe_id: str,
    accountable_user: str,
    jurisdiction: str = "GLOBAL",
    broker_url: str = "http://localhost:8080",
    private_key: str | None = None,
    **constraints: Any,
) -> ActionResult:
    """Execute an action with minimal configuration.

    Args:
        action: Action identifier (e.g., "sap.vendor.change").
        params: Action parameters.
        agent_spiffe_id: SPIFFE ID of the agent.
        accountable_user: Email/ID of the accountable user.
        jurisdiction: Legal jurisdiction (default: "GLOBAL").
        broker_url: Broker URL.
        private_key: Private key for signing.
        **constraints: Additional constraints.

    Returns:
        ActionResult with success status and data.

    Example:
        >>> result = execute_action(
        ...     action="sap.vendor.change",
        ...     params={"vendor_id": "V-12345", "amount": 5000},
        ...     agent_spiffe_id="spiffe://atb.example/agent/copilot",
        ...     accountable_user="alice@example.com",
        ...     jurisdiction="DE",
        ...     liability_cap=10000,
        ... )
    """
    from atb.poa import AccountableParty

    poa = (
        PoABuilder()
        .for_agent(agent_spiffe_id)
        .action(action)
        .with_params(**params)
        .with_constraints(**constraints)
        .legal(
            jurisdiction=jurisdiction,
            accountable_party=AccountableParty(type="user", id=accountable_user),
        )
        .build()
    )

    with ATBClient(config=ATBConfig(broker_url=broker_url)) as client:
        return client.execute(poa, private_key=private_key)
