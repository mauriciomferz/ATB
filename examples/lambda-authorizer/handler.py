"""
ATB AWS Lambda Authorizer

This Lambda authorizer integrates with ATB (Agent Trust Broker) to authorize
API Gateway requests from AI agents using Proof of Authorization (PoA) tokens.

The authorizer:
1. Extracts the PoA token from the Authorization header
2. Extracts the requested action from the request path/method
3. Calls ATB Broker for policy decision
4. Returns an IAM policy allowing or denying the request

Environment Variables:
  ATB_BROKER_URL: URL of the ATB Broker (e.g., https://atb.example.com)
  ATB_JWKS_URL: URL to fetch JWKS for local token validation (optional)
  CACHE_TTL_SECONDS: TTL for caching decisions (default: 60)
  LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)

Usage with API Gateway:
  1. Create this Lambda function
  2. Configure as a Lambda authorizer in API Gateway
  3. Set Authorization header type to "Token"
  4. Set Token source to "Authorization"
"""

import base64
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# Configure logging
log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.basicConfig(level=getattr(logging, log_level))
logger = logging.getLogger(__name__)

# Configuration
ATB_BROKER_URL = os.environ.get("ATB_BROKER_URL", "https://atb-broker.example.com")
CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "60"))

# Simple in-memory cache for decisions
_decision_cache: dict[str, tuple[dict, float]] = {}


@dataclass
class ATBDecision:
    """Result from ATB authorization decision."""

    allowed: bool
    risk_tier: str
    reason: str | None
    request_id: str
    agent_id: str | None
    metadata: dict[str, Any] | None


def lambda_handler(event: dict, context: Any) -> dict:
    """
    AWS Lambda handler for API Gateway authorizer.

    Args:
        event: API Gateway authorizer event
        context: Lambda context

    Returns:
        IAM policy document
    """
    logger.info("Received authorization request")
    logger.debug(f"Event: {json.dumps(event, default=str)}")

    try:
        # Extract token from Authorization header
        token = extract_token(event)
        if not token:
            logger.warning("No token provided")
            raise Exception("Unauthorized")

        # Extract action from request
        action = extract_action(event)
        logger.info(f"Authorizing action: {action}")

        # Check cache first
        cache_key = compute_cache_key(token, action)
        cached = get_cached_decision(cache_key)
        if cached:
            logger.info(f"Using cached decision: allowed={cached.allowed}")
            return generate_policy(cached, event)

        # Call ATB for decision
        decision = call_atb_decide(token, action)

        # Cache the decision
        cache_decision(cache_key, decision)

        # Log decision for audit
        log_decision(decision, action, event)

        # Generate and return policy
        return generate_policy(decision, event)

    except Exception as e:
        logger.error(f"Authorization error: {e}")
        # Return deny policy on any error
        return generate_deny_policy(event, str(e))


def extract_token(event: dict) -> str | None:
    """
    Extract PoA token from the event.

    Supports multiple token locations:
    - authorizationToken (for TOKEN type authorizer)
    - headers.Authorization (for REQUEST type authorizer)
    - queryStringParameters.token
    """
    # TOKEN type authorizer
    if "authorizationToken" in event:
        token = event["authorizationToken"]
        # Remove "Bearer " prefix if present
        if token.startswith("Bearer "):
            token = token[7:]
        return token

    # REQUEST type authorizer
    headers = event.get("headers", {}) or {}

    # Case-insensitive header lookup
    auth_header = None
    for key, value in headers.items():
        if key.lower() == "authorization":
            auth_header = value
            break

    if auth_header:
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return auth_header

    # Query parameter fallback
    query_params = event.get("queryStringParameters", {}) or {}
    return query_params.get("token")


def extract_action(event: dict) -> str:
    """
    Extract ATB action from the API Gateway event.

    Maps API Gateway request to ATB action format:
    - HTTP method + path -> action string
    - Example: GET /api/v1/agents -> agents.list
    """
    method = event.get(
        "httpMethod",
        event.get("requestContext", {}).get("http", {}).get("method", "GET"),
    )
    path = event.get("path", event.get("rawPath", "/"))

    # Remove API version prefix if present
    path = path.lstrip("/")
    if path.startswith("api/"):
        parts = path.split("/")
        if len(parts) > 2:
            path = "/".join(parts[2:])  # Skip api/v1/

    # Convert path to action
    path_parts = [p for p in path.split("/") if p and not p.startswith("{")]

    # Map HTTP method to action verb
    method_map = {
        "GET": "read",
        "POST": "create",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete",
        "HEAD": "read",
        "OPTIONS": "read",
    }
    verb = method_map.get(method.upper(), "execute")

    if path_parts:
        resource = ".".join(path_parts)
        return f"{resource}.{verb}"

    return f"api.{verb}"


def call_atb_decide(token: str, action: str) -> ATBDecision:
    """
    Call ATB Broker for authorization decision.

    Args:
        token: PoA token
        action: Action to authorize

    Returns:
        ATBDecision with authorization result
    """
    url = f"{ATB_BROKER_URL}/api/v1/decide"

    payload = json.dumps({"action": action, "token": token}).encode("utf-8")

    request = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))

            return ATBDecision(
                allowed=data.get("allowed", False),
                risk_tier=data.get("risk_tier", "UNKNOWN"),
                reason=data.get("reason"),
                request_id=data.get("request_id", ""),
                agent_id=data.get("agent_id"),
                metadata=data.get("metadata"),
            )

    except HTTPError as e:
        logger.error(f"ATB HTTP error: {e.code} - {e.read().decode()}")
        return ATBDecision(
            allowed=False,
            risk_tier="UNKNOWN",
            reason=f"ATB error: {e.code}",
            request_id="",
            agent_id=None,
            metadata=None,
        )
    except URLError as e:
        logger.error(f"ATB connection error: {e}")
        return ATBDecision(
            allowed=False,
            risk_tier="UNKNOWN",
            reason=f"ATB unavailable: {e.reason}",
            request_id="",
            agent_id=None,
            metadata=None,
        )


def generate_policy(decision: ATBDecision, event: dict) -> dict:
    """
    Generate IAM policy document based on ATB decision.

    Args:
        decision: ATB authorization decision
        event: Original API Gateway event

    Returns:
        IAM policy document
    """
    # Extract principal identifier
    principal_id = decision.agent_id or "agent"

    # Get the method ARN from the event
    method_arn = event.get("methodArn", "")

    if not method_arn:
        # For HTTP API (v2)
        route_arn = event.get("routeArn", "")
        if route_arn:
            method_arn = route_arn
        else:
            # Construct ARN from context
            ctx = event.get("requestContext", {})
            account_id = ctx.get("accountId", "*")
            api_id = ctx.get("apiId", "*")
            stage = ctx.get("stage", "*")
            method_arn = f"arn:aws:execute-api:*:{account_id}:{api_id}/{stage}/*"

    # Determine effect
    effect = "Allow" if decision.allowed else "Deny"

    policy = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": method_arn,
                }
            ],
        },
        "context": {
            "atb_allowed": str(decision.allowed).lower(),
            "atb_risk_tier": decision.risk_tier,
            "atb_request_id": decision.request_id,
        },
    }

    if decision.reason:
        policy["context"]["atb_reason"] = decision.reason

    if decision.agent_id:
        policy["context"]["agent_id"] = decision.agent_id

    logger.info(f"Generated policy: effect={effect}, principal={principal_id}")

    return policy


def generate_deny_policy(event: dict, reason: str) -> dict:
    """
    Generate a deny policy for error cases.

    Args:
        event: Original API Gateway event
        reason: Reason for denial

    Returns:
        IAM policy document denying access
    """
    method_arn = event.get("methodArn", event.get("routeArn", "*"))

    return {
        "principalId": "unknown",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Deny",
                    "Resource": method_arn,
                }
            ],
        },
        "context": {"atb_allowed": "false", "atb_reason": reason},
    }


def compute_cache_key(token: str, action: str) -> str:
    """
    Compute a cache key for the decision.

    Uses a hash of the token to avoid storing sensitive data in memory.
    """
    token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
    return f"{token_hash}:{action}"


def get_cached_decision(cache_key: str) -> ATBDecision | None:
    """
    Get a cached decision if not expired.
    """
    if cache_key not in _decision_cache:
        return None

    cached, timestamp = _decision_cache[cache_key]
    if time.time() - timestamp > CACHE_TTL_SECONDS:
        del _decision_cache[cache_key]
        return None

    return ATBDecision(**cached)


def cache_decision(cache_key: str, decision: ATBDecision) -> None:
    """
    Cache a decision with current timestamp.
    """
    _decision_cache[cache_key] = (
        {
            "allowed": decision.allowed,
            "risk_tier": decision.risk_tier,
            "reason": decision.reason,
            "request_id": decision.request_id,
            "agent_id": decision.agent_id,
            "metadata": decision.metadata,
        },
        time.time(),
    )

    # Clean up old cache entries periodically
    if len(_decision_cache) > 1000:
        cleanup_cache()


def cleanup_cache() -> None:
    """
    Remove expired entries from the cache.
    """
    now = time.time()
    expired = [
        key
        for key, (_, timestamp) in _decision_cache.items()
        if now - timestamp > CACHE_TTL_SECONDS
    ]
    for key in expired:
        del _decision_cache[key]


def log_decision(decision: ATBDecision, action: str, event: dict) -> None:
    """
    Log the authorization decision for audit purposes.
    """
    source_ip = (
        event.get("requestContext", {}).get("identity", {}).get("sourceIp")
        or event.get("requestContext", {}).get("http", {}).get("sourceIp")
        or "unknown"
    )

    log_entry = {
        "event_type": "authorization_decision",
        "action": action,
        "allowed": decision.allowed,
        "risk_tier": decision.risk_tier,
        "agent_id": decision.agent_id,
        "request_id": decision.request_id,
        "source_ip": source_ip,
        "reason": decision.reason,
    }

    logger.info(f"AUDIT: {json.dumps(log_entry)}")


# For local testing
if __name__ == "__main__":
    # Test event
    test_event = {
        "type": "TOKEN",
        "authorizationToken": "Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.test",
        "methodArn": "arn:aws:execute-api:us-east-1:123456789:api-id/stage/GET/resource",
        "httpMethod": "GET",
        "path": "/api/v1/agents",
    }

    # Mock context
    class MockContext:
        function_name = "atb-authorizer"
        aws_request_id = "test-request-id"

    result = lambda_handler(test_event, MockContext())
    print(json.dumps(result, indent=2))
