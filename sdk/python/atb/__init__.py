"""ATB SDK - Agent Trust Broker client library for Python.

This SDK provides a simple interface for:
- Creating and signing Proof-of-Authorization (PoA) mandates
- Submitting actions through the ATB broker
- Validating PoA tokens
"""

from atb.client import ATBClient
from atb.exceptions import (
    ATBError,
    AuthorizationDeniedError,
    ConnectionError,
    TokenExpiredError,
    ValidationError,
)
from atb.poa import AccountableParty, LegalGrounding, PoA, PoABuilder

__version__ = "0.1.0"
__all__ = [
    "ATBClient",
    "PoA",
    "PoABuilder",
    "AccountableParty",
    "LegalGrounding",
    "ATBError",
    "AuthorizationDeniedError",
    "TokenExpiredError",
    "ValidationError",
    "ConnectionError",
]
