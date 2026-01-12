"""ATB SDK exceptions."""

from __future__ import annotations


class ATBError(Exception):
    """Base exception for all ATB SDK errors."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class AuthorizationDeniedError(ATBError):
    """Raised when OPA denies the action."""

    def __init__(self, message: str, reason: str | None = None, details: dict | None = None):
        super().__init__(message, details)
        self.reason = reason or "Policy evaluation denied the action"


class TokenExpiredError(ATBError):
    """Raised when a PoA token has expired."""

    def __init__(self, message: str = "PoA token has expired"):
        super().__init__(message)


class ValidationError(ATBError):
    """Raised when PoA validation fails."""

    def __init__(self, message: str, field: str | None = None):
        super().__init__(message)
        self.field = field


class ConnectionError(ATBError):
    """Raised when connection to ATB services fails."""

    def __init__(self, message: str, endpoint: str | None = None):
        super().__init__(message)
        self.endpoint = endpoint
