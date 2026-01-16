"""Platform-specific integrations for ATB.

This module provides pre-built integrations for common enterprise platforms:
- Microsoft Copilot / Azure AI
- SAP (Joule, S/4HANA)
- Salesforce (Agentforce)
- ServiceNow
- Workday
"""

from atb.platforms.base import PlatformConnector
from atb.platforms.copilot import CopilotConnector
from atb.platforms.salesforce import SalesforceConnector
from atb.platforms.sap import SAPConnector

__all__ = [
    "PlatformConnector",
    "CopilotConnector",
    "SalesforceConnector",
    "SAPConnector",
]
