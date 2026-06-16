"""import os
from azure.identity import ClientSecretCredential

def get_azure_credential():
    return ClientSecretCredential(
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_id=os.environ["AZURE_CLIENT_ID"],
        client_secret=os.environ["AZURE_CLIENT_SECRET"]
    )

def get_subscription_id():
    return os.environ["AZURE_SUBSCRIPTION_ID"]"""

import os
from azure.identity import ClientSecretCredential


def get_azure_credential(tenant_id: str, client_id: str = None, client_secret: str = None):
    """
    Returns an Azure ClientSecretCredential using CloudGuardian's own
    platform credentials to scan the customer's tenant.

    For the multi-tenant OAuth flow, the customer has already consented
    via the Microsoft login page. CloudGuardian uses its own Client ID
    and Secret (stored in Render environment variables) plus the
    customer's Tenant ID obtained from the OAuth callback.

    Parameters
    ----------
    tenant_id     : The customer's Azure Tenant ID obtained from OAuth callback.
    client_id     : Optional override. Defaults to AZURE_CLIENT_ID env var.
    client_secret : Optional override. Defaults to AZURE_CLIENT_SECRET env var.
    """
    return ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id or os.environ["AZURE_CLIENT_ID"],
        client_secret=client_secret or os.environ["AZURE_CLIENT_SECRET"],
    )


def get_subscription_id(subscription_id: str = None) -> str:
    """
    Returns the customer's subscription ID.
    Accepts an explicit value (from OAuth session) or falls back to
    the environment variable for backward compatibility.
    """
    return subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")


