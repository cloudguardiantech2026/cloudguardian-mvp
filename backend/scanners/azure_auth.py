import os
from azure.identity import ClientSecretCredential


def get_azure_credential(tenant_id: str = None, client_id: str = None, client_secret: str = None):
    """
    Returns an Azure ClientSecretCredential.

    All parameters are optional and fall back to environment variables.
    This keeps backward compatibility with scanner files that call
    get_azure_credential() with zero arguments, while still allowing
    explicit tenant_id to be passed in for the OAuth multi-tenant flow.

    Parameters
    ----------
    tenant_id     : Customer's Azure Tenant ID. Falls back to AZURE_TENANT_ID env var.
    client_id     : CloudGuardian's platform Client ID. Falls back to AZURE_CLIENT_ID env var.
    client_secret : CloudGuardian's platform Client Secret. Falls back to AZURE_CLIENT_SECRET env var.
    """
    resolved_tenant_id = tenant_id or os.environ.get("AZURE_TENANT_ID", "")

    if not resolved_tenant_id:
        raise ValueError(
            "No tenant_id provided and AZURE_TENANT_ID environment variable is not set. "
            "Make sure run_azure_scan() sets os.environ['AZURE_TENANT_ID'] before calling scanners."
        )

    return ClientSecretCredential(
        tenant_id=resolved_tenant_id,
        client_id=client_id or os.environ["AZURE_CLIENT_ID"],
        client_secret=client_secret or os.environ["AZURE_CLIENT_SECRET"],
    )


def get_subscription_id(subscription_id: str = None) -> str:
    """
    Returns the customer's subscription ID.
    Accepts an explicit value or falls back to the environment variable.
    """
    return subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")